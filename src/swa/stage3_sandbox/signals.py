"""Turn a normalized SandboxReport into swa.models.Finding objects.

This is design doc section 7.2 made executable: the network / filesystem /
process / registry / resource signals, each mapped to a finding with a
severity calibrated to swa.stage4_decision.

Calibration (same principle as Stage 2): a HIGH finding from Stage 3 is
treated as *confirmed* and blocks outright, so HIGH is reserved for behaviours
that are unambiguously malicious when observed at runtime -- the doc's
immediate-block set (Steam credential access, C2 connection, dropped
executable, ransomware) plus process injection and disabling of Windows
Defender/UAC. Merely abnormal behaviour for a wallpaper (spawning a child
process, touching an autostart key, sustained CPU) stays MEDIUM so the score,
not a single event, drives a block.

Pure and backend-agnostic: report in, findings out. No I/O, no execution.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..models import Finding, Severity
from .config import DEFAULT_CONFIG, SandboxConfig
from .report import SandboxReport

# Cap on findings emitted per noisy category, so a report with hundreds of
# events can't saturate the score by volume alone (it still gets flagged).
_MAX_PER_CATEGORY = 5

# Steam session/credential artefacts (self-contained; Stage 2 has its own copy
# on purpose -- each stage stays independently reviewable).
_STEAM_CRED_RE = re.compile(
    r"(loginusers\.vdf|[\\/]ssfn\d+|\bssfn\d{5,}|steam[\\/][^\"']*config\.vdf)",
    re.IGNORECASE,
)
# Writes into locations a wallpaper has no business touching.
_SENSITIVE_WRITE_RE = re.compile(
    r"(\\system32\\|\\syswow64\\|\\start menu\\programs\\startup\\|\\startup\\)",
    re.IGNORECASE,
)
# Autostart / persistence registry locations.
_AUTOSTART_KEY_RE = re.compile(
    r"(currentversion\\run|currentversion\\runonce|\\winlogon\\|"
    r"\\services\\|policies\\explorer\\run|currentversion\\policies\\system)",
    re.IGNORECASE,
)
# Windows Defender / UAC / SmartScreen tampering.
_SECURITY_TAMPER_RE = re.compile(
    r"(windows defender|real-time protection|disableantispyware|disableantivirus|"
    r"disablerealtimemonitoring|smartscreen|enablelua|consentpromptbehavioradmin)",
    re.IGNORECASE,
)
# Security processes whose termination is itself an attack.
_SECURITY_PROCS = frozenset(
    {
        "msmpeng.exe",
        "windefend",
        "securityhealthservice.exe",
        "mpcmdrun.exe",
        "smartscreen.exe",
        "taskmgr.exe",
    }
)

_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "::1"})

# Sandbox-signature name -> (code, severity). First substring match wins.
_SIGNATURE_MAP: tuple[tuple[str, str, Severity], ...] = (
    ("ransom", "dyn_sig_ransomware", Severity.HIGH),
    ("stealer", "dyn_sig_infostealer", Severity.HIGH),
    ("keylog", "dyn_sig_keylogger", Severity.HIGH),
    ("inject", "dyn_sig_injection", Severity.HIGH),
    ("credential", "dyn_sig_credential_theft", Severity.HIGH),
    ("miner", "dyn_sig_cryptominer", Severity.MEDIUM),
    ("persistence", "dyn_sig_persistence", Severity.MEDIUM),
    ("evasion", "dyn_sig_evasion", Severity.LOW),
    ("anti-vm", "dyn_sig_anti_vm", Severity.LOW),
    ("anti_vm", "dyn_sig_anti_vm", Severity.LOW),
)


def _host_of(url: str | None) -> str | None:
    if not url:
        return None
    try:
        netloc = urlsplit(url).netloc or urlsplit("//" + url).netloc
    except ValueError:
        return None
    host = netloc.split("@")[-1].split(":")[0].strip().lower().rstrip(".")
    return host or None


def _declared(host: str | None, allowed: set[str]) -> bool:
    if host is None or host in _LOCAL_HOSTS:
        return True
    return any(host == d or host.endswith("." + d) for d in allowed)


def analyze_report(
    report: SandboxReport,
    allowed_domains: set[str] | None = None,
    config: SandboxConfig = DEFAULT_CONFIG,
) -> list[Finding]:
    """Map a behavioural report to findings (design doc 7.2)."""
    allowed = allowed_domains or set()
    findings: list[Finding] = []

    findings += _network_signals(report, allowed)
    findings += _filesystem_signals(report)
    findings += _process_signals(report)
    findings += _registry_signals(report)
    findings += _resource_signals(report, config)
    findings += _signature_signals(report)

    return _dedup(findings)


# --- network (doc 7.2: outbound to undeclared, C2, newly-registered DNS) -----

def _network_signals(report: SandboxReport, allowed: set[str]) -> list[Finding]:
    out: list[Finding] = []
    c2_seen: set[str] = set()
    undeclared_hosts: list[str] = []
    direct_ips: list[str] = []

    for ev in report.network:
        host = ev.host or _host_of(ev.url)
        dest = host or ev.ip
        if dest is None:
            continue

        if ev.newly_registered and dest not in c2_seen:
            c2_seen.add(dest)
            out.append(
                _f(
                    "dyn_c2_connection",
                    Severity.HIGH,
                    f"connection to recently-registered domain '{dest}' "
                    "(command-and-control pattern)",
                    dest,
                )
            )
            continue

        if host is not None:
            if not _declared(host, allowed) and host not in undeclared_hosts:
                undeclared_hosts.append(host)
        elif ev.ip and ev.ip not in _LOCAL_HOSTS and ev.ip not in direct_ips:
            direct_ips.append(ev.ip)

    for host in undeclared_hosts[:_MAX_PER_CATEGORY]:
        out.append(
            _f(
                "dyn_network_undeclared",
                Severity.MEDIUM,
                f"outbound connection to '{host}', not declared in project.json",
                host,
            )
        )
    for ip in direct_ips[:_MAX_PER_CATEGORY]:
        out.append(
            _f(
                "dyn_direct_ip_connection",
                Severity.MEDIUM,
                f"outbound connection to raw IP {ip} with no DNS resolution",
                ip,
            )
        )
    return out


# --- filesystem (doc 7.2: writes outside workdir, Steam files, droppers) -----

def _filesystem_signals(report: SandboxReport) -> list[Finding]:
    out: list[Finding] = []
    dropped = 0
    sensitive = 0
    for ev in report.files:
        if _STEAM_CRED_RE.search(ev.path):
            out.append(
                _f(
                    "dyn_steam_credential_access",
                    Severity.HIGH,
                    f"accessed Steam session/credential file: {ev.path}",
                    ev.path,
                )
            )
        if ev.op == "write" and ev.is_executable and dropped < _MAX_PER_CATEGORY:
            dropped += 1
            out.append(
                _f(
                    "dyn_dropped_executable",
                    Severity.HIGH,
                    f"dropped an executable to disk: {ev.path}",
                    ev.path,
                )
            )
        if (
            ev.op == "write"
            and not ev.is_executable
            and _SENSITIVE_WRITE_RE.search(ev.path)
            and sensitive < _MAX_PER_CATEGORY
        ):
            sensitive += 1
            out.append(
                _f(
                    "dyn_write_sensitive_location",
                    Severity.MEDIUM,
                    f"wrote to a system/autostart location: {ev.path}",
                    ev.path,
                )
            )
    return out


# --- processes (doc 7.2: child processes, injection, kill security procs) ----

def _process_signals(report: SandboxReport) -> list[Finding]:
    out: list[Finding] = []
    children = 0
    for ev in report.processes:
        if ev.op == "inject":
            tgt = f" into {ev.target}" if ev.target else ""
            api = f" ({ev.detail})" if ev.detail else ""
            out.append(
                _f(
                    "dyn_process_injection",
                    Severity.HIGH,
                    f"code injection{tgt}{api}",
                    ev.name or ev.target,
                )
            )
        elif ev.op == "terminate" and (ev.target or ev.name).lower() in _SECURITY_PROCS:
            out.append(
                _f(
                    "dyn_security_process_kill",
                    Severity.HIGH,
                    f"terminated a security process: {ev.target or ev.name}",
                    ev.target or ev.name,
                )
            )
        elif ev.op == "create" and children < _MAX_PER_CATEGORY:
            children += 1
            out.append(
                _f(
                    "dyn_child_process_spawn",
                    Severity.MEDIUM,
                    f"spawned a child process: {ev.name}",
                    ev.name,
                )
            )
    return out


# --- registry (doc 7.2: boot keys, Defender/UAC disable) ---------------------

def _registry_signals(report: SandboxReport) -> list[Finding]:
    out: list[Finding] = []
    autostart = 0
    for ev in report.registry:
        if _SECURITY_TAMPER_RE.search(ev.key) or (
            ev.value is not None and _SECURITY_TAMPER_RE.search(ev.value)
        ):
            out.append(
                _f(
                    "dyn_security_tampering",
                    Severity.HIGH,
                    f"tampered with Defender/UAC/SmartScreen: {ev.key}",
                    ev.key,
                )
            )
        elif _AUTOSTART_KEY_RE.search(ev.key) and autostart < _MAX_PER_CATEGORY:
            autostart += 1
            out.append(
                _f(
                    "dyn_autostart_persistence",
                    Severity.MEDIUM,
                    f"created an autostart/persistence registry entry: {ev.key}",
                    ev.key,
                )
            )
    return out


# --- resources (doc 7.2: mining CPU, mass encryption) ------------------------

def _resource_signals(report: SandboxReport, config: SandboxConfig) -> list[Finding]:
    out: list[Finding] = []
    res = report.resources
    if res.files_encrypted is not None and res.files_encrypted >= config.ransomware_min_files:
        out.append(
            _f(
                "dyn_ransomware_behavior",
                Severity.HIGH,
                f"mass file encryption: {res.files_encrypted} user files rewritten",
                None,
            )
        )
    # CPU-based mining only. GPU is intentionally NOT used: wallpapers are
    # GPU-heavy by nature, so high GPU is not evidence of mining.
    if res.cpu_avg is not None and res.cpu_avg >= config.mining_cpu_threshold:
        out.append(
            _f(
                "dyn_resource_mining",
                Severity.MEDIUM,
                f"sustained CPU {res.cpu_avg:.0f}% consistent with cryptomining",
                None,
            )
        )
    return out


# --- sandbox's own named detections -----------------------------------------

def _signature_signals(report: SandboxReport) -> list[Finding]:
    out: list[Finding] = []
    for sig in report.signatures:
        low = sig.lower()
        matched = False
        for needle, code, sev in _SIGNATURE_MAP:
            if needle in low:
                out.append(_f(code, sev, f"sandbox signature: {sig}", None))
                matched = True
                break
        if not matched:
            out.append(
                _f("dyn_sandbox_signature", Severity.LOW, f"sandbox signature: {sig}", None)
            )
    return out


def _f(code: str, severity: Severity, message: str, path: str | None) -> Finding:
    return Finding(code=code, severity=severity, message=message, path=path)


def _dedup(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str | None, str]] = set()
    out: list[Finding] = []
    order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2, Severity.INFO: 3}
    for f in findings:
        key = (f.code, f.path, f.message)
        if key not in seen:
            seen.add(key)
            out.append(f)
    out.sort(key=lambda f: (order[f.severity], f.code, f.path or ""))
    return out
