"""IOC tables, math helpers, and the content-IOC scanner shared by every
detector in Stage 2.

Everything here is *data* or a *pure function* -- no file I/O, no state. The
detectors (pe.py, scripts.py, strings.py) import from here so a single IOC
pattern lives in exactly one place, and the finding codes/severities stay
consistent no matter which file type surfaced the indicator.

Severity calibration is deliberate and tied to swa.stage4_decision's scoring
(HIGH from Stage 2 is treated as *confirmed* and blocks outright; MEDIUM=20,
LOW=5, block threshold=60). So HIGH is reserved for indicators a legitimate
wallpaper has no reason to contain at all -- Steam session-file references and
system-library impersonation -- while merely *suspicious* traits (packing,
network imports, an undeclared domain) stay MEDIUM/LOW and let corroboration,
not a single heuristic, drive a block.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlsplit

from ..models import Finding, Severity
from .config import DEFAULT_CONFIG, StaticConfig

# --- Windows system libraries a Workshop item must never legitimately ship ---
# The AggregatorHost.dll case from the Kaspersky campaign: a DLL bearing the
# name of a real OS library, used to hijack the loader search order. These are
# OS-only components (NOT redistributable runtimes like msvcp140.dll, which
# apps legitimately bundle), so the mere presence of one under untrusted
# Workshop content is itself the high-severity indicator.
SYSTEM_DLL_NAMES = frozenset(
    {
        "aggregatorhost.dll",  # the documented impersonation target
        "version.dll",
        "wininet.dll",
        "winhttp.dll",
        "secur32.dll",
        "sspicli.dll",
        "userenv.dll",
        "profapi.dll",
        "cryptsp.dll",
        "dbghelp.dll",
        "dwmapi.dll",
        "uxtheme.dll",
        "ntmarta.dll",
        "wtsapi32.dll",
        "bcrypt.dll",
        "ncrypt.dll",
        "cryptbase.dll",
        "netapi32.dll",
        "wldap32.dll",
    }
)

# --- Suspicious PE imports, grouped by capability. Matched as lowercase
# substrings against imported function names (covers the A/W and Nt/Zw
# variants without listing each). One finding per category present. ---
IMPORT_CATEGORIES: dict[str, tuple[Severity, str, tuple[str, ...]]] = {
    "process_injection": (
        Severity.MEDIUM,
        "process injection / code-execution primitives",
        (
            "createremotethread",
            "ntcreatethreadex",
            "rtlcreateuserthread",
            "virtualallocex",
            "writeprocessmemory",
            "queueuserapc",
            "setwindowshookex",
            "ntunmapviewofsection",
            "ntmapviewofsection",
        ),
    ),
    "persistence": (
        Severity.LOW,
        "autostart / service persistence",
        ("regsetvalue", "regcreatekey", "createservice", "startservice"),
    ),
    "anti_analysis": (
        Severity.LOW,
        "debugger / sandbox evasion checks",
        (
            "isdebuggerpresent",
            "checkremotedebuggerpresent",
            "ntqueryinformationprocess",
            "ntsetinformationthread",
            "blockinput",
        ),
    ),
    "network": (
        Severity.LOW,
        "network / download capability",
        (
            "internetopen",
            "internetconnect",
            "internetreadfile",
            "httpopenrequest",
            "httpsendrequest",
            "winhttpopen",
            "winhttpconnect",
            "winhttpsendrequest",
            "urldownloadtofile",
            "wsastartup",
            "getaddrinfo",
        ),
    ),
    "privilege": (
        Severity.LOW,
        "token / privilege manipulation",
        ("adjusttokenprivileges", "openprocesstoken", "lookupprivilegevalue"),
    ),
}

# --- Content regexes (compiled once). Used against script source and against
# strings pulled out of binaries alike. ---

# Steam credential/session artefacts. A wallpaper referencing these is the
# session-theft pattern from the campaign; nothing benign needs them. HIGH.
STEAM_CRED_RE = re.compile(r"(loginusers\.vdf|[\\/]ssfn\d+|\bssfn\d{5,})", re.IGNORECASE)

URL_RE = re.compile(r"""https?://[^\s"'`<>)\]}|\\]+""", re.IGNORECASE)
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

# Crypto wallet addresses (clipboard-hijacker / miner IOC). MEDIUM.
_WALLET_RES = (
    re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),  # BTC
    re.compile(r"\b0x[a-fA-F0-9]{40}\b"),  # ETH
    re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),  # Monero
)

# Encoded/obfuscated PowerShell -- a strong LOLBin-abuse signal. MEDIUM.
PS_ENCODED_RE = re.compile(
    r"powershell(?:\.exe)?[^\n\r]{0,120}?"
    r"(?:-enc\b|-e\b|-encodedcommand|-nop\b|-noprofile\b|-w\s*hidden|"
    r"-windowstyle\s+hidden|iex\b|invoke-expression)",
    re.IGNORECASE,
)

# Living-off-the-land binaries frequently abused as loaders. LOW (context).
LOLBIN_RE = re.compile(
    r"\b(rundll32|regsvr32|mshta|bitsadmin|certutil|schtasks|wmic|"
    r"cmd(?:\.exe)?\s*/c)\b",
    re.IGNORECASE,
)

# Hosts that legitimately appear as XML namespaces / schema URIs, not as
# network destinations -- suppressed so SVG/HTML boilerplate isn't flagged.
BENIGN_HOSTS = frozenset(
    {
        "www.w3.org",
        "w3.org",
        "schemas.microsoft.com",
        "schemas.openxmlformats.org",
        "www.khronos.org",
        "ns.adobe.com",
        "purl.org",
        "creativecommons.org",
    }
)
# Loopback / this-host names that are not exfiltration destinations.
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "::1"})


def entropy(data: bytes) -> float:
    """Shannon entropy of `data` in bits per byte (0.0 .. 8.0)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def host_of(url: str) -> str | None:
    """Extract the lowercased hostname from a URL (no scheme required)."""
    candidate = url.strip()
    try:
        netloc = urlsplit(candidate).netloc or urlsplit("//" + candidate).netloc
    except ValueError:
        return None
    host = netloc.split("@")[-1].split(":")[0].strip().lower().rstrip(".")
    return host or None


def domains_from_urls(urls: list[str]) -> set[str]:
    """Hostnames declared by the author (from project.json's external URLs)."""
    out: set[str] = set()
    for u in urls:
        h = host_of(u)
        if h:
            out.add(h)
    return out


def host_is_declared(host: str, allowed: set[str]) -> bool:
    """True if `host` equals or is a subdomain of any allowed/benign domain."""
    if host in LOCAL_HOSTS or host in BENIGN_HOSTS:
        return True
    return any(host == d or host.endswith("." + d) for d in allowed)


def scan_common_iocs(
    text: str,
    name: str,
    allowed_domains: set[str],
    config: StaticConfig = DEFAULT_CONFIG,
) -> list[Finding]:
    """Scan an arbitrary text blob (script source, or strings joined out of a
    binary) for the IOCs that are independent of file type: Steam session
    theft, crypto wallets, encoded PowerShell, LOLBins, and network
    destinations not declared in project.json.
    """
    findings: list[Finding] = []

    steam = sorted({m.group(0) for m in STEAM_CRED_RE.finditer(text)})
    if steam:
        findings.append(
            Finding(
                code="ioc_steam_session_theft",
                severity=Severity.HIGH,
                message=(
                    "reference to Steam session/credential files "
                    f"({', '.join(steam)}); no legitimate wallpaper needs these"
                ),
                path=name,
            )
        )

    wallets: list[str] = []
    for rex in _WALLET_RES:
        wallets += rex.findall(text)
    if wallets:
        sample = ", ".join(sorted(set(wallets))[:3])
        findings.append(
            Finding(
                code="ioc_crypto_wallet_address",
                severity=Severity.MEDIUM,
                message=f"hardcoded cryptocurrency wallet address(es): {sample}",
                path=name,
            )
        )

    if PS_ENCODED_RE.search(text):
        findings.append(
            Finding(
                code="ioc_encoded_powershell",
                severity=Severity.MEDIUM,
                message="encoded/hidden PowerShell invocation",
                path=name,
            )
        )

    lolbins = sorted({m.group(1).lower() for m in LOLBIN_RE.finditer(text)})
    if lolbins:
        findings.append(
            Finding(
                code="ioc_lolbin_reference",
                severity=Severity.LOW,
                message=f"living-off-the-land binary reference(s): {', '.join(lolbins)}",
                path=name,
            )
        )

    # Network destinations vs the author's declared allowlist.
    undeclared: list[str] = []
    for url in URL_RE.findall(text):
        h = host_of(url)
        if h and not host_is_declared(h, allowed_domains) and h not in undeclared:
            undeclared.append(h)
    for host in undeclared[: config.max_undeclared_host_findings]:
        findings.append(
            Finding(
                code="network_undeclared_domain",
                severity=Severity.MEDIUM,
                message=f"references domain '{host}' not declared in project.json",
                path=name,
            )
        )

    # Raw IPv4 literals (skip the ones already covered as local hosts).
    ips = sorted(
        {ip for ip in IPV4_RE.findall(text) if ip not in LOCAL_HOSTS}
    )
    if ips:
        findings.append(
            Finding(
                code="ioc_hardcoded_ip",
                severity=Severity.LOW,
                message=f"hardcoded IP address(es): {', '.join(ips[:5])}",
                path=name,
            )
        )

    return findings
