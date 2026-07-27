"""Tests for Stage 3 -- dynamic sandbox integration + behavioural analysis.

Nothing here executes anything: the NullBackend never runs, and every
behavioural signal is exercised by feeding the analyser a normalized report
(the same shape a real CAPEv2/ANY.RUN run would be reduced to). The ReplayBackend
path shows the full pipeline reaching a dynamic-evidence verdict with no live
sandbox involved.
"""

from __future__ import annotations

import json
from pathlib import Path

from swa.models import TriageResult, Verdict, WorkshopItem
from swa.stage3_sandbox import (
    BACKEND_NULL,
    BACKEND_REPLAY,
    SandboxConfig,
    SandboxReport,
    analyze_report,
    detonate,
)
from swa.stage3_sandbox.backends import NullBackend, select_backend
from swa.stage3_sandbox.backends.capev2 import normalize_cape_report
from swa.stage4_decision import decide
from swa.models import Severity


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def make_item(tmp_path: Path, project: dict | None = None) -> WorkshopItem:
    root = tmp_path / "raw"
    root.mkdir(parents=True, exist_ok=True)
    if project is not None:
        (root / "project.json").write_text(json.dumps(project), encoding="utf-8")
    return WorkshopItem(
        workshop_id="ws1", content_hash="h", quarantine_dir=str(tmp_path), files=[]
    )


def report(**kw) -> SandboxReport:
    base: dict = {"workshop_id": "ws1", "executed": True, "backend": "test"}
    base.update(kw)
    return SandboxReport.from_dict(base)


def codes(findings) -> set[str]:
    return {f.code for f in findings}


def sev(findings, code) -> Severity:
    return next(f.severity for f in findings if f.code == code)


# --------------------------------------------------------------------------- #
# Backend selection / null default
# --------------------------------------------------------------------------- #

def test_default_backend_is_null():
    assert isinstance(select_backend(SandboxConfig()), NullBackend)


def test_unknown_backend_falls_back_to_null():
    assert isinstance(select_backend(SandboxConfig(backend="bogus")), NullBackend)


def test_null_backend_does_not_execute(tmp_path):
    findings, executed = detonate(make_item(tmp_path), SandboxConfig(backend=BACKEND_NULL))
    assert findings == []
    assert executed is False


def test_not_executed_escalates_sandbox_required(tmp_path):
    findings, executed = detonate(make_item(tmp_path), SandboxConfig(backend=BACKEND_NULL))
    tr = TriageResult(workshop_id="ws1", verdict=Verdict.SANDBOX_REQUIRED, declared_type="application")
    d = decide(tr, dynamic_findings=findings, dynamic_executed=executed)
    assert d.verdict is Verdict.ESCALATE


# --------------------------------------------------------------------------- #
# Network signals
# --------------------------------------------------------------------------- #

def test_undeclared_domain_medium():
    r = report(network=[{"kind": "http", "host": "evil.tld", "url": "http://evil.tld/x"}])
    f = analyze_report(r, allowed_domains=set())
    assert "dyn_network_undeclared" in codes(f)
    assert sev(f, "dyn_network_undeclared") is Severity.MEDIUM


def test_declared_domain_suppressed():
    r = report(network=[{"kind": "http", "host": "cdn.trusted.com"}])
    assert "dyn_network_undeclared" not in codes(analyze_report(r, allowed_domains={"trusted.com"}))


def test_newly_registered_domain_is_c2_high():
    r = report(network=[{"kind": "dns", "host": "kj23s.top", "newly_registered": True}])
    f = analyze_report(r, allowed_domains=set())
    assert "dyn_c2_connection" in codes(f)
    assert sev(f, "dyn_c2_connection") is Severity.HIGH


def test_direct_ip_connection_medium():
    r = report(network=[{"kind": "tcp", "ip": "45.9.148.10"}])
    assert "dyn_direct_ip_connection" in codes(analyze_report(r, allowed_domains=set()))


# --------------------------------------------------------------------------- #
# Filesystem / process / registry / resources
# --------------------------------------------------------------------------- #

def test_steam_credential_access_high():
    r = report(files=[{"op": "read", "path": "C:\\Program Files\\Steam\\config\\loginusers.vdf"}])
    f = analyze_report(r)
    assert sev(f, "dyn_steam_credential_access") is Severity.HIGH


def test_dropped_executable_high():
    r = report(files=[{"op": "write", "path": "C:\\Users\\x\\AppData\\a.exe", "is_executable": True}])
    assert sev(analyze_report(r), "dyn_dropped_executable") is Severity.HIGH


def test_sensitive_write_medium():
    r = report(files=[{"op": "write", "path": "C:\\Windows\\System32\\evil.dat"}])
    assert sev(analyze_report(r), "dyn_write_sensitive_location") is Severity.MEDIUM


def test_process_injection_high():
    r = report(processes=[{"op": "inject", "name": "wp.exe", "target": "explorer.exe", "detail": "CreateRemoteThread"}])
    assert sev(analyze_report(r), "dyn_process_injection") is Severity.HIGH


def test_security_process_kill_high():
    r = report(processes=[{"op": "terminate", "name": "wp.exe", "target": "MsMpEng.exe"}])
    assert sev(analyze_report(r), "dyn_security_process_kill") is Severity.HIGH


def test_child_process_spawn_medium():
    r = report(processes=[{"op": "create", "name": "cmd.exe"}])
    assert sev(analyze_report(r), "dyn_child_process_spawn") is Severity.MEDIUM


def test_autostart_persistence_medium():
    r = report(registry=[{"op": "set", "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x"}])
    assert sev(analyze_report(r), "dyn_autostart_persistence") is Severity.MEDIUM


def test_defender_tampering_high():
    r = report(registry=[{"op": "set", "key": "HKLM\\...\\Windows Defender\\DisableAntiSpyware", "value": "1"}])
    assert sev(analyze_report(r), "dyn_security_tampering") is Severity.HIGH


def test_ransomware_behavior_high():
    r = report(resources={"files_encrypted": 200})
    assert sev(analyze_report(r), "dyn_ransomware_behavior") is Severity.HIGH


def test_mining_cpu_medium_gpu_ignored():
    r = report(resources={"cpu_avg": 96.0, "gpu_avg": 99.0})
    f = analyze_report(r)
    assert "dyn_resource_mining" in codes(f)
    # GPU alone must never be flagged (wallpapers are GPU-heavy by nature).
    r2 = report(resources={"cpu_avg": 5.0, "gpu_avg": 99.0})
    assert "dyn_resource_mining" not in codes(analyze_report(r2))


def test_signature_mapping():
    r = report(signatures=["Ransomware_Generic", "anti-vm trick", "Unknown_Thing"])
    f = analyze_report(r)
    assert sev(f, "dyn_sig_ransomware") is Severity.HIGH
    assert sev(f, "dyn_sig_anti_vm") is Severity.LOW
    assert "dyn_sandbox_signature" in codes(f)


def test_findings_sorted_high_first():
    r = report(
        network=[{"kind": "dns", "host": "kj.top", "newly_registered": True}],
        processes=[{"op": "create", "name": "cmd.exe"}],
    )
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    sevs = [order[f.severity.value] for f in analyze_report(r)]
    assert sevs == sorted(sevs)


# --------------------------------------------------------------------------- #
# Report parsing robustness
# --------------------------------------------------------------------------- #

def test_from_dict_tolerates_garbage():
    r = SandboxReport.from_dict({"workshop_id": "x", "network": "nope", "files": [42, {"path": "a"}]})
    assert r.network == []
    assert len(r.files) == 1  # the non-dict entry is skipped


# --------------------------------------------------------------------------- #
# ReplayBackend end-to-end + decision engine
# --------------------------------------------------------------------------- #

def _write_report(tmp_path: Path, data: dict) -> str:
    p = tmp_path / "report.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def test_replay_malicious_report_blocks(tmp_path):
    path = _write_report(tmp_path, {
        "workshop_id": "ws1",
        "executed": True,
        "files": [{"op": "read", "path": "steam\\config\\loginusers.vdf"}],
    })
    item = make_item(tmp_path)
    findings, executed = detonate(item, SandboxConfig(backend=BACKEND_REPLAY, replay_path=path))
    assert executed is True
    tr = TriageResult(workshop_id="ws1", verdict=Verdict.SANDBOX_REQUIRED, declared_type="application")
    d = decide(tr, dynamic_findings=findings, dynamic_executed=executed)
    assert d.verdict is Verdict.BLOCK


def test_replay_clean_report_can_approve(tmp_path):
    path = _write_report(tmp_path, {"workshop_id": "ws1", "executed": True})
    item = make_item(tmp_path)
    findings, executed = detonate(item, SandboxConfig(backend=BACKEND_REPLAY, replay_path=path))
    assert executed is True and findings == []
    tr = TriageResult(workshop_id="ws1", verdict=Verdict.SANDBOX_REQUIRED, declared_type="application")
    d = decide(tr, dynamic_findings=findings, dynamic_executed=executed)
    assert d.verdict is Verdict.APPROVE


def test_replay_wrong_workshop_id_refused(tmp_path):
    path = _write_report(tmp_path, {"workshop_id": "OTHER", "executed": True})
    findings, executed = detonate(make_item(tmp_path), SandboxConfig(backend=BACKEND_REPLAY, replay_path=path))
    assert executed is False and findings == []


def test_replay_uses_project_json_allowlist(tmp_path):
    # A domain the author declared must not be flagged as undeclared.
    item = make_item(tmp_path, project={"type": "web", "cdn": "https://trusted.com/app.js"})
    path = _write_report(tmp_path, {
        "workshop_id": "ws1", "executed": True,
        "network": [{"kind": "http", "host": "trusted.com"}, {"kind": "http", "host": "evil.tld"}],
    })
    findings, executed = detonate(item, SandboxConfig(backend=BACKEND_REPLAY, replay_path=path))
    hosts_flagged = {f.path for f in findings if f.code == "dyn_network_undeclared"}
    assert "evil.tld" in hosts_flagged
    assert "trusted.com" not in hosts_flagged


# --------------------------------------------------------------------------- #
# CAPE report normalizer (pure)
# --------------------------------------------------------------------------- #

def test_normalize_cape_report():
    raw = {
        "info": {"id": 7},
        "network": {
            "dns": [{"request": "bad.tld"}],
            "http": [{"uri": "http://bad.tld/p", "host": "bad.tld", "port": 80}],
            "hosts": ["8.8.8.8"],
        },
        "behavior": {
            "summary": {
                "write_files": ["C:\\a.exe"],
                "write_keys": [
                    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil"
                ],
            },
            "processes": [{"process_name": "cmd.exe"}],
        },
        "signatures": [{"name": "injection_generic"}],
        "dropped": [{"filepath": "C:\\b.dll", "type": "PE32 executable"}],
    }
    norm = normalize_cape_report(raw, "ws1")
    r = SandboxReport.from_dict(norm)
    f = analyze_report(r)
    c = codes(f)
    assert "dyn_dropped_executable" in c        # C:\a.exe write + b.dll dropped
    assert "dyn_network_undeclared" in c        # bad.tld
    assert "dyn_autostart_persistence" in c     # Run key
    assert "dyn_child_process_spawn" in c       # cmd.exe
    assert "dyn_sig_injection" in c             # signature
