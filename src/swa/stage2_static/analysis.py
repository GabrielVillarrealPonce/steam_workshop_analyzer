"""Stage 2 orchestrator: dispatch each flagged file to the right detector.

`analyze()` is the single public entry point (the MCP `run_static_analysis`
tool calls it). It takes the same WorkshopItem Stage 0 produced plus the
`files_to_analyze` list Stage 1 triage flagged, inspects exactly those files,
and returns a list of `swa.models.Finding` for the decision engine.

Design mirrors stage1_triage.triage: a thin orchestrator over focused modules
(pe, scripts, strings, archives, indicators). It never trusts a path blindly
(traversal-guarded against the quarantine root), bounds every read, and
isolates per-file failures so one malformed file can't abort the whole stage.
"""

from __future__ import annotations

from pathlib import Path

from ..models import FileEntry, FileType, Finding, Severity, WorkshopItem
from ..stage1_triage import project_json
from ..stage1_triage.filetype import detect
from . import archives, indicators, pe, scripts, strings
from .config import DEFAULT_CONFIG, StaticConfig

_SCRIPT_TYPES = {FileType.JAVASCRIPT, FileType.LUA, FileType.HTML}

# Ordering for a stable, most-severe-first result.
_SEV_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2, Severity.INFO: 3}


def _allowed_domains(root: Path) -> set[str]:
    """Domains the author declared in project.json -- the network allowlist."""
    info = project_json.parse(root / "project.json")
    return indicators.domains_from_urls(info.external_urls)


def _resolve_in_root(root: Path, rel: str) -> Path | None:
    """Resolve `rel` under `root`, refusing anything that escapes it."""
    candidate = (root / rel)
    try:
        resolved = candidate.resolve()
        root_resolved = root.resolve()
    except OSError:
        return None
    if not resolved.is_relative_to(root_resolved):
        return None
    if not resolved.is_file():
        return None
    return resolved


def _read(path: Path, config: StaticConfig) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(config.max_scan_bytes)


def analyze(
    item: WorkshopItem,
    files_to_analyze: list[str],
    config: StaticConfig = DEFAULT_CONFIG,
) -> list[Finding]:
    """Run Stage 2 static analysis over the flagged files of an item."""
    if not files_to_analyze:
        return []

    root = Path(item.quarantine_dir) / "raw"
    allowed = _allowed_domains(root)
    by_path: dict[str, FileEntry] = {f.path: f for f in item.files}

    findings: list[Finding] = []
    encrypted_paths: list[str] = []

    for rel in files_to_analyze:
        path = _resolve_in_root(root, rel)
        if path is None:
            findings.append(
                Finding(
                    code="file_unavailable",
                    severity=Severity.INFO,
                    message="flagged file is missing or outside the quarantine root",
                    path=rel,
                )
            )
            continue

        entry = by_path.get(rel)
        ftype = entry.filetype if entry else detect(path)

        # System-library impersonation (the AggregatorHost.dll case): a PE that
        # bears the name of a Windows system library has no place in untrusted
        # Workshop content and cannot be the genuine OS copy.
        if ftype in (FileType.PE, FileType.ELF) and (
            Path(rel).name.lower() in indicators.SYSTEM_DLL_NAMES
        ):
            findings.append(
                Finding(
                    code="ioc_system_library_impersonation",
                    severity=Severity.HIGH,
                    message=(
                        f"binary named after a Windows system library "
                        f"('{Path(rel).name}') shipped inside Workshop content"
                    ),
                    path=rel,
                )
            )

        try:
            findings.extend(_dispatch(path, rel, ftype, allowed, config, encrypted_paths))
        except Exception as exc:  # never let one file abort the stage
            findings.append(
                Finding(
                    code="static_analysis_error",
                    severity=Severity.LOW,
                    message=f"analysis failed for this file: {exc}",
                    path=rel,
                )
            )

    if encrypted_paths:
        findings.extend(
            archives.detect_embedded_password(item, encrypted_paths, root, config)
        )

    return _dedup_sorted(findings)


def _dispatch(
    path: Path,
    rel: str,
    ftype: FileType,
    allowed: set[str],
    config: StaticConfig,
    encrypted_paths: list[str],
) -> list[Finding]:
    if ftype is FileType.ENCRYPTED_ARCHIVE:
        encrypted_paths.append(rel)
        return []

    if ftype in _SCRIPT_TYPES:
        text = _read(path, config).decode("utf-8-sig", errors="replace")
        return scripts.analyze_script(text, rel, ftype, allowed, config)

    data = _read(path, config)
    out: list[Finding] = []
    if ftype is FileType.PE:
        out += pe.analyze_pe(data, rel, config)
    # Strings/IOC scan applies to every binary-ish flagged file (PE, ELF, and
    # any other non-script content that reached here).
    out += strings.scan_binary(data, rel, allowed, config)
    return out


def _dedup_sorted(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str | None, str]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.code, f.path, f.message)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    unique.sort(key=lambda f: (_SEV_ORDER[f.severity], f.code, f.path or ""))
    return unique
