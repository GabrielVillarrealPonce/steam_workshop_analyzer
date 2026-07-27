"""Stage 1 triage engine.

Core rule: the verdict is the MAXIMUM of the risk declared in project.json and
the risk observed by real file inspection. The declared type is never enough to
approve; a mismatch (declares video but there is a PE) is itself a high-severity
IOC.
"""

from __future__ import annotations

from pathlib import Path

from swa.models import (
    FileEntry,
    FileType,
    Finding,
    Severity,
    TriageResult,
    Verdict,
    WorkshopItem,
)
from swa.stage1_triage import project_json
from swa.stage1_triage.pkg import PkgFormatError, list_entries

# Declared types considered "safe" (they do not execute code by themselves).
_SAFE_DECLARED = {"image", "video"}
# Declared types that require a mandatory dynamic sandbox.
_APPLICATION = {"application"}


def _pkg_findings(item_root: Path, entry: FileEntry) -> tuple[list[Finding], set[FileType]]:
    """Inspect an embedded .pkg: report scripts and format errors."""
    findings: list[Finding] = []
    observed: set[FileType] = set()
    pkg_path = item_root / entry.path
    try:
        for sub in list_entries(pkg_path):
            observed.add(sub.filetype)
            if sub.filetype in (FileType.JAVASCRIPT, FileType.LUA, FileType.HTML):
                findings.append(
                    Finding(
                        code="embedded_script",
                        severity=Severity.LOW,
                        message=f"script embedded in container: {sub.filetype.value}",
                        path=f"{entry.path}!{sub.name}",
                    )
                )
    except PkgFormatError as exc:
        findings.append(
            Finding(
                code="pkg_malformed",
                severity=Severity.MEDIUM,
                message=f"malformed .pkg container: {exc}",
                path=entry.path,
            )
        )
    return findings, observed


def triage(item: WorkshopItem) -> TriageResult:
    """Apply triage to an already-ingested WorkshopItem (with manifest)."""
    root = Path(item.quarantine_dir) / "raw"
    info = project_json.parse(root / "project.json")

    findings: list[Finding] = []
    observed_types: set[FileType] = set()
    files_to_analyze: list[str] = []

    # 1. Walk the manifest accumulating real types and files to analyze.
    for entry in item.files:
        ft = entry.filetype
        observed_types.add(ft)

        # Disguise: innocuous extension but executable content.
        if ft in (FileType.PE, FileType.ELF):
            expected_ext = ".exe" if ft is FileType.PE else ""
            if entry.declared_ext not in (".exe", ".dll", ".scr", ".sys"):
                findings.append(
                    Finding(
                        code="disguised_executable",
                        severity=Severity.HIGH,
                        message=f"{ft.value} executable with extension '{entry.declared_ext or 'none'}'",
                        path=entry.path,
                    )
                )
            files_to_analyze.append(entry.path)

        if ft is FileType.ENCRYPTED_ARCHIVE:
            findings.append(
                Finding(
                    code="password_protected_archive",
                    severity=Severity.HIGH,
                    message="password-protected archive embedded in the package",
                    path=entry.path,
                )
            )
            files_to_analyze.append(entry.path)

        if ft in (FileType.JAVASCRIPT, FileType.LUA, FileType.HTML):
            files_to_analyze.append(entry.path)

        if ft is FileType.PKG:
            pf, pobs = _pkg_findings(root, entry)
            findings.extend(pf)
            observed_types |= pobs

    # 2. Determine the observed risk from the real types.
    has_executable = any(
        t in (FileType.PE, FileType.ELF, FileType.ENCRYPTED_ARCHIVE)
        for t in observed_types
    )
    has_script = any(
        t in (FileType.JAVASCRIPT, FileType.LUA, FileType.HTML) for t in observed_types
    )

    declared = info.declared_type

    # 3. Unreadable project.json or unknown type -> escalate.
    if not info.is_readable:
        findings.append(
            Finding(
                code="project_json_unreadable",
                severity=Severity.MEDIUM,
                message=info.parse_error or "unreadable project.json",
                path="project.json",
            )
        )
        verdict = Verdict.ESCALATE
        return _result(item, verdict, declared, observed_types, findings, files_to_analyze)

    # 4. Apply the decision matrix (max of declared vs observed).
    verdict = _decide(declared, has_executable, has_script, findings)

    return _result(item, verdict, declared, observed_types, findings, files_to_analyze)


def _decide(
    declared: str | None,
    has_executable: bool,
    has_script: bool,
    findings: list[Finding],
) -> Verdict:
    # A present executable/encrypted archive dominates any declaration.
    if has_executable:
        if declared in _SAFE_DECLARED:
            findings.append(
                Finding(
                    code="type_mismatch",
                    severity=Severity.HIGH,
                    message=f"declares '{declared}' but contains executable code",
                )
            )
        if declared in _APPLICATION:
            return Verdict.SANDBOX_REQUIRED
        return Verdict.ESCALATE

    if declared in _APPLICATION:
        return Verdict.SANDBOX_REQUIRED

    if declared in _SAFE_DECLARED:
        # Declares image/video: only approved if there is nothing executable nor scripts.
        if has_script:
            findings.append(
                Finding(
                    code="type_mismatch",
                    severity=Severity.HIGH,
                    message=f"declares '{declared}' but contains scripts",
                )
            )
            return Verdict.ESCALATE
        return Verdict.APPROVE

    if declared in ("scene", "web"):
        return Verdict.ANALYZE_STATIC

    # Declared type absent or unknown.
    return Verdict.ESCALATE


def _result(
    item: WorkshopItem,
    verdict: Verdict,
    declared: str | None,
    observed_types: set[FileType],
    findings: list[Finding],
    files_to_analyze: list[str],
) -> TriageResult:
    return TriageResult(
        workshop_id=item.workshop_id,
        verdict=verdict,
        declared_type=declared,
        observed_types=sorted(t.value for t in observed_types),
        findings=findings,
        files_to_analyze=sorted(set(files_to_analyze)),
    )
