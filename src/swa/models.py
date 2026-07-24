"""Data models shared across stages.

These types are the contract between Stage 0 (ingest -> manifest) and Stage 1
(triage -> verdict), and what Stage 2 will consume. Changing them here changes
the contract for the whole pipeline.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class FileType(str, Enum):
    """Real type of a file, detected by magic bytes (never by extension)."""

    PE = "pe"  # Windows executable/DLL
    ELF = "elf"
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    HTML = "html"
    JAVASCRIPT = "javascript"
    LUA = "lua"
    JSON = "json"
    TEXT = "text"
    ZIP = "zip"  # zip / rar / 7z and other compressed containers
    PKG = "pkg"  # Wallpaper Engine proprietary container (PKGV0001)
    ENCRYPTED_ARCHIVE = "encrypted_archive"  # password-protected archive
    UNKNOWN = "unknown"

    # Types that can execute code -> never auto-approved.
    @property
    def is_executable_risk(self) -> bool:
        return self in {
            FileType.PE,
            FileType.ELF,
            FileType.JAVASCRIPT,
            FileType.LUA,
            FileType.HTML,
            FileType.ENCRYPTED_ARCHIVE,
        }


class Verdict(str, Enum):
    """A stage's decision about an item."""

    APPROVE = "approve"  # safe format, end of pipeline
    ANALYZE_STATIC = "analyze_static"  # pass on to Stage 2
    SANDBOX_REQUIRED = "sandbox_required"  # Stage 2 + Stage 3 mandatory
    ESCALATE = "escalate"  # anomaly; needs review
    BLOCK = "block"  # immediate block


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Finding:
    """A concrete finding for the final report."""

    code: str  # stable slug, e.g. "type_mismatch"
    severity: Severity
    message: str
    path: str | None = None  # relative path within the item, if applicable

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class FileEntry:
    """A file inside a wallpaper package."""

    path: str  # relative path; .pkg entries use "scene.pkg!internal/foo"
    size: int
    sha256: str
    filetype: FileType
    declared_ext: str  # declared extension, used to detect disguises

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["filetype"] = self.filetype.value
        return d


@dataclass
class WorkshopItem:
    """A quarantined Workshop item, with its inventory and metadata."""

    workshop_id: str
    content_hash: str  # hash of the whole content (detects updates)
    quarantine_dir: str
    files: list[FileEntry] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "workshop_id": self.workshop_id,
            "content_hash": self.content_hash,
            "quarantine_dir": self.quarantine_dir,
            "files": [f.to_dict() for f in self.files],
            "metadata": self.metadata,
        }

    def write_manifest(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, ensure_ascii=False)


@dataclass
class TriageResult:
    """Stage 1 output (Stage 2's input contract)."""

    workshop_id: str
    verdict: Verdict
    declared_type: str | None
    observed_types: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    files_to_analyze: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "workshop_id": self.workshop_id,
            "verdict": self.verdict.value,
            "declared_type": self.declared_type,
            "observed_types": self.observed_types,
            "findings": [f.to_dict() for f in self.findings],
            "files_to_analyze": self.files_to_analyze,
        }

    def write(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, ensure_ascii=False)
