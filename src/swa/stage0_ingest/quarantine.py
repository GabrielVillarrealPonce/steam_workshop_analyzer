"""Copy a Workshop item to quarantine, with a manifest and inventory.

Invariants (see docs/plan-etapas-0-1.md):
- Never write to the Steam folder: we COPY to quarantine, never move.
- Compute each file's SHA-256 before any other operation.
- The manifest is Stage 1's input contract and the forensic evidence.
"""

from __future__ import annotations

import hashlib
import shutil
from datetime import datetime, timezone
from pathlib import Path

from swa.config import QUARANTINE_ROOT
from swa.models import FileEntry, WorkshopItem
from swa.stage1_triage.filetype import detect


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _iter_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*") if p.is_file())


def compute_content_hash(source_dir: str | Path) -> str:
    """Hash of the item's whole content (detects updates).

    Computed over the sorted list of (relative path, size, sha256) so it is
    stable and independent of the filesystem's traversal order.
    """
    root = Path(source_dir)
    h = hashlib.sha256()
    for f in _iter_files(root):
        rel = f.relative_to(root).as_posix()
        line = f"{rel}\0{f.stat().st_size}\0{_sha256_file(f)}\n"
        h.update(line.encode("utf-8"))
    return h.hexdigest()


def ingest(
    workshop_id: str,
    source_dir: str | Path,
    metadata: dict | None = None,
    quarantine_root: str | Path = QUARANTINE_ROOT,
) -> WorkshopItem:
    """Copy the item to quarantine and return the WorkshopItem with its manifest.

    Structure created:
        <quarantine_root>/<workshop_id>/<timestamp>/
            raw/          faithful copy of the content
            metadata.json
            manifest.json
    """
    source = Path(source_dir)
    if not source.is_dir():
        raise FileNotFoundError(f"The item directory does not exist: {source}")

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    qdir = Path(quarantine_root) / workshop_id / ts
    raw = qdir / "raw"
    raw.mkdir(parents=True, exist_ok=True)

    entries: list[FileEntry] = []
    for f in _iter_files(source):
        rel = f.relative_to(source)
        target = raw / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, target)  # file-by-file copy, not a blind copytree
        entries.append(
            FileEntry(
                path=rel.as_posix(),
                size=target.stat().st_size,
                sha256=_sha256_file(target),
                filetype=detect(target),
                declared_ext=f.suffix.lower(),
            )
        )

    content_hash = compute_content_hash(source)
    item = WorkshopItem(
        workshop_id=workshop_id,
        content_hash=content_hash,
        quarantine_dir=str(qdir),
        files=entries,
        metadata=metadata or {},
    )

    item.write_manifest(str(qdir / "manifest.json"))
    _write_json(qdir / "metadata.json", item.metadata)
    return item


def _write_json(path: Path, data: dict) -> None:
    import json

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
