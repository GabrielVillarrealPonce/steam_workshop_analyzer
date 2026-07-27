"""Safe extraction of untrusted nested archives.

Wallpaper Engine delivers already-extracted trees, but a package may contain
inner .zip/.rar files. This module guards against:
- path traversal / zip-slip (entries like "../../evil", absolute paths, symlinks)
- reserved Windows names (CON, NUL, AUX, COM1...)
- zip-bomb (entry count, total size, compression ratio)

Password-protected archives are NOT opened: they are detected and reported,
because their mere presence is already a high-severity IOC (Kaspersky pattern).
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from swa.config import (
    MAX_COMPRESSION_RATIO,
    MAX_EXTRACT_ENTRIES,
    MAX_EXTRACT_TOTAL_BYTES,
)

# Reserved device names on Windows (regardless of extension).
_RESERVED_WIN = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


class UnsafeArchiveError(ValueError):
    """The archive tries to write outside the destination or exceeds the limits."""


@dataclass
class ExtractResult:
    extracted: list[str] = field(default_factory=list)
    password_protected: bool = False
    skipped_reason: str | None = None


def _is_safe_member_name(name: str) -> bool:
    """True if `name` is a safe relative path within the destination."""
    norm = name.replace("\\", "/")
    if not norm or norm.startswith("/") or ":" in name:
        return False  # absolute path or drive letter
    parts = norm.split("/")
    if ".." in parts:
        return False
    for part in parts:
        if not part or part in (".",):
            continue
        stem = part.split(".")[0].lower()
        if stem in _RESERVED_WIN:
            return False
    return True


def _has_encrypted_entries(zf: zipfile.ZipFile) -> bool:
    # Bit 0x1 of flag_bits indicates encryption in the ZIP format.
    return any(info.flag_bits & 0x1 for info in zf.infolist())


def extract_zip(archive_path: str | Path, dest_dir: str | Path) -> ExtractResult:
    """Extract a .zip safely into `dest_dir`.

    Validates every member BEFORE writing; on any unsafe entry it aborts having
    written nothing outside the destination. Does not open encrypted archives.
    """
    dest = Path(dest_dir).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    result = ExtractResult()

    try:
        zf = zipfile.ZipFile(archive_path)
    except zipfile.BadZipFile as exc:
        result.skipped_reason = f"invalid ZIP: {exc}"
        return result

    with zf:
        if _has_encrypted_entries(zf):
            result.password_protected = True
            result.skipped_reason = "password-protected archive (not extracted)"
            return result

        infos = zf.infolist()
        if len(infos) > MAX_EXTRACT_ENTRIES:
            raise UnsafeArchiveError(f"too many entries: {len(infos)}")

        total = 0
        for info in infos:
            total += info.file_size
            if total > MAX_EXTRACT_TOTAL_BYTES:
                raise UnsafeArchiveError("uncompressed size exceeds the limit")
            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > MAX_COMPRESSION_RATIO:
                    raise UnsafeArchiveError(
                        f"suspicious compression ratio ({ratio:.0f}x) in {info.filename}"
                    )
            if not _is_safe_member_name(info.filename):
                raise UnsafeArchiveError(f"unsafe entry: {info.filename!r}")
            # Final check: the resolved path stays within the destination.
            target = (dest / info.filename).resolve()
            if not target.is_relative_to(dest):
                raise UnsafeArchiveError(f"path traversal: {info.filename!r}")

        # Only after validating ALL entries is anything written.
        for info in infos:
            if info.is_dir():
                continue
            target = (dest / info.filename).resolve()
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                out.write(src.read())
            result.extracted.append(info.filename)

    return result
