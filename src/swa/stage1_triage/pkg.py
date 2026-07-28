"""Reader for Wallpaper Engine's proprietary container (PKGV0001 format).

It is not a ZIP. Structure confirmed against real Workshop samples:

    [u32 = 8]["PKGV0001"][u32 entry_count]
      per entry:  [u32 name_len][name utf-8][u32 offset][u32 size]
    [blob region]    # offset is relative to the start of this region

Entry names are relative paths (models/foo.json, shaders/effects/bar.vert), so
they are a path-traversal vector if they are ever extracted to disk. Here we
NEVER extract: we read each blob's leading bytes in memory to classify its
real type.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from swa.config import MAX_PKG_ENTRIES, MAX_PKG_NAME_LEN
from swa.models import FileType
from swa.stage1_triage.filetype import detect_bytes

import re

# The signature is "PKGV" + a 4-digit version. Versions PKGV0001..PKGV0022 have
# been observed in the Workshop with an identical header layout; we only
# validate the prefix and that the version is numeric.
_MAGIC_LEN = 8
_MAGIC_RE = re.compile(rb"^PKGV\d{4}$")
_SNIFF_BYTES = 64  # bytes read from each blob to classify it


class PkgFormatError(ValueError):
    """The .pkg container is malformed or not a PKGV0001."""


@dataclass
class PkgEntry:
    name: str  # internal relative path
    offset: int  # relative to the start of the blob region
    size: int
    filetype: FileType


def _read_u32(data: bytes, pos: int) -> tuple[int, int]:
    if pos + 4 > len(data):
        raise PkgFormatError("Read out of range while parsing .pkg header")
    (val,) = struct.unpack_from("<I", data, pos)
    return val, pos + 4


def list_entries(path: str | Path) -> list[PkgEntry]:
    """Enumerate a .pkg's entries without extracting anything to disk.

    Validates aggressively: any inconsistency (magic, counters, offsets/sizes
    outside the file, names with traversal) raises PkgFormatError so triage
    treats it as ESCALATE, not as a crash.
    """
    data = Path(path).read_bytes()
    pos = 0

    magic_len, pos = _read_u32(data, pos)
    if magic_len != _MAGIC_LEN or not _MAGIC_RE.match(data[pos : pos + magic_len]):
        raise PkgFormatError("PKGV#### signature missing or invalid")
    pos += magic_len

    entry_count, pos = _read_u32(data, pos)
    if not (0 <= entry_count <= MAX_PKG_ENTRIES):
        raise PkgFormatError(f"entry_count out of range: {entry_count}")

    raw: list[tuple[str, int, int]] = []
    for _ in range(entry_count):
        name_len, pos = _read_u32(data, pos)
        if not (0 < name_len <= MAX_PKG_NAME_LEN) or pos + name_len > len(data):
            raise PkgFormatError(f"invalid name_len: {name_len}")
        name = data[pos : pos + name_len].decode("utf-8", errors="replace")
        pos += name_len
        offset, pos = _read_u32(data, pos)
        size, pos = _read_u32(data, pos)

        # Reject traversal or absolute paths already in the listing.
        norm = name.replace("\\", "/")
        if norm.startswith("/") or ".." in norm.split("/") or ":" in name:
            raise PkgFormatError(f"Entry name with path traversal: {name!r}")
        raw.append((name, offset, size))

    # `pos` now marks the start of the blob region.
    blob_base = pos
    entries: list[PkgEntry] = []
    for name, offset, size in raw:
        start = blob_base + offset
        end = start + size
        if offset < 0 or size < 0 or end > len(data):
            raise PkgFormatError(
                f"Entry {name!r} points outside the file (offset={offset}, size={size})"
            )
        sniff = data[start : start + _SNIFF_BYTES]
        ftype = detect_bytes(sniff, Path(name).suffix)
        entries.append(PkgEntry(name=name, offset=offset, size=size, filetype=ftype))

    return entries
