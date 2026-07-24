"""Real type detection by magic bytes.

The extension is never trusted: the critical case is a PE with an innocuous
extension (.dat, .png, no extension). Detection is based on the file's leading
bytes and, for PE, on validating the "PE\\0\\0" header pointed to by e_lfanew.
"""

from __future__ import annotations

import struct
from pathlib import Path

from swa.models import FileType

# How many header bytes to read for classification.
_HEADER_BYTES = 4096


def _looks_like_pe(data: bytes) -> bool:
    """True if `data` is a real Windows PE executable (not just 'MZ')."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    # e_lfanew is at offset 0x3C: it points to the PE header.
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if e_lfanew + 4 > len(data):
        return False
    return data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"


def _looks_like_zip(data: bytes) -> bool:
    # PK\x03\x04 (local file), PK\x05\x06 (empty), PK\x07\x08 (spanned).
    return data[:2] == b"PK" and data[2:4] in (b"\x03\x04", b"\x05\x06", b"\x07\x08")


def _is_probably_text(data: bytes) -> bool:
    if not data:
        return False
    # Simple heuristic: no null bytes and mostly printable/utf-8 decodable.
    if b"\x00" in data[:1024]:
        return False
    try:
        data[:1024].decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def _classify_text(data: bytes, ext: str) -> FileType:
    """Refine a text file by declared extension + content."""
    head = data[:1024].lstrip().lower()
    if ext in (".html", ".htm") or head.startswith((b"<!doctype html", b"<html")):
        return FileType.HTML
    if ext == ".js":
        return FileType.JAVASCRIPT
    if ext == ".lua":
        return FileType.LUA
    if ext == ".json" or head[:1] in (b"{", b"["):
        return FileType.JSON
    return FileType.TEXT


def detect_bytes(data: bytes, declared_ext: str = "") -> FileType:
    """Classify from an already-read byte header."""
    ext = declared_ext.lower()

    if _looks_like_pe(data):
        return FileType.PE
    if data[:4] == b"\x7fELF":
        return FileType.ELF
    if data[:8] == b"\x08\x00\x00\x00PKGV":
        return FileType.PKG

    # Images.
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return FileType.IMAGE
    if data[:3] == b"\xff\xd8\xff":  # JPEG
        return FileType.IMAGE
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return FileType.IMAGE
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return FileType.IMAGE
    if data[:2] == b"BM":  # BMP
        return FileType.IMAGE

    # Video / audio.
    if data[4:8] == b"ftyp":  # MP4 and ISO-BMFF variants
        return FileType.VIDEO
    if data[:4] == b"\x1aE\xdf\xa3":  # Matroska / WebM
        return FileType.VIDEO
    if data[:4] == b"RIFF" and data[8:12] == b"AVI ":
        return FileType.VIDEO
    if data[:3] == b"ID3" or data[:2] in (b"\xff\xfb", b"\xff\xf3"):
        return FileType.AUDIO

    if _looks_like_zip(data):
        return FileType.ZIP

    if _is_probably_text(data):
        return _classify_text(data, ext)

    return FileType.UNKNOWN


def detect(path: str | Path) -> FileType:
    """Classify a file on disk by its content."""
    p = Path(path)
    with open(p, "rb") as fh:
        data = fh.read(_HEADER_BYTES)
    return detect_bytes(data, p.suffix)
