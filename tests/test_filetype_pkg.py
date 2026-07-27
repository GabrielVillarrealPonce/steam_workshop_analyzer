"""Tests for type detection (magic bytes) and the .pkg container reader."""

from __future__ import annotations

import pytest

from swa.models import FileType
from swa.stage1_triage import pkg
from swa.stage1_triage.filetype import detect_bytes
from tests.conftest import make_pe_bytes, make_pkg_bytes


def test_detect_pe():
    assert detect_bytes(make_pe_bytes(), ".dat") is FileType.PE


def test_mz_without_pe_header_is_not_pe():
    # Starts with MZ but has no valid PE header -> must not be PE.
    assert detect_bytes(b"MZ" + b"\x00" * 100, ".dat") is not FileType.PE


def test_detect_media():
    assert detect_bytes(b"\x89PNG\r\n\x1a\n", ".png") is FileType.IMAGE
    assert detect_bytes(b"\x00\x00\x00\x18ftypmp42", ".mp4") is FileType.VIDEO


def test_detect_text_types():
    assert detect_bytes(b"console.log(1)", ".js") is FileType.JAVASCRIPT
    assert detect_bytes(b"<!doctype html>", ".html") is FileType.HTML
    assert detect_bytes(b'{"a":1}', ".json") is FileType.JSON


def test_pkg_roundtrip(tmp_path):
    data = make_pkg_bytes({"scene.json": b'{"v":1}', "scripts/a.lua": b"local x=1"})
    p = tmp_path / "scene.pkg"
    p.write_bytes(data)
    entries = pkg.list_entries(p)
    names = {e.name for e in entries}
    assert names == {"scene.json", "scripts/a.lua"}
    lua = next(e for e in entries if e.name == "scripts/a.lua")
    assert lua.filetype is FileType.LUA


def test_pkg_rejects_traversal(tmp_path):
    data = make_pkg_bytes({"../evil.txt": b"x"})
    p = tmp_path / "bad.pkg"
    p.write_bytes(data)
    with pytest.raises(pkg.PkgFormatError):
        pkg.list_entries(p)


def test_pkg_rejects_bad_magic(tmp_path):
    p = tmp_path / "nope.pkg"
    p.write_bytes(b"\x08\x00\x00\x00NOTPKGV1")
    with pytest.raises(pkg.PkgFormatError):
        pkg.list_entries(p)
