"""Synthetic fixtures for the tests.

None contain real harmful code: the "executables" are minimal, structurally
valid but inert PE headers. Each is generated in a tmp_path per test.
"""

from __future__ import annotations

import json
import struct
import zipfile
from pathlib import Path

import pytest


def make_pe_bytes() -> bytes:
    """Minimal, valid PE header (MZ + e_lfanew -> 'PE\\0\\0'). Inert."""
    stub = bytearray(b"MZ" + b"\x00" * 0x3E)
    e_lfanew = 0x40
    struct.pack_into("<I", stub, 0x3C, e_lfanew)
    return bytes(stub) + b"PE\x00\x00" + b"\x00" * 20


def make_pkg_bytes(entries: dict[str, bytes]) -> bytes:
    """Build a valid PKGV0001 container from {name: content}."""
    out = bytearray()
    out += struct.pack("<I", 8) + b"PKGV0001"
    out += struct.pack("<I", len(entries))
    blob = bytearray()
    table = bytearray()
    for name, content in entries.items():
        nb = name.encode("utf-8")
        table += struct.pack("<I", len(nb)) + nb
        table += struct.pack("<I", len(blob))  # offset relative to blob region
        table += struct.pack("<I", len(content))
        blob += content
    return bytes(out + table + blob)


def _write(root: Path, rel: str, data: bytes | str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        p.write_text(data, encoding="utf-8")
    else:
        p.write_bytes(data)


@pytest.fixture
def clean_video(tmp_path: Path) -> Path:
    root = tmp_path / "clean_video"
    _write(root, "project.json", json.dumps({"type": "video", "file": "bg.mp4", "title": "clean"}))
    # Minimal MP4: ....ftyp
    _write(root, "bg.mp4", b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 16)
    return root


@pytest.fixture
def video_with_disguised_pe(tmp_path: Path) -> Path:
    root = tmp_path / "video_pe"
    _write(root, "project.json", json.dumps({"type": "video", "file": "bg.mp4"}))
    _write(root, "bg.mp4", b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 16)
    _write(root, "assets/bg.dat", make_pe_bytes())  # disguised PE
    return root


@pytest.fixture
def scene_with_lua(tmp_path: Path) -> Path:
    root = tmp_path / "scene_lua"
    _write(root, "project.json", json.dumps({"type": "scene", "file": "scene.json"}))
    _write(root, "scene.json", json.dumps({"version": 1}))
    _write(root, "scripts/main.lua", "-- lua script\nlocal x = 1\n")
    return root


@pytest.fixture
def web_with_js(tmp_path: Path) -> Path:
    root = tmp_path / "web_js"
    _write(root, "project.json", json.dumps({"type": "web", "file": "index.html"}))
    _write(root, "index.html", "<!doctype html><html><body></body></html>")
    _write(root, "app.js", "console.log('hi');\n")
    return root


@pytest.fixture
def corrupt_project_json(tmp_path: Path) -> Path:
    root = tmp_path / "corrupt"
    _write(root, "project.json", "{ this is not valid json ")
    _write(root, "bg.mp4", b"\x00\x00\x00\x18ftypmp42")
    return root


@pytest.fixture
def scene_case_variant(tmp_path: Path) -> Path:
    """Reproduces the real item that declares 'Scene' capitalized and with a BOM."""
    root = tmp_path / "scene_case"
    body = json.dumps({"type": "Scene", "file": "scene.json"})
    _write(root, "project.json", "﻿" + body)  # UTF-8 BOM
    _write(root, "scene.json", json.dumps({"version": 1}))
    return root


@pytest.fixture
def zipslip_archive(tmp_path: Path) -> Path:
    """A .zip with a path-traversal entry."""
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../../evil.txt", "pwned")
        zf.writestr("harmless.txt", "ok")
    return archive
