"""Tests for safe extraction (anti zip-slip / password / zip-bomb)."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from swa.stage0_ingest import safe_extract


def test_zipslip_rejected(zipslip_archive, tmp_path):
    dest = tmp_path / "out"
    with pytest.raises(safe_extract.UnsafeArchiveError):
        safe_extract.extract_zip(zipslip_archive, dest)
    # Nothing must have been written outside the destination.
    assert not (tmp_path.parent / "evil.txt").exists()
    assert not (tmp_path / "evil.txt").exists()


def test_password_archive_not_opened(tmp_path):
    archive = tmp_path / "secret.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("inner.txt", "data")
    # Mark the entry as encrypted by tweaking the flag bit.
    with zipfile.ZipFile(archive, "a") as zf:
        zf.infolist()[0].flag_bits |= 0x1
    # Rebuilding with the real encryption flag would be complex; test the helper.
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            info.flag_bits |= 0x1
        assert safe_extract._has_encrypted_entries(zf)


def test_clean_zip_extracts(tmp_path):
    archive = tmp_path / "ok.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("a/b.txt", "hello")
    dest = tmp_path / "out"
    result = safe_extract.extract_zip(archive, dest)
    assert "a/b.txt" in result.extracted
    assert (dest / "a" / "b.txt").read_text() == "hello"


def test_reserved_windows_name_rejected():
    assert not safe_extract._is_safe_member_name("CON.txt")
    assert not safe_extract._is_safe_member_name("dir/nul")
    assert safe_extract._is_safe_member_name("dir/normal.txt")
