"""Tests for the triage engine (Stage 1) over synthetic fixtures."""

from __future__ import annotations

from pathlib import Path

from swa.models import Verdict
from swa.stage0_ingest import quarantine
from swa.stage1_triage import triage as triage_mod


def _triage_dir(source: Path, tmp_path: Path) -> "TriageResult":
    qroot = tmp_path / "q"
    item = quarantine.ingest(source.name, source, metadata={}, quarantine_root=qroot)
    return triage_mod.triage(item)


def test_clean_video_approved(clean_video, tmp_path):
    r = _triage_dir(clean_video, tmp_path)
    assert r.verdict is Verdict.APPROVE
    assert r.declared_type == "video"


def test_disguised_pe_escalates(video_with_disguised_pe, tmp_path):
    r = _triage_dir(video_with_disguised_pe, tmp_path)
    assert r.verdict is Verdict.ESCALATE
    codes = {f.code for f in r.findings}
    assert "disguised_executable" in codes
    assert "type_mismatch" in codes
    assert any(f.severity.value == "high" for f in r.findings)


def test_scene_analyze_static(scene_with_lua, tmp_path):
    r = _triage_dir(scene_with_lua, tmp_path)
    assert r.verdict is Verdict.ANALYZE_STATIC


def test_web_analyze_static(web_with_js, tmp_path):
    r = _triage_dir(web_with_js, tmp_path)
    assert r.verdict is Verdict.ANALYZE_STATIC


def test_corrupt_project_json_escalates(corrupt_project_json, tmp_path):
    r = _triage_dir(corrupt_project_json, tmp_path)
    assert r.verdict is Verdict.ESCALATE
    assert any(f.code == "project_json_unreadable" for f in r.findings)


def test_case_and_bom_handled(scene_case_variant, tmp_path):
    """'Scene' capitalized + BOM must be normalized and NOT escalate."""
    r = _triage_dir(scene_case_variant, tmp_path)
    assert r.declared_type == "scene"
    assert r.verdict is Verdict.ANALYZE_STATIC
