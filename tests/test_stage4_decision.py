"""Unit tests for Stage 4 -- decision engine.

Built against the real `swa.models` contract (Finding/Severity/TriageResult/
Verdict) produced by Stage 1 triage, not an invented schema.
"""

from __future__ import annotations

import pytest

from swa.models import Finding, Severity, TriageResult, Verdict
from swa.stage4_decision import DecisionConfig, decide
from swa.stage4_decision.scoring import composite_score, score_findings


def triage_result(**kw) -> TriageResult:
    base = dict(
        workshop_id="42",
        verdict=Verdict.APPROVE,
        declared_type="image",
        observed_types=["image"],
        findings=[],
        files_to_analyze=[],
    )
    base.update(kw)
    return TriageResult(**base)


def finding(severity: Severity, code: str = "test_code") -> Finding:
    return Finding(code=code, severity=severity, message="x")


# --- Rule 1/2: triage already terminal -------------------------------------

def test_triage_block_is_final():
    d = decide(triage_result(workshop_id="1", verdict=Verdict.BLOCK))
    assert d.verdict == Verdict.BLOCK


def test_triage_approve_with_nothing_else_is_final_approve():
    d = decide(triage_result(workshop_id="2", verdict=Verdict.APPROVE))
    assert d.verdict == Verdict.APPROVE
    assert "Safe format" in d.reasons[0]


# --- Rule 3: confirmed HIGH from static/dynamic blocks ----------------------

def test_high_from_triage_alone_does_not_auto_block():
    # A HIGH finding from triage is suspicion, not proof by itself.
    tr = triage_result(
        workshop_id="3",
        verdict=Verdict.ESCALATE,
        findings=[finding(Severity.HIGH, "type_mismatch")],
    )
    d = decide(tr)
    assert d.verdict != Verdict.BLOCK


def test_high_confirmed_by_static_analysis_blocks():
    tr = triage_result(workshop_id="4", verdict=Verdict.ANALYZE_STATIC)
    d = decide(tr, static_findings=[finding(Severity.HIGH, "known_stealer_pattern")])
    assert d.verdict == Verdict.BLOCK
    assert d.triggering_findings


def test_high_confirmed_by_dynamic_analysis_blocks():
    tr = triage_result(workshop_id="5", verdict=Verdict.SANDBOX_REQUIRED)
    d = decide(
        tr,
        dynamic_findings=[finding(Severity.HIGH, "credential_theft_confirmed")],
        dynamic_executed=True,
    )
    assert d.verdict == Verdict.BLOCK


# --- Rule 4: sandbox required but never run ---------------------------------

def test_sandbox_required_but_not_executed_escalates():
    tr = triage_result(workshop_id="6", verdict=Verdict.SANDBOX_REQUIRED)
    d = decide(tr, dynamic_executed=False)
    assert d.verdict == Verdict.ESCALATE


def test_sandbox_required_and_executed_clean_can_approve():
    tr = triage_result(workshop_id="7", verdict=Verdict.SANDBOX_REQUIRED)
    d = decide(tr, dynamic_findings=[], dynamic_executed=True)
    assert d.verdict == Verdict.APPROVE


# --- Rule 5/6/7: score thresholds ------------------------------------------

def test_high_composite_score_blocks():
    tr = triage_result(
        workshop_id="8",
        verdict=Verdict.ANALYZE_STATIC,
        findings=[finding(Severity.MEDIUM), finding(Severity.MEDIUM), finding(Severity.MEDIUM)],
    )
    d = decide(tr, static_findings=[finding(Severity.MEDIUM)])
    assert d.verdict == Verdict.BLOCK


def test_low_score_clean_approves():
    tr = triage_result(
        workshop_id="9",
        verdict=Verdict.ANALYZE_STATIC,
        findings=[finding(Severity.LOW)],
    )
    d = decide(tr, static_findings=[])
    assert d.verdict == Verdict.APPROVE


def test_medium_band_escalates():
    tr = triage_result(
        workshop_id="10",
        verdict=Verdict.ANALYZE_STATIC,
        findings=[finding(Severity.MEDIUM)],
    )
    d = decide(tr, static_findings=[finding(Severity.MEDIUM)])
    assert d.verdict == Verdict.ESCALATE


def test_custom_config_thresholds_apply():
    strict = DecisionConfig(block_score=15, approve_score=5)
    tr = triage_result(
        workshop_id="11",
        verdict=Verdict.ANALYZE_STATIC,
        findings=[finding(Severity.MEDIUM)],
    )
    d = decide(tr, config=strict)
    assert d.verdict == Verdict.BLOCK


# --- Scoring helpers ---------------------------------------------------------

def test_score_findings_saturates_at_100():
    findings = [finding(Severity.HIGH) for _ in range(3)]
    assert score_findings(findings) == 100


def test_composite_score_merges_multiple_lists():
    a = [finding(Severity.LOW)]
    b = [finding(Severity.MEDIUM)]
    c = [finding(Severity.HIGH)]
    assert composite_score(a, b, c) == 5 + 20 + 50


def test_decision_to_dict_keys():
    d = decide(triage_result(workshop_id="12", verdict=Verdict.APPROVE))
    keys = set(d.to_dict())
    assert keys == {"workshop_id", "verdict", "score", "reasons", "triggering_findings"}
