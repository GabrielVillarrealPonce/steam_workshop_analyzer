"""Scoring helpers for Stage 4 (motor de decision).

Converts lists of `swa.models.Finding` (the real type produced by Stage 1
triage and, once built, Stage 2 static analysis / Stage 3 sandbox) into a
0-100 composite risk score.
"""

from __future__ import annotations

from typing import Iterable

from ..models import Finding, Severity

# Points contributed by a single finding, by severity. Severity in this
# project only goes up to HIGH (see swa.models.Severity) -- there is no
# separate CRITICAL tier, so a single HIGH finding does not automatically
# saturate the score on its own; corroboration across stages does.
SEVERITY_POINTS = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 20,
    Severity.HIGH: 50,
}

_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
}


def rank(severity: Severity) -> int:
    return _SEVERITY_RANK[severity]


def score_findings(findings: Iterable[Finding]) -> int:
    """Aggregate a list of findings into a 0-100 saturating score."""
    total = sum(SEVERITY_POINTS[f.severity] for f in findings)
    return min(100, total)


def max_severity(findings: Iterable[Finding]) -> Severity:
    """Highest severity among the findings (INFO if empty)."""
    highest = Severity.INFO
    for f in findings:
        if rank(f.severity) > rank(highest):
            highest = f.severity
    return highest


def composite_score(*finding_lists: Iterable[Finding]) -> int:
    """Combine findings from every stage (triage + static + dynamic) into one score.

    A plain sum across all findings, saturated at 100. Kept deliberately
    simple: corroboration naturally raises the score because more findings
    means more points, without needing a separate "agreement bonus" like an
    earlier draft of this module had -- that draft was written before the
    real Finding/Severity contract existed, and over-engineered a case this
    simpler model already covers.
    """
    all_findings: list[Finding] = []
    for lst in finding_lists:
        all_findings.extend(lst)
    return score_findings(all_findings)
