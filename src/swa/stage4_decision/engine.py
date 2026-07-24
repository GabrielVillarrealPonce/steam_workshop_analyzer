"""Stage 4 -- Motor de decision.

This is the mandatory step the agent calls once it has gathered whatever
evidence it decided it needed (Stage 1 triage always; Stage 2 static analysis
and/or Stage 3 sandbox only if the agent chose to run them as tools). It never
trusts the LLM's own free-text judgement for the actual approve/block call --
the LLM supplies the assembled evidence, this function supplies the verdict,
deterministically and reproducibly. The LLM's job downstream (Stage 5) is to
explain that verdict in plain language, not to invent it.

Decision ladder (first matching rule wins):

  1. Stage 1 triage already returned BLOCK               -> BLOCK
  2. Stage 1 triage returned APPROVE and nothing else was
     investigated                                        -> APPROVE
  3. Any HIGH-severity finding came from Stage 2 or Stage 3
     (i.e. *confirmed* by deeper analysis, not just triage
     suspicion)                                           -> BLOCK
  4. Triage said a sandbox run was required but it never
     ran                                                  -> ESCALATE
     (an application-type item can't be cleared without detonating it)
  5. Composite score over the block threshold             -> BLOCK
  6. Composite score at/under the approve threshold, and
     the dynamic run (if required) was clean              -> APPROVE
  7. Anything else (the ambiguous middle band)             -> ESCALATE
"""

from __future__ import annotations

from typing import Optional

from ..models import Finding, Severity, TriageResult, Verdict
from .config import DEFAULT_CONFIG, DecisionConfig
from .decision import Decision
from .scoring import composite_score


def decide(
    triage: TriageResult,
    static_findings: Optional[list[Finding]] = None,
    dynamic_findings: Optional[list[Finding]] = None,
    dynamic_executed: bool = False,
    config: DecisionConfig = DEFAULT_CONFIG,
) -> Decision:
    static_findings = static_findings or []
    dynamic_findings = dynamic_findings or []
    all_findings = list(triage.findings) + static_findings + dynamic_findings
    score = composite_score(triage.findings, static_findings, dynamic_findings)

    # 1. Triage already reached a terminal BLOCK.
    if triage.verdict == Verdict.BLOCK:
        return Decision(
            workshop_id=triage.workshop_id,
            verdict=Verdict.BLOCK,
            score=score,
            reasons=["Stage 1 triage already concluded BLOCK."],
            triggering_findings=all_findings,
        )

    # 2. Triage approved and nothing further was investigated -> done, cheaply.
    if triage.verdict == Verdict.APPROVE and not static_findings and not dynamic_findings:
        return Decision(
            workshop_id=triage.workshop_id,
            verdict=Verdict.APPROVE,
            score=score,
            reasons=["Safe format per Stage 1 triage; no further analysis was needed."],
        )

    # 3. A HIGH finding *confirmed* by static or dynamic analysis is conclusive.
    #    (A HIGH finding from triage alone is suspicion, not proof -- that's
    #    exactly why triage routes those cases onward instead of blocking.)
    confirmed_high = [
        f for f in static_findings + dynamic_findings if f.severity == Severity.HIGH
    ]
    if confirmed_high:
        codes = sorted({f.code for f in confirmed_high})
        return Decision(
            workshop_id=triage.workshop_id,
            verdict=Verdict.BLOCK,
            score=score,
            reasons=[f"Confirmed high-severity finding(s): {', '.join(codes)}."],
            triggering_findings=confirmed_high,
        )

    # 4. Triage demanded a sandbox run and the agent never did one -> can't clear it.
    if triage.verdict == Verdict.SANDBOX_REQUIRED and not dynamic_executed:
        return Decision(
            workshop_id=triage.workshop_id,
            verdict=Verdict.ESCALATE,
            score=score,
            reasons=[
                "Stage 1 triage required a dynamic sandbox run for this "
                "application-type item, but it was not executed; cannot "
                "confirm safety from static evidence alone."
            ],
            triggering_findings=all_findings,
        )

    # 5. Composite score over the block threshold, regardless of source.
    if score >= config.block_score:
        return Decision(
            workshop_id=triage.workshop_id,
            verdict=Verdict.BLOCK,
            score=score,
            reasons=[f"Composite risk score {score} >= block threshold {config.block_score}."],
            triggering_findings=all_findings,
        )

    # 6. Low score and, if a sandbox run was required, it came back clean.
    dynamic_clean = all(f.severity in (Severity.INFO, Severity.LOW) for f in dynamic_findings)
    sandbox_satisfied = triage.verdict != Verdict.SANDBOX_REQUIRED or (
        dynamic_executed and dynamic_clean
    )
    if score <= config.approve_score and sandbox_satisfied:
        return Decision(
            workshop_id=triage.workshop_id,
            verdict=Verdict.APPROVE,
            score=score,
            reasons=[
                f"Composite risk score {score} <= approve threshold "
                f"{config.approve_score}; no unresolved high-severity findings."
            ],
            triggering_findings=all_findings,
        )

    # 7. Ambiguous middle band -> flag for a human.
    return Decision(
        workshop_id=triage.workshop_id,
        verdict=Verdict.ESCALATE,
        score=score,
        reasons=[
            f"Composite risk score {score} falls between the approve "
            f"({config.approve_score}) and block ({config.block_score}) "
            "thresholds; flagged for manual review."
        ],
        triggering_findings=all_findings,
    )
