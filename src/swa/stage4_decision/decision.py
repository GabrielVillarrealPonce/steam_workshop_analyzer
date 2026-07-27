"""The Stage 4 output type: a final Decision, handed to Stage 5."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import Finding, Verdict


@dataclass
class Decision:
    """Final verdict produced by Stage 4, consumed by Stage 5.

    `verdict` is restricted in practice to Verdict.APPROVE, Verdict.ESCALATE,
    or Verdict.BLOCK -- the other Verdict members (ANALYZE_STATIC,
    SANDBOX_REQUIRED) are intermediate routing signals from Stage 1 and are
    never a final answer.
    """

    workshop_id: str
    verdict: Verdict
    score: int
    reasons: list[str] = field(default_factory=list)
    triggering_findings: list[Finding] = field(default_factory=list)

    @property
    def is_blocked(self) -> bool:
        return self.verdict == Verdict.BLOCK

    @property
    def requires_manual_review(self) -> bool:
        return self.verdict == Verdict.ESCALATE

    def to_dict(self) -> dict[str, Any]:
        return {
            "workshop_id": self.workshop_id,
            "verdict": self.verdict.value,
            "score": self.score,
            "reasons": list(self.reasons),
            "triggering_findings": [f.to_dict() for f in self.triggering_findings],
        }
