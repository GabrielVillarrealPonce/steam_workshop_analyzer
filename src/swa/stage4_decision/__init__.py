"""Stage 4 -- Motor de decision (decision engine).

Public API:

    decide(triage, static_findings, dynamic_findings, dynamic_executed) -> Decision

`Decision` is the final, deterministic verdict (APPROVE / ESCALATE / BLOCK)
computed from the evidence the agent gathered via Stage 1/2/3 tools. See
`engine.py` for the rule ladder and its reasoning.
"""

from .config import DEFAULT_CONFIG, DecisionConfig
from .decision import Decision
from .engine import decide

__all__ = ["decide", "Decision", "DecisionConfig", "DEFAULT_CONFIG"]
