"""Stage 5 -- Respuesta al usuario.

Takes the Decision from Stage 4 and closes the loop: persists it (so re-scans
of an unchanged item skip straight to the recorded verdict, via `swa.state`),
writes a durable report next to the quarantined copy, and returns the
human-readable message the agent should show the user. This stage is
deliberately NOT an LLM call -- once a Decision exists, reporting it is
mechanical, and doing it in plain code means the "confirmed the wallpaper is
malicious" message can never be paraphrased away by the model into something
softer or missing the concrete reason.

Note on what "blocking" means here: Stage 0 already copies every item into
`quarantine_dir` for analysis, separate from Steam's own workshop content
folder -- Wallpaper Engine keeps loading the original from Steam's directory
regardless of what we do in quarantine. This project does not currently
modify or move the live Steam-managed folder (that risks fighting Steam's own
integrity checks / re-downloads); BLOCK means "recorded and reported to the
user," who then acts on it (e.g. unsubscribe in Steam). Actually renaming the
live item out of Wallpaper Engine's way is a reasonable follow-up feature, not
implemented here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ..models import Verdict, WorkshopItem
from ..stage4_decision import Decision
from ..state import State

_HEADLINE = {
    Verdict.APPROVE: "APPROVED",
    Verdict.ESCALATE: "NEEDS MANUAL REVIEW",
    Verdict.BLOCK: "BLOCKED",
}


def respond(decision: Decision, item: WorkshopItem, state: Optional[State] = None) -> str:
    """Persist the decision and return the message to show the user.

    If `state` is given, records the verdict against the item's content hash
    so unchanged items don't get re-analyzed on the next scan (mirrors the
    pattern Stage 0/1 already use in `swa.cli`).
    """
    report_path = Path(item.quarantine_dir) / "decision.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(decision.to_dict(), fh, indent=2, ensure_ascii=False)

    if state is not None:
        state.record(item.workshop_id, item.content_hash, decision.verdict.value)

    return format_message(decision, item)


def format_message(decision: Decision, item: WorkshopItem) -> str:
    headline = _HEADLINE.get(decision.verdict, decision.verdict.value.upper())
    lines = [f"[{headline}] workshop item {item.workshop_id} (risk score {decision.score}/100)"]
    for reason in decision.reasons:
        lines.append(f"  - {reason}")
    if decision.triggering_findings:
        lines.append("  Findings that drove this verdict:")
        for f in decision.triggering_findings:
            where = f" ({f.path})" if f.path else ""
            lines.append(f"    * [{f.severity.value}] {f.code}: {f.message}{where}")
    if decision.verdict == Verdict.BLOCK:
        lines.append(
            "  Action: this item was NOT released. Consider unsubscribing from "
            "it in the Steam Workshop."
        )
    elif decision.verdict == Verdict.ESCALATE:
        lines.append(
            "  Action: inconclusive -- a human should review the findings above "
            "before trusting this wallpaper."
        )
    return "\n".join(lines)
