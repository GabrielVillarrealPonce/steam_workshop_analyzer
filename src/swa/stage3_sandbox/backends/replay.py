"""Replay a behavioural report captured elsewhere.

Detonation happened on dedicated infrastructure (a CAPEv2/ANY.RUN/Joe run);
its output was normalized to the SandboxReport schema and saved to disk. This
backend just loads and returns it -- no execution here at all. That makes the
full pipeline (including a dynamic-evidence BLOCK) demonstrable and testable
without any live sandbox, and is also how you'd wire in offline/batch sandbox
output.

The report path comes from `config.replay_path`; a report keyed to a different
workshop_id is rejected (returns None) so a stale file can't be mistaken for
this item's run.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from ...models import WorkshopItem
from ..config import BACKEND_REPLAY, SandboxConfig
from ..report import SandboxReport


class ReplayBackend:
    name = BACKEND_REPLAY

    def run(self, item: WorkshopItem, config: SandboxConfig) -> SandboxReport | None:
        if not config.replay_path:
            print(
                "stage3 replay: no replay_path configured (SWA_SANDBOX_REPLAY)",
                file=sys.stderr,
            )
            return None
        path = Path(config.replay_path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"stage3 replay: cannot read report {path}: {exc}", file=sys.stderr)
            return None

        report = SandboxReport.from_dict(data)
        # Guard against replaying another item's report.
        if report.workshop_id and report.workshop_id != item.workshop_id:
            print(
                f"stage3 replay: report is for {report.workshop_id!r}, "
                f"not {item.workshop_id!r}; refusing",
                file=sys.stderr,
            )
            return None
        report.workshop_id = item.workshop_id
        report.backend = self.name
        return report
