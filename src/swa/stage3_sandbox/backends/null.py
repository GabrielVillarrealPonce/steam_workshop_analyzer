"""The default backend: never executes anything.

This is the safe out-of-the-box behaviour. It reports that no dynamic analysis
ran (executed=False), which swa.stage4_decision treats as "cannot clear an
application-type item" -> ESCALATE, rather than silently skipping the check or,
worse, pretending the item came back clean. An operator who wants real dynamic
analysis opts in by configuring a real backend and dedicated infrastructure.
"""

from __future__ import annotations

from ...models import WorkshopItem
from ..config import BACKEND_NULL, SandboxConfig
from ..report import SandboxReport


class NullBackend:
    name = BACKEND_NULL

    def run(self, item: WorkshopItem, config: SandboxConfig) -> SandboxReport | None:
        return SandboxReport(
            workshop_id=item.workshop_id, executed=False, backend=self.name
        )
