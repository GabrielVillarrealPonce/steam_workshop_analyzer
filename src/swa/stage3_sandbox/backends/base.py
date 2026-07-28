"""The sandbox backend interface.

A backend's one job: given a quarantined item, produce a normalized
SandboxReport (or None if it could not run). It must NEVER execute untrusted
code on the analysis host itself -- either it drives dedicated, isolated
infrastructure (CAPEv2 over its API), it replays a report captured on such
infrastructure, or it does nothing (NullBackend). That invariant is what keeps
Stage 3 safe to import and call from anywhere in the pipeline.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ...models import WorkshopItem
from ..config import SandboxConfig
from ..report import SandboxReport


@runtime_checkable
class SandboxBackend(Protocol):
    #: Stable identifier, echoed into the report's `backend` field.
    name: str

    def run(self, item: WorkshopItem, config: SandboxConfig) -> SandboxReport | None:
        """Detonate `item` (on isolated infra) and return its report, or None
        if detonation was not possible. Must not raise on operational failure:
        return None so the pipeline degrades to 'not executed' (ESCALATE),
        never a false clean."""
        ...
