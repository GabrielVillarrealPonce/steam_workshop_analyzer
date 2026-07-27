"""Backend registry and selection.

`select_backend` maps a config's backend name to an instance, defaulting to the
safe NullBackend for anything unknown -- an operator misconfiguring the name
gets "nothing executed" (ESCALATE), never accidental execution.
"""

from __future__ import annotations

import sys

from ..config import BACKEND_CAPEV2, BACKEND_NULL, BACKEND_REPLAY, SandboxConfig
from .base import SandboxBackend
from .capev2 import CapeV2Backend
from .null import NullBackend
from .replay import ReplayBackend

__all__ = [
    "SandboxBackend",
    "NullBackend",
    "ReplayBackend",
    "CapeV2Backend",
    "select_backend",
]


def select_backend(config: SandboxConfig) -> SandboxBackend:
    if config.backend == BACKEND_NULL:
        return NullBackend()
    if config.backend == BACKEND_REPLAY:
        return ReplayBackend()
    if config.backend == BACKEND_CAPEV2:
        return CapeV2Backend()
    print(
        f"stage3: unknown backend {config.backend!r}; falling back to NullBackend",
        file=sys.stderr,
    )
    return NullBackend()
