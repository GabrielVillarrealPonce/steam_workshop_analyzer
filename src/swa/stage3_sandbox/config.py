"""Configuration for Stage 3 (dynamic sandbox).

The single most important default here is `backend="null"`: out of the box,
Stage 3 executes nothing. A real detonation backend (CAPEv2, or a replay of a
report captured on dedicated infrastructure) is opt-in and only takes effect
when an operator explicitly configures it -- because detonating untrusted code
must happen on isolated, dedicated infrastructure, never as a silent default
on whatever host the pipeline runs on (design doc sections 2 and 7).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# Backend identifiers.
BACKEND_NULL = "null"  # never executes -> executed=False -> ESCALATE at Stage 4
BACKEND_REPLAY = "replay"  # analyse a pre-captured report (no execution here)
BACKEND_CAPEV2 = "capev2"  # submit to an external, dedicated CAPEv2 instance


@dataclass(frozen=True)
class SandboxConfig:
    # Which backend to use. Default is the safe no-op.
    backend: str = BACKEND_NULL

    # Observation window. The doc recommends at least several minutes because
    # part of the campaign's malware delays its payload to evade sandboxes.
    timeout_seconds: int = 300

    # Polling of an external sandbox for task completion.
    poll_interval_seconds: int = 15
    max_wait_seconds: int = 1800

    # ReplayBackend: path to a normalized SandboxReport JSON to analyse.
    replay_path: str | None = None

    # CapeV2Backend: base URL (e.g. https://cape.internal) and API token of a
    # dedicated instance. Absent -> the backend cannot run and degrades to
    # executed=False rather than executing anything locally.
    cape_base_url: str | None = None
    cape_token: str | None = None

    # Behavioural heuristics (used by the report analyser).
    # Sustained CPU% consistent with a cryptominer.
    mining_cpu_threshold: float = 85.0
    # Number of user files rewritten that reads as mass encryption (ransomware).
    ransomware_min_files: int = 50

    @classmethod
    def from_env(cls) -> "SandboxConfig":
        """Build config from environment variables (all optional)."""

        def _int(name: str, default: int) -> int:
            raw = os.environ.get(name)
            try:
                return int(raw) if raw is not None else default
            except ValueError:
                return default

        def _float(name: str, default: float) -> float:
            raw = os.environ.get(name)
            try:
                return float(raw) if raw is not None else default
            except ValueError:
                return default

        return cls(
            backend=os.environ.get("SWA_SANDBOX_BACKEND", BACKEND_NULL).strip().lower(),
            timeout_seconds=_int("SWA_SANDBOX_TIMEOUT", 300),
            poll_interval_seconds=_int("SWA_SANDBOX_POLL_INTERVAL", 15),
            max_wait_seconds=_int("SWA_SANDBOX_MAX_WAIT", 1800),
            replay_path=os.environ.get("SWA_SANDBOX_REPLAY"),
            cape_base_url=os.environ.get("SWA_SANDBOX_CAPE_URL"),
            cape_token=os.environ.get("SWA_SANDBOX_CAPE_TOKEN"),
            mining_cpu_threshold=_float("SWA_SANDBOX_MINING_CPU", 85.0),
            ransomware_min_files=_int("SWA_SANDBOX_RANSOMWARE_FILES", 50),
        )


DEFAULT_CONFIG = SandboxConfig()
