"""Stage 3 -- Sandbox dinamico (dynamic behavioural analysis).

This stage observes what a wallpaper *does* when run, which static analysis
cannot guarantee (packed code, conditional logic, anti-analysis). Executing
untrusted code safely requires dedicated, isolated infrastructure (hypervisor,
disposable snapshots, simulated network with honeytoken Steam credentials);
that infrastructure is out of scope here and MUST NOT be improvised on a
general-purpose host (design doc sections 2 and 7).

What this package provides is the safe, complete integration + analysis layer:

  * a backend abstraction with three implementations --
      - NullBackend   (default): never executes; executed=False -> ESCALATE
      - ReplayBackend: analyse a report captured on dedicated infra (no exec)
      - CapeV2Backend: submit to an external, dedicated CAPEv2 instance
  * a normalized behavioural-report schema (report.py) every backend targets
  * the signal analyser (signals.py): design doc 7.2 mapped to Finding objects,
    severity-calibrated to swa.stage4_decision (confirmed HIGH behaviours --
    C2, credential theft, dropped exe, ransomware, injection, Defender-disable
    -- block outright).

Public API:

    detonate(item, config=None) -> (findings, executed)

`config` defaults to SandboxConfig.from_env(), so the backend is selected via
environment variables without code changes; the default is NullBackend.
"""

from .config import (
    BACKEND_CAPEV2,
    BACKEND_NULL,
    BACKEND_REPLAY,
    DEFAULT_CONFIG,
    SandboxConfig,
)
from .detonate import detonate
from .report import SandboxReport
from .signals import analyze_report

__all__ = [
    "detonate",
    "analyze_report",
    "SandboxReport",
    "SandboxConfig",
    "DEFAULT_CONFIG",
    "BACKEND_NULL",
    "BACKEND_REPLAY",
    "BACKEND_CAPEV2",
]
