"""Stage 3 -- Sandbox dinamico (especificacion de integracion).

Owner: TBD (teammate). Not yet implemented -- see the design doc for the
integration spec (CAPEv2/Cuckoo, isolated VM, simulated network, honeytoken
Steam credentials). Detonating untrusted binaries must not happen on a
general-purpose host, so this stub deliberately never executes anything; it
reports that no dynamic analysis ran, which `swa.stage4_decision` treats as
"cannot clear an application-type item" (ESCALATE) rather than silently
skipping the check.
"""

from __future__ import annotations

from ..models import Finding


def detonate(workshop_id: str) -> tuple[list[Finding], bool]:
    """Run the sample in the sandbox. STUB: returns (no findings, executed=False)."""
    return [], False
