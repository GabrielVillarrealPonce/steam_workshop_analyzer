"""Stage 2 -- Analisis estatico de scripts y binarios.

Owner: TBD (teammate). Not yet implemented -- inspects the specific files
Stage 1 flagged in `TriageResult.files_to_analyze` (PE headers, JS/Lua source)
and returns a list of `swa.models.Finding`.

Until this is built, `analyze()` returns a single MEDIUM finding saying static
analysis is unavailable, rather than silently returning an empty (falsely
reassuring) list. See `swa.stage4_decision`: a MEDIUM finding nudges the
decision engine toward ESCALATE instead of a false APPROVE for any item where
Stage 1 actually flagged files worth analyzing -- the pipeline degrades to
"ask a human" rather than "assume it's fine" when a stage is missing.
"""

from __future__ import annotations

from ..models import Finding, Severity


def analyze(workshop_id: str, files_to_analyze: list[str]) -> list[Finding]:
    """Run static analysis on the given files. STUB: not yet implemented."""
    if not files_to_analyze:
        return []
    return [
        Finding(
            code="static_analysis_not_implemented",
            severity=Severity.MEDIUM,
            message=(
                f"Stage 2 static analysis is not implemented yet; "
                f"{len(files_to_analyze)} flagged file(s) were not inspected."
            ),
        )
    ]
