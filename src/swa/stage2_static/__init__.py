"""Stage 2 -- Analisis estatico de scripts y binarios.

Static analysis of the specific files Stage 1 triage flagged
(`TriageResult.files_to_analyze`): PE headers (signature, packing, suspicious
imports), script source (JS/Lua/HTML: eval, obfuscation, sandbox-escape,
undeclared network destinations), extracted binary strings (Steam session
paths, C2 URLs, wallets, LOLBins), system-library impersonation
(the AggregatorHost.dll case), and password-protected archives whose password
is stashed in a filename or config file.

Nothing here executes the sample -- it only reads and parses files, which is
exactly what makes Stage 2 safe to run on the analyst host (unlike Stage 3).

Public API:

    analyze(item, files_to_analyze, config=DEFAULT_CONFIG) -> list[Finding]

Severity is calibrated to swa.stage4_decision's scoring: HIGH is reserved for
indicators a legitimate wallpaper has no reason to contain (and blocks
outright); merely suspicious traits stay MEDIUM/LOW so corroboration, not a
single heuristic, drives a block. See indicators.py for the full rationale.
"""

from .analysis import analyze
from .config import DEFAULT_CONFIG, StaticConfig

__all__ = ["analyze", "StaticConfig", "DEFAULT_CONFIG"]
