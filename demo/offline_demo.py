"""Offline demo runner -- the full pipeline WITHOUT the LLM (deterministic).

This is a SAFETY NET for the live demo: if the venue network or the Anthropic
API is unavailable, run this instead of `swa analyze` to show the exact same
stages and the exact same final verdict, computed deterministically (the
verdict engine, Stage 4, is a plain function -- it never depends on the LLM).

    python demo/offline_demo.py demo/steam_stealer
    python demo/offline_demo.py tests/fixtures/web_con_descarga

Optional dynamic stage: set SWA_SANDBOX_BACKEND=replay and SWA_SANDBOX_REPLAY
to a normalized report to include Stage 3 evidence.
"""

from __future__ import annotations

import sys
from pathlib import Path

from swa.stage0_ingest import quarantine
from swa.stage1_triage import triage as triage_mod
from swa import stage2_static, stage3_sandbox
from swa.stage4_decision import decide
from swa.stage5_response import respond


def main(path: str) -> int:
    source = Path(path)
    if not source.is_dir():
        print(f"error: not a directory: {source}", file=sys.stderr)
        return 2

    print(f"\n=== Analyzing: {source.name} ===\n")

    # Stage 0 -- ingest into quarantine (never touch the original).
    item = quarantine.ingest(source.name, source, metadata={}, quarantine_root=Path("quarantine"))
    print(f"[Stage 0] ingested {len(item.files)} file(s) into quarantine")

    # Stage 1 -- format triage.
    tr = triage_mod.triage(item)
    print(f"[Stage 1] triage verdict: {tr.verdict.value}")
    if tr.files_to_analyze:
        print(f"          files to analyze: {', '.join(tr.files_to_analyze)}")

    # Stage 2 -- static analysis of the flagged files.
    static = stage2_static.analyze(item, tr.files_to_analyze)
    print(f"[Stage 2] static findings: {len(static)}")
    for f in static:
        print(f"          [{f.severity.value.upper():6}] {f.code}: {f.message}")

    # Stage 3 -- dynamic sandbox (only if a backend is configured; default: none).
    dynamic, executed = stage3_sandbox.detonate(item)
    print(f"[Stage 3] executed: {executed}, findings: {len(dynamic)}")
    for f in dynamic:
        print(f"          [{f.severity.value.upper():6}] {f.code}: {f.message}")

    # Stage 4 -- deterministic final verdict.
    decision = decide(tr, static_findings=static, dynamic_findings=dynamic, dynamic_executed=executed)
    print(f"\n[Stage 4] FINAL VERDICT: {decision.verdict.value.upper()}  (risk score {decision.score})")

    # Stage 5 -- the user-facing report.
    print("\n[Stage 5] report to the user:\n")
    print(respond(decision, item, state=None))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python demo/offline_demo.py <wallpaper-directory>", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
