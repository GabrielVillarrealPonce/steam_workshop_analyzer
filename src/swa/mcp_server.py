"""Local MCP server: exposes Stage 1/2/3/4/5 as tools an LLM agent can call.

Runs over stdio (no network exposure needed -- your machine only, which is
what "we only use free credits" implies: no hosting costs, no remote server
to secure). Start it directly for manual testing:

    python -m swa.mcp_server

`swa.agent` (the orchestrator) spawns this as a subprocess and talks to it
over stdio; it is never invoked by a person directly in normal operation.

Design note on tool granularity: Stage 0 (ingest) is deliberately NOT exposed
as a tool. Downloading/scanning doesn't require reasoning -- `swa.agent` runs
it as plain code before the LLM conversation even starts, and hands the
resulting manifest to the model as context. This keeps the agent loop
(and its token cost) focused on the steps that actually need judgement:
triage, static/dynamic analysis, deciding, and responding.
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from . import stage2_static, stage3_sandbox
from .models import Finding, Severity, TriageResult, Verdict, WorkshopItem
from .stage1_triage import triage as triage_mod
from .stage4_decision import decide as decide_fn
from .stage5_response import respond as respond_fn
from .state import State

mcp = FastMCP("steam-workshop-analyzer")


def _load_item(quarantine_dir: str) -> WorkshopItem:
    """Rebuild a WorkshopItem from the manifest.json Stage 0 wrote."""
    manifest_path = Path(quarantine_dir) / "manifest.json"
    with open(manifest_path, encoding="utf-8") as fh:
        raw = json.load(fh)
    from .models import FileEntry, FileType

    files = [
        FileEntry(
            path=f["path"],
            size=f["size"],
            sha256=f["sha256"],
            filetype=FileType(f["filetype"]),
            declared_ext=f["declared_ext"],
        )
        for f in raw["files"]
    ]
    return WorkshopItem(
        workshop_id=raw["workshop_id"],
        content_hash=raw["content_hash"],
        quarantine_dir=raw["quarantine_dir"],
        files=files,
        metadata=raw.get("metadata", {}),
    )


def _findings_from_dicts(raw: list[dict]) -> list[Finding]:
    return [
        Finding(
            code=f["code"],
            severity=Severity(f["severity"]),
            message=f["message"],
            path=f.get("path"),
        )
        for f in raw
    ]


@mcp.tool()
def run_triage(quarantine_dir: str) -> dict:
    """Run Stage 1 triage on an already-ingested item.

    `quarantine_dir` is the directory Stage 0 ingested the item into (it
    contains manifest.json and the extracted files under raw/). Returns the
    TriageResult: a verdict (approve/analyze_static/sandbox_required/
    escalate/block), the list of findings, and which files are worth
    analyzing further.
    """
    item = _load_item(quarantine_dir)
    result = triage_mod.triage(item)
    return result.to_dict()


@mcp.tool()
def run_static_analysis(quarantine_dir: str, files_to_analyze: list[str]) -> dict:
    """Run Stage 2 static analysis on specific flagged files.

    Pass the `files_to_analyze` list from a prior `run_triage` call. Returns
    a list of findings. NOTE: Stage 2 is not implemented yet by the team --
    this currently returns a single MEDIUM finding saying so, rather than an
    empty list, so the decision engine doesn't mistake "not analyzed" for
    "confirmed clean."
    """
    item = _load_item(quarantine_dir)
    findings = stage2_static.analyze(item.workshop_id, files_to_analyze)
    return {"findings": [f.to_dict() for f in findings]}


@mcp.tool()
def run_sandbox(quarantine_dir: str) -> dict:
    """Run Stage 3 dynamic sandbox analysis.

    NOTE: Stage 3 is not implemented yet -- this is a design-only stub (see
    the architecture doc for the CAPEv2/Cuckoo integration spec). It never
    executes anything and always reports executed=False, which the decision
    engine treats as "cannot clear an application-type item," not as a clean
    result.
    """
    item = _load_item(quarantine_dir)
    findings, executed = stage3_sandbox.detonate(item.workshop_id)
    return {"findings": [f.to_dict() for f in findings], "executed": executed}


@mcp.tool()
def decide(
    quarantine_dir: str,
    triage_result: dict,
    static_findings: list[dict] | None = None,
    dynamic_findings: list[dict] | None = None,
    dynamic_executed: bool = False,
) -> dict:
    """Compute the FINAL verdict (Stage 4). Call this once you have gathered
    whatever evidence you judged necessary -- you MUST call this before
    `finalize`, and you must not state a verdict yourself in prose before
    calling it. This function is deterministic and reproducible: it is the
    actual source of truth for approve/escalate/block, not your own reasoning.

    `triage_result` is the dict returned by `run_triage`. `static_findings`
    and `dynamic_findings` are the `findings` lists returned by
    `run_static_analysis` / `run_sandbox`, if you called them (omit if you
    didn't run that stage).
    """
    tr = TriageResult(
        workshop_id=triage_result["workshop_id"],
        verdict=Verdict(triage_result["verdict"]),
        declared_type=triage_result.get("declared_type"),
        observed_types=triage_result.get("observed_types", []),
        findings=_findings_from_dicts(triage_result.get("findings", [])),
        files_to_analyze=triage_result.get("files_to_analyze", []),
    )
    decision = decide_fn(
        tr,
        static_findings=_findings_from_dicts(static_findings or []),
        dynamic_findings=_findings_from_dicts(dynamic_findings or []),
        dynamic_executed=dynamic_executed,
    )
    return decision.to_dict()


@mcp.tool()
def finalize(quarantine_dir: str, decision: dict) -> str:
    """Stage 5 -- MANDATORY last call. Persists the decision from `decide`
    and returns the exact message to show the user. You must call this tool
    to end the analysis; do not compose the final message yourself -- return
    this tool's output verbatim as your final answer, so the user-facing
    report always matches what was actually recorded.
    """
    import sys

    from .stage4_decision import Decision

    item = _load_item(quarantine_dir)
    dec = Decision(
        workshop_id=decision["workshop_id"],
        verdict=Verdict(decision["verdict"]),
        score=decision["score"],
        reasons=decision.get("reasons", []),
        triggering_findings=_findings_from_dicts(decision.get("triggering_findings", [])),
    )
    try:
        with State() as st:
            return respond_fn(dec, item, state=st)
    except Exception as exc:  # sqlite can fail on some filesystems/mounts;
        # losing the "skip unchanged items on rescan" optimization is far
        # better than losing the verdict itself.
        print(f"warning: could not persist to state DB ({exc}); continuing", file=sys.stderr)
        return respond_fn(dec, item, state=None)


if __name__ == "__main__":
    mcp.run()
