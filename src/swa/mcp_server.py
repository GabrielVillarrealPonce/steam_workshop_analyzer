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

Design note on state: each stage caches its result server-side, keyed by
`quarantine_dir` (see `_RUN_CACHE`). The agent therefore only ever passes a
`quarantine_dir` (and, for static analysis, the list of files to inspect) --
never the bulky evidence itself. Two payoffs: (1) every tool parameter is a
string or a list of strings, which every model's function-calling schema
handles cleanly; and (2) the decision is computed from the *actual* findings
each stage produced, not from anything the model hands back -- so adversarial
content inside a wallpaper cannot reshape the evidence on its way to `decide`.
The server is a fresh subprocess per analysis, so the cache is naturally
scoped to a single run.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# Keep the server's own request logging ("Processing request of type ...") off
# stderr so a live demo shows only the agent's reasoning and the final verdict.
logging.getLogger("mcp").setLevel(logging.WARNING)

from . import stage2_static, stage3_sandbox
from .models import Finding, TriageResult, WorkshopItem
from .stage1_triage import triage as triage_mod
from .stage4_decision import Decision
from .stage4_decision import decide as decide_fn
from .stage5_response import respond as respond_fn
from .state import State

mcp = FastMCP("steam-workshop-analyzer")


class _RunState:
    """Evidence gathered so far for one quarantined item, held in memory."""

    def __init__(self) -> None:
        self.triage: TriageResult | None = None
        self.static_findings: list[Finding] = []
        self.dynamic_findings: list[Finding] = []
        self.dynamic_executed: bool = False
        self.decision: Decision | None = None


# quarantine_dir -> evidence. One process per analysis run, so this stays
# scoped to a single item's lifecycle.
_RUN_CACHE: dict[str, _RunState] = {}


def _run_state(quarantine_dir: str) -> _RunState:
    return _RUN_CACHE.setdefault(quarantine_dir, _RunState())


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


@mcp.tool()
def run_triage(quarantine_dir: str) -> dict:
    """Run Stage 1 triage on an already-ingested item.

    `quarantine_dir` is the directory Stage 0 ingested the item into (it
    contains manifest.json and the extracted files under raw/). Returns the
    TriageResult: a verdict (approve/analyze_static/sandbox_required/
    escalate/block), the list of findings, and which files are worth
    analyzing further. The result is cached, so `decide` will read it
    automatically -- you do not need to pass it back.
    """
    item = _load_item(quarantine_dir)
    result = triage_mod.triage(item)
    _run_state(quarantine_dir).triage = result
    return result.to_dict()


@mcp.tool()
def run_static_analysis(quarantine_dir: str, files_to_analyze: list[str]) -> dict:
    """Run Stage 2 static analysis on specific flagged files.

    Pass the `files_to_analyze` list from a prior `run_triage` call. Inspects
    those files without executing anything -- PE headers (signature, packing,
    suspicious imports), script source (eval/obfuscation/sandbox-escape/
    undeclared network destinations), extracted binary strings (Steam session
    paths, C2 URLs, wallets), system-library impersonation, and
    password-protected archives with an embedded password. Returns a list of
    findings; HIGH-severity ones are treated as confirmed by the decision
    engine (`decide`) and block outright. The findings are cached for `decide`.
    """
    item = _load_item(quarantine_dir)
    findings = stage2_static.analyze(item, files_to_analyze)
    _run_state(quarantine_dir).static_findings = findings
    return {"findings": [f.to_dict() for f in findings]}


@mcp.tool()
def run_sandbox(quarantine_dir: str) -> dict:
    """Run Stage 3 dynamic sandbox analysis.

    Returns {findings, executed}. By default no backend is configured, so
    nothing is executed and executed=False -- the decision engine treats that
    as "cannot clear an application-type item" (ESCALATE), never a clean
    result. A real backend (an external CAPEv2 instance, or a replay of a
    report captured on dedicated infrastructure) is opt-in via environment
    (SWA_SANDBOX_BACKEND). Detonation never happens on this host; see
    swa.stage3_sandbox for the integration architecture. The findings are
    cached for `decide`.
    """
    item = _load_item(quarantine_dir)
    findings, executed = stage3_sandbox.detonate(item)
    state = _run_state(quarantine_dir)
    state.dynamic_findings = findings
    state.dynamic_executed = executed
    return {"findings": [f.to_dict() for f in findings], "executed": executed}


@mcp.tool()
def decide(quarantine_dir: str) -> dict:
    """Compute the FINAL verdict (Stage 4) from the evidence gathered so far.

    Call this once you have run whatever stages you judged necessary -- you
    MUST call `run_triage` before this, and you must not state a verdict
    yourself in prose before calling it. This function is deterministic and
    reproducible: it reads the cached triage/static/dynamic findings the tools
    actually produced (not anything you pass in) and is the actual source of
    truth for approve/escalate/block. The decision is cached for `finalize`.
    """
    state = _run_state(quarantine_dir)
    if state.triage is None:
        return {"error": "run_triage must be called before decide."}
    decision = decide_fn(
        state.triage,
        static_findings=state.static_findings,
        dynamic_findings=state.dynamic_findings,
        dynamic_executed=state.dynamic_executed,
    )
    state.decision = decision
    return decision.to_dict()


@mcp.tool()
def finalize(quarantine_dir: str) -> str:
    """Stage 5 -- MANDATORY last call. Persists the decision `decide` computed
    and returns the exact message to show the user. You must call this tool
    to end the analysis; do not compose the final message yourself -- return
    this tool's output verbatim as your final answer, so the user-facing
    report always matches what was actually recorded.
    """
    import sys

    state = _run_state(quarantine_dir)
    if state.decision is None:
        return "error: decide must be called before finalize."

    item = _load_item(quarantine_dir)
    try:
        with State() as st:
            return respond_fn(state.decision, item, state=st)
    except Exception as exc:  # sqlite can fail on some filesystems/mounts;
        # losing the "skip unchanged items on rescan" optimization is far
        # better than losing the verdict itself.
        print(f"warning: could not persist to state DB ({exc}); continuing", file=sys.stderr)
        return respond_fn(state.decision, item, state=None)


if __name__ == "__main__":
    mcp.run()
