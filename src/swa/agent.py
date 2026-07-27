"""The agent loop: Claude as the analyst, Stage 1/2/3/4/5 as its MCP tools.

This is the piece that makes the project an *agent* rather than a fixed
pipeline (see the design discussion in docs/ -- an LLM that decides which
tools to call and in what order, versus a checklist that always runs the same
steps). Stage 0 (ingest) runs first as plain code, no reasoning needed; then
Claude takes over via this loop until it calls `finalize` (Stage 5), which is
the only way the loop ends with an actual verdict delivered to the user.

Usage:

    export ANTHROPIC_API_KEY=sk-ant-...
    python -m swa.agent <path-to-a-wallpaper-directory>

Model: defaults to the cheapest current model (Haiku) to stretch free API
credits as far as possible -- override with ANTHROPIC_MODEL if you need
stronger reasoning on ambiguous cases. See the architecture doc for the
Sonnet/Opus cost trade-off.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import anthropic
from anthropic.lib.tools.mcp import async_mcp_tool
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from .stage0_ingest import quarantine

DEFAULT_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")

SYSTEM_PROMPT = """\
You are a security analyst agent for Wallpaper Engine content downloaded via \
the Steam Workshop. You are given a manifest of one already-quarantined item \
(files, hashes, declared type) and a set of tools to investigate it further.

Your job, in order:
1. Always call run_triage first. It is cheap, local, and mandatory.
2. Based on the triage verdict and findings, decide whether run_static_analysis \
and/or run_sandbox are worth calling. Don't call them if triage already \
approved a plain image/video with nothing else flagged -- that would waste \
tokens for no benefit. Do call them if triage flagged executable content, \
scripts, a type mismatch, or an encrypted archive.
3. Once you've gathered the evidence you judge sufficient, call `decide` with \
everything you collected. You must never state approve/escalate/block \
yourself in prose before calling `decide` -- it is the actual source of \
truth for the verdict, not your own judgement. Your role is choosing what \
evidence to gather, not computing the final score.
4. Call `finalize` with the decision `decide` returned. This is mandatory -- \
the analysis is not complete until you call it. Return its output as your \
final answer, verbatim, so the user sees exactly what was recorded.

Be economical: call the minimum set of tools that lets you reach a confident \
`decide` call. Explain your reasoning briefly between tool calls, but the \
finding-gathering should be evidence-driven, not exhaustive for its own sake.
"""


def _server_params() -> StdioServerParameters:
    """Spawn `python -m swa.mcp_server` as a subprocess, with `src/` on its
    PYTHONPATH so it can `import swa` regardless of how this script was
    invoked."""
    src_dir = str(Path(__file__).resolve().parents[1])
    env = dict(os.environ)
    env["PYTHONPATH"] = src_dir + os.pathsep + env.get("PYTHONPATH", "")
    return StdioServerParameters(command=sys.executable, args=["-m", "swa.mcp_server"], env=env)


async def analyze(quarantine_dir: str, model: str = DEFAULT_MODEL) -> str:
    """Run the full agent loop over an already-ingested item. Returns the
    final message (Stage 5's output, via the `finalize` tool)."""
    client = anthropic.AsyncAnthropic()

    manifest = json.loads((Path(quarantine_dir) / "manifest.json").read_text(encoding="utf-8"))

    async with stdio_client(_server_params()) as (read, write):
        async with ClientSession(read, write) as mcp_client:
            await mcp_client.initialize()
            tools_result = await mcp_client.list_tools()

            user_message = (
                f"Analyze this quarantined Workshop item.\n\n"
                f"quarantine_dir: {quarantine_dir}\n\n"
                f"Manifest:\n{json.dumps(manifest, indent=2)}"
            )

            runner = client.beta.messages.tool_runner(
                model=model,
                max_tokens=2048,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_message}],
                tools=[async_mcp_tool(tool, mcp_client) for tool in tools_result.tools],
            )
            final_message = await runner.until_done()

    # The tool_runner's final message is the model's last text turn -- which
    # our system prompt instructs to be finalize()'s output verbatim.
    return "".join(
        block.text for block in final_message.content if getattr(block, "type", None) == "text"
    )


def analyze_path(path: str, model: str = DEFAULT_MODEL) -> str:
    """Ingest a standalone directory (Stage 0) and run the agent loop on it.

    For development/testing against a fixture directory rather than a real
    Steam library. For the real pipeline, wire this to `swa.cli`'s `scan`
    flow (which already enumerates installed Workshop items) instead.
    """
    source = Path(path)
    item = quarantine.ingest(source.name, source, metadata={})
    return asyncio.run(analyze(item.quarantine_dir, model=model))


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: python -m swa.agent <path-to-wallpaper-directory>", file=sys.stderr)
        return 2
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("error: ANTHROPIC_API_KEY is not set.", file=sys.stderr)
        return 2
    print(analyze_path(argv[0]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
