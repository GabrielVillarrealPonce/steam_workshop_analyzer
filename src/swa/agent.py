"""The agent loop: Gemini as the analyst, Stage 1/2/3/4/5 as its MCP tools.

This is the piece that makes the project an *agent* rather than a fixed
pipeline (see the design discussion in docs/ -- an LLM that decides which
tools to call and in what order, versus a checklist that always runs the same
steps). Stage 0 (ingest) runs first as plain code, no reasoning needed; then
the model takes over via this loop until it calls `finalize` (Stage 5), which
is the only way the loop ends with an actual verdict delivered to the user.

The model provider is Google Gemini, driven through the `google-genai` SDK.
MCP is model-agnostic: the exact same `swa.mcp_server` (Stage 1-5 as tools)
is reused unchanged; only the "brain" driving it changed from Claude to
Gemini. `google-genai` speaks MCP natively -- passing the MCP `ClientSession`
in `tools` turns on automatic function calling, so the SDK lists the tools,
calls them, feeds results back, and loops until the model produces its final
text (finalize's output).

Usage:

    export GEMINI_API_KEY=...        # or GOOGLE_API_KEY
    python -m swa.agent <path-to-a-wallpaper-directory>

Model: defaults to the cheapest capable current model (gemini-3-flash) to
stretch free API credits as far as possible -- override with GEMINI_MODEL if
you need stronger reasoning on ambiguous cases.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from pathlib import Path

from google import genai
from google.genai import types
from google.genai._mcp_utils import mcp_to_gemini_tools
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from .stage0_ingest import quarantine

DEFAULT_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3-flash")

# Safety ceiling on the agent loop. The pipeline is triage -> maybe
# static/sandbox -> decide -> finalize (~5 tool calls plus reasoning turns);
# this leaves comfortable headroom while guaranteeing the loop always ends.
MAX_STEPS = 12

# The tool whose output is the user-facing verdict (Stage 5). We capture its
# return value directly rather than trusting the model to echo it verbatim.
FINAL_TOOL = "finalize"

# The env vars google-genai (and this project) accept for the Gemini API key.
API_KEY_ENV_VARS = ("GEMINI_API_KEY", "GOOGLE_API_KEY")

# The SDK logs an "experimental" notice the first time an MCP session is used
# as a tool. It is expected and just noise for a demo; quiet it so the agent's
# own reasoning is the only thing on stderr.
logging.getLogger("google_genai").setLevel(logging.ERROR)

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
3. Once you've gathered the evidence you judge sufficient, call `decide` \
(it only needs quarantine_dir -- it reads the triage/static/dynamic findings \
the tools already produced). You must never state approve/escalate/block \
yourself in prose before calling `decide` -- it is the actual source of \
truth for the verdict, not your own judgement. Your role is choosing what \
evidence to gather, not computing the final score.
4. Call `finalize` (also just quarantine_dir). This is mandatory -- the \
analysis is not complete until you call it. Return its output as your final \
answer, verbatim, so the user sees exactly what was recorded.

Be economical: call the minimum set of tools that lets you reach a confident \
`decide` call. Explain your reasoning briefly between tool calls, but the \
finding-gathering should be evidence-driven, not exhaustive for its own sake.
"""


def api_key() -> str | None:
    """Return the configured Gemini API key from the accepted env vars."""
    for name in API_KEY_ENV_VARS:
        value = os.environ.get(name)
        if value:
            return value
    return None


def _server_params() -> StdioServerParameters:
    """Spawn `python -m swa.mcp_server` as a subprocess, with `src/` on its
    PYTHONPATH so it can `import swa` regardless of how this script was
    invoked."""
    src_dir = str(Path(__file__).resolve().parents[1])
    env = dict(os.environ)
    env["PYTHONPATH"] = src_dir + os.pathsep + env.get("PYTHONPATH", "")
    return StdioServerParameters(command=sys.executable, args=["-m", "swa.mcp_server"], env=env)


def _tool_result_payload(result) -> dict:
    """Turn an MCP CallToolResult into the JSON object Gemini expects as a
    function response. Our tools return a JSON dict (or, for finalize, a plain
    string); wrap non-dict payloads under a `result` key."""
    text = "".join(
        getattr(block, "text", "") for block in (result.content or [])
    )
    if getattr(result, "isError", False):
        return {"error": text}
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        parsed = text
    return parsed if isinstance(parsed, dict) else {"result": parsed}


async def analyze(quarantine_dir: str, model: str = DEFAULT_MODEL) -> str:
    """Run the full agent loop over an already-ingested item. Returns the
    final message (Stage 5's output, via the `finalize` tool).

    We drive the loop by hand instead of the SDK's automatic MCP function
    calling: that path deep-copies the config, which fails on a live MCP
    session (it holds un-pickleable asyncio objects). Here the session never
    enters the config -- we convert its tools to Gemini tools once, then
    ping-pong function calls and results ourselves, calling the same MCP
    server the design already ships.
    """
    client = genai.Client(api_key=api_key())

    manifest = json.loads((Path(quarantine_dir) / "manifest.json").read_text(encoding="utf-8"))

    async with stdio_client(_server_params()) as (read, write):
        async with ClientSession(read, write) as mcp_client:
            await mcp_client.initialize()
            tools_result = await mcp_client.list_tools()
            gemini_tools = mcp_to_gemini_tools(tools_result.tools)

            config = types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0,
                tools=gemini_tools,
                # We run the tool loop ourselves, so turn the SDK's automatic
                # function calling off -- otherwise it would also try to invoke
                # the tools and double up.
                automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
            )

            user_message = (
                f"Analyze this quarantined Workshop item.\n\n"
                f"quarantine_dir: {quarantine_dir}\n\n"
                f"Manifest:\n{json.dumps(manifest, indent=2)}"
            )
            contents: list[types.Content] = [
                types.Content(role="user", parts=[types.Part(text=user_message)])
            ]

            final_output: str | None = None
            last_text = ""

            for _ in range(MAX_STEPS):
                response = await client.aio.models.generate_content(
                    model=model, contents=contents, config=config
                )
                candidate = response.candidates[0]
                contents.append(candidate.content)

                calls = response.function_calls

                # Surface the model's reasoning between tool calls (the narration
                # you see scroll by during the demo). Skip the final turn: it
                # just echoes finalize's report, which we already print once from
                # `final_output` -- printing it here too would double it.
                if response.text and calls:
                    print(response.text.strip(), file=sys.stderr, flush=True)
                if response.text:
                    last_text = response.text.strip()

                if not calls:
                    break

                response_parts: list[types.Part] = []
                for call in calls:
                    result = await mcp_client.call_tool(call.name, dict(call.args or {}))
                    payload = _tool_result_payload(result)
                    if call.name == FINAL_TOOL and "result" in payload:
                        final_output = str(payload["result"])
                    response_parts.append(
                        types.Part.from_function_response(name=call.name, response=payload)
                    )
                contents.append(types.Content(role="user", parts=response_parts))

    # Prefer finalize()'s own output (the recorded, user-facing verdict) over
    # the model's closing paraphrase; fall back to the last text if for some
    # reason finalize was never reached.
    message = final_output or last_text
    if not message:
        raise RuntimeError(
            "the agent produced no verdict (it may not have reached finalize)."
        )
    return message


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
    if not api_key():
        print(
            "error: no Gemini API key set (GEMINI_API_KEY or GOOGLE_API_KEY).",
            file=sys.stderr,
        )
        return 2
    print(analyze_path(argv[0]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
