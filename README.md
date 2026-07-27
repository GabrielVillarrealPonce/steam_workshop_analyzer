# steam_workshop_analyzer

An AI agent that detects malicious/vulnerable Wallpaper Engine content in the
Steam Workshop. Claude is the reasoning engine; Stages 1-5 are exposed to it
as local MCP tools it decides how and when to use, not a fixed checklist.

## Architecture

Stage 0 (ingest) runs as plain code before any LLM call -- downloading/
scanning doesn't need reasoning, and skipping it saves tokens. Everything
after that is the actual agent loop:

```
swa.cli / swa.agent (orchestrator, runs locally)
        |
        |  1. Stage 0 ingest (plain code, no LLM)         -> WorkshopItem manifest
        |
        |  2. opens a conversation with Claude's API ------> Claude (Anthropic's servers)
        |     (manifest + list of MCP tools)                    |
        |                                                        | decides to call a tool
        |  3. relays the tool call to the local  <---------------
        |     MCP server (swa.mcp_server, stdio)
        |
        |  4. MCP server runs the real stage function
        |     locally (files, hashes, etc.) and
        |     returns the result
        |
        |  5. orchestrator sends the result back -------------> Claude
        |     to Claude; repeat 2-5 until Claude                  |
        |     calls `finalize`                                    | reasons, may call
        |                                                          another tool, or finish
        v
   final message (Stage 5's report, returned verbatim)
```

Claude never touches your machine directly -- the orchestrator (`swa.agent`)
is always the one asking your local MCP server to actually run a stage, then
handing the result back. See the "Agent loop" section below for exactly which
tool wraps which stage.

## Pipeline stages

| Stage | Package | Responsibility | Exposed as | Status |
|-------|---------|-----------------|------------|--------|
| 0 | `swa.stage0_ingest` | Copy a Workshop item to quarantine, build the manifest | plain code, runs before the agent starts | done |
| 1 | `swa.stage1_triage` | Format triage: real file types vs. declared type, disguises, password-protected archives | tool: `run_triage` | done |
| 2 | `swa.stage2_static` | Static analysis of flagged scripts/PE binaries (signature, packing, imports, strings, script IOCs, system-lib impersonation, embedded archive passwords) | tool: `run_static_analysis` | done |
| 3 | `swa.stage3_sandbox` | Dynamic sandbox: backend integration (null/replay/CAPEv2) + behavioural-report analysis (doc 7.2) | tool: `run_sandbox` | integration layer done; detonation runs on external/dedicated infra only (default: no execution, `executed=False`) |
| 4 | `swa.stage4_decision` | Deterministic final verdict from gathered evidence | tool: `decide` | done |
| 5 | `swa.stage5_response` | Persist + report the verdict to the user | tool: `finalize` | done |

Shared data contracts (`FileEntry`, `WorkshopItem`, `Finding`, `Severity`,
`TriageResult`, `Verdict`) live in `swa.models` -- this is the integration
surface every stage and tool is built against.

## Why Stage 4's verdict isn't just "whatever Claude says"

`decide` is a plain deterministic function (`swa/stage4_decision/engine.py`),
not something the LLM computes by itself. The agent's system prompt
(`swa/agent.py`) instructs Claude to gather evidence via tools and then call
`decide` with that evidence -- Claude never states approve/block in its own
prose as the actual verdict. This matters specifically because the input here
is adversarial content (a malicious wallpaper's own script/strings could try
to talk the model into a favorable verdict); a fixed rule ladder over
structured findings can't be argued with the way free text can. See the rule
ladder's docstring in `engine.py` for the full priority order.

## Agent loop

`swa/mcp_server.py` is a local MCP server (stdio transport -- no network
exposure, no hosting cost) exposing `run_triage`, `run_static_analysis`,
`run_sandbox`, `decide`, and `finalize` as tools.

`swa/agent.py` is the orchestrator: it ingests an item (Stage 0), spawns the
MCP server as a subprocess, opens a Claude conversation with the manifest and
the tool list, and runs the loop via the Anthropic SDK's `tool_runner` until
Claude calls `finalize`.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python -m swa.agent path/to/a/wallpaper/directory
# or, once installed:
swa analyze path/to/a/wallpaper/directory
```

Default model is the cheapest current one (Haiku) to stretch free API
credits; override with `--model` or the `ANTHROPIC_MODEL` env var if a case
needs stronger reasoning.

## Develop

```bash
pip install -e ".[dev]"
pytest                              # full suite, including the MCP server
                                     # integration test (no API key needed --
                                     # it calls tools directly, bypassing Claude)
python -m swa.mcp_server            # run the MCP server standalone, for manual testing
swa triage path/to/dir              # Stage 0+1 only, no LLM (existing dev command)
swa analyze path/to/dir             # full agent loop (needs ANTHROPIC_API_KEY)
```

## Notes for the team

- `stage3_sandbox/` is the safe integration + analysis layer, NOT a local
  detonation engine (running untrusted code must happen on dedicated, isolated
  infrastructure -- design doc 2 and 7). It ships a backend abstraction
  (`backends/`: `null` default, `replay`, `capev2`), a normalized report
  schema (`report.py`), and the doc-7.2 signal analyser (`signals.py`). Select
  a backend via `SWA_SANDBOX_BACKEND` (`null`|`replay`|`capev2`); `replay`
  (point `SWA_SANDBOX_REPLAY` at a normalized report JSON) makes a full
  dynamic-evidence verdict demonstrable without any live sandbox.
- `stage2_static/` is implemented as a thin orchestrator (`analysis.py`) over
  focused detectors (`pe.py`, `scripts.py`, `strings.py`, `archives.py`) plus
  a shared IOC/severity table (`indicators.py`) and tunable thresholds
  (`config.py`) -- same layout as `stage1_triage`. HIGH severity is reserved
  for indicators no legitimate wallpaper contains (Steam session-file
  references, system-library impersonation, an archive password stashed in a
  filename/config), which the decision engine treats as confirmed and blocks.
