# steam_workshop_analyzer

An AI agent that detects malicious/vulnerable Wallpaper Engine content in the
Steam Workshop. Google Gemini is the reasoning engine; Stages 1-5 are exposed
to it as local MCP tools it decides how and when to use, not a fixed checklist.
(MCP is model-agnostic -- the tools and pipeline are unchanged from the design;
only the driving model is Gemini.)

## Architecture

Stage 0 (ingest) runs as plain code before any LLM call -- downloading/
scanning doesn't need reasoning, and skipping it saves tokens. Everything
after that is the actual agent loop:

```
swa.cli / swa.agent (orchestrator, runs locally)
        |
        |  1. Stage 0 ingest (plain code, no LLM)         -> WorkshopItem manifest
        |
        |  2. opens a conversation with Gemini's API ------> Gemini (Google's servers)
        |     (manifest + list of MCP tools)                    |
        |                                                        | decides to call a tool
        |  3. relays the tool call to the local  <---------------
        |     MCP server (swa.mcp_server, stdio)
        |
        |  4. MCP server runs the real stage function
        |     locally (files, hashes, etc.) and
        |     returns the result
        |
        |  5. orchestrator sends the result back -------------> Gemini
        |     to Gemini; repeat 2-5 until Gemini                  |
        |     calls `finalize`                                    | reasons, may call
        |                                                          another tool, or finish
        v
   final message (Stage 5's report, returned verbatim)
```

Gemini never touches your machine directly -- the orchestrator (`swa.agent`)
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

## Why Stage 4's verdict isn't just "whatever Gemini says"

`decide` is a plain deterministic function (`swa/stage4_decision/engine.py`),
not something the LLM computes by itself. Gemini only chooses *which* stages to
run; each stage caches its real findings in the MCP server, and `decide` reads
those cached findings directly -- the model does not hand the evidence back, so
it cannot reshape it. Gemini never states approve/block in its own prose as the
actual verdict. This matters specifically because the input here is adversarial
content (a malicious wallpaper's own script/strings could try to talk the model
into a favorable verdict); a fixed rule ladder over structured findings can't be
argued with the way free text can. See the rule ladder's docstring in
`engine.py` for the full priority order.

## Agent loop

`swa/mcp_server.py` is a local MCP server (stdio transport -- no network
exposure, no hosting cost) exposing `run_triage`, `run_static_analysis`,
`run_sandbox`, `decide`, and `finalize` as tools.

`swa/agent.py` is the orchestrator: it ingests an item (Stage 0), spawns the
MCP server as a subprocess, converts the MCP tools to Gemini tools, and runs
the function-calling loop via the `google-genai` SDK until Gemini calls
`finalize`.

```bash
export GEMINI_API_KEY=...        # or GOOGLE_API_KEY
python -m swa.agent path/to/a/wallpaper/directory
# or, once installed:
swa analyze path/to/a/wallpaper/directory
```

Default model is a cheap current one (`gemini-3-flash`) to stretch free API
credits; override with `--model` or the `GEMINI_MODEL` env var if a case needs
stronger reasoning.

## Try it out

Setup (once):

```bash
pip install -e ".[dev]"
```

Environment variables below use bash syntax (`export`). On Windows PowerShell
use `$env:NAME = "value"` instead, and `python -m swa.cli` if the `swa` script
is not on your PATH.

**1. Run the tests** (no API key -- the MCP integration test drives the real
tool loop over stdio, bypassing the LLM):

```bash
pytest
```

**2. Deterministic pipeline** (no API key -- Stage 0-5 without the LLM):

```bash
swa triage tests/fixtures/web_con_descarga     # Stage 0+1 on one folder, prints JSON
swa scan --no-metadata                         # triage every installed Wallpaper Engine item
swa scan --appid 431960 --no-metadata          # any Steam game's Workshop, by its AppID
python demo/offline_demo.py demo/steam_stealer # full pipeline (0-5), no LLM -> BLOCK verdict
```

**3. The full AI agent** (needs a Gemini API key -- Gemini decides which
tools to run):

```bash
export GEMINI_API_KEY=...                       # or GOOGLE_API_KEY
swa analyze demo/steam_stealer                 # agent loop over a folder -> BLOCK
swa analyze tests/fixtures/web_con_descarga    # -> ESCALATE (undeclared download)
swa analyze-id 1081688800 --appid 431960       # locate an installed item by its Workshop ID
```

The Workshop layout (`steamapps/workshop/content/<appid>/<id>`) is identical
for every Steam title, so `--appid` generalizes the scan/analysis to any game,
not just Wallpaper Engine (default AppID `431960`).

**4. Dynamic sandbox** (Stage 3): the default backend never executes anything
(`executed=False` -> ESCALATE). To include dynamic evidence from a report
captured on dedicated infrastructure, without executing here:

```bash
export SWA_SANDBOX_BACKEND=replay
export SWA_SANDBOX_REPLAY=path/to/normalized_report.json
```

Other dev entry points:

```bash
python -m swa.mcp_server            # run the MCP server standalone, for manual testing
python -m swa.cli --help            # all commands and flags
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
