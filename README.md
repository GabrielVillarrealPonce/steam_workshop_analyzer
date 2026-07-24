# steam_workshop_analyzer

Agent for detecting malicious wallpapers in Wallpaper Engine's Steam Workshop.
5-stage pipeline (see `docs/diseno-arquitectura-agente.pdf`).

**Current status: stages 0 (ingest) and 1 (format triage) implemented.**
The detailed plan is in `docs/plan-etapas-0-1.md`.

## Installation

```bash
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -e ".[dev]"
```

## Usage

```bash
swa scan                 # scan the Workshop folder, ingest and triage what's new
swa scan --no-metadata   # without querying the Steam Web API
swa triage <path>        # triage a standalone wallpaper directory
swa show <workshop_id>   # last recorded verdict
```

`swa scan` locates Wallpaper Engine automatically by parsing
`libraryfolders.vdf` (supports libraries on secondary disks). It reads the
folder only when invoked: there is no background process. The documented payload
runs when the wallpaper is *applied*, not when it is downloaded, so reading the
folder is safe.

## How it works

- **Stage 0 — Ingest:** copies the item to `quarantine/<id>/<timestamp>/raw/`
  (never touches the Steam folder), computes each file's SHA-256 and generates a
  `manifest.json`. A content hash detects updates for re-analysis.
- **Stage 1 — Triage:** classifies each file by *magic bytes* (not by
  extension) and cross-checks the result against the `type` declared in
  `project.json`. The verdict is the **maximum** of the declared and observed
  risk: declaring "video" while hiding a disguised `.exe` yields `ESCALATE` with
  high severity.

Verdicts: `APPROVE` · `ANALYZE_STATIC` · `SANDBOX_REQUIRED` · `ESCALATE`.

## Tests

```bash
./.venv/Scripts/python.exe -m pytest -q
```

Includes synthetic fixtures (none with real harmful code) and a regression
against the real installed wallpapers (skipped if Steam/WE are not present).

## Security invariants

- A sample is never executed.
- The Steam folder is never written to (copied to quarantine, not moved).
- Password-protected archives are recorded as an IOC, **not opened**.
- Quarantine is never deleted (forensic evidence).
