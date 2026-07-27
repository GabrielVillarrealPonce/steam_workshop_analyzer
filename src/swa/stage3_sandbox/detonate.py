"""Stage 3 orchestrator: pick a backend, run it, analyse the report.

`detonate` is the public entry point (the MCP `run_sandbox` tool calls it). It
returns `(findings, executed)`:

  * executed=False  -> no dynamic analysis happened (NullBackend, a
                       misconfigured/failed backend). Stage 4 turns this into
                       ESCALATE for an application-type item -- it cannot be
                       cleared without a real run.
  * executed=True   -> a report was produced and analysed; `findings` reflect
                       the observed behaviour (empty == clean, which lets
                       Stage 4 APPROVE a sandbox-required item).

The `executed` flag is the crux: "not analysed" must never look like
"confirmed clean". Every backend upholds this by returning None / executed=False
on any failure instead of a clean-looking empty report.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from ..models import Finding, WorkshopItem
from ..stage1_triage import project_json
from .backends import select_backend
from .config import DEFAULT_CONFIG, SandboxConfig
from .signals import analyze_report


def _declared_domains(item: WorkshopItem) -> set[str]:
    """Hosts the author declared in project.json -- the network allowlist."""
    root = Path(item.quarantine_dir) / "raw"
    info = project_json.parse(root / "project.json")
    hosts: set[str] = set()
    for url in info.external_urls:
        try:
            netloc = urlsplit(url).netloc or urlsplit("//" + url).netloc
        except ValueError:
            continue
        host = netloc.split("@")[-1].split(":")[0].strip().lower().rstrip(".")
        if host:
            hosts.add(host)
    return hosts


def detonate(
    item: WorkshopItem, config: SandboxConfig | None = None
) -> tuple[list[Finding], bool]:
    """Run Stage 3 dynamic analysis for an item. See module docstring."""
    cfg = config if config is not None else SandboxConfig.from_env()

    backend = select_backend(cfg)
    report = backend.run(item, cfg)
    if report is None or not report.executed:
        return [], False

    allowed = _declared_domains(item)
    findings = analyze_report(report, allowed_domains=allowed, config=cfg)
    return findings, True
