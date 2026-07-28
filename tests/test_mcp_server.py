"""Structural/integration test for the local MCP server -- verifies the tool
wiring (Stage 1/2/3/4/5 exposed correctly over stdio) without needing an
Anthropic API key. Calls tools directly through an MCP ClientSession, the
same way `swa.agent` does, just without Claude in the loop.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from swa.stage0_ingest import quarantine

FIXTURE = Path(__file__).parent / "fixtures" / "web_con_descarga"


def _server_params():
    from mcp.client.stdio import StdioServerParameters

    src_dir = str(Path(__file__).resolve().parents[1] / "src")
    env = dict(os.environ)
    env["PYTHONPATH"] = src_dir + os.pathsep + env.get("PYTHONPATH", "")
    return StdioServerParameters(command=sys.executable, args=["-m", "swa.mcp_server"], env=env)


async def _run(quarantine_dir: str) -> dict:
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    out = {}
    async with stdio_client(_server_params()) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            out["tool_names"] = sorted(t.name for t in tools.tools)

            triage_res = await session.call_tool("run_triage", {"quarantine_dir": quarantine_dir})
            triage_dict = json.loads(triage_res.content[0].text)
            out["triage"] = triage_dict

            decide_res = await session.call_tool(
                "decide",
                {
                    "quarantine_dir": quarantine_dir,
                    "triage_result": triage_dict,
                    "static_findings": None,
                    "dynamic_findings": None,
                    "dynamic_executed": False,
                },
            )
            decision_dict = json.loads(decide_res.content[0].text)
            out["decision"] = decision_dict

            finalize_res = await session.call_tool(
                "finalize", {"quarantine_dir": quarantine_dir, "decision": decision_dict}
            )
            out["message"] = finalize_res.content[0].text
    return out


def test_mcp_server_full_loop_without_claude(tmp_path):
    item = quarantine.ingest("web_con_descarga", FIXTURE, metadata={}, quarantine_root=tmp_path)

    result = asyncio.run(_run(item.quarantine_dir))

    assert result["tool_names"] == [
        "decide",
        "finalize",
        "run_sandbox",
        "run_static_analysis",
        "run_triage",
    ]

    # This fixture declares "web" and ships a script -> triage must route it
    # onward for further analysis, never a bare APPROVE.
    assert result["triage"]["verdict"] != "approve"
    assert result["triage"]["workshop_id"] == "web_con_descarga"

    assert result["decision"]["verdict"] in ("approve", "escalate", "block")
    assert "workshop item web_con_descarga" in result["message"]

    # finalize() must have actually persisted the report.
    report = Path(item.quarantine_dir) / "decision.json"
    assert report.exists()
    on_disk = json.loads(report.read_text(encoding="utf-8"))
    assert on_disk["verdict"] == result["decision"]["verdict"]
