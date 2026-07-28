"""Adapter for a CAPEv2 sandbox instance (self-hosted, dedicated).

IMPORTANT: this backend does not detonate anything on the analysis host. It
submits the sample to an *external* CAPEv2 instance over its REST API and
retrieves the behavioural report. The dangerous part -- actually running the
malware -- happens inside that dedicated, isolated infrastructure (VM +
snapshots + controlled network), exactly as the design doc requires. Standing
up that infrastructure is out of scope here; this is the integration seam to it.

Untested against a live instance in this repo (there is none to test against);
the report normalizer is factored out as a pure function `normalize_cape_report`
so it can be unit-tested with a synthetic CAPE payload. Every network call is
wrapped: any failure returns None (-> executed=False -> ESCALATE), never a
false clean.

CAPE report shapes vary by version; `normalize_cape_report` is best-effort and
the place to adjust for a specific deployment.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any

from ...models import FileType, WorkshopItem
from ..config import BACKEND_CAPEV2, SandboxConfig
from ..report import SandboxReport

_EXECUTABLE_EXTS = (".exe", ".dll", ".scr", ".sys")


class CapeV2Backend:
    name = BACKEND_CAPEV2

    def run(self, item: WorkshopItem, config: SandboxConfig) -> SandboxReport | None:
        if not config.cape_base_url:
            print("stage3 cape: no cape_base_url configured", file=sys.stderr)
            return None

        sample = _primary_sample(item)
        if sample is None:
            print("stage3 cape: no executable sample to submit", file=sys.stderr)
            return None

        try:
            import requests  # lazy: only this backend needs it
        except ImportError:
            print("stage3 cape: the 'requests' package is required", file=sys.stderr)
            return None

        base = config.cape_base_url.rstrip("/")
        headers = {"Authorization": f"Token {config.cape_token}"} if config.cape_token else {}
        try:
            task_id = self._submit(requests, base, headers, sample, config)
            if task_id is None:
                return None
            if not self._await_report(requests, base, headers, task_id, config):
                return None
            raw = self._fetch_report(requests, base, headers, task_id, config)
            if raw is None:
                return None
        except Exception as exc:  # requests.* and any parsing surprise
            print(f"stage3 cape: backend error: {exc}", file=sys.stderr)
            return None

        return SandboxReport.from_dict(normalize_cape_report(raw, item.workshop_id))

    # --- REST steps ---------------------------------------------------------

    def _submit(self, requests, base, headers, sample: Path, config) -> int | None:
        with open(sample, "rb") as fh:
            resp = requests.post(
                f"{base}/apiv2/tasks/create/file/",
                headers=headers,
                files={"file": (sample.name, fh)},
                data={"timeout": config.timeout_seconds, "enforce_timeout": True},
                timeout=60,
            )
        resp.raise_for_status()
        data = resp.json()
        # Accept the common shapes: {"data": {"task_ids": [id]}} / {"task_id": id}.
        payload = data.get("data", data)
        if isinstance(payload, dict):
            if payload.get("task_ids"):
                return int(payload["task_ids"][0])
            if payload.get("task_id") is not None:
                return int(payload["task_id"])
        print(f"stage3 cape: unexpected submit response: {data}", file=sys.stderr)
        return None

    def _await_report(self, requests, base, headers, task_id, config) -> bool:
        deadline = time.monotonic() + config.max_wait_seconds
        while time.monotonic() < deadline:
            resp = requests.get(
                f"{base}/apiv2/tasks/view/{task_id}/", headers=headers, timeout=30
            )
            resp.raise_for_status()
            status = (resp.json().get("data") or {}).get("status", "")
            if status in ("reported", "completed"):
                return True
            if status in ("failed_analysis", "failed_processing", "failure"):
                print(f"stage3 cape: task {task_id} status={status}", file=sys.stderr)
                return False
            time.sleep(config.poll_interval_seconds)
        print(f"stage3 cape: task {task_id} timed out", file=sys.stderr)
        return False

    def _fetch_report(self, requests, base, headers, task_id, config) -> dict | None:
        resp = requests.get(
            f"{base}/apiv2/tasks/get/report/{task_id}/", headers=headers, timeout=120
        )
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, dict) else None


def _primary_sample(item: WorkshopItem) -> Path | None:
    """Pick the file to submit: the first native executable in the manifest."""
    root = Path(item.quarantine_dir) / "raw"
    for entry in item.files:
        if entry.filetype in (FileType.PE, FileType.ELF):
            candidate = root / entry.path
            if candidate.is_file():
                return candidate
    return None


def normalize_cape_report(raw: dict[str, Any], workshop_id: str) -> dict[str, Any]:
    """Best-effort map of a CAPE JSON report to the normalized schema.

    Pure and defensive: unknown/missing sections just yield fewer events.
    """
    net = raw.get("network") if isinstance(raw.get("network"), dict) else {}
    behavior = raw.get("behavior") if isinstance(raw.get("behavior"), dict) else {}
    summary = behavior.get("summary") if isinstance(behavior.get("summary"), dict) else {}

    network: list[dict] = []
    for dns in _list(net.get("dns")):
        if isinstance(dns, dict) and dns.get("request"):
            network.append({"kind": "dns", "host": dns.get("request")})
    for dom in _list(net.get("domains")):
        if isinstance(dom, dict) and dom.get("domain"):
            network.append({"kind": "dns", "host": dom.get("domain"), "ip": dom.get("ip")})
    for http in _list(net.get("http")):
        if isinstance(http, dict):
            network.append(
                {
                    "kind": "http",
                    "url": http.get("uri") or http.get("url"),
                    "host": http.get("host"),
                    "port": http.get("port"),
                }
            )
    for host in _list(net.get("hosts")):
        if isinstance(host, str):
            network.append({"kind": "tcp", "ip": host})
        elif isinstance(host, dict) and host.get("ip"):
            network.append({"kind": "tcp", "ip": host.get("ip")})

    files: list[dict] = []
    for p in _list(summary.get("write_files")) + _list(summary.get("files")):
        if isinstance(p, str):
            files.append(
                {"op": "write", "path": p, "is_executable": p.lower().endswith(_EXECUTABLE_EXTS)}
            )
    for drop in _list(raw.get("dropped")):
        if isinstance(drop, dict):
            fpath = drop.get("filepath") or drop.get("name") or ""
            dtype = str(drop.get("type", "")).lower()
            is_exe = "executable" in dtype or "pe32" in dtype or str(fpath).lower().endswith(
                _EXECUTABLE_EXTS
            )
            files.append({"op": "write", "path": fpath, "is_executable": is_exe})

    registry: list[dict] = []
    for k in _list(summary.get("write_keys")) + _list(summary.get("keys")):
        if isinstance(k, str):
            registry.append({"op": "set", "key": k})

    processes: list[dict] = []
    for proc in _list(behavior.get("processes")):
        if isinstance(proc, dict):
            nm = proc.get("process_name") or proc.get("name")
            if nm:
                processes.append({"op": "create", "name": nm})

    signatures: list[str] = []
    for sig in _list(raw.get("signatures")):
        if isinstance(sig, dict) and sig.get("name"):
            signatures.append(str(sig["name"]))
        elif isinstance(sig, str):
            signatures.append(sig)

    return {
        "workshop_id": workshop_id,
        "executed": True,
        "backend": BACKEND_CAPEV2,
        "network": network,
        "files": files,
        "registry": registry,
        "processes": processes,
        "signatures": signatures,
        "raw": {"info": raw.get("info", {})},  # keep it light; full report is huge
    }


def _list(v: Any) -> list:
    return v if isinstance(v, list) else []
