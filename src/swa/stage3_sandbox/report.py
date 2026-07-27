"""Normalized behavioural report -- the contract between a sandbox backend and
the signal analyser.

Every backend (a live CAPEv2 instance, a replayed ANY.RUN/Joe export, a future
adapter) is responsible for translating its own report format into this one
shape. The analyser (signals.py) then depends on nothing but this schema, so a
new sandbox platform can be added without touching the detection logic.

The categories mirror design doc section 7.2 (network, filesystem, processes,
registry, resources). `from_dict` is deliberately tolerant: a partial or
slightly-off report yields a partial SandboxReport, never an exception --
losing one event is far better than aborting the whole verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class NetworkEvent:
    kind: str = "tcp"  # dns | http | tls | tcp | udp
    host: str | None = None
    ip: str | None = None
    port: int | None = None
    url: str | None = None
    # Backends that enrich DNS with WHOIS age can flag this; the analyser uses
    # it for the "DNS to a recently registered domain" signal (doc 7.2).
    newly_registered: bool = False


@dataclass
class FileEvent:
    op: str = "write"  # write | read | delete | rename
    path: str = ""
    # True if the sandbox recognised the written content as an executable
    # (PE/ELF) -- the dropper signal.
    is_executable: bool = False


@dataclass
class ProcessEvent:
    op: str = "create"  # create | inject | terminate
    name: str = ""
    target: str | None = None  # injection/target process, if any
    detail: str | None = None  # e.g. the API used (CreateRemoteThread)


@dataclass
class RegistryEvent:
    op: str = "set"  # set | delete
    key: str = ""
    value: str | None = None


@dataclass
class ResourceStats:
    cpu_avg: float | None = None  # percent, averaged over the run
    gpu_avg: float | None = None
    files_encrypted: int | None = None  # count of user files rewritten/encrypted
    duration_seconds: float | None = None


@dataclass
class SandboxReport:
    workshop_id: str
    executed: bool
    backend: str
    duration_seconds: float = 0.0
    network: list[NetworkEvent] = field(default_factory=list)
    files: list[FileEvent] = field(default_factory=list)
    processes: list[ProcessEvent] = field(default_factory=list)
    registry: list[RegistryEvent] = field(default_factory=list)
    resources: ResourceStats = field(default_factory=ResourceStats)
    # Named detections from the sandbox itself (e.g. CAPE signatures).
    signatures: list[str] = field(default_factory=list)
    # Original backend payload, retained for forensics / debugging.
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SandboxReport":
        """Build a report from a normalized dict (ReplayBackend / tests).

        Tolerant by design: unknown keys are ignored, missing keys default,
        and a malformed event is skipped rather than raising.
        """
        return cls(
            workshop_id=str(data.get("workshop_id", "")),
            executed=bool(data.get("executed", True)),
            backend=str(data.get("backend", "replay")),
            duration_seconds=_as_float(data.get("duration_seconds"), 0.0) or 0.0,
            network=[_network(e) for e in _as_list(data.get("network")) if isinstance(e, dict)],
            files=[_file(e) for e in _as_list(data.get("files")) if isinstance(e, dict)],
            processes=[_process(e) for e in _as_list(data.get("processes")) if isinstance(e, dict)],
            registry=[_registry(e) for e in _as_list(data.get("registry")) if isinstance(e, dict)],
            resources=_resources(data.get("resources")),
            signatures=[str(s) for s in _as_list(data.get("signatures"))],
            raw=data if isinstance(data, dict) else {},
        )


# --- tolerant field coercion ------------------------------------------------

def _as_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def _as_float(v: Any, default: float | None = None) -> float | None:
    try:
        return float(v) if v is not None else default
    except (TypeError, ValueError):
        return default


def _as_int(v: Any) -> int | None:
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def _network(e: dict[str, Any]) -> NetworkEvent:
    return NetworkEvent(
        kind=str(e.get("kind", "tcp")).lower(),
        host=_opt_str(e.get("host")),
        ip=_opt_str(e.get("ip")),
        port=_as_int(e.get("port")),
        url=_opt_str(e.get("url")),
        newly_registered=bool(e.get("newly_registered", False)),
    )


def _file(e: dict[str, Any]) -> FileEvent:
    return FileEvent(
        op=str(e.get("op", "write")).lower(),
        path=str(e.get("path", "")),
        is_executable=bool(e.get("is_executable", False)),
    )


def _process(e: dict[str, Any]) -> ProcessEvent:
    return ProcessEvent(
        op=str(e.get("op", "create")).lower(),
        name=str(e.get("name", "")),
        target=_opt_str(e.get("target")),
        detail=_opt_str(e.get("detail")),
    )


def _registry(e: dict[str, Any]) -> RegistryEvent:
    return RegistryEvent(
        op=str(e.get("op", "set")).lower(),
        key=str(e.get("key", "")),
        value=_opt_str(e.get("value")),
    )


def _resources(v: Any) -> ResourceStats:
    if not isinstance(v, dict):
        return ResourceStats()
    return ResourceStats(
        cpu_avg=_as_float(v.get("cpu_avg")),
        gpu_avg=_as_float(v.get("gpu_avg")),
        files_encrypted=_as_int(v.get("files_encrypted")),
        duration_seconds=_as_float(v.get("duration_seconds")),
    )


def _opt_str(v: Any) -> str | None:
    return str(v) if v is not None else None
