"""Tolerant parsing of project.json (a wallpaper's manifest).

The `type` field is NOT trusted data: an attacker can declare "video" and
disguise an executable. Here we only extract what is declared; triage later
cross-checks it against real file inspection.

Traps seen in real Workshop items:
- `type` comes with inconsistent casing ("Scene" vs "scene") -> normalize.
- The file arrives with a UTF-8 BOM -> read with utf-8-sig.
- The entry point is not fixed: `file` points to scene.json, gifscene.json,
  index.html or directly an .mp4 -> always follow the `file` field.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ProjectInfo:
    declared_type: str | None  # normalized to lowercase; None if absent/unreadable
    entry_file: str | None  # value of the `file` field
    title: str | None
    external_urls: list[str] = field(default_factory=list)
    parse_error: str | None = None  # reason if the JSON could not be read

    @property
    def is_readable(self) -> bool:
        return self.parse_error is None


def _collect_urls(obj: object, out: list[str]) -> None:
    """Walk the JSON collecting any string that looks like an external URL."""
    if isinstance(obj, str):
        s = obj.strip()
        if s.startswith(("http://", "https://", "//")):
            out.append(s)
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect_urls(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _collect_urls(v, out)


def parse(project_json_path: str | Path) -> ProjectInfo:
    """Read project.json defensively. Never raises on corrupt content."""
    p = Path(project_json_path)
    if not p.exists():
        return ProjectInfo(None, None, None, parse_error="project.json missing")
    try:
        # utf-8-sig strips the BOM if present.
        raw = p.read_text(encoding="utf-8-sig")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return ProjectInfo(None, None, None, parse_error=f"unreadable JSON: {exc}")

    if not isinstance(data, dict):
        return ProjectInfo(None, None, None, parse_error="project.json is not an object")

    raw_type = data.get("type")
    declared = str(raw_type).strip().lower() if isinstance(raw_type, str) else None

    entry = data.get("file")
    entry_file = str(entry) if isinstance(entry, str) else None

    title = data.get("title")
    title = str(title) if isinstance(title, str) else None

    urls: list[str] = []
    _collect_urls(data, urls)

    return ProjectInfo(
        declared_type=declared,
        entry_file=entry_file,
        title=title,
        external_urls=sorted(set(urls)),
    )
