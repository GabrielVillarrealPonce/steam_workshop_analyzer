"""Regression against the real corpus of installed wallpapers.

Guardrail against false positives: no legitimate installed wallpaper should
yield ESCALATE. Covers the real traps ('Scene' casing, BOM, gifscene.json,
multiple .pkg versions). Skipped if Steam/WE are not present on this machine.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from swa.models import Verdict
from swa.stage0_ingest import quarantine
from swa.stage1_triage import triage as triage_mod

try:
    from swa.steam.libraryfolders import SteamNotFoundError, find_workshop_content

    _CONTENT = find_workshop_content()
    _ITEMS = [p for p in _CONTENT.iterdir() if p.is_dir() and p.name.isdigit()]
except (SteamNotFoundError, OSError):
    _ITEMS = []

pytestmark = pytest.mark.skipif(
    not _ITEMS, reason="Wallpaper Engine not installed on this machine"
)


@pytest.mark.parametrize("item_dir", _ITEMS, ids=lambda p: p.name)
def test_real_item_not_escalated(item_dir: Path, tmp_path):
    item = quarantine.ingest(item_dir.name, item_dir, metadata={}, quarantine_root=tmp_path)
    result = triage_mod.triage(item)
    assert result.verdict is not Verdict.ESCALATE, (
        f"{item_dir.name} declares {result.declared_type!r} and escalated: "
        f"{[f.message for f in result.findings]}"
    )
    assert result.verdict in (
        Verdict.APPROVE,
        Verdict.ANALYZE_STATIC,
        Verdict.SANDBOX_REQUIRED,
    )
