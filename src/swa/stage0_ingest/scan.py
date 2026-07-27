"""On-demand scan of the Workshop folder.

Pull model: the Steam folder is read ONLY when the command is invoked, with no
background watcher process. Safe because the documented payload runs when the
wallpaper is applied, not when it is downloaded.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from swa.stage0_ingest.quarantine import compute_content_hash
from swa.state import State
from swa.steam.libraryfolders import find_workshop_content


@dataclass
class ScannedItem:
    workshop_id: str
    source_dir: Path
    content_hash: str
    is_new_or_changed: bool


def scan(content_dir: str | Path | None = None, state: State | None = None) -> list[ScannedItem]:
    """Enumerate installed items and mark which are new or have changed.

    If `content_dir` is None, it is auto-located via libraryfolders.vdf.
    """
    root = Path(content_dir) if content_dir else find_workshop_content()
    owns_state = state is None
    st = state or State()
    try:
        results: list[ScannedItem] = []
        for sub in sorted(root.iterdir()):
            if not sub.is_dir() or not sub.name.isdigit():
                continue
            chash = compute_content_hash(sub)
            changed = not st.is_unchanged(sub.name, chash)
            results.append(
                ScannedItem(
                    workshop_id=sub.name,
                    source_dir=sub,
                    content_hash=chash,
                    is_new_or_changed=changed,
                )
            )
        return results
    finally:
        if owns_state:
            st.close()
