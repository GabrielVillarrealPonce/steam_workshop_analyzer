"""Central configuration: paths, thresholds and pipeline constants."""

from __future__ import annotations

from pathlib import Path

# Wallpaper Engine's Steam AppID.
WALLPAPER_ENGINE_APPID = 431960

# Quarantine directory: outside the Steam tree, inside the repo by default.
QUARANTINE_ROOT = Path(__file__).resolve().parents[2] / "quarantine"

# State database (items already analyzed, keyed by hash).
STATE_DB = QUARANTINE_ROOT / "state.sqlite3"

# Safe-extraction limits (anti zip-bomb).
MAX_EXTRACT_ENTRIES = 10_000
MAX_EXTRACT_TOTAL_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB
MAX_COMPRESSION_RATIO = 100  # uncompressed/compressed

# .pkg container reader limits (anti malformed file).
MAX_PKG_ENTRIES = 100_000
MAX_PKG_NAME_LEN = 4096
