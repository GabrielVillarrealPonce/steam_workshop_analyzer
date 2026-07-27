"""Locate the Workshop content folder by parsing Steam's config.

Wallpaper Engine may be installed in any Steam library (secondary disks
included), so the path CANNOT be hardcoded: we have to read
`libraryfolders.vdf` and find which library declares the appid.
"""

from __future__ import annotations

import re
from pathlib import Path

from swa.config import WALLPAPER_ENGINE_APPID


class SteamNotFoundError(RuntimeError):
    """Could not locate the Steam installation or the requested appid."""


# Usual Steam installation paths on Windows.
_DEFAULT_STEAM_PATHS = [
    Path(r"C:\Program Files (x86)\Steam"),
    Path(r"C:\Program Files\Steam"),
]


def _steam_path_from_registry() -> Path | None:
    """Read HKCU\\Software\\Valve\\Steam\\SteamPath. Returns None if N/A."""
    try:
        import winreg  # Windows only
    except ImportError:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam") as key:
            value, _ = winreg.QueryValueEx(key, "SteamPath")
        p = Path(value)
        return p if p.exists() else None
    except OSError:
        return None


def find_steam_root() -> Path:
    """Return the Steam installation root."""
    candidate = _steam_path_from_registry()
    if candidate:
        return candidate
    for p in _DEFAULT_STEAM_PATHS:
        if p.exists():
            return p
    raise SteamNotFoundError(
        "Steam installation not found (neither registry nor default paths)."
    )


def _parse_library_paths(vdf_text: str) -> list[tuple[Path, set[int]]]:
    """Parse libraryfolders.vdf -> list of (library_path, {appids}).

    VDF is a "key" "value" pair format with {} blocks. Instead of a full
    parser, we extract each library block's `path` and the appids listed in its
    `apps` section, which is all we need.
    """
    results: list[tuple[Path, set[int]]] = []
    # Each library is a numbered block: "0" { ... } "1" { ... }
    for block in re.finditer(r'"\d+"\s*\{(.*?)\n\t\}', vdf_text, re.DOTALL):
        body = block.group(1)
        path_match = re.search(r'"path"\s*"([^"]+)"', body)
        if not path_match:
            continue
        lib_path = Path(path_match.group(1).replace("\\\\", "\\"))
        apps_match = re.search(r'"apps"\s*\{(.*?)\}', body, re.DOTALL)
        appids: set[int] = set()
        if apps_match:
            for aid in re.finditer(r'"(\d+)"\s*"\d+"', apps_match.group(1)):
                appids.add(int(aid.group(1)))
        results.append((lib_path, appids))
    return results


def find_workshop_content(appid: int = WALLPAPER_ENGINE_APPID) -> Path:
    """Path of `steamapps/workshop/content/<appid>` for the given appid.

    Raises SteamNotFoundError if Steam is missing or the appid is not installed
    in any library (explicit error, never a silent None).
    """
    steam_root = find_steam_root()
    vdf = steam_root / "steamapps" / "libraryfolders.vdf"
    if not vdf.exists():
        raise SteamNotFoundError(f"{vdf} does not exist")

    libraries = _parse_library_paths(vdf.read_text(encoding="utf-8", errors="replace"))
    for lib_path, appids in libraries:
        if appid in appids:
            content = lib_path / "steamapps" / "workshop" / "content" / str(appid)
            if content.exists():
                return content

    # Fallback: some setups don't list apps in the block; try the root itself.
    fallback = steam_root / "steamapps" / "workshop" / "content" / str(appid)
    if fallback.exists():
        return fallback

    raise SteamNotFoundError(
        f"Appid {appid} does not appear installed in any Steam library. "
        f"Subscribe to the item from the Steam client first."
    )
