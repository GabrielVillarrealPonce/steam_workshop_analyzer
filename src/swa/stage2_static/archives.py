"""Detection of the password-protected-archive-with-embedded-password pattern.

Straight from the campaign the design doc cites: the payload sits in a
password-protected .zip/.rar shipped inside the wallpaper, and the password is
hidden in plain sight -- in the archive's own filename or in one of the
wallpaper's config/JSON files. As the doc puts it, this is itself a
high-severity indicator: a legitimate author has no reason to hide their own
assets from the user.

Stage 1 already flags the *presence* of an encrypted archive (as suspicion).
Stage 2's job here is the confirming step: finding the password stashed
alongside it, which turns suspicion into a HIGH (block-worthy) finding.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..models import FileType, Finding, Severity, WorkshopItem
from .config import DEFAULT_CONFIG, StaticConfig

# A password hint in a filename: pass/pwd/clave/contrase(n|ñ)a/unlock, or a
# stem that ends in an underscore-delimited alphanumeric token.
_FILENAME_HINT_RE = re.compile(
    r"(pass|pwd|passwd|clave|contrase|unlock|key)", re.IGNORECASE
)
# A password declared in a config file: a "password"-like key with a value.
_CONFIG_HINT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|contrase[nñ]a|clave|unlock[\s_-]*code)\b\s*[\"']?\s*[:=]"
)

# Config/text file types worth reading for a stashed password.
_TEXT_TYPES = {FileType.JSON, FileType.TEXT, FileType.HTML}


def detect_embedded_password(
    item: WorkshopItem,
    encrypted_paths: list[str],
    root: Path,
    config: StaticConfig = DEFAULT_CONFIG,
) -> list[Finding]:
    """Return HIGH findings if a password for an encrypted archive appears in
    its filename or in any of the package's config/text files."""
    findings: list[Finding] = []

    for rel in encrypted_paths:
        stem = Path(rel).stem
        if _FILENAME_HINT_RE.search(stem):
            findings.append(
                Finding(
                    code="archive_password_in_filename",
                    severity=Severity.HIGH,
                    message=(
                        "password-protected archive whose filename embeds the "
                        f"password/unlock hint ('{Path(rel).name}')"
                    ),
                    path=rel,
                )
            )

    if not encrypted_paths:
        return findings

    # Scan config/text files once; a hit implicates every encrypted archive.
    for entry in item.files:
        if entry.filetype not in _TEXT_TYPES:
            continue
        fpath = root / entry.path
        try:
            text = fpath.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            continue
        text = text[: config.max_scan_bytes]
        if _CONFIG_HINT_RE.search(text):
            findings.append(
                Finding(
                    code="archive_password_in_config",
                    severity=Severity.HIGH,
                    message=(
                        "a config/text file declares a password/unlock code "
                        "for a password-protected archive shipped in the package"
                    ),
                    path=entry.path,
                )
            )
            break  # one confirming file is enough

    return findings
