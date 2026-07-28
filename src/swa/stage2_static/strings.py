"""Printable-string extraction and the binary IOC scan.

Malware rarely exposes its intent in imports alone -- the damning evidence is
usually in the strings: hardcoded C2 URLs, the path to Steam's loginusers.vdf,
a wallet address, an embedded PowerShell one-liner. This module pulls the
printable runs out of a binary (both ASCII and UTF-16LE, since Windows strings
are frequently wide) and runs the shared content-IOC scan over them.
"""

from __future__ import annotations

import re

from ..models import Finding
from . import indicators
from .config import DEFAULT_CONFIG, StaticConfig

# Byte-string templates (formatted with min_len at call time, then compiled).
# A printable ASCII run: space through '~'.
_ASCII_RUN = rb"[\x20-\x7e]{%d,}"
# A UTF-16LE run: printable ASCII byte followed by a NUL, repeated.
_UTF16_RUN = rb"(?:[\x20-\x7e]\x00){%d,}"


def extract_strings(data: bytes, min_len: int) -> list[str]:
    """Return printable ASCII and UTF-16LE strings of length >= min_len."""
    if min_len < 1:
        min_len = 1
    ascii_re = re.compile(_ASCII_RUN % min_len)
    utf16_re = re.compile(_UTF16_RUN % min_len)

    out: list[str] = [m.decode("ascii", "replace") for m in ascii_re.findall(data)]
    out += [
        m.decode("utf-16-le", "replace") for m in utf16_re.findall(data)
    ]
    return out


def scan_binary(
    data: bytes,
    name: str,
    allowed_domains: set[str],
    config: StaticConfig = DEFAULT_CONFIG,
) -> list[Finding]:
    """Extract strings from a binary and scan them for content IOCs."""
    strings = extract_strings(data, config.min_string_len)
    # Join with newlines so multi-token regexes (e.g. encoded PowerShell) can
    # still match within a single extracted string, but not bleed across two
    # unrelated ones on the same line.
    blob = "\n".join(strings)
    return indicators.scan_common_iocs(blob, name, allowed_domains, config)
