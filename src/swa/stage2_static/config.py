"""Tunable configuration for Stage 2 (static analysis).

Kept separate from the analysis logic (same pattern as swa.stage4_decision)
so thresholds can be overridden in a test or a stricter deployment without
touching the detectors.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StaticConfig:
    # Hard cap on how many bytes we read per file. Bounds both cost and the
    # damage a hostile, deliberately huge file can do to the analyzer host.
    max_scan_bytes: int = 16 * 1024 * 1024  # 16 MiB

    # Minimum length of a printable run extracted from a binary as a "string".
    min_string_len: int = 5

    # Shannon entropy (bits/byte, 0..8) above which a code/data section is
    # treated as packed or encrypted. 7.2 is the conventional UPX/crypter line;
    # legitimately compressed resources can approach it, hence MEDIUM not HIGH.
    entropy_threshold: float = 7.2
    # Only score entropy on sections large enough for the measure to be
    # meaningful (a 40-byte section is noise, not evidence).
    min_entropy_section_bytes: int = 1024

    # A quoted literal of at least this many base64/hex chars reads as an
    # obfuscated blob rather than incidental data.
    long_blob_len: int = 200
    # This many String.fromCharCode(...) calls is string-array obfuscation.
    fromcharcode_threshold: int = 8

    # Upper bound on how many distinct undeclared hosts we emit as separate
    # findings, so a file listing hundreds of URLs can't saturate the score by
    # itself (it still gets flagged, just not once per host).
    max_undeclared_host_findings: int = 5

    # PE import-walk safety bounds (hostile files can craft loops/huge tables).
    max_import_dlls: int = 256
    max_import_symbols: int = 8192


DEFAULT_CONFIG = StaticConfig()
