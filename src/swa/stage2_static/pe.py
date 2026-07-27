"""Structural static analysis of a PE (Windows .exe/.dll).

A minimal, dependency-free PE reader (stdlib `struct` only -- the same choice
the Stage 1 magic-byte detector already makes, and it keeps the analyzer
free of a native `pefile` build). It extracts exactly the structural signals
the design doc calls for and nothing more:

  * digital signature present or absent (Certificate directory)
  * packed / encrypted sections (high entropy, or a known packer section name)
  * suspicious imports grouped by capability (injection, network, ...)

The string-based IOCs (C2 URLs, Steam paths, wallets) are handled separately
by strings.py over the same bytes -- this module is only the header work.

Every parse step is bounded and wrapped: a truncated or hostile file yields an
INFO 'pe_parse_incomplete' finding plus whatever was recovered, never an
exception that would abort the whole stage.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ..models import Finding, Severity
from . import indicators
from .config import DEFAULT_CONFIG, StaticConfig

IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_SECURITY = 4
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000

# Section names that betray a known packer/protector.
_PACKER_SECTIONS = (
    "upx",
    ".aspack",
    ".adata",
    ".nsp",
    ".packed",
    ".themida",
    ".vmp",
    ".enigma",
    ".petite",
    ".mpress",
)


@dataclass
class _Section:
    name: str
    vaddr: int
    vsize: int
    raw_ptr: int
    raw_size: int
    characteristics: int


def _u16(d: bytes, o: int) -> int:
    return struct.unpack_from("<H", d, o)[0]


def _u32(d: bytes, o: int) -> int:
    return struct.unpack_from("<I", d, o)[0]


def _read_cstr(d: bytes, o: int, maxlen: int = 256) -> str:
    end = d.find(b"\x00", o, o + maxlen)
    if end == -1:
        end = min(o + maxlen, len(d))
    return d[o:end].decode("ascii", "replace")


def _rva_to_offset(sections: list[_Section], rva: int) -> int | None:
    for s in sections:
        span = max(s.vsize, s.raw_size)
        if s.vaddr <= rva < s.vaddr + span:
            return s.raw_ptr + (rva - s.vaddr)
    return None


def _parse_sections(data: bytes, table_off: int, count: int) -> list[_Section]:
    sections: list[_Section] = []
    for i in range(min(count, 96)):  # PE spec caps at 96 sections
        base = table_off + i * 40
        if base + 40 > len(data):
            break
        name = data[base : base + 8].split(b"\x00", 1)[0].decode("ascii", "replace")
        sections.append(
            _Section(
                name=name,
                vsize=_u32(data, base + 8),
                vaddr=_u32(data, base + 12),
                raw_size=_u32(data, base + 16),
                raw_ptr=_u32(data, base + 20),
                characteristics=_u32(data, base + 36),
            )
        )
    return sections


def _walk_imports(
    data: bytes,
    sections: list[_Section],
    import_rva: int,
    is_pe32_plus: bool,
    config: StaticConfig,
) -> set[str]:
    """Collect imported function names (lowercased) from the import table."""
    imported: set[str] = set()
    idt_off = _rva_to_offset(sections, import_rva)
    if idt_off is None:
        return imported

    thunk_size = 8 if is_pe32_plus else 4
    ordinal_flag = 0x8000000000000000 if is_pe32_plus else 0x80000000
    unpack = "<Q" if is_pe32_plus else "<I"

    for d in range(config.max_import_dlls):
        desc = idt_off + d * 20
        if desc + 20 > len(data):
            break
        original_first_thunk = _u32(data, desc)
        name_rva = _u32(data, desc + 12)
        first_thunk = _u32(data, desc + 16)
        if original_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
            break  # null terminator descriptor

        thunk_rva = original_first_thunk or first_thunk
        thunk_off = _rva_to_offset(sections, thunk_rva)
        if thunk_off is None:
            continue

        t = thunk_off
        while len(imported) < config.max_import_symbols:
            if t + thunk_size > len(data):
                break
            entry = struct.unpack_from(unpack, data, t)[0]
            t += thunk_size
            if entry == 0:
                break
            if entry & ordinal_flag:
                continue  # import by ordinal: no name to inspect
            hint_off = _rva_to_offset(sections, entry & 0x7FFFFFFF)
            if hint_off is None:
                continue
            fn = _read_cstr(data, hint_off + 2)  # skip the 2-byte hint
            if fn:
                imported.add(fn.lower())
        if len(imported) >= config.max_import_symbols:
            break

    return imported


def analyze_pe(
    data: bytes,
    name: str,
    config: StaticConfig = DEFAULT_CONFIG,
) -> list[Finding]:
    """Header-level static analysis of PE bytes. Returns structural findings
    (signature, packing, imports). String IOCs are covered by strings.py."""
    findings: list[Finding] = []
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return findings
        e_lfanew = _u32(data, 0x3C)
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return findings

        coff = e_lfanew + 4
        num_sections = _u16(data, coff + 2)
        size_opt = _u16(data, coff + 16)
        opt = coff + 20
        magic = _u16(data, opt)
        is_pe32_plus = magic == 0x20B

        # Data directories: located just past the fixed part of the optional
        # header, which differs between PE32 and PE32+.
        if is_pe32_plus:
            num_dirs_off, dir_off = opt + 108, opt + 112
        else:
            num_dirs_off, dir_off = opt + 92, opt + 96
        num_dirs = _u32(data, num_dirs_off) if num_dirs_off + 4 <= len(data) else 0

        def directory(index: int) -> tuple[int, int]:
            if index >= num_dirs:
                return (0, 0)
            base = dir_off + index * 8
            if base + 8 > len(data):
                return (0, 0)
            return (_u32(data, base), _u32(data, base + 4))

        sections = _parse_sections(data, opt + size_opt, num_sections)

        # --- Digital signature (Certificate directory) ---
        _, sec_size = directory(IMAGE_DIRECTORY_ENTRY_SECURITY)
        if sec_size == 0:
            findings.append(
                Finding(
                    code="pe_unsigned",
                    severity=Severity.LOW,
                    message="no Authenticode digital signature",
                    path=name,
                )
            )

        # --- Packing / high entropy per section ---
        for s in sections:
            low = s.name.lower()
            if any(low.startswith(p) for p in _PACKER_SECTIONS):
                findings.append(
                    Finding(
                        code="pe_known_packer",
                        severity=Severity.MEDIUM,
                        message=f"known packer/protector section '{s.name}'",
                        path=name,
                    )
                )
                continue
            start = s.raw_ptr
            end = min(s.raw_ptr + s.raw_size, len(data))
            if end - start < config.min_entropy_section_bytes:
                continue
            is_code = bool(
                s.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)
            )
            if not is_code:
                continue
            ent = indicators.entropy(data[start:end])
            if ent >= config.entropy_threshold:
                findings.append(
                    Finding(
                        code="pe_high_entropy_section",
                        severity=Severity.MEDIUM,
                        message=(
                            f"executable section '{s.name}' entropy {ent:.2f} "
                            f">= {config.entropy_threshold} (packed/encrypted)"
                        ),
                        path=name,
                    )
                )

        # --- Imports grouped by capability ---
        import_rva, _ = directory(IMAGE_DIRECTORY_ENTRY_IMPORT)
        if import_rva:
            imported = _walk_imports(data, sections, import_rva, is_pe32_plus, config)
            for category, (sev, label, needles) in indicators.IMPORT_CATEGORIES.items():
                hits = sorted(
                    {n for n in needles if any(n in fn for fn in imported)}
                )
                if hits:
                    findings.append(
                        Finding(
                            code=f"pe_import_{category}",
                            severity=sev,
                            message=f"{label}: imports {', '.join(hits)}",
                            path=name,
                        )
                    )

    except (struct.error, IndexError, ValueError) as exc:
        findings.append(
            Finding(
                code="pe_parse_incomplete",
                severity=Severity.INFO,
                message=f"PE header parse stopped early: {exc}",
                path=name,
            )
        )

    return findings
