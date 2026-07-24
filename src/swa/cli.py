"""Command-line interface: chains ingestion (Stage 0) and triage (Stage 1).

    swa scan [--no-metadata]     enumerate, ingest new items and triage them
    swa triage <path>            triage a standalone directory (development)
    swa show <workshop_id>       last recorded verdict
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from swa.models import Verdict, WorkshopItem
from swa.stage0_ingest import quarantine
from swa.stage0_ingest.scan import scan
from swa.stage1_triage import triage as triage_mod
from swa.state import State
from swa.steam import metadata as metadata_mod
from swa.steam.libraryfolders import SteamNotFoundError

# Visual marker per verdict for the summary table.
_MARK = {
    Verdict.APPROVE: "[OK ]",
    Verdict.ANALYZE_STATIC: "[STA]",
    Verdict.SANDBOX_REQUIRED: "[SBX]",
    Verdict.ESCALATE: "[ESC]",
    Verdict.BLOCK: "[BLK]",
}


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        items = scan()
    except SteamNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    new_items = [i for i in items if i.is_new_or_changed]
    print(f"{len(items)} items installed, {len(new_items)} new or changed.\n")

    with State() as st:
        for si in items:
            if not si.is_new_or_changed:
                print(f"[   ] {si.workshop_id}  (unchanged, skipped)")
                continue

            meta = {} if args.no_metadata else metadata_mod.fetch(si.workshop_id)
            item = quarantine.ingest(si.workshop_id, si.source_dir, metadata=meta)
            result = triage_mod.triage(item)
            result.write(str(Path(item.quarantine_dir) / "triage.json"))
            st.record(si.workshop_id, si.content_hash, result.verdict.value)

            mark = _MARK.get(result.verdict, "[?  ]")
            hi = [f for f in result.findings if f.severity.value == "high"]
            extra = f"  !! {len(hi)} high-severity finding(s)" if hi else ""
            print(f"{mark} {si.workshop_id}  {result.verdict.value}{extra}")

    return 0


def _cmd_triage(args: argparse.Namespace) -> int:
    source = Path(args.path)
    if not source.is_dir():
        print(f"error: not a directory: {source}", file=sys.stderr)
        return 2
    item = quarantine.ingest(source.name, source, metadata={})
    result = triage_mod.triage(item)
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    with State() as st:
        h = st.content_hash(args.workshop_id)
        if h is None:
            print(f"{args.workshop_id}: no prior record.")
            return 1
        row = st._conn.execute(
            "SELECT verdict, analyzed_at FROM analyzed WHERE workshop_id = ?",
            (args.workshop_id,),
        ).fetchone()
        print(f"{args.workshop_id}: {row[0]}  (analyzed {row[1]})")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="swa", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan, ingest and triage new items")
    p_scan.add_argument("--no-metadata", action="store_true", help="do not query the Steam Web API")
    p_scan.set_defaults(func=_cmd_scan)

    p_triage = sub.add_parser("triage", help="triage a standalone directory")
    p_triage.add_argument("path", help="wallpaper directory")
    p_triage.set_defaults(func=_cmd_triage)

    p_show = sub.add_parser("show", help="last verdict of an item")
    p_show.add_argument("workshop_id")
    p_show.set_defaults(func=_cmd_show)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
