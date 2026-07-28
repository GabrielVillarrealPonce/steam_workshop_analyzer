"""Command-line interface: chains ingestion (Stage 0) and triage (Stage 1).

    swa scan [--appid N] [--no-metadata]
                                  enumerate, ingest and triage installed items
                                  of a Steam title (default: Wallpaper Engine)
    swa triage <path>            triage a standalone directory (development)
    swa show <workshop_id>       last recorded verdict
    swa analyze <path>           full agent loop over a directory: ingest, then
                                  let Claude drive Stage 1-5 via the MCP tools
    swa analyze-id <id> [--appid N]
                                  same, but locate the item by its Workshop ID
                                  in the installed Steam library
                                  (analyze / analyze-id require ANTHROPIC_API_KEY)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from swa.config import WALLPAPER_ENGINE_APPID
from swa.models import Verdict, WorkshopItem
from swa.stage0_ingest import quarantine
from swa.stage0_ingest.scan import scan
from swa.stage1_triage import triage as triage_mod
from swa.state import State
from swa.steam import metadata as metadata_mod
from swa.steam.libraryfolders import SteamNotFoundError, find_workshop_content

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
        items = scan(appid=args.appid)
    except SteamNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    new_items = [i for i in items if i.is_new_or_changed]
    print(
        f"AppID {args.appid}: {len(items)} items installed, "
        f"{len(new_items)} new or changed.\n"
    )

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


def _cmd_analyze(args: argparse.Namespace) -> int:
    import os

    source = Path(args.path)
    if not source.is_dir():
        print(f"error: not a directory: {source}", file=sys.stderr)
        return 2
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("error: ANTHROPIC_API_KEY is not set.", file=sys.stderr)
        return 2

    from swa.agent import DEFAULT_MODEL, analyze_path

    print(analyze_path(str(source), model=args.model or DEFAULT_MODEL))
    return 0


def _cmd_analyze_id(args: argparse.Namespace) -> int:
    """Full agent loop over an installed item located by its Workshop ID.

    Resolves `steamapps/workshop/content/<appid>/<workshop_id>` in the local
    Steam library (across disks, via libraryfolders.vdf) and runs the same
    agent loop as `analyze`. Works for any Steam title, not just Wallpaper
    Engine -- pass the game's AppID with --appid.
    """
    import os

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("error: ANTHROPIC_API_KEY is not set.", file=sys.stderr)
        return 2
    try:
        content = find_workshop_content(args.appid)
    except SteamNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    item_dir = content / args.workshop_id
    if not item_dir.is_dir():
        print(
            f"error: item {args.workshop_id} not installed under AppID "
            f"{args.appid} (looked in {item_dir})",
            file=sys.stderr,
        )
        return 2

    from swa.agent import DEFAULT_MODEL, analyze_path

    print(analyze_path(str(item_dir), model=args.model or DEFAULT_MODEL))
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
    p_scan.add_argument(
        "--appid",
        type=int,
        default=WALLPAPER_ENGINE_APPID,
        help=f"Steam AppID of the title whose Workshop to scan (default: {WALLPAPER_ENGINE_APPID}, Wallpaper Engine)",
    )
    p_scan.add_argument("--no-metadata", action="store_true", help="do not query the Steam Web API")
    p_scan.set_defaults(func=_cmd_scan)

    p_triage = sub.add_parser("triage", help="triage a standalone directory")
    p_triage.add_argument("path", help="wallpaper directory")
    p_triage.set_defaults(func=_cmd_triage)

    p_show = sub.add_parser("show", help="last verdict of an item")
    p_show.add_argument("workshop_id")
    p_show.set_defaults(func=_cmd_show)

    p_analyze = sub.add_parser(
        "analyze", help="full agent loop over a standalone directory (needs ANTHROPIC_API_KEY)"
    )
    p_analyze.add_argument("path", help="wallpaper directory")
    p_analyze.add_argument("--model", help="override the default (cheapest) model")
    p_analyze.set_defaults(func=_cmd_analyze)

    p_analyze_id = sub.add_parser(
        "analyze-id",
        help="full agent loop over an installed item, located by Workshop ID (needs ANTHROPIC_API_KEY)",
    )
    p_analyze_id.add_argument("workshop_id", help="Steam Workshop item ID")
    p_analyze_id.add_argument(
        "--appid",
        type=int,
        default=WALLPAPER_ENGINE_APPID,
        help=f"Steam AppID the item belongs to (default: {WALLPAPER_ENGINE_APPID}, Wallpaper Engine)",
    )
    p_analyze_id.add_argument("--model", help="override the default (cheapest) model")
    p_analyze_id.set_defaults(func=_cmd_analyze_id)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
