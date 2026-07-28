"""Persistent state: which items were analyzed and with which content hash.

Lets us skip unchanged items and, when the hash changes (a wallpaper update),
force a re-analysis from scratch -- exactly the "recent suspicious edits" signal
from the design document.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from swa.config import STATE_DB


class State:
    def __init__(self, db_path: str | Path = STATE_DB):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analyzed (
                workshop_id   TEXT PRIMARY KEY,
                content_hash  TEXT NOT NULL,
                verdict       TEXT,
                analyzed_at   TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def content_hash(self, workshop_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT content_hash FROM analyzed WHERE workshop_id = ?",
            (workshop_id,),
        ).fetchone()
        return row[0] if row else None

    def is_unchanged(self, workshop_id: str, content_hash: str) -> bool:
        return self.content_hash(workshop_id) == content_hash

    def record(self, workshop_id: str, content_hash: str, verdict: str) -> None:
        self._conn.execute(
            """
            INSERT INTO analyzed (workshop_id, content_hash, verdict, analyzed_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(workshop_id) DO UPDATE SET
                content_hash = excluded.content_hash,
                verdict = excluded.verdict,
                analyzed_at = excluded.analyzed_at
            """,
            (workshop_id, content_hash, verdict, datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "State":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
