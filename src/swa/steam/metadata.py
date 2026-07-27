"""Item metadata via the Steam Web API (no game ownership required).

Useful signals for the decision engine (Stage 4): account age, recency of the
last update, subscription count. NOT a blocker for stages 0-1: if the network
fails, ingestion continues with empty metadata.
"""

from __future__ import annotations

from typing import Any

_ENDPOINT = "https://api.steampowered.com/ISteamRemoteStorage/GetPublishedFileDetails/v1/"


def fetch(workshop_id: str, timeout: float = 10.0) -> dict[str, Any]:
    """Return the item's metadata, or {} if it could not be obtained.

    Public endpoint that needs no API key. To verify in production: if it stops
    returning useful data, migrate to IPublishedFileService/GetDetails with an
    API key.
    """
    try:
        import requests
    except ImportError:
        return {}

    try:
        resp = requests.post(
            _ENDPOINT,
            data={"itemcount": 1, "publishedfileids[0]": workshop_id},
            timeout=timeout,
        )
        resp.raise_for_status()
        payload = resp.json()
    except Exception:  # network, timeout, invalid JSON: degrade to empty
        return {}

    details = (
        payload.get("response", {}).get("publishedfiledetails", [{}])
    )
    if not details:
        return {}
    d = details[0]
    if d.get("result") != 1:  # 1 == OK in the Steam Web API
        return {}

    return {
        "title": d.get("title"),
        "creator": d.get("creator"),
        "time_created": d.get("time_created"),
        "time_updated": d.get("time_updated"),
        "subscriptions": d.get("subscriptions"),
        "views": d.get("views"),
        "file_size": d.get("file_size"),
        "tags": [t.get("tag") for t in d.get("tags", []) if isinstance(t, dict)],
    }
