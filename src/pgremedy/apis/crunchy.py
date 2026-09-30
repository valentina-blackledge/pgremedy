"""Crunchy Data releases API client."""

from __future__ import annotations

from typing import Any

import requests

RELEASES_API = "https://api.github.com/repos/CrunchyData/postgres-operator/releases"
HEADERS = {"User-Agent": "pgremedy/0.1.0"}


def fetch_releases(per_page: int = 30) -> list[dict]:
    try:
        resp = requests.get(RELEASES_API, headers=HEADERS, params={"per_page": per_page}, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException:
        return []


def find_cve_in_releases(cve_id: str, releases: list[dict] | None = None) -> dict[str, Any] | None:
    if releases is None:
        releases = fetch_releases()
    cve_upper = cve_id.upper()
    for r in releases:
        body = (r.get("body") or "").upper()
        name = (r.get("name") or "").upper()
        if cve_upper in body or cve_upper in name:
            return {
                "release_tag": r.get("tag_name"),
                "release_name": r.get("name"),
                "published": (r.get("published_at") or "")[:10],
                "prerelease": r.get("prerelease", False),
                "url": r.get("html_url"),
            }
    return None
