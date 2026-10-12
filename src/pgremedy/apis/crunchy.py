"""Crunchy Data releases API client."""

from __future__ import annotations

import re
from typing import Any

import requests

from pgremedy import __version__
from pgremedy.errors import SourceUnavailable, describe

RELEASES_API = "https://api.github.com/repos/CrunchyData/postgres-operator/releases"
SOURCE = "GitHub (Crunchy PGO releases)"


def fetch_releases(per_page: int = 30) -> list[dict]:
    try:
        resp = requests.get(
            RELEASES_API,
            headers={"User-Agent": f"pgremedy/{__version__}"},
            params={"per_page": per_page},
            timeout=30,
        )
    except requests.RequestException as exc:
        raise SourceUnavailable(SOURCE, describe(exc)) from exc
    if resp.status_code == 403 and "rate limit" in resp.text.lower():
        raise SourceUnavailable(SOURCE, "GitHub API rate limit reached (60 requests an hour without a token)")
    if resp.status_code != 200:
        raise SourceUnavailable(SOURCE, f"HTTP {resp.status_code}")
    try:
        data = resp.json()
    except ValueError as exc:
        raise SourceUnavailable(SOURCE, "the response was not valid JSON") from exc
    return data if isinstance(data, list) else []


def find_cve_in_releases(cve_id: str, releases: list[dict] | None = None) -> dict[str, Any] | None:
    if releases is None:
        releases = fetch_releases()
    # Whole IDs only: CVE-2024-1097 must not match CVE-2024-10978.
    pattern = re.compile(rf"\b{re.escape(cve_id.upper())}\b")
    for r in releases:
        body = (r.get("body") or "").upper()
        name = (r.get("name") or "").upper()
        if pattern.search(body) or pattern.search(name):
            return {
                "release_tag": r.get("tag_name"),
                "release_name": r.get("name"),
                "published": (r.get("published_at") or "")[:10],
                "prerelease": r.get("prerelease", False),
                "url": r.get("html_url"),
            }
    return None
