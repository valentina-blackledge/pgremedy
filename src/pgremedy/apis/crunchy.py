"""Crunchy Data releases API client."""

from __future__ import annotations

import os
import re
from typing import Any

import requests

from pgremedy import __version__, offline
from pgremedy.errors import SourceUnavailable, describe

RELEASES_API = "https://api.github.com/repos/CrunchyData/postgres-operator/releases"
SOURCE = "GitHub (Crunchy PGO releases)"
PAGE_SIZE = 100          # GitHub's maximum
MAX_PAGES = 10


def _headers() -> dict[str, str]:
    headers = {"User-Agent": f"pgremedy/{__version__}", "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"     # 5,000 requests an hour instead of 60
    return headers


def _get_page(page: int) -> list[dict]:
    try:
        resp = requests.get(RELEASES_API, headers=_headers(), params={"per_page": PAGE_SIZE, "page": page}, timeout=30)
    except requests.RequestException as exc:
        raise SourceUnavailable(SOURCE, describe(exc)) from exc
    if resp.status_code in (403, 429) and "rate limit" in resp.text.lower():
        raise SourceUnavailable(SOURCE, "GitHub API rate limit reached (60 requests an hour without a token; "
                                        "set GITHUB_TOKEN to raise it)")
    if resp.status_code != 200:
        raise SourceUnavailable(SOURCE, f"HTTP {resp.status_code}")
    try:
        data = resp.json()
    except ValueError as exc:
        raise SourceUnavailable(SOURCE, "the response was not valid JSON") from exc
    if not isinstance(data, list):
        raise SourceUnavailable(SOURCE, "unexpected response format")
    return data


def fetch_releases() -> list[dict]:
    """Every PGO release, newest first, following GitHub's pages.

    Raises SourceUnavailable rather than returning a partial or empty list: a
    CVE not found in the notes must mean it isn't mentioned, not that some
    notes went unread.
    """
    bundle = offline.active()
    if bundle is not None:
        releases = bundle.crunchy()
    else:
        releases = []
        for page in range(1, MAX_PAGES + 1):
            data = _get_page(page)
            releases.extend(data)
            if len(data) < PAGE_SIZE:
                break
        else:
            raise SourceUnavailable(SOURCE, f"more than {MAX_PAGES * PAGE_SIZE} releases")
    if not releases:
        raise SourceUnavailable(SOURCE, "no releases listed")
    return releases


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
