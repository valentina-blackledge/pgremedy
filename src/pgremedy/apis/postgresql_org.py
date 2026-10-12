"""postgresql.org release data: latest minor release and end-of-life date per branch."""

from __future__ import annotations

from typing import Any

import requests

from pgremedy import __version__
from pgremedy.errors import SourceUnavailable, describe

VERSIONS_URL = "https://www.postgresql.org/versions.json"


def fetch_versions() -> list[dict[str, Any]]:
    """One entry per major version: major, latestMinor, supported, eolDate, ..."""
    try:
        resp = requests.get(VERSIONS_URL, headers={"User-Agent": f"pgremedy/{__version__}"}, timeout=30)
    except requests.RequestException as exc:
        raise SourceUnavailable("postgresql.org", describe(exc)) from exc
    if resp.status_code != 200:
        raise SourceUnavailable("postgresql.org", f"HTTP {resp.status_code}")
    try:
        data = resp.json()
    except ValueError as exc:
        raise SourceUnavailable("postgresql.org", "the response was not valid JSON") from exc
    if not isinstance(data, list) or not all(isinstance(e, dict) and "major" in e for e in data):
        raise SourceUnavailable("postgresql.org", "unexpected response format")
    return data
