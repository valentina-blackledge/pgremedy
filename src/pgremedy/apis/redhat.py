"""Red Hat Security Data API client."""

from __future__ import annotations

from typing import Any

import requests

from pgremedy import __version__
from pgremedy.errors import SourceUnavailable, describe

CVE_API = "https://access.redhat.com/hydra/rest/securitydata/cve"


def _get_json(url: str, params: dict | None = None) -> Any:
    """GET a Red Hat API URL. None means "no such record"; failures raise SourceUnavailable."""
    try:
        resp = requests.get(url, headers={"User-Agent": f"pgremedy/{__version__}"}, params=params, timeout=30)
    except requests.RequestException as exc:
        raise SourceUnavailable("Red Hat", describe(exc)) from exc
    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        raise SourceUnavailable("Red Hat", f"HTTP {resp.status_code}")
    try:
        return resp.json()
    except ValueError as exc:
        raise SourceUnavailable("Red Hat", "the response was not valid JSON") from exc


def fetch_cve(cve_id: str) -> dict[str, Any] | None:
    return _get_json(f"{CVE_API}/{cve_id}.json")


def search_by_package(
    package: str,
    severity: str | None = None,
    days_ago: int = 90,
    per_page: int = 50,
) -> list[dict]:
    params: dict[str, Any] = {"package": package, "created_days_ago": days_ago, "per_page": per_page}
    if severity:
        params["severity"] = severity
    data = _get_json(f"{CVE_API}.json", params)
    return data if isinstance(data, list) else []
