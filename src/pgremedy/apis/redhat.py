"""Red Hat Security API client."""

from __future__ import annotations

from typing import Any

import requests

CVE_API = "https://access.redhat.com/hydra/rest/securitydata/cve"
ERRATA_API = "https://access.redhat.com/hydra/rest/securitydata/errata"
HEADERS = {"User-Agent": "pgremedy/0.1.0"}


def _get_json(url: str, params: dict | None = None) -> Any:
    try:
        resp = requests.get(url, headers=HEADERS, params=params, timeout=30)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException:
        return None


def fetch_cve(cve_id: str) -> dict[str, Any] | None:
    return _get_json(f"{CVE_API}/{cve_id}.json")


def fetch_errata(cve_id: str) -> list[dict]:
    data = _get_json(f"{ERRATA_API}.json", {"cve": cve_id})
    return data if isinstance(data, list) else []


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
