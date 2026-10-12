"""Red Hat Security Data API client."""

from __future__ import annotations

from typing import Any

import requests

from pgremedy import __version__
from pgremedy.errors import SourceUnavailable, describe
from pgremedy.models import RedHatInfo, RedHatPackageState, RedHatPatch

CVE_API = "https://access.redhat.com/hydra/rest/securitydata/cve"

# Red Hat fills the mitigation field with this sentence when it has nothing to offer.
NO_MITIGATION_PREFIX = "mitigation for this issue is either not available"


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


def to_info(rh: dict[str, Any]) -> RedHatInfo:
    """The parts of a Red Hat CVE record that lookup and remedy display."""
    return RedHatInfo(
        severity=rh.get("threat_severity", "Unknown"),
        fix_state=rh.get("fix_state", "Unknown"),
        upstream_fix=rh.get("upstream_fix"),
        bugzilla_url=(rh.get("bugzilla") or {}).get("url"),
        patches=[
            RedHatPatch(package=ar.get("package", "N/A"), advisory=ar.get("advisory", "N/A"))
            for ar in rh.get("affected_release", [])[:8]
        ],
        package_states=[
            RedHatPackageState(
                package_name=ps.get("package_name", "N/A"),
                product_name=ps.get("product_name", ""),
                fix_state=ps.get("fix_state", "N/A"),
            )
            for ps in rh.get("package_state", [])[:8]
        ],
    )


def mitigation_text(rh: dict[str, Any]) -> str | None:
    """Red Hat's documented mitigation, or None when it has none.

    The field is {"value": "...", "lang": "en:us"}; older records may hold a
    plain string.
    """
    raw = rh.get("mitigation")
    text = raw.get("value") if isinstance(raw, dict) else raw
    if not isinstance(text, str) or not text.strip():
        return None
    text = text.strip()
    if text.lower().startswith(NO_MITIGATION_PREFIX):
        return None
    return text


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
