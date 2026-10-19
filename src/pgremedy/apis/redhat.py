"""Red Hat Security Data API client."""

from __future__ import annotations

from typing import Any

import requests

from pgremedy import __version__, offline
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
    bundle = offline.active()
    if bundle is not None:
        return bundle.redhat_cve(cve_id)
    return _get_json(f"{CVE_API}/{cve_id}.json")


def to_info(rh: dict[str, Any]) -> RedHatInfo:
    """The parts of a Red Hat CVE record that lookup and remedy display.

    Every entry is kept: a record often lists dozens of fixed packages (one per
    RHEL release and module stream), and the one a user runs can be anywhere.
    """
    return RedHatInfo(
        severity=rh.get("threat_severity") or "Unknown",
        upstream_fix=rh.get("upstream_fix"),
        bugzilla_url=(rh.get("bugzilla") or {}).get("url"),
        patches=[
            RedHatPatch(
                package=ar.get("package") or "",
                advisory=ar.get("advisory") or "",
                product_name=ar.get("product_name") or "",
            )
            for ar in rh.get("affected_release") or []
        ],
        package_states=[
            RedHatPackageState(
                package_name=ps.get("package_name") or "",
                product_name=ps.get("product_name") or "",
                fix_state=ps.get("fix_state") or "Unknown",
            )
            for ps in rh.get("package_state") or []
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


SEVERITIES = ("critical", "important", "moderate", "low")   # Red Hat's scale, not NVD's
PAGE_SIZE = 1000         # Red Hat's default page size
MAX_PAGES = 20


def search_by_package(package: str, severity: str | None = None, days_ago: int = 90) -> list[dict]:
    """Every Red Hat CVE for a package, following Red Hat's pages.

    `severity` is a comma-separated list on Red Hat's scale. Results that can't
    all be read raise SourceUnavailable rather than coming back short.
    """
    offline.require_live("audit-package")
    params: dict[str, Any] = {"package": package, "created_days_ago": days_ago, "per_page": PAGE_SIZE}
    if severity:
        params["severity"] = severity
    url = f"{CVE_API}.json"
    results: list[dict] = []
    for page in range(1, MAX_PAGES + 1):
        data = _get_json(url, {**params, "page": page})
        if data is None:
            raise SourceUnavailable("Red Hat", "HTTP 404 from the CVE search")   # no matches is [], not 404
        if not isinstance(data, list):
            raise SourceUnavailable("Red Hat", "unexpected response format")
        results.extend(data)
        if len(data) < PAGE_SIZE:
            return results
    raise SourceUnavailable(
        "Red Hat", f"more than {MAX_PAGES * PAGE_SIZE} results; narrow the search with --days-ago or --severity")
