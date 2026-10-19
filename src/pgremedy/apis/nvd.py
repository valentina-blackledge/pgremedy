"""NVD (National Vulnerability Database) API client and version matching."""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

import requests
from packaging.version import Version

from pgremedy import __version__, pgversion
from pgremedy.errors import SourceUnavailable, describe

API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Every CVE NVD has attached to the PostgreSQL server product. Matching on the
# product instead of a description keyword avoids both misses (descriptions that
# never mention "16") and noise (pgjdbc, pgAdmin, distro packaging scripts).
PRODUCT_CPE = "cpe:2.3:a:postgresql:postgresql"

PAGE_SIZE = 2000         # NVD maximum per request
MAX_WINDOW_DAYS = 120    # NVD maximum for lastMod/pub date ranges
ATTEMPTS = 3
BACKOFF_SECONDS = (6, 15)
RETRY_STATUSES = {403, 429, 500, 502, 503, 504}  # NVD answers 403 when rate limiting

_sleep = time.sleep      # replaced in tests
_last_request_at: float | None = None


# ── HTTP ─────────────────────────────────────────────────────────────────────

def _api_key() -> str | None:
    return os.environ.get("NVD_API_KEY") or None


def _min_interval() -> float:
    # NVD allows 5 requests per rolling 30 seconds without a key, 50 with one.
    return 0.6 if _api_key() else 6.0


def _throttle() -> None:
    if _last_request_at is None:
        return
    wait = _min_interval() - (time.monotonic() - _last_request_at)
    if wait > 0:
        _sleep(wait)


def _get(params: dict[str, Any]) -> dict[str, Any]:
    """GET the CVE API, retrying rate limits and outages. Raises SourceUnavailable."""
    global _last_request_at
    headers = {"User-Agent": f"pgremedy/{__version__}"}
    key = _api_key()
    if key:
        headers["apiKey"] = key

    reason = "no response"
    for attempt in range(ATTEMPTS):
        _throttle()
        try:
            resp = requests.get(API_BASE, params=params, headers=headers, timeout=60)
        except requests.RequestException as exc:
            reason = describe(exc)
        else:
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError:
                    reason = "the response was not valid JSON"
                else:
                    _last_request_at = time.monotonic()
                    return data
            elif resp.status_code in RETRY_STATUSES:
                reason = f"HTTP {resp.status_code}"
                if resp.status_code == 403 and not key:
                    reason += ", rate limited (set NVD_API_KEY for a higher limit)"
            else:
                _last_request_at = time.monotonic()
                raise SourceUnavailable("NVD", f"HTTP {resp.status_code}")
        _last_request_at = time.monotonic()
        if attempt + 1 < ATTEMPTS:
            _sleep(BACKOFF_SECONDS[min(attempt, len(BACKOFF_SECONDS) - 1)])
    raise SourceUnavailable("NVD", reason)


def fetch_cve(cve_id: str) -> dict[str, Any] | None:
    """One CVE record, or None if NVD has no record with that ID."""
    vulns = _get({"cveId": cve_id}).get("vulnerabilities") or []
    return vulns[0].get("cve") if vulns else None


def fetch_product_cves(extra_params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """All PostgreSQL server CVEs (optionally filtered), following every page."""
    params = {"virtualMatchString": PRODUCT_CPE, "resultsPerPage": PAGE_SIZE, **(extra_params or {})}
    cves: list[dict[str, Any]] = []
    total = 0
    while True:
        data = _get({**params, "startIndex": len(cves)})
        total = int(data.get("totalResults") or 0)
        page = [v.get("cve", {}) for v in data.get("vulnerabilities") or []]
        cves.extend(page)
        if not page or len(cves) >= total:
            break
    if len(cves) < total:
        raise SourceUnavailable("NVD", f"returned {len(cves)} of {total} results")
    return cves


def _nvd_timestamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def fetch_product_cves_modified(since: datetime, until: datetime) -> list[dict[str, Any]]:
    """PostgreSQL server CVEs added or changed between two moments."""
    seen: set[str] = set()
    cves: list[dict[str, Any]] = []
    window_start = since
    while window_start < until:
        window_end = min(window_start + timedelta(days=MAX_WINDOW_DAYS), until)
        for cve in fetch_product_cves({
            "lastModStartDate": _nvd_timestamp(window_start),
            "lastModEndDate": _nvd_timestamp(window_end),
        }):
            if cve.get("id") not in seen:
                seen.add(cve.get("id"))
                cves.append(cve)
        window_start = window_end
    return cves


# ── Record fields ────────────────────────────────────────────────────────────

def english_description(cve_data: dict) -> str:
    for d in cve_data.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def extract_cvss(cve_data: dict) -> dict[str, Any]:
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            cvss = entries[0].get("cvssData", {})
            return {
                "score": cvss.get("baseScore"),
                "severity": cvss.get("baseSeverity", "UNKNOWN"),
                "vector": cvss.get("attackVector", "UNKNOWN"),
                "version": cvss.get("version"),
            }
    return {"score": None, "severity": "UNKNOWN", "vector": "UNKNOWN", "version": None}


def detect_type(cve_data: dict | None) -> str:
    if not cve_data:
        return "unknown"
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "").lower()
                if "postgresql" in cpe:
                    return "postgresql"
                if "golang" in cpe or "go_project" in cpe:
                    return "golang"
    desc = english_description(cve_data).lower()
    if "postgresql" in desc:
        return "postgresql"
    if any(tok in desc for tok in ("go ", "golang", "net/", "crypto/")):
        return "golang"
    return "base-image"


def extract_affected_versions(cve_data: dict, cve_type: str = "postgresql") -> list[str]:
    affected: list[str] = []
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "").lower()
                hit = (
                    (cve_type == "postgresql" and "postgresql" in cpe)
                    or (cve_type == "golang" and ("golang" in cpe or "go_project" in cpe))
                    or cve_type == "base-image"
                )
                if not hit:
                    continue
                vs = match.get("versionStartIncluding", "")
                ve = match.get("versionEndExcluding", match.get("versionEndIncluding", ""))
                if vs or ve:
                    affected.append(f"{vs} - {ve}".strip(" -"))
                else:
                    parts = match.get("criteria", "").split(":")
                    if len(parts) > 5 and parts[5] != "*":
                        affected.append(parts[5])
    return affected or ["Check NVD/vendor advisory for version details"]


# ── Version matching ─────────────────────────────────────────────────────────

_CPE_SEPARATOR = re.compile(r"(?<!\\):")


@dataclass(frozen=True)
class _Range:
    start: Version | None
    start_inclusive: bool
    end: Version | None
    end_inclusive: bool

    def contains(self, v: Version) -> bool:
        if self.start is not None and (v < self.start or (v == self.start and not self.start_inclusive)):
            return False
        if self.end is not None and (v > self.end or (v == self.end and not self.end_inclusive)):
            return False
        return True

    def overlaps(self, low: Version, high: Version) -> bool:
        """True if any version in [low, high) falls in this range."""
        above_low = self.end is None or self.end > low or (self.end == low and self.end_inclusive)
        below_high = self.start is None or self.start < high
        return above_low and below_high

    def fix_in(self, major: str) -> str | None:
        """The first fixed release in `major`, if this range ends inside that branch."""
        if self.end is None or self.end_inclusive or pgversion.major_of(self.end) != major:
            return None
        return str(self.end)


def _is_postgresql_server(fields: list[str]) -> bool:
    return len(fields) >= 6 and fields[2] == "a" and fields[3] == "postgresql" and fields[4] == "postgresql"


def _range_of(match: dict[str, Any], fields: list[str]) -> _Range | None:
    """The versions one cpeMatch entry covers, or None if it can't be read."""
    start_inc, start_exc = match.get("versionStartIncluding"), match.get("versionStartExcluding")
    end_exc, end_inc = match.get("versionEndExcluding"), match.get("versionEndIncluding")

    if start_inc or start_exc or end_exc or end_inc:
        start = pgversion.parse(start_inc or start_exc)
        end = pgversion.parse(end_exc or end_inc)
        if ((start_inc or start_exc) and start is None) or ((end_exc or end_inc) and end is None):
            return None
        return _Range(start, bool(start_inc), end, bool(end_inc))

    # No range fields: the version is in the CPE string itself (older CVEs list
    # every affected release this way, e.g. postgresql:8.4.3).
    version = fields[5].replace("\\", "")
    if version == "*":
        return _Range(None, True, None, True)        # NVD says every version
    if version in ("-", ""):
        return None
    update = fields[6].replace("\\", "") if len(fields) > 6 else "*"
    exact = pgversion.parse(version + (update if update not in ("*", "-", "") else ""))
    return _Range(exact, True, exact, True) if exact is not None else None


def postgresql_ranges(cve_data: dict) -> Iterator[_Range]:
    """Vulnerable PostgreSQL server version ranges listed on a CVE."""
    for config in cve_data.get("configurations") or []:
        for node in config.get("nodes") or []:
            if node.get("negate"):
                continue
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue          # e.g. "runs on PostgreSQL" platform entries
                fields = _CPE_SEPARATOR.split(match.get("criteria", "").lower())
                if not _is_postgresql_server(fields):
                    continue
                rng = _range_of(match, fields)
                if rng is not None:
                    yield rng


@dataclass(frozen=True)
class Applicability:
    affected: bool
    fixed_in: str | None = None   # first fixed release in the same branch, when NVD lists one


def check_version(cve_data: dict, version: str) -> Applicability:
    """Does this CVE affect one specific PostgreSQL release?"""
    v = pgversion.parse(version)
    if v is None:
        return Applicability(False)
    major = pgversion.major_of(v)
    hits = [r for r in postgresql_ranges(cve_data) if r.contains(v)]
    if not hits:
        return Applicability(False)
    fixes = [f for f in (r.fix_in(major) for r in hits) if f]
    return Applicability(True, max(fixes, key=Version) if fixes else None)


def check_branch(cve_data: dict, major: str) -> Applicability:
    """Does this CVE affect at least one release in a branch ("16", "9.6")?"""
    low, high = pgversion.branch_bounds(major)
    hits = [r for r in postgresql_ranges(cve_data) if r.overlaps(low, high)]
    if not hits:
        return Applicability(False)
    fixes = [f for f in (r.fix_in(major) for r in hits) if f]
    return Applicability(True, max(fixes, key=Version) if fixes else None)


def is_version_affected(pg_version: str, cve_data: dict) -> bool:
    return check_version(cve_data, pg_version).affected


def find_fix_version(cve_data: dict, pg_version: str | None = None) -> str | None:
    """The release that fixes this CVE in the user's branch.

    Without pg_version, returns the highest fix across all branches.
    """
    fix_map: dict[str, Version] = {}
    for rng in postgresql_ranges(cve_data):
        if rng.end is None or rng.end_inclusive:
            continue
        major = pgversion.major_of(rng.end)
        if rng.start is not None and pgversion.major_of(rng.start) != major:
            continue   # range spans branches; its start branch has no fix listed
        if major not in fix_map or rng.end > fix_map[major]:
            fix_map[major] = rng.end

    if not fix_map:
        return None
    if pg_version:
        fix = fix_map.get(pgversion.major_of(pg_version))
        return str(fix) if fix else None
    return str(max(fix_map.values()))
