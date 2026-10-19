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

from pgremedy import __version__, offline, pgversion
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
    bundle = offline.active()
    if bundle is not None:
        return bundle.nvd_cve(cve_id)
    vulns = _get({"cveId": cve_id}).get("vulnerabilities") or []
    return vulns[0].get("cve") if vulns else None


def fetch_product_cves(extra_params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """All PostgreSQL server CVEs (optionally filtered), following every page."""
    bundle = offline.active()
    if bundle is not None:
        if extra_params:
            raise SourceUnavailable(offline.SOURCE, "it can't filter CVEs by date")
        return list(bundle.nvd_cves)
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
    if not cves and not extra_params:
        # NVD lists more than 200 PostgreSQL CVEs. None at all means the query
        # broke (an API change, a renamed product), not that PostgreSQL is safe.
        raise SourceUnavailable("NVD", "returned no PostgreSQL CVEs at all (there should be more than 200)")
    return cves


def _nvd_timestamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def fetch_product_cves_modified(since: datetime, until: datetime) -> list[dict[str, Any]]:
    """PostgreSQL server CVEs added or changed between two moments."""
    offline.require_live("watch")
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


GO_VENDORS = {"golang"}    # the Go toolchain and standard library, and golang.org/x modules
_POSTGRESQL_WORD = re.compile(r"\bpostgresql\b", re.IGNORECASE)
_GO_WORDS = re.compile(r"\bgolang\b|\b(?:net|crypto)/[a-z]", re.IGNORECASE)
_GO_RELEASE = re.compile(r"\bGo (?:before|through|prior to|versions?\b|\d)")   # "Go before 1.21.5"


def detect_type(cve_data: dict | None) -> str:
    """postgresql (the server), golang, or base-image (any other product).

    Decided by the products NVD marks vulnerable. Only while NVD hasn't recorded
    any (a new CVE) does the description decide.
    """
    if not cve_data:
        return "unknown"
    vulnerable = [fields for _, fields in _vulnerable_cpe_matches(cve_data)]
    if any(_is_postgresql_server(fields) for fields in vulnerable):
        return "postgresql"
    if any(len(fields) > 3 and fields[3] in GO_VENDORS for fields in vulnerable):
        return "golang"
    if vulnerable:
        return "base-image"
    desc = english_description(cve_data)
    if _POSTGRESQL_WORD.search(desc):
        return "postgresql"
    if _GO_WORDS.search(desc) or _GO_RELEASE.search(desc):
        return "golang"
    return "base-image"


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


def _vulnerable_cpe_matches(cve_data: dict) -> Iterator[tuple[dict[str, Any], list[str]]]:
    """Each cpeMatch NVD marks as vulnerable, with its CPE split into fields."""
    for config in cve_data.get("configurations") or []:
        for node in config.get("nodes") or []:
            if node.get("negate"):
                continue
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue          # e.g. "runs on PostgreSQL" platform entries
                yield match, _CPE_SEPARATOR.split(match.get("criteria", "").lower())


def postgresql_ranges(cve_data: dict) -> Iterator[_Range]:
    """Vulnerable PostgreSQL server version ranges listed on a CVE."""
    for match, fields in _vulnerable_cpe_matches(cve_data):
        if not _is_postgresql_server(fields):
            continue
        rng = _range_of(match, fields)
        if rng is not None:
            yield rng


def has_affected_data(cve_data: dict) -> bool:
    """False while NVD hasn't recorded affected products yet (e.g. "Awaiting Analysis")."""
    return bool(cve_data.get("configurations"))


def lists_postgresql_server(cve_data: dict) -> bool:
    """True if NVD lists the PostgreSQL server itself as vulnerable."""
    return any(_is_postgresql_server(fields) for _, fields in _vulnerable_cpe_matches(cve_data))


SERVER_LABEL = "PostgreSQL server"


def product_label(fields: list[str]) -> str:
    """ "PostgreSQL server", or "product (vendor)" such as "postgresql_jdbc_driver (postgresql)"."""
    if _is_postgresql_server(fields):
        return SERVER_LABEL
    vendor, product = (field.replace("\\", "") for field in fields[3:5])   # CPEs escape e.g. "pl\/php"
    return f"{product} ({vendor})"


def affected_products(cve_data: dict) -> list[str]:
    """Vulnerable products, labelled as product_label() does, in NVD's order."""
    names: list[str] = []
    for _, fields in _vulnerable_cpe_matches(cve_data):
        if len(fields) < 5:
            continue
        name = product_label(fields)
        if name not in names:
            names.append(name)
    return names


# ── Describing affected versions ─────────────────────────────────────────────

def _cpe_version(fields: list[str]) -> str:
    """The version written in a CPE itself, with its update: "8.4.1", "1.3.5beta1"."""
    version = fields[5].replace("\\", "") if len(fields) > 5 else "*"
    update = fields[6].replace("\\", "") if len(fields) > 6 else "*"
    return version + (update if update not in ("*", "-", "") else "")


def _release_before(text: str) -> str | None:
    """The PostgreSQL release just before this one: 16.4 for 16.5, 9.6.23 for 9.6.24.

    Minor releases are numbered consecutively, so this is exact. None for x.0
    releases and anything that isn't a plain release number.
    """
    v = pgversion.parse(text)
    if v is None or v.pre is not None or v.dev is not None or v.post is not None or v.local:
        return None
    rel = v.release
    if len(rel) != (2 if rel[0] >= 10 else 3) or rel[-1] == 0:
        return None
    return ".".join(str(n) for n in (*rel[:-1], rel[-1] - 1))


def _range_text(match: dict[str, Any], fields: list[str], server: bool) -> str:
    """One cpeMatch entry in words: "16.0 to 16.4", "9.4.25 and earlier", ">=42.3.0 <42.3.9".

    NVD's end versions are usually exclusive (the first fixed release). For the
    PostgreSQL server the last affected release can be named; for other
    products, whose numbering may skip, an exclusive end is shown as "<".
    """
    start_inc, start_exc = match.get("versionStartIncluding"), match.get("versionStartExcluding")
    end_exc, end_inc = match.get("versionEndExcluding"), match.get("versionEndIncluding")
    if not (start_inc or start_exc or end_exc or end_inc):
        exact = _cpe_version(fields)
        return "every version" if exact == "*" else exact

    last = end_inc or (_release_before(end_exc) if server and end_exc else None)
    if last and not start_exc:
        if not start_inc:
            return f"{last} and earlier"
        first, final = pgversion.parse(start_inc), pgversion.parse(last)
        if first is not None and final is not None and first <= final:
            return start_inc if first == final else f"{start_inc} to {last}"
    if not (end_exc or end_inc):
        return f"{start_inc} and later" if start_inc else f"after {start_exc}"
    lower = f">={start_inc}" if start_inc else (f">{start_exc}" if start_exc else "")
    upper = f"<{end_exc}" if end_exc else f"<={end_inc}"
    return f"{lower} {upper}".strip()


def _follows(previous: Version, version: Version) -> bool:
    before = _release_before(str(version))
    return before is not None and Version(before) == previous


def _describe(entries: list[tuple[_Range, dict[str, Any], list[str]]], server: bool) -> list[str]:
    """Readable affected versions for one product, lowest first.

    Exact versions that a listed range already covers are dropped, and for the
    server, runs of consecutive releases are joined: 8.4.1 ... 8.4.5 becomes
    "8.4.1 to 8.4.5".
    """
    exact: dict[Version, str] = {}
    spans: list[tuple[_Range, dict[str, Any], list[str]]] = []
    for rng, match, fields in entries:
        if rng.start is not None and rng.start == rng.end and rng.start_inclusive and rng.end_inclusive:
            exact.setdefault(rng.start, _range_text(match, fields, server))
        else:
            spans.append((rng, match, fields))
    exact = {v: text for v, text in exact.items() if not any(r.contains(v) for r, _, _ in spans)}

    lowest = Version("0")
    items: list[tuple[Version, str]] = [(rng.start or lowest, _range_text(match, fields, server))
                                        for rng, match, fields in spans]
    run: list[tuple[Version, str]] = []
    for v, text in sorted(exact.items()):
        if run and server and _follows(run[-1][0], v):
            run.append((v, text))
            continue
        if run:
            items.append((run[0][0], run[0][1] if len(run) == 1 else f"{run[0][1]} to {run[-1][1]}"))
        run = [(v, text)]
    if run:
        items.append((run[0][0], run[0][1] if len(run) == 1 else f"{run[0][1]} to {run[-1][1]}"))

    described: list[str] = []
    for _, text in sorted(items, key=lambda item: item[0]):
        if text not in described:
            described.append(text)
    return described


def product_versions(cve_data: dict) -> dict[str, list[str]]:
    """Affected versions of every product NVD marks vulnerable, by product_label()."""
    groups: dict[str, list[tuple[_Range, dict[str, Any], list[str]]]] = {}
    for match, fields in _vulnerable_cpe_matches(cve_data):
        if len(fields) < 6:
            continue
        entries = groups.setdefault(product_label(fields), [])
        rng = _range_of(match, fields)
        if rng is not None:
            entries.append((rng, match, fields))
    return {label: _describe(entries, server=label == SERVER_LABEL) for label, entries in groups.items()}


def extract_affected_versions(cve_data: dict) -> list[str]:
    """Affected PostgreSQL server releases in words: ["16.0 to 16.4", "17.0"]."""
    return product_versions(cve_data).get(SERVER_LABEL, [])


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


def fixes_by_branch(cve_data: dict) -> dict[str, str]:
    """First fixed release per branch, oldest branch first: {"12": "12.21", ..., "17": "17.1"}.

    A range that ends inside a branch (versionEndExcluding 16.5) gives that
    branch's fix. Branches a range covers completely get no entry.
    """
    fix_map: dict[str, Version] = {}
    for rng in postgresql_ranges(cve_data):
        if rng.end is None or rng.end_inclusive:
            continue
        major = pgversion.major_of(rng.end)
        if major not in fix_map or rng.end > fix_map[major]:
            fix_map[major] = rng.end
    return {major: str(fix) for major, fix in sorted(fix_map.items(), key=lambda item: item[1])}


def find_fix_version(cve_data: dict, pg_version: str | None = None) -> str | None:
    """The release that fixes this CVE in the user's branch.

    Without pg_version, returns the highest fix across all branches.
    """
    fixes = fixes_by_branch(cve_data)
    if not fixes:
        return None
    if pg_version:
        return fixes.get(pgversion.major_of(pg_version))
    return max(fixes.values(), key=Version)
