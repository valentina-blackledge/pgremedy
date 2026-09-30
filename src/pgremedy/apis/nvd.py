"""NVD (National Vulnerability Database) API client."""

from __future__ import annotations

import time
from typing import Any

import requests

API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {"User-Agent": "pgremedy/0.1.0"}
RATE_LIMIT_SECONDS = 6


def _get(url: str, params: dict | None = None) -> dict | None:
    try:
        resp = requests.get(url, headers=HEADERS, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException:
        return None


def fetch_cve(cve_id: str) -> dict[str, Any] | None:
    data = _get(API_BASE, {"cveId": cve_id})
    if data:
        vulns = data.get("vulnerabilities", [])
        if vulns:
            return vulns[0].get("cve", {})
    return None


def search_by_keyword(keyword: str, results_per_page: int = 50) -> list[dict]:
    data = _get(API_BASE, {"keywordSearch": keyword, "resultsPerPage": results_per_page})
    if data:
        return [v.get("cve", {}) for v in data.get("vulnerabilities", [])]
    return []


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
    desc = _english_desc(cve_data).lower()
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


def find_fix_version(cve_data: dict, pg_version: str | None = None) -> str | None:
    """Return the versionEndExcluding for the CPE range matching the user's major version.

    If pg_version is given (e.g. "16.2"), only returns the fix for the 16.x branch.
    Without it, returns all fix versions as a comma-separated string.
    """
    from packaging.version import Version, InvalidVersion

    fix_map: dict[str, str] = {}  # major -> fix version
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "").lower()
                if "postgresql" not in cpe:
                    continue
                if not match.get("vulnerable", False):
                    continue
                ve = match.get("versionEndExcluding")
                vs = match.get("versionStartIncluding")
                if ve and vs:
                    major = vs.split(".")[0]
                    fix_map[major] = ve

    if not fix_map:
        return None

    if pg_version:
        user_major = pg_version.split(".")[0]
        return fix_map.get(user_major)

    try:
        versions = sorted(fix_map.values(), key=lambda v: Version(v))
    except InvalidVersion:
        versions = sorted(fix_map.values())
    return versions[-1] if versions else None


def is_version_affected(pg_version: str, cve_data: dict) -> bool:
    from packaging.version import Version, InvalidVersion

    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if "postgresql" not in match.get("criteria", "").lower():
                    continue
                if not match.get("vulnerable", False):
                    continue
                try:
                    uv = Version(pg_version)
                    start = match.get("versionStartIncluding")
                    end_exc = match.get("versionEndExcluding")
                    end_inc = match.get("versionEndIncluding")
                    if start and uv < Version(start):
                        continue
                    if end_exc and uv >= Version(end_exc):
                        continue
                    if end_inc and uv > Version(end_inc):
                        continue
                    return True
                except (InvalidVersion, Exception):
                    continue
    return False


def _english_desc(cve_data: dict) -> str:
    for d in cve_data.get("descriptions", []):
        if d.get("lang") == "en":
            return d["value"]
    return ""


def rate_limit_pause():
    time.sleep(RATE_LIMIT_SECONDS)
