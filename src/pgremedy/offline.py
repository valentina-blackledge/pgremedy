"""Offline data bundles, for networks that can't reach NVD or postgresql.org.

On a connected machine, `pgremedy bundle create FILE` saves everything the
checks need into one JSON file. Copy it across, then run any command with
`--data FILE` (or PGREMEDY_DATA=FILE): the API clients answer from the bundle
and never touch the network. Missing data fails closed, like an unreachable
source.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from pgremedy import __version__
from pgremedy.errors import SourceUnavailable

FORMAT = "pgremedy-bundle"
FORMAT_VERSION = 1
STALE_AFTER_DAYS = 30           # PostgreSQL ships security releases at least quarterly
SOURCE = "offline bundle"
REDHAT_PAUSE_SECONDS = 0.2     # be gentle with Red Hat's API
_pause = time.sleep             # replaced in tests


class BundleError(Exception):
    """The file isn't a usable bundle."""


@dataclass
class Bundle:
    path: str
    created_at: datetime
    pgremedy_version: str
    nvd_cves: list[dict[str, Any]]
    postgresql_versions: list[dict[str, Any]]
    redhat_cves: dict[str, dict | None] | None = None    # None: not included; value None: Red Hat has no record
    crunchy_releases: list[dict] | None = None
    sources: dict[str, Any] = field(default_factory=dict)
    sha256: str = ""
    _by_id: dict[str, dict] = field(default_factory=dict, repr=False)

    def age_days(self, now: datetime | None = None) -> int:
        return ((now or datetime.now(timezone.utc)) - self.created_at).days

    def is_stale(self, now: datetime | None = None) -> bool:
        return self.age_days(now) > STALE_AFTER_DAYS

    def describe(self, now: datetime | None = None) -> str:
        days = self.age_days(now)
        return f"offline bundle created {self.created_at:%Y-%m-%d} ({days} day{'s' if days != 1 else ''} old)"

    # ── what the API clients ask for ─────────────────────────────────────────

    def nvd_cve(self, cve_id: str) -> dict[str, Any]:
        if not self._by_id:
            self._by_id = {c.get("id"): c for c in self.nvd_cves}
        cve = self._by_id.get(cve_id.upper())
        if cve is None:
            raise SourceUnavailable(SOURCE, f"{cve_id} isn't in it (bundles hold PostgreSQL server CVEs only)")
        return cve

    def redhat_cve(self, cve_id: str) -> dict | None:
        if self.redhat_cves is None:
            raise SourceUnavailable("Red Hat", "not included in the offline bundle")
        if cve_id.upper() not in self.redhat_cves:
            raise SourceUnavailable("Red Hat", f"{cve_id} isn't in the offline bundle")
        return self.redhat_cves[cve_id.upper()]

    def crunchy(self) -> list[dict]:
        if self.crunchy_releases is None:
            raise SourceUnavailable("GitHub (Crunchy PGO releases)", "not included in the offline bundle")
        return self.crunchy_releases


_active: Bundle | None = None


def active() -> Bundle | None:
    return _active


def activate(path: str) -> Bundle:
    global _active
    _active = load(path)
    return _active


def deactivate() -> None:
    global _active
    _active = None


def data_source(now: datetime | None = None) -> dict[str, Any]:
    """Where this run's data came from, for JSON output and evidence."""
    if _active is None:
        return {"mode": "live"}
    return {
        "mode": "offline",
        "bundle": _active.path,
        "created_at": _active.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "age_days": _active.age_days(now),
        "sha256": _active.sha256,
    }


def describe_source(now: datetime | None = None, full_hash: bool = False) -> str:
    if _active is None:
        return "live from NVD and postgresql.org"
    digest = _active.sha256 if full_hash else f"{_active.sha256[:16]}..."
    return f"{_active.describe(now)}, SHA-256 {digest}"


def require_live(what: str) -> None:
    """For commands that can't work from a bundle (watch, audit-package)."""
    if _active is not None:
        raise SourceUnavailable(SOURCE, f"{what} needs live data and can't run from a bundle")


def load(path: str) -> Bundle:
    raw = Path(path).read_bytes()
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise BundleError(f"{path} isn't valid JSON") from exc
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise BundleError(f"{path} isn't a pgremedy data bundle")
    if data.get("format_version") != FORMAT_VERSION:
        raise BundleError(
            f"{path} uses bundle format {data.get('format_version')}; this pgremedy reads format {FORMAT_VERSION}"
        )
    for key in ("nvd_cves", "postgresql_versions"):
        if not isinstance(data.get(key), list) or not data[key]:
            raise BundleError(f"{path} has no {key}")
    try:
        created = datetime.strptime(data["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (KeyError, TypeError, ValueError) as exc:
        raise BundleError(f"{path} has no valid created_at") from exc
    return Bundle(
        path=path,
        created_at=created,
        pgremedy_version=str(data.get("pgremedy_version", "?")),
        nvd_cves=data["nvd_cves"],
        postgresql_versions=data["postgresql_versions"],
        redhat_cves=data.get("redhat_cves"),
        crunchy_releases=data.get("crunchy_releases"),
        sources=data.get("sources") or {},
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def create(
    path: str,
    fetch_nvd: Callable[[], list[dict]],
    fetch_versions: Callable[[], list[dict]],
    fetch_redhat: Callable[[str], dict | None] | None = None,
    fetch_crunchy: Callable[[], list[dict]] | None = None,
    progress: Callable[[str], None] = lambda message: None,
    now: datetime | None = None,
) -> Bundle:
    """Fetch everything and write the bundle atomically. Any failure raises and writes nothing."""
    now = now or datetime.now(timezone.utc)
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    progress("Fetching PostgreSQL CVEs from NVD...")
    nvd_cves = fetch_nvd()
    progress(f"{len(nvd_cves)} CVEs. Fetching release data from postgresql.org...")
    versions = fetch_versions()
    sources: dict[str, Any] = {
        "nvd": {"query": "virtualMatchString=cpe:2.3:a:postgresql:postgresql", "count": len(nvd_cves)},
        "postgresql_org": {"url": "https://www.postgresql.org/versions.json", "count": len(versions)},
    }

    redhat_cves = None
    if fetch_redhat is not None:
        redhat_cves = {}
        ids = sorted({c["id"] for c in nvd_cves if c.get("id")})
        for i, cve_id in enumerate(ids, 1):
            if i == 1 or i % 25 == 0 or i == len(ids):
                progress(f"Fetching Red Hat records ({i} of {len(ids)})...")
            redhat_cves[cve_id] = fetch_redhat(cve_id)
            if i < len(ids):
                _pause(REDHAT_PAUSE_SECONDS)
        sources["redhat"] = {"count": sum(1 for v in redhat_cves.values() if v is not None), "requested": len(ids)}

    crunchy_releases = None
    if fetch_crunchy is not None:
        progress("Fetching Crunchy PGO releases from GitHub...")
        crunchy_releases = fetch_crunchy()
        sources["crunchy"] = {"count": len(crunchy_releases)}

    body = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "created_at": stamp,
        "pgremedy_version": __version__,
        "sources": sources,
        "nvd_cves": nvd_cves,
        "postgresql_versions": versions,
        "redhat_cves": redhat_cves,
        "crunchy_releases": crunchy_releases,
    }
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(body, f)
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return load(path)
