"""Shared test setup: no real network, no real sleeping, fake HTTP routing."""

from __future__ import annotations

import copy
import json
from datetime import date
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
import requests

from pgremedy import branches, offline, scanner
from pgremedy.apis import crunchy, nvd, postgresql_org, redhat

FIXTURES = Path(__file__).parent / "fixtures"
TODAY = date(2026, 10, 12)   # the day the fixtures were copied; end-of-life checks count from it


class FakeResponse:
    def __init__(self, status_code: int = 200, payload=None, text: str | None = None):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text is not None else ("" if payload is None else json.dumps(payload))

    def json(self):
        if self._payload is None:
            raise ValueError("no JSON body")
        return self._payload


def nvd_page(records, total=None, start=0) -> FakeResponse:
    return FakeResponse(200, {
        "totalResults": len(records) if total is None else total,
        "startIndex": start,
        "resultsPerPage": len(records),
        "vulnerabilities": [{"cve": r} for r in records],
    })


class Router:
    """Stands in for requests.get, dispatching on URL prefix and recording every call."""

    def __init__(self):
        self.routes: list[tuple[str, object]] = []
        self.calls: list[dict] = []

    def add(self, prefix: str, handler, first: bool = False) -> None:
        if first:
            self.routes.insert(0, (prefix, handler))
        else:
            self.routes.append((prefix, handler))

    def down(self, prefix: str) -> None:
        """Make every request to `prefix` fail as if the host were unreachable."""
        self.add(prefix, lambda url, params: requests.ConnectionError("connection refused"), first=True)

    def __call__(self, url, params=None, headers=None, timeout=None):
        self.calls.append({"url": url, "params": dict(params or {}), "headers": dict(headers or {})})
        for prefix, handler in self.routes:
            if url.startswith(prefix):
                result = handler(url, dict(params or {}))
                if isinstance(result, Exception):
                    raise result
                return result
        raise AssertionError(f"unexpected request to {url}")


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError(f"real network request attempted: {args} {kwargs}")

    monkeypatch.setattr(requests, "get", refuse)
    monkeypatch.setattr(nvd, "_sleep", lambda seconds: None)
    monkeypatch.setattr(nvd, "_last_request_at", None)
    monkeypatch.setattr(branches, "_today", lambda: TODAY)
    monkeypatch.setattr(offline, "_active", None)
    monkeypatch.setattr(offline, "_pause", lambda seconds: None)
    monkeypatch.delenv("PGREMEDY_DATA", raising=False)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setenv("COLUMNS", "300")   # keep Rich from wrapping lines tests look for


@pytest.fixture
def http(monkeypatch) -> Router:
    router = Router()
    monkeypatch.setattr(requests, "get", router)
    return router


@pytest.fixture
def nvd_records() -> dict[str, dict]:
    return {p.stem: json.loads(p.read_text()) for p in sorted((FIXTURES / "nvd").glob("*.json"))}


@pytest.fixture
def versions_json() -> list[dict]:
    return json.loads((FIXTURES / "postgresql_org_versions.json").read_text())


@pytest.fixture
def redhat_records() -> dict[str, dict]:
    return {p.stem: json.loads(p.read_text()) for p in sorted((FIXTURES / "redhat").glob("*.json"))}


PGO_RELEASES = [   # made-up release notes in GitHub's format; neither mentions a fixture CVE
    {"tag_name": "v5.8.4", "name": "v5.8.4", "body": "Updates the base images.", "prerelease": False,
     "published_at": "2026-09-30T12:00:00Z", "html_url": "https://example.test/v5.8.4"},
    {"tag_name": "v5.8.3", "name": "v5.8.3", "body": "Bug fixes.", "prerelease": False,
     "published_at": "2026-08-20T12:00:00Z", "html_url": "https://example.test/v5.8.3"},
]


class World:
    """Healthy sources by default: NVD serves the fixture records, Red Hat serves
    the records in `redhat` (404 otherwise), GitHub serves `releases` page by
    page. Tests change `product`, `modified`, `versions`, `redhat` or
    `releases`, or call `http.down(...)` to simulate an outage."""

    def __init__(self, http: Router, records: dict[str, dict], versions: list[dict]):
        self.http = http
        self.records = records
        self.product = list(records.values())
        self.modified: list[dict] = []
        self.versions = copy.deepcopy(versions)
        self.redhat: dict[str, dict] = {}
        self.releases: list[dict] = copy.deepcopy(PGO_RELEASES)
        http.add(nvd.API_BASE, self._nvd)
        http.add(postgresql_org.VERSIONS_URL, lambda url, params: FakeResponse(200, self.versions))
        http.add(redhat.CVE_API, self._redhat)
        http.add(crunchy.RELEASES_API, self._github)

    def _github(self, url, params):
        page, size = int(params.get("page", 1)), int(params.get("per_page", 30))
        return FakeResponse(200, self.releases[(page - 1) * size:page * size])

    def _redhat(self, url, params):
        record = self.redhat.get(url.rsplit("/", 1)[-1].removesuffix(".json"))
        return FakeResponse(200, record) if record else FakeResponse(404)

    def _nvd(self, url, params):
        if "cveId" in params:
            record = self.records.get(params["cveId"])
            return nvd_page([record] if record else [])
        pool = self.modified if "lastModStartDate" in params else self.product
        start = params.get("startIndex", 0)
        size = params.get("resultsPerPage", nvd.PAGE_SIZE)
        return nvd_page(pool[start:start + size], total=len(pool), start=start)

    def nvd_calls(self) -> list[dict]:
        return [c for c in self.http.calls if c["url"].startswith(nvd.API_BASE)]


@pytest.fixture
def world(http, nvd_records, versions_json) -> World:
    return World(http, nvd_records, versions_json)


# ── fake PostgreSQL clusters (for scan and compliance) ──────────────────────

def viewdefs(branch: str, state: str) -> tuple[str, str]:
    return tuple((FIXTURES / "postgres" / f"{branch}-{state}.{view}.sql").read_text()
                 for view in ("pg_stats_ext", "pg_stats_ext_exprs"))


class FakeConnection:
    def __init__(self, row=None, query_error=None):
        self.row, self.query_error = row, query_error

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, query):
        assert query.lstrip().upper().startswith("SELECT"), "manual-fix checks must be read-only"
        if self.query_error:
            raise self.query_error
        return SimpleNamespace(fetchone=lambda: self.row)


@pytest.fixture
def cluster(monkeypatch):
    """A cluster whose databases each have vulnerable or fixed views (or refuse connections)."""
    calls = []

    def make(version, branch, databases, template0=True):
        listed = [(name, True) for name in databases] + ([("template0", False)] if template0 else [])
        info = scanner.ServerInfo(version, 0, [], "scanner@db.example.com:5432/postgres", sorted(listed))
        monkeypatch.setattr(scanner, "read_server", lambda conninfo, password=None: info)

        def connect(conninfo, **kwargs):
            calls.append(kwargs)
            state = databases[kwargs["dbname"]]
            if isinstance(state, Exception) and state.args and state.args[0].startswith("query:"):
                return FakeConnection(query_error=psycopg.Error(state.args[0].removeprefix("query:")))
            if isinstance(state, Exception):
                raise state
            return FakeConnection(row=viewdefs(branch, state))

        monkeypatch.setattr(psycopg, "connect", connect)
        return calls

    return make
