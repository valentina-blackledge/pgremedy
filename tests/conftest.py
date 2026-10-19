"""Shared test setup: no real network, no real sleeping, fake HTTP routing."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import requests

from pgremedy.apis import crunchy, nvd, postgresql_org, redhat

FIXTURES = Path(__file__).parent / "fixtures"


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
    monkeypatch.delenv("NVD_API_KEY", raising=False)
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


class World:
    """Healthy sources by default: NVD serves the fixture records, Red Hat has no
    record, GitHub lists no releases. Tests change `product`, `modified` or
    `versions`, or call `http.down(...)` to simulate an outage."""

    def __init__(self, http: Router, records: dict[str, dict], versions: list[dict]):
        self.http = http
        self.records = records
        self.product = list(records.values())
        self.modified: list[dict] = []
        self.versions = copy.deepcopy(versions)
        http.add(nvd.API_BASE, self._nvd)
        http.add(postgresql_org.VERSIONS_URL, lambda url, params: FakeResponse(200, self.versions))
        http.add(redhat.CVE_API, lambda url, params: FakeResponse(404))
        http.add(crunchy.RELEASES_API, lambda url, params: FakeResponse(200, []))

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
