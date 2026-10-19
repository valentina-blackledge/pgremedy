"""NVD client: pagination, retries, rate limiting, failing closed."""

from datetime import datetime, timedelta, timezone

import pytest

from conftest import FakeResponse, nvd_page
from pgremedy.apis import nvd
from pgremedy.errors import SourceUnavailable


def test_product_query_follows_every_page(http, monkeypatch):
    monkeypatch.setattr(nvd, "PAGE_SIZE", 2)
    pool = [{"id": f"CVE-2026-{i:04d}"} for i in range(5)]

    def serve(url, params):
        start = params["startIndex"]
        return nvd_page(pool[start:start + params["resultsPerPage"]], total=len(pool), start=start)

    http.add(nvd.API_BASE, serve)
    assert [c["id"] for c in nvd.fetch_product_cves()] == [c["id"] for c in pool]
    assert [c["params"]["startIndex"] for c in http.calls] == [0, 2, 4]
    assert {c["params"]["virtualMatchString"] for c in http.calls} == {"cpe:2.3:a:postgresql:postgresql"}


def test_incomplete_results_fail_closed(http):
    http.add(nvd.API_BASE, lambda url, params: nvd_page(
        [{"id": "CVE-2026-0001"}] if params["startIndex"] == 0 else [], total=3, start=params["startIndex"]))
    with pytest.raises(SourceUnavailable, match="returned 1 of 3"):
        nvd.fetch_product_cves()


def test_unreachable_nvd_raises_after_retrying(http):
    http.down(nvd.API_BASE)
    with pytest.raises(SourceUnavailable) as err:
        nvd.fetch_cve("CVE-2024-10979")
    assert err.value.source == "NVD"
    assert len(http.calls) == nvd.ATTEMPTS


def test_rate_limit_is_retried(http):
    responses = iter([FakeResponse(403), nvd_page([])])
    http.add(nvd.API_BASE, lambda url, params: next(responses))
    assert nvd.fetch_cve("CVE-2024-10979") is None
    assert len(http.calls) == 2


def test_persistent_rate_limit_explains_the_api_key(http):
    http.add(nvd.API_BASE, lambda url, params: FakeResponse(403))
    with pytest.raises(SourceUnavailable, match="NVD_API_KEY"):
        nvd.fetch_cve("CVE-2024-10979")


def test_client_errors_are_not_retried(http):
    http.add(nvd.API_BASE, lambda url, params: FakeResponse(404))
    with pytest.raises(SourceUnavailable, match="HTTP 404"):
        nvd.fetch_cve("CVE-2024-10979")
    assert len(http.calls) == 1


def test_invalid_json_is_an_error_not_an_empty_result(http):
    http.add(nvd.API_BASE, lambda url, params: FakeResponse(200, None, text="<html>maintenance</html>"))
    with pytest.raises(SourceUnavailable, match="not valid JSON"):
        nvd.fetch_product_cves()


def test_api_key_is_sent_when_set(http, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "test-key")
    http.add(nvd.API_BASE, lambda url, params: nvd_page([]))
    nvd.fetch_cve("CVE-2024-10979")
    assert http.calls[0]["headers"]["apiKey"] == "test-key"


def test_pauses_only_between_requests(http, monkeypatch):
    sleeps = []
    monkeypatch.setattr(nvd, "_sleep", sleeps.append)
    http.add(nvd.API_BASE, lambda url, params: nvd_page([]))
    nvd.fetch_cve("CVE-2024-10979")
    assert sleeps == []
    nvd.fetch_cve("CVE-2024-10979")
    assert len(sleeps) == 1 and 0 < sleeps[0] <= 6.0


def test_modified_windows_respect_the_120_day_limit(http):
    http.add(nvd.API_BASE, lambda url, params: nvd_page([{"id": "CVE-2026-0001"}]))
    until = datetime(2026, 10, 12, tzinfo=timezone.utc)
    cves = nvd.fetch_product_cves_modified(until - timedelta(days=250), until)
    windows = [(c["params"]["lastModStartDate"], c["params"]["lastModEndDate"]) for c in http.calls]
    assert windows == [
        ("2026-02-04T00:00:00.000", "2026-06-04T00:00:00.000"),
        ("2026-06-04T00:00:00.000", "2026-10-02T00:00:00.000"),
        ("2026-10-02T00:00:00.000", "2026-10-12T00:00:00.000"),
    ]
    assert [c["id"] for c in cves] == ["CVE-2026-0001"]   # repeats across windows collapse


def test_no_postgresql_cves_at_all_fails_closed(http):
    # NVD has more than 200; none means the query broke, not that PostgreSQL is safe.
    http.add(nvd.API_BASE, lambda url, params: nvd_page([]))
    with pytest.raises(SourceUnavailable, match="returned no PostgreSQL CVEs at all"):
        nvd.fetch_product_cves()


def test_a_watch_window_with_no_changes_is_not_an_error(http):
    http.add(nvd.API_BASE, lambda url, params: nvd_page([]))
    until = datetime(2026, 10, 12, tzinfo=timezone.utc)
    assert nvd.fetch_product_cves_modified(until - timedelta(days=1), until) == []
