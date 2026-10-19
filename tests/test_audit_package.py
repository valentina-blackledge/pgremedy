"""audit-package: every page of Red Hat's results, Red Hat's severity scale, failing closed."""

import json

import pytest
from click.testing import CliRunner

from conftest import FakeResponse
from pgremedy.apis import redhat
from pgremedy.cli import cli

SEARCH = f"{redhat.CVE_API}.json"


def run(*args):
    return CliRunner().invoke(cli, list(args))


def flat(text: str) -> str:
    return " ".join(text.split())


def cve(n: int) -> dict:
    return {"CVE": f"CVE-2026-{n:05d}", "severity": "moderate", "public_date": "2026-10-01T00:00:00Z",
            "bugzilla_description": f"golang: issue {n}"}


@pytest.fixture
def search(http, monkeypatch):
    """Red Hat's CVE search, serving `pool` page by page (pages of 2 here)."""
    monkeypatch.setattr(redhat, "PAGE_SIZE", 2)
    state = {"pool": [cve(n) for n in range(5)]}

    def serve(url, params):
        page, size = params["page"], params["per_page"]
        return FakeResponse(200, state["pool"][(page - 1) * size:page * size])

    http.add(SEARCH, serve)
    return state


def test_reads_every_page(search, http):
    result = run("audit-package", "golang", "--format", "json")
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["count"] == 5 and [c["CVE"] for c in report["results"]] == [f"CVE-2026-{n:05d}" for n in range(5)]
    assert [c["params"]["page"] for c in http.calls] == [1, 2, 3]
    assert "Found 5 CVEs from Red Hat" in flat(run("audit-package", "golang").output)


def test_a_full_last_page_is_followed_by_one_more_request(search, http):
    search["pool"] = [cve(n) for n in range(4)]
    assert json.loads(run("audit-package", "golang", "--format", "json").stdout)["count"] == 4
    assert [c["params"]["page"] for c in http.calls] == [1, 2, 3]


def test_too_many_results_is_an_error_not_a_short_list(search, monkeypatch):
    monkeypatch.setattr(redhat, "MAX_PAGES", 2)
    result = run("audit-package", "golang")
    assert result.exit_code == 2
    assert "more than 4 results; narrow the search" in flat(result.output)


def test_no_results(search):
    search["pool"] = []
    result = run("audit-package", "no-such-package")
    assert result.exit_code == 0
    assert "No CVEs found matching criteria" in result.output


@pytest.mark.parametrize("response, reason", [
    (FakeResponse(200, {"message": "Internal error"}), "unexpected response format"),
    (FakeResponse(404), "HTTP 404"),
    (FakeResponse(503), "HTTP 503"),
])
def test_unusable_responses_fail_closed(http, response, reason):
    http.add(SEARCH, lambda url, params: response)
    result = run("audit-package", "golang")
    out = flat(result.output)
    assert result.exit_code == 2
    assert f"couldn't get data from Red Hat ({reason}" in out
    assert "No CVEs found" not in out and "Found" not in out


def test_severities_use_red_hats_scale(search, http):
    assert run("audit-package", "golang", "--severity", "Critical, important").exit_code == 0
    assert {c["params"]["severity"] for c in http.calls} == {"critical,important"}


@pytest.mark.parametrize("value, message", [
    ("high", "'high' is on NVD's scale; the nearest Red Hat severity is 'important'"),
    ("severe", "'severe' isn't one of Red Hat's severities (critical, important, moderate, low)"),
])
def test_rejects_severities_red_hat_does_not_use(http, value, message):
    result = run("audit-package", "golang", "--severity", value)
    assert result.exit_code == 2
    assert message in flat(result.output)
    assert http.calls == []


def test_rejects_a_search_window_of_no_days(http):
    assert run("audit-package", "golang", "--days-ago", "0").exit_code == 2
    assert http.calls == []
