"""Matching CVE IDs in Crunchy PGO release notes."""

import pytest

from conftest import FakeResponse
from pgremedy.apis import crunchy
from pgremedy.errors import SourceUnavailable

RELEASES = [
    {"tag_name": "v5.8.9", "name": "v5.8.9", "body": "Updates the base image for CVE-2024-10978.",
     "published_at": "2026-09-01T12:00:00Z", "html_url": "https://example.test/v5.8.9"},
    {"tag_name": "v6.0.3", "name": "v6.0.3 (fixes cve-2026-6471)", "body": "",
     "published_at": "2026-09-15T12:00:00Z", "html_url": "https://example.test/v6.0.3"},
]


@pytest.mark.parametrize("cve_id", ["CVE-2024-1097", "CVE-2024-109", "CVE-2024-10978-1"])
def test_a_shorter_or_longer_id_does_not_match(cve_id):
    assert crunchy.find_cve_in_releases(cve_id, RELEASES) is None


def test_exact_id_matches_in_the_body():
    assert crunchy.find_cve_in_releases("CVE-2024-10978", RELEASES)["release_tag"] == "v5.8.9"


def test_exact_id_matches_in_the_name_ignoring_case():
    found = crunchy.find_cve_in_releases("CVE-2026-6471", RELEASES)
    assert found["release_tag"] == "v6.0.3"
    assert found["published"] == "2026-09-15"


# ── fetching ─────────────────────────────────────────────────────────────────

def test_follows_every_page_and_stops_at_a_short_one(http, monkeypatch):
    monkeypatch.setattr(crunchy, "PAGE_SIZE", 2)
    pool = [{"tag_name": f"v5.{n}.0"} for n in range(5)]
    http.add(crunchy.RELEASES_API, lambda url, params: FakeResponse(
        200, pool[(params["page"] - 1) * 2:params["page"] * 2]))
    assert [r["tag_name"] for r in crunchy.fetch_releases()] == [r["tag_name"] for r in pool]
    assert [c["params"]["page"] for c in http.calls] == [1, 2, 3]


def test_more_releases_than_it_reads_is_an_error(http, monkeypatch):
    monkeypatch.setattr(crunchy, "PAGE_SIZE", 1)
    monkeypatch.setattr(crunchy, "MAX_PAGES", 3)
    http.add(crunchy.RELEASES_API, lambda url, params: FakeResponse(200, [{"tag_name": "v5.0.0"}]))
    with pytest.raises(SourceUnavailable, match="more than 3 releases"):
        crunchy.fetch_releases()
