"""Matching CVE IDs in Crunchy PGO release notes."""

import pytest

from pgremedy.apis import crunchy

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
