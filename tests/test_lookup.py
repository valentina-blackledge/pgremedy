"""lookup: what NVD says is affected and fixed, Red Hat's packages, Crunchy's release notes."""

import json

import pytest
from click.testing import CliRunner

from conftest import FakeResponse
from pgremedy.apis import crunchy
from pgremedy.cli import cli


def run(*args, env=None):
    return CliRunner().invoke(cli, list(args), env=env)


def lookup(*args, env=None) -> str:
    result = run("lookup", *args, env=env)
    assert result.exit_code == 0, result.output
    return " ".join(result.output.split())


def lookup_json(*args) -> dict:
    result = run("lookup", *args, "--format", "json")
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)


# ── what NVD says ────────────────────────────────────────────────────────────

def test_server_cve_names_the_affected_and_fixed_releases(world):
    out = lookup("CVE-2024-10979")
    assert ("Affected 12.0 to 12.20, 13.0 to 13.16, 14.0 to 14.13, 15.0 to 15.8, 16.0 to 16.4, 17.0" in out)
    assert "Fixed in 12.21, 13.17, 14.14, 15.9, 16.5, 17.1" in out
    assert "Advisory https://www.postgresql.org/support/security/CVE-2024-10979/" in out
    assert "16.0 - 16.5" not in out and "not the PostgreSQL server" not in out

    report = lookup_json("CVE-2024-10979")
    assert report["cve_type"] == "postgresql"
    assert report["affected_versions"][-2:] == ["16.0 to 16.4", "17.0"]
    assert report["fixes"]["16"] == "16.5"


def test_driver_cve_is_not_called_a_server_cve(world):
    out = lookup("CVE-2024-1597")
    assert ("This CVE affects other products, not the PostgreSQL server: "
            "postgresql_jdbc_driver (postgresql), fedora (fedoraproject).") in out
    assert "postgresql_jdbc_driver (postgresql): <42.2.28, >=42.3.0 <42.3.9" in out
    assert "Fixed in" not in out and "Advisory" not in out

    report = lookup_json("CVE-2024-1597")
    assert report["cve_type"] == "base-image"
    assert report["affected_versions"] == []      # no server releases
    assert len(report["product_versions"]["postgresql_jdbc_driver (postgresql)"]) == 6


@pytest.mark.parametrize("cve_id, product", [
    ("CVE-2010-3781", "pl/php (alvaro_herrera): 1.4 and earlier"),   # PostgreSQL only as the platform
    ("CVE-2016-1255", "postgresql-common (debian): 1, 2, 3"),        # Debian packaging
])
def test_other_products_with_postgresql_in_their_cpes(world, cve_id, product):
    out = lookup(cve_id)
    assert "not the PostgreSQL server" in out and product in out
    assert lookup_json(cve_id)["cve_type"] == "base-image"


def test_cve_nvd_has_not_analyzed_yet(world):
    world.records["CVE-2026-0003"] = {
        "id": "CVE-2026-0003",
        "vulnStatus": "Awaiting Analysis",
        "descriptions": [{"lang": "en", "value": "A PostgreSQL server bug published today."}],
    }
    out = lookup("CVE-2026-0003")
    assert "NVD hasn't recorded which products or versions this CVE affects yet (status: Awaiting Analysis)" in out
    assert "https://www.postgresql.org/support/security/CVE-2026-0003/" in out
    assert "CVSS not scored yet" in out
    assert lookup_json("CVE-2026-0003")["analyzed"] is False


def test_long_version_lists_say_how_many_more(world):
    world.records["CVE-2026-0005"] = {
        "id": "CVE-2026-0005",
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": f"cpe:2.3:a:example:widget:{i}.0:*:*:*:*:*:*:*"} for i in range(1, 16)
        ]}]}],
    }
    out = lookup("CVE-2026-0005")
    assert "widget (example): 1.0, 2.0," in out and "and 3 more (--format json lists them all)" in out
    assert len(lookup_json("CVE-2026-0005")["product_versions"]["widget (example)"]) == 15


def test_type_override_changes_only_the_category(world):
    report = lookup_json("CVE-2024-1597", "--type", "postgresql")
    assert report["cve_type"] == "postgresql"
    assert report["affected_versions"] == []      # still not a server CVE


# ── Red Hat ──────────────────────────────────────────────────────────────────

def test_every_red_hat_package_is_listed_with_its_product(world, redhat_records):
    world.redhat = redhat_records
    out = lookup("CVE-2024-10979")
    assert "Fixed: 14 products (30 packages). Out of support scope: 1 product." in out
    assert "Fix State" not in out
    # The RHEL 9 packages come after the first eight; all of them are shown, with the release.
    for advisory in ("RHSA-2024:10787", "RHSA-2024:10593", "RHSA-2024:10736"):
        assert advisory in out
    assert "RHEL 9.4 Extended Update Support Fixed RHSA-2024:10736 postgresql:15-9040020241121160342.rhel9" in out
    assert "RHEL 6 Out of" in out           # the unfixed product, with its state (wrapped in the table)

    redhat = lookup_json("CVE-2024-10979")["redhat"]
    assert "fix_state" not in redhat
    assert redhat["package_states"] == [{"package_name": "postgresql", "fix_state": "Out of support scope",
                                         "product_name": "Red Hat Enterprise Linux 6"}]
    assert len(redhat["patches"]) == 30
    assert redhat["patches"][-1] == {"package": "postgresql:15-9040020241121160342.rhel9",
                                     "advisory": "RHSA-2024:10736",
                                     "product_name": "Red Hat Enterprise Linux 9.4 Extended Update Support"}


def test_package_names_are_never_cut_short(world, redhat_records):
    world.redhat = redhat_records
    result = run("lookup", "CVE-2024-10979", env={"COLUMNS": "80"})
    assert result.exit_code == 0
    assert "…" not in result.output


# ── Crunchy ──────────────────────────────────────────────────────────────────

def release(n: int, body: str = "Bug fixes.") -> dict:
    return {"tag_name": f"v5.{n}.0", "name": f"v5.{n}.0", "body": body, "prerelease": False,
            "published_at": "2026-01-01T12:00:00Z", "html_url": f"https://example.test/v5.{n}.0"}


def test_release_notes_beyond_the_first_page_are_searched(world):
    world.releases = [release(n) for n in range(150, 0, -1)]
    world.releases[-1]["body"] = "Fixes CVE-2024-10979."            # the oldest of 150
    out = lookup("CVE-2024-10979")
    assert "PGO Release: v5.1.0" in out
    pages = [c["params"]["page"] for c in world.http.calls if c["url"] == crunchy.RELEASES_API]
    assert pages == [1, 2]


def test_says_how_many_release_notes_were_searched(world):
    world.releases = [release(n) for n in range(137, 0, -1)]
    out = lookup("CVE-2024-10979")
    assert "Not mentioned in the release notes of the 137 PGO releases on GitHub" in out
    assert lookup_json("CVE-2024-10979")["crunchy_releases_searched"] == 137


@pytest.mark.parametrize("response, reason", [
    (FakeResponse(200, []), "no releases listed"),
    (FakeResponse(200, {"message": "Moved Permanently"}), "unexpected response format"),
    (FakeResponse(404, {"message": "Not Found"}), "HTTP 404"),
    (FakeResponse(403, text="API rate limit exceeded for 203.0.113.9."), "set GITHUB_TOKEN"),
])
def test_unusable_release_data_is_unavailable_not_absent(world, response, reason):
    world.http.add(crunchy.RELEASES_API, lambda url, params: response, first=True)
    out = lookup("CVE-2024-10979")
    assert "Unavailable: couldn't get PGO release notes from GitHub (" in out and reason in out
    assert "Not mentioned" not in out and "No Crunchy advisory" not in out


def test_github_token_is_sent_only_when_set(world, monkeypatch):
    lookup("CVE-2024-10979")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    lookup("CVE-2024-10979")
    sent = [c["headers"].get("Authorization") for c in world.http.calls if c["url"] == crunchy.RELEASES_API]
    assert sent == [None, "Bearer ghp_test"]
