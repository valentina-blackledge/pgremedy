"""remedy: upgrade advice per branch, end-of-life, vendor workarounds, failing closed."""

import json

import pytest
from click.testing import CliRunner

from pgremedy.apis import nvd, postgresql_org, redhat
from pgremedy.cli import cli


def run(*args):
    return CliRunner().invoke(cli, list(args))


def remedy(*args) -> str:
    result = run("remedy", *args)
    assert result.exit_code == 0, result.output
    return " ".join(result.output.split())


def remedy_json(*args) -> dict:
    result = run("remedy", *args, "--format", "json")
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)


# ── advice for one release ───────────────────────────────────────────────────

def test_affected_release_is_told_to_go_to_the_latest_minor(world):
    out = remedy("CVE-2024-10979", "--pg-version", "16.4")
    assert "Affected. The fix first shipped in 16.5." in out
    assert "Upgrade to 16.15, the latest 16.x release." in out


def test_release_with_the_fix_but_behind(world):
    out = remedy("CVE-2024-10979", "--pg-version", "16.12")
    assert "Not affected: 16.12 already includes the fix (first shipped in 16.5)." in out
    assert "It is 3 minor releases behind the latest 16.x (16.15)" in out


def test_release_with_the_fix_and_current(world):
    advice = remedy_json("CVE-2024-10979", "--pg-version", "16.15")["advice"]
    assert advice["affected"] is False
    assert [f["level"] for f in advice["findings"]] == ["ok"]


def test_branch_released_after_the_fix_is_not_affected(world):
    out = remedy("CVE-2024-10979", "--pg-version", "18.6")
    assert "Not affected: NVD doesn't list 18.6 as affected." in out


def test_end_of_life_branch_missing_from_nvd_is_not_called_safe(world):
    out = remedy("CVE-2026-6471", "--pg-version", "13.23")
    assert "NVD doesn't list 13.x for this CVE, but that doesn't mean 13.23 is safe" in out
    assert "PostgreSQL 13 reached end-of-life on 2025-11-13" in out
    assert remedy_json("CVE-2026-6471", "--pg-version", "13.23")["advice"]["affected"] is None


def test_end_of_life_branch_with_a_listed_fix(world):
    out = remedy("CVE-2024-10979", "--pg-version", "12.20")
    assert "Affected. The fix first shipped in 12.21." in out
    assert "Upgrade to 12.22, the last 12.x release." in out
    assert "PostgreSQL 12 reached end-of-life on 2024-11-21" in out


def test_end_of_life_coming_up(world):
    out = remedy("CVE-2024-10979", "--pg-version", "14.10")
    assert "Upgrade to 14.24, the latest 14.x release." in out
    assert "PostgreSQL 14 reaches end-of-life on 2026-11-12 (in 31 days)" in out


def test_latest_release_still_listed_as_affected(world):
    world.records["CVE-2026-0002"] = {
        "id": "CVE-2026-0002",
        "descriptions": [{"lang": "en", "value": "Hypothetical PostgreSQL bug with no fix yet."}],
        "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [{
            "vulnerable": True, "criteria": "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "16.0", "versionEndIncluding": "16.15"}]}]}],
    }
    out = remedy("CVE-2026-0002", "--pg-version", "16.15")
    assert "Affected. NVD doesn't list a fixed 16.x release." in out
    assert "16.15 is already the latest 16.x release, and NVD still lists it as affected" in out
    assert "Upgrade to" not in out


# ── without --pg-version ─────────────────────────────────────────────────────

def test_without_a_version_lists_every_branch_instead_of_one_upgrade(world):
    out = remedy("CVE-2026-6471")
    assert "Upgrade to" not in out
    assert "Fixed releases by branch" in out
    assert "--pg-version" in out
    branches = {b["major"]: b for b in remedy_json("CVE-2026-6471")["branches"]}
    assert list(branches) == ["14", "15", "16", "17", "18"]
    assert (branches["16"]["fixed_in"], branches["16"]["latest"]) == ("16.15", "16.15")
    assert (branches["18"]["fixed_in"], branches["18"]["latest"]) == ("18.5", "18.6")


def test_branch_table_includes_end_of_life_branches_nvd_lists(world):
    branches = {b["major"]: b for b in remedy_json("CVE-2024-10979")["branches"]}
    assert branches["12"] == {"major": "12", "affected": True, "fixed_in": "12.21", "latest": "12.22",
                              "supported": False, "eol_date": "2024-11-21"}
    assert branches["18"]["affected"] is False   # released after the fix
    assert "9.6" not in branches                  # not listed and not supported


def test_links_the_postgresql_advisory(world):
    assert "PostgreSQL advisory: https://www.postgresql.org/support/security/CVE-2024-10979/" in remedy("CVE-2024-10979")


# ── CVEs that aren't about the server ────────────────────────────────────────

def test_other_products(world):
    out = remedy("CVE-2024-1597", "--pg-version", "16.4")
    assert "This CVE affects other products, not the PostgreSQL server: postgresql_jdbc_driver (postgresql)" in out
    assert "the server version doesn't matter" in out
    assert "Fixed releases by branch" not in out


def test_cve_nvd_has_not_analyzed_yet(world):
    world.records["CVE-2026-0003"] = {
        "id": "CVE-2026-0003",
        "vulnStatus": "Awaiting Analysis",
        "descriptions": [{"lang": "en", "value": "A PostgreSQL server bug published today."}],
    }
    out = remedy("CVE-2026-0003", "--pg-version", "16.12")
    assert "NVD hasn't recorded which products or versions this CVE affects yet (status: Awaiting Analysis)" in out
    assert "https://www.postgresql.org/support/security/CVE-2026-0003/" in out
    assert "so pgremedy can't tell whether 16.12 is affected" in out
    assert "Upgrade to 16.15, the latest 16.x release: it includes every fix released so far." in out


# ── workarounds ──────────────────────────────────────────────────────────────

def test_shows_red_hats_documented_workaround(world, redhat_records):
    world.redhat = redhat_records
    out = remedy("CVE-2026-6471", "--pg-version", "16.14")
    assert "Workarounds From Red Hat: Grant the REPLICATION attribute only to highly trusted users" in out
    mitigations = remedy_json("CVE-2026-6471")["mitigations"]
    assert [m["source"] for m in mitigations] == ["Red Hat"]


def test_ignores_red_hats_not_available_boilerplate(world, redhat_records):
    world.redhat = redhat_records
    world.records["CVE-2024-7348"] = dict(world.records["CVE-2024-10979"], id="CVE-2024-7348")
    out = remedy("CVE-2024-7348")
    assert "None documented by Red Hat. Upgrading is the fix." in out
    assert "either not available" not in out


@pytest.mark.parametrize("description", [
    "A crafted request containing URLs can crash the server.",
    "An unprivileged user can read the password hash of another role.",
    "Missing check on extension scripts allows privilege escalation over SSL.",
])
def test_never_guesses_workarounds_from_the_description(world, description):
    world.records["CVE-2026-0004"] = dict(
        world.records["CVE-2024-10979"], id="CVE-2026-0004",
        descriptions=[{"lang": "en", "value": description}])
    report = remedy_json("CVE-2026-0004", "--pg-version", "16.4")
    assert report["mitigations"] == []
    out = remedy("CVE-2026-0004", "--pg-version", "16.4")
    for guessed in ("ROW LEVEL SECURITY", "pg_hba", "superuser", "SECURITY DEFINER", "ssl_min_protocol"):
        assert guessed not in out


def test_red_hat_outage_is_reported_not_hidden(world):
    world.http.down(redhat.CVE_API)
    out = remedy("CVE-2026-6471", "--pg-version", "16.14")
    assert "Couldn't check Red Hat for a documented workaround" in out
    assert "None documented by Red Hat" not in out


# ── failing closed and bad input ─────────────────────────────────────────────

@pytest.mark.parametrize("source, name", [(nvd.API_BASE, "NVD"), (postgresql_org.VERSIONS_URL, "postgresql.org")])
def test_fails_closed_when_a_required_source_is_down(world, source, name):
    world.http.down(source)
    result = run("remedy", "CVE-2024-10979", "--pg-version", "16.4")
    assert result.exit_code == 2
    assert f"couldn't get data from {name}" in " ".join(result.output.split())


def test_unknown_cve(world):
    result = run("remedy", "CVE-2099-0001")
    assert result.exit_code == 2
    assert "NVD has no record of CVE-2099-0001" in result.output


@pytest.mark.parametrize("version", ["16", "sixteen"])
def test_pg_version_must_be_a_specific_release(world, version):
    result = run("remedy", "CVE-2024-10979", "--pg-version", version)
    assert result.exit_code == 2
    assert "is not a specific release" in " ".join(result.output.split())
    assert world.http.calls == []
