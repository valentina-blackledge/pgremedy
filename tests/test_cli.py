"""End-to-end CLI behaviour: what users see and what the exit code says."""

import json

import psycopg
import pytest
from click.testing import CliRunner

from pgremedy import scanner
from pgremedy.apis import nvd, postgresql_org, redhat
from pgremedy.cli import cli


def run(*args):
    return CliRunner().invoke(cli, list(args))


def flat(text: str) -> str:
    return " ".join(text.split())


@pytest.fixture
def server(monkeypatch):
    """Pretend to be a PostgreSQL server of the given version."""
    def serve(version: str):
        major, minor = version.split(".")
        num = int(major) * 10000 + int(minor)
        extensions = [{"name": "plpgsql", "default_version": "1.0", "installed_version": "1.0", "comment": ""}]
        info = scanner.ServerInfo(f"{version} (Ubuntu {version}-1)", num, extensions, "scanner@db:5432/postgres")
        monkeypatch.setattr(scanner, "read_server", lambda conninfo, password=None: info)
    return serve


# ── scan ─────────────────────────────────────────────────────────────────────

def test_scan_reports_only_cves_that_affect_the_server(world, server):
    server("16.14")
    result = run("scan", "postgresql://scanner@db/postgres")
    out = flat(result.output)
    assert result.exit_code == 0, out
    assert "16.14 is 1 minor release behind the latest 16.x (16.15)" in out
    assert "CVE-2026-6471" in out and "16.15" in out
    for not_applicable in ("CVE-2024-10979", "CVE-2016-1255", "CVE-2014-0060", "CVE-2010-3781", "CVE-2024-1597"):
        assert not_applicable not in out
    assert "checked 7 PostgreSQL CVE records" in out


def test_scan_of_the_latest_release(world, server):
    server("16.15")
    result = run("scan", "postgresql://scanner@db/postgres")
    out = flat(result.output)
    assert result.exit_code == 0, out
    assert "16.15 is the latest 16.x release" in out
    assert "NVD lists no medium+ severity CVEs affecting 16.15 (checked 7 PostgreSQL CVE records)" in out


def test_scan_never_calls_an_end_of_life_server_safe(world, server):
    server("13.23")
    result = run("scan", "postgresql://scanner@db/postgres")
    out = flat(result.output)
    assert result.exit_code == 0, out
    assert "PostgreSQL 13 reached end-of-life on 2025-11-13" in out
    assert "does not mean it is safe" in out


@pytest.mark.parametrize("source, name", [(nvd.API_BASE, "NVD"), (postgresql_org.VERSIONS_URL, "postgresql.org")])
def test_scan_fails_closed_when_a_source_is_unreachable(world, server, source, name):
    server("16.15")
    world.http.down(source)
    result = run("scan", "postgresql://scanner@db/postgres")
    out = flat(result.output)
    assert result.exit_code == 2
    assert f"couldn't get data from {name}" in out
    assert "not a clean result" in out
    assert "lists no" not in out


def test_scan_reports_database_errors_without_a_traceback(world, monkeypatch):
    def refuse(conninfo, **kwargs):
        raise psycopg.OperationalError('connection to server at "db", port 5432 failed: Connection refused')
    monkeypatch.setattr(psycopg, "connect", refuse)
    result = run("scan", "postgresql://scanner@db/postgres")
    assert result.exit_code == 2
    assert "couldn't connect to PostgreSQL" in flat(result.output)
    assert "Traceback" not in result.output


# ── audit ────────────────────────────────────────────────────────────────────

def _audit_json(*args):
    result = run("audit", *args, "--format", "json")
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)


def test_audit_a_release_lists_only_what_affects_it(world):
    report = _audit_json("16.4")
    assert {r["cve_id"]: r["fixed_in"] for r in report["results"]} == {
        "CVE-2024-10979": "16.5", "CVE-2026-6471": "16.15"}
    assert [r["cve_id"] for r in _audit_json("16.5")["results"]] == ["CVE-2026-6471"]
    assert _audit_json("16.15")["results"] == []


def test_audit_a_branch_lists_everything_that_affected_it(world):
    report = _audit_json("16")
    assert report["scope"] == "branch"
    assert {r["cve_id"] for r in report["results"]} == {"CVE-2024-10979", "CVE-2026-6471", "CVE-2024-4317"}
    assert report["records_checked"] == 7


def test_audit_warns_about_end_of_life(world):
    out = flat(run("audit", "13").output)
    assert "PostgreSQL 13 reached end-of-life on 2025-11-13" in out


def test_audit_fails_closed(world):
    world.http.down(nvd.API_BASE)
    result = run("audit", "16")
    assert result.exit_code == 2
    assert "Found 0" not in result.output


@pytest.mark.parametrize("value, message", [
    ("important", "'important' is on Red Hat's scale; the nearest NVD severity is 'high'"),
    ("crit", "'crit' isn't one of NVD's severities (critical, high, medium, low)"),
    (",", "give at least one of critical, high, medium, low"),
])
def test_audit_rejects_severities_nvd_does_not_use(world, value, message):
    # An unknown value would match nothing and look like a clean result.
    result = run("audit", "16.2", "--severity", value)
    assert result.exit_code == 2
    assert message in flat(result.output)
    assert "Found 0" not in result.output
    assert world.http.calls == []


def test_audit_severity_filter_ignores_case_and_spaces(world):
    report = _audit_json("16.2", "--severity", "HIGH, Critical")
    assert {r["cve_id"] for r in report["results"]} == {"CVE-2024-10979", "CVE-2026-6471"}


@pytest.mark.parametrize("command", [["audit", "16.2"], ["scan", "postgresql://scanner@db/postgres"]])
def test_no_postgresql_cves_from_nvd_is_an_error_not_a_clean_result(world, server, command):
    server("16.14")
    world.product = []
    result = run(*command)
    out = flat(result.output)
    assert result.exit_code == 2
    assert "couldn't get data from NVD (returned no PostgreSQL CVEs at all" in out
    assert "lists no" not in out and "Found 0" not in out


# ── lookup / remedy ──────────────────────────────────────────────────────────

def test_lookup_marks_secondary_sources_as_unavailable(world):
    world.http.down(redhat.CVE_API)
    result = run("lookup", "CVE-2024-10979")
    assert result.exit_code == 0, result.output
    assert "Unavailable: couldn't get data from Red Hat" in flat(result.output)

    report = json.loads(run("lookup", "CVE-2024-10979", "--format", "json").stdout)
    assert "redhat" in report["source_errors"]


def test_lookup_of_an_unknown_cve_is_an_error(world):
    result = run("lookup", "CVE-2099-0001")
    assert result.exit_code == 2
    assert "NVD has no record of CVE-2099-0001" in flat(result.output)


def test_malformed_cve_ids_are_rejected_before_any_request(world):
    result = run("lookup", "CVE-24-1")
    assert result.exit_code == 2
    assert "is not a CVE ID" in flat(result.output)
    assert world.http.calls == []


def test_remedy_fails_closed_instead_of_claiming_the_cve_does_not_exist(world):
    world.http.down(nvd.API_BASE)
    result = run("remedy", "CVE-2024-10978", "--pg-version", "16.2")
    out = flat(result.output)
    assert result.exit_code == 2
    assert "couldn't get data from NVD" in out
    assert "no record" not in out and "not found" not in out


# ── watch ────────────────────────────────────────────────────────────────────

def _watch(state_file):
    return run("watch", "--versions", "16,17", "--once", "--state-file", str(state_file))


def test_watch_records_a_baseline_then_reports_only_new_cves_and_releases(world, tmp_path):
    state_file = tmp_path / "watch.json"
    world.product = [world.records[i] for i in ("CVE-2024-10979", "CVE-2026-6471", "CVE-2016-1255")]

    first = _watch(state_file)
    assert first.exit_code == 0, first.output
    assert "Baseline recorded: 2 known CVEs affect PostgreSQL 16, 17" in flat(first.output)
    assert json.loads(state_file.read_text())["seen"] == ["CVE-2024-10979", "CVE-2026-6471"]

    new_cve = {
        "id": "CVE-2026-99999",
        "descriptions": [{"lang": "en", "value": "Hypothetical new PostgreSQL CVE."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.8, "baseSeverity": "HIGH"}}]},
        "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [{
            "vulnerable": True, "criteria": "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "16.0", "versionEndExcluding": "16.16"}]}]}],
    }
    world.modified = [new_cve, world.records["CVE-2024-10979"], world.records["CVE-2016-1255"]]
    next(v for v in world.versions if v["major"] == "16")["latestMinor"] = "16"
    calls_before = len(world.nvd_calls())

    second = _watch(state_file)
    out = flat(second.output)
    assert second.exit_code == 0, out
    assert "CVE-2026-99999 (CVSS 8.8) affects PG 16 (fixed in 16.16)" in out
    assert "New release: PostgreSQL 16.16 (was 16.15)" in out
    assert "CVE-2024-10979" not in out and "CVE-2016-1255" not in out
    assert all("lastModStartDate" in c["params"] for c in world.nvd_calls()[calls_before:])
    assert "CVE-2026-99999" in json.loads(state_file.read_text())["seen"]


def test_watch_fails_closed_and_leaves_its_state_alone(world, tmp_path):
    state_file = tmp_path / "watch.json"
    assert _watch(state_file).exit_code == 0
    before = state_file.read_text()

    world.http.down(nvd.API_BASE)
    result = _watch(state_file)
    assert result.exit_code == 2
    assert "No new CVEs" not in result.output
    assert state_file.read_text() == before


def test_watch_rejects_minor_versions(world, tmp_path):
    result = run("watch", "--versions", "16.2", "--once", "--state-file", str(tmp_path / "w.json"))
    assert result.exit_code == 2
    assert "not a major version" in flat(result.output)
