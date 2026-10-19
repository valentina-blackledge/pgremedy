"""Offline data bundles: create on a connected machine, run anywhere with no network."""

import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
import requests
from click.testing import CliRunner

from pgremedy import offline, scanner
from pgremedy.apis import nvd, postgresql_org, redhat
from pgremedy.cli import cli

CONN = "postgresql://scanner@db.example.com/postgres"


def run(*args, env=None):
    return CliRunner().invoke(cli, list(args), env=env)


def flat(text: str) -> str:
    return " ".join(text.split())


def cut_the_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError(f"network request in offline mode: {args}")
    monkeypatch.setattr(requests, "get", refuse)


@pytest.fixture
def bundle(world, tmp_path, redhat_records):
    """A bundle created from the fixture sources (Red Hat has two records)."""
    world.redhat = redhat_records
    path = tmp_path / "pg-data.json"
    result = run("bundle", "create", str(path))
    assert result.exit_code == 0, result.output
    return path


@pytest.fixture
def server(monkeypatch):
    info = scanner.ServerInfo("16.14 (Ubuntu 16.14-1)", 160014, [], "scanner@db.example.com:5432/postgres")
    monkeypatch.setattr(scanner, "read_server", lambda conninfo, password=None: info)


# ── creating ─────────────────────────────────────────────────────────────────

def test_create_saves_every_source(bundle, world):
    data = json.loads(bundle.read_text())
    assert data["format"] == "pgremedy-bundle" and data["format_version"] == 1
    assert {c["id"] for c in data["nvd_cves"]} == {c["id"] for c in world.product}
    assert data["postgresql_versions"] == world.versions
    assert data["redhat_cves"]["CVE-2026-6471"]["mitigation"]["lang"] == "en:us"
    assert data["redhat_cves"]["CVE-2024-10979"] is None          # Red Hat has no record: kept as "no record"
    assert data["crunchy_releases"] == []
    assert data["sources"]["redhat"] == {"count": 1, "requested": 7}


def test_create_prints_the_sha256(world, tmp_path):
    path = tmp_path / "b.json"
    out = flat(run("bundle", "create", str(path)).output)
    assert f"SHA-256: {hashlib.sha256(path.read_bytes()).hexdigest()}" in out
    assert "NVD: 7 PostgreSQL CVEs" in out


def test_create_without_red_hat(world, tmp_path):
    path = tmp_path / "b.json"
    assert run("bundle", "create", str(path), "--no-redhat").exit_code == 0
    assert json.loads(path.read_text())["redhat_cves"] is None
    assert not any(c["url"].startswith(redhat.CVE_API) for c in world.http.calls)


@pytest.mark.parametrize("source, name", [(nvd.API_BASE, "NVD"), (postgresql_org.VERSIONS_URL, "postgresql.org"),
                                          (redhat.CVE_API, "Red Hat")])
def test_create_writes_nothing_when_a_source_fails(world, tmp_path, source, name):
    world.http.down(source)
    path = tmp_path / "b.json"
    result = run("bundle", "create", str(path))
    assert result.exit_code == 2
    assert f"couldn't get data from {name}" in flat(result.output) and "No bundle was written" in result.output
    assert not path.exists() and list(tmp_path.iterdir()) == []
    if name == "Red Hat":
        assert "--no-redhat" in result.output


def test_create_ignores_a_bundle_set_in_the_environment(bundle, world, tmp_path):
    world.http.calls.clear()
    fresh = tmp_path / "fresh.json"
    assert run("bundle", "create", str(fresh), "--no-redhat", env={"PGREMEDY_DATA": str(bundle)}).exit_code == 0
    assert any(c["url"].startswith(nvd.API_BASE) for c in world.http.calls)


def test_info(bundle):
    out = flat(run("bundle", "info", str(bundle)).output)
    assert "NVD: 7 PostgreSQL CVEs" in out and "Red Hat: 1 records" in out
    assert hashlib.sha256(bundle.read_bytes()).hexdigest() in out


# ── using ────────────────────────────────────────────────────────────────────

def test_offline_scan_makes_no_requests_and_matches_live(bundle, server, monkeypatch):
    live = json.loads(run("scan", CONN, "--format", "json").stdout)
    cut_the_network(monkeypatch)
    result = run("--data", str(bundle), "scan", CONN, "--format", "json")
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert [c["cve_id"] for c in report["cves"]] == [c["cve_id"] for c in live["cves"]] == ["CVE-2026-6471"]
    assert report["data_source"]["mode"] == "offline" and report["data_source"]["sha256"]
    assert live["data_source"] == {"mode": "live"}


def test_offline_table_output_names_the_bundle(bundle, server, monkeypatch):
    cut_the_network(monkeypatch)
    out = flat(run("--data", str(bundle), "scan", CONN).output)
    assert "Using the offline bundle created" in out and "no network requests" in out
    assert "Data: offline bundle created" in out


def test_environment_variable(bundle, server, monkeypatch):
    cut_the_network(monkeypatch)
    assert run("scan", CONN, env={"PGREMEDY_DATA": str(bundle)}).exit_code == 0


def test_offline_remedy_and_lookup(bundle, monkeypatch):
    cut_the_network(monkeypatch)
    out = flat(run("--data", str(bundle), "remedy", "CVE-2026-6471", "--pg-version", "16.14").output)
    assert "Upgrade to 16.15, the latest 16.x release." in out
    assert "From Red Hat: Grant the REPLICATION attribute" in out
    assert run("--data", str(bundle), "lookup", "CVE-2024-10979").exit_code == 0


def test_cve_missing_from_the_bundle_fails_closed(bundle, monkeypatch):
    cut_the_network(monkeypatch)
    result = run("--data", str(bundle), "lookup", "CVE-2026-33811")
    assert result.exit_code == 2
    assert "CVE-2026-33811 isn't in it" in flat(result.output)


def test_red_hat_missing_from_the_bundle_is_reported(world, tmp_path, monkeypatch):
    path = tmp_path / "b.json"
    run("bundle", "create", str(path), "--no-redhat")
    cut_the_network(monkeypatch)
    out = flat(run("--data", str(path), "remedy", "CVE-2026-6471").output)
    assert "Couldn't check Red Hat for a documented workaround (not included in the offline bundle)" in out


@pytest.mark.parametrize("args", [["watch", "--versions", "16", "--once"], ["audit-package", "golang"]])
def test_commands_that_need_live_data_refuse(bundle, monkeypatch, args, tmp_path):
    cut_the_network(monkeypatch)
    if args[0] == "watch":
        args = args + ["--state-file", str(tmp_path / "w.json")]
    result = run("--data", str(bundle), *args)
    assert result.exit_code == 2
    assert "needs live data" in flat(result.output)


def test_stale_bundle_warns(bundle, server, monkeypatch):
    data = json.loads(bundle.read_text())
    data["created_at"] = (datetime.now(timezone.utc) - timedelta(days=45)).strftime("%Y-%m-%dT%H:%M:%SZ")
    bundle.write_text(json.dumps(data))
    cut_the_network(monkeypatch)
    out = flat(run("--data", str(bundle), "scan", CONN).output)
    assert "Warning: the offline bundle is 45 days old" in out


@pytest.mark.parametrize("content, message", [
    ("not json", "isn't valid JSON"),
    ('{"format": "something-else"}', "isn't a pgremedy data bundle"),
    ('{"format": "pgremedy-bundle", "format_version": 99}', "uses bundle format 99"),
    ('{"format": "pgremedy-bundle", "format_version": 1, "nvd_cves": [], "postgresql_versions": [{}]}', "has no nvd_cves"),
])
def test_unusable_files_are_rejected(tmp_path, monkeypatch, content, message):
    cut_the_network(monkeypatch)
    path = tmp_path / "bad.json"
    path.write_text(content)
    result = run("--data", str(path), "audit", "16")
    assert result.exit_code == 2
    assert message in flat(result.output)


def test_age_and_staleness():
    b = offline.Bundle("x", datetime(2026, 10, 1, tzinfo=timezone.utc), "0.1.0", [{}], [{}])
    assert b.age_days(datetime(2026, 10, 31, tzinfo=timezone.utc)) == 30
    assert not b.is_stale(datetime(2026, 10, 31, tzinfo=timezone.utc))
    assert b.is_stale(datetime(2026, 11, 1, tzinfo=timezone.utc))
