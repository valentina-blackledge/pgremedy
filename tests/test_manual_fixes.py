"""Fixes that need a manual step after upgrading (CVE-2024-4317).

The view definitions in fixtures/postgres/ come from real clusters: "vulnerable"
ones were created on 14.11, 15.6 and 16.2 and upgraded in place to 14.23, 15.18
and 16.15; "fixed" ones were created fresh on those releases.
"""

import json
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
from click.testing import CliRunner

from pgremedy import postupgrade, scanner
from pgremedy.cli import cli

FIXTURES = Path(__file__).parent / "fixtures" / "postgres"
CONN = "postgresql://scanner@db.example.com/postgres"
SECRET = "Sup3rS3cretPW"


def run(*args):
    return CliRunner().invoke(cli, list(args))


def flat(text: str) -> str:
    return " ".join(text.split())


def viewdefs(branch: str, state: str) -> tuple[str, str]:
    return tuple((FIXTURES / f"{branch}-{state}.{view}.sql").read_text()
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


# ── detection ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("branch", ["14", "15", "16"])
def test_detection_on_real_view_definitions(branch):
    fix = postupgrade.CVE_2024_4317
    assert fix.is_applied(viewdefs(branch, "fixed"))
    assert not fix.is_applied(viewdefs(branch, "vulnerable"))
    half_done = (viewdefs(branch, "fixed")[0], viewdefs(branch, "vulnerable")[1])
    assert not fix.is_applied(half_done)


def test_only_branches_14_to_16_are_checked():
    assert [f.cve_id for f in postupgrade.for_branch("16")] == ["CVE-2024-4317"]
    for branch in ("13", "17", "18", "9.6", None):
        assert postupgrade.for_branch(branch) == []


# ── scan ─────────────────────────────────────────────────────────────────────

def test_upgraded_cluster_without_the_fix(world, cluster):
    cluster("16.15", "16", {"app": "vulnerable", "postgres": "vulnerable", "template1": "vulnerable"})
    result = run("scan", CONN)
    out = flat(result.output)
    assert result.exit_code == 0, out
    assert "16.15 is the latest 16.x release" in out          # the version check alone says all is well
    assert "Fixes that need a manual step" in out
    assert "CVE-2024-4317 (LOW, CVSS 3.1)" in out
    assert "Not applied in 3 of 3 databases checked: app, postgres, template1." in out
    assert "16.15 includes the fix, but a cluster created before 16.3 keeps the vulnerable objects" in out
    assert "Run fix-CVE-2024-4317.sql as a superuser in every database, including template0 and template1" in out
    assert "Not checked: template0 (doesn't accept connections)." in out


def test_fix_applied_in_only_some_databases(world, cluster):
    cluster("16.15", "16", {"app": "vulnerable", "postgres": "fixed", "template1": "vulnerable"})
    out = flat(run("scan", CONN).output)
    assert "Not applied in 2 of 3 databases checked: app, template1." in out


def test_fix_applied_everywhere(world, cluster):
    cluster("16.15", "16", {"app": "fixed", "postgres": "fixed", "template1": "fixed"})
    out = flat(run("scan", CONN).output)
    assert "Applied in all 3 databases checked." in out
    assert "Not applied" not in out
    check = json.loads(run("scan", CONN, "--format", "json").stdout)["manual_fixes"][0]
    assert check["exposed"] is False
    assert {d["database"]: d["status"] for d in check["databases"]} == {
        "app": "applied", "postgres": "applied", "template0": "not checked", "template1": "applied"}


def test_release_without_the_fix(world, cluster):
    cluster("16.2", "16", {"postgres": "vulnerable", "template1": "vulnerable"})
    out = flat(run("scan", CONN).output)
    assert "16.2 doesn't include the fix (first shipped in 16.3). Upgrade first, then apply it" in out
    assert json.loads(run("scan", CONN, "--format", "json").stdout)["manual_fixes"][0]["release_has_fix"] is False


@pytest.mark.parametrize("branch", ["14", "15"])
def test_other_affected_branches(world, cluster, branch):
    latest = {"14": "14.24", "15": "15.19"}[branch]
    fixed_in = {"14": "14.12", "15": "15.7"}[branch]
    cluster(latest, branch, {"postgres": "vulnerable", "template1": "fixed"})
    out = flat(run("scan", CONN).output)
    assert "Not applied in 1 of 2 databases checked: postgres." in out
    assert f"cluster created before {fixed_in}" in out


@pytest.mark.parametrize("version", ["13.23", "17.11", "18.6"])
def test_unaffected_branches_make_no_extra_connections(world, cluster, version):
    calls = cluster(version, version.split(".")[0], {"postgres": "fixed"})
    result = run("scan", CONN)
    assert result.exit_code == 0, result.output
    assert "Fixes that need a manual step" not in flat(result.output)
    assert calls == []


def test_unreachable_database_is_never_reported_as_fixed(world, cluster):
    refused = psycopg.OperationalError(
        'connection failed: connection to server at "10.0.0.5", port 5432 failed: FATAL:  permission denied '
        'for database "payroll"\nDETAIL:  User does not have CONNECT privilege.')
    cluster("16.15", "16", {"payroll": refused, "postgres": "fixed", "template1": "fixed"})
    out = flat(run("scan", CONN).output)
    assert "Applied in all 2 databases checked." in out
    assert ('Not checked: payroll (permission denied for database "payroll" DETAIL: User does not have '
            'CONNECT privilege).') in out
    assert json.loads(run("scan", CONN, "--format", "json").stdout)["manual_fixes"][0]["exposed"] is None


def test_query_errors_mark_only_that_database(world, cluster):
    cluster("16.15", "16", {"app": Exception("query:permission denied for view pg_stats_ext"),
                            "postgres": "vulnerable", "template1": "fixed"})
    out = flat(run("scan", CONN).output)
    assert "Not applied in 1 of 2 databases checked: postgres." in out
    assert "Not checked: app (permission denied for view pg_stats_ext)." in out


def test_no_database_could_be_checked(world, cluster):
    refused = psycopg.OperationalError("FATAL:  too many connections for role \"scanner\"")
    cluster("16.15", "16", {"postgres": refused, "template1": refused})
    out = flat(run("scan", CONN).output)
    assert "No database could be checked, so this is unknown." in out
    assert json.loads(run("scan", CONN, "--format", "json").stdout)["manual_fixes"][0]["exposed"] is None


def test_shown_whatever_severity_min_is(world, cluster):
    cluster("16.15", "16", {"postgres": "vulnerable"})
    out = flat(run("scan", CONN, "--severity-min", "critical").output)
    assert "CVE-2024-4317 (LOW, CVSS 3.1)" in out


def test_each_database_connection_reuses_the_settings(world, cluster, monkeypatch):
    calls = cluster("16.15", "16", {"app": "fixed", "postgres": "fixed"})
    run("scan", f"{CONN}?connect_timeout=3")
    assert [c["dbname"] for c in calls] == ["app", "postgres"]
    assert all(c["autocommit"] is True and "connect_timeout" not in c for c in calls)

    calls.clear()
    CliRunner().invoke(cli, ["scan", CONN, "-W"], input=f"{SECRET}\n")
    assert calls and all(c["password"] == SECRET and c["connect_timeout"] == 10 for c in calls)


def test_database_errors_never_show_the_password(world, cluster):
    echo = psycopg.OperationalError(f'FATAL:  password "{SECRET}" rejected for database "app"')
    cluster("16.15", "16", {"app": echo, "postgres": "fixed"})
    result = run("scan", f"postgresql://scanner:{SECRET}@db.example.com/postgres")
    assert SECRET not in result.output
    assert 'Not checked: app (password "***" rejected for database "app").' in flat(result.output)


# ── remedy and audit ─────────────────────────────────────────────────────────

def remedy(*args) -> str:
    result = run("remedy", "CVE-2024-4317", *args)
    assert result.exit_code == 0, result.output
    return flat(result.output)


def test_remedy_before_the_fix_adds_the_manual_step(world):
    out = remedy("--pg-version", "16.2")
    assert "Affected. The fix first shipped in 16.3." in out
    assert "Upgrade to 16.15, the latest 16.x release." in out
    assert "After upgrading, also run fix-CVE-2024-4317.sql in every database" in out
    assert "Manual step after upgrading" in out
    assert "The fix is the upgrade plus the manual step above." in out


def test_remedy_never_calls_a_fixed_release_safe_for_this_cve(world):
    out = remedy("--pg-version", "16.15")
    assert "Not affected" not in out
    assert "16.15 includes the fix (first shipped in 16.3), but only clusters created on 16.3 or later" in out
    advice = json.loads(run("remedy", "CVE-2024-4317", "--pg-version", "16.15", "--format", "json").stdout)["advice"]
    assert advice["affected"] is None


def test_remedy_without_a_version_shows_the_manual_step(world):
    out = remedy()
    assert "Manual step after upgrading" in out
    report = json.loads(run("remedy", "CVE-2024-4317", "--format", "json").stdout)
    assert report["manual_step"]["script"] == "fix-CVE-2024-4317.sql"


def test_remedy_leaves_other_branches_and_cves_alone(world):
    out = remedy("--pg-version", "17.1")
    assert "Not affected: NVD doesn't list 17.1 as affected." in out
    assert "Manual step after upgrading" not in out
    other = flat(run("remedy", "CVE-2024-10979", "--pg-version", "16.4").output)
    assert "Manual step after upgrading" not in other
    assert "Upgrading is the fix." in other


def test_audit_mentions_the_manual_step_for_affected_branches(world):
    out = flat(run("audit", "16.15").output)
    assert ("CVE-2024-4317: clusters created before 16.3 stay exposed after upgrading until "
            "fix-CVE-2024-4317.sql is run in every database.") in out
    assert "CVE-2024-4317: clusters created" not in flat(run("audit", "17").output)
