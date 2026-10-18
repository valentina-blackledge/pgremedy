"""compliance: STIG V-283674 and CIS 1.5, evidence, exit codes, and checklist updates."""

import json
import re
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import psycopg
import pytest
from click.testing import CliRunner

from pgremedy import scanner
from pgremedy.apis import nvd, postgresql_org
from pgremedy.cli import cli

CONN = "postgresql://auditor@db01.example.com/postgres"
CHECKLISTS = Path(__file__).parent / "fixtures" / "checklists"


def run(*args):
    return CliRunner().invoke(cli, list(args))


def flat(text: str) -> str:
    return " ".join(text.split())


def checks_json(*args) -> tuple[int, dict]:
    result = run("compliance", CONN, "--format", "json", *args)
    return result.exit_code, json.loads(result.stdout)


def by_id(report: dict) -> dict:
    return {c["id"]: c for c in report["checks"]}


@pytest.fixture
def server(monkeypatch):
    def serve(version: str):
        major, minor = version.split(".")
        num = int(major) * 10000 + int(minor) if minor.isdigit() else 0
        info = scanner.ServerInfo(version, num, [], "auditor@db01.example.com:5432/postgres")
        monkeypatch.setattr(scanner, "read_server", lambda conninfo, password=None: info)
    return serve


@pytest.fixture
def checklist(tmp_path):
    def copy(name: str) -> Path:
        target = tmp_path / name
        shutil.copy(CHECKLISTS / name, target)
        return target
    return copy


# ── evaluation ───────────────────────────────────────────────────────────────

def test_latest_release_passes_both(world, server):
    server("16.15")
    code, report = checks_json()
    assert code == 0
    checks = by_id(report)
    assert checks["V-283674"]["status"] == "pass" and checks["1.5"]["status"] == "pass"
    assert checks["V-283674"]["severity"] == "high" and checks["V-283674"]["rule_id"] == "SV-283674r1193281_rule"


def test_behind_the_latest_minor_fails_both(world, server):
    server("16.14")
    result = run("compliance", CONN)
    out = flat(result.output)
    assert result.exit_code == 1
    assert "FAIL DISA STIG V-283674 (CAT I): PostgreSQL products must be a version supported by the vendor." in out
    assert "FAIL CIS 1.5: Ensure the Latest Security Patches are Applied" in out
    assert "16.14 is 1 minor release behind the latest 16.x (16.15). Fix: Upgrade to 16.15." in out
    assert "2 of 2 checks need attention." in out


def test_end_of_life_fails_both(world, server):
    server("13.23")
    code, report = checks_json()
    assert code == 1
    stig = by_id(report)["V-283674"]
    assert stig["status"] == "fail"
    assert stig["reasons"] == ["PostgreSQL 13 reached end-of-life on 2025-11-13 and no longer receives fixes."]
    assert stig["fix"] == "Upgrade to a supported major version (14, 15, 16, 17, 18)."
    assert by_id(report)["1.5"]["status"] == "fail"


def test_unknown_build_needs_review(world, server):
    server("19.0")
    code, report = checks_json()
    assert code == 1
    assert {c["status"] for c in report["checks"]} == {"review"}


def test_missing_manual_fix_fails_cis_but_not_the_version_rule(world, cluster):
    cluster("16.15", "16", {"app": "vulnerable", "postgres": "fixed", "template1": "vulnerable"})
    code, report = checks_json()
    checks = by_id(report)
    assert code == 1
    assert checks["V-283674"]["status"] == "pass"
    assert ("Separate from this rule's version check: CVE-2024-4317 manual fix (fix-CVE-2024-4317.sql): "
            "not applied in app, template1 (not checked: template0).") in checks["V-283674"]["evidence"]
    assert checks["1.5"]["status"] == "fail"
    assert checks["1.5"]["reasons"] == ["CVE-2024-4317's fix isn't applied in 2 databases: app, template1."]
    assert "Run fix-CVE-2024-4317.sql in every database" in checks["1.5"]["fix"]


def test_unchecked_database_makes_cis_need_review(world, cluster):
    refused = psycopg.OperationalError('FATAL:  permission denied for database "payroll"')
    cluster("16.15", "16", {"payroll": refused, "postgres": "fixed", "template1": "fixed"})
    code, report = checks_json()
    assert code == 1
    assert by_id(report)["V-283674"]["status"] == "pass"
    assert by_id(report)["1.5"]["status"] == "review"
    assert "Couldn't check payroll for CVE-2024-4317's manual fix." in by_id(report)["1.5"]["reasons"]


def test_evidence_is_self_contained(world, server):
    server("16.14")
    evidence = by_id(checks_json()[1])["V-283674"]["evidence"]
    lines = evidence.splitlines()
    assert re.match(r"Evaluated by pgremedy \S+ on \d{4}-\d\d-\d\d \d\d:\d\d UTC\.", lines[0])
    assert "Data: live from NVD and postgresql.org." in lines
    assert "Server: auditor@db01.example.com:5432/postgres." in lines
    assert "Installed: PostgreSQL 16.14 (server_version_num 160014), read with SHOW server_version." in lines
    assert "Latest 16.x release: 16.15. PostgreSQL 16 is supported until 2028-11-09." in lines
    assert "Result: Finding. 16.14 is 1 minor release behind the latest 16.x (16.15)." in lines
    assert "NVD lists 1 CVE affecting 16.14: CVE-2026-6471 (HIGH 7.2, fixed in 16.15)." in lines


@pytest.mark.parametrize("source, name", [(nvd.API_BASE, "NVD"), (postgresql_org.VERSIONS_URL, "postgresql.org")])
def test_fails_closed_and_leaves_the_checklist_alone(world, server, checklist, source, name):
    server("16.14")
    path = checklist("postgres16.cklb")
    before = path.read_bytes()
    world.http.down(source)
    result = run("compliance", CONN, "--checklist", str(path))
    assert result.exit_code == 2
    assert f"couldn't get data from {name}" in flat(result.output)
    assert path.read_bytes() == before and not Path(f"{path}.bak").exists()


def test_offline(world, server, tmp_path, monkeypatch):
    bundle = tmp_path / "b.json"
    assert run("bundle", "create", str(bundle), "--no-redhat").exit_code == 0
    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **k: (_ for _ in ()).throw(AssertionError("network used")))
    server("16.14")
    result = run("--data", str(bundle), "compliance", CONN, "--format", "json")
    assert result.exit_code == 1
    report = json.loads(result.stdout)
    assert report["data_source"]["mode"] == "offline"
    assert "Data: offline bundle created" in by_id(report)["V-283674"]["evidence"]


# ── checklists ───────────────────────────────────────────────────────────────

def test_cklb_records_the_result_and_nothing_else(world, server, checklist):
    server("16.14")
    path = checklist("postgres16.cklb")
    before = json.loads(path.read_text())
    result = run("compliance", CONN, "--checklist", str(path))
    assert result.exit_code == 1, result.output
    out = flat(result.output)
    assert (f"Recorded V-283674 (Crunchy Data Postgres 16 STIG) in {path} for asset db01: "
            "not_reviewed -> open.") in out
    after = json.loads(path.read_text())
    other_before, rule_before = before["stigs"][0]["rules"]
    other_after, rule_after = after["stigs"][0]["rules"]
    assert other_after == other_before
    assert rule_after["status"] == "open"
    assert rule_after["finding_details"].startswith("Evaluated by pgremedy")
    assert rule_after["comments"] == rule_before["comments"] == "Assessor note: confirm with the DBA team."
    assert {k: v for k, v in rule_after.items() if k not in ("status", "finding_details")} == \
        {k: v for k, v in rule_before.items() if k not in ("status", "finding_details")}
    assert {k: after[k] for k in after if k != "stigs"} == {k: before[k] for k in before if k != "stigs"}
    assert json.loads(Path(f"{path}.bak").read_text()) == before


def test_ckl_edits_only_status_and_details(world, server, checklist):
    server("16.14")
    path = checklist("postgres16.ckl")
    original = path.read_text()
    assert run("compliance", CONN, "--checklist", str(path)).exit_code == 1
    updated = path.read_text()
    root = ET.fromstring(updated)
    vulns = {v.find("STIG_DATA/ATTRIBUTE_DATA").text: v for v in root.iter("VULN")}
    rule = vulns["V-283674"]
    assert rule.findtext("STATUS") == "Open"
    assert rule.findtext("FINDING_DETAILS").startswith("Evaluated by pgremedy")
    assert rule.findtext("COMMENTS") == "Assessor note: confirm with the DBA team."
    assert vulns["V-000001"].findtext("STATUS") == "NotAFinding"
    # Apart from those two elements, the file is byte-for-byte the same, comment line included.
    strip = lambda text: re.sub(r"<(STATUS|FINDING_DETAILS)>.*?</\1>|<FINDING_DETAILS/>", "", text, flags=re.S)
    assert strip(updated) == strip(original)
    assert "<!--DISA STIG Viewer :: 2.18-->" in updated
    assert Path(f"{path}.bak").read_text() == original


def test_details_are_escaped_in_ckl(world, cluster, checklist):
    cluster("16.15", "16", {"a&b<c>": "vulnerable", "postgres": "fixed"})
    path = checklist("postgres16.ckl")
    run("compliance", CONN, "--checklist", str(path))
    details = [v for v in ET.parse(path).getroot().iter("VULN")][1].findtext("FINDING_DETAILS")
    assert "not applied in a&b<c>" in details


def test_passing_result(world, server, checklist):
    server("16.15")
    path = checklist("postgres16.ckl")
    assert run("compliance", CONN, "--checklist", str(path)).exit_code == 0
    assert [v for v in ET.parse(path).getroot().iter("VULN")][1].findtext("STATUS") == "NotAFinding"


@pytest.mark.parametrize("name, group_id", [("older-release.cklb", "V-265871"), ("renumbered.cklb", "V-999998")])
def test_matches_earlier_releases_and_renumbered_rules(world, server, checklist, name, group_id):
    server("16.15")
    path = checklist(name)
    result = run("compliance", CONN, "--checklist", str(path))
    assert result.exit_code == 0
    assert json.loads(path.read_text())["stigs"][0]["rules"][0]["status"] == "not_a_finding"
    assert f"Recorded {group_id}" in flat(result.output)


@pytest.mark.parametrize("name, message", [
    ("not-postgres.cklb", "has no rule V-283674"),
    ("notes.txt", "isn't a .ckl or .cklb checklist"),
])
def test_wrong_checklists_are_left_alone(world, server, checklist, tmp_path, name, message):
    server("16.15")
    if name == "notes.txt":
        (tmp_path / name).write_text("hello")
        path = tmp_path / name
    else:
        path = checklist(name)
    before = path.read_bytes()
    result = run("compliance", CONN, "--checklist", str(path))
    assert result.exit_code == 2
    assert message in flat(result.output)
    assert path.read_bytes() == before and not Path(f"{path}.bak").exists()


def test_crlf_ckl_keeps_its_line_endings(world, server, checklist):
    server("16.14")
    path = checklist("postgres16.ckl")
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    run("compliance", CONN, "--checklist", str(path))
    data = path.read_bytes()
    assert b"\r\n" in data and b"\n" not in data.replace(b"\r\n", b"")
