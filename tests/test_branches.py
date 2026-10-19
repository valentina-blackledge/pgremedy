"""Branch support status from postgresql.org's versions.json."""

from datetime import date

from pgremedy import branches

TODAY = date(2026, 10, 12)


def test_release_behind_the_latest_minor(versions_json):
    status = branches.branch_status("16.12", versions_json, today=TODAY)
    assert (status.latest, status.minors_behind, status.supported) == ("16.15", 3, True)
    level, message = branches.assess(status)[0]
    assert level == "warning"
    assert "16.12 is 3 minor releases behind the latest 16.x (16.15)" in message


def test_latest_release(versions_json):
    status = branches.branch_status("16.15", versions_json, today=TODAY)
    assert branches.assess(status) == [("ok", "16.15 is the latest 16.x release.")]


def test_end_of_life_branch(versions_json):
    status = branches.branch_status("13.23", versions_json, today=TODAY)
    assert status.is_eol and status.eol_date == "2025-11-13"
    findings = branches.assess(status)
    assert findings[0][0] == "critical"
    assert "reached end-of-life on 2025-11-13" in findings[0][1]
    assert "(14, 15, 16, 17, 18)" in findings[0][1]
    assert any("won't be listed here" in message for _, message in findings)


def test_end_of_life_coming_up(versions_json):
    status = branches.branch_status("14.24", versions_json, today=TODAY)
    assert status.days_to_eol == 31
    assert ("warning", "PostgreSQL 14 reaches end-of-life on 2026-11-12 (in 31 days). "
            "Plan the upgrade to a newer major version.") in branches.assess(status)


def test_pre_10_branch(versions_json):
    status = branches.branch_status("9.6.24", versions_json, today=TODAY)
    assert (status.major, status.latest, status.is_eol) == ("9.6", "9.6.24", True)


def test_unknown_branch(versions_json):
    status = branches.branch_status("19beta1", versions_json, today=TODAY)
    assert not status.known
    assert branches.assess(status)[0][0] == "warning"


def test_branch_without_a_release(versions_json):
    status = branches.branch_status("17", versions_json, today=TODAY)
    assert status.version is None
    assert branches.assess(status) == [("info", "Latest 17.x release: 17.11.")]
