"""Version matching against real NVD records (see fixtures/README.md)."""

import pytest

from pgremedy import pgversion
from pgremedy.apis import nvd
from pgremedy.apis.nvd import Applicability


def test_exact_version_entries_match_only_the_listed_versions(nvd_records):
    cve = nvd_records["CVE-2014-0060"]   # 8.4-era bug, listed as exact versions
    assert nvd.check_version(cve, "8.4.3").affected
    assert nvd.check_version(cve, "8.4.19").affected          # the one range: <= 8.4.19
    assert not nvd.check_version(cve, "8.4.20").affected
    assert not nvd.check_version(cve, "16.15").affected
    assert not nvd.check_version(cve, "18.0").affected
    assert not nvd.check_branch(cve, "16").affected


@pytest.mark.parametrize("cve_id", ["CVE-2016-1255", "CVE-2024-1597"])
def test_other_products_with_postgresql_in_the_name_never_match(nvd_records, cve_id):
    # Debian's postgresql-common script and the pgjdbc driver ("< 42.2.28" has no lower bound)
    cve = nvd_records[cve_id]
    for version in ("9.6.24", "16.0", "16.15", "18.6"):
        assert not nvd.check_version(cve, version).affected
    assert not nvd.check_branch(cve, "16").affected


def test_postgresql_listed_only_as_a_platform_is_ignored(nvd_records):
    cve = nvd_records["CVE-2010-3781"]   # PL/php add-on; PostgreSQL is vulnerable=false
    assert not nvd.check_version(cve, "16.15").affected
    assert not nvd.check_branch(cve, "9.6").affected


@pytest.mark.parametrize("version, expected", [
    ("12.20", Applicability(True, "12.21")),
    ("12.21", Applicability(False)),
    ("16.4", Applicability(True, "16.5")),
    ("16.5", Applicability(False)),
    ("17.0", Applicability(True, "17.1")),
    ("17.1", Applicability(False)),
    ("18.0", Applicability(False)),
])
def test_ranges_are_end_exclusive_and_report_the_fix_in_the_same_branch(nvd_records, version, expected):
    assert nvd.check_version(nvd_records["CVE-2024-10979"], version) == expected


def test_branch_check_reports_the_branch_fix(nvd_records):
    cve = nvd_records["CVE-2026-6471"]
    assert nvd.check_branch(cve, "16") == Applicability(True, "16.15")
    assert nvd.check_branch(cve, "18") == Applicability(True, "18.5")
    assert not nvd.check_branch(cve, "13").affected   # end-of-life branch: not listed at all


def _cve(*matches, negate=False):
    return {"id": "CVE-TEST", "configurations": [{"nodes": [
        {"operator": "OR", "negate": negate, "cpeMatch": list(matches)}]}]}


def _pg(**fields):
    return {"criteria": "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*", "vulnerable": True, **fields}


def test_start_excluding_and_end_including_bounds():
    cve = _cve(_pg(versionStartExcluding="16.2", versionEndIncluding="16.4"))
    assert not nvd.check_version(cve, "16.2").affected
    assert nvd.check_version(cve, "16.3").affected
    assert nvd.check_version(cve, "16.4") == Applicability(True, None)   # first fixed release unknown
    assert not nvd.check_version(cve, "16.5").affected


def test_negated_nodes_are_skipped():
    assert not nvd.check_version(_cve(_pg(versionEndExcluding="99.0"), negate=True), "16.4").affected


def test_range_without_a_start_covers_older_branches_without_inventing_a_fix():
    cve = _cve(_pg(versionEndExcluding="12.21"))
    assert nvd.check_version(cve, "11.5") == Applicability(True, None)   # the fix is in another branch
    assert nvd.check_version(cve, "12.3") == Applicability(True, "12.21")


def test_pre_10_branches_are_two_numbers():
    cve = _cve(
        _pg(versionStartIncluding="9.5.0", versionEndExcluding="9.5.25"),
        _pg(versionStartIncluding="9.6.0", versionEndExcluding="9.6.21"),
    )
    assert nvd.check_version(cve, "9.6.20") == Applicability(True, "9.6.21")
    assert nvd.find_fix_version(cve, "9.5.3") == "9.5.25"
    assert nvd.find_fix_version(cve, "9.6.3") == "9.6.21"


def test_find_fix_version_uses_the_users_branch(nvd_records):
    cve = nvd_records["CVE-2024-10979"]
    assert nvd.find_fix_version(cve, "16.2") == "16.5"
    assert nvd.find_fix_version(cve, "12.3") == "12.21"
    assert nvd.find_fix_version(cve, "11.9") is None


@pytest.mark.parametrize("text, major, minor, branch", [
    ("16.4", "16", 4, False),
    ("16", "16", None, True),
    ("9.6.24", "9.6", 24, False),
    ("9.6", "9.6", None, True),
    ("16.4 (Ubuntu 16.4-1.pgdg24.04+1)", "16", 4, False),
    ("17beta1", "17", None, False),
    ("17devel", "17", None, False),
])
def test_version_parsing(text, major, minor, branch):
    assert pgversion.major_of(text) == major
    assert pgversion.minor_of(text) == minor
    assert pgversion.is_branch(text) == branch


# ── describing affected versions ─────────────────────────────────────────────

SERVER = "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*"


def record(*matches):
    return {"configurations": [{"nodes": [{"cpeMatch": [dict(vulnerable=True, **m) for m in matches]}]}]}


def test_affected_releases_name_the_last_affected_one_not_the_fix(nvd_records):
    cve = nvd_records["CVE-2024-10979"]
    assert nvd.extract_affected_versions(cve) == [
        "12.0 to 12.20", "13.0 to 13.16", "14.0 to 14.13", "15.0 to 15.8", "16.0 to 16.4", "17.0"]
    assert nvd.fixes_by_branch(cve) == {"12": "12.21", "13": "13.17", "14": "14.14", "15": "15.9",
                                        "16": "16.5", "17": "17.1"}


@pytest.mark.parametrize("match, text", [
    ({"versionEndExcluding": "9.4.26"}, "9.4.25 and earlier"),
    ({"versionEndIncluding": "8.4.19"}, "8.4.19 and earlier"),
    ({"versionStartIncluding": "16.0", "versionEndIncluding": "16.4"}, "16.0 to 16.4"),
    ({"versionStartIncluding": "16.2", "versionEndIncluding": "16.2"}, "16.2"),
    ({"versionStartIncluding": "16.0", "versionEndExcluding": "17.0"}, ">=16.0 <17.0"),   # no "16.x" to name
    ({"versionStartExcluding": "15.1", "versionEndExcluding": "15.4"}, ">15.1 <15.4"),
    ({"versionStartIncluding": "18.0"}, "18.0 and later"),
    ({"versionStartIncluding": "9.6.0", "versionEndExcluding": "9.6.24"}, "9.6.0 to 9.6.23"),
])
def test_server_range_descriptions(match, text):
    assert nvd.extract_affected_versions(record(dict(criteria=SERVER, **match))) == [text]


def test_every_version_and_exact_versions():
    assert nvd.extract_affected_versions(record({"criteria": SERVER})) == ["every version"]
    exact = [{"criteria": f"cpe:2.3:a:postgresql:postgresql:9.0.{i}:*:*:*:*:*:*:*"} for i in (1, 2, 3, 5)]
    beta = {"criteria": "cpe:2.3:a:postgresql:postgresql:9.6:beta1:*:*:*:*:*:*"}
    # Consecutive releases are joined; the gap at 9.0.4 is kept.
    assert nvd.extract_affected_versions(record(*exact, beta)) == ["9.0.1 to 9.0.3", "9.0.5", "9.6beta1"]
    # Exact versions inside a listed range add nothing.
    assert nvd.extract_affected_versions(record(*exact, {"criteria": SERVER, "versionEndExcluding": "9.0.6"})) == [
        "9.0.5 and earlier"]


def test_other_products_keep_exclusive_ends_as_written(nvd_records):
    # pgjdbc's numbering can skip, so the release before 42.3.9 isn't named.
    versions = nvd.product_versions(nvd_records["CVE-2024-1597"])
    assert versions["postgresql_jdbc_driver (postgresql)"][:2] == ["<42.2.28", ">=42.3.0 <42.3.9"]
    assert versions["fedora (fedoraproject)"] == ["40"]
    assert nvd.extract_affected_versions(nvd_records["CVE-2024-1597"]) == []
    # Numbered like an old PostgreSQL release, but 1.4.2 may never have shipped.
    widget = record({"criteria": "cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*",
                     "versionStartIncluding": "1.4.0", "versionEndExcluding": "1.4.3"})
    assert nvd.product_versions(widget) == {"widget (example)": [">=1.4.0 <1.4.3"]}


def test_platform_entries_are_not_affected_products(nvd_records):
    # PL/php lists PostgreSQL as vulnerable=false: the platform it runs on.
    assert nvd.product_versions(nvd_records["CVE-2010-3781"]) == {"pl/php (alvaro_herrera)": ["1.4 and earlier"]}


@pytest.mark.parametrize("cve_id, expected", [
    ("CVE-2024-10979", "postgresql"),
    ("CVE-2014-0060", "postgresql"),
    ("CVE-2024-1597", "base-image"),     # pgjdbc: "postgresql" vendor, but not the server
    ("CVE-2016-1255", "base-image"),     # Debian's postgresql-common
    ("CVE-2010-3781", "base-image"),     # PL/php, PostgreSQL only as the platform
])
def test_type_follows_the_vulnerable_products(nvd_records, cve_id, expected):
    assert nvd.detect_type(nvd_records[cve_id]) == expected


def test_go_cpe_is_golang():
    assert nvd.detect_type(record({"criteria": "cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*",
                                   "versionEndExcluding": "1.21.5"})) == "golang"


@pytest.mark.parametrize("description, expected", [
    ("A flaw introduced years ago in libfoo lets a user go around the check.", "base-image"),
    ("In Go before 1.21.5, a crafted request can exhaust memory.", "golang"),
    ("The ParseAddress function in net/mail can loop forever.", "golang"),
    ("Missing authorization in PostgreSQL logical decoding.", "postgresql"),
])
def test_type_of_a_cve_nvd_has_not_analyzed_comes_from_the_description(description, expected):
    assert nvd.detect_type({"descriptions": [{"lang": "en", "value": description}]}) == expected
