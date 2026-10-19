"""Compliance checks: DISA STIG V-283674 and CIS PostgreSQL Benchmark 1.5.

Both are manual checks in their documents:

- STIG V-283674 (Crunchy Data Postgres 16 STIG, CAT I): "PostgreSQL products
  must be a version supported by the vendor." The auditor compares the
  installed version against the vendor's version list and security
  advisories; not being at the latest version is a finding.
- CIS 1.5 (numbering as in the CIS PostgreSQL 17 Benchmark v1.0.0): "Ensure
  the Latest Security Patches are Applied." The auditor runs SHOW
  server_version as a low-privileged user and compares it with postgresql.org.

pgremedy automates the comparison and records the evidence. The STIG rule is
judged on the version alone, as its check text says. CIS 1.5 also fails when
a security fix that needs a manual step hasn't been applied, because then the
latest patches aren't in effect. An assessor still owns the final call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from pgremedy import __version__, offline
from pgremedy.models import ScanResult

PASS, FAIL, REVIEW = "pass", "fail", "review"

STIG_RULE = {
    "framework": "DISA STIG",
    "document": "Crunchy Data Postgres 16 STIG",
    "id": "V-283674",
    "rule_id": "SV-283674r1193281_rule",
    "rule_version": "CD16-00-009300",
    "severity": "high",
    "title": "PostgreSQL products must be a version supported by the vendor.",
}
# The same requirement under the IDs of earlier STIG releases, for matching checklists.
STIG_EQUIVALENT_IDS = {"V-283674", "V-265871"}

CIS_RECOMMENDATION = {
    "framework": "CIS",
    "document": "CIS PostgreSQL Benchmark",
    "id": "1.5",
    "rule_id": None,
    "rule_version": None,
    "severity": None,
    "title": "Ensure the Latest Security Patches are Applied",
}

CAT = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}


@dataclass
class ComplianceCheck:
    framework: str
    document: str
    id: str
    title: str
    status: str                       # pass, fail or review
    reasons: list[str] = field(default_factory=list)
    fix: str | None = None
    evidence: str = ""                # plain text, suitable for a checklist's finding details
    rule_id: str | None = None
    rule_version: str | None = None
    severity: str | None = None

    @property
    def label(self) -> str:
        cat = f" ({CAT[self.severity]})" if self.severity in CAT else ""
        return f"{self.framework} {self.id}{cat}"


def _version_findings(result: ScanResult) -> tuple[str, list[str], str | None]:
    """Status, reasons and fix from the release check alone."""
    b = result.branch
    v = result.pg_version
    if b is None or not b.known:
        return REVIEW, [f"PostgreSQL {v} isn't in postgresql.org's release list, so vendor support can't be confirmed."], None
    upgrade_majors = ", ".join(b.supported_majors) or "a supported major version"
    if b.is_eol:
        return FAIL, [f"PostgreSQL {b.major} reached end-of-life on {b.eol_date} and no longer receives fixes."], \
            f"Upgrade to a supported major version ({upgrade_majors})."
    if b.minors_behind is None:
        return REVIEW, [f"{v} isn't a regular release (a beta or development build?), so it can't be compared."], \
            f"Run a released version, such as {b.latest}."
    if b.minors_behind > 0:
        n = b.minors_behind
        return FAIL, [f"{v} is {n} minor release{'s' if n != 1 else ''} behind the latest {b.major}.x ({b.latest})."], \
            f"Upgrade to {b.latest}."
    return PASS, [f"{v} is the latest {b.major}.x release, and PostgreSQL {b.major} is supported until {b.eol_date}."], None


def _manual_fix_findings(result: ScanResult) -> tuple[list[str], list[str], str | None]:
    """(failures, unknowns, fix) from fixes that need a manual step."""
    failures, unknowns, fixes = [], [], []
    for check in result.manual_fixes:
        if check.exposed is True:
            failures.append(
                f"{check.cve_id}'s fix isn't applied in {len(check.missing)} database"
                f"{'s' if len(check.missing) != 1 else ''}: {', '.join(check.missing)}."
            )
            fixes.append(f"Run {check.script} in every database ({check.advisory_url}).")
        elif check.exposed is None:
            names = [d.database for d in check.unchecked if d.reason != "doesn't accept connections"] or ["any database"]
            unknowns.append(f"Couldn't check {', '.join(names)} for {check.cve_id}'s manual fix.")
    return failures, unknowns, " ".join(fixes) or None


def _evidence(result: ScanResult, check_status: str, reasons: list[str], checked_at: datetime,
              include_manual: str) -> str:
    b = result.branch
    lines = [
        f"Evaluated by pgremedy {__version__} on {checked_at:%Y-%m-%d %H:%M} UTC.",
        f"Data: {offline.describe_source(full_hash=True)}.",
        f"Server: {result.connection_info}.",
        f"Installed: PostgreSQL {result.pg_version} (server_version_num {result.pg_version_num}), "
        "read with SHOW server_version.",
    ]
    if b is not None and b.known:
        support = (f"reached end-of-life on {b.eol_date}" if b.is_eol else f"is supported until {b.eol_date}")
        lines.append(f"Latest {b.major}.x release: {b.latest}. PostgreSQL {b.major} {support}.")
    verdict = {PASS: "Not a finding", FAIL: "Finding", REVIEW: "Needs manual review"}[check_status]
    lines.append(f"Result: {verdict}. " + " ".join(reasons))

    if result.cves:
        listed = ", ".join(
            f"{c.cve_id} ({c.cvss.severity} {c.cvss.score}{f', fixed in {c.fixed_in}' if c.fixed_in else ''})"
            for c in result.cves[:10]
        )
        more = f", and {len(result.cves) - 10} more" if len(result.cves) > 10 else ""
        lines.append(f"NVD lists {len(result.cves)} CVE{'s' if len(result.cves) != 1 else ''} "
                     f"affecting {result.pg_version}: {listed}{more}.")
    else:
        lines.append(f"NVD lists no CVEs affecting {result.pg_version} (checked {result.records_checked} records).")

    for mf in result.manual_fixes:
        if mf.exposed is True:
            state = f"not applied in {', '.join(mf.missing)}"
        elif mf.exposed is False:
            state = f"applied in all {len(mf.applied)} databases checked"
        else:
            state = "couldn't be confirmed in every database"
        unchecked = [d.database for d in mf.unchecked]
        note = f" (not checked: {', '.join(unchecked)})" if unchecked else ""
        lines.append(f"{include_manual}{mf.cve_id} manual fix ({mf.script}): {state}{note}.")
    return "\n".join(lines)


def evaluate(result: ScanResult, checked_at: datetime | None = None) -> list[ComplianceCheck]:
    checked_at = checked_at or datetime.now(timezone.utc)
    status, reasons, fix = _version_findings(result)

    stig = ComplianceCheck(status=status, reasons=list(reasons), fix=fix, **STIG_RULE)
    stig.evidence = _evidence(result, status, reasons, checked_at,
                              include_manual="Separate from this rule's version check: ")

    failures, unknowns, manual_fix = _manual_fix_findings(result)
    cis_status, cis_reasons = status, list(reasons)
    if failures:
        cis_status = FAIL
        cis_reasons = [r for r in cis_reasons if status != PASS] + failures
    elif unknowns and status == PASS:
        cis_status = REVIEW
        cis_reasons = cis_reasons + unknowns
    cis_fix = " ".join(f for f in (fix, manual_fix) if f) or None
    cis = ComplianceCheck(status=cis_status, reasons=cis_reasons, fix=cis_fix, **CIS_RECOMMENDATION)
    cis.evidence = _evidence(result, cis_status, cis_reasons, checked_at, include_manual="")
    return [stig, cis]
