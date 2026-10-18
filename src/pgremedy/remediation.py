"""Remediation guidance for a CVE.

For a PostgreSQL server CVE the fix is a minor-release upgrade. Minor releases
are cumulative, so the advice points at the latest release of the user's
branch, which includes the fix and every other one released since, rather than
the first release that fixed this CVE. End-of-life branches get no fixes, so
they are flagged instead.

Workarounds are shown only when a vendor documents one (Red Hat's mitigation
field). pgremedy doesn't guess them from the CVE description: generic advice
matched on keywords was often irrelevant and sometimes harmful.
"""

from __future__ import annotations

from typing import Any

from rich.console import Console

from pgremedy import branches, pgversion, postupgrade
from pgremedy.apis import crunchy, nvd, postgresql_org, redhat
from pgremedy.branches import BranchStatus
from pgremedy.errors import SourceUnavailable
from pgremedy.models import (
    BranchFix,
    CrunchyInfo,
    Finding,
    ManualStep,
    Mitigation,
    RemediationReport,
    VersionAdvice,
)

console = Console(stderr=True)

ADVISORY_URL = "https://www.postgresql.org/support/security/{cve_id}/"


def generate_remediation(cve_id: str, pg_version: str | None = None) -> RemediationReport | None:
    """Remediation for a CVE, or None if NVD has no record of it.

    Raises SourceUnavailable if NVD or postgresql.org can't be reached. Red Hat
    and Crunchy are secondary: their failures are recorded in source_errors.
    """
    console.log(f"Generating remediation for {cve_id}...")
    nvd_data = nvd.fetch_cve(cve_id)
    if nvd_data is None:
        return None
    versions = postgresql_org.fetch_versions()

    cvss = nvd.extract_cvss(nvd_data)
    report = RemediationReport(
        cve_id=cve_id,
        description=nvd.english_description(nvd_data),
        severity=(cvss.get("severity") or "UNKNOWN").upper(),
        cvss_score=cvss.get("score"),
        nvd_status=nvd_data.get("vulnStatus"),
    )

    if not nvd.has_affected_data(nvd_data):
        report.scope = "not-analyzed"
        if nvd.detect_type(nvd_data) == "postgresql":
            report.advisory_url = ADVISORY_URL.format(cve_id=cve_id)
    elif nvd.lists_postgresql_server(nvd_data):
        report.scope = "postgresql-server"
        report.advisory_url = ADVISORY_URL.format(cve_id=cve_id)
        report.branches = _branch_table(nvd_data, versions)
        manual = postupgrade.find(cve_id)
        if manual and (pg_version is None or pgversion.major_of(pg_version) in manual.fixed_in):
            report.manual_step = ManualStep(
                cve_id=manual.cve_id,
                script=manual.script,
                instructions=manual.instructions(),
                advisory_url=manual.advisory_url,
            )
    else:
        report.scope = "other-products"
        report.other_products = nvd.affected_products(nvd_data)

    if pg_version:
        report.advice = _advise(nvd_data, pg_version, versions, report)

    _add_vendor_data(report)
    return report


def _branch_table(nvd_data: dict, versions: list[dict[str, Any]]) -> list[BranchFix]:
    """Every branch NVD lists as affected, plus every supported branch."""
    rows = []
    for entry in versions:
        major = str(entry["major"])
        match = nvd.check_branch(nvd_data, major)
        if not match.affected and not entry.get("supported"):
            continue
        rows.append(BranchFix(
            major=major,
            affected=match.affected,
            fixed_in=match.fixed_in,
            latest=f"{major}.{entry['latestMinor']}",
            supported=bool(entry.get("supported")),
            eol_date=entry.get("eolDate"),
        ))
    rows.sort(key=lambda row: pgversion.parse(row.major))
    return rows


def _advise(nvd_data: dict, version: str, versions: list[dict[str, Any]], report: RemediationReport) -> VersionAdvice:
    status = branches.branch_status(version, versions)
    advice = VersionAdvice(version=version, major=status.major)

    def add(level: str, message: str) -> None:
        advice.findings.append(Finding(level, message))

    if report.scope == "other-products":
        advice.affected = False
        add("ok", "This CVE is in another product, not the PostgreSQL server, so the server version doesn't matter.")
        return advice

    if report.scope == "not-analyzed":
        add("warning", (
            f"NVD hasn't recorded which versions this CVE affects yet (status: {report.nvd_status or 'unknown'}), "
            f"so pgremedy can't tell whether {version} is affected."
        ))
        if not _add_upgrade(advice, status, fix=None, reason="it includes every fix released so far") and status.latest:
            add("info", f"{version} is the {_latest_word(status)} {status.major}.x release.")
        advice.findings += [Finding(level, msg) for level, msg in branches.eol_findings(status)]
        return advice

    match = nvd.check_version(nvd_data, version)
    branch = nvd.check_branch(nvd_data, status.major)
    advice.fixed_in = match.fixed_in or branch.fixed_in
    fix = advice.fixed_in
    current = pgversion.parse(version)
    manual = postupgrade.find(report.cve_id)
    if manual and status.major not in manual.fixed_in:
        manual = None

    if match.affected:
        advice.affected = True
        if fix:
            add("critical", f"Affected. The fix first shipped in {fix}.")
        else:
            add("critical", f"Affected. NVD doesn't list a fixed {status.major}.x release.")
        if not _add_upgrade(advice, status, fix):
            add("warning", (
                f"{version} is already the {_latest_word(status)} {status.major}.x release, and NVD still lists it "
                "as affected. Check the advisory for a workaround or an upcoming fix."
            ))
        if manual:
            add("warning", (
                f"After upgrading, also run {manual.script} in every database: the upgrade alone only fixes "
                "clusters created afterward."
            ))
    elif manual and fix and current is not None and current >= pgversion.parse(fix):
        # The release has the fix, but a cluster created before it doesn't.
        add("warning", (
            f"{version} includes the fix (first shipped in {fix}), but only clusters created on {fix} or later "
            f"get it automatically. A cluster created earlier stays exposed until {manual.script} is run in every "
            "database. `pgremedy scan` checks yours."
        ))
        _add_behind_note(advice, status)
    elif fix and current is not None and current >= pgversion.parse(fix):
        advice.affected = False
        add("ok", f"Not affected: {version} already includes the fix (first shipped in {fix}).")
        _add_behind_note(advice, status)
    elif status.is_eol:
        add("warning", (
            f"NVD doesn't list {status.major}.x for this CVE, but that doesn't mean {version} is safe: "
            "advisories only cover supported branches."
        ))
    elif not status.known:
        add("warning", (
            f"NVD doesn't list {version} as affected, but PostgreSQL {status.major} isn't in postgresql.org's "
            "release list, so that can't be confirmed."
        ))
    else:
        advice.affected = False
        add("ok", f"Not affected: NVD doesn't list {version} as affected.")
        _add_behind_note(advice, status)

    advice.findings += [Finding(level, msg) for level, msg in branches.eol_findings(status)]
    return advice


def _latest_word(status: BranchStatus) -> str:
    return "last" if status.is_eol else "latest"


def _add_upgrade(advice: VersionAdvice, status: BranchStatus, fix: str | None, reason: str | None = None) -> bool:
    """Add the "upgrade to X" step. False if the version is already at or past every target."""
    targets = [v for v in (pgversion.parse(status.latest), pgversion.parse(fix)) if v is not None]
    if not targets:
        return False
    target = max(targets)
    current = pgversion.parse(advice.version)
    if current is not None and current >= target:
        return False
    advice.upgrade_to = str(target)
    if status.latest and target == pgversion.parse(status.latest):
        message = f"Upgrade to {target}, the {_latest_word(status)} {status.major}.x release"
    else:
        message = f"Upgrade to {target} or later"
    advice.findings.append(Finding("info", f"{message}{f': {reason}' if reason else ''}."))
    return True


def _add_behind_note(advice: VersionAdvice, status: BranchStatus) -> None:
    n = status.minors_behind
    if n and not status.is_eol:
        advice.upgrade_to = status.latest
        advice.findings.append(Finding("info", (
            f"It is {n} minor release{'s' if n != 1 else ''} behind the latest {status.major}.x "
            f"({status.latest}); upgrading picks up the other security fixes."
        )))


def _add_vendor_data(report: RemediationReport) -> None:
    try:
        rh = redhat.fetch_cve(report.cve_id)
    except SourceUnavailable as exc:
        report.source_errors["redhat"] = exc.reason
    else:
        if rh:
            report.redhat = redhat.to_info(rh)
            text = redhat.mitigation_text(rh)
            if text:
                report.mitigations.append(Mitigation(source="Red Hat", text=text))

    try:
        cr = crunchy.find_cve_in_releases(report.cve_id, crunchy.fetch_releases())
    except SourceUnavailable as exc:
        report.source_errors["crunchy"] = exc.reason
    else:
        if cr:
            report.crunchy = CrunchyInfo(**cr)
