"""pgremedy CLI — PostgreSQL CVE detection, remediation, and monitoring."""

from __future__ import annotations

import json
import re
from dataclasses import asdict

import click
import psycopg
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from pgremedy import branches, pgversion, postupgrade
from pgremedy.apis import crunchy, nvd, postgresql_org, redhat
from pgremedy.errors import ConnectionFailed, SourceUnavailable
from pgremedy.scanner import NO_CONNECTIONS
from pgremedy.models import (
    CVEReport,
    CVSSInfo,
    CrunchyInfo,
    ManualFixCheck,
    RedHatInfo,
    RemediationReport,
)

console = Console(stderr=True)
output = Console()

# Exit codes: 0 = the check ran; 2 = it could not run (a data source was
# unreachable, the CVE doesn't exist, the database refused the connection, or
# the command line was invalid). A failed check never exits 0.
EXIT_ERROR = 2

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "IMPORTANT": "red",
    "MEDIUM": "yellow",
    "MODERATE": "yellow",
    "LOW": "green",
    "UNKNOWN": "dim",
}

ASSESSMENT_STYLES = {"critical": "bold red", "warning": "yellow", "ok": "green", "info": "default"}

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _severity_style(sev: str) -> str:
    return SEVERITY_COLORS.get(sev.upper(), "dim")


def _cve_id(ctx, param, value: str) -> str:
    cve_id = value.strip().upper()
    if not CVE_ID_PATTERN.match(cve_id):
        raise click.BadParameter(f"'{value}' is not a CVE ID (expected e.g. CVE-2024-10978).")
    return cve_id


def _pg_version(ctx, param, value: str) -> str:
    if pgversion.parse(value) is None:
        raise click.BadParameter(f"'{value}' is not a PostgreSQL version (expected e.g. 16 or 16.4).")
    return value.strip()


def _pg_release(ctx, param, value: str | None) -> str | None:
    """A specific release such as 16.4, not a branch such as 16."""
    if value is None:
        return None
    if pgversion.parse(value) is None or pgversion.is_branch(value):
        raise click.BadParameter(
            f"'{value}' is not a specific release. Use the full version, e.g. 16.4 "
            "(SHOW server_version on the server tells you)."
        )
    return value.strip()


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[:width].rstrip() + "..."


def _print_assessment(assessment: list[tuple[str, str]]) -> None:
    for level, message in assessment:
        style = ASSESSMENT_STYLES.get(level, "default")
        output.print(f"[{style}]{escape(message)}[/{style}]")


def _build_report(cve_id: str, forced_type: str | None = None) -> CVEReport | None:
    """Full CVE report, or None if NVD has no such CVE. Raises SourceUnavailable for NVD."""
    console.log(f"Looking up {cve_id}...")
    nvd_data = nvd.fetch_cve(cve_id)
    if nvd_data is None:
        return None

    cve_type = forced_type or nvd.detect_type(nvd_data)
    console.log(f"CVE type: {cve_type}")

    report = CVEReport(cve_id=cve_id, cve_type=cve_type)
    report.description = nvd.english_description(nvd_data)
    report.cvss = CVSSInfo(**nvd.extract_cvss(nvd_data))
    report.affected_versions = nvd.extract_affected_versions(nvd_data, cve_type)
    report.references = [r.get("url", "") for r in nvd_data.get("references", [])[:5]]

    try:
        rh = redhat.fetch_cve(cve_id)
    except SourceUnavailable as exc:
        report.source_errors["redhat"] = exc.reason
        rh = None
    if rh:
        report.redhat = redhat.to_info(rh)

    try:
        cr = crunchy.find_cve_in_releases(cve_id, crunchy.fetch_releases())
    except SourceUnavailable as exc:
        report.source_errors["crunchy"] = exc.reason
        cr = None
    if cr:
        report.crunchy = CrunchyInfo(**cr)

    return report


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _print_manual_fixes(checks: list[ManualFixCheck], pg_version: str) -> None:
    """Fixes the upgrade alone doesn't apply: shown whenever they were checked, whatever --severity-min says."""
    if not checks:
        return
    output.print("[bold]Fixes that need a manual step[/bold]")
    for check in checks:
        score = f", CVSS {check.cvss_score}" if check.cvss_score is not None else ""
        output.print(f"  {check.cve_id} ({check.severity}{score}): {escape(check.summary)}")
        checked = len(check.missing) + len(check.applied)
        if check.missing:
            output.print(
                f"    [bold red]Not applied in {len(check.missing)} of {_plural(checked, 'database')} checked: "
                f"{escape(', '.join(check.missing))}.[/bold red]"
            )
            if check.release_has_fix:
                output.print(
                    f"    {pg_version} includes the fix, but a cluster created before {check.fixed_in} keeps the "
                    "vulnerable objects until the fix is applied in each database."
                )
            else:
                output.print(
                    f"    {pg_version} doesn't include the fix (first shipped in {check.fixed_in}). Upgrade first, "
                    "then apply it: the upgrade alone only fixes clusters created afterward."
                )
            output.print(
                f"    Run {check.script} as a superuser in every database, including template0 and template1 "
                f"(template0 needs connections enabled temporarily). Steps: {check.advisory_url}"
            )
        elif check.applied:
            output.print(f"    [green]Applied in all {_plural(checked, 'database')} checked.[/green]")
        else:
            output.print("    [yellow]No database could be checked, so this is unknown.[/yellow]")
        for db in check.unchecked:
            style = "dim" if db.reason == NO_CONNECTIONS else "yellow"
            reason = (db.reason or "unknown reason").rstrip(".")
            output.print(f"    [{style}]Not checked: {escape(db.database)} ({escape(reason)}).[/{style}]")
    output.print()


def _print_redhat(rh: RedHatInfo | None, error: str | None) -> None:
    output.print("[bold]Red Hat Status[/bold]")
    if error:
        output.print(f"  [yellow]Unavailable: couldn't reach Red Hat ({escape(error)})[/yellow]")
    elif rh:
        output.print(f"  Severity: {rh.severity}")
        output.print(f"  Fix State: {rh.fix_state}")
        if rh.upstream_fix:
            output.print(f"  Upstream Fix: {escape(rh.upstream_fix)}")
        if rh.bugzilla_url:
            output.print(f"  Bugzilla: {rh.bugzilla_url}")
        if rh.patches:
            output.print("  Patched Packages:")
            for p in rh.patches:
                output.print(f"    {escape(p.package)} via {p.advisory}")
        if rh.package_states:
            output.print("  Package State:")
            for ps in rh.package_states:
                output.print(f"    {escape(ps.package_name)} ({escape(ps.product_name)}): {ps.fix_state}")
    else:
        output.print("  [dim]Red Hat has no record of this CVE[/dim]")
    output.print()


def _print_crunchy(cr: CrunchyInfo | None, error: str | None) -> None:
    output.print("[bold]Crunchy Data Status[/bold]")
    if error:
        output.print(f"  [yellow]Unavailable: couldn't reach GitHub ({escape(error)})[/yellow]")
    elif cr:
        output.print(f"  PGO Release: {cr.release_tag} ({escape(cr.release_name or '')})")
        output.print(f"  Published: {cr.published}")
        if cr.prerelease:
            output.print("  [yellow]Status: Pre-release (not yet GA)[/yellow]")
        if cr.url:
            output.print(f"  Details: {cr.url}")
    else:
        output.print("  [dim]No Crunchy advisory found[/dim]")
    output.print()


def _print_remediation(report: RemediationReport) -> None:
    output.print()
    output.rule(f"[bold]Remediation: {report.cve_id}[/bold]")
    output.print()
    output.print(f"[bold]Description:[/bold] {escape(report.description or 'N/A')}")
    style = _severity_style(report.severity)
    score = f" (CVSS {report.cvss_score})" if report.cvss_score is not None else ""
    output.print(f"[bold]Severity:[/bold] [{style}]{report.severity}[/{style}]{score}")
    output.print()

    if report.scope == "not-analyzed":
        output.print(
            "[yellow]NVD hasn't recorded which products or versions this CVE affects yet "
            f"(status: {escape(report.nvd_status or 'unknown')}).[/yellow]"
        )
        if report.advisory_url:
            output.print(f"If it's a PostgreSQL server CVE, its advisory lists the fixed releases: {report.advisory_url}")
        output.print()
    elif report.scope == "other-products":
        products = ", ".join(report.other_products) or "unnamed products"
        output.print(
            f"This CVE affects other products, not the PostgreSQL server: {escape(products)}. "
            "Update those; the vendor status below may help."
        )
        output.print()

    if report.advice:
        output.print(f"[bold]Your version ({escape(report.advice.version)})[/bold]")
        for finding in report.advice.findings:
            level_style = ASSESSMENT_STYLES.get(finding.level, "default")
            output.print(f"  [{level_style}]{escape(finding.message)}[/{level_style}]")
        output.print()
    elif report.branches:
        t = Table(title="Fixed releases by branch", title_justify="left", title_style="bold")
        t.add_column("Branch")
        t.add_column("First fixed in")
        t.add_column("Latest release")
        t.add_column("Support")
        for row in report.branches:
            fixed = row.fixed_in or ("not listed" if row.affected else "not affected")
            if row.supported:
                support = f"until {row.eol_date}" if row.eol_date else "supported"
                latest = row.latest or "?"
            else:
                support = Text(f"ended {row.eol_date}" if row.eol_date else "end-of-life", style="yellow")
                latest = f"{row.latest} (final)" if row.latest else "?"
            t.add_row(row.major, fixed, latest, support)
        output.print(t)
        output.print("[dim]Add --pg-version (e.g. 16.4) for advice on a specific server.[/dim]")
        output.print()

    if report.advisory_url and report.scope == "postgresql-server":
        output.print(f"PostgreSQL advisory: {report.advisory_url}")
        output.print()

    if report.manual_step:
        step = report.manual_step
        output.print("[bold]Manual step after upgrading[/bold]")
        output.print(
            "  [yellow]Upgrading alone only fixes clusters created afterward. Existing clusters stay exposed "
            "until the fix is applied in each database.[/yellow]"
        )
        output.print(f"  {escape(step.instructions)}")
        output.print("  [dim]`pgremedy scan` checks whether it has been applied.[/dim]")
        output.print()

    output.print("[bold]Workarounds[/bold]")
    if "redhat" in report.source_errors:
        output.print(
            f"  [yellow]Couldn't check Red Hat for a documented workaround "
            f"({escape(report.source_errors['redhat'])}).[/yellow]"
        )
    elif report.mitigations:
        for m in report.mitigations:
            output.print(f"  From {escape(m.source)}:")
            for line in m.text.splitlines():
                if line.strip():
                    output.print(f"    {escape(line.strip())}")
    elif report.manual_step:
        output.print("  None documented by Red Hat. The fix is the upgrade plus the manual step above.")
    else:
        output.print("  None documented by Red Hat. Upgrading is the fix.")
    output.print()

    _print_redhat(report.redhat, report.source_errors.get("redhat"))
    _print_crunchy(report.crunchy, report.source_errors.get("crunchy"))


def _print_report(report: CVEReport) -> None:
    output.print()
    output.rule(f"[bold]{report.cve_id}[/bold]")
    if report.cve_type != "postgresql":
        output.print(f"[dim]Type:[/dim] {report.cve_type.replace('-', ' ').title()}")
    output.print()

    if report.description:
        output.print(escape(report.description))
        output.print()

    t = Table(show_header=False, box=None, padding=(0, 2))
    t.add_column("Field", style="bold")
    t.add_column("Value")
    sev_text = Text(f"{report.cvss.score} ({report.cvss.severity})")
    sev_text.stylize(_severity_style(report.cvss.severity))
    t.add_row("CVSS", sev_text)
    t.add_row("Attack Vector", report.cvss.vector)
    t.add_row("Affected", ", ".join(report.affected_versions))
    output.print(t)
    output.print()

    _print_redhat(report.redhat, report.source_errors.get("redhat"))
    _print_crunchy(report.crunchy, report.source_errors.get("crunchy"))

    if report.references:
        output.print("[bold]References[/bold]")
        for ref in report.references:
            output.print(f"  {ref}")
        output.print()


LOOKUP_EXAMPLES = """
\b
Examples:
  pgremedy lookup CVE-2024-10978
  pgremedy lookup CVE-2026-33811 --type golang
  pgremedy lookup CVE-2024-10978 --format json
"""

AUDIT_EXAMPLES = """
\b
Examples:
  pgremedy audit 17                         every CVE that affected any 17.x release
  pgremedy audit 16.2 --severity critical,high
  pgremedy audit 14.9 --format json
"""

AUDIT_PACKAGE_EXAMPLES = """
\b
Examples:
  pgremedy audit-package golang
  pgremedy audit-package openssl --severity critical
  pgremedy audit-package glibc --days-ago 180
"""

SCAN_EXAMPLES = """
\b
Examples:
  pgremedy scan "postgresql://admin@localhost:5432/mydb" -W     prompt for the password
  pgremedy scan "host=db.example.com dbname=prod user=admin"    password from ~/.pgpass
  pgremedy scan "service=my_pg_service" --severity-min high     settings from pg_service.conf

\b
Avoid putting the password in the connection string: it ends up in your
shell history and the process list.
"""

REMEDY_EXAMPLES = """
\b
Examples:
  pgremedy remedy CVE-2024-10978                       fixed releases for every branch
  pgremedy remedy CVE-2024-10978 --pg-version 16.2     advice for one server
  pgremedy remedy CVE-2024-10979 --pg-version 17.0 --format json
"""

WATCH_EXAMPLES = """
\b
Examples:
  pgremedy watch --versions 16,17 --once
  pgremedy watch --versions 17 --interval 1800
  pgremedy watch --versions 14,15,16,17
"""


# ── CLI ──────────────────────────────────────────────────────────────────────

class ExamplesCommand(click.Command):
    def format_epilog(self, ctx, formatter):
        if self.epilog:
            formatter.write(self.epilog)


class PgRemedyGroup(click.Group):
    """Turns failed lookups into a clear error and exit code 2, never a clean result."""

    def invoke(self, ctx):
        try:
            return super().invoke(ctx)
        except SourceUnavailable as exc:
            console.print(
                f"[bold red]Error:[/bold red] couldn't get data from {escape(exc.source)} "
                f"({escape(exc.reason)})."
            )
            console.print("The check did not run, so this is not a clean result.")
            ctx.exit(EXIT_ERROR)
        except ConnectionFailed as exc:
            console.print(f"[bold red]Error:[/bold red] couldn't connect to PostgreSQL: {escape(str(exc))}")
            ctx.exit(EXIT_ERROR)
        except psycopg.Error as exc:
            # The scanner converts database errors to ConnectionFailed with
            # secrets removed. Anything that slips past it may quote the
            # connection string, so print only its type.
            console.print(f"[bold red]Error:[/bold red] database error ({type(exc).__name__}).")
            ctx.exit(EXIT_ERROR)


MAIN_HELP = """
pgremedy — PostgreSQL CVE detection, remediation, and monitoring.

\b
For usage examples on any command, run:
  pgremedy <command> --help
  pgremedy scan --help
  pgremedy remedy --help

\b
Exit codes: 0 when the check ran, 2 when it couldn't (a data
source was unreachable, the CVE doesn't exist, or the database
refused the connection).
"""


@click.group(cls=PgRemedyGroup, help=MAIN_HELP)
@click.version_option(package_name="pgremedy")
def cli():
    pass


@cli.command(cls=ExamplesCommand, epilog=LOOKUP_EXAMPLES)
@click.argument("cve_id", callback=_cve_id)
@click.option("--type", "forced_type", type=click.Choice(["postgresql", "golang", "base-image"]), help="Force CVE type.")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.pass_context
def lookup(ctx, cve_id: str, forced_type: str | None, fmt: str):
    """Look up a specific CVE ID."""
    report = _build_report(cve_id, forced_type)
    if report is None:
        console.print(f"[bold red]Error:[/bold red] NVD has no record of {cve_id}.")
        ctx.exit(EXIT_ERROR)
    if fmt == "json":
        click.echo(json.dumps(asdict(report), indent=2, default=str))
    else:
        _print_report(report)


@cli.command(cls=ExamplesCommand, epilog=AUDIT_EXAMPLES)
@click.argument("pg_version", callback=_pg_version)
@click.option("--severity", help="Filter: critical,high,medium,low (comma-separated)")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def audit(pg_version: str, severity: str | None, fmt: str):
    """Audit a PostgreSQL release (16.2) or a whole branch (16) for known CVEs."""
    whole_branch = pgversion.is_branch(pg_version)
    major = pgversion.major_of(pg_version)
    scope = f"PostgreSQL {major}.x" if whole_branch else f"PostgreSQL {pg_version}"
    console.log(f"Auditing {scope}...")

    status = branches.branch_status(pg_version, postgresql_org.fetch_versions())
    assessment = branches.assess(status)
    for fix in postupgrade.for_branch(major):
        assessment.append(("warning", (
            f"{fix.cve_id}: clusters created before {fix.fixed_in[major]} stay exposed after upgrading until "
            f"{fix.script} is run in every database. `pgremedy scan` checks whether it has been."
        )))
    cves = nvd.fetch_product_cves()

    severity_filter = [s.strip().upper() for s in severity.split(",")] if severity else None
    results = []
    for cve_data in cves:
        match = nvd.check_branch(cve_data, major) if whole_branch else nvd.check_version(cve_data, pg_version)
        if not match.affected:
            continue
        cvss = nvd.extract_cvss(cve_data)
        sev = (cvss.get("severity") or "UNKNOWN").upper()
        if severity_filter and sev not in severity_filter:
            continue
        results.append({
            "cve_id": cve_data.get("id", ""),
            "score": cvss["score"],
            "severity": sev,
            "vector": cvss["vector"],
            "fixed_in": match.fixed_in,
            "affected": nvd.extract_affected_versions(cve_data),
            "description": nvd.english_description(cve_data),
        })

    results.sort(key=lambda x: x.get("score") or 0, reverse=True)

    if fmt == "json":
        click.echo(json.dumps({
            "pg_version": pg_version,
            "scope": "branch" if whole_branch else "release",
            "branch": asdict(status),
            "assessment": [{"level": level, "message": msg} for level, msg in assessment],
            "records_checked": len(cves),
            "count": len(results),
            "results": results,
        }, indent=2))
        return

    output.print()
    output.rule(f"[bold]{scope} — CVE Audit[/bold]")
    _print_assessment(assessment)
    output.print()
    if whole_branch:
        output.print(
            f"Found [bold]{len(results)}[/bold] CVEs that affected at least one {major}.x release "
            f"(checked {len(cves)} PostgreSQL CVE records)."
        )
        output.print(f"[dim]Pass a full release (e.g. {status.latest or major + '.0'}) to see only what affects it.[/dim]")
    else:
        output.print(
            f"Found [bold]{len(results)}[/bold] CVEs affecting PostgreSQL {pg_version} "
            f"(checked {len(cves)} PostgreSQL CVE records)."
        )
    output.print()

    if results:
        t = Table()
        t.add_column("CVE ID")
        t.add_column("CVSS", justify="right")
        t.add_column("Severity")
        t.add_column("Fixed in")
        t.add_column("Description", max_width=60)
        for r in results[:25]:
            sev_text = Text(r["severity"])
            sev_text.stylize(_severity_style(r["severity"]))
            t.add_row(r["cve_id"], str(r["score"]), sev_text, r["fixed_in"] or "—", _truncate(r["description"], 120))
        output.print(t)

    if len(results) > 25:
        output.print(f"\n[dim]... and {len(results) - 25} more. Use --severity to filter or --format json for all.[/dim]")
    output.print("\n[dim]Run `pgremedy lookup <CVE-ID>` for full details.[/dim]")


@cli.command("audit-package", cls=ExamplesCommand, epilog=AUDIT_PACKAGE_EXAMPLES)
@click.argument("package")
@click.option("--severity", help="Filter: critical,important,moderate,low")
@click.option("--days-ago", default=90, type=int, help="How far back to search.")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def audit_package(package: str, severity: str | None, days_ago: int, fmt: str):
    """Audit a Red Hat package for recent CVEs."""
    console.log(f"Searching Red Hat CVEs for '{package}' (last {days_ago} days)...")
    cves = redhat.search_by_package(package, severity=severity, days_ago=days_ago)

    if fmt == "json":
        click.echo(json.dumps({"package": package, "count": len(cves), "results": cves}, indent=2, default=str))
        return

    output.print()
    output.rule(f"[bold]Package Audit: {escape(package)}[/bold]")
    output.print(f"Found [bold]{len(cves)}[/bold] CVEs from Red Hat (last {days_ago} days)")
    if severity:
        output.print(f"Filtered by severity: {escape(severity)}")
    output.print()

    if not cves:
        output.print("[dim]No CVEs found matching criteria.[/dim]")
        return

    t = Table()
    t.add_column("CVE ID")
    t.add_column("Severity")
    t.add_column("Synopsis", max_width=60)
    t.add_column("Date")
    for cve in cves[:30]:
        t.add_row(
            cve.get("CVE", "N/A"),
            cve.get("severity", "N/A"),
            (cve.get("bugzilla_description") or "")[:80],
            (cve.get("public_date") or "N/A")[:10],
        )
    output.print(t)

    if len(cves) > 30:
        output.print(f"\n[dim]... and {len(cves) - 30} more. Use --severity to filter.[/dim]")
    output.print("\n[dim]Run `pgremedy lookup <CVE-ID>` for full details.[/dim]")


@cli.command(cls=ExamplesCommand, epilog=SCAN_EXAMPLES)
@click.argument("conninfo")
@click.option("--severity-min", type=click.Choice(["low", "medium", "high", "critical"]), default="medium")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("-W", "--password-prompt", is_flag=True,
              help="Prompt for the password instead of putting it in the connection string.")
def scan(conninfo: str, severity_min: str, fmt: str, password_prompt: bool):
    """Scan a live PostgreSQL instance for CVEs."""
    from pgremedy.scanner import scan_instance
    password = click.prompt("Password", hide_input=True, err=True) if password_prompt else None
    result = scan_instance(conninfo, severity_min=severity_min, password=password)

    if fmt == "json":
        click.echo(json.dumps(asdict(result), indent=2, default=str))
        return

    output.print()
    output.rule(f"[bold]Scan: PostgreSQL {result.pg_version}[/bold]")
    output.print(f"Connection: {escape(result.connection_info)}")
    output.print(f"Version: {result.pg_version} ({result.pg_version_num})")
    output.print(f"Extensions: {len(result.extensions)} installed")
    output.print()
    _print_assessment([(a["level"], a["message"]) for a in result.assessment])
    output.print()
    _print_manual_fixes(result.manual_fixes, result.pg_version)

    if not result.cves:
        if result.branch is not None and result.branch.is_eol:
            output.print(
                f"[yellow]NVD lists no {severity_min}+ severity CVEs for {result.pg_version}, but this branch "
                "is end-of-life (see above), so that does not mean it is safe.[/yellow]"
            )
        else:
            output.print(
                f"[green]NVD lists no {severity_min}+ severity CVEs affecting {result.pg_version}[/green] "
                f"(checked {result.records_checked} PostgreSQL CVE records)."
            )
        return

    output.print(
        f"[bold red]Found {len(result.cves)} applicable CVEs[/bold red] "
        f"(checked {result.records_checked} PostgreSQL CVE records):"
    )
    output.print()
    t = Table()
    t.add_column("CVE ID")
    t.add_column("CVSS", justify="right")
    t.add_column("Severity")
    t.add_column("Fixed in")
    t.add_column("Description", max_width=60)
    for cve in result.cves:
        sev_text = Text(cve.cvss.severity)
        sev_text.stylize(_severity_style(cve.cvss.severity))
        t.add_row(cve.cve_id, str(cve.cvss.score), sev_text, cve.fixed_in or "—", _truncate(cve.description, 80))
    output.print(t)
    output.print("\n[dim]Run `pgremedy remedy <CVE-ID> --pg-version " + result.pg_version + "` for fix steps.[/dim]")


@cli.command(cls=ExamplesCommand, epilog=REMEDY_EXAMPLES)
@click.argument("cve_id", callback=_cve_id)
@click.option("--pg-version", callback=_pg_release,
              help="Your server's PostgreSQL release, e.g. 16.4 (SHOW server_version).")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.pass_context
def remedy(ctx, cve_id: str, pg_version: str | None, fmt: str):
    """Show how to fix a CVE: the release to upgrade to, and documented workarounds."""
    from pgremedy.remediation import generate_remediation
    report = generate_remediation(cve_id, pg_version=pg_version)
    if report is None:
        console.print(f"[bold red]Error:[/bold red] NVD has no record of {cve_id}.")
        ctx.exit(EXIT_ERROR)

    if fmt == "json":
        click.echo(json.dumps(asdict(report), indent=2, default=str))
    else:
        _print_remediation(report)


@cli.command(cls=ExamplesCommand, epilog=WATCH_EXAMPLES)
@click.option("--versions", required=True, help="PG major versions to watch (comma-separated, e.g. 16,17)")
@click.option("--interval", default=3600, type=int, help="Poll interval in seconds.")
@click.option("--state-file", default="~/.pgremedy/watch.json", help="State file path.")
@click.option("--once", is_flag=True, help="Run once and exit (don't loop).")
def watch(versions: str, interval: int, state_file: str, once: bool):
    """Monitor for new PostgreSQL CVEs and releases."""
    from pgremedy.watcher import run_watch
    version_list = [v.strip() for v in versions.split(",") if v.strip()]
    run_watch(version_list, interval=interval, state_file=state_file, once=once)


if __name__ == "__main__":
    cli()
