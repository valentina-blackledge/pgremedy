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

from pgremedy import branches, pgversion
from pgremedy.apis import crunchy, nvd, postgresql_org, redhat
from pgremedy.errors import SourceUnavailable
from pgremedy.models import (
    CVEReport,
    CVSSInfo,
    CrunchyInfo,
    RedHatInfo,
    RedHatPackageState,
    RedHatPatch,
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
        report.redhat = RedHatInfo(
            severity=rh.get("threat_severity", "Unknown"),
            fix_state=rh.get("fix_state", "Unknown"),
            upstream_fix=rh.get("upstream_fix"),
            bugzilla_url=rh.get("bugzilla", {}).get("url"),
            patches=[
                RedHatPatch(package=ar.get("package", "N/A"), advisory=ar.get("advisory", "N/A"))
                for ar in rh.get("affected_release", [])[:8]
            ],
            package_states=[
                RedHatPackageState(
                    package_name=ps.get("package_name", "N/A"),
                    product_name=ps.get("product_name", ""),
                    fix_state=ps.get("fix_state", "N/A"),
                )
                for ps in rh.get("package_state", [])[:8]
            ],
        )

    try:
        cr = crunchy.find_cve_in_releases(cve_id, crunchy.fetch_releases())
    except SourceUnavailable as exc:
        report.source_errors["crunchy"] = exc.reason
        cr = None
    if cr:
        report.crunchy = CrunchyInfo(**cr)

    return report


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

    output.print("[bold]Red Hat Status[/bold]")
    if "redhat" in report.source_errors:
        output.print(f"  [yellow]Unavailable: couldn't reach Red Hat ({escape(report.source_errors['redhat'])})[/yellow]")
    elif report.redhat:
        rh = report.redhat
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

    output.print("[bold]Crunchy Data Status[/bold]")
    if "crunchy" in report.source_errors:
        output.print(f"  [yellow]Unavailable: couldn't reach GitHub ({escape(report.source_errors['crunchy'])})[/yellow]")
    elif report.crunchy:
        cr = report.crunchy
        output.print(f"  PGO Release: {cr.release_tag} ({escape(cr.release_name or '')})")
        output.print(f"  Published: {cr.published}")
        if cr.prerelease:
            output.print("  [yellow]Status: Pre-release (not yet GA)[/yellow]")
        if cr.url:
            output.print(f"  Details: {cr.url}")
    else:
        output.print("  [dim]No Crunchy advisory found[/dim]")
    output.print()

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
  pgremedy scan "postgresql://user:pass@localhost:5432/mydb"
  pgremedy scan "host=db.example.com port=5432 dbname=prod user=admin"
  pgremedy scan "service=my_pg_service" --severity-min high
"""

REMEDY_EXAMPLES = """
\b
Examples:
  pgremedy remedy CVE-2024-10978
  pgremedy remedy CVE-2024-10978 --pg-version 16.2
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
        except psycopg.Error as exc:
            reason = " ".join(str(exc).split())
            console.print(f"[bold red]Error:[/bold red] couldn't connect to PostgreSQL: {escape(reason)}")
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
def scan(conninfo: str, severity_min: str, fmt: str):
    """Scan a live PostgreSQL instance for CVEs."""
    from pgremedy.scanner import scan_instance
    result = scan_instance(conninfo, severity_min=severity_min)

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
@click.option("--pg-version", help="Your current PostgreSQL version.")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.pass_context
def remedy(ctx, cve_id: str, pg_version: str | None, fmt: str):
    """Generate remediation steps for a CVE."""
    from pgremedy.remediation import generate_remediation
    result = generate_remediation(cve_id, pg_version=pg_version)

    if fmt == "json":
        click.echo(json.dumps(result, indent=2, default=str))
        if result.get("error"):
            ctx.exit(EXIT_ERROR)
        return

    output.print()
    output.rule(f"[bold]Remediation: {cve_id}[/bold]")
    output.print()

    if result.get("error"):
        output.print(f"[red]{escape(result['error'])}[/red]")
        ctx.exit(EXIT_ERROR)

    output.print(f"[bold]Description:[/bold] {escape(result.get('description', 'N/A'))}")
    sev = result.get("severity", "UNKNOWN")
    style = _severity_style(sev)
    output.print(f"[bold]Severity:[/bold] [{style}]{sev}[/{style}]")
    output.print()

    upgrade = result.get("upgrade_path")
    if upgrade:
        output.print("[bold]Upgrade Path[/bold]")
        output.print(f"  Current version: {upgrade.get('current', 'unknown')}")
        output.print(f"  Fix version: {upgrade.get('fix_version', 'unknown')}")
        output.print(f"  Action: {upgrade.get('action', 'Upgrade PostgreSQL')}")
        output.print()

    mitigations = result.get("mitigations", [])
    if mitigations:
        output.print("[bold]Mitigations[/bold]")
        for i, m in enumerate(mitigations, 1):
            output.print(f"  {i}. {escape(m)}")
        output.print()

    errors = result.get("source_errors", {})
    rh = result.get("redhat_status")
    if "redhat" in errors:
        output.print("[bold]Red Hat Patch Status[/bold]")
        output.print(f"  [yellow]Unavailable: couldn't reach Red Hat ({escape(errors['redhat'])})[/yellow]")
        output.print()
    elif rh:
        output.print("[bold]Red Hat Patch Status[/bold]")
        output.print(f"  Fix state: {rh.get('fix_state', 'Unknown')}")
        if rh.get("upstream_fix"):
            output.print(f"  Upstream fix: {escape(rh['upstream_fix'])}")
        if rh.get("patches"):
            output.print("  Patched packages:")
            for p in rh["patches"]:
                output.print(f"    {escape(p)}")
        output.print()

    cr = result.get("crunchy_status")
    if "crunchy" in errors:
        output.print("[bold]Crunchy Data Status[/bold]")
        output.print(f"  [yellow]Unavailable: couldn't reach GitHub ({escape(errors['crunchy'])})[/yellow]")
        output.print()
    elif cr:
        output.print("[bold]Crunchy Data Status[/bold]")
        output.print(f"  Release: {cr.get('release_tag', 'N/A')}")
        output.print(f"  Published: {cr.get('published', 'N/A')}")
        output.print()


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
