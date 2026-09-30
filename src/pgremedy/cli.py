"""pgremedy CLI — PostgreSQL CVE detection, remediation, and monitoring."""

from __future__ import annotations

import json
import sys

import click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from pgremedy.apis import crunchy, nvd, redhat
from pgremedy.models import (
    CVEReport,
    CVSSInfo,
    CrunchyInfo,
    ErrataEntry,
    RedHatInfo,
    RedHatPackageState,
    RedHatPatch,
)

console = Console(stderr=True)
output = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "IMPORTANT": "red",
    "MEDIUM": "yellow",
    "MODERATE": "yellow",
    "LOW": "green",
    "UNKNOWN": "dim",
}


def _severity_style(sev: str) -> str:
    return SEVERITY_COLORS.get(sev.upper(), "dim")


def _build_report(cve_id: str, forced_type: str | None = None) -> CVEReport:
    console.log(f"Looking up {cve_id}...")
    nvd_data = nvd.fetch_cve(cve_id)
    nvd.rate_limit_pause()

    cve_type = forced_type or nvd.detect_type(nvd_data)
    console.log(f"CVE type: {cve_type}")

    report = CVEReport(cve_id=cve_id, cve_type=cve_type)

    if nvd_data:
        for d in nvd_data.get("descriptions", []):
            if d.get("lang") == "en":
                report.description = d["value"]
                break
        cvss_raw = nvd.extract_cvss(nvd_data)
        report.cvss = CVSSInfo(**cvss_raw)
        report.affected_versions = nvd.extract_affected_versions(nvd_data, cve_type)
        report.references = [r.get("url", "") for r in nvd_data.get("references", [])[:5]]

    rh = redhat.fetch_cve(cve_id)
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

    errata_raw = redhat.fetch_errata(cve_id)
    report.errata = [
        ErrataEntry(
            id=e.get("RHSA", e.get("id", "Unknown")),
            synopsis=e.get("synopsis", "N/A"),
            severity=e.get("severity", "N/A"),
            released_on=e.get("released_on", "N/A"),
        )
        for e in errata_raw[:5]
    ]

    crunchy_releases = crunchy.fetch_releases()
    cr = crunchy.find_cve_in_releases(cve_id, crunchy_releases)
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
        output.print(report.description)
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
    if report.redhat:
        rh = report.redhat
        output.print(f"  Severity: {rh.severity}")
        output.print(f"  Fix State: {rh.fix_state}")
        if rh.upstream_fix:
            output.print(f"  Upstream Fix: {rh.upstream_fix}")
        if rh.bugzilla_url:
            output.print(f"  Bugzilla: {rh.bugzilla_url}")
        if rh.patches:
            output.print("  Patched Packages:")
            for p in rh.patches:
                output.print(f"    {p.package} via {p.advisory}")
        if rh.package_states:
            output.print("  Package State:")
            for ps in rh.package_states:
                output.print(f"    {ps.package_name} ({ps.product_name}): {ps.fix_state}")
    else:
        output.print("  [dim]No Red Hat data available[/dim]")
    output.print()

    if report.errata:
        output.print("[bold]Red Hat Errata[/bold]")
        for e in report.errata:
            output.print(f"  {e.id}: {e.synopsis} ({e.severity}, {e.released_on})")
        output.print()

    output.print("[bold]Crunchy Data Status[/bold]")
    if report.crunchy:
        cr = report.crunchy
        output.print(f"  PGO Release: {cr.release_tag} ({cr.release_name})")
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


def _report_to_dict(report: CVEReport) -> dict:
    from dataclasses import asdict
    return asdict(report)


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
  pgremedy audit 17
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


MAIN_HELP = """
pgremedy — PostgreSQL CVE detection, remediation, and monitoring.

\b
For usage examples on any command, run:
  pgremedy <command> --help
  pgremedy scan --help
  pgremedy remedy --help
"""


@click.group(help=MAIN_HELP)
@click.version_option(package_name="pgremedy")
def cli():
    pass


@cli.command(cls=ExamplesCommand, epilog=LOOKUP_EXAMPLES)
@click.argument("cve_id")
@click.option("--type", "forced_type", type=click.Choice(["postgresql", "golang", "base-image"]), help="Force CVE type.")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def lookup(cve_id: str, forced_type: str | None, fmt: str):
    """Look up a specific CVE ID."""
    report = _build_report(cve_id, forced_type)
    if fmt == "json":
        click.echo(json.dumps(_report_to_dict(report), indent=2, default=str))
    else:
        _print_report(report)


@cli.command(cls=ExamplesCommand, epilog=AUDIT_EXAMPLES)
@click.argument("pg_version")
@click.option("--severity", help="Filter: critical,high,medium,low (comma-separated)")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def audit(pg_version: str, severity: str | None, fmt: str):
    """Audit a PostgreSQL version for known CVEs."""
    major = pg_version.split(".")[0]
    console.log(f"Auditing PostgreSQL {pg_version} (major {major})...")

    cves = nvd.search_by_keyword(f"postgresql {major}", results_per_page=50)
    nvd.rate_limit_pause()

    severity_filter = [s.strip().upper() for s in severity.split(",")] if severity else None
    results = []
    for cve_data in cves:
        cvss = nvd.extract_cvss(cve_data)
        sev = (cvss.get("severity") or "UNKNOWN").upper()
        if severity_filter and sev not in severity_filter:
            continue
        desc = ""
        for d in cve_data.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d["value"][:120]
                break
        results.append({
            "cve_id": cve_data.get("id", ""),
            "score": cvss["score"],
            "severity": sev,
            "vector": cvss["vector"],
            "affected": nvd.extract_affected_versions(cve_data),
            "description": desc,
        })

    results.sort(key=lambda x: x.get("score") or 0, reverse=True)

    if fmt == "json":
        click.echo(json.dumps({"pg_version": pg_version, "count": len(results), "results": results}, indent=2))
        return

    output.print()
    output.rule(f"[bold]PostgreSQL {pg_version} — CVE Audit[/bold]")
    output.print(f"Found [bold]{len(results)}[/bold] CVEs matching PostgreSQL {major}.x")
    output.print()

    t = Table()
    t.add_column("CVE ID")
    t.add_column("CVSS", justify="right")
    t.add_column("Severity")
    t.add_column("Vector")
    t.add_column("Description", max_width=60)
    for r in results[:25]:
        sev_text = Text(r["severity"])
        sev_text.stylize(_severity_style(r["severity"]))
        t.add_row(r["cve_id"], str(r["score"]), sev_text, r["vector"], r["description"] + "...")
    output.print(t)

    if len(results) > 25:
        output.print(f"\n[dim]... and {len(results) - 25} more. Use --severity to filter.[/dim]")
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
    output.rule(f"[bold]Package Audit: {package}[/bold]")
    output.print(f"Found [bold]{len(cves)}[/bold] CVEs from Red Hat (last {days_ago} days)")
    if severity:
        output.print(f"Filtered by severity: {severity}")
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
        from dataclasses import asdict
        click.echo(json.dumps(asdict(result), indent=2, default=str))
        return

    output.print()
    output.rule(f"[bold]Scan: PostgreSQL {result.pg_version}[/bold]")
    output.print(f"Connection: {result.connection_info}")
    output.print(f"Version: {result.pg_version} ({result.pg_version_num})")
    output.print(f"Extensions: {len(result.extensions)} installed")
    output.print()

    if not result.cves:
        output.print("[green]No known CVEs found for this version.[/green]")
        return

    output.print(f"[bold red]Found {len(result.cves)} applicable CVEs:[/bold red]")
    output.print()
    t = Table()
    t.add_column("CVE ID")
    t.add_column("CVSS", justify="right")
    t.add_column("Severity")
    t.add_column("Description", max_width=60)
    for cve in result.cves:
        sev_text = Text(cve.cvss.severity)
        sev_text.stylize(_severity_style(cve.cvss.severity))
        t.add_row(cve.cve_id, str(cve.cvss.score), sev_text, cve.description[:80] + "...")
    output.print(t)
    output.print("\n[dim]Run `pgremedy remedy <CVE-ID> --pg-version " + result.pg_version + "` for fix steps.[/dim]")


@cli.command(cls=ExamplesCommand, epilog=REMEDY_EXAMPLES)
@click.argument("cve_id")
@click.option("--pg-version", help="Your current PostgreSQL version.")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def remedy(cve_id: str, pg_version: str | None, fmt: str):
    """Generate remediation steps for a CVE."""
    from pgremedy.remediation import generate_remediation
    result = generate_remediation(cve_id, pg_version=pg_version)

    if fmt == "json":
        click.echo(json.dumps(result, indent=2, default=str))
        return

    output.print()
    output.rule(f"[bold]Remediation: {cve_id}[/bold]")
    output.print()

    if result.get("error"):
        output.print(f"[red]{result['error']}[/red]")
        return

    output.print(f"[bold]Description:[/bold] {result.get('description', 'N/A')}")
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
            output.print(f"  {i}. {m}")
        output.print()

    rh = result.get("redhat_status")
    if rh:
        output.print("[bold]Red Hat Patch Status[/bold]")
        output.print(f"  Fix state: {rh.get('fix_state', 'Unknown')}")
        if rh.get("upstream_fix"):
            output.print(f"  Upstream fix: {rh['upstream_fix']}")
        if rh.get("patches"):
            output.print("  Patched packages:")
            for p in rh["patches"]:
                output.print(f"    {p}")
        output.print()

    cr = result.get("crunchy_status")
    if cr:
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
    """Monitor for new PostgreSQL CVEs."""
    from pgremedy.watcher import run_watch
    version_list = [v.strip() for v in versions.split(",")]
    run_watch(version_list, interval=interval, state_file=state_file, once=once)


if __name__ == "__main__":
    cli()
