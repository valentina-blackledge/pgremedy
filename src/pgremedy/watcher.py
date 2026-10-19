"""CVE monitoring / watch mode.

The first run records a baseline (every CVE already known for the watched
branches) without alerting. Later runs ask NVD only for PostgreSQL records
added or changed since the previous check, and report CVEs that affect a
watched branch and haven't been reported before. Each run also reports new
minor releases and upcoming end-of-life dates from postgresql.org: every
PostgreSQL security fix ships in a minor release, often before NVD has
attached affected versions to the CVE.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import click
from rich.console import Console
from rich.markup import escape

from pgremedy import branches, pgversion
from pgremedy.apis import nvd, postgresql_org
from pgremedy.errors import SourceUnavailable

console = Console(stderr=True)
output = Console()

STATE_VERSION = 2
WINDOW_OVERLAP = timedelta(hours=1)   # re-read a little of the last window; seen-state removes repeats

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
}


def _timestamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_timestamp(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _load_state(state_file: str) -> dict:
    path = Path(state_file).expanduser()
    if not path.exists():
        return {}
    try:
        state = json.loads(path.read_text())
    except (OSError, ValueError):
        console.log(f"[yellow]State file {escape(str(path))} is unreadable; recording a new baseline.[/yellow]")
        return {}
    return state if isinstance(state, dict) else {}


def _save_state(state_file: str, state: dict) -> None:
    """Write atomically so an interrupted run can't leave a corrupt state file."""
    path = Path(state_file).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(state, f, indent=2)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _normalize_majors(versions: list[str]) -> list[str]:
    majors = []
    for v in versions:
        if not pgversion.is_branch(v):
            raise click.BadParameter(
                f"'{v}' is not a major version. Use branch numbers like 16,17 (or 9.6 for pre-10 releases).",
                param_hint="'--versions'",
            )
        majors.append(pgversion.major_of(v))
    return sorted(set(majors), key=pgversion.parse)


def run_watch(
    versions: list[str],
    interval: int = 3600,
    state_file: str = "~/.pgremedy/watch.json",
    once: bool = False,
) -> None:
    majors = _normalize_majors(versions)
    console.log(f"Watching PostgreSQL versions: {', '.join(majors)}")
    console.log(f"Poll interval: {interval}s | State: {state_file}")
    if once:
        console.log("Running once (--once)")

    while True:
        try:
            check_once(majors, state_file)
        except SourceUnavailable as exc:
            if once:
                raise
            console.log(
                f"[red]Check failed:[/red] couldn't get data from {escape(exc.source)} "
                f"({escape(exc.reason)}). State not updated; retrying in {interval}s."
            )
        if once:
            break
        console.log(f"Next check in {interval}s...")
        time.sleep(interval)


def check_once(majors: list[str], state_file: str, now: datetime | None = None) -> None:
    """One check. Raises SourceUnavailable without touching the state file."""
    now = now or datetime.now(timezone.utc)
    state = _load_state(state_file)
    versions = postgresql_org.fetch_versions()
    statuses = {m: branches.branch_status(m, versions, today=now.date()) for m in majors}

    needs_baseline = (
        state.get("version") != STATE_VERSION
        or "last_check" not in state
        or sorted(state.get("majors", []), key=pgversion.parse) != majors
    )
    if needs_baseline:
        _record_baseline(majors, statuses, state_file, now, had_state=bool(state))
        return

    since = _parse_timestamp(state["last_check"]) - WINDOW_OVERLAP
    console.log(f"Checking NVD for PostgreSQL records changed since {state['last_check']}...")
    changed = nvd.fetch_product_cves_modified(since, now)

    seen = set(state.get("seen", []))
    new_cves = []
    for cve_data in changed:
        cve_id = cve_data.get("id", "")
        if not cve_id or cve_id in seen:
            continue
        hits = {m: nvd.check_branch(cve_data, m) for m in majors}
        hits = {m: a for m, a in hits.items() if a.affected}
        if not hits:
            continue
        cvss = nvd.extract_cvss(cve_data)
        new_cves.append({
            "cve_id": cve_id,
            "score": cvss.get("score"),
            "severity": cvss.get("severity", "UNKNOWN"),
            "description": nvd.english_description(cve_data),
            "branches": {m: a.fixed_in for m, a in hits.items()},
        })
        seen.add(cve_id)

    previous_latest = state.get("latest", {})
    new_releases = [
        (m, previous_latest[m], s.latest)
        for m, s in statuses.items()
        if s.latest and previous_latest.get(m) and previous_latest[m] != s.latest
    ]
    eol_warned = set(state.get("eol_warned", []))
    eol_notices = []
    for m, s in statuses.items():
        if m in eol_warned:
            continue
        if s.is_eol or (s.days_to_eol is not None and s.days_to_eol <= branches.EOL_WARNING_DAYS):
            eol_notices.append((m, s))
            eol_warned.add(m)

    state.update({
        "seen": sorted(seen),
        "latest": {m: s.latest for m, s in statuses.items()},
        "eol_warned": sorted(eol_warned),
        "last_check": _timestamp(now),
    })
    _save_state(state_file, state)

    if not (new_cves or new_releases or eol_notices):
        console.log("No new CVEs, releases or end-of-life notices.")
        return

    output.print(f"\n[bold]pgremedy watch report[/bold] ({state['last_check']})\n")
    for m, old, new in new_releases:
        output.print(
            f"  [bold]New release:[/bold] PostgreSQL {new} (was {old}). Minor releases carry the "
            f"security fixes for {m}.x, so check the release notes and plan the update."
        )
    for m, s in eol_notices:
        if s.is_eol:
            output.print(f"  [bold red]End-of-life:[/bold red] PostgreSQL {m} stopped receiving fixes on {s.eol_date}.")
        else:
            output.print(f"  [yellow]End-of-life soon:[/yellow] PostgreSQL {m} on {s.eol_date} (in {s.days_to_eol} days).")
    if (new_releases or eol_notices) and new_cves:
        output.print()

    new_cves.sort(key=lambda c: c.get("score") or 0, reverse=True)
    if new_cves:
        output.print(f"  [bold]{len(new_cves)} new CVE(s)[/bold]")
    for cve in new_cves:
        sev = cve["severity"]
        style = SEVERITY_COLORS.get(sev.upper(), "dim")
        where = ", ".join(
            f"{m} (fixed in {fix})" if fix else f"{m} (no fix listed)" for m, fix in cve["branches"].items()
        )
        output.print(
            f"  [{style}]{sev}[/{style}] {cve['cve_id']} (CVSS {cve['score']}) affects PG {where}: "
            f"{escape(cve['description'][:160])}{'...' if len(cve['description']) > 160 else ''}"
        )
    output.print()


def _record_baseline(majors, statuses, state_file, now, had_state: bool) -> None:
    if had_state:
        console.log("State file is from an older pgremedy or watches different versions; recording a new baseline.")
    console.log("Fetching all PostgreSQL CVEs from NVD for the baseline...")
    cves = nvd.fetch_product_cves()
    seen = sorted(
        c["id"] for c in cves
        if c.get("id") and any(nvd.check_branch(c, m).affected for m in majors)
    )
    eol_warned = [
        m for m, s in statuses.items()
        if s.is_eol or (s.days_to_eol is not None and s.days_to_eol <= branches.EOL_WARNING_DAYS)
    ]
    _save_state(state_file, {
        "version": STATE_VERSION,
        "majors": majors,
        "seen": seen,
        "latest": {m: s.latest for m, s in statuses.items()},
        "eol_warned": eol_warned,
        "last_check": _timestamp(now),
    })
    output.print(
        f"Baseline recorded: {len(seen)} known CVEs affect PostgreSQL {', '.join(majors)}. "
        "Later runs report only new CVEs and releases."
    )
    for m in majors:
        for level, message in branches.assess(statuses[m]):
            if level in ("critical", "warning"):
                output.print(f"  [yellow]{escape(message)}[/yellow]")
