"""CVE monitoring / watch mode."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from rich.console import Console

from pgremedy.apis import nvd

console = Console(stderr=True)
output = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
}


def _load_state(state_file: str) -> dict:
    path = Path(state_file).expanduser()
    if path.exists():
        return json.loads(path.read_text())
    return {"seen": []}


def _save_state(state_file: str, state: dict) -> None:
    path = Path(state_file).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2))


def run_watch(
    versions: list[str],
    interval: int = 3600,
    state_file: str = "~/.pgremedy/watch.json",
    once: bool = False,
) -> None:
    console.log(f"Watching PostgreSQL versions: {', '.join(versions)}")
    console.log(f"Poll interval: {interval}s | State: {state_file}")
    if once:
        console.log("Running once (--once)")

    while True:
        state = _load_state(state_file)
        seen = set(state.get("seen", []))
        new_cves = []

        for major in versions:
            console.log(f"Checking PostgreSQL {major}...")
            cves = nvd.search_by_keyword(f"postgresql {major}", results_per_page=50)
            nvd.rate_limit_pause()

            for cve_data in cves:
                cve_id = cve_data.get("id", "")
                if not cve_id or cve_id in seen:
                    continue

                cvss = nvd.extract_cvss(cve_data)
                desc = ""
                for d in cve_data.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d["value"][:120]
                        break

                new_cves.append({
                    "cve_id": cve_id,
                    "score": cvss.get("score"),
                    "severity": cvss.get("severity", "UNKNOWN"),
                    "description": desc,
                    "major": major,
                })
                seen.add(cve_id)

        state["seen"] = sorted(seen)
        state["last_check"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        _save_state(state_file, state)

        if new_cves:
            new_cves.sort(key=lambda c: c.get("score") or 0, reverse=True)
            output.print(f"\n[bold]pgremedy: {len(new_cves)} new CVE(s) found[/bold]")
            output.print(f"Checked: {state['last_check']}")
            output.print()
            for cve in new_cves:
                sev = cve["severity"]
                style = SEVERITY_COLORS.get(sev.upper(), "dim")
                output.print(
                    f"  [{style}]{sev}[/{style}] {cve['cve_id']} "
                    f"(CVSS {cve['score']}, PG {cve['major']}): {cve['description']}..."
                )
            output.print()
        else:
            console.log("No new CVEs found.")

        if once:
            break

        console.log(f"Next check in {interval}s...")
        time.sleep(interval)
