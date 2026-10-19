"""Live PostgreSQL instance scanner."""

from __future__ import annotations

import psycopg
from rich.console import Console

from pgremedy import branches
from pgremedy.apis import nvd, postgresql_org
from pgremedy.models import CVEReport, CVSSInfo, ScanResult

console = Console(stderr=True)

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def read_server(conninfo: str) -> tuple[str, int, list[dict]]:
    """server_version, server_version_num and installed extensions."""
    with psycopg.connect(conninfo) as conn:
        with conn.cursor() as cur:
            cur.execute("SHOW server_version")
            server_version = cur.fetchone()[0]

            cur.execute("SHOW server_version_num")
            version_num = int(cur.fetchone()[0])

            cur.execute("""
                SELECT name, default_version, installed_version, comment
                FROM pg_available_extensions
                WHERE installed_version IS NOT NULL
                ORDER BY name
            """)
            extensions = [
                {"name": row[0], "default_version": row[1], "installed_version": row[2], "comment": row[3]}
                for row in cur.fetchall()
            ]
    return server_version, version_num, extensions


def scan_instance(conninfo: str, severity_min: str = "medium") -> ScanResult:
    min_rank = SEVERITY_ORDER.get(severity_min.upper(), 0)

    console.log("Connecting to PostgreSQL...")
    server_version, version_num, extensions = read_server(conninfo)
    pg_version = server_version.split(" ")[0]

    safe_conninfo = conninfo
    if "@" in conninfo:
        parts = conninfo.split("@")
        safe_conninfo = "***@" + parts[-1]

    console.log(f"PostgreSQL {pg_version} ({version_num}), {len(extensions)} extensions")
    console.log("Checking release status on postgresql.org...")
    status = branches.branch_status(pg_version, postgresql_org.fetch_versions())

    console.log("Fetching PostgreSQL CVEs from NVD...")
    cves_raw = nvd.fetch_product_cves()

    applicable: list[CVEReport] = []
    for cve_data in cves_raw:
        match = nvd.check_version(cve_data, pg_version)
        if not match.affected:
            continue
        cvss_raw = nvd.extract_cvss(cve_data)
        sev = (cvss_raw.get("severity") or "UNKNOWN").upper()
        if SEVERITY_ORDER.get(sev, 0) < min_rank:
            continue
        applicable.append(CVEReport(
            cve_id=cve_data.get("id", ""),
            description=nvd.english_description(cve_data),
            cvss=CVSSInfo(**cvss_raw),
            affected_versions=nvd.extract_affected_versions(cve_data),
            fixed_in=match.fixed_in,
        ))

    applicable.sort(key=lambda c: c.cvss.score or 0, reverse=True)

    return ScanResult(
        pg_version=pg_version,
        pg_version_num=version_num,
        extensions=extensions,
        cves=applicable,
        connection_info=safe_conninfo,
        branch=status,
        assessment=[{"level": level, "message": msg} for level, msg in branches.assess(status)],
        records_checked=len(cves_raw),
    )
