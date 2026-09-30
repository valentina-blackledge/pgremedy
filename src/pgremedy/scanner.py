"""Live PostgreSQL instance scanner."""

from __future__ import annotations

import psycopg
from rich.console import Console

from pgremedy.apis import nvd
from pgremedy.models import CVEReport, CVSSInfo, ScanResult

console = Console(stderr=True)

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def scan_instance(conninfo: str, severity_min: str = "medium") -> ScanResult:
    min_rank = SEVERITY_ORDER.get(severity_min.upper(), 0)

    console.log(f"Connecting to PostgreSQL...")
    with psycopg.connect(conninfo) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT version()")
            full_version = cur.fetchone()[0]

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

    pg_version = server_version.split(" ")[0]
    major = pg_version.split(".")[0]

    safe_conninfo = conninfo
    if "@" in conninfo:
        parts = conninfo.split("@")
        safe_conninfo = "***@" + parts[-1]

    console.log(f"PostgreSQL {pg_version} ({version_num}), {len(extensions)} extensions")
    console.log(f"Searching NVD for CVEs affecting PostgreSQL {major}...")

    cves_raw = nvd.search_by_keyword(f"postgresql {major}", results_per_page=50)
    nvd.rate_limit_pause()

    applicable: list[CVEReport] = []
    for cve_data in cves_raw:
        if not nvd.is_version_affected(pg_version, cve_data):
            continue
        cvss_raw = nvd.extract_cvss(cve_data)
        sev = (cvss_raw.get("severity") or "UNKNOWN").upper()
        if SEVERITY_ORDER.get(sev, 0) < min_rank:
            continue

        desc = ""
        for d in cve_data.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d["value"]
                break

        applicable.append(CVEReport(
            cve_id=cve_data.get("id", ""),
            description=desc,
            cvss=CVSSInfo(**cvss_raw),
            affected_versions=nvd.extract_affected_versions(cve_data),
        ))

    applicable.sort(key=lambda c: c.cvss.score or 0, reverse=True)

    return ScanResult(
        pg_version=pg_version,
        pg_version_num=version_num,
        extensions=extensions,
        cves=applicable,
        connection_info=safe_conninfo,
    )
