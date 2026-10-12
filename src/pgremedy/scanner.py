"""Live PostgreSQL instance scanner."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import psycopg
from psycopg import conninfo as pg_conninfo
from rich.console import Console

from pgremedy import branches
from pgremedy.apis import nvd, postgresql_org
from pgremedy.errors import ConnectionFailed
from pgremedy.models import CVEReport, CVSSInfo, ScanResult

console = Console(stderr=True)

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
SECRET_KEYS = ("password", "sslpassword")
DEFAULT_CONNECT_TIMEOUT = 10   # seconds; libpq waits indefinitely by default

_QUOTED = re.compile(r'"([^"]*)"')
_UNKNOWN_OPTION = re.compile(r'^invalid connection option "[^"]*"$')


@dataclass
class ServerInfo:
    server_version: str
    version_num: int
    extensions: list[dict]
    endpoint: str     # user@host:port/dbname, never the password


# ── Keeping passwords out of output ──────────────────────────────────────────

def _libpq_keywords() -> set[str]:
    return {opt.keyword.decode() for opt in psycopg.pq.Conninfo.get_defaults()}


def redact_parse_error(message: str) -> str:
    """Hide what libpq quotes from a connection string it couldn't parse.

    Parse errors quote the piece libpq choked on, which can be the password
    ('invalid percent-encoded token: "<password>"') or the whole URL. Only
    option names and single characters (like "=") are kept.
    """
    message = " ".join(message.split())
    if _UNKNOWN_OPTION.match(message):
        return message        # quotes the option name typed before "=", never a value
    keywords = _libpq_keywords()

    def keep_or_hide(m: re.Match) -> str:
        token = m.group(1)
        return m.group(0) if len(token) <= 1 or token in keywords else '"***"'

    return _QUOTED.sub(keep_or_hide, message)


def redact_secrets(message: str, secrets: list[str]) -> str:
    message = " ".join(message.split())
    for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
        message = message.replace(secret, "***")
    return message


def parse_conninfo(conninfo: str) -> dict[str, str]:
    try:
        return pg_conninfo.conninfo_to_dict(conninfo)
    except psycopg.Error as exc:
        raise ConnectionFailed(
            f"the connection string couldn't be parsed: {redact_parse_error(str(exc))}"
        ) from None


def _secrets(conninfo: str, params: dict[str, str], password: str | None) -> list[str]:
    secrets = [params[key] for key in SECRET_KEYS if params.get(key)]
    if password:
        secrets.append(password)
    try:
        raw = urlsplit(conninfo).password      # as typed, still percent-encoded
    except ValueError:
        raw = None
    if raw:
        secrets.append(raw)
    return secrets


def describe_endpoint(info) -> str:
    return f"{info.user}@{info.host}:{info.port}/{info.dbname}"


# ── Scanning ─────────────────────────────────────────────────────────────────

def read_server(conninfo: str, password: str | None = None) -> ServerInfo:
    """Version and installed extensions. Raises ConnectionFailed with a password-free reason."""
    params = parse_conninfo(conninfo)
    secrets = _secrets(conninfo, params, password)
    extra: dict[str, object] = {}
    if password:
        extra["password"] = password
    if "connect_timeout" not in params:
        extra["connect_timeout"] = DEFAULT_CONNECT_TIMEOUT

    try:
        with psycopg.connect(conninfo, **extra) as conn:
            endpoint = describe_endpoint(conn.info)
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
    except psycopg.Error as exc:
        raise ConnectionFailed(redact_secrets(str(exc), secrets)) from None
    return ServerInfo(server_version, version_num, extensions, endpoint)


def scan_instance(conninfo: str, severity_min: str = "medium", password: str | None = None) -> ScanResult:
    min_rank = SEVERITY_ORDER.get(severity_min.upper(), 0)

    if password is None and parse_conninfo(conninfo).get("password"):
        console.log(
            "[yellow]Tip:[/yellow] a password in the connection string ends up in your shell history "
            "and the process list. Use -W to be prompted for it, or a ~/.pgpass or service file."
        )
    console.log("Connecting to PostgreSQL...")
    server = read_server(conninfo, password=password)
    pg_version = server.server_version.split(" ")[0]

    console.log(f"PostgreSQL {pg_version} ({server.version_num}), {len(server.extensions)} extensions")
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
        pg_version_num=server.version_num,
        extensions=server.extensions,
        cves=applicable,
        connection_info=server.endpoint,
        branch=status,
        assessment=[{"level": level, "message": msg} for level, msg in branches.assess(status)],
        records_checked=len(cves_raw),
    )
