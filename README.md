# pgremedy

PostgreSQL CVE detection, remediation, and monitoring.

pgremedy queries the NVD, Red Hat Security, and Crunchy Data APIs to find vulnerabilities affecting your PostgreSQL installations and generate actionable fix steps.

## Install

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/valentina-blackledge/pgremedy.git
cd pgremedy
uv tool install .
```

This puts `pgremedy` on your PATH so you can run it from anywhere.

## Usage

```bash
# Look up a specific CVE
pgremedy lookup CVE-2024-10978

# Audit a PostgreSQL version for known CVEs
pgremedy audit 17

# Audit a Red Hat package (golang, openssl, glibc, etc.)
pgremedy audit-package golang --severity important --days-ago 180

# Scan a live PostgreSQL instance
pgremedy scan "postgresql://user:pass@host:5432/dbname"

# Generate remediation steps for a CVE
pgremedy remedy CVE-2024-10978 --pg-version 16.2

# Watch for new CVEs (single check)
pgremedy watch --versions 16,17 --once

# Watch continuously (polls every hour)
pgremedy watch --versions 16,17
```

All commands support `--format json` for machine-readable output.

## Commands

### `lookup <CVE-ID>`
Full CVE details from NVD, Red Hat, and Crunchy Data. Auto-detects whether the CVE affects PostgreSQL, Go, or a base image package. Use `--type` to override detection.

### `audit <PG-VERSION>`
Finds all CVEs affecting a specific PostgreSQL major version, sorted by CVSS score. Use `--severity critical,high` to filter.

### `audit-package <PACKAGE>`
Searches Red Hat Security API for recent CVEs on a RHEL package. Useful for checking Go, OpenSSL, glibc, and other dependencies in container images.

### `scan <CONNECTION-STRING>`
Connects to a live PostgreSQL instance, detects the exact version and installed extensions, then cross-references NVD for applicable CVEs.

Accepts any libpq connection string:
- `postgresql://user:pass@host:5432/dbname`
- `host=x port=5432 dbname=y user=z`
- `service=myservice` (from pg_service.conf)

### `remedy <CVE-ID>`
Generates remediation steps for a specific CVE:
- **Upgrade path** -- branch-aware fix version (e.g., for PG 16.2 it finds the 16.x fix, not the 12.x fix)
- **Config mitigations** -- pg_hba.conf changes, GUC settings, privilege hardening
- **Red Hat patch status** -- backport and errata info
- **Crunchy Data status** -- PGO release info

### `watch --versions <MAJORS>`
Monitors NVD for new CVEs. Stores seen-state in `~/.pgremedy/watch.json` to avoid duplicate alerts. Designed for cron or launchd.

## Data Sources

- [NVD (National Vulnerability Database)](https://nvd.nist.gov/) -- CVSS scores, affected versions, CPE data
- [Red Hat Security API](https://access.redhat.com/hydra/rest/securitydata/) -- RHEL patch status, errata, backport info
- [Crunchy Data PGO Releases](https://github.com/CrunchyData/postgres-operator/releases) -- container image advisory info

No local CVE database -- all data is fetched live from these APIs on every run.

## License

MIT
