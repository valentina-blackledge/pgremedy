# pgremedy

PostgreSQL CVE detection, remediation, and monitoring.

pgremedy queries postgresql.org, NVD, Red Hat Security, and Crunchy Data to find vulnerabilities affecting your PostgreSQL installations and generate actionable fix steps.

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

# Audit a PostgreSQL release, or a whole branch
pgremedy audit 16.2
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

Every command except `watch` supports `--format json` for machine-readable output.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | The check ran. Read the output for findings. |
| 2 | The check did **not** run: a data source was unreachable or rate limited, the CVE doesn't exist, the database refused the connection, or the command line was invalid. |

pgremedy never reports a clean result for a check it couldn't complete. If NVD or postgresql.org can't be reached, `scan`, `audit` and `watch` stop with an error instead of saying "no CVEs found".

## NVD API key

Without a key, NVD allows 5 requests per 30 seconds, so pgremedy waits 6 seconds between NVD requests and retries when rate limited. [Request a free key](https://nvd.nist.gov/developers/request-an-api-key) and set it to raise the limit tenfold:

```bash
export NVD_API_KEY=your-key
```

## Commands

### `lookup <CVE-ID>`
Full CVE details from NVD, Red Hat, and Crunchy Data. Auto-detects whether the CVE affects PostgreSQL, Go, or a base image package. Use `--type` to override detection.

### `audit <PG-VERSION>`
With a release (`16.2`), lists the CVEs that affect that exact release. With a branch (`16`, or `9.6` for pre-10 versions), lists every CVE that affected any release in it. Each result shows the release in that branch that fixes it, sorted by CVSS score. The output starts with the branch's status from postgresql.org: latest minor release, and whether it is end-of-life or close to it. Use `--severity critical,high` to filter.

### `audit-package <PACKAGE>`
Searches Red Hat Security API for recent CVEs on a RHEL package. Useful for checking Go, OpenSSL, glibc, and other dependencies in container images.

### `scan <CONNECTION-STRING>`
Connects to a live PostgreSQL instance and reads its exact version (and lists installed extensions). It then:

1. Checks the version against postgresql.org's release list. Is it the latest minor release, how many releases behind is it, and is the branch end-of-life? Minor releases are cumulative, so this is the most reliable exposure check. It's also the only one that works for end-of-life branches, because NVD has no affected-version data for them.
2. Matches the version against every PostgreSQL server CVE in NVD and lists the ones that apply, with the fixing release.

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
Monitors the given branches (`16,17`). The first run records a baseline of the CVEs already known for those branches without alerting. Later runs report:

- **New CVEs:** NVD records added or changed since the last check that affect a watched branch.
- **New minor releases:** these carry the security fixes, often before NVD has attached affected versions to the CVEs.
- **End-of-life:** a watched branch has reached end-of-life, or is within 90 days of it.

State lives in `~/.pgremedy/watch.json`. A failed check leaves the state untouched, so nothing is skipped. Designed for cron or launchd.

## Data Sources

- [postgresql.org versions.json](https://www.postgresql.org/versions.json) -- latest minor release and end-of-life date per branch
- [NVD (National Vulnerability Database)](https://nvd.nist.gov/) -- CVSS scores, affected versions, CPE data. pgremedy queries by product (`cpe:2.3:a:postgresql:postgresql`) and reads every page of results.
- [Red Hat Security API](https://access.redhat.com/hydra/rest/securitydata/) -- RHEL patch status and advisories
- [Crunchy Data PGO Releases](https://github.com/CrunchyData/postgres-operator/releases) -- container image advisory info

No local CVE database -- all data is fetched live from these APIs on every run.

## Development

```bash
uv run pytest
```

The tests use records copied from the live APIs (see `tests/fixtures/README.md`) and never touch the network.

## License

MIT
