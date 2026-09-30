---
name: pgremedy
description: "PostgreSQL CVE detection, remediation, and monitoring. Use for: looking up CVEs, auditing PG versions for vulnerabilities, scanning live instances, generating fix steps, monitoring for new CVEs. Triggers: CVE, vulnerability, postgres security, patch status, RHSA, errata, crunchy advisory, security audit, CVSS, affected version, unpatched, exploit, base image, Go vulnerability, golang CVE, openssl CVE, glibc CVE, UBI package, operator CVE, pgremedy, scan postgres, remedy, remediation, watch CVEs, monitor vulnerabilities."
---

# pgremedy — PostgreSQL CVE Detection, Remediation & Monitoring

## When to Use

- User asks about a PostgreSQL, Go, or base-image CVE
- User wants to audit a PG version for known vulnerabilities
- User wants to scan a live Postgres instance
- User wants remediation/fix steps for a specific CVE
- User wants to monitor for new CVEs
- User mentions pgremedy by name

## Prerequisites

- `uv` installed (for running the tool)
- Internet access (NVD, Red Hat, Crunchy Data APIs)
- For `scan`: network access to the target PostgreSQL instance

## Commands

All commands use this invocation pattern:
```bash
uv run --project <SKILL_DIR> python -m pgremedy <command> [args]
```

### lookup — Look up a specific CVE

```bash
uv run --project <SKILL_DIR> python -m pgremedy lookup <CVE-ID> [--type postgresql|golang|base-image] [--format table|json]
```

Auto-detects CVE type (PostgreSQL, Go, base-image) from NVD CPE data. Use `--type` to force.

**When:** User provides a CVE-ID (e.g., CVE-2024-10978).

### audit — Audit a PostgreSQL version

```bash
uv run --project <SKILL_DIR> python -m pgremedy audit <PG-VERSION> [--severity critical,high] [--format table|json]
```

Searches NVD for CVEs affecting the given major version, sorted by CVSS score.

**When:** User provides a PG version (e.g., 16.4, 14.9).

### audit-package — Audit a Red Hat package

```bash
uv run --project <SKILL_DIR> python -m pgremedy audit-package <PACKAGE> [--severity important] [--days-ago 180] [--format table|json]
```

Searches Red Hat Security API for recent CVEs on a package (golang, openssl, glibc, etc.).

**When:** User asks about CVEs for a specific package.

### scan — Scan a live PostgreSQL instance

```bash
uv run --project <SKILL_DIR> python -m pgremedy scan "<CONNECTION-STRING>" [--severity-min medium] [--format table|json]
```

Connects to a live Postgres instance, detects version and extensions, then cross-references NVD for applicable CVEs.

**Connection string formats:**
- `postgresql://user:pass@host:port/dbname`
- `host=x port=5432 dbname=y user=z`
- `service=myservice` (from pg_service.conf)

**When:** User wants to check a running instance for vulnerabilities.

### remedy — Generate remediation steps

```bash
uv run --project <SKILL_DIR> python -m pgremedy remedy <CVE-ID> [--pg-version 16.2] [--format table|json]
```

For a given CVE, generates:
1. **Upgrade path** — which version fixes it
2. **Config mitigations** — pg_hba.conf changes, GUC settings, workarounds
3. **Red Hat patch status** — backport info
4. **Crunchy Data status** — PGO release info

**When:** User wants to know how to fix a specific CVE.

### watch — Monitor for new CVEs

```bash
uv run --project <SKILL_DIR> python -m pgremedy watch --versions 16,17 [--interval 3600] [--once] [--state-file ~/.pgremedy/watch.json]
```

Polls NVD for new CVEs matching tracked PG versions. Stores seen-state to avoid duplicate alerts. Use `--once` for a single check.

**When:** User wants ongoing monitoring. Suitable for cron jobs.

## Workflow

### Step 1: Determine Intent

| Intent | Command |
|--------|---------|
| Specific CVE details | `lookup <CVE-ID>` |
| Version vulnerability check | `audit <VERSION>` |
| Package CVE search | `audit-package <PACKAGE>` |
| Live instance check | `scan <CONNINFO>` |
| How to fix a CVE | `remedy <CVE-ID>` |
| Ongoing monitoring | `watch --versions X,Y` |

### Step 2: Run the Command

Execute the appropriate command and present results to the user.

### Step 3: Follow Up

- After `audit` or `scan`: Offer to run `lookup` or `remedy` on specific CVEs
- After `lookup`: Offer `remedy` if the user needs fix steps
- After `remedy`: Summarize the action items clearly

## Stopping Points

- After presenting audit/scan results: Ask if user wants details on specific CVEs
- If Critical/High CVE with no patch: Warn and suggest mitigations
- For base image CVEs: Note whether Crunchy has consumed the Red Hat fix

## Troubleshooting

- **NVD rate limited**: The tool waits 6s between requests automatically
- **Red Hat data unavailable**: Supplement with `web_fetch` on `https://access.redhat.com/security/cve/<CVE_ID>`
- **CVE type misdetected**: Use `--type` flag to force correct detection
- **Connection refused on scan**: Verify network access and pg_hba.conf allows the connection
