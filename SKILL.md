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
- Internet access (NVD, Red Hat, Crunchy Data APIs), or an offline bundle (see Offline bundles)
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

For a PostgreSQL server CVE: the affected releases per branch, the first fixed release in each, and the advisory link. If the output says the CVE "affects other products, not the PostgreSQL server" (a driver such as pgjdbc, an add-on, a distro package), say so: upgrading the server doesn't fix it. Red Hat's section lists every fixed package with its RHEL product and advisory. `--type` only overrides the category in JSON.

**When:** User provides a CVE-ID (e.g., CVE-2024-10978).

### audit — Audit a PostgreSQL version

```bash
uv run --project <SKILL_DIR> python -m pgremedy audit <PG-VERSION> [--severity critical,high] [--format table|json]
```

With a release (16.4), lists the CVEs affecting that release. With a branch (16), lists every CVE that affected any 16.x release. Each result includes the fixing release for that branch. Starts with the branch's support status (latest minor, end-of-life). `--severity` takes NVD's scale (critical, high, medium, low); any other value exits 2.

**When:** User provides a PG version (e.g., 16.4, 14.9).

### audit-package — Audit a Red Hat package

```bash
uv run --project <SKILL_DIR> python -m pgremedy audit-package <PACKAGE> [--severity important] [--days-ago 180] [--format table|json]
```

Searches Red Hat Security API for recent CVEs on a package (golang, openssl, glibc, etc.), reading every page of results. `--severity` takes Red Hat's scale (critical, important, moderate, low), not NVD's.

**When:** User asks about CVEs for a specific package.

### scan — Scan a live PostgreSQL instance

```bash
uv run --project <SKILL_DIR> python -m pgremedy scan "<CONNECTION-STRING>" [--severity-min medium] [--format table|json]
```

Connects to a live Postgres instance and reads its version. Checks that version against postgresql.org: is it the latest minor release, and is the branch end-of-life? Then lists the NVD CVEs that apply, with the fixing release.

On 14, 15 and 16 it also checks every database for fixes that need a manual step (CVE-2024-4317). If the output has a "Fixes that need a manual step" section saying the fix is not applied, tell the user even when the version is current: the server is exposed until the listed script is run in each database. "Not checked" databases are unknown, not fixed.

**Connection string formats:**
- `postgresql://user@host:port/dbname`
- `host=x port=5432 dbname=y user=z`
- `service=myservice` (from pg_service.conf)

Never put a password in the connection string, and don't ask the user to paste one into the chat. It would end up in shell history and in this conversation. The password should come from the user's `~/.pgpass` or service file. Alternatively, ask the user to run the command themselves with `-W`, which prompts for it.

**When:** User wants to check a running instance for vulnerabilities.

### remedy — Generate remediation steps

```bash
uv run --project <SKILL_DIR> python -m pgremedy remedy <CVE-ID> [--pg-version 16.2] [--format table|json]
```

With `--pg-version` (a full release like 16.2, not 16): whether that release is affected, when the fix first shipped, and the release to upgrade to (always the latest of its branch). It flags end-of-life branches. Without it: a per-branch table of fixed and latest releases.

Workarounds come only from vendor-documented sources (Red Hat's mitigation text). If none is shown, upgrading is the fix: don't invent configuration workarounds. The output also says when a CVE is about another product (e.g. a driver) or hasn't been analyzed by NVD yet, and links the PostgreSQL advisory.

**When:** User wants to know how to fix a specific CVE.

### watch — Monitor for new CVEs

```bash
uv run --project <SKILL_DIR> python -m pgremedy watch --versions 16,17 [--interval 3600] [--once] [--state-file ~/.pgremedy/watch.json]
```

The first run records a baseline without alerting. Later runs report new CVEs for the tracked branches, new minor releases, and end-of-life notices. Stores seen-state to avoid duplicate alerts. Use `--once` for a single check.

**When:** User wants ongoing monitoring. Suitable for cron jobs.

### compliance — STIG V-283674 and CIS 1.5

```bash
uv run --project <SKILL_DIR> python -m pgremedy compliance "<CONNECTION-STRING>" [--checklist FILE.cklb] [--format table|json]
```

Pass/fail/review for the DISA STIG version rule (V-283674, CAT I) and CIS 1.5 (latest security patches), with evidence. `--checklist` records the STIG result in an existing STIG Viewer checklist (.ckl or .cklb); the original is kept as FILE.bak. Exit code 0 = all passed, 1 = a check failed or needs review, 2 = couldn't run.

Present the verdicts as evidence for an assessor, not as the assessment. The STIG rule is judged on version only; CIS 1.5 also fails when a manual fix (CVE-2024-4317) is missing.

**When:** User mentions STIG, CIS benchmark, compliance, audit evidence, or STIG Viewer checklists.

### Offline bundles

```bash
uv run --project <SKILL_DIR> python -m pgremedy bundle create pg-data.json      # needs internet
uv run --project <SKILL_DIR> python -m pgremedy --data pg-data.json <command> ...  # no network at all
```

For networks without internet access. With `--data` (or PGREMEDY_DATA), every command except watch and audit-package runs from the file. Mention the bundle's age from the output; warn if it's over 30 days old.

**When:** The target network can't reach NVD or postgresql.org (air-gapped, DoD), or the user asks for offline use.

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
| STIG / CIS evidence | `compliance <CONNINFO>` |
| No internet on the target network | `bundle create`, then `--data FILE` |

### Step 2: Run the Command

Execute the appropriate command and present results to the user.

**Check the exit code.** Exit code 2 means the check did not run: a data source was unreachable, the CVE doesn't exist, or the database refused the connection. Report the error. Never present it as "no vulnerabilities found."

If the output says the branch is end-of-life, lead with that. NVD has no affected-version data for end-of-life branches, so an empty CVE list there does not mean the server is safe.

### Step 3: Follow Up

- After `audit` or `scan`: Offer to run `lookup` or `remedy` on specific CVEs
- After `lookup`: Offer `remedy` if the user needs fix steps
- After `remedy`: Summarize the action items clearly

## Stopping Points

- After presenting audit/scan results: Ask if user wants details on specific CVEs
- If Critical/High CVE with no patch: Warn, and pass on only the workarounds `remedy` shows
- For base image CVEs: Note whether Crunchy has consumed the Red Hat fix

## Troubleshooting

- **NVD rate limited**: The tool spaces requests (6s apart, 0.6s with `NVD_API_KEY` set) and retries. If NVD still refuses, it exits 2 and suggests setting `NVD_API_KEY`.
- **Red Hat data unavailable**: Supplement with `web_fetch` on `https://access.redhat.com/security/cve/<CVE_ID>`
- **Crunchy data unavailable (GitHub rate limit)**: Set `GITHUB_TOKEN`; without one GitHub allows 60 requests an hour
- **CVE type misdetected**: Use `--type` flag to force correct detection
- **Connection refused on scan**: Verify network access and pg_hba.conf allows the connection
