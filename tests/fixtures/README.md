# Test fixtures

Copied from the live APIs on 2026-10-12 and trimmed to the fields pgremedy
reads. Each file in `nvd/` is the `cve` object NVD returns inside
`vulnerabilities[]`.

| File | Why it's here |
|------|---------------|
| `nvd/CVE-2024-10979.json` | Ordinary PostgreSQL CVE: one end-exclusive range per supported branch (12.0–12.21 … 17.0–17.1). |
| `nvd/CVE-2026-6471.json` | Recent CVE whose ranges cover only the branches supported when it was published (14–18). |
| `nvd/CVE-2014-0060.json` | Older CVE that lists exact versions (`postgresql:8.4.1`, …) with no range fields. Abridged: the real record has 56 exact versions plus one range. |
| `nvd/CVE-2016-1255.json` | Debian `postgresql-common` packaging bug. The CPE contains "postgresql" but it is not the server product. Abridged: the real record has 339 CPE entries across 7 configurations. |
| `nvd/CVE-2010-3781.json` | PL/php add-on that lists PostgreSQL only as a non-vulnerable platform (`vulnerable: false`). |
| `nvd/CVE-2024-1597.json` | pgjdbc (JDBC driver) CVE, CRITICAL. Vendor is `postgresql` but the product is `postgresql_jdbc_driver`, and its first range has no start ("< 42.2.28"), so a loose match would flag every server version. NVD's product query doesn't return it; the local product check is the backstop. |
| `nvd/CVE-2024-4317.json` | The CVE whose fix needs a manual step. Built from the PostgreSQL advisory (fixed in 14.12, 15.7 and 16.3; CVSS 3.1) because NVD's record couldn't be fetched when this was written. The ranges follow NVD's usual layout for PostgreSQL CVEs. |
| `postgres/<branch>-vulnerable.<view>.sql` | `pg_get_viewdef()` output from real clusters created on 14.11, 15.6 and 16.2 (before the CVE-2024-4317 fix), then upgraded in place to 14.23, 15.18 and 16.15. Another user could read private statistics through these views. |
| `postgres/<branch>-fixed.<view>.sql` | The same views from clusters created fresh on 14.23, 15.18 and 16.15. The same test showed nothing. |
| `postgresql_org_versions.json` | Subset of https://www.postgresql.org/versions.json (9.6 and 12–18). |
| `checklists/*.ckl`, `*.cklb` | Small STIG Viewer checklists written for these tests, in the structure STIG Viewer 2 (`.ckl`, XML) and 3 (`.cklb`, JSON) use (checked against STIG Manager's sample files). Rule V-283674 is the real version rule; V-000001 and V-999998 are made-up IDs (an unrelated rule, and the version rule under a changed ID). |
| `redhat/CVE-2026-6471.json` | Red Hat record with a real workaround. Structure as served (`mitigation` is `{"value", "lang"}`); the text is a paraphrase of Red Hat's, not a copy. |
| `redhat/CVE-2024-7348.json` | Red Hat record whose mitigation is Red Hat's "not available" boilerplate (the opening words are copied; the rest is cut). |

Descriptions are shortened. CVSS metrics are included only where they were
checked against the live record; the others are omitted rather than guessed.
