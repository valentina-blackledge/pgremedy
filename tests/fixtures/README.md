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
| `postgresql_org_versions.json` | Subset of https://www.postgresql.org/versions.json (9.6 and 12–18). |
| `redhat/CVE-2026-6471.json` | Red Hat record with a real workaround. Structure as served (`mitigation` is `{"value", "lang"}`); the text is a paraphrase of Red Hat's, not a copy. |
| `redhat/CVE-2024-7348.json` | Red Hat record whose mitigation is Red Hat's "not available" boilerplate (the opening words are copied; the rest is cut). |

Descriptions are shortened. CVSS metrics are included only where they were
checked against the live record; the others are omitted rather than guessed.
