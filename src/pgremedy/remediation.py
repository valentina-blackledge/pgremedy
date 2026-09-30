"""Remediation guidance generator."""

from __future__ import annotations

import re
from typing import Any

from rich.console import Console

from pgremedy.apis import crunchy, nvd, redhat

console = Console(stderr=True)

KNOWN_MITIGATIONS: dict[str, list[str]] = {
    "search_path": [
        "Set search_path explicitly in postgresql.conf: search_path = '\"$user\", public'",
        "Use fully-qualified table/function names in application SQL",
        "Revoke CREATE on public schema from PUBLIC: REVOKE CREATE ON SCHEMA public FROM PUBLIC",
    ],
    "pg_hba": [
        "Restrict pg_hba.conf to reject untrusted connections",
        "Use scram-sha-256 instead of md5 for password authentication",
        "Limit hostssl entries to specific IP ranges",
    ],
    "row_security": [
        "Enable row-level security on affected tables: ALTER TABLE t ENABLE ROW LEVEL SECURITY",
        "Audit existing RLS policies for bypass conditions",
    ],
    "privilege_escalation": [
        "Revoke unnecessary superuser grants",
        "Audit SECURITY DEFINER functions: SELECT proname, proowner FROM pg_proc WHERE prosecdef",
        "Use SECURITY INVOKER where possible",
    ],
    "ssl": [
        "Enforce ssl=on in postgresql.conf",
        "Set ssl_min_protocol_version = 'TLSv1.2'",
        "Rotate server certificates if private key may be compromised",
    ],
    "extension": [
        "Drop or upgrade the affected extension",
        "Restrict extension installation: ALTER SYSTEM SET shared_preload_libraries (review list)",
        "Limit CREATE EXTENSION privileges to trusted roles",
    ],
}

KEYWORD_TO_MITIGATION: list[tuple[list[str], str]] = [
    (["search_path", "search path"], "search_path"),
    (["pg_hba", "authentication", "password", "md5", "scram"], "pg_hba"),
    (["row level security", "row-level security", "rls", "policy"], "row_security"),
    (["privilege", "superuser", "escalation", "security definer"], "privilege_escalation"),
    (["ssl", "tls", "certificate", "x509"], "ssl"),
    (["extension", "contrib", "shared_preload"], "extension"),
]


def _match_mitigations(description: str) -> list[str]:
    desc_lower = description.lower()
    mitigations: list[str] = []
    seen_categories: set[str] = set()
    for keywords, category in KEYWORD_TO_MITIGATION:
        if category in seen_categories:
            continue
        for kw in keywords:
            if kw in desc_lower:
                mitigations.extend(KNOWN_MITIGATIONS[category])
                seen_categories.add(category)
                break
    return mitigations


def generate_remediation(cve_id: str, pg_version: str | None = None) -> dict[str, Any]:
    console.log(f"Generating remediation for {cve_id}...")

    nvd_data = nvd.fetch_cve(cve_id)
    nvd.rate_limit_pause()

    if not nvd_data:
        return {"cve_id": cve_id, "error": f"CVE {cve_id} not found in NVD"}

    description = ""
    for d in nvd_data.get("descriptions", []):
        if d.get("lang") == "en":
            description = d["value"]
            break

    cvss = nvd.extract_cvss(nvd_data)
    fix_version = nvd.find_fix_version(nvd_data, pg_version=pg_version)

    result: dict[str, Any] = {
        "cve_id": cve_id,
        "description": description,
        "severity": cvss.get("severity", "UNKNOWN"),
        "cvss_score": cvss.get("score"),
    }

    if fix_version:
        upgrade_info: dict[str, Any] = {
            "fix_version": fix_version,
            "action": f"Upgrade PostgreSQL to {fix_version} or later",
        }
        if pg_version:
            upgrade_info["current"] = pg_version
            from packaging.version import Version, InvalidVersion
            try:
                if Version(pg_version) >= Version(fix_version):
                    upgrade_info["action"] = f"Your version ({pg_version}) already includes the fix (fixed in {fix_version})"
            except InvalidVersion:
                pass
        result["upgrade_path"] = upgrade_info

    mitigations = _match_mitigations(description)
    if not mitigations and not fix_version:
        mitigations.append("No automated mitigation available — review the CVE description and upstream advisory for manual workarounds")
    result["mitigations"] = mitigations

    rh = redhat.fetch_cve(cve_id)
    if rh:
        rh_status: dict[str, Any] = {
            "fix_state": rh.get("fix_state", "Unknown"),
            "upstream_fix": rh.get("upstream_fix"),
        }
        patches = []
        for ar in rh.get("affected_release", [])[:5]:
            patches.append(f"{ar.get('package', 'N/A')} via {ar.get('advisory', 'N/A')}")
        if patches:
            rh_status["patches"] = patches
        result["redhat_status"] = rh_status

    crunchy_releases = crunchy.fetch_releases()
    cr = crunchy.find_cve_in_releases(cve_id, crunchy_releases)
    if cr:
        result["crunchy_status"] = cr

    return result
