"""Security fixes that need a manual step after upgrading.

Most PostgreSQL security fixes take effect as soon as the server runs the
fixed minor release. A few change objects that initdb creates, such as system
views, so they only reach clusters created after the fix. A cluster created
earlier keeps the vulnerable objects, whatever release it runs, until an
administrator applies the fix in every database.

A version check can't see that, so each entry here describes a read-only query
that looks at the objects themselves.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

ADVISORY_URL = "https://www.postgresql.org/support/security/{cve_id}/"


@dataclass(frozen=True)
class ManualFix:
    cve_id: str
    summary: str
    fixed_in: dict[str, str]           # branch -> first release with the fix
    script: str                        # shipped in the share directory of fixed releases
    query: str                         # read-only; one row
    is_applied: Callable[[tuple], bool]

    @property
    def advisory_url(self) -> str:
        return ADVISORY_URL.format(cve_id=self.cve_id)

    def instructions(self) -> str:
        return (
            f"Run {self.script} as a superuser in every database, including template0 and template1 "
            "(template0 needs connections enabled temporarily). The advisory has the steps."
        )


# The fix restricts both views to the table owner. The vulnerable definitions
# check column privileges instead (pg_stats_ext) or nothing (pg_stats_ext_exprs).
_OWNER_CHECK = re.compile(r"pg_has_role\(\s*c\.relowner\s*,\s*'USAGE'")

CVE_2024_4317 = ManualFix(
    cve_id="CVE-2024-4317",
    summary="pg_stats_ext and pg_stats_ext_exprs show other users' statistics, including most common values",
    fixed_in={"14": "14.12", "15": "15.7", "16": "16.3"},
    script="fix-CVE-2024-4317.sql",
    query=(
        "SELECT pg_get_viewdef('pg_catalog.pg_stats_ext'::regclass), "
        "pg_get_viewdef('pg_catalog.pg_stats_ext_exprs'::regclass)"
    ),
    is_applied=lambda row: all(_OWNER_CHECK.search(definition or "") for definition in row),
)

KNOWN = [CVE_2024_4317]


def for_branch(major: str | None) -> list[ManualFix]:
    """Manual fixes relevant to clusters of this branch."""
    return [fix for fix in KNOWN if major in fix.fixed_in]


def find(cve_id: str) -> ManualFix | None:
    return next((fix for fix in KNOWN if fix.cve_id == cve_id.upper()), None)
