"""Support status of a PostgreSQL branch: end-of-life, latest minor, how far behind.

PostgreSQL minor releases are cumulative, so "is this the latest minor release
of a supported branch?" is the most reliable single answer to "is this server
exposed to known CVEs?". It also covers what NVD can't: advisories only list
supported branches, so NVD has no affected-version data for end-of-life ones.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any

from pgremedy import pgversion

EOL_WARNING_DAYS = 90


@dataclass
class BranchStatus:
    major: str
    known: bool                      # listed on postgresql.org
    supported: bool | None = None
    latest: str | None = None        # e.g. "16.15"
    eol_date: str | None = None      # e.g. "2028-11-09"
    days_to_eol: int | None = None
    version: str | None = None       # the release checked, when one was given
    minors_behind: int | None = None
    supported_majors: list[str] = field(default_factory=list)

    @property
    def is_eol(self) -> bool:
        return self.known and self.supported is False


def _latest_release(entry: dict[str, Any]) -> str:
    return f"{entry['major']}.{entry['latestMinor']}"


def branch_status(version_or_major: str, versions: list[dict[str, Any]], today: date | None = None) -> BranchStatus:
    """Look up a release ("16.4") or a branch ("16") in postgresql.org's version list."""
    today = today or date.today()
    major = pgversion.major_of(version_or_major) or version_or_major
    supported_majors = [str(e["major"]) for e in versions if e.get("supported")]
    entry = next((e for e in versions if str(e.get("major")) == major), None)
    is_release = not pgversion.is_branch(version_or_major)

    status = BranchStatus(
        major=major,
        known=entry is not None,
        version=version_or_major if is_release else None,
        supported_majors=supported_majors,
    )
    if entry is None:
        return status

    status.supported = bool(entry.get("supported"))
    status.latest = _latest_release(entry)
    status.eol_date = entry.get("eolDate")
    if status.eol_date:
        try:
            status.days_to_eol = (date.fromisoformat(status.eol_date) - today).days
        except ValueError:
            status.days_to_eol = None

    if is_release:
        mine = pgversion.minor_of(version_or_major)
        if mine is not None:
            status.minors_behind = max(0, int(entry["latestMinor"]) - mine)
    return status


def assess(status: BranchStatus) -> list[tuple[str, str]]:
    """Plain-language findings as (level, message); level is critical, warning, ok or info."""
    if not status.known:
        return [("warning", (
            f"PostgreSQL {status.major} isn't in postgresql.org's release list (a beta, "
            "development or unrecognized build?), so its support status can't be checked."
        ))]

    if status.is_eol:
        upgrade_to = ", ".join(status.supported_majors) or "a supported version"
        return [
            ("critical", (
                f"PostgreSQL {status.major} reached end-of-life on {status.eol_date} and no longer "
                f"receives security fixes. Upgrade to a supported major version ({upgrade_to})."
            )),
            ("info", (
                "Advisories only cover supported branches, so CVEs published after "
                f"{status.eol_date} won't be listed here even when they affect this version."
            )),
        ]

    findings: list[tuple[str, str]] = []
    if status.version and status.minors_behind:
        n = status.minors_behind
        findings.append(("warning", (
            f"{status.version} is {n} minor release{'s' if n != 1 else ''} behind the latest "
            f"{status.major}.x ({status.latest}). Minor releases are cumulative: upgrading to "
            f"{status.latest} picks up every security fix released for {status.major}.x so far."
        )))
    elif status.version and status.minors_behind == 0:
        findings.append(("ok", f"{status.version} is the latest {status.major}.x release."))
    else:
        findings.append(("info", f"Latest {status.major}.x release: {status.latest}."))

    if status.days_to_eol is not None and 0 <= status.days_to_eol <= EOL_WARNING_DAYS:
        days = status.days_to_eol
        findings.append(("warning", (
            f"PostgreSQL {status.major} reaches end-of-life on {status.eol_date} "
            f"(in {days} day{'s' if days != 1 else ''}). Plan the upgrade to a newer major version."
        )))
    return findings
