"""PostgreSQL version parsing.

PostgreSQL 10 and later number releases MAJOR.MINOR (16.4 is minor release 4
of branch 16). Before 10 the branch was the first two numbers (9.6.24 is minor
release 24 of branch 9.6), so "the major version" is not always the first
number.
"""

from __future__ import annotations

import re

from packaging.version import InvalidVersion, Version

_LEADING_NUMBERS = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def parse(text: str | None) -> Version | None:
    """Parse "16.4", "9.6.24", "17beta1" or "16.4 (Ubuntu 16.4-1.pgdg24.04+1)".

    Builds that packaging can't read ("17devel") fall back to their leading
    numbers. Returns None for anything without a version number.
    """
    if not text or not text.strip():
        return None
    token = text.strip().split()[0]
    try:
        return Version(token)
    except InvalidVersion:
        m = _LEADING_NUMBERS.match(token)
        if not m:
            return None
        numbers = ".".join(g for g in m.groups() if g is not None)
        # Anything after the numbers ("devel") marks a development build.
        return Version(numbers + (".dev0" if token[m.end():] else ""))


def major_of(version: str | Version | None) -> str | None:
    """The branch a version belongs to: "16" for 16.4, "9.6" for 9.6.24."""
    v = version if isinstance(version, Version) else parse(version)
    if v is None:
        return None
    rel = v.release
    if rel[0] >= 10 or len(rel) == 1:
        return str(rel[0])
    return f"{rel[0]}.{rel[1]}"


def minor_of(version: str | Version | None) -> int | None:
    """The minor release number: 4 for 16.4, 24 for 9.6.24, None for "16"."""
    v = version if isinstance(version, Version) else parse(version)
    if v is None:
        return None
    rel = v.release
    index = 1 if rel[0] >= 10 else 2
    return rel[index] if len(rel) > index else None


def is_branch(text: str) -> bool:
    """True for a branch ("16", "9.6"), False for a release ("16.2", "9.6.24", "17beta1")."""
    v = parse(text)
    if v is None or v.pre is not None or v.dev is not None:
        return False
    rel = v.release
    return len(rel) == (1 if rel[0] >= 10 else 2)


def branch_bounds(major: str) -> tuple[Version, Version]:
    """[lowest, highest) versions in a branch: 16 -> [16, 17), 9.6 -> [9.6, 9.7)."""
    parts = [int(p) for p in major.split(".")]
    if len(parts) == 1:
        return Version(str(parts[0])), Version(str(parts[0] + 1))
    return Version(f"{parts[0]}.{parts[1]}"), Version(f"{parts[0]}.{parts[1] + 1}")
