"""Shared data classes for pgremedy."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CVSSInfo:
    score: float | None = None
    severity: str = "UNKNOWN"
    vector: str = "UNKNOWN"
    version: str | None = None


@dataclass
class RedHatPackageState:
    package_name: str
    product_name: str
    fix_state: str


@dataclass
class RedHatPatch:
    package: str
    advisory: str


@dataclass
class RedHatInfo:
    severity: str = "Unknown"
    fix_state: str = "Unknown"
    upstream_fix: str | None = None
    bugzilla_url: str | None = None
    patches: list[RedHatPatch] = field(default_factory=list)
    package_states: list[RedHatPackageState] = field(default_factory=list)


@dataclass
class ErrataEntry:
    id: str
    synopsis: str
    severity: str
    released_on: str = ""


@dataclass
class CrunchyInfo:
    release_tag: str
    release_name: str
    published: str
    prerelease: bool = False
    url: str = ""


@dataclass
class CVEReport:
    cve_id: str
    cve_type: str = "postgresql"
    description: str = ""
    cvss: CVSSInfo = field(default_factory=CVSSInfo)
    affected_versions: list[str] = field(default_factory=list)
    redhat: RedHatInfo | None = None
    errata: list[ErrataEntry] = field(default_factory=list)
    crunchy: CrunchyInfo | None = None
    references: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    pg_version: str
    pg_version_num: int
    extensions: list[dict] = field(default_factory=list)
    cves: list[CVEReport] = field(default_factory=list)
    connection_info: str = ""
