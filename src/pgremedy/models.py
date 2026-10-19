"""Shared data classes for pgremedy."""

from __future__ import annotations

from dataclasses import dataclass, field

from pgremedy.branches import BranchStatus


@dataclass
class CVSSInfo:
    score: float | None = None
    severity: str = "UNKNOWN"
    vector: str = "UNKNOWN"
    version: str | None = None


@dataclass
class RedHatPackageState:
    """A product Red Hat hasn't fixed with an advisory, and why ("Out of support scope")."""
    package_name: str
    product_name: str
    fix_state: str


@dataclass
class RedHatPatch:
    """A fixed package: which product it's for and the advisory that ships it."""
    package: str
    advisory: str
    product_name: str = ""


@dataclass
class RedHatInfo:
    # Red Hat records the fix state per product, so there's no single state here:
    # patches are the fixed packages, package_states the rest.
    severity: str = "Unknown"
    upstream_fix: str | None = None
    bugzilla_url: str | None = None
    patches: list[RedHatPatch] = field(default_factory=list)
    package_states: list[RedHatPackageState] = field(default_factory=list)


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
    cve_type: str = "postgresql"     # postgresql (the server), golang or base-image (anything else)
    description: str = ""
    cvss: CVSSInfo = field(default_factory=CVSSInfo)
    # Affected PostgreSQL server releases in words ("16.0 to 16.4"); empty when
    # the CVE isn't about the server.
    affected_versions: list[str] = field(default_factory=list)
    fixed_in: str | None = None      # scan and audit: the fix in the server's own branch
    # lookup only:
    nvd_status: str | None = None
    analyzed: bool = True            # False while NVD hasn't recorded affected products
    product_versions: dict[str, list[str]] = field(default_factory=dict)   # every vulnerable product
    fixes: dict[str, str] = field(default_factory=dict)     # first fixed release per branch
    advisory_url: str | None = None
    redhat: RedHatInfo | None = None
    crunchy: CrunchyInfo | None = None
    crunchy_releases_searched: int | None = None
    references: list[str] = field(default_factory=list)
    # Sources that couldn't be reached, e.g. {"redhat": "could not connect"}.
    source_errors: dict[str, str] = field(default_factory=dict)


@dataclass
class Finding:
    level: str        # critical, warning, ok or info
    message: str


@dataclass
class BranchFix:
    """One row of remedy's per-branch table."""
    major: str
    affected: bool                 # NVD lists at least one release of this branch
    fixed_in: str | None = None    # first fixed release, when NVD lists one
    latest: str | None = None      # latest (or final) release, from postgresql.org
    supported: bool | None = None
    eol_date: str | None = None


@dataclass
class VersionAdvice:
    """What a CVE means for one specific release (remedy --pg-version)."""
    version: str
    major: str
    affected: bool | None = None   # None when the data can't tell (end-of-life branch, unanalyzed CVE)
    fixed_in: str | None = None
    upgrade_to: str | None = None
    findings: list[Finding] = field(default_factory=list)


@dataclass
class Mitigation:
    source: str
    text: str


@dataclass
class ManualStep:
    """A fix the upgrade alone doesn't apply to existing clusters."""
    cve_id: str
    script: str
    instructions: str
    advisory_url: str


@dataclass
class DatabaseCheck:
    database: str
    status: str                    # "applied", "not applied" or "not checked"
    reason: str | None = None      # why it wasn't checked


@dataclass
class ManualFixCheck:
    """Whether a manual fix has been applied in each database of a cluster."""
    cve_id: str
    summary: str
    fixed_in: str                  # for this server's branch
    script: str
    advisory_url: str
    severity: str = "UNKNOWN"
    cvss_score: float | None = None
    release_has_fix: bool = True   # the running release includes the fix (it still needs the script)
    databases: list[DatabaseCheck] = field(default_factory=list)
    # True: not applied in at least one database. False: applied in every
    # database that accepts connections. None: unknown, because a database that
    # accepts connections couldn't be checked (or none could).
    exposed: bool | None = None

    @property
    def missing(self) -> list[str]:
        return [d.database for d in self.databases if d.status == "not applied"]

    @property
    def applied(self) -> list[str]:
        return [d.database for d in self.databases if d.status == "applied"]

    @property
    def unchecked(self) -> list[DatabaseCheck]:
        return [d for d in self.databases if d.status == "not checked"]


@dataclass
class RemediationReport:
    cve_id: str
    description: str = ""
    severity: str = "UNKNOWN"
    cvss_score: float | None = None
    nvd_status: str | None = None
    # postgresql-server: NVD lists the server; other-products: NVD lists only
    # other products (drivers, tools, distro packages); not-analyzed: NVD hasn't
    # recorded affected products yet.
    scope: str = "postgresql-server"
    other_products: list[str] = field(default_factory=list)
    advisory_url: str | None = None
    branches: list[BranchFix] = field(default_factory=list)
    advice: VersionAdvice | None = None
    mitigations: list[Mitigation] = field(default_factory=list)
    manual_step: ManualStep | None = None
    redhat: RedHatInfo | None = None
    crunchy: CrunchyInfo | None = None
    crunchy_releases_searched: int | None = None
    source_errors: dict[str, str] = field(default_factory=dict)


@dataclass
class ScanResult:
    pg_version: str
    pg_version_num: int
    extensions: list[dict] = field(default_factory=list)
    cves: list[CVEReport] = field(default_factory=list)
    connection_info: str = ""
    branch: BranchStatus | None = None
    assessment: list[dict] = field(default_factory=list)
    records_checked: int = 0
    manual_fixes: list[ManualFixCheck] = field(default_factory=list)
    data_source: dict = field(default_factory=dict)
