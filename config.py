"""Tunable constants for ScanityCheck.

Everything that shapes the score lives here so the model is easy to audit,
explain, or adjust without touching the scanner or UI code.
"""

from __future__ import annotations  # imports annotations from the __future__ module

import os  # imports the os module
from pathlib import Path  # imports Path from the pathlib module

APP_NAME = "ScanityCheck"  # sets the APP_NAME text
APP_TAGLINE = "ScanityCheck... Because Ignoring Vulnerabilities is a Special Kind of Insanity"  # sets the APP_TAGLINE text

# The launch-time legal disclaimer. Shown before every UI session; the app
# cannot open until the user presses "I Understand & Agree" (or closes the
# gate, which is a refusal). Bump VALIDATION_VERSION whenever the wording
# changes, so past acceptances stay auditable.
LEGAL_DISCLAIMER_VERSION = 1  # assigns the computed value to LEGAL_DISCLAIMER_VERSION
LEGAL_DISCLAIMER = (  # assigns the computed value to LEGAL_DISCLAIMER
    "Legal Disclaimer & Authorized Use:\n"
    "This vulnerability scanning tool is provided \"as is\" and \"as available,\" "
    "without warranties or guarantees of any kind, express or implied.\n\n"
    "The tool is intended solely for authorized security testing, vulnerability "
    "assessment, and defensive security purposes. Users may only scan systems, "
    "applications, repositories, networks, and other assets that they own or have "
    "explicit, documented permission to assess. Unauthorized scanning, access, "
    "testing, or interference with third-party systems is strictly prohibited and "
    "may violate applicable laws and regulations.\n\n"
    "Users are solely responsible for obtaining and maintaining all necessary "
    "authorizations before initiating scans and ensuring their activities comply "
    "with applicable laws, contractual obligations, and organizational policies.\n\n"
    "Scan results, vulnerability findings, risk scores, and compliance mappings are "
    "provided for informational purposes only and do not constitute a definitive "
    "assessment of security posture, regulatory compliance, or system integrity. "
    "All findings must be independently validated, as false positives, false "
    "negatives, incomplete results, and inaccurate severity assessments may occur. "
    "No guarantee is made regarding the accuracy, completeness, or timeliness of "
    "results.\n\n"
    "Use of this tool is entirely at the user's own risk. The developers and "
    "associated parties assume no liability for damages, losses, security "
    "incidents, unauthorized activity, or other consequences arising from the "
    "use, misuse, or reliance upon this tool or its results."
)  # closes the multiline block
APP_VERSION = "1.3.0"  # sets the APP_VERSION text

# Brand palette, sampled from the ScanityCheck wordmark / logo graphics. The navy
# background is identical to BG, so the artwork blends into the window.
BRAND_GREEN = "#b1dd72"  # sets the BRAND_GREEN text
BRAND_GREEN_HOVER = "#9cc75f"  # sets the BRAND_GREEN_HOVER text
BRAND_NAVY = "#0b1220"  # sets the BRAND_NAVY text

# Wordmark / icon shipped with the app (same folder as app.py).
BRANDING_WORDMARK = "Branding.png"  # sets the BRANDING_WORDMARK text
BRANDING_LOGO = "Branding Logo.png"  # sets the BRANDING_LOGO text
# White-background wordmark for printed PDF pages.
BRANDING_WHITE = "Branding White.png"  # sets the BRANDING_WHITE text

# --------------------------------------------------------------------------
# Local state (downloaded scanners, scratch space, saved reports)
# --------------------------------------------------------------------------
CACHE_DIR = Path(  # creates the path object
    os.environ.get("RSS_CACHE_DIR") or (Path.home() / ".repo-security-scorer")  # fetches the value
).expanduser()  # closes the multiline block
TOOLS_DIR = CACHE_DIR / "tools"  # copies the CACHE_DIR value into TOOLS_DIR
WORK_DIR = CACHE_DIR / "work"  # copies the CACHE_DIR value into WORK_DIR
REPORTS_DIR = CACHE_DIR / "reports"  # copies the CACHE_DIR value into REPORTS_DIR
SETTINGS_FILE = CACHE_DIR / "settings.json"  # copies the CACHE_DIR value into SETTINGS_FILE
URL_HISTORY_FILE = CACHE_DIR / "url_history.json"  # the rolling list of scanned targets
URL_HISTORY_LIMIT = 10  # how many past targets the URL dropdown remembers

# --------------------------------------------------------------------------
# Scanner selection
# --------------------------------------------------------------------------
# Display order in the UI and in the report. The three dependency scanners
# overlap on purpose: cross-tool de-duplication keeps the same CVE from being
# charged more than once while still recording every tool that found it.
TOOL_LABELS: dict[str, str] = {  # evaluates the TOOL_LABELS expression
    "codeql": "CodeQL",  # maps the codeql dictionary entry
    "trivy": "Trivy",  # maps the trivy dictionary entry
    "semgrep": "Semgrep CE",  # maps the semgrep dictionary entry
    "grype": "Grype",  # maps the grype dictionary entry
    "osv": "OSV-Scanner",  # maps the osv dictionary entry
    "gitleaks": "GitLeaks",  # maps the gitleaks dictionary entry
    "trufflehog": "TruffleHog",  # maps the trufflehog dictionary entry
    "syft": "Syft",  # maps the syft dictionary entry
    "checkov": "Checkov",  # maps the checkov dictionary entry
    "cdxgen": "cdxgen",  # maps the cdxgen dictionary entry
    "guarddog": "GuardDog",  # maps the guarddog dictionary entry
    "fossology": "FOSSology",  # maps the fossology dictionary entry
    "nuclei": "Nuclei",  # maps the nuclei dictionary entry
    "kubescape": "Kubescape",  # maps the kubescape dictionary entry
    "scorecard": "OpenSSF Scorecard",  # maps the scorecard dictionary entry
    "ossfuzz": "OSS-Fuzz",  # maps the ossfuzz dictionary entry
}  # closes the multiline block

TOOL_DESCRIPTIONS: dict[str, str] = {  # evaluates the TOOL_DESCRIPTIONS expression
    "codeql": (
        "SAST by GitHub: builds a database of your source and runs security "
        "queries - injection, SSRF, unsafe deserialisation, weak crypto. "
        "Interpreted languages scan without a build; compiled ones use CodeQL's "
        "buildless mode. First run downloads the ~700 MB CLI bundle."
    ),  # maps the codeql dictionary entry
    "trivy": (
        "SCA + secrets + IaC in one pass: dependency CVEs from manifests and "
        "lockfiles, container/IaC misconfigurations, and committed secrets. "
        "First run downloads the vulnerability database; updates ride on later runs."
    ),  # maps the trivy dictionary entry
    "semgrep": (
        "SAST patterns: the community ruleset searches your source for dangerous "
        "patterns - injection sinks, weak randomness, insecure defaults, logging "
        "leaks. First run installs a managed Python environment and pulls the ruleset."
    ),  # maps the semgrep dictionary entry
    "grype": (
        "SCA (second opinion): dependency CVEs from Anchore's database, over the "
        "same SBOM Syft produced when both are selected, so its findings match "
        "Syft's component list exactly. Deduped against Trivy, never double-charged."
    ),  # maps the grype dictionary entry
    "osv": (
        "SCA (third opinion): checks lockfiles and manifests against Google's OSV "
        "advisory database - a cross-check on the dependency CVEs Trivy/Grype found; "
        "agreements raise report confidence."
    ),  # maps the osv dictionary entry
    "gitleaks": (
        "Secrets: scans the checked-out tree for API keys, tokens, private keys, "
        "database URLs and passwords - with the credential kind attached so you "
        "can go straight from finding to rotation."
    ),  # maps the gitleaks dictionary entry
    "trufflehog": (
        "Secrets (second opinion): 20+ detector families (AWS, GCP, Stripe, JWT, "
        "private keys...) over the same tree. Verification is disabled so probe "
        "traffic never leaks the credential it just found."
    ),  # maps the trufflehog dictionary entry
    "syft": (
        "SBOM inventory: catalogues every package in the tree into a component "
        "list - it never scores a point, but it is the catalog Grype and OSV "
        "scan against and the basis of the SBOM section in the report."
    ),  # maps the syft dictionary entry
    "cdxgen": (
        "CycloneDX SBOM generator: catalogues every component into the "
        "machine-readable CycloneDX format - never scores a point, and powers "
        "the Print SBOM / Export SBOM buttons. Needs Node.js 18+ installed."
    ),  # maps the cdxgen dictionary entry
    "checkov": (
        "IaC posture: misconfigurations in Dockerfiles, Terraform, Kubernetes "
        "manifests and CI workflows - root containers, missing healthchecks, "
        "unpinned actions, open ports. First run installs a managed venv."
    ),  # maps the checkov dictionary entry
    "kubescape": (
        "K8s/IaC hardening: audits the manifests against NSA hardening guidance "
        "and the MITRE ATT&CK framework, so IaC failures read as named attacks "
        "rather than raw config drift. First run downloads ~300 MB."
    ),  # maps the kubescape dictionary entry
    "nuclei": (
        "DAST on the live site: when the repo publishes a web service, Nuclei's "
        "ten-thousand-template community library probes endpoints, exposed files "
        "and known CVEs at runtime. First run downloads the ~50 MB binary."
    ),  # maps the nuclei dictionary entry
    "guarddog": (
        "Supply chain: runs Datadog GuardDog's malicious-package checks - install "
        "scripts, typosquatting, exfiltration patterns - over the dependency "
        "metadata before anything is charged to the score."
    ),  # maps the guarddog dictionary entry
    "fossology": (
        "Licence compliance: the Nomos/Ojo agents on your FOSSology server classify "
        "every file's open-source licence; copyleft obligations (GPL/AGPL) surface "
        "as findings while permissive families show only in the dashboard mix. "
        "Needs FOSSOLOGY_SERVER and FOSSOLOGY_TOKEN set."
    ),  # maps the fossology dictionary entry
    "scorecard": (
        "Supply-chain posture: asks the public OpenSSF Scorecard record how the "
        "repo performs pipeline security - code review, branch protection, pinned "
        "releases, SAST in CI - and only failing checks are charged."
    ),  # maps the scorecard dictionary entry
    "ossfuzz": (
        "Fuzzing coverage: checks whether the project is continuously fuzzed under "
        "Google's OSS-Fuzz. A registration is a positive signal; its absence is an "
        "informational note that never removes points."
    ),  # maps the ossfuzz dictionary entry
}  # closes the multiline block

ALL_TOOLS: tuple[str, ...] = tuple(TOOL_LABELS)  # runs the tuple() call
DEFAULT_TOOLS: tuple[str, ...] = ALL_TOOLS  # evaluates the DEFAULT_TOOLS expression

# The scanner row is grouped by what each tool actually does, so fifteen
# checkboxes read as a legend instead of a wall of names. The order here is
# the row's display order only: registry order (TOOL_LABELS) still drives the
# report tables and the internal scanner-status ordering.
SCANNER_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (  # evaluates the groups table
    ("SAST", ("codeql", "semgrep")),  # static code security analysis
    ("SCA", ("trivy", "grype", "osv")),  # dependency CVE scanners
    ("Secrets", ("gitleaks", "trufflehog")),  # committed-credential hunts
    ("SBOM", ("syft", "cdxgen")),  # the software-bill-of-materials inventory
    ("IaC", ("checkov", "kubescape")),  # infrastructure / container posture
    ("Dynamic", ("nuclei",)),  # live-web DAST
    ("Supply Chain", ("guarddog", "fossology", "scorecard")),  # malicious packages, licences, maintenance posture
    ("Fuzzing", ("ossfuzz",)),  # continuous fuzzing coverage
)  # closes the multiline block

# Bumped whenever new scanners are added. v6 adds FOSSology (licence
# compliance against a FOSSology server). Settings files written by
# an older version have no version marker, so their saved tool list predates
# the newer scanners; those are merged in on load instead of silently staying
# disabled.
SETTINGS_VERSION = 7  # assigns the computed value to SETTINGS_VERSION

# Only these two must succeed for a scan to be trusted. An optional scanner
# that fails becomes a warning instead of forcing an INSECURE verdict.
REQUIRED_TOOLS: tuple[str, ...] = ("codeql", "trivy")  # evaluates the REQUIRED_TOOLS expression

# Semgrep CE fetches the community ruleset from the registry. "--config auto"
# refuses to run when metrics are off, so the named pack is used instead.
# Semgrep has no supported runtime ruleset-cache switch (verified against the
# CLI source: the resolver re-downloads registry packs each invocation), and
# hardcoding a rules snapshot is not safe either. The scan pipeline runs
# Semgrep at most once per project scan, so the registry fetch already
# happens once per project; keep SEMGREP_CONFIG here as the escape hatch.
SEMGREP_CONFIG = "p/default"  # sets the SEMGREP_CONFIG text
MAX_LISTED_FINDINGS = 300  # assigns the computed value to MAX_LISTED_FINDINGS

# Managed Python tools. Versions are pinned because a scanner that silently
# changes its JSON schema would break the parsers; bump deliberately.
CHECKOV_VERSION = "3.4.0"  # sets the CHECKOV_VERSION text
# GuardDog 3.x pulls in nono-py, which has no Windows wheels and tries to build
# a Rust extension. 2.2.0 is the newest release that installs cleanly here.
GUARDDOG_VERSION = "2.2.0" if os.name == "nt" else "3.2.0"  # sets the GUARDDOG_VERSION text
GUARDDOG_REFERENCE = "https://github.com/DataDog/guarddog"  # sets the GUARDDOG_REFERENCE text

# Harden-scanner wiring. Nuclei and Kubescape are pinned release binaries;
# OpenSSF Scorecard and OSS-Fuzz are pure HTTP lookups with no binary at all.
NUCLEI_VERSION = "3.11.1"  # sets the NUCLEI_VERSION text
NUCLEI_ZIP = "nuclei_3.11.1_windows_amd64.zip"  # sets the NUCLEI_ZIP text
NUCLEI_DOWNLOAD_URL = (  # assigns the computed value to NUCLEI_DOWNLOAD_URL
    "https://github.com/projectdiscovery/nuclei/releases/download/"  # supplies the literal text
    f"v{NUCLEI_VERSION}/{NUCLEI_ZIP}"  # supplies the literal text
)  # closes the multiline block
KUBESCAPE_VERSION = "4.0.17"  # sets the KUBESCAPE_VERSION text
KUBESCAPE_DOWNLOAD_URL = (  # assigns the computed value to KUBESCAPE_DOWNLOAD_URL
    "https://github.com/kubescape/kubescape/releases/download/"  # supplies the literal text
    f"v{KUBESCAPE_VERSION}/kubescape_{KUBESCAPE_VERSION}_windows_amd64.exe"  # supplies the literal text
)  # closes the multiline block
SCORECARD_API = "https://api.scorecard.dev/projects/github.com/{}"  # owner/repo slug formatted
# Runtime checksum sources for the pinned binaries (verified live against the
# pinned releases; both publish "<sha256>  <artifact>" style files). The
# digests themselves are resolved at download time, never hardcoded here, so
# a version bump re-verifies against the fresh file automatically.
NUCLEI_CHECKSUM_URL = (  # assigns the computed value to NUCLEI_CHECKSUM_URL
    "https://github.com/projectdiscovery/nuclei/releases/download/"  # supplies the literal text
    f"v{NUCLEI_VERSION}/nuclei_{NUCLEI_VERSION}_checksums.txt"  # supplies the literal text
)  # closes the multiline block
NUCLEI_CHECKSUM_OBJECT = NUCLEI_ZIP  # entry name inside the checksum file  # sets the NUCLEI_CHECKSUM_OBJECT text
KUBESCAPE_CHECKSUM_URL = (  # assigns the computed value to KUBESCAPE_CHECKSUM_URL
    "https://github.com/kubescape/kubescape/releases/download/"  # supplies the literal text
    f"v{KUBESCAPE_VERSION}/checksums.sha256"  # supplies the literal text
)  # closes the multiline block
KUBESCAPE_CHECKSUM_OBJECT = (  # assigns the computed value to KUBESCAPE_CHECKSUM_OBJECT
    f"kubescape_{KUBESCAPE_VERSION}_windows_amd64.exe"  # supplies the literal text
)  # closes the multiline block

# cdxgen (CycloneDX SBOM generator). Runs through npx with a floating major
# pin, so a scan only needs Node.js>=18 on the PATH - no per-scanner
# download, and the pin keeps the output schema stable across releases.
CDXGEN_NPX_PACKAGE = "@cyclonedx/cdxgen@11"  # sets the CDXGEN_NPX_PACKAGE text
CDXGEN_SPEC_VERSION = "1.5"  # assigns the computed value to CDXGEN_SPEC_VERSION

# GitHub Advisory Database quick-check ("Check GAD"): per pinned
# component, a /advisories?affects=name@version lookup; the cve_id tier
# sweeps every CVE the scanners reported. The caps exist only as a runaway
# safety valve - they are set high enough that a sweep always covers every
# applicable component, and GitHub's own rate limit (with the early-stop
# note in the results) is the real-world budget.
GAD_MAX_CHECKS = 10_000  # effectively uncapped: every pinned component goes out
GAD_MAX_CVE_CHECKS = 10_000  # effectively uncapped: every reported CVE goes out
GAD_MAX_WORKERS = 8  # advisory lookups fan out eight-wide for wall-clock speed
OSSFUZZ_PROJECT_URL = (  # assigns the computed value to OSSFUZZ_PROJECT_URL
    "https://raw.githubusercontent.com/google/oss-fuzz/master/"  # supplies the literal text
    "projects/{}/project.yaml"  # supplies the literal text
)  # closes the multiline block

# FOSSology (open-source licence compliance). There is no Windows-native
# Nomos/Ojo binary, so the scanner talks to a user-supplied FOSSology server
# over its REST v1 API: upload a source archive, schedule the Nomos/Ojo
# agents, poll the job and fetch the licence findings. Point the environment
# at the server (FOSSOLOGY_SERVER, e.g. https://fossology.local) and authorise
# with FOSSOLOGY_TOKEN (a FOSSology API token); without either the scanner
# reports itself skipped instead of failing the scan.
FOSSOLOGY_SERVER_ENV = "FOSSOLOGY_SERVER"  # sets the FOSSOLOGY_SERVER_ENV text
FOSSOLOGY_TOKEN_ENVS: tuple[str, ...] = ("FOSSOLOGY_TOKEN", "FOSSOLOGY_API_TOKEN")  # assigns the computed value
FOSSOLOGY_FOLDER_ID = 1  # the server's default folder  # assigns the computed value
FOSSOLOGY_AGENTS: dict[str, bool] = {"nomos": True, "ojo": True}  # evaluates the agents dict
FOSSOLOGY_TIMEOUT_SECONDS = 60 * 20  # the whole agent run on the server  # assigns the computed value
FOSSOLOGY_POLL_SECONDS = 5.0  # the job-status poll cadence  # assigns the computed value
FOSSOLOGY_MAX_ARCHIVE_BYTES = 200 * 1024 * 1024  # skip huge trees rather than choking a small server  # assigns the computed value
# The licence policy: regex -> severity, applied case-insensitively against
# the SPDX ids Nomos/Ojo report. Permissive families stay unflagged; anything
# unmatched and not permissive keeps the default severity. Tune freely.
FOSSOLOGY_POLICY: tuple[tuple[str, str], ...] = (  # evaluates the FOSSOLOGY_POLICY expression
    (r"AGPL", "high"),  # the strongest copyleft family
    (r"^GPL-3", "high"),  # strong copyleft
    (r"^SSPL", "high"),  # licence-family risk like AGPL
    (r"^GPL-2", "medium"),  # weaker copyleft
    (r"^LGPL", "medium"),  # weak copyleft
    (r"EUPL|CPL|OSL|RPL|MPL", "medium"),  # file/requirement copylefts
    (r"NOASSERTION|^UNKNOWN$|OTHER|^NONE$", "low"),  # the server could not name a licence
)  # closes the multiline block
FOSSOLOGY_DEFAULT_SEVERITY = "low"  # assigns the computed value to FOSSOLOGY_DEFAULT_SEVERITY

# The window/taskbar icon ("AppIcon.png" next to app.py) — the square device
# icon, distinct from the wordmark assets above.
APP_ICON = "AppIcon.png"  # sets the APP_ICON text
FOSSOLOGY_PERMISSIVE: tuple[str, ...] = (  # assigns the computed value to FOSSOLOGY_PERMISSIVE
    "MIT", "BSD-2-Clause", "BSD-3-Clause", "BSD-Source-Code",  # permissive names
    "Apache-2.0", "ISC", "0BSD", "Unlicense", "CC0-1.0", "Zlib",  # permissive names
    "BSL-1.0", "Python-2.0", "PostgreSQL", "PSF-2.0", "WTFPL", "OpenSSL",  # permissive names
)  # closes the multiline block

# --------------------------------------------------------------------------
# Scanner acquisition
# --------------------------------------------------------------------------
CODEQL_BUNDLE_URL = (  # assigns the computed value to CODEQL_BUNDLE_URL
    "https://github.com/github/codeql-action/releases/latest/download/"  # maps the https://github.com/githu dictionary entry
    "codeql-bundle-{platform}.tar.gz"  # supplies the literal text
)  # closes the multiline block
CODEQL_PLATFORM = "win64"  # bundle flavour for this host  # sets the CODEQL_PLATFORM text
TRIVY_LATEST_API = "https://api.github.com/repos/aquasecurity/trivy/releases/latest"  # sets the TRIVY_LATEST_API text
TRIVY_FALLBACK_VERSION = "0.76.1"  # used only if the GitHub API is unavailable  # sets the TRIVY_FALLBACK_VERSION text
GITHUB_API = "https://api.github.com"  # sets the GITHUB_API text
CODELOAD_URL = "https://codeload.github.com/{owner}/{repo}/zip/{ref}"  # sets the CODELOAD_URL text
USER_AGENT = f"scanitycheck/{APP_VERSION}"  # sets the USER_AGENT text

# --------------------------------------------------------------------------
# Scan behaviour
# --------------------------------------------------------------------------
MAX_CODEQL_LANGUAGES = 2  # assigns the computed value to MAX_CODEQL_LANGUAGES
TOP_RISK_LIMIT = 15  # assigns the computed value to TOP_RISK_LIMIT
SCAN_TIMEOUT_SECONDS = 60 * 45  # per scanner invocation  # assigns the computed value to SCAN_TIMEOUT_SECONDS
DOWNLOAD_TIMEOUT_SECONDS = 60 * 30  # assigns the computed value to DOWNLOAD_TIMEOUT_SECONDS
HTTP_TIMEOUT_SECONDS = 30  # assigns the computed value to HTTP_TIMEOUT_SECONDS

# Bounded pools. Scanner subprocesses walk the same NTFS tree on disk, so
# beyond a handful of workers they only fight each other for I/O.
SCANNER_POOL_WORKERS = 3  # parallel optional scanners after CodeQL  # assigns the computed value to SCANNER_POOL_WORKERS
CARE_ENDPOINT_WORKERS = 5  # parallel GitHub maintenance-metric fetches  # assigns the computed value to CARE_ENDPOINT_WORKERS

# IaC shapes Checkov and Kubescape read: Terraform/HCL, YAML/JSON manifests
# (CloudFormation/Kubernetes/helm/ARM) and container files. Conservative on
# purpose - a repo that HAS IaC must never be skipped, so JSON and .tfvars
# are included even though they also appear in non-IaC codebases.
IAC_FILE_SUFFIXES = frozenset(  # gathers the values into a set
    {  # executes the statement
        ".yml",  # Kubernetes / helm / CloudFormation / workflows  # supplies the literal text
        ".yaml",  # ditto, spelled out  # supplies the literal text
        ".tf",  # Terraform  # supplies the literal text
        ".tfvars",  # Terraform variables  # supplies the literal text
        ".hcl",  # HCL modules / CDKTF  # supplies the literal text
        ".json",  # CloudFormation / ARM / CycloneDX-flavoured manifests  # supplies the literal text
    }  # closes the multiline block
)  # closes the multiline block
IAC_FILE_NAMES = ("dockerfile", "containerfile")  # name prefixes for container files  # sets the IAC_FILE_NAMES text

SEVERITY_ORDER = ("critical", "high", "medium", "low", "unknown")

# Dashboard metric toggles: users tick any subset; nothing is drawn or printed
# unless it is selected. Descriptions are the hover/status hints.
DASHBOARD_METRICS: dict[str, tuple[str, str]] = {
    "total_vulnerabilities": ("Total vulnerabilities", "all findings in the vulnerability category"),
    "severity_counts": ("Severity breakdown", "critical / high / medium / low counts"),
    "by_cwe": ("Vulnerabilities by CWE", "top CWE weakness classes"),
    "by_scanner": ("Vulnerabilities by scanner", "which tool reported findings"),
    "by_language": ("Vulnerabilities by language", "findings mapped to file language"),
    "top_files": ("Top 10 vulnerable files", "files with the most findings"),
    "cvss_scores": ("CVSS scores", "histogram of CVSS base scores"),
    "epss_scores": ("EPSS scores", "exploitation-likelihood histogram"),
    "kev_status": ("CISA KEV status", "known exploited vulnerabilities found"),
    "oldest_10": ("10 oldest vulnerabilities", "sorted by publication date"),
    "languages_detected": ("Languages detected", "file counts per language"),
    "ownership_changes": ("Packages that changed ownership", "source-only scan cannot tell"),
    "secrets_total": ("Total secrets detected", "count in the secret category"),
    "recurring_types": ("Top 5 recurring vulnerability types", "most frequent rule families"),
    "containers_count": ("Containers analyzed", "Dockerfiles found in the repo"),
    "dep_tree_depth": ("Dependency tree depth", "longest npm dependency chain"),
    "deprecated_packages": ("Deprecated package count", "npm packages flagged deprecated"),
    "api_listing": ("API listing", "OpenAPI / Swagger specs detected"),
    "license_mix": ("Licence mix detected", "FOSSology licence proportions across the tree"),
    "heat_map": ("Risk heat map", "file x severity heat grid"),
    "internet_exposure": ("Internet exposure", "needs runtime info; placeholder"),
    "repo_activity_ratio": ("Active vs dormant repos", "is this repo actively developed or wasting space"),
    "churn_value_index": ("Churn-weighted value", "90-day commits x files x contributors"),
    "authored_volume_trend": ("Authored-code volume trend", "commits per quarter over the last 12 months"),
    "cost_of_change_proxy": ("Cost-of-change proxy", "how much of the change risk sits in a few hotspots"),
}
DASHBOARD_ALL: tuple[str, ...] = tuple(DASHBOARD_METRICS)
DASHBOARD_DEFAULTS: tuple[str, ...] = ()  # off by default: user ticks what they want  # assigns the computed value to SEVERITY_ORDER

# Colours used by the report pane, the status counts and the pie chart.
SEVERITY_COLOURS: dict[str, str] = {  # evaluates the SEVERITY_COLOURS expression
    "critical": "#f87171",  # maps the critical dictionary entry
    "high": "#fb923c",  # maps the high dictionary entry
    "medium": "#fbbf24",  # maps the medium dictionary entry
    "low": "#84cc16",  # maps the low dictionary entry
    "unknown": "#8ba3c2",  # maps the unknown dictionary entry
    "clean": "#22c55e",  # maps the clean dictionary entry
}  # closes the multiline block

# Penalty points removed from a perfect 100 for every individual finding.
WEIGHTS: dict[str, dict[str, float]] = {  # evaluates the WEIGHTS expression
    "vulnerability": {"critical": 12.0, "high": 6.0, "medium": 1.5, "low": 0.3, "unknown": 0.5},  # maps the vulnerability dictionary entry
    "secret": {"critical": 15.0, "high": 10.0, "medium": 5.0, "low": 1.0, "unknown": 2.0},  # maps the secret dictionary entry
    "misconfiguration": {"critical": 8.0, "high": 4.0, "medium": 1.0, "low": 0.2, "unknown": 0.5},  # maps the misconfiguration dictionary entry
    "code": {"critical": 10.0, "high": 5.0, "medium": 1.5, "low": 0.4, "unknown": 1.0},  # maps the code dictionary entry
    "license": {"critical": 6.0, "high": 3.0, "medium": 1.2, "low": 0.2, "unknown": 0.4},  # maps the license dictionary entry
}  # closes the multiline block
CODE_QUALITY_WEIGHT = 0.2  # assigns the computed value to CODE_QUALITY_WEIGHT

# A single noisy scanner must not be able to zero out an otherwise clean repo.
CAPS: dict[str, float] = {  # evaluates the CAPS expression
    "vulnerability": 45.0,  # maps the vulnerability dictionary entry
    "secret": 25.0,  # maps the secret dictionary entry
    "misconfiguration": 10.0,  # maps the misconfiguration dictionary entry
    "code": 40.0,  # maps the code dictionary entry
    "license": 8.0,  # maps the license dictionary entry
    "code-quality": 6.0,  # maps the code-quality dictionary entry
}  # closes the multiline block

# --------------------------------------------------------------------------
# Context normalisation of the caps
# --------------------------------------------------------------------------
# The plain caps above are worst-case ceilings, but they are absolute: a
# mature product with 600 transitive dependencies saturates the CVE cap the
# same way an abandoned 20-dependency repo does, and the score were pinned at
# zero for either. The relief table widens a category's cap when the scan's
# measured context explains part of the finding count:
#
#   * density  - findings scale with the attacked surface, so a large
#     dependency tree (SBOM components) or a large codebase (scanned files)
#     inherits proportionally more of its ecosystem's CVEs. The density
#     factor grows as 1 + weight x ln(count / base) and only for counts above
#     the base, so small repos keep the plain cap untouched.
#   * pulse    - the maintenance pulse (recent commits, releases,
#     contributor count) softens the CVE cap: actively maintained projects
#     patch inherited issues continuously. Secrets are exempt on purpose:
#     committed credentials are never long-tail noise.
#
# relief = max(floor, 1 / factor). The floors keep the instrument honest - a
# flooded repo can still never score above ~half even with perfect context.
# No measured context (no SBOM small counts, no Care data) means relief 1.0:
# the plain caps apply exactly as before.
SCORING_CONTEXT: dict[str, dict[str, float]] = {  # evaluates the SCORING_CONTEXT expression
    "vulnerability": {  # maps the vulnerability dictionary entry
        "density_from": "packages",  # the SBOM component count drives the relief
        "density_base": 25.0,  # component count where relief starts
        "density_weight": 0.32,  # the log-density slope
        "density_cap": 2.0,  # the widest density step
        "pulse_bonus": 0.55,  # the maintenance-pulse multiplier headroom
        "relief_floor": 0.45,  # the context cannot excuse below this
    },  # closes the entry
    "code": {  # maps the code dictionary entry
        "density_from": "files",  # the scanned-file count drives the relief
        "density_base": 25.0,  # scanned-file count where relief starts
        "density_weight": 0.28,  # the log-density slope
        "density_cap": 1.6,  # the widest density step
        "relief_floor": 0.55,  # the context cannot excuse below this
    },  # closes the entry
    # secret / misconfiguration / code-quality deliberately absent: their
    # findings are few and absolute, so the plain caps stay in force.
}  # closes the multiline block

CONTEXT_PULSE: dict[str, float] = {  # evaluates the CONTEXT_PULSE expression
    "commits_weight": 0.5,  # the 90-day commit share
    "commits_norm": 50.0,  # commits at which this signal saturates
    "releases_weight": 0.25,  # the release-cadence share
    "releases_norm": 6.0,  # releases per year at which this saturates
    "contributors_weight": 0.25,  # the contributor-count share
    "contributors_norm": 8.0,  # contributors at which this saturates
}  # closes the multiline block

# Score bands, highest first. The label is shown in the popup next to the score.
# Seven bands on the risk spectrum: Very Low (green, safest) down to Critical
# (dark red). 100 is the safest score.
BANDS: tuple[tuple[int, str, str], ...] = (  # evaluates the BANDS expression
    (90, "Very Low", "#22c55e"),  # 90-100: green  # executes the statement
    (80, "Low", "#86efac"),  # 80-89: light green  # executes the statement
    (70, "Moderate", "#fde047"),  # 70-79: light yellow  # executes the statement
    (60, "Elevated", "#eab308"),  # 60-69: yellow  # executes the statement
    (40, "High", "#ea580c"),  # 40-59: orange  # executes the statement
    (20, "Very High", "#dc2626"),  # 20-39: red  # executes the statement
    (0, "Critical", "#7f1d1d"),  # 0-19: dark red  # executes the statement
)  # closes the multiline block

# A repo is only called "secure" when it clears this bar *and* has no critical
# findings. Anything less is reported as insecure. The verdict rule is
# independent of the display band scale above.
SECURE_MIN_SCORE = 85  # assigns the computed value to SECURE_MIN_SCORE

LANGUAGE_PACKS = {  # assigns the computed value to LANGUAGE_PACKS
    "python": "python",  # maps the python dictionary entry
    "javascript-typescript": "javascript",  # maps the javascript-typescript dictionary entry
    "java-kotlin": "java",  # maps the java-kotlin dictionary entry
    "csharp": "csharp",  # maps the csharp dictionary entry
    "cpp": "cpp",  # maps the cpp dictionary entry
    "go": "go",  # maps the go dictionary entry
    "ruby": "ruby",  # maps the ruby dictionary entry
    "swift": "swift",  # maps the swift dictionary entry
    "actions": "actions",  # maps the actions dictionary entry
}  # closes the multiline block

# Interpreted languages need no build step; compiled ones use CodeQL's
# "none" build mode so scanning never requires a toolchain on the host.
BUILDLESS_LANGUAGES = frozenset({"python", "javascript-typescript", "ruby", "actions"})  # gathers the values into a set

EXTENSION_LANGUAGES = {  # assigns the computed value to EXTENSION_LANGUAGES
    ".py": "python",  # maps the .py dictionary entry
    ".pyw": "python",  # maps the .pyw dictionary entry
    ".js": "javascript-typescript",  # maps the .js dictionary entry
    ".jsx": "javascript-typescript",  # maps the .jsx dictionary entry
    ".mjs": "javascript-typescript",  # maps the .mjs dictionary entry
    ".cjs": "javascript-typescript",  # maps the .cjs dictionary entry
    ".ts": "javascript-typescript",  # maps the .ts dictionary entry
    ".tsx": "javascript-typescript",  # maps the .tsx dictionary entry
    ".vue": "javascript-typescript",  # maps the .vue dictionary entry
    ".svelte": "javascript-typescript",  # maps the .svelte dictionary entry
    ".java": "java-kotlin",  # maps the .java dictionary entry
    ".kt": "java-kotlin",  # maps the .kt dictionary entry
    ".kts": "java-kotlin",  # maps the .kts dictionary entry
    ".cs": "csharp",  # maps the .cs dictionary entry
    ".go": "go",  # maps the .go dictionary entry
    ".rb": "ruby",  # maps the .rb dictionary entry
    ".swift": "swift",  # maps the .swift dictionary entry
    ".c": "cpp",  # maps the .c dictionary entry
    ".h": "cpp",  # maps the .h dictionary entry
    ".cc": "cpp",  # maps the .cc dictionary entry
    ".cpp": "cpp",  # maps the .cpp dictionary entry
    ".cxx": "cpp",  # maps the .cxx dictionary entry
    ".hpp": "cpp",  # maps the .hpp dictionary entry
    ".hh": "cpp",  # maps the .hh dictionary entry
}  # closes the multiline block

SKIP_DIRS = frozenset(  # gathers the values into a set
    {  # executes the statement
        ".git",  # supplies the literal text
        ".hg",  # supplies the literal text
        ".svn",  # supplies the literal text
        "node_modules",  # supplies the literal text
        "bower_components",  # supplies the literal text
        "vendor",  # supplies the literal text
        "dist",  # supplies the literal text
        "build",  # supplies the literal text
        "target",  # supplies the literal text
        "out",  # supplies the literal text
        "bin",  # supplies the literal text
        "obj",  # supplies the literal text
        ".venv",  # supplies the literal text
        "venv",  # supplies the literal text
        "env",  # supplies the literal text
        "__pycache__",  # supplies the literal text
        ".tox",  # supplies the literal text
        ".mypy_cache",  # supplies the literal text
        ".pytest_cache",  # supplies the literal text
        ".gradle",  # supplies the literal text
        ".idea",  # supplies the literal text
        ".next",  # supplies the literal text
        ".nuxt",  # supplies the literal text
        "coverage",  # supplies the literal text
        "site-packages",  # supplies the literal text
        "third_party",  # supplies the literal text
        "thirdparty",  # supplies the literal text
        "Pods",  # supplies the literal text
        ".terraform",  # supplies the literal text
    }  # closes the multiline block
)  # closes the multiline block
