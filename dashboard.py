"""Dashboard payload builder for the selected metric widgets.

Pure data, no Tkinter: the same payloads feed the GUI canvas, the PDF graphics
and the ASCII report, so a widget looks the same everywhere.

Widget kinds (``payload["kind"]``):

* ``number``   one big figure with a caption
* ``bar``      horizontal bars: ``rows`` = [(label, value, colour)] + ``max``
* ``donut``    share slices: same row shape as ``bar``
* ``heat``     grid: ``rows`` = [(file, {severity: count})] + ``sevs``
* ``table``    plain rows with a header
* ``na``       honest "not assessable from a source-only scan" placeholder

Repo-file inputs (containers, API specs, npm dependency depth and deprecated
packages) are gathered once per scan by :func:`collect_repo_inputs`; language
mapping reuses :data:`config.EXTENSION_LANGUAGES`, and severity palette/
metric labels come from :mod:`config`. Nothing here imports the scoring
module, so scoring can import this module freely.
"""

from __future__ import annotations

import json  # imports the json module
import re as _regex  # imports the regex module
from collections import Counter  # imports the Counter class
from pathlib import Path  # imports Path from the pathlib module
from typing import Any, Iterable  # imports typing helpers

import config  # imports the config module
import textutil  # imports the shared clip/clean helpers

BAR_COLOURS = ("#22c55e", "#60a5fa", "#fbbf24", "#fb923c", "#f87171", "#8ba3c2")

_SEV_COLOURS = {
    "critical": "#f87171",
    "high": "#fb923c",
    "medium": "#fbbf24",
    "low": "#84cc16",
    "unknown": "#8ba3c2",
}

_SEV_ORDER = ("critical", "high", "medium", "low", "unknown")


def validate(keys: Iterable[str] | None) -> list[str]:
    """Keep the selected metric keys in the defined order; drop unknown ones."""
    chosen = {str(key) for key in (keys or [])}
    return [key for key in config.DASHBOARD_ALL if key in chosen]


# ---------------------------------------------------------------------------
# Section explainers
# ---------------------------------------------------------------------------

# One-to-two-sentence explanations rendered under each dashboard section
# title: what the widget measures and what it implies. Keyed by the metric
# id from ``config.DASHBOARD_METRICS``; a missing entry simply draws nothing.
METRIC_EXPLAINERS: dict[str, str] = {
    "total_vulnerabilities": (
        "Unique, cross-tool de-duplicated dependency CVEs - the published-source "
        "flaws in the libraries you ship. Each charge scales with severity, and "
        "a single critical finding vetoes the SECURE verdict whatever the score."
    ),
    "severity_counts": (
        "How the whole finding set splits across critical / high / medium / low. "
        "The mix matters more than the total: many lows are hygiene noise, while "
        "any critical block means act now rather than plan later."
    ),
    "by_cwe": (
        "The weakness classes behind the findings (CWE-79 XSS, CWE-89 SQL "
        "injection...). The same class recurring across files points at a "
        "systemic pattern to fix once, instead of a stream of one-off bugs."
    ),
    "by_scanner": (
        "Which engines reported each issue. When independent tools (Trivy, "
        "Grype, OSV) agree on one item, it is counted once for the score but "
        "the agreement itself raises the report's confidence."
    ),
    "by_language": (
        "Where the findings live in the source, mapped per language. A heavy "
        "concentration in one stack tells you which team and review process "
        "the remediation work belongs to."
    ),
    "top_files": (
        "The files carrying the most findings - the known hotspots. A file that "
        "keeps regenerating findings usually needs a refactor before more "
        "patchwork, so it is where maintenance effort pays back fastest."
    ),
    "cvss_scores": (
        "The distribution of CVSS base scores (0-10) on the vulnerability "
        "findings: how hard each bug is to exploit and how much damage it "
        "admits. Findings without an engine-supplied score stay in the unknown band."
    ),
    "epss_scores": (
        "The exploitation likelihood (EPSS, 0-100%) that a vulnerability will "
        "be attacked in the next ~30 days. High EPSS on a medium CVSS finding "
        "usually outranks a low-probability critical in triage order."
    ),
    "kev_status": (
        "Whether any finding appears in CISA's Known Exploited Vulnerabilities "
        "catalogue. The KEV list is evidence of live attacks in the wild, so "
        "each hit jumps to the top of every patch queue."
    ),
    "oldest_10": (
        "The oldest publication dates still sitting in your dependency tree. "
        "Age plus continued presence means patch debt that has survived many "
        "release cycles - an honest picture of backlog pressure."
    ),
    "languages_detected": (
        "The composition of what was actually scanned: files per language. An "
        "ecosystem you did not expect (or one the deep scanners skipped) shows "
        "up here before it shows up anywhere else."
    ),
    "ownership_changes": (
        "Packages that changed maintainer or organisation mid-life - the "
        "classic supply-chain hijack signal. Needs a dependency-audit record; "
        "a source-only scan honestly cannot tell."
    ),
    "secrets_total": (
        "Credentials committed in plain text (API keys, tokens, private keys) "
        "with their kind attached. Treat each as an immediate rotation event: "
        "committed secrets are the harshest category in the score."
    ),
    "recurring_types": (
        "The rule families that repeat across the scan. A family with many "
        "instances usually means one underlying habit (or copy-paste template) "
        "that a single convention, linter rule or CI fix can retire wholesale."
    ),
    "containers_count": (
        "Dockerfiles and Containerfiles found in the tree - the container "
        "build surfaces the IaC scanners audited. Zero does not mean safe; it "
        "means nothing container-shaped existed here to review."
    ),
    "dep_tree_depth": (
        "The longest dependency chain in the npm lockfile. Deep trees mean "
        "more transitive code you did not choose, and slower, riskier impact "
        "analysis when an upstream package breaks or is exploited."
    ),
    "deprecated_packages": (
        "npm packages the upstream registry flags as deprecated. Deprecation "
        "means fixes will stop arriving, so each entry is a planned-replacement "
        "ticket waiting to be cut."
    ),
    "api_listing": (
        "OpenAPI/Swagger specifications detected in the tree. These describe "
        "the machine-facing surface you should map against the runtime findings "
        "when planning remediation and API reviews."
    ),
    "license_mix": (
        "FOSSology licence proportions across the scanned files. Permissive "
        "licences are information only; copyleft families (GPL/AGPL) carry "
        "obligations that can restrict how you redistribute the project."
    ),
    "heat_map": (
        "Findings per file and severity in one grid. A single dark row means "
        "one very worried file; an even spread across rows means the debt is "
        "broad and diffuse - best attacked by convention rather than heroics."
    ),
    "internet_exposure": (
        "Whether this code appears to run on an internet-facing service. "
        "Runtime or deployment metadata is required to know it honestly, so "
        "this row stays a placeholder until that data is available."
    ),
    "repo_activity_ratio": (
        "Whether the project is alive: commits in the last 90 days and the "
        "archived flag decide Active vs Dormant. Dormant repositories are "
        "waste - archive them, or budget a rescue before a scan means anything."
    ),
    "churn_value_index": (
        "Recent commit activity x code size x contributor count - one number "
        "for how much productive work this repository carries. Compare repos "
        "on the same scale when you rank where security attention pays most."
    ),
    "authored_volume_trend": (
        "Quarterly commits over the last 12 months, oldest quarter first. "
        "A rising or steady curve is a maintained project; a fading curve is "
        "a maintenance risk that usually precedes abandoned security fixes."
    ),
    "cost_of_change_proxy": (
        "The share of findings concentrated in the three hottest files. Above "
        "50% means the codebase's risk sits in few places - a rising "
        "maintenance tax that any targeted refactor can pay down quickly."
    ),
}

# ---------------------------------------------------------------------------
# Repo-file inputs gathered once per scan
# ---------------------------------------------------------------------------

_MAX_WALKED_FILES = 50_000


def collect_repo_inputs(  # defines the collect_repo_inputs() function
    root: Path,  # the repository root the relative spec paths are built from
    file_paths: Iterable[Path | str] | None = None,  # optional pre-listed files, instead of walking root
) -> dict[str, Any]:  # closes the multiline block
    """Cheap file-based inputs the scanners' own reports never carry.

    When ``file_paths`` is given the walk is skipped entirely and only the
    supplied paths are classified (the callers already know which files they
    scanned); without it the historical ``rglob`` walk over ``root`` runs,
    capped at :data:`_MAX_WALKED_FILES` entries either way.
    """
    root = Path(root)  # makes the path form
    containers = 0  # counts Dockerfile/Containerfile names
    api_specs: list[str] = []  # the OpenAPI/Swagger spec paths, root-relative
    dep_depth: int | None = None  # npm dependency-tree depth, lockfile optional
    deprecated: list[str] = []  # lockfile-flagged package names

    def classify(path: Path) -> None:  # defines the small classifier
        nonlocal containers  # the counter is rebased by the closure
        if not path.is_file():  # evaluates the branch condition
            return  # directories are never container names
        lowered = path.name.lower()  # lowercases the leaf name
        if lowered.startswith("dockerfile") or lowered.startswith("containerfile"):  # evaluates the branch condition
            containers += 1  # counts one more container file
        elif lowered in {  # checks the spec name set
            "openapi.json", "openapi.yaml", "openapi.yml",
            "swagger.json", "swagger.yaml", "swagger.yml",
        }:  # closes the multiline block
            try:  # watches for paths outside the root
                relative = path.relative_to(root).as_posix()  # keeps today's root-relative shape
            except ValueError:  # handles the raised error
                relative = path.as_posix()  # falls back to the verbatim path
            api_specs.append(relative)  # appends the spec path

    walked = 0  # counts the visited entries for the walk cap
    if file_paths is None:  # no pre-listed files: walk the tree as always
        for path in root.rglob("*"):  # loops over the collection
            walked += 1  # runs the counter
            if walked > _MAX_WALKED_FILES:  # evaluates the branch condition
                break  # stops at the safety cap
            classify(path)  # classifies the entry
    else:  # covers the remaining branch
        for path in file_paths:  # loops over the pre-listed paths
            walked += 1  # runs the counter
            if walked > _MAX_WALKED_FILES:  # evaluates the branch condition
                break  # stops at the safety cap
            classify(Path(path))  # classifies the given path

    lockfile = root / "package-lock.json"  # builds the lockfile path
    if lockfile.exists():  # evaluates the branch condition
        lock = _parse_lockfile(lockfile)  # parses the lockfile
        if isinstance(lock, dict):  # evaluates the branch condition
            dep_depth = _dependency_depth(lock)  # runs the depth walk
            deprecated = _deprecated_packages(lock)  # collects the flagged names

    return {  # returns the gathered inputs
        "containers": containers,  # maps the containers dictionary entry
        "api_specs": sorted(api_specs),  # maps the api_specs dictionary entry
        "dep_tree_depth": dep_depth,  # maps the dep_tree_depth dictionary entry
        "deprecated": sorted(set(deprecated)),  # maps the deprecated dictionary entry
    }  # closes the multiline block


def _parse_lockfile(lockfile: Path) -> dict[str, Any] | None:
    try:
        return json.loads(lockfile.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return None


def _lock_graph(lock: dict[str, Any]) -> dict[str, list[str]]:
    """Package -> child package names, from an npm v1/2/3 lockfile."""
    graph: dict[str, list[str]] = {}
    packages = lock.get("packages") or {}
    if packages:
        for name, info in packages.items():
            if not isinstance(info, dict) or not name:
                continue  # "" is the manifest root, not a dependency link
            clean = str(name).removeprefix("node_modules/")
            deps = info.get("dependencies") or {}
            graph[clean] = [
                str(dep).removeprefix("node_modules/") for dep in deps
            ]
    else:
        # npm v1: a nested tree of dependency objects.
        stack = list((lock.get("dependencies") or {}).items())
        while stack:
            name, node = stack.pop()
            if not isinstance(node, dict):
                continue
            graph[str(name)] = [str(child) for child in (node.get("dependencies") or {})]
            stack.extend((node.get("dependencies") or {}).items())
    return graph


def _dependency_depth(lock: dict[str, Any]) -> int | None:
    """Longest dependency chain; cycles are cut at the node they start from."""
    try:
        graph = _lock_graph(lock)
        depth_cache: dict[str, int] = {}

        def depth_of(node: str, walking: frozenset[str]) -> int:
            cached = depth_cache.get(node)
            if cached is not None:
                return cached
            best = 0
            for child in graph.get(node) or []:
                if child in walking or child not in graph:
                    continue
                best = max(best, depth_of(child, walking | {node}))
            depth_cache[node] = best + 1
            return best + 1

        chain_lengths = [depth_of(name, frozenset()) for name in graph]
        return max(chain_lengths) - 1 if chain_lengths else 0
    except RecursionError:
        return None


def _deprecated_packages(lock: dict[str, Any]) -> list[str]:
    """Package names npm's lockfile explicitly flags as deprecated."""
    out: list[str] = []
    sources: list[Iterable[Any]] = []
    if isinstance(lock.get("packages"), dict):
        sources.append(lock["packages"].values())
    stack: list[Any] = [lock.get("dependencies") or {}]
    while stack:
        tree = stack.pop()
        if isinstance(tree, dict):
            sources.append(v for v in tree.values())
            stack.extend(v for v in tree.values() if isinstance(v, dict))
    for entries in sources:
        for info in entries:
            if isinstance(info, dict) and info.get("deprecated"):
                out.append(str(info.get("name") or info.get("version") or "unnamed"))
    return out


_DORMANT_AFTER_DAYS = 90  # gap without a commit before a repo counts as dormant

# Git-history widgets read the Care-and-Feeding material (`report["care"]`,
# `report["care_raw"]`) that scanners.fetch_care_and_feeding already gathered
# from the GitHub REST API, so nothing new is fetched: the ratio, index, curve
# and hotspot share are pure arithmetic over data every scan carries.


def _quarter_totals(weeks: list[dict[str, Any]]) -> list[tuple[str, int]]:
    """Weekly Git commits bucketed into four quarters of the last 12 months.

    Oldest quarter first so a bar rendered in row order reads as a curve.
    Thin history is padded on the left so short-lived repos still show where
    their (little) activity sits in time.
    """
    totals = [int(item.get("total") or 0) for item in weeks[-52:]]
    while len(totals) < 52:
        totals.insert(0, 0)
    rows: list[tuple[str, int]] = []
    for index, chunk in enumerate((
        totals[start : start + 13] for start in range(0, 52, 13)
    )):
        suffix = " (newest)" if index == 3 else (" (oldest)" if index == 0 else "")
        rows.append((f"Q{index + 1}{suffix}", sum(chunk)))
    return rows


def _hotspot_state(share: float) -> tuple[str, str]:
    """(verdict, colour) for the hotspot concentration share."""
    if share > 50:
        return "concentrated: a rising maintenance tax", "#f87171"
    if share > 25:
        return "mildly concentrated", "#fbbf24"
    return "broadly spread: healthy", "#22c55e"


# ---------------------------------------------------------------------------
# Payload helpers
# ---------------------------------------------------------------------------


def _clip(text: Any, limit: int) -> str:  # defines the _clip() function
    """Shared single-ellipsis clip (see :mod:`textutil`)."""  # keeps the docstring text
    return textutil.clip_raw(text, limit)  # returns the clipped value


def _colour(index: int) -> str:
    return BAR_COLOURS[index % len(BAR_COLOURS)]


def _bar_payload(
    label: str,
    rows: list[tuple[str, int]],
    colour: str | None = None,
    note: str = "",
) -> dict[str, Any]:
    single_colour = colour or _colour(0)
    bars = [
        (_clip(text, 34), value, single_colour)
        for text, value in rows
        if value
    ]
    bars.sort(key=lambda item: -item[1])
    return {
        "label": label,
        "kind": "bar",
        "rows": bars,
        "max": max([value for _, value, _ in bars], default=1),
        "note": note,
    }


def _bar_text(rows, max_value: float, width: int = 24) -> list[str]:
    """ASCII horizontal bars for the text/CLI report."""
    lines: list[str] = []
    for label, value, _colour in rows or []:
        try:
            filled = int(round(width * (float(value) / max_value))) if max_value else 0
        except (TypeError, ValueError):
            filled = 0
        lines.append(f"{label:<30}{'#' * filled} {value}")
    return lines


def render_text(payloads: dict[str, dict[str, Any]]) -> list[str]:
    """Lines for the plain-text report (an ASCII version of every widget)."""
    lines: list[str] = []
    for payload in payloads.values():
        kind = payload.get("kind")
        lines.append(f"{str(payload.get('label', '')).upper()}:")
        if kind == "number":
            lines.append(f"    {payload.get('value', 0)}  ({payload.get('caption', '')})")
        elif kind == "bar":
            rows = [(label, value, colour) for label, value, colour in payload.get("rows") or []]
            lines.extend(f"    {line}" for line in _bar_text(rows, payload.get("max", 1)))
            note = payload.get("note") or ""
            if note:
                lines.append(f"    ({note})")
        elif kind == "donut":
            shares = float(payload.get("max") or 1)
            unit = str(payload.get("unit") or "files")
            for label, value, _colour in payload.get("rows") or []:
                pct = round(100 * float(value) / shares) if shares else 0
                lines.append(f"    {label:<22}{pct:>4}%  ({value} {unit})")
            note = payload.get("note") or ""
            if note:
                lines.append(f"    ({note})")
        elif kind == "heat":
            sevs = payload.get("sevs") or []
            rows = list(payload.get("rows") or [])
            if not sevs or not rows:
                lines.append("    (nothing to plot)")
                continue
            header = "".join(f"{sev[0].upper():>5}" for sev in sevs)
            lines.append(f"    {'file':<42}{header}")
            for file_id, buckets in rows:
                cells = "".join(f"{int(buckets.get(sev, 0)):>5d}" for sev in sevs)
                lines.append(f"    {file_id:<42}{cells}")
            note = payload.get("note") or ""
            if note:
                lines.append(f"    ({note})")
        elif kind == "table":
            for row in payload.get("rows") or []:
                lines.append("    " + "  ·  ".join(str(cell) for cell in row))
            note = payload.get("note") or ""
            if note:
                lines.append(f"    ({note})")
        elif kind == "na":
            lines.append(f"    (not assessable here: {payload.get('note', '')})")
        lines.append("")
    if lines:
        lines.pop()  # drops the trailing blank line
    return lines


def _histogram_payload(
    label: str,
    values: list[float],
    buckets: list[tuple[str, float, float]],
    note: str,
) -> dict[str, Any]:
    bars = []
    for (name, low, high), colour in zip(buckets, BAR_COLOURS):
        bars.append((name, sum(1 for v in values if low <= v < high), colour))
    return {
        "label": label,
        "kind": "bar",
        "rows": [item for item in bars if item[1]],
        "max": max([value for _n, value, _c in bars], default=1),
        "note": note,
    }


def _language_of(file_id: str) -> str:
    suffix = Path(str(file_id or "")).suffix.lower()
    return config.EXTENSION_LANGUAGES.get(suffix, "other")


# ---------------------------------------------------------------------------
# Lazy metric aggregate
# ---------------------------------------------------------------------------


class _Metrics:  # defines the _Metrics class
    """Lazily computed, memoized findin-aggregate counters for one report walk-set.

    Every aggregate is a keyed builder: only the counters a ticked widget
    needs are ever computed, and each exactly once (the cache holds the
    result). The snapshots are pure functions of the constructor arguments,
    so payload values match the previously eager implementation digit for
    digit.
    """

    _BUILDERS: tuple[str, ...] = (  # the aggregate names collect_metrics may ask for
        "vulns",  # the vulnerability-category findings
        "secrets",  # the secret-category findings
        "sev_counts",  # findings per severity
        "cwe_counts",  # findings per CWE class
        "tool_counts",  # findings per reporting tool
        "file_counts",  # findings per file
        "rule_counts",  # findings per rule family
        "language_counts",  # findings per file language
        "cvss_values",  # the CVSS scores the findings carry
        "epss_values",  # the EPSS scores the findings carry
        "kev_findings",  # the CISA KEV-listed findings
        "dated",  # the dated findings, oldest first
        "git_weeks",  # the commit-activity weeks in chronological order
        "top_files",  # the ten most-flagged files
        "heat_sevs",  # the severity columns worth drawing
        "heat_rows",  # per-file severity buckets for the heat map
        "size_files",  # the scanned file count behind the churn index
    )  # closes the multiline block

    def __init__(  # defines the __init__() function
        self,  # evaluates the self expression
        findings: list[dict[str, Any]],  # the open (non-omitted) findings
        report: dict[str, Any],  # the finished scan report
    ) -> None:  # closes the multiline block
        self.findings = findings  # saves the findings list
        self.report = report  # saves the report handle
        self._cache: dict[str, Any] = {}  # the computed-once cache

    def get(self, name: str) -> Any:  # defines the get() function
        """One aggregate, computed at most once per instance."""
        if name not in self._cache:  # evaluates the branch condition
            self._cache[name] = getattr(self, f"_{name}")()  # computes and stores
        return self._cache[name]  # returns the snapshot

    # -- individual builders (each a pure function of the snapshots) ------
    def _vulns(self) -> list[dict[str, Any]]:  # defines the _vulns() function
        return [f for f in self.findings if f.get("category") == "vulnerability"]  # filters the vulns

    def _secrets(self) -> list[dict[str, Any]]:  # defines the _secrets() function
        return [f for f in self.findings if f.get("category") == "secret"]  # filters the secrets

    def _sev_counts(self) -> Counter:  # defines the _sev_counts() function
        return Counter(str(f.get("severity") or "unknown") for f in self.findings)  # tallies the severities

    def _cwe_counts(self) -> Counter:  # defines the _cwe_counts() function
        return Counter(f.get("cwe") or "" for f in self.get("vulns"))  # tallies the CWE classes

    def _tool_counts(self) -> Counter:  # defines the _tool_counts() function
        counts = Counter()  # counts findings per reporting tool
        for item in self.findings:  # walks the findings
            for tool in item.get("tools") or [item.get("tool") or "unknown-tool"]:  # loops over the tools
                counts[tool] += 1  # adds an item to the set
        return counts  # returns the counter

    def _file_counts(self) -> Counter:  # defines the _file_counts() function
        return Counter(f.get("file") or "?known location" for f in self.findings)  # counts findings per file

    def _rule_counts(self) -> Counter:  # defines the _rule_counts() function
        return Counter(f.get("rule_id") or f.get("title") or "rule" for f in self.findings)  # counts the rules

    def _language_counts(self) -> Counter:  # defines the _language_counts() function
        return Counter(  # counts the findings per language
            _language_of(f.get("file")) for f in self.findings if f.get("file")  # fetches the value
        )  # closes the multiline block

    def _cvss_values(self) -> list[float]:  # defines the _cvss_values() function
        return [float(f.get("cvss")) for f in self.findings if f.get("cvss")]  # gathers the scores

    def _epss_values(self) -> list[float]:  # defines the _epss_values() function
        return [float(f.get("epss")) for f in self.findings if f.get("epss")]  # gathers the scores

    def _kev_findings(self) -> list[dict[str, Any]]:  # defines the _kev_findings() function
        return [f for f in self.findings if f.get("kev")]  # filters the KEV rows

    def _dated(self) -> list[dict[str, Any]]:  # defines the _dated() function
        return sorted(  # sorts the values
            (f for f in self.findings if f.get("published")),  # keeps the dated rows
            key=lambda f: str(f.get("published")),  # str-sorts chronologically
        )  # closes the multiline block

    def _git_weeks(self) -> list[dict[str, Any]]:  # defines the _git_weeks() function
        return sorted(  # chronology matters: the trend curve is drawn in order
            (
                item
                for item in (self.report.get("care_raw") or {}).get("commit_activity") or []  # the raw weekly blobs
                if isinstance(item, dict) and item.get("week")  # evaluates the branch condition
            ),
            key=lambda item: item["week"],  # sorts by the week stamp
        )  # closes the multiline block

    def _top_files(self) -> list[str]:  # defines the _top_files() function
        return [file_id for file_id, _ in self.get("file_counts").most_common(10)]  # picks the ten busiest

    def _heat_sevs(self) -> list[str]:  # defines the _heat_sevs() function
        counts = self.get("sev_counts")  # reads the severity counter
        return [sev for sev in _SEV_ORDER if counts.get(sev)]  # keeps the drawn columns

    def _heat_rows(self) -> list[tuple[str, dict[str, int]]]:  # defines the _heat_rows() function
        """Per-file severity buckets for the hottest files, in one pass."""
        top_files = self.get("top_files")  # reads the busiest files
        buckets: dict[str, dict[str, int]] = {file_id: {} for file_id in top_files}  # the per-file tallies
        wanted = set(top_files)  # the membership set for the single pass
        for finding in self.findings:  # walks the findings once
            file_id = finding.get("file")  # reads the file value
            if file_id not in wanted:  # evaluates the branch condition
                continue  # skips the long tail
            severity = finding.get("severity")  # reads the severity value
            if severity:  # evaluates the branch condition
                per_file = buckets[file_id]  # fetches the file's tallies
                per_file[severity] = per_file.get(severity, 0) + 1  # bumps the bucket
        return [  # returns the ordered (file, buckets) rows
            (_clip(file_id, 40), {sev: buckets[file_id].get(sev, 0) for sev in self.get("heat_sevs")})  # fetches the value
            for file_id in top_files  # keeps the most-common order
        ]  # closes the multiline block

    def _size_files(self) -> int:  # defines the _size_files() function
        return sum(  # adds up the values
            int(count or 0) for count in (self.report.get("language_file_counts") or {}).values()  # fetches the value
        )  # closes the multiline block


# ---------------------------------------------------------------------------
# Collect payloads for the ticked widgets
# ---------------------------------------------------------------------------


def collect_metrics(
    report: dict[str, Any], selected: Iterable[str]
) -> dict[str, dict[str, Any]]:
    """Build one payload per ticked metric; every box unticked gives ``{}``.

    The aggregate counters behind the payloads are built lazily through
    :class:`_Metrics`, so an unticked widget's numbers are never computed and
    a ticked widget's counters are never computed twice.
    """
    findings = report.get("findings") or []  # fetches the findings
    findings = [f for f in findings if not f.get("omitted")]  # excluded themes leave the widgets
    metrics = _Metrics(findings, report)  # the lazy aggregate for this call

    care_summary = report.get("care") or {}  # Git history, already summarised
    repo_meta = report.get("repo") or {}  # archived flag lives here

    total = len(findings)  # the open finding count
    language_files = report.get("language_file_counts") or {}  # the per-language file counts
    extra = report.get("dashboard_inputs") or {}  # the gathered repo-file inputs

    payloads: dict[str, dict[str, Any]] = {}
    for key in validate(selected):
        label = config.DASHBOARD_METRICS[key][0]

        if key == "total_vulnerabilities":  # the big top-left figure
            vulns = metrics.get("vulns")  # fetches the vulnerability rows
            payloads[key] = {
                "label": label,
                "kind": "number",
                "value": len(vulns),
                "caption": f"of {total} findings total",
                "colour": "#f87171" if vulns else "#22c55e",
            }
        elif key == "severity_counts":  # bars per severity
            sev_counts = metrics.get("sev_counts")  # fetches the counter
            bars = [
                (sev.upper(), sev_counts.get(sev, 0), _SEV_COLOURS[sev])
                for sev in _SEV_ORDER
                if sev_counts.get(sev)
            ]
            payloads[key] = {
                "label": label,
                "kind": "bar",
                "rows": bars,
                "max": max([v for _, v, _ in bars], default=1),
                "note": f"{total} findings overall",
            }
        elif key == "by_cwe":  # CWE weakness classes
            cwe_counts = metrics.get("cwe_counts")  # fetches the counter
            rows = [
                (cwe or "CWE not reported", count, _colour(index))
                for index, (cwe, count) in enumerate(cwe_counts.most_common(8))
            ]
            payloads[key] = {
                "label": label,
                "kind": "bar",
                "rows": rows,
                "max": max([count for _, count, _ in rows], default=1),
                "note": f"{len(cwe_counts)} distinct CWE class(es)" if cwe_counts else "no CWE data",
            }
        elif key == "by_scanner":  # per-scanner attribution
            tool_counts = metrics.get("tool_counts")  # fetches the counter
            rows = [
                (config.TOOL_LABELS.get(tool, tool.title()), count)
                for tool, count in tool_counts.most_common()
            ]
            payloads[key] = _bar_payload(label, rows, "#60a5fa", f"{len(rows)} scanner(s) reported")
        elif key == "by_language":  # findings per file language
            rows = [
                (lang, count) for lang, count in metrics.get("language_counts").most_common(10)  # fetches the counter
            ]
            payloads[key] = _bar_payload(label, rows, "#60a5fa", "")
        elif key == "top_files":  # most-troubled files
            file_counts = metrics.get("file_counts")  # fetches the counter
            rows = [
                (_clip(file_id, 34), count)
                for file_id, count in file_counts.most_common(10)
            ]
            payloads[key] = _bar_payload(label, rows, "#fbbf24", f"{len(file_counts)} file(s) flagged")
        elif key == "cvss_scores":  # CVSS base-score histogram
            cvss_values = metrics.get("cvss_values")  # fetches the scores
            payloads[key] = _histogram_payload(
                label, cvss_values,
                [("0-3", 0, 3), ("3-6", 3, 6), ("6-8", 6, 8), ("8-10", 8, 10.0001)],
                note=f"{total - len(cvss_values)} finding(s) carry no CVSS score",
            )
        elif key == "epss_scores":  # EPSS likelihood histogram
            epss_values = metrics.get("epss_values")  # fetches the scores
            payloads[key] = _histogram_payload(
                label, epss_values,
                [("0-25%", 0, 0.25), ("25-50%", 0.25, 0.5),
                 ("50-75%", 0.5, 0.75), ("75-100%", 0.75, 1.01)],
                note=f"{total - len(epss_values)} finding(s) carry no EPSS data",
            )
        elif key == "kev_status":  # CISA known-exploited vulnerabilities
            kev_findings = metrics.get("kev_findings")  # fetches the KEV rows
            if kev_findings:
                payloads[key] = {
                    "label": label,
                    "kind": "number",
                    "value": len(kev_findings),
                    "caption": "CISA KEV: "
                    + "; ".join(
                        _clip(f.get("title") or f.get("package") or f.get("rule_id") or "CVE", 24)
                        for f in kev_findings[:3]
                    ),
                    "colour": "#f87171",
                }
            else:
                payloads[key] = {
                    "label": label,
                    "kind": "na",
                    "note": "no CISA KEV entries among the scanned dependencies",
                }
        elif key == "oldest_10":  # sorted by publish date
            dated = metrics.get("dated")  # fetches the dated rows
            rows = [
                (
                    _clip(f.get("title") or f.get("package") or "CVE", 40),
                    str(f.get("published") or "")[:10],
                    str(f.get("severity") or "unknown").upper(),
                )
                for f in dated[:10]
            ]
            payloads[key] = {
                "label": label,
                "kind": "table",
                "columns": ("Vulnerability", "Published", "Severity"),
                "rows": rows,
                "note": f"{len(dated)} dated finding(s)" if dated else "engines supplied no publish dates",
            }
        elif key == "languages_detected":  # donut of language file counts
            slices = [
                (lang, count, _colour(index))
                for index, (lang, count) in enumerate(language_files.items())
            ]
            payloads[key] = {
                "label": label,
                "kind": "donut",
                "rows": slices,
                "note": f"{sum(c for _, c, _ in slices)} file(s) across {len(slices)} language(s)",
            }
        elif key == "ownership_changes":
            payloads[key] = {
                "label": label,
                "kind": "na",
                "note": "ownership changes need a dependency-audit record; a source-only scan cannot tell",
            }
        elif key == "secrets_total":  # big secret figure
            secrets = metrics.get("secrets")  # fetches the secret rows
            payloads[key] = {
                "label": label,
                "kind": "number",
                "value": len(secrets),
                "caption": f"{total - len(secrets)} other findings alongside",
                "colour": "#fbbf24" if secrets else "#22c55e",
            }
        elif key == "recurring_types":
            rule_counts = metrics.get("rule_counts")  # fetches the counter
            rows = [
                (_clip(rule, 34), count) for rule, count in rule_counts.most_common(5)
            ]
            payloads[key] = _bar_payload(label, rows, "#fb923c", "most frequent rule families")
        elif key == "containers_count":
            count = int(extra.get("containers") or 0)
            payloads[key] = {
                "label": label,
                "kind": "number",
                "value": count,
                "caption": "Dockerfile/Containerfile files found",
                "colour": "#60a5fa" if count else "#8ba3c2",
            }
        elif key == "dep_tree_depth":
            depth = extra.get("dep_tree_depth")
            if depth is None:
                payloads[key] = {
                    "label": label,
                    "kind": "na",
                    "note": "no npm package-lock.json to walk",
                }
            else:
                payloads[key] = {
                    "label": label,
                    "kind": "number",
                    "value": depth,
                    "caption": "dependency levels in package-lock.json",
                    "colour": "#22c55e",
                }
        elif key == "deprecated_packages":
            items = list(extra.get("deprecated") or [])
            payloads[key] = {
                "label": label,
                "kind": "number",
                "value": len(items),
                "caption": ", ".join(_clip(name, 20) for name in items[:3])
                if items else "none flagged in the npm lockfile",
                "colour": "#fbbf24" if items else "#22c55e",
            }
        elif key == "api_listing":
            specs = list(extra.get("api_specs") or [])
            payloads[key] = {
                "label": label,
                "kind": "table",
                "columns": ("Detected API specification",),
                "rows": [(spec,) for spec in specs[:10]],
                "note": f"{len(specs)} OpenAPI/Swagger spec(s)" if specs else "no OpenAPI/Swagger specs found",
            }
        elif key == "license_mix":
            mix = {  # ordered by count through the donut's own sorting
                _clip(name, 24): int(count)
                for name, count in (extra.get("license_mix") or {}).items()
            }
            if mix:  # FOSSology ran and reported a component licence mix
                slices = [  # the largest families, in scan order
                    (name, count, _colour(index))
                    for index, (name, count) in enumerate(mix.items())
                ]  # closes the slices build
                payloads[key] = {
                    "label": label,
                    "kind": "donut",
                    "rows": slices[:10],  # the ten largest licence families
                    "unit": "files",
                    "note": f"{sum(mix.values())} licensed file(s) across {len(mix)} licence(s)",
                }
            else:  # no FOSSology server configured, or it was not selected
                payloads[key] = {
                    "label": label,
                    "kind": "na",
                    "note": "licence mix needs the FOSSology scanner (set FOSSOLOGY_SERVER "
                    "and FOSSOLOGY_TOKEN and tick FOSSology)",
                }
        elif key == "heat_map":
            heat_rows = metrics.get("heat_rows")  # the per-file buckets
            payloads[key] = {
                "label": label,
                "kind": "heat",
                "rows": heat_rows,  # the grid rows
                "sevs": metrics.get("heat_sevs"),  # the drawn columns
                "note": f"{len(heat_rows)} most-flagged file(s)",
            }
        elif key == "internet_exposure":
            payloads[key] = {
                "label": label,
                "kind": "na",
                "note": "exposure needs runtime/deployment metadata; "
                "a source-only scan cannot assert it",
            }
        elif key == "repo_activity_ratio":
            if not care_summary:
                payloads[key] = {
                    "label": label,
                    "kind": "na",
                    "note": "no Git history was fetched for this repository",
                }
            else:
                archived = bool(repo_meta.get("archived"))
                last_days = care_summary.get("last_commit_days")
                commits_90d = int(care_summary.get("commits_last_90d") or 0)
                active = (not archived) and (
                    commits_90d > 0
                    or (last_days is not None and last_days <= _DORMANT_AFTER_DAYS)
                )
                state = "Active" if active else "Dormant"
                if active:
                    state_colour = "#22c55e"
                else:
                    state_colour = "#f87171" if archived else "#fbbf24"
                if archived:
                    caption_note = "archived repository"
                else:
                    caption_note = (
                        f"last commit {int(last_days)} days ago"
                        if last_days is not None
                        else "last commit date unavailable"
                    )
                payloads[key] = {
                    "label": label,
                    "kind": "number",
                    "value": state,
                    "caption": f"{caption_note} · {commits_90d} commits in 90 days",
                    "colour": state_colour,
                }
        elif key == "churn_value_index":
            activity = care_summary.get("commits_last_90d")
            people = care_summary.get("contributors")
            size_files = metrics.get("size_files")  # the scanned file count
            if activity is None and people is None:
                payloads[key] = {
                    "label": label,
                    "kind": "na",
                    "note": "no Git history or contributor data for this repo",
                }
            elif size_files <= 0:
                payloads[key] = {
                    "label": label,
                    "kind": "na",
                    "note": "no files were scanned, so there is no size to weigh",
                }
            else:
                people_used = (
                    int(people)
                    if people is not None
                    else int(care_summary.get("contributors_recent") or 0)
                )
                activity_used = int(activity or 0)
                index = activity_used * size_files * people_used
                people_note = (
                    f"contributors: {people_used} (recent-commit sample)"
                    if people is None
                    else f"contributors: {people_used}"
                )
                payloads[key] = {
                    "label": label,
                    "kind": "number",
                    "value": index,
                    "caption": f"{activity_used} commits(90d) × {size_files} files × "
                    f"{people_note}",
                    "colour": "#22c55e" if index else "#8ba3c2",
                }
        elif key == "authored_volume_trend":
            git_weeks = metrics.get("git_weeks")  # fetches the weekly blob
            if not git_weeks:
                payloads[key] = {
                    "label": label,
                    "kind": "na",
                    "note": "no weekly commit history came back from the Git API",
                }
            else:
                quarters = _quarter_totals(git_weeks)
                year_total = sum(value for _q, value in quarters)
                newest = quarters[-1][1]
                share = round(100 * newest / year_total) if year_total else 0
                payloads[key] = {
                    "label": label,
                    "kind": "bar",
                    # row order is kept chronological on purpose (oldest → newest
                    # quarters): the curve, not a ranking
                    "rows": [
                        (name, value, colour)
                        for (name, value), colour in zip(quarters, BAR_COLOURS)
                    ],
                    "max": max([value for _q, value in quarters], default=1),
                    "note": f"{year_total} commits in 12 months; the newest "
                    f"quarter holds {share}% of them",
                }
        elif key == "cost_of_change_proxy":
            hot_total = sum(  # totals found in the top 3 hotspot files
                count for _file_id, count in metrics.get("file_counts").most_common(3)  # fetches the counter
            )
            if not hot_total:
                payloads[key] = {
                    "label": label,
                    "kind": "na",
                    "note": "no findings were reported, so no change hotspot exists",
                }
            else:
                share = round(100 * hot_total / total) if total else 0
                verdict, colour = _hotspot_state(share)
                payloads[key] = {
                    "label": label,
                    "kind": "donut",
                    "rows": [
                        ("Top 3 hotspots", share, colour),
                        ("Everything else", 100 - share, "#8ba3c2"),
                    ],
                    "note": f"{total} findings over {len(metrics.get('file_counts'))} file(s); "
                    f"{share}% in the hottest 3 — {verdict}",
                }
    return payloads
