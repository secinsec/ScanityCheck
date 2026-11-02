"""Convert raw scanner output into one weighted score.

The model is deliberately simple to explain to a human:

    score = 100 - sum(capped penalty per category)

Every finding contributes a penalty based on its category and severity; the
per-category caps in :mod:`config` prevent one noisy scanner from dominating.
Findings about the same underlying issue are merged across scanners so they are
charged once while still recording every tool that detected them.
"""

from __future__ import annotations  # imports annotations from the __future__ module

import dataclasses  # imports the dataclasses module (field introspection)
import json  # imports the json module
import math  # imports the math module (the density log curve)
import re  # imports the re module (kept for the scanner parsers below)
import urllib.parse  # imports the urllib.parse module
from dataclasses import dataclass, field, replace  # imports dataclass, field, replace from the dataclasses module
from datetime import datetime, timezone  # imports datetime, timezone from the datetime module
from pathlib import Path  # imports Path from the pathlib module
from typing import Any, Iterable, Iterator, NamedTuple  # imports typing helpers

import care  # imports the care module
import compliance  # imports the compliance module
import config  # imports the config module
import dashboard as dashboard_module  # imports dashboard as dashboard_module from the dashboard module
import reportkeys  # imports the shared keys/ranks/category registry
import textutil  # imports the shared clip/clean helpers
from care import summarize as summarize_care  # imports summarize as summarize_care from the care module

# --------------------------------------------------------------------------
# Severity helpers
# --------------------------------------------------------------------------

_SEVERITY_ALIASES = {  # assigns the computed value to _SEVERITY_ALIASES
    "critical": "critical",  # maps the critical dictionary entry
    "crit": "critical",  # maps the crit dictionary entry
    "high": "high",  # maps the high dictionary entry
    "important": "high",  # maps the important dictionary entry
    "error": "high",  # maps the error dictionary entry
    "medium": "medium",  # maps the medium dictionary entry
    "moderate": "medium",  # maps the moderate dictionary entry
    "warning": "medium",  # maps the warning dictionary entry
    "low": "low",  # maps the low dictionary entry
    "minor": "low",  # maps the minor dictionary entry
    "note": "low",  # maps the note dictionary entry
    "negligible": "low",  # maps the negligible dictionary entry
    "unknown": "unknown",  # maps the unknown dictionary entry
    "unspecified": "unknown",  # maps the unspecified dictionary entry
    "none": "unknown",  # maps the none dictionary entry
    "info": "unknown",  # maps the info dictionary entry
    "informational": "unknown",  # maps the informational dictionary entry
}  # closes the multiline block


def normalize_severity(value: Any) -> str:  # defines the normalize_severity() function
    """Map any scanner's severity spelling onto critical/high/medium/low/unknown."""  # keeps the docstring text
    text = str(value or "").strip().lower()  # runs the str() call
    return _SEVERITY_ALIASES.get(text, "unknown")  # returns the _SEVERITY_ALIASES.get to the caller


def severity_rank(severity: str) -> int:  # defines the severity_rank() function
    """Lower is worse. Useful for sorting (shared implementation)."""  # keeps the docstring text
    return reportkeys.severity_rank(severity)  # returns the shared rank lookup


# The shared reporting vocabulary, re-exported for every report consumer.
SCORING_CATEGORIES: tuple[str, ...] = reportkeys.SCORING_CATEGORIES  # the five weighted categories
RISK_CATEGORIES: tuple[str, ...] = reportkeys.RISK_CATEGORIES  # the four critical-count categories


def cvss_to_severity(score: float) -> str:  # defines the cvss_to_severity() function
    if score >= 9.0:  # evaluates the branch condition
        return "critical"  # returns the value to the caller
    if score >= 7.0:  # evaluates the branch condition
        return "high"  # returns the value to the caller
    if score >= 4.0:  # evaluates the branch condition
        return "medium"  # returns the value to the caller
    if score > 0:  # evaluates the branch condition
        return "low"  # returns the value to the caller
    return "unknown"  # returns the value to the caller


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------


@dataclass  # applies the dataclass decorator
class Finding:  # defines the Finding class
    """A single actionable result from any scanner.

    ``source`` is the scanner that produced the finding; ``tools`` is the set
    of scanners that reported the same issue after cross-tool de-duplication.
    ``file``/``line`` keep the location structured so it can be shown in the
    UI and merged reliably; ``location`` is the ready-to-render string.
    """

    source: str  # tool id, e.g. "trivy", "semgrep", "gitleaks"  # evaluates the source expression
    category: str  # vulnerability | secret | misconfiguration | code | code-quality  # evaluates the category expression
    severity: str  # evaluates the severity expression
    rule_id: str  # evaluates the rule_id expression
    title: str  # evaluates the title expression
    location: str = ""  # evaluates the location expression
    detail: str = ""  # evaluates the detail expression
    reference: str = ""  # evaluates the reference expression
    weight: float = 0.0  # evaluates the weight expression
    file: str = ""  # evaluates the file expression
    line: int = 0  # evaluates the line expression
    package: str = ""  # package name for dependency findings  # evaluates the package expression
    cwe: str = ""  # first CWE id, used for code-finding de-duplication  # evaluates the cwe expression
    kind: str = ""  # coarse secret/config family, used for de-duplication  # evaluates the kind expression
    aliases: list[str] = field(default_factory=list)  # runs the field() call
    tools: list[str] = field(default_factory=list)  # runs the field() call
    locations: list[str] = field(default_factory=list)  # runs the field() call
    cvss: float = 0.0  # CVSS base score when an engine supplies one
    epss: float = 0.0  # EPSS exploitation likelihood when provided
    kev: bool = False  # listed in the CISA known-exploited catalog
    published: str = ""  # vulnerability publication date (ISO), when known

    def __post_init__(self) -> None:  # defines the __post_init__() function
        if not self.tools:  # evaluates the branch condition
            self.tools = [self.source]  # starts the list on tools
        if self.location and self.location not in self.locations:  # evaluates the branch condition
            self.locations = [self.location]  # starts the list on locations

    @property  # applies the property decorator
    def tool_labels(self) -> list[str]:  # defines the tool_labels() function
        return [config.TOOL_LABELS.get(tool, tool.title()) for tool in self.tools]  # returns the value to the caller

    def to_dict(self) -> dict[str, Any]:  # defines the to_dict() function
        return {  # returns the value to the caller
            "source": self.source,  # maps the source dictionary entry
            "tool": self.source,  # maps the tool dictionary entry
            "tool_label": config.TOOL_LABELS.get(self.source, self.source.title()),  # maps the tool_label dictionary entry
            "tools": list(self.tools),  # maps the tools dictionary entry
            "tool_labels": self.tool_labels,  # maps the tool_labels dictionary entry
            "category": self.category,  # maps the category dictionary entry
            "severity": self.severity,  # maps the severity dictionary entry
            "rule_id": self.rule_id,  # maps the rule_id dictionary entry
            "title": self.title,  # maps the title dictionary entry
            "location": self.location,  # maps the location dictionary entry
            "locations": list(self.locations),  # maps the locations dictionary entry
            "file": self.file,  # maps the file dictionary entry
            "line": self.line,  # maps the line dictionary entry
            "package": self.package,  # maps the package dictionary entry
            "cwe": self.cwe,  # maps the cwe dictionary entry
            "kind": self.kind,  # maps the kind dictionary entry
            "detail": self.detail,  # maps the detail dictionary entry
            "reference": self.reference,  # maps the reference dictionary entry
            "weight": round(self.weight, 2),  # maps the weight dictionary entry
            "cvss": self.cvss,  # maps the cvss dictionary entry
            "epss": self.epss,  # maps the epss dictionary entry
            "kev": self.kev,  # maps the kev dictionary entry
            "published": self.published,  # maps the published dictionary entry
        }  # closes the multiline block


def weight_for(category: str, severity: str) -> float:  # defines the weight_for() function
    if category == "code-quality":  # evaluates the branch condition
        return config.CODE_QUALITY_WEIGHT  # returns the config.CODE_QUALITY_WEIGHT to the caller
    table = config.WEIGHTS.get(category, config.WEIGHTS["code"])  # fetches the value
    return table.get(severity, table["unknown"])  # returns the table.get to the caller


def _clean(text: Any, limit: int = 400) -> str:  # defines the _clean() function
    """Shared whitespace-collapsing clip (see :mod:`textutil`)."""  # keeps the docstring text
    return textutil.clip(text, limit)  # returns the cleaned clip


def _short_path(path: str, limit: int = 90) -> str:  # defines the _short_path() function
    if len(path) <= limit:  # evaluates the branch condition
        return path  # returns the path to the caller
    return "\u2026" + path[-(limit - 1) :]  # returns the value to the caller


def _rel_path(value: Any, root: str | Path | None) -> str:  # defines the _rel_path() function
    """Normalise a scanner path to a repo-relative forward-slash path."""  # keeps the docstring text
    text = str(value or "").strip().replace("\\", "/")  # runs the str() call
    if not text:  # evaluates the branch condition
        return ""  # returns the value to the caller
    text = text.replace("file:///", "").replace("file://", "")  # swaps the text
    if root is None:  # evaluates the branch condition
        return text  # returns the text to the caller

    try:  # watches for errors in the block
        return Path(text).resolve().relative_to(Path(root).resolve()).as_posix()  # returns the Path to the caller
    except (ValueError, OSError):  # handles the raised error
        pass  # keeps the block syntactically empty

    root_text = str(Path(root).resolve()).replace("\\", "/").rstrip("/")  # creates the path object
    if text.lower().startswith(root_text.lower() + "/"):  # evaluates the branch condition
        return text[len(root_text) + 1 :]  # returns the text to the caller
    return text.lstrip("/")  # returns the text.lstrip to the caller


def _location(file: str, line: int = 0) -> str:  # defines the _location() function
    if not file:  # evaluates the branch condition
        return ""  # returns the value to the caller
    return _short_path(f"{file}:{line}" if line else file)  # returns the _short_path to the caller


def _cwe_from_tags(tags: Iterable[Any]) -> str:  # defines the _cwe_from_tags() function
    for tag in tags or []:  # loops over the collection
        match = re.search(r"cwe-?(\d+)", str(tag), re.IGNORECASE)  # runs the search() call
        if match:  # evaluates the branch condition
            return f"CWE-{int(match.group(1))}"  # returns the f to the caller
    return ""  # returns the value to the caller


def _secret_kind(*names: Any) -> str:  # defines the _secret_kind() function
    """Collapse vendor-specific rule names so the same secret merges across tools."""  # keeps the docstring text
    text = " ".join(str(name or "") for name in names).lower()  # sets the text text
    families = (  # assigns the computed value to families
        ("private-key", ("private-key", "private_key", "privatekey", "rsa", "ssh", "pgp")),  # executes the statement
        ("aws", ("aws", "amazon")),  # executes the statement
        ("github", ("github", "ghp_", "gho_", "ghs_")),  # executes the statement
        ("gitlab", ("gitlab",)),  # executes the statement
        ("slack", ("slack",)),  # executes the statement
        ("stripe", ("stripe",)),  # executes the statement
        ("google", ("google", "gcp", "gcm-")),  # executes the statement
        ("azure", ("azure", "microsoft")),  # executes the statement
        ("jwt", ("jwt",)),  # executes the statement
        ("generic", ("generic", "api-key", "apikey", "api_key", "token", "secret")),  # executes the statement
    )  # closes the multiline block
    for family, needles in families:  # loops over the collection
        if any(needle in text for needle in needles):  # evaluates the branch condition
            return family  # returns the family to the caller
    return ""  # returns the value to the caller


def _first_cve(values: Iterable[Any], default: str = "") -> str:  # defines the _first_cve() function
    for value in values or []:  # loops over the collection
        text = str(value or "")  # runs the str() call
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE):  # evaluates the branch condition
            return text.upper()  # returns the text.upper to the caller
    return default  # returns the default to the caller


def _load_json(path: str | Path) -> Any:  # defines the _load_json() function
    """Load a scanner JSON report without assuming clean UTF-8.

    Scanner CLIs on Windows occasionally write non-UTF-8 bytes (for example a
    cp1252 curly quote copied out of a source comment), which would otherwise
    reject the whole report. UTF-8 is tried first; cp1252 is the fallback.
    """
    raw = Path(path).read_bytes()  # creates the path object
    try:  # watches for errors in the block
        text = raw.decode("utf-8-sig")  # runs the decode() call
    except UnicodeDecodeError:  # handles the raised error
        text = raw.decode("cp1252", errors="replace")  # runs the decode() call
    return json.loads(text)  # returns the json.loads to the caller


def _max_cvss(block: dict[str, Any]) -> float:  # defines the _max_cvss() function
    """Highest V3/V2 base score inside a Trivy-style CVSS block."""
    best = 0.0  # sets the best text
    for entry in block.values() or []:  # loops over the collection
        for key in ("V3Score", "V3VectorScore", "V2Score"):  # loops over the collection
            try:  # watches for errors in the block
                best = max(best, float(entry.get(key) or 0))  # runs the float() call
            except (TypeError, ValueError, AttributeError):  # handles the raised error
                continue  # skips to the next loop iteration
    return best  # returns the best to the caller


def _max_cvss_list(items: list[Any]) -> float:  # defines the _max_cvss_list() function
    """Highest base score inside Grype-style ``cvss`` entries."""
    best = 0.0  # sets the best text
    for item in items or []:  # loops over the collection
        if not isinstance(item, dict):  # evaluates the branch condition
            continue  # skips to the next loop iteration
        try:  # watches for errors in the block
            score = float((item.get("metrics") or {}).get("baseScore") or 0)  # runs the float() call
        except (TypeError, ValueError, AttributeError):  # handles the raised error
            continue  # skips to the next loop iteration
        best = max(best, score)  # updates the stored value in place
    return best  # returns the best to the caller


def _max_epss(items: Any) -> float:  # defines the _max_epss() function
    """Highest EPSS score from Grype-style ``epss`` entries."""
    best = 0.0  # sets the best text
    entries = (  # assigns the computed value to entries
        items if isinstance(items, list) else ([items] if isinstance(items, dict) else [])
    )  # closes the multiline block
    for item in entries or []:  # loops over the collection
        if not isinstance(item, dict):  # evaluates the branch condition
            continue  # skips to the next loop iteration
        try:  # watches for errors in the block
            best = max(best, float(item.get("score") or 0))  # runs the float() call
        except (TypeError, ValueError):  # handles the raised error
            continue  # skips to the next loop iteration
    return best  # returns the best to the caller


# --------------------------------------------------------------------------
# Trivy JSON
# --------------------------------------------------------------------------


def parse_trivy_report(  # defines the parse_trivy_report() function
    path: str | Path, root: str | Path | None = None  # evaluates the path expression
) -> list[Finding]:  # closes the multiline block
    """Parse ``trivy fs --format json`` output into findings."""  # keeps the docstring text
    data = _load_json(path)  # runs the _load_json() call
    findings: list[Finding] = []  # evaluates the findings expression
    seen: set[tuple[str, ...]] = set()  # updates the stored value

    for result in data.get("Results") or []:  # loops over the collection
        target = result.get("Target") or ""  # fetches the value
        target_file = _rel_path(target, root)  # runs the _rel_path() call
        for vuln in result.get("Vulnerabilities") or []:  # loops over the collection
            vuln_id = vuln.get("VulnerabilityID") or "UNKNOWN-CVE"  # fetches the value
            package = vuln.get("PkgName") or "unknown-package"  # fetches the value
            key = ("vuln", vuln_id, package)  # assigns the computed value to key
            if key in seen:  # evaluates the branch condition
                continue  # skips to the next loop iteration
            seen.add(key)  # adds an item to the set

            severity = normalize_severity(vuln.get("Severity"))  # runs the normalize_severity() call
            installed = vuln.get("InstalledVersion") or "?"  # fetches the value
            fixed = vuln.get("FixedVersion") or ""  # fetches the value
            detail = _clean(vuln.get("Title") or vuln.get("Description") or "")  # runs the _clean() call
            if fixed:  # evaluates the branch condition
                detail = f"{detail} Fixed in {fixed}.".strip()  # sets the detail text
            else:  # covers the remaining branch
                detail = f"{detail} No fix available yet.".strip()  # sets the detail text
            cvss = _max_cvss(vuln.get("CVSS") or {})  # runs the _max_cvss() call
            cwes = vuln.get("CweIDs") or []  # fetches the value
            published = str(vuln.get("PublishedDate") or "")  # fetches the value

            findings.append(  # adds an item to the list
                Finding(  # runs the Finding() call
                    source="trivy",  # sets the source text
                    category="vulnerability",  # sets the category text
                    severity=severity,  # copies the severity value into severity
                    rule_id=vuln_id,  # copies the vuln_id value into rule_id
                    title=f"{package} {installed}",  # sets the title text
                    location=_location(target_file),  # runs the _location() call
                    detail=detail,  # copies the detail value into detail
                    reference=vuln.get("PrimaryURL") or "",  # fetches the value
                    weight=weight_for("vulnerability", severity),  # runs the weight_for() call
                    file=target_file,  # copies the target_file value into file
                    package=package,  # copies the package value into package
                    aliases=[vuln_id],  # assigns the computed value to aliases
                    cvss=cvss,  # copies the cvss value into cvss
                    cwe=str(cwes[0]) if cwes else "",  # copies the cwes[0] value into cwe
                    published=published,  # copies the published value into published
                )  # closes the multiline block
            )  # closes the multiline block

        for secret in result.get("Secrets") or []:  # loops over the collection
            rule_id = secret.get("RuleID") or "secret"  # fetches the value
            line = int(secret.get("StartLine") or 0)  # runs the int() call
            key = ("secret", rule_id, target, str(line))  # runs the str() call
            if key in seen:  # evaluates the branch condition
                continue  # skips to the next loop iteration
            seen.add(key)  # adds an item to the set

            severity = normalize_severity(secret.get("Severity"))  # runs the normalize_severity() call
            findings.append(  # adds an item to the list
                Finding(  # runs the Finding() call
                    source="trivy",  # sets the source text
                    category="secret",  # sets the category text
                    severity=severity,  # copies the severity value into severity
                    rule_id=rule_id,  # copies the rule_id value into rule_id
                    title=secret.get("Title") or rule_id,  # fetches the value
                    location=_location(target_file, line),  # runs the _location() call
                    detail=_clean(  # runs the _clean() call
                        "A value that looks like a live credential is committed to the repository."  # supplies the literal text
                    ),  # closes the multiline block
                    weight=weight_for("secret", severity),  # runs the weight_for() call
                    file=target_file,  # copies the target_file value into file
                    line=line,  # copies the line value into line
                    kind=_secret_kind(rule_id, secret.get("Title")),  # runs the _secret_kind() call
                )  # closes the multiline block
            )  # closes the multiline block

        for misconfig in result.get("Misconfigurations") or []:  # loops over the collection
            status = str(misconfig.get("Status") or "").upper()  # runs the str() call
            if status in {"PASS", "PASSED"}:  # evaluates the branch condition
                continue  # skips to the next loop iteration
            misconfig_id = misconfig.get("ID") or "misconfig"  # fetches the value
            cause = misconfig.get("CauseMetadata") or {}  # fetches the value
            line = int(cause.get("StartLine") or 0)  # runs the int() call
            key = ("misconfig", misconfig_id, target, str(line))  # runs the str() call
            if key in seen:  # evaluates the branch condition
                continue  # skips to the next loop iteration
            seen.add(key)  # adds an item to the set

            severity = normalize_severity(misconfig.get("Severity"))  # runs the normalize_severity() call
            findings.append(  # adds an item to the list
                Finding(  # runs the Finding() call
                    source="trivy",  # sets the source text
                    category="misconfiguration",  # sets the category text
                    severity=severity,  # copies the severity value into severity
                    rule_id=misconfig_id,  # copies the misconfig_id value into rule_id
                    title=misconfig.get("Title") or misconfig_id,  # fetches the value
                    location=_location(target_file, line),  # runs the _location() call
                    detail=_clean(misconfig.get("Message") or misconfig.get("Description") or ""),  # runs the _clean() call
                    reference=(misconfig.get("PrimaryURL") or ""),  # fetches the value
                    weight=weight_for("misconfiguration", severity),  # runs the weight_for() call
                    file=target_file,  # copies the target_file value into file
                    line=line,  # copies the line value into line
                )  # closes the multiline block
            )  # closes the multiline block

    return findings  # returns the findings to the caller


# --------------------------------------------------------------------------
# CodeQL SARIF
# --------------------------------------------------------------------------


def parse_codeql_sarif(  # defines the parse_codeql_sarif() function
    path: str | Path, language: str = "", root: str | Path | None = None  # evaluates the path expression
) -> list[Finding]:  # closes the multiline block
    """Parse a CodeQL SARIF file into findings."""  # keeps the docstring text
    data = _load_json(path)  # runs the _load_json() call
    findings: list[Finding] = []  # evaluates the findings expression
    seen: set[tuple[str, ...]] = set()  # updates the stored value

    for run in data.get("runs") or []:  # loops over the collection
        driver = (run.get("tool") or {}).get("driver") or {}  # fetches the value
        rules = {rule.get("id"): rule for rule in driver.get("rules") or [] if rule.get("id")}  # fetches the value

        for result in run.get("results") or []:  # loops over the collection
            rule_id = result.get("ruleId") or (result.get("rule") or {}).get("id") or "unknown-rule"  # fetches the value
            rule = rules.get(rule_id) or {}  # fetches the value
            props = rule.get("properties") or {}  # fetches the value

            severity, category = _codeql_severity(result, rule, props)  # runs the _codeql_severity() call
            location, line = _codeql_location(result)  # runs the _codeql_location() call
            file = _rel_path(location, root)  # runs the _rel_path() call
            cwe = _cwe_from_tags(props.get("tags") or [])  # runs the _cwe_from_tags() call

            key = ("code", rule_id, file, str(line))  # runs the str() call
            if key in seen:  # evaluates the branch condition
                continue  # skips to the next loop iteration
            seen.add(key)  # adds an item to the set

            title = (  # assigns the computed value to title
                (rule.get("shortDescription") or {}).get("text")  # fetches the value
                or rule.get("name")  # fetches the value
                or (result.get("message") or {}).get("text")  # fetches the value
                or rule_id  # evaluates the or expression
            )  # closes the multiline block

            findings.append(  # adds an item to the list
                Finding(  # runs the Finding() call
                    source="codeql",  # sets the source text
                    category=category,  # copies the category value into category
                    severity=severity,  # copies the severity value into severity
                    rule_id=rule_id,  # copies the rule_id value into rule_id
                    title=_clean(title, 160),  # runs the _clean() call
                    location=_location(file, line),  # runs the _location() call
                    detail=_clean((result.get("message") or {}).get("text") or ""),  # runs the _clean() call
                    reference=_codeql_help_uri(rule),  # runs the _codeql_help_uri() call
                    weight=weight_for(category, severity),  # runs the weight_for() call
                    file=file,  # copies the file value into file
                    line=line,  # copies the line value into line
                    cwe=cwe,  # copies the cwe value into cwe
                )  # closes the multiline block
            )  # closes the multiline block
    return findings  # returns the findings to the caller


def _codeql_severity(  # defines the _codeql_severity() function
    result: dict[str, Any], rule: dict[str, Any], props: dict[str, Any]  # evaluates the result expression
) -> tuple[str, str]:  # closes the multiline block
    """Return (severity, category) for a CodeQL result."""  # keeps the docstring text
    raw_score = props.get("security-severity")  # fetches the value
    try:  # watches for errors in the block
        score = float(raw_score)  # type: ignore[arg-type]  # runs the float() call
    except (TypeError, ValueError):  # handles the raised error
        score = 0.0  # assigns the computed value to score

    tags = [str(tag).lower() for tag in props.get("tags") or []]  # runs the str() call
    default_level = ((rule.get("defaultConfiguration") or {}).get("level")) or result.get("level")  # fetches the value
    is_security = score > 0 or any(tag.startswith("security") for tag in tags)  # runs the any() call

    if is_security:  # evaluates the branch condition
        severity = cvss_to_severity(score) if score > 0 else normalize_severity(default_level)  # runs the cvss_to_severity() call
        return severity, "code"  # returns the severity to the caller
    return normalize_severity(default_level or "note"), "code-quality"  # returns the normalize_severity to the caller


def _codeql_location(result: dict[str, Any]) -> tuple[str, int]:  # defines the _codeql_location() function
    locations = result.get("locations") or []  # fetches the value
    if not locations:  # evaluates the branch condition
        return "", 0  # returns the value to the caller
    physical = (locations[0] or {}).get("physicalLocation") or {}  # fetches the value
    uri = ((physical.get("artifactLocation") or {}).get("uri") or "").replace("file:///", "")  # fetches the value
    line = int((physical.get("region") or {}).get("startLine") or 0)  # runs the int() call
    return uri, line  # returns the uri to the caller


def _codeql_help_uri(rule: dict[str, Any]) -> str:  # defines the _codeql_help_uri() function
    help_uri = rule.get("helpUri") or ""  # fetches the value
    if help_uri:  # evaluates the branch condition
        return str(help_uri)  # returns the str to the caller
    rule_id = rule.get("id")  # fetches the value
    return f"https://codeql.github.com/codeql-query-help/{rule_id}/" if rule_id else ""  # returns the f to the caller


# --------------------------------------------------------------------------
# Semgrep CE JSON
# --------------------------------------------------------------------------

_SEMGREP_IAC_TECH = frozenset(  # gathers the values into a set
    {  # executes the statement
        "dockerfile",  # supplies the literal text
        "docker-compose",  # supplies the literal text
        "terraform",  # supplies the literal text
        "kubernetes",  # supplies the literal text
        "k8s",  # supplies the literal text
        "helm",  # supplies the literal text
        "cloudformation",  # supplies the literal text
        "ansible",  # supplies the literal text
        "serverless",  # supplies the literal text
    }  # closes the multiline block
)  # closes the multiline block


def parse_semgrep_report(  # defines the parse_semgrep_report() function
    path: str | Path, root: str | Path | None = None  # evaluates the path expression
) -> list[Finding]:  # closes the multiline block
    """Parse ``semgrep scan --json`` output into findings."""  # keeps the docstring text
    data = _load_json(path)  # runs the _load_json() call
    findings: list[Finding] = []  # evaluates the findings expression
    seen: set[tuple[str, ...]] = set()  # updates the stored value

    for result in data.get("results") or []:  # loops over the collection
        rule_id = result.get("check_id") or "semgrep-rule"  # fetches the value
        extra = result.get("extra") or {}  # fetches the value
        metadata = extra.get("metadata") or {}  # fetches the value
        file = _rel_path(result.get("path"), root)  # runs the _rel_path() call
        line = int((result.get("start") or {}).get("line") or 0)  # runs the int() call
        key = ("semgrep", rule_id, file, str(line))  # runs the str() call
        if key in seen:  # evaluates the branch condition
            continue  # skips to the next loop iteration
        seen.add(key)  # adds an item to the set

        severity = _semgrep_severity(extra.get("severity"))  # runs the _semgrep_severity() call
        category = _semgrep_category(rule_id, metadata)  # runs the _semgrep_category() call
        cwe = _first_text(metadata.get("cwe"))  # runs the _first_text() call
        message = _clean(extra.get("message") or rule_id, 240)  # runs the _clean() call

        findings.append(  # adds an item to the list
            Finding(  # runs the Finding() call
                source="semgrep",  # sets the source text
                category=category,  # copies the category value into category
                severity=severity,  # copies the severity value into severity
                rule_id=rule_id,  # copies the rule_id value into rule_id
                title=_clean(message, 160),  # runs the _clean() call
                location=_location(file, line),  # runs the _location() call
                detail=message,  # copies the message value into detail
                reference=str(metadata.get("source") or metadata.get("shortlink") or ""),  # runs the str() call
                weight=weight_for(category, severity),  # runs the weight_for() call
                file=file,  # copies the file value into file
                line=line,  # copies the line value into line
                cwe=_cwe_from_tags([cwe]),  # runs the _cwe_from_tags() call
            )  # closes the multiline block
        )  # closes the multiline block
    return findings  # returns the findings to the caller


def _semgrep_severity(value: Any) -> str:  # defines the _semgrep_severity() function
    explicit = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}  # assigns the computed value to explicit
    return explicit.get(str(value or "").upper(), normalize_severity(value) or "low")  # returns the explicit.get to the caller


def _semgrep_category(rule_id: str, metadata: dict[str, Any]) -> str:  # defines the _semgrep_category() function
    technologies = {str(item).lower() for item in metadata.get("technology") or []}  # runs the str() call
    if technologies & _SEMGREP_IAC_TECH:  # evaluates the branch condition
        return "misconfiguration"  # returns the value to the caller
    if rule_id.split(".")[0].lower() in _SEMGREP_IAC_TECH:  # evaluates the branch condition
        return "misconfiguration"  # returns the value to the caller

    category = str(metadata.get("category") or "").lower()  # runs the str() call
    subcategories = {str(item).lower() for item in metadata.get("subcategory") or []}  # runs the str() call
    if category == "security" or "security" in subcategories or metadata.get("cwe"):  # evaluates the branch condition
        return "code"  # returns the value to the caller
    return "code-quality"  # returns the value to the caller


def _first_text(value: Any) -> str:  # defines the _first_text() function
    if isinstance(value, (list, tuple)):  # evaluates the branch condition
        return str(value[0]) if value else ""  # returns the str to the caller
    return str(value or "")  # returns the str to the caller


# --------------------------------------------------------------------------
# Grype JSON
# --------------------------------------------------------------------------


def parse_grype_report(  # defines the parse_grype_report() function
    path: str | Path, root: str | Path | None = None  # evaluates the path expression
) -> list[Finding]:  # closes the multiline block
    """Parse ``grype dir:... -o json`` output into findings."""  # keeps the docstring text
    data = _load_json(path)  # runs the _load_json() call
    findings: list[Finding] = []  # evaluates the findings expression
    seen: set[tuple[str, str]] = set()  # updates the stored value

    for match in data.get("matches") or []:  # loops over the collection
        vuln = match.get("vulnerability") or {}  # fetches the value
        artifact = match.get("artifact") or {}  # fetches the value
        vuln_id = vuln.get("id") or "UNKNOWN-CVE"  # fetches the value
        related = [  # assigns the computed value to related
            str(item.get("id") or "")  # runs the str() call
            for item in vuln.get("relatedVulnerabilities") or []  # loops over the collection
            if isinstance(item, dict)  # evaluates the branch condition
        ]  # closes the multiline block
        aliases = [value for value in [vuln_id, *related] if value]  # assigns the computed value to aliases

        # Grype frequently reports a GHSA id with no relatedVulnerabilities
        # entry, but the matching CVE is present in its epss/cwes/urls blocks.
        # Harvest those so the same issue merges with Trivy/OSV findings.
        for block_name in ("epss", "cwes"):  # loops over the collection
            for item in vuln.get(block_name) or []:  # loops over the collection
                if isinstance(item, dict) and item.get("cve"):  # evaluates the branch condition
                    aliases.append(str(item["cve"]))  # adds an item to the list
        for url in vuln.get("urls") or []:  # loops over the collection
            cve_match = re.search(r"(CVE-\d{4}-\d{4,})", str(url), re.IGNORECASE)  # runs the search() call
            if cve_match:  # evaluates the branch condition
                aliases.append(cve_match.group(1).upper())  # adds an item to the list
        aliases = list(dict.fromkeys(aliases))  # builds the list collection

        canonical = _first_cve(aliases, vuln_id)  # runs the _first_cve() call
        package = artifact.get("name") or "unknown-package"  # fetches the value

        key = (canonical.upper(), package.lower())  # uppercases the text
        if key in seen:  # evaluates the branch condition
            continue  # skips to the next loop iteration
        seen.add(key)  # adds an item to the set

        severity = normalize_severity(vuln.get("severity"))  # runs the normalize_severity() call
        version = artifact.get("version") or "?"  # fetches the value
        file = ""  # sets the file text
        locations = artifact.get("locations") or []  # fetches the value
        if locations and isinstance(locations[0], dict):  # evaluates the branch condition
            file = _rel_path(locations[0].get("path"), root)  # runs the _rel_path() call

        fixed = ""  # sets the fixed text
        fix = vuln.get("fix") or {}  # fetches the value
        versions = fix.get("versions") or []  # fetches the value
        if versions:  # evaluates the branch condition
            fixed = str(versions[0])  # runs the str() call
        if not fixed:  # evaluates the branch condition
            for detail in match.get("matchDetails") or []:  # loops over the collection
                suggested = (detail.get("fix") or {}).get("suggestedVersion")  # fetches the value
                if suggested:  # evaluates the branch condition
                    fixed = str(suggested)  # runs the str() call
                    break  # exits the loop early

        detail = _clean(vuln.get("description") or "")  # runs the _clean() call
        detail = f"{detail} Fixed in {fixed}.".strip() if fixed else f"{detail} No fix available yet.".strip()  # sets the detail text
        references = vuln.get("urls") or []  # fetches the value
        cvss = _max_cvss_list(vuln.get("cvss") or [])  # runs the _max_cvss_list() call
        epss = _max_epss(vuln.get("epss") or [])  # runs the _max_epss() call
        cwes = [  # assigns the computed value to cwes
            str(item.get("cwe"))  # runs the str() call
            for item in (vuln.get("cwes") or [])  # loops over the collection
            if isinstance(item, dict) and item.get("cwe")  # evaluates the branch condition
        ]  # closes the multiline block
        published = str(vuln.get("published") or "")  # fetches the value
        kev = bool(vuln.get("known_exploited"))  # evaluates the KEV flag

        findings.append(  # adds an item to the list
            Finding(  # runs the Finding() call
                source="grype",  # sets the source text
                category="vulnerability",  # sets the category text
                severity=severity,  # copies the severity value into severity
                rule_id=canonical,  # copies the canonical value into rule_id
                title=f"{package} {version}",  # sets the title text
                location=_location(file),  # runs the _location() call
                detail=detail,  # copies the detail value into detail
                reference=str(references[0]) if references else "",  # runs the str() call
                weight=weight_for("vulnerability", severity),  # runs the weight_for() call
                file=file,  # copies the file value into file
                package=package,  # copies the package value into package
                aliases=aliases,  # copies the aliases value into aliases
                cvss=cvss,  # copies the cvss value into cvss
                epss=epss,  # copies the epss value into epss
                kev=kev,  # copies the kev value into kev
                published=published,  # copies the published value into published
                cwe=str(cwes[0]) if cwes else "",  # copies the cwes[0] value into cwe
            )  # closes the multiline block
        )  # closes the multiline block
    return findings  # returns the findings to the caller


# --------------------------------------------------------------------------
# OSV-Scanner JSON
# --------------------------------------------------------------------------


def parse_osv_report(  # defines the parse_osv_report() function
    path: str | Path, root: str | Path | None = None  # evaluates the path expression
) -> list[Finding]:  # closes the multiline block
    """Parse ``osv-scanner scan source --format json`` output into findings."""  # keeps the docstring text
    data = _load_json(path)  # runs the _load_json() call
    findings: list[Finding] = []  # evaluates the findings expression
    seen: set[tuple[str, str]] = set()  # updates the stored value

    for result in data.get("results") or []:  # loops over the collection
        source = result.get("source") or {}  # fetches the value
        file = _rel_path(source.get("path"), root)  # runs the _rel_path() call

        for entry in result.get("packages") or []:  # loops over the collection
            package = entry.get("package") or {}  # fetches the value
            name = package.get("name") or "unknown-package"  # fetches the value
            version = package.get("version") or "?"  # fetches the value

            for vuln in entry.get("vulnerabilities") or []:  # loops over the collection
                vuln_id = vuln.get("id") or "UNKNOWN-CVE"  # fetches the value
                aliases = [str(item) for item in vuln.get("aliases") or [] if item]  # runs the str() call
                canonical = _first_cve([vuln_id, *aliases], vuln_id)  # runs the _first_cve() call
                key = (canonical.upper(), name.lower())  # uppercases the text
                if key in seen:  # evaluates the branch condition
                    continue  # skips to the next loop iteration
                seen.add(key)  # adds an item to the set

                severity = _osv_severity(vuln)  # runs the _osv_severity() call
                references = vuln.get("references") or []  # fetches the value
                reference = ""  # sets the reference text
                if references and isinstance(references[0], dict):  # evaluates the branch condition
                    reference = str(references[0].get("url") or "")  # runs the str() call
                specific = vuln.get("database_specific") or {}  # fetches the value
                cwes = (  # assigns the computed value to cwes
                    specific.get("cwe_ids") or []
                    if isinstance(specific, dict)
                    else []
                )  # closes the multiline block
                published = str(vuln.get("published") or specific.get("published") or "")  # fetches the value

                findings.append(  # adds an item to the list
                    Finding(  # runs the Finding() call
                        source="osv",  # sets the source text
                        category="vulnerability",  # sets the category text
                        severity=severity,  # copies the severity value into severity
                        rule_id=canonical,  # copies the canonical value into rule_id
                        title=f"{name} {version}",  # sets the title text
                        location=_location(file),  # runs the _location() call
                        detail=_clean(vuln.get("summary") or vuln.get("details") or ""),  # runs the _clean() call
                        reference=reference,  # copies the reference value into reference
                        weight=weight_for("vulnerability", severity),  # runs the weight_for() call
                        file=file,  # copies the file value into file
                        package=name,  # copies the name value into package
                        aliases=[vuln_id, *aliases],  # assigns the computed value to aliases
                        cwe=str(cwes[0]) if cwes else "",  # copies the cwes[0] value into cwe
                        published=published,  # copies the published value into published
                    )  # closes the multiline block
                )  # closes the multiline block
    return findings  # returns the findings to the caller


def _osv_severity(vuln: dict[str, Any]) -> str:  # defines the _osv_severity() function
    for key in ("database_specific", "ecosystem_specific"):  # loops over the collection
        block = vuln.get(key) or {}  # fetches the value
        if not isinstance(block, dict):  # evaluates the branch condition
            continue  # skips to the next loop iteration
        raw = block.get("severity")  # fetches the value
        if isinstance(raw, str):  # evaluates the branch condition
            severity = normalize_severity(raw)  # runs the normalize_severity() call
            if severity != "unknown":  # evaluates the branch condition
                return severity  # returns the severity to the caller
    return "medium"  # returns the value to the caller


# --------------------------------------------------------------------------
# GitLeaks JSON
# --------------------------------------------------------------------------


def parse_gitleaks_report(  # defines the parse_gitleaks_report() function
    path: str | Path, root: str | Path | None = None  # evaluates the path expression
) -> list[Finding]:  # closes the multiline block
    """Parse ``gitleaks dir --report-format json`` output into findings."""  # keeps the docstring text
    data = _load_json(path)  # runs the _load_json() call
    if isinstance(data, dict):  # evaluates the branch condition
        data = data.get("findings") or data.get("leaks") or []  # fetches the value
    findings: list[Finding] = []  # evaluates the findings expression
    seen: set[tuple[str, int, str]] = set()  # updates the stored value

    for leak in data or []:  # loops over the collection
        rule_id = leak.get("RuleID") or leak.get("ruleId") or "secret"  # fetches the value
        file = _rel_path(leak.get("File") or leak.get("file"), root)  # runs the _rel_path() call
        line = int(leak.get("StartLine") or leak.get("startLine") or 0)  # runs the int() call
        kind = _secret_kind(rule_id, leak.get("Description"), leak.get("Tags"))  # runs the _secret_kind() call
        key = (file.lower(), line, kind or rule_id)  # lowercases the text
        if key in seen:  # evaluates the branch condition
            continue  # skips to the next loop iteration
        seen.add(key)  # adds an item to the set

        severity = "critical" if kind == "private-key" else "high"  # sets the severity text
        findings.append(  # adds an item to the list
            Finding(  # runs the Finding() call
                source="gitleaks",  # sets the source text
                category="secret",  # sets the category text
                severity=severity,  # copies the severity value into severity
                rule_id=rule_id,  # copies the rule_id value into rule_id
                title=_clean(leak.get("Description") or rule_id, 160),  # runs the _clean() call
                location=_location(file, line),  # runs the _location() call
                detail="GitLeaks detected a credential-shaped value in the repository. The value is redacted.",  # sets the detail text
                reference=f"https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml",  # sets the reference text
                weight=weight_for("secret", severity),  # runs the weight_for() call
                file=file,  # copies the file value into file
                line=line,  # copies the line value into line
                kind=kind,  # copies the kind value into kind
            )  # closes the multiline block
        )  # closes the multiline block
    return findings  # returns the findings to the caller


# --------------------------------------------------------------------------
# TruffleHog JSONL
# --------------------------------------------------------------------------


def parse_trufflehog_report(  # defines the parse_trufflehog_report() function
    path: str | Path, root: str | Path | None = None  # evaluates the path expression
) -> list[Finding]:  # closes the multiline block
    """Parse ``trufflehog filesystem --json`` output (one JSON object per line)."""  # keeps the docstring text
    findings: list[Finding] = []  # evaluates the findings expression
    seen: set[tuple[str, int, str]] = set()  # updates the stored value
    text = Path(path).read_text(encoding="utf-8", errors="replace")  # creates the path object

    for raw in text.splitlines():  # loops over the collection
        raw = raw.strip()  # trims the whitespace
        if not raw:  # evaluates the branch condition
            continue  # skips to the next loop iteration
        try:  # watches for errors in the block
            item = json.loads(raw)  # parses the text into JSON data
        except json.JSONDecodeError:  # handles the raised error
            continue  # skips to the next loop iteration
        if not isinstance(item, dict) or not item.get("DetectorName"):  # evaluates the branch condition
            continue  # skips to the next loop iteration

        file, line = _trufflehog_location(item.get("SourceMetadata") or {})  # runs the _trufflehog_location() call
        file = _rel_path(file, root)  # runs the _rel_path() call
        detector = str(item.get("DetectorName") or "secret")  # runs the str() call
        verified = bool(item.get("Verified"))  # runs the bool() call
        kind = _secret_kind(detector)  # runs the _secret_kind() call
        key = (file.lower(), line, kind or detector)  # lowercases the text
        if key in seen:  # evaluates the branch condition
            continue  # skips to the next loop iteration
        seen.add(key)  # adds an item to the set

        if verified:  # evaluates the branch condition
            severity = "critical"  # sets the severity text
        elif kind == "private-key":  # checks the alternate condition
            severity = "high"  # sets the severity text
        else:  # covers the remaining branch
            severity = "medium"  # sets the severity text

        if verified:  # evaluates the branch condition
            detail = "TruffleHog verified that this credential is live."  # sets the detail text
        else:  # covers the remaining branch
            detail = (  # assigns the computed value to detail
                "TruffleHog detected a credential but did not verify it (verification is "  # supplies the literal text
                "disabled so secrets are never sent to third parties)."  # supplies the literal text
            )  # closes the multiline block
        rotation = (item.get("ExtraData") or {}).get("rotation_guide") or ""  # fetches the value

        findings.append(  # adds an item to the list
            Finding(  # runs the Finding() call
                source="trufflehog",  # sets the source text
                category="secret",  # sets the category text
                severity=severity,  # copies the severity value into severity
                rule_id=detector,  # copies the detector value into rule_id
                title=f"{detector} credential" + (" (verified)" if verified else ""),  # sets the title text
                location=_location(file, line),  # runs the _location() call
                detail=detail,  # copies the detail value into detail
                reference=str(rotation),  # runs the str() call
                weight=weight_for("secret", severity),  # runs the weight_for() call
                file=file,  # copies the file value into file
                line=line,  # copies the line value into line
                kind=kind,  # copies the kind value into kind
            )  # closes the multiline block
        )  # closes the multiline block
    return findings  # returns the findings to the caller


def _trufflehog_location(metadata: dict[str, Any]) -> tuple[str, int]:  # defines the _trufflehog_location() function
    data = metadata.get("Data") if isinstance(metadata, dict) else {}  # fetches the value
    if not isinstance(data, dict):  # evaluates the branch condition
        return "", 0  # returns the value to the caller
    for block in data.values():  # loops over the collection
        if not isinstance(block, dict):  # evaluates the branch condition
            continue  # skips to the next loop iteration
        file = block.get("file") or block.get("File") or block.get("path") or ""  # fetches the value
        if file:  # evaluates the branch condition
            try:  # watches for errors in the block
                line = int(block.get("line") or block.get("Line") or 0)  # runs the int() call
            except (TypeError, ValueError):  # handles the raised error
                line = 0  # assigns the computed value to line
            return str(file), line  # returns the str to the caller
    return "", 0  # returns the value to the caller


# --------------------------------------------------------------------------
# Syft SBOM (inventory only - never scored directly)
# --------------------------------------------------------------------------


def parse_syft_inventory(  # defines the parse_syft_inventory() function
    path: str | Path, root: str | Path | None = None  # evaluates the path expression
) -> dict[str, Any]:  # closes the multiline block
    """Summarise a Syft JSON document into a compact SBOM inventory.

    Syft does not report vulnerabilities, so this contributes context (what is
    in the repo) rather than points. When Grype is also selected, the same SBOM
    is handed to Grype so both tools describe exactly the same components.
    """
    data = _load_json(path)  # runs the _load_json() call
    artifacts = data.get("artifacts") or []  # fetches the value
    ecosystems: dict[str, int] = {}  # evaluates the ecosystems expression
    components: list[dict[str, Any]] = []  # evaluates the components expression
    unversioned = 0  # assigns the computed value to unversioned

    for artifact in artifacts:  # loops over the collection
        if not isinstance(artifact, dict):  # evaluates the branch condition
            continue  # skips to the next loop iteration
        name = str(artifact.get("name") or "unknown")  # runs the str() call
        version = str(artifact.get("version") or "")  # runs the str() call
        kind = str(artifact.get("language") or artifact.get("type") or "package")  # runs the str() call
        if not version:  # evaluates the branch condition
            unversioned += 1  # evaluates the unversioned expression
        ecosystems[kind] = ecosystems.get(kind, 0) + 1  # fetches the value

        file = ""  # sets the file text
        locations = artifact.get("locations") or []  # fetches the value
        if locations and isinstance(locations[0], dict):  # evaluates the branch condition
            file = _rel_path(locations[0].get("path"), root)  # runs the _rel_path() call

        components.append(  # adds an item to the list
            {  # executes the statement
                "name": name,  # maps the name dictionary entry
                "version": version,  # maps the version dictionary entry
                "type": kind,  # maps the type dictionary entry
                "purl": str(artifact.get("purl") or ""),  # maps the purl dictionary entry
                "file": file,  # maps the file dictionary entry
            }  # closes the multiline block
        )  # closes the multiline block

    components.sort(key=lambda item: (item["type"], item["name"].lower(), item["version"]))  # sorts the values
    return {  # returns the value to the caller
        "tool": "syft",  # maps the tool dictionary entry
        "components": len(components),  # maps the components dictionary entry
        "unversioned": unversioned,  # maps the unversioned dictionary entry
        "ecosystems": dict(sorted(ecosystems.items(), key=lambda item: (-item[1], item[0]))),  # maps the ecosystems dictionary entry
        "top_packages": [item for item in components if item["version"]][:15],  # maps the top_packages dictionary entry
        "all_components": list(components),  # maps the all_components dictionary entry
    }  # closes the multiline block


# --------------------------------------------------------------------------
# cdxgen (CycloneDX SBOM, JSON written by scanners.run_cdxgen)
# --------------------------------------------------------------------------


def parse_cdxgen_sbom(path: str | Path) -> dict[str, Any]:  # defines the parse_cdxgen_sbom() function
    """Summarise a CycloneDX document into the SBOM-inventory shape.

    The returned summary mirrors :func:`parse_syft_inventory` (with a
    ``tool`` marker), so a cdxgen-only scan feeds the report inventory, the
    context normalisation and the Print SBOM / Export SBOM buttons exactly
    the way a Syft scan does.
    """
    data = _load_json(path)  # runs the _load_json() call
    raw_components = data.get("components") if isinstance(data, dict) else []  # fetches the value
    if not isinstance(raw_components, list):  # evaluates the branch condition
        raw_components = []  # covers the remaining branch
    spec = str(data.get("specVersion") or "")  # the root-level spec claim

    all_components: list[dict[str, str]] = []  # the normalised component list
    ecosystems: dict[str, int] = {}  # the per-type counts
    unversioned = 0  # assigns the unversioned value
    for component in raw_components:  # loops over the components
        if not isinstance(component, dict):  # evaluates the branch condition
            continue  # skips the malformed rows
        name = str(component.get("name") or "unknown")  # runs the str() call
        version = str(component.get("version") or "")  # runs the str() call
        kind = str(component.get("type") or "library")  # the framework/library family
        if not version:  # evaluates the branch condition
            unversioned += 1  # counts one more unpinned row
        ecosystems[kind] = ecosystems.get(kind, 0) + 1  # counts the family
        all_components.append({  # stores the normalised row
            "name": name,  # maps the name dictionary entry
            "version": version,  # maps the version dictionary entry
            "type": kind,  # maps the type dictionary entry
            "purl": str(component.get("purl") or ""),  # maps the purl dictionary entry
            "file": "",  # cdxgen carries no per-file path  # maps the file dictionary entry
        })  # closes the row build

    all_components.sort(key=lambda item: (item["type"], item["name"].lower(), item["version"]))  # sorts the values
    return {  # returns the summary
        "tool": "cdxgen",  # maps the tool dictionary entry
        "spec_version": spec,  # maps the spec_version dictionary entry
        "components": len(all_components),  # maps the components dictionary entry
        "unversioned": unversioned,  # maps the unversioned dictionary entry
        "ecosystems": dict(sorted(ecosystems.items(), key=lambda item: (-item[1], item[0]))),  # the family counts
        "top_packages": [item for item in all_components if item["version"]][:15],  # the top rows
        "all_components": all_components,  # maps the all_components dictionary entry
    }  # closes the summary


def merge_sbom_summaries(summaries: Iterable[dict[str, Any]]) -> dict[str, Any] | None:
    """Merge SBOM-inventory summaries into one report ``sbom`` payload.

    Syft and cdxgen can both run: the component lists are unioned on
    (name, version, purl), the tool names join, and counts stay exact, so the
    Print SBOM / Export SBOM buttons always print the deduplicated union.
    """
    present = [summary for summary in summaries or [] if isinstance(summary, dict)]  # the real ones
    if not present:  # evaluates the branch condition
        return None  # no SBOM ran: the caller reports the honest gap
    tools = [str(summary.get("tool") or "sbom") for summary in present]  # the tool names
    specs = [  # the spec versions that were claimed
        str(summary.get("spec_version") or "") for summary in present
        if summary.get("spec_version")  # keeps only the claimed ones
    ]
    merged: dict[tuple[str, str, str], dict[str, str]] = {}  # keyed by name+version+purl
    unversioned = 0  # the unpinned rows total
    ecosystems: dict[str, int] = {}  # the merged family counts
    for summary in present:  # loops over the summaries
        unversioned += int(summary.get("unversioned") or 0)  # adds the unpinned rows
        for family, count in (summary.get("ecosystems") or {}).items():  # loops over the families
            ecosystems[family] = ecosystems.get(family, 0) + int(count or 0)  # accumulates
        for component in summary.get("all_components") or []:  # loops over the rows
            key = (  # the stable identity tuple
                str(component.get("name") or "").lower(),  # the component name
                str(component.get("version") or ""),  # the version
                str(component.get("purl") or ""),  # the purl
            )  # closes the key build
            merged.setdefault(key, component)  # keeps the first sighting
    components = sorted(  # the merged list, stable order
        merged.values(),  # every unique row
        key=lambda item: (item.get("type") or "", (item.get("name") or "").lower(), item.get("version") or ""),  # the key
    )  # closes the sort
    return {  # returns the merged payload
        "tools": "  +  ".join(dict.fromkeys(tools)),  # the deduplicated tool names
        "spec_version": "  +  ".join(dict.fromkeys(specs)),  # the joined claims
        "components": len(components),  # maps the components dictionary entry
        "unversioned": unversioned,  # maps the unversioned dictionary entry
        "ecosystems": dict(sorted(ecosystems.items(), key=lambda item: (-item[1], item[0]))),  # the families
        "top_packages": [item for item in components if item["version"]][:15],  # the top rows
        "all_components": components,  # maps the all_components dictionary entry
    }  # closes the payload


# --------------------------------------------------------------------------
# Checkov JSON
# --------------------------------------------------------------------------

_CHECKOV_SECRET_IDS = ("CKV_SECRET", "CKV_SECRETS")  # assigns the computed value to _CHECKOV_SECRET_IDS


def parse_checkov_report(  # defines the parse_checkov_report() function
    path: str | Path, root: str | Path | None = None  # evaluates the path expression
) -> list[Finding]:  # closes the multiline block
    """Parse Checkov's ``results_json.json`` (one file or a directory of them)."""  # keeps the docstring text
    source = Path(path)  # creates the path object
    files = (  # assigns the computed value to files
        sorted(item for item in source.rglob("*") if item.is_file() and item.suffix == ".json")  # runs the sorted() call
        if source.is_dir()  # evaluates the branch condition
        else [source]  # covers the remaining branch
    )  # closes the multiline block
    findings: list[Finding] = []  # evaluates the findings expression
    seen: set[tuple[str, str, int]] = set()  # updates the stored value

    for report_file in files:  # loops over the collection
        try:  # watches for errors in the block
            data = _load_json(report_file)  # runs the _load_json() call
        except Exception:  # handles the raised error
            continue  # skips to the next loop iteration
        blocks = data if isinstance(data, list) else [data]  # runs the isinstance() call

        for block in blocks:  # loops over the collection
            if not isinstance(block, dict):  # evaluates the branch condition
                continue  # skips to the next loop iteration
            check_type = str(block.get("check_type") or "").lower()  # runs the str() call
            failed = ((block.get("results") or {}).get("failed_checks") or [])  # fetches the value

            for check in failed:  # loops over the collection
                if not isinstance(check, dict):  # evaluates the branch condition
                    continue  # skips to the next loop iteration
                check_id = str(check.get("check_id") or "checkov-check")  # runs the str() call
                is_secret = check_type.startswith("secret") or check_id.upper().startswith(  # checks the text prefix
                    _CHECKOV_SECRET_IDS  # evaluates the _CHECKOV_SECRET_IDS expression
                )  # closes the multiline block
                category = "secret" if is_secret else "misconfiguration"  # sets the category text

                raw_file = str(check.get("file_abs_path") or check.get("file_path") or "")  # runs the str() call
                file = _rel_path(raw_file, root)  # runs the _rel_path() call
                line = _checkov_line(check)  # runs the _checkov_line() call
                key = (check_id, file.lower(), line)  # lowercases the text
                if key in seen:  # evaluates the branch condition
                    continue  # skips to the next loop iteration
                seen.add(key)  # adds an item to the set

                severity = normalize_severity(check.get("severity"))  # runs the normalize_severity() call
                title = (  # assigns the computed value to title
                    str(check.get("check_name") or "").strip()  # runs the str() call
                    or check_id  # evaluates the or expression
                )  # closes the multiline block
                detail = _clean(  # runs the _clean() call
                    check.get("short_description")  # fetches the value
                    or check.get("description")  # fetches the value
                    or (f"Checkov check {check_id} failed for {check_type or 'configuration'}.")  # evaluates the or expression
                )  # closes the multiline block
                findings.append(  # adds an item to the list
                    Finding(  # runs the Finding() call
                        source="checkov",  # sets the source text
                        category=category,  # copies the category value into category
                        severity=severity,  # copies the severity value into severity
                        rule_id=check_id,  # copies the check_id value into rule_id
                        title=_clean(title, 180),  # runs the _clean() call
                        location=_location(file, line),  # runs the _location() call
                        detail=detail,  # copies the detail value into detail
                        reference=str(check.get("guideline") or ""),  # runs the str() call
                        weight=weight_for(category, severity),  # runs the weight_for() call
                        file=file,  # copies the file value into file
                        line=line,  # copies the line value into line
                        kind=check_id,  # copies the check_id value into kind
                    )  # closes the multiline block
                )  # closes the multiline block
    return findings  # returns the findings to the caller


def _checkov_line(check: dict[str, Any]) -> int:  # defines the _checkov_line() function
    lines = check.get("file_line_range") or []  # fetches the value
    if isinstance(lines, (list, tuple)) and lines:  # evaluates the branch condition
        try:  # watches for errors in the block
            return int(lines[0] or 0)  # returns the int to the caller
        except (TypeError, ValueError):  # handles the raised error
            pass  # keeps the block syntactically empty
    configuration = (check.get("check_result") or {}).get("results_configuration") or []  # fetches the value
    if configuration and isinstance(configuration[0], dict):  # evaluates the branch condition
        try:  # watches for errors in the block
            return int(configuration[0].get("startline") or 0)  # returns the int to the caller
        except (TypeError, ValueError):  # handles the raised error
            return 0  # returns the value to the caller
    return 0  # returns the value to the caller


# --------------------------------------------------------------------------
# GuardDog (local source-code scan)
# --------------------------------------------------------------------------

_GUARDDOG_CRITICAL_RULES = frozenset(  # gathers the values into a set
    {  # executes the statement
        "code-execution",  # supplies the literal text
        "exec-base64",  # supplies the literal text
        "download-executable",  # supplies the literal text
        "exfiltrate-sensitive-data",  # supplies the literal text
        "silent-process-execution",  # supplies the literal text
        "cmd-overwrite",  # supplies the literal text
        "dll-hijacking",  # supplies the literal text
        "obfuscation",  # supplies the literal text
        "clipboard-access",  # supplies the literal text
        "steganography",  # supplies the literal text
        "npm-install-script",  # supplies the literal text
        "npm-exec-base64",  # supplies the literal text
        "npm-exfiltrate-sensitive-data",  # supplies the literal text
        "npm-obfuscation",  # supplies the literal text
        "npm-silent-process-execution",  # supplies the literal text
        "npm-serialize-environment",  # supplies the literal text
        "npm-dll-hijacking",  # supplies the literal text
        "npm-steganography",  # supplies the literal text
    }  # closes the multiline block
)  # closes the multiline block


def parse_guarddog_report(  # defines the parse_guarddog_report() function
    path: str | Path, root: str | Path | None = None  # evaluates the path expression
) -> list[Finding]:  # closes the multiline block
    """Parse the JSON written by the GuardDog helper script."""  # keeps the docstring text
    data = _load_json(path)  # runs the _load_json() call
    scans = data.get("scans") if isinstance(data, dict) and "scans" in data else [data]  # fetches the value
    findings: list[Finding] = []  # evaluates the findings expression
    seen: set[tuple[str, str, int, str]] = set()  # updates the stored value

    for scan in scans or []:  # loops over the collection
        if not isinstance(scan, dict):  # evaluates the branch condition
            continue  # skips to the next loop iteration
        ecosystem = str(scan.get("ecosystem") or "").strip().lower()  # runs the str() call
        result = scan.get("result") if "result" in scan else scan  # fetches the value
        if not isinstance(result, dict):  # evaluates the branch condition
            continue  # skips to the next loop iteration

        for rule, matches in (result.get("results") or {}).items():  # loops over the collection
            if not matches:  # evaluates the branch condition
                continue  # skips to the next loop iteration
            rule_id = f"guarddog:{ecosystem}:{rule}" if ecosystem else f"guarddog:{rule}"  # sets the rule_id text
            title = rule.replace("-", " ").replace("_", " ").title()  # swaps the text
            severity = "critical" if str(rule).lower() in _GUARDDOG_CRITICAL_RULES else "high"  # sets the severity text

            if isinstance(matches, dict):  # evaluates the branch condition
                matches = [matches]  # assigns the computed value to matches
            for match in matches:  # loops over the collection
                if not isinstance(match, dict):  # evaluates the branch condition
                    match = {"location": str(match)}  # runs the str() call
                file, line = _guarddog_location(match.get("location"))  # runs the _guarddog_location() call
                file = _rel_path(file, root)  # runs the _rel_path() call
                key = (rule_id, file.lower(), line, str(match.get("code") or ""))  # lowercases the text
                if key in seen:  # evaluates the branch condition
                    continue  # skips to the next loop iteration
                seen.add(key)  # adds an item to the set

                message = _clean(match.get("message") or f"GuardDog rule '{rule}' matched.")  # runs the _clean() call
                code = _clean(match.get("code") or "", 160)  # runs the _clean() call
                detail = f"{message} Matched code: {code}" if code else message  # sets the detail text
                findings.append(  # adds an item to the list
                    Finding(  # runs the Finding() call
                        source="guarddog",  # sets the source text
                        category="vulnerability",  # sets the category text
                        severity=severity,  # copies the severity value into severity
                        rule_id=rule_id,  # copies the rule_id value into rule_id
                        title=f"{title} pattern",  # sets the title text
                        location=_location(file, line),  # runs the _location() call
                        detail=detail,  # copies the detail value into detail
                        reference=config.GUARDDOG_REFERENCE,  # copies the config.GUARDDOG_REFERENCE value into reference
                        weight=weight_for("vulnerability", severity),  # runs the weight_for() call
                        file=file,  # copies the file value into file
                        line=line,  # copies the line value into line
                        package=file,  # copies the file value into package
                    )  # closes the multiline block
                )  # closes the multiline block
    return findings  # returns the findings to the caller


def _guarddog_location(value: Any) -> tuple[str, int]:  # defines the _guarddog_location() function
    text = str(value or "").strip()  # runs the str() call
    if not text:  # evaluates the branch condition
        return "", 0  # returns the value to the caller
    file, _, suffix = text.rpartition(":")  # runs the rpartition() call
    if file and suffix.isdigit():  # evaluates the branch condition
        return file, int(suffix)  # returns the file to the caller
    return text, 0  # returns the text to the caller


# --------------------------------------------------------------------------
# Nuclei JSONL
# --------------------------------------------------------------------------


def parse_nuclei_report(  # defines the parse_nuclei_report() function
    path: str | Path, root: str | Path | None = None  # evaluates the path expression
) -> list[Finding]:  # closes the multiline block
    """Parse Nuclei's ``-j`` output (one JSON object per line).

    Nuclei probes live URLs rather than repository files, so ``root`` is
    accepted for signature consistency but never used: a finding's ``file``
    is the remote ``host:port`` and ``location`` is the matched URL with the
    scheme stripped. Lines that did not match the template
    (``matcher-status: false``) and lines that are not JSON objects are
    skipped.
    """
    findings: list[Finding] = []  # evaluates the findings expression
    seen: set[tuple[str, str]] = set()  # updates the stored value
    text = Path(path).read_text(encoding="utf-8", errors="replace")  # creates the path object

    for raw in text.splitlines():  # loops over the collection
        raw = raw.strip()  # trims the whitespace
        if not raw:  # evaluates the branch condition
            continue  # skips to the next loop iteration
        try:  # watches for errors in the block
            item = json.loads(raw)  # parses the text into JSON data
        except json.JSONDecodeError:  # handles the invalid lines
            continue  # skips to the next loop iteration
        if not isinstance(item, dict):  # evaluates the branch condition
            continue  # skips to the next loop iteration
        if item.get("matcher-status") is False:  # templates that did not match
            continue  # skips to the next loop iteration

        template_id = str(item.get("template-id") or "nuclei-template")  # runs the str() call
        info = item.get("info") or {}  # fetches the value
        if not isinstance(info, dict):  # evaluates the branch condition
            info = {}  # covers the remaining branch
        classification = info.get("classification") or {}  # fetches the value
        if not isinstance(classification, dict):  # evaluates the branch condition
            classification = {}  # covers the remaining branch

        cwes = _first_list(classification.get("cwe-id"))  # runs the _first_list() call
        cves = _first_list(classification.get("cve-id"))  # runs the _first_list() call
        references = _first_list(info.get("reference"))  # runs the _first_list() call
        matched = str(  # sets the matched text
            item.get("matched-at") or item.get("host") or item.get("url") or ""
        )  # closes the multiline block
        host = _nuclei_endpoint(matched)  # runs the _nuclei_endpoint() call

        key = (template_id, host)  # merges repeat hits of one template on one host  # assigns the computed value to key
        if key in seen:  # evaluates the branch condition
            continue  # skips to the next loop iteration
        seen.add(key)  # adds an item to the set

        severity = normalize_severity(info.get("severity"))  # "info" ratings become unknown  # runs the normalize_severity() call
        category = "vulnerability" if cves else "misconfiguration"  # a CVE narrows the class  # sets the category text
        findings.append(  # adds an item to the list
            Finding(  # runs the Finding() call
                source="nuclei",  # sets the source text
                category=category,  # copies the category value into category
                severity=severity,  # copies the severity value into severity
                rule_id=template_id,  # copies the template_id value into rule_id
                title=_clean(info.get("name") or template_id, 160),  # runs the _clean() call
                location=_nuclei_location(matched),  # scheme-stripped matched URL  # runs the _nuclei_location() call
                detail=_clean(matched),  # copies the matched value into detail
                reference=str(references[0]) if references else "",  # copies the references[0] value into reference
                weight=weight_for(category, severity),  # runs the weight_for() call
                file=host,  # remote host:port, not a repo path  # copies the host value into file
                line=0,  # remote findings have no line number  # assigns the computed value to line
                package="",  # live probing is not a dependency finding  # sets the package text
                cwe=str(cwes[0]) if cwes else "",  # copies the cwes[0] value into cwe
                kind=template_id,  # copies the template_id value into kind
            )  # closes the multiline block
        )  # closes the multiline block
    return findings  # returns the findings to the caller


def _first_list(value: Any) -> list[Any]:  # defines the _first_list() function
    """Normalise a scalar-or-list scanner field into a flat list."""
    if isinstance(value, (list, tuple)):  # evaluates the branch condition
        return list(value)  # returns the list to the caller
    return [value] if value else []  # returns the single-item list to the caller


def _nuclei_endpoint(value: str) -> str:  # defines the _nuclei_endpoint() function
    """Host:port of a matched URL, or the raw text when it is not a URL."""
    text = str(value or "").strip()  # trims the whitespace
    if not text:  # evaluates the branch condition
        return ""  # returns the value to the caller
    parts = urllib.parse.urlsplit(text)  # runs the urlsplit() call
    if parts.scheme and parts.netloc:  # evaluates the branch condition
        return parts.netloc  # returns the netloc to the caller
    return text  # returns the raw text to the caller


def _nuclei_location(value: str) -> str:  # defines the _nuclei_location() function
    """Matched URL with the scheme stripped, ready for the report column."""
    text = str(value or "").strip()  # trims the whitespace
    parts = urllib.parse.urlsplit(text)  # runs the urlsplit() call
    if parts.scheme and parts.netloc:  # evaluates the branch condition
        path = parts.path or "/"  # sets the path text
        return f"{parts.netloc}{path}"  # returns the f to the caller
    return text  # returns the raw text to the caller


# --------------------------------------------------------------------------
# Kubescape JSON
# --------------------------------------------------------------------------


def parse_kubescape_report(  # defines the parse_kubescape_report() function
    path: str | Path, root: str | Path | None = None  # evaluates the path expression
) -> list[Finding]:  # closes the multiline block
    """Parse Kubescape's ``scan --format json`` output into findings.

    Kubescape has shipped several report shapes, so the parser walks the whole
    document and accepts every object that carries a control id, a severity
    and a failed indicator, and skips anything it cannot interpret:

    * v4-style``results[].results.posture.frameworks[].controls[]`` with
      ``id``/``name``, ``severity`` and ``ruleStatus``/``status`` (nested
      ``object`` blocks provide namespace/kind/name resource context);
    * flat control blocks using ``controlID``/``controlName``;
    * the bare ``controlsFailed`` style summaries, which are ignored.
    """
    try:  # watches for errors in the block
        data = _load_json(path)  # runs the _load_json() call
    except (ValueError, OSError):  # an empty or dirty file simply yields nothing
        return []  # returns the findings to the caller
    findings: list[Finding] = []  # evaluates the findings expression
    seen: set[tuple[str, str]] = set()  # updates the stored value

    def walk_dicts(value: Any) -> Iterator[dict[str, Any]]:  # defines the walk_dicts() function
        """Yield every nested dict in a parsed JSON payload."""  # keeps the docstring text
        if isinstance(value, dict):  # evaluates the branch condition
            yield value  # yields the value incrementally
            for child in value.values():  # loops over the collection
                yield from walk_dicts(child)  # walks the subtree
        elif isinstance(value, list):  # handles the list containers
            for child in value:  # loops over the collection
                yield from walk_dicts(child)  # walks the subtree

    fallback_file = Path(root).name if root else ""  # evaluates the fallback_file expression
    for block in walk_dicts(data):  # loops over the collection
        rule_id = str(block.get("controlID") or block.get("id") or "")  # fetches the value
        if not rule_id or not block.get("severity"):  # controls must carry a rating  # evaluates the branch condition
            continue  # skips to the next loop iteration
        rule_status = str(block.get("ruleStatus") or block.get("status") or "")  # fetches the value
        if rule_status not in {"Failed", "failed", "FailedEvidence"}:  # evaluates the branch condition
            continue  # skips to the next loop iteration

        key = (rule_id, _kubescape_file(block).lower())  # lowercases the text
        if key in seen:  # evaluates the branch condition
            continue  # skips to the next loop iteration
        seen.add(key)  # adds an item to the set

        raw_file = _rel_path(_kubescape_file(block), root) or fallback_file  # fetches the value
        severity = normalize_severity(str(block.get("severity")))  # Important maps to high  # runs the normalize_severity() call
        title = str(  # assigns the computed value to title
            block.get("controlName") or block.get("name") or f"Kubescape control {rule_id}"
        )  # closes the multiline block
        message = _kubescape_message(block)  # runs the _kubescape_message() call
        findings.append(  # adds an item to the list
            Finding(  # runs the Finding() call
                source="kubescape",  # sets the source text
                category="misconfiguration",  # sets the category text
                severity=severity,  # copies the severity value into severity
                rule_id=rule_id,  # copies the rule_id value into rule_id
                title=_clean(title, 180),  # runs the _clean() call
                location=_location(raw_file),  # runs the _location() call
                detail=_clean(message),  # copies the message value into detail
                weight=weight_for("misconfiguration", severity),  # runs the weight_for() call
                file=raw_file,  # copies the raw_file value into file
                line=0,  # control reports have no line numbers  # assigns the computed value to line
                package="",  # misconfigurations are not package findings  # sets the package text
                kind="kubescape",  # sets the kind text
            )  # closes the multiline block
        )  # closes the multiline block
    return findings  # returns the findings to the caller


def _kubescape_file(block: dict[str, Any]) -> str:  # defines the _kubescape_file() function
    """Best available resource path for a failed Kubescape control."""
    obj = block.get("object")  # fetches the value
    if isinstance(obj, dict) and obj.get("kind"):  # nested v4 resource context
        parts = [str(obj.get(key) or "") for key in ("kind", "namespace", "name")]  # gathers the list values
        joined = "/".join(part for part in parts if part)  # joins the joined parts
        if joined:  # evaluates the branch condition
            return joined  # returns the joined to the caller
    for key in ("path", "resource", "key"):  # loops over the collection
        value = block.get(key)  # fetches the value
        if isinstance(value, str) and value.strip():  # evaluates the branch condition
            return value.strip()  # returns the value to the caller
        if isinstance(value, dict):  # evaluates the branch condition
            nested = str(value.get("name") or value.get("path") or "")  # fetches the value
            if nested.strip():  # evaluates the branch condition
                return nested.strip()  # returns the nested to the caller
    collections = block.get("doc-collections")  # fetches the value
    if isinstance(collections, list) and collections:  # evaluates the branch condition
        return str(collections[0])  # returns the collections[0] to the caller
    return ""  # returns the value to the caller


def _kubescape_message(block: dict[str, Any]) -> str:  # defines the _kubescape_message() function
    """First failed message, reason, or failed path of a control block."""
    for key in ("messages", "reasons"):  # loops over the collection
        entries = block.get(key)  # fetches the value
        if isinstance(entries, list) and entries and isinstance(entries[0], str):  # evaluates the branch condition
            return str(entries[0])  # returns the entries[0] to the caller
    for key in ("message", "reason"):  # loops over the collection
        value = block.get(key)  # fetches the value
        if isinstance(value, str) and value.strip():  # evaluates the branch condition
            return value.strip()  # returns the value to the caller
    failed_paths = block.get("failedPaths")  # fetches the value
    if isinstance(failed_paths, list) and failed_paths and isinstance(failed_paths[0], str):  # evaluates the branch condition
        return str(failed_paths[0])  # returns the failed_paths[0] to the caller
    return ""  # returns the value to the caller


# --------------------------------------------------------------------------
# OpenSSF Scorecard JSON
# --------------------------------------------------------------------------


def parse_scorecard_report(  # defines the parse_scorecard_report() function
    path: str | Path, root: str | Path | None = None  # evaluates the path expression
) -> list[Finding]:  # closes the multiline block
    """Parse the public scorecard.dev JSON snapshot into findings.

    Scorecard rates each check 0 (worst) to 10 (best). Only failing checks
    become findings: a 0 rates medium, any other sub-7 score rates low, and
    checks at 7+ (or marked not-applicable with a negative score) are ignored.
    A payload without a ``checks`` list simply yields nothing.
    """
    data = _load_json(path)  # runs the _load_json() call
    findings: list[Finding] = []  # evaluates the findings expression
    seen: set[str] = set()  # updates the stored value
    checks = data.get("checks") if isinstance(data, dict) else None  # fetches the value
    if not isinstance(checks, list):  # evaluates the branch condition
        return []  # returns the findings to the caller

    for check in checks:  # loops over the collection
        if not isinstance(check, dict):  # evaluates the branch condition
            continue  # skips to the next loop iteration
        name = str(check.get("name") or "").strip()  # runs the str() call
        if not name:  # evaluates the branch condition
            continue  # skips to the next loop iteration
        try:  # watches for errors in the block
            score = float(check.get("score"))  # runs the float() call
        except (TypeError, ValueError):  # handles the raised error
            continue  # skips to the next loop iteration
        if not 0 <= score <= 6:  # passing or not-applicable checks
            continue  # skips to the next loop iteration
        if name in seen:  # evaluates the branch condition
            continue  # skips to the next loop iteration
        seen.add(name)  # adds an item to the set

        severity = "medium" if score == 0 else "low"  # a 0 is the worst rating  # sets the severity text
        documentation = check.get("documentation") or {}  # fetches the value
        if not isinstance(documentation, dict):  # evaluates the branch condition
            documentation = {}  # covers the remaining branch
        extras = [  # gathers the readable Warn/Info notes  # assigns the computed value to extras
            str(item)  # runs the str() call
            for item in check.get("details") or []  # loops over the collection
            if str(item).startswith(("Warn:", "Info:"))  # keeps the human-readable notes
        ]
        parts = [str(check.get("reason") or "").strip(), *extras[:4]]  # reason plus four notes  # builds the list collection
        detail = "; ".join(part for part in parts if part)  # joins the collected parts
        findings.append(  # adds an item to the list
            Finding(  # runs the Finding() call
                source="scorecard",  # sets the source text
                category="misconfiguration",  # sets the category text
                severity=severity,  # copies the severity value into severity
                rule_id=name,  # copies the name value into rule_id
                title=f"{name} {score:g}/10",  # copies the formatted value into title
                detail=_clean(detail),  # copies the detail value into detail
                reference=str(documentation.get("url") or ""),  # copies the documentation.get value into reference
                weight=weight_for("misconfiguration", severity),  # runs the weight_for() call
                file="",  # a check has no repo-relative path  # sets the file text
                line=0,  # line-less by design  # assigns the computed value to line
                kind=f"scorecard.{name}",  # keeps the merge key unique per check  # sets the kind text
            )  # closes the multiline block
        )  # closes the multiline block
    return findings  # returns the findings to the caller


# --------------------------------------------------------------------------
# OSS-Fuzz coverage (synthetic JSON written by the runner)
# --------------------------------------------------------------------------


def parse_ossfuzz_report(  # defines the parse_ossfuzz_report() function
    path: str | Path, root: str | Path | None = None  # evaluates the path expression
) -> list[Finding]:  # closes the multiline block
    """Parse the synthetic OSS-Fuzz coverage document written by the runner.

    Continuous fuzzing is a positive signal, so it never costs points: the
    runner emits ``{"fuzzed": ...}`` and only the "not fuzzed" branch produces
    one informational code finding. A fuzzed project returns no findings at
    all - the coverage detail is visible in the scanner status instead.
    """
    data = _load_json(path)  # runs the _load_json() call
    if not data or not isinstance(data, dict) or data.get("fuzzed"):  # creates the path object
        return []  # returns the findings to the caller

    return [  # returns the value to the caller
        Finding(  # runs the Finding() call
            source="ossfuzz",  # sets the source text
            category="code",  # sets the category text
            severity="low",  # sets the severity text
            rule_id="ossfuzz-coverage",  # sets the rule_id text
            title="No OSS-Fuzz continuous fuzzing",  # sets the title text
            detail=_clean(data.get("note") or ""),  # copies the data.get value into detail
            weight=weight_for("code", "low"),  # runs the weight_for() call
            file="",  # a repository-level signal has no path  # sets the file text
            line=0,  # assigns the computed value to line
            kind="ossfuzz",  # sets the kind text
        )  # closes the multiline block
    ]  # closes the multiline block


# --------------------------------------------------------------------------
# FOSSology licence compliance (JSON normalised by scanners.run_fossology)
# --------------------------------------------------------------------------


def fossology_severity(name: str) -> str | None:  # defines the fossology_severity() function
    """The policy severity of a licence name, or None when it stays unflagged.

    Permissive families never become findings (they still appear in the
    dashboard's licence mix); everything else is matched against
    ``config.FOSSOLOGY_POLICY`` in order and keeps
    ``config.FOSSOLOGY_DEFAULT_SEVERITY`` when nothing matches.
    """
    clean_name = _clean(name).split("+")[0].strip()  # "(or later)" suffixes off
    upper = clean_name.upper()  # compares without case
    if not upper or upper in {"NULL", "NONE"}:  # evaluates the branch condition
        return None  # the server carries no licence claim here
    if any(upper == permitted.upper() for permitted in config.FOSSOLOGY_PERMISSIVE):  # evaluates the branch condition
        return None  # a permissive licence is not a compliance finding
    for pattern, severity in config.FOSSOLOGY_POLICY:  # loops over the policy
        try:  # watches for a bad user-authored pattern
            if re.search(pattern, clean_name, flags=re.IGNORECASE):  # evaluates the branch condition
                return severity  # returns the matched severity
        except re.error:  # handles the bad pattern
            continue  # skips the broken row
    return config.FOSSOLOGY_DEFAULT_SEVERITY  # returns the default severity


def parse_fossology_report(  # defines the parse_fossology_report() function
    path: str | Path,  # the normalised report file
    root: str | Path | None = None,  # the checked-out tree (for relative paths)
) -> list[Finding]:  # closes the multiline block
    """Turn the runner's licence summary into compliance findings.

    One finding per licence family the policy flags (permissive families are
    reported only in the dashboard mix); the row names the file count and
    carries up to four sample paths so a reviewer can jump straight to the
    affected components.
    """
    data = _load_json(path)  # runs the _load_json() call
    findings: list[Finding] = []  # evaluates the findings expression
    if not isinstance(data, dict):  # evaluates the branch condition
        return []  # returns the findings to the caller
    for licence in data.get("licenses") or []:  # loops over the licence rows
        if not isinstance(licence, dict):  # evaluates the branch condition
            continue  # skips the malformed row
        name = _clean(licence.get("name"))  # copies the name value into name
        severity = fossology_severity(name)  # runs the fossology_severity() call
        if not name or severity is None:  # permissive or empty: mix only
            continue  # skips the unflagged licence
        files = [str(item) for item in (licence.get("files") or []) if str(item)]  # the sample paths
        count = int(licence.get("file_count") or len(files) or 1)  # the affected file count
        findings.append(  # adds an item to the list
            Finding(  # runs the Finding() call
                source="fossology",  # sets the source text
                category="license",  # sets the category text
                severity=severity,  # copies the severity value into severity
                rule_id=name,  # the SPDX identifier is the stable rule id
                title=f"Licence {name} appears on {count} file(s)",  # the human-readable title
                detail=_clean(  # the sample paths in prose
                    f"Detected by the FOSSology Nomos/Ojo agents on the server; "
                    f"e.g. {', '.join(files[:3])}" + (f" (+{max(0, len(files) - 3)} more)" if len(files) > 3 else "")
                ),  # closes the detail build
                reference=f"https://spdx.org/licenses/{name}.html",  # the SPDX reference
                weight=weight_for("license", severity),  # runs the weight_for() call
                file=_rel_path(files[0], root) if files else "",  # the first affected path
                line=0,  # licence findings are file-scoped
                locations=[_rel_path(item, root) for item in files[:4]],  # the jump-to sample
                kind=f"fossology.{name}",  # keeps the merge key unique per licence
            )  # closes the multiline block
        )  # closes the block
    return findings  # returns the findings to the caller


# --------------------------------------------------------------------------
# Website audit JSON (written by scanners._run_web_check)
# --------------------------------------------------------------------------


def _missing_web_headers(headers: dict[str, str], scheme: str) -> list[tuple[str, str]]:
    """HTTP hardening headers that a page should carry but does not.

    Returns ``(title, kind-suffix)`` pairs; all header omissions rate as low
    misconfigurations. HSTS only makes sense on an https page, and plain-http
    transport is rated separately as a high finding.
    """
    lowered = {str(key).lower() for key in headers}  # lowercases every header name
    wanted: list[tuple[str, str]] = []  # evaluates the wanted expression
    if "content-security-policy" not in lowered:  # evaluates the branch condition
        wanted.append(("Missing Content-Security-Policy", "csp"))  # adds an item
    if "strict-transport-security" not in lowered and scheme == "https":  # evaluates the branch condition
        wanted.append(("Missing Strict-Transport-Security (HSTS)", "hsts"))  # adds an item
    if "x-content-type-options" not in lowered:  # evaluates the branch condition
        wanted.append(("Missing X-Content-Type-Options", "nosniff"))  # adds an item
    if "x-frame-options" not in lowered:  # judged independently: a bare CSP rarely sets frame rules
        wanted.append(("Missing clickjacking defence (X-Frame-Options)", "frame"))
    if "referrer-policy" not in lowered:  # evaluates the branch condition
        wanted.append(("Missing Referrer-Policy", "referrer"))  # adds an item to the list
    return wanted  # returns the wanted to the caller


def _web_probe_finding(probe: dict[str, Any]) -> Finding | None:
    """One exposed dotfile probe as a secret finding, or None when clean.

    A 200 reply alone proves nothing (many single-page apps answer every
    path with their index), so the body must look like the probed artifact.
    """
    if str(probe.get("status") or "") != "200":  # evaluates the branch condition
        return None  # returns None to the caller
    body = str(probe.get("body") or "")  # copies the probe.get value into body
    name = str(probe.get("name") or "")  # copies the probe.get value into name
    looks_html = "<html" in body.lower()[:400]  # SPA fall-back pages copy the index
    if name == ".env" and "=" in body and len(body) > 40 and not looks_html:  # evaluates the branch condition
        return Finding(  # runs the Finding() call
            source="webcheck",  # sets the source text
            category="secret",  # an exposed env file leaks credentials
            severity="high",  # copies the severity value into severity
            rule_id="exposed-env",  # sets the rule_id text
            title="Exposed .env file",  # sets the title text
            location=str(probe.get("path") or ""),  # copies the probe.get value into location
            detail="A request for /.env returned configuration-style content.",  # supplies the literal text
            weight=weight_for("secret", "high"),  # runs the weight_for() call
            file="",  # a website has no source file path  # sets the file text
            line=0,  # assigns the computed value to line
            kind="web.exposed-env",  # sets the kind text
        )  # closes the multiline block
    if name == ".git/config" and "[core" in body and not looks_html:  # evaluates the branch condition
        return Finding(  # runs the Finding() call
            source="webcheck",  # sets the source text
            category="secret",  # exposes the full source history
            severity="high",  # copies the severity value into severity
            rule_id="exposed-git",  # sets the rule_id text
            title="Exposed .git repository",  # sets the title text
            location=str(probe.get("path") or ""),  # copies the probe.get value into location
            detail="A request for /.git/config returned Git configuration content.",  # supplies the literal text
            weight=weight_for("secret", "high"),  # runs the weight_for() call
            file="",  # a website has no source file path  # sets the file text
            line=0,  # assigns the computed value to line
            kind="web.exposed-git",  # sets the kind text
        )  # closes the multiline block
    return None  # returns None to the caller


def parse_webcheck_report(  # defines the parse_webcheck_report() function
    path: str | Path, root: str | Path | None = None  # evaluates the path expression
) -> list[Finding]:  # closes the multiline block
    """Parse the website-audit JSON written by the web-check runner.

    The document carries the fetched page (final URL, status line, headers)
    plus dotfile probes. Findings rate as :class:`Finding` rows:

    * missing hardening headers -> low misconfigurations;
    * an un-upgraded plain-http address -> one high transport finding;
    * probes for ``/.env`` and ``/.git/config`` that answer with
      configuration-style bodies -> high secret leaks (an SPA fall-back
      that echoes ``index.html`` is not treated as exposure).
    """
    try:  # watches for errors in the block
        data = _load_json(path)  # runs the _load_json() call
    except (ValueError, OSError):  # an empty or dirty file simply yields nothing
        return []  # returns the findings to the caller
    if not isinstance(data, dict):  # evaluates the branch condition
        return []  # returns the findings to the caller

    page = data.get("page") or {}  # fetches the value
    scheme = str(page.get("scheme") or data.get("scheme") or "https")  # fetches the value
    headers = page.get("headers") or {}  # fetches the value
    if not isinstance(headers, dict):  # evaluates the branch condition
        headers = {}  # covers the remaining branch
    final_url = str(page.get("final_url") or data.get("url") or "")  # the page is the redirect truth

    findings: list[Finding] = []  # evaluates the findings expression
    seen: set[str] = set()  # starts the seen set
    if scheme != "https" and final_url.startswith("http://"):  # evaluates the branch condition
        findings.append(  # adds an item to the list
            Finding(  # runs the Finding() call
                source="webcheck",  # sets the source text
                category="misconfiguration",  # transport hardening
                severity="high",  # copies the severity value into severity
                rule_id="plain-http",  # sets the rule_id text
                title="Site served over plain HTTP without TLS",  # sets the title text
                location=final_url,  # copies the final_url value into location
                detail="Visitors' traffic to the checked address is not encrypted.",  # supplies the literal text
                weight=weight_for("misconfiguration", "high"),  # runs the weight_for() call
                file="",  # a website has no source file path  # sets the file text
                line=0,  # assigns the computed value to line
                kind="web.plain-http",  # sets the kind text
            )  # closes the multiline block
        )  # closes the multiline block

    for title, suffix in _missing_web_headers(headers, scheme):  # loops over the collection
        findings.append(  # adds an item to the list
            Finding(  # runs the Finding() call
                source="webcheck",  # sets the source text
                category="misconfiguration",  # sets the category text
                severity="low",  # header omissions rate low
                rule_id=f"missing-{suffix}",  # sets the rule_id text
                title=title,  # copies the title value into title
                location=final_url,  # copies the final_url value into location
                detail="The checked page does not send this hardening header.",  # supplies the literal text
                weight=weight_for("misconfiguration", "low"),  # runs the weight_for() call
                file="",  # a website has no source file path  # sets the file text
                line=0,  # assigns the computed value to line
                kind=f"web.headers.{suffix}",  # makes every merge key unique  # sets the kind text
            )  # closes the multiline block
        )  # closes the multiline block

    for probe in data.get("probes") or []:  # loops over the collection
        probe_block = probe if isinstance(probe, dict) else {}  # keeps shapes safe
        finding = _web_probe_finding(probe_block)  # runs the _web_probe_finding() call
        if finding and finding.kind not in seen:  # evaluates the branch condition
            seen.add(finding.kind)  # adds an item to the seen set
            findings.append(finding)  # adds an item to the list
    return findings  # returns the findings to the caller


# --------------------------------------------------------------------------
# Cross-tool de-duplication
# --------------------------------------------------------------------------


def _merge_key(finding: Finding) -> tuple[Any, ...]:  # defines the _merge_key() function
    """Identity of an issue across tools - the same bug must only cost points once."""  # keeps the docstring text
    if finding.category == "vulnerability":  # evaluates the branch condition
        identifier = _first_cve([finding.rule_id, *finding.aliases], finding.rule_id)  # runs the _first_cve() call
        package = (finding.package or finding.title).lower()  # lowercases the text
        return ("vulnerability", identifier.upper(), package)  # returns the value to the caller
    if finding.category in {"secret", "misconfiguration"}:  # evaluates the branch condition
        return (  # returns the value to the caller
            finding.category,  # evaluates the finding.category expression
            (finding.file or finding.location).lower(),  # lowercases the text
            finding.line,  # evaluates the finding.line expression
            finding.kind,  # evaluates the finding.kind expression
        )  # closes the multiline block
    return (  # returns the value to the caller
        finding.category,  # evaluates the finding.category expression
        (finding.file or finding.location).lower(),  # lowercases the text
        finding.line,  # evaluates the finding.line expression
        finding.cwe or finding.rule_id,  # evaluates the finding.cwe expression
    )  # closes the multiline block


def merge_findings(findings: Iterable[Finding]) -> list[Finding]:  # defines the merge_findings() function
    """Collapse duplicate findings reported by more than one scanner.

    The merged finding keeps the worst severity and the largest single penalty,
    so a CVE reported by Trivy, Grype and OSV costs 12 points once - not 36 -
    while still naming all three tools.
    """
    merged: dict[tuple[Any, ...], Finding] = {}  # evaluates the merged expression

    for original in findings:  # loops over the collection
        finding = replace(original)  # swaps the text
        finding.tools = list(dict.fromkeys(finding.tools or [finding.source]))  # builds the list collection
        finding.aliases = list(dict.fromkeys(finding.aliases))  # builds the list collection
        finding.locations = list(dict.fromkeys(finding.locations or ([finding.location] if finding.location else [])))  # builds the list collection

        key = _merge_key(finding)  # runs the _merge_key() call
        current = merged.get(key)  # fetches the value
        if current is None:  # evaluates the branch condition
            merged[key] = finding  # copies the finding value into merged[key]
            continue  # skips to the next loop iteration

        current.tools = list(dict.fromkeys([*current.tools, *finding.tools]))  # builds the list collection
        if severity_rank(finding.severity) < severity_rank(current.severity):  # evaluates the branch condition
            current.severity = finding.severity  # copies the finding.severity value into current.severity
        if finding.weight > current.weight:  # evaluates the branch condition
            current.weight = finding.weight  # copies the finding.weight value into current.weight
            current.title = finding.title  # copies the finding.title value into current.title
            current.detail = finding.detail  # copies the finding.detail value into current.detail
            current.rule_id = finding.rule_id  # copies the finding.rule_id value into current.rule_id
            current.reference = finding.reference or current.reference  # copies the finding.reference value into current.reference
        if not current.file and finding.file:  # evaluates the branch condition
            current.file = finding.file  # copies the finding.file value into current.file
            current.line = finding.line  # copies the finding.line value into current.line
            current.location = finding.location  # copies the finding.location value into current.location
        current.cwe = current.cwe or finding.cwe  # keeps the first reported CWE
        current.cvss = max(current.cvss, finding.cvss)  # keeps the highest score
        current.epss = max(current.epss, finding.epss)  # keeps the highest likelihood
        current.kev = current.kev or finding.kev  # KEV flag sticks once known
        if not current.published or finding.published < current.published:  # evaluates the earlier date
            current.published = current.published or finding.published  # keeps the oldest, earliest run
        for location in finding.locations:  # loops over the collection
            if location and location not in current.locations:  # evaluates the branch condition
                current.locations.append(location)  # adds an item to the list

    return list(merged.values())  # returns the list to the caller


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------

# The five scoring categories and the labels/why-text the renderers print.
# The category list is authoritative in :mod:`reportkeys`; the label/why
# registries live here so every consumer (render text, exports, app) reads
# the module, and no report copy of them drifts from the source.
CATEGORY_LABELS = {  # assigns the computed value to CATEGORY_LABELS
    "vulnerability": "Dependency vulnerabilities",  # maps the vulnerability dictionary entry
    "secret": "Committed secrets",  # maps the secret dictionary entry
    "misconfiguration": "IaC / container misconfigurations",  # maps the misconfiguration dictionary entry
    "code": "Code security findings",  # maps the code dictionary entry
    "license": "Open-source licence findings",  # maps the license dictionary entry
    "code-quality": "Code maintainability findings",  # maps the code-quality dictionary entry
}  # closes the multiline block

CATEGORY_WHY = {  # assigns the computed value to CATEGORY_WHY
    "vulnerability": "a library you ship has a known, publicly documented flaw",  # maps the vulnerability dictionary entry
    "secret": "a credential appears to be committed in plain text",  # maps the secret dictionary entry
    "misconfiguration": "deployment or infrastructure config weakens the runtime",  # maps the misconfiguration dictionary entry
    "code": "a scanner traced attacker-controlled data into a dangerous operation",  # maps the code dictionary entry
    "license": "a component ships under a licence that limits how you can use it",  # maps the license dictionary entry
    "code-quality": "maintainability issue that makes future bugs more likely",  # maps the code-quality dictionary entry
}  # closes the multiline block


def _charge_category(item: Any) -> str:  # defines the _charge_category() function
    """A finding's scoring category, accepting rows and dict payloads."""
    if isinstance(item, dict):  # evaluates the branch condition
        return str(item.get("category") or "code")  # copies the category value
    return str(getattr(item, "category", "") or "code")  # copies the attribute value


def _charge_weight(item: Any) -> float:  # defines the _charge_weight() function
    """A finding's raw point weight, accepting rows and dict payloads."""
    if isinstance(item, dict):  # evaluates the branch condition
        return float(item.get("weight") or 0.0)  # copies the weight value
    return float(getattr(item, "weight", 0.0) or 0.0)  # copies the attribute value


class EffectiveCharges(NamedTuple):  # defines the EffectiveCharges class
    """The cap arithmetic shared by the rescore refunds and recommendations."""

    findings: list[Any]  # the materialised sweep set, in walk order
    raw: dict[str, float]  # the pre-caps raw charge per category
    shares: list[float]  # each finding's effective charge, aligned with ``findings``


def effective_charges(  # defines the effective_charges() function
    findings: Iterable[Any],  # evaluates the findings expression
    caps: dict[str, float],  # evaluates the caps expression
) -> EffectiveCharges:  # closes the multiline block
    """One category's cap spreads its charge over its findings proportionally.

    Each finding's EFFECTIVE charge is its pro-rata slice of the category
    charge (``cap x weight / raw`` when the cap binds, otherwise the raw
    headline weight), so an omission refunds that share - not the raw weight -
    and the refunds across a category never exceed the cap. Used verbatim by
    the rescore refund maths and the recommendations impact ranking; there is
    deliberately a single implementation so the two can never diverge.

    Works with :class:`Finding` rows and plain dict payloads alike; the input
    is materialised once, so a one-shot iterator is safe.
    """
    items = list(findings)  # materialises the sweep set
    raw: dict[str, float] = {}  # the pre-caps raw per category
    for item in items:  # loops over the collection
        category = _charge_category(item)  # reads the category
        raw[category] = raw.get(category, 0.0) + _charge_weight(item)  # accumulates
    shares: list[float] = []  # the per-finding effective charges
    for item in items:  # loops over the collection
        category = _charge_category(item)  # reads the category
        weight = _charge_weight(item)  # reads the point weight
        total = raw.get(category, 0.0)  # copies the category value into total
        cap_value = caps.get(category, weight)  # reads the cap value
        if total > cap_value:  # cap-bound: charge spreads pro-rata
            applied = min(total, caps.get(category, total))  # the category charge
            shares.append(applied * (weight / total))  # the finding's slice
        else:  # covers the remaining branch
            shares.append(weight)  # unbound categories charge the headline weight
    return EffectiveCharges(items, raw, shares)  # returns the typed result


def _band(score: int) -> tuple[str, str]:  # defines the _band() function
    for threshold, label, colour in config.BANDS:  # loops over the collection
        if score >= threshold:  # evaluates the branch condition
            return label, colour  # returns the label to the caller
    return config.BANDS[-1][1], config.BANDS[-1][2]  # returns the config.BANDS to the caller


# --------------------------------------------------------------------------
# Context normalisation
# --------------------------------------------------------------------------


def maintenance_pulse(care_summary: dict[str, Any] | None) -> float | None:
    """The 0-1 maintenance pulse behind the CVE cap relief.

    A project shipping commits and releases with a broad contributor base is
    patching inherited issues continuously, so part of its raw CVE count is
    the ecosystem moving, not neglect. Missing Care data returns None and the
    caller keeps the neutral factor.
    """
    if not care_summary:  # evaluates the branch condition
        return None  # no Care blob: nothing measured
    knobs = config.CONTEXT_PULSE  # copies the config value into knobs
    parts: list[tuple[Any, float, float]] = [  # (value, weight, saturating norm)
        (care_summary.get("commits_last_90d"), knobs["commits_weight"], knobs["commits_norm"]),  # the recent-commit block
        (care_summary.get("releases_last_year"), knobs["releases_weight"], knobs["releases_norm"]),  # the release block
        (care_summary.get("contributors"), knobs["contributors_weight"], knobs["contributors_norm"]),  # the people block
    ]  # closes the parts build
    pulse = 0.0  # evaluates the pulse expression
    seen = False  # whether any signal was measurable at all
    for value, weight, norm in parts:  # loops over the parts
        if value is None:  # evaluates the branch condition
            continue  # an unfetched signal contributes nothing
        seen = True  # at least one signal exists
        pulse += float(value) / max(1.0, norm) * weight  # saturates at the norm
    if not seen:  # evaluates the branch condition
        return None  # the blob exists but carries no signals
    return min(1.0, pulse)  # clamps the pulse at full credit


def _density_factor(count: int | None, knobs: dict[str, float]) -> float | None:
    """1 + weight x log growth above the base, clamped; None when unmeasured."""
    if not count:  # evaluates the branch condition
        return None  # no SBOM / file table: nothing measured
    base = float(knobs.get("density_base") or 1.0)  # copies the base value
    excess = max(0.0, float(count) - base)  # counts at or under the base are neutral
    if excess <= 0.0:  # evaluates the branch condition
        return None  # a small surface measures nothing worth relieving
    step = math.log(1.0 + excess / base)  # the log growth of the surface
    width = knobs.get("density_weight") or 0.0  # copies the slope value
    cap_at = knobs.get("density_cap")  # the widest step allowed
    density = 1.0 + width * step  # evaluates the density expression
    if cap_at is not None:  # evaluates the branch condition
        density = min(density, 1.0 + cap_at)  # clamps the step at the widest allowed
    return density  # returns the density to the caller


def normalised_caps(  # defines the normalised_caps() function
    packages: int | None,  # evaluates the packages expression
    files: int | None,  # evaluates the files expression
    care_summary: dict[str, Any] | None,  # evaluates the care_summary expression
) -> tuple[dict[str, float], dict[str, Any]]:
    """The effective cap table plus the persisted context summary.

    Every category with no measured context keeps the plain
    :data:`config.CAPS` value exactly, so a scan without an SBOM, a small
    dependency surface and no Care blob scores identically to the
    pre-normalisation model. Returns ``(effective_caps, context)`` where
    ``context`` is stored on the report and reused verbatim by the rescore.
    """
    pulse = maintenance_pulse(care_summary)  # runs the maintenance_pulse() call
    effective: dict[str, float] = dict(config.CAPS)  # starts from the plain caps
    factors: dict[str, dict[str, Any]] = {}  # the per-category context table
    counts = {"packages": packages, "files": files}  # the measured surface sizes
    for category, knobs in config.SCORING_CONTEXT.items():  # walks the relief table
        density = _density_factor(  # runs the _density_factor() call
            counts.get(knobs.get("density_from") or ""), knobs  # the surface count for this category
        )  # closes the density call
        if density is None and pulse is None:  # evaluates the branch condition
            continue  # nothing measured: the plain cap stands
        factor = density or 1.0  # the density share of the factor
        if pulse is not None and knobs.get("pulse_bonus"):  # evaluates the branch condition
            factor *= 1.0 + float(knobs["pulse_bonus"]) * pulse  # the maintenance widen
        relief = max(float(knobs.get("relief_floor") or 0.0), 1.0 / factor)  # the applied relief
        effective[category] = round(config.CAPS.get(category, 100.0) * relief, 2)  # the widened cap
        factors[category] = {  # stores the explanation table
            "density": density,  # maps the density dictionary entry
            "pulse": pulse,  # maps the pulse dictionary entry
            "factor": round(factor, 2),  # maps the factor dictionary entry
            "relief": round(relief, 2),  # maps the relief dictionary entry
            "effective_cap": effective[category],  # maps the effective_cap dictionary entry
        }  # closes the block
    context: dict[str, Any] = {  # builds the summary structure
        "packages": packages,  # maps the packages dictionary entry
        "files": files,  # maps the files dictionary entry
        "pulse": None if pulse is None else round(pulse, 2),  # maps the pulse dictionary entry
        "factors": factors,  # maps the factors dictionary entry
        "effective_caps": dict(effective),  # maps the effective_caps dictionary entry
    }  # closes the structure
    return effective, context  # returns the pair to the caller


def build_report(  # defines the build_report() function
    findings: Iterable[Finding],  # evaluates the findings expression
    *,  # spreads the collected values
    repo: dict[str, Any] | None = None,  # evaluates the repo expression
    scanner_status: dict[str, dict[str, Any]] | None = None,  # evaluates the scanner_status expression
    warnings: list[str] | None = None,  # evaluates the warnings expression
    languages: list[str] | None = None,  # evaluates the languages expression
    duration_seconds: float = 0.0,  # evaluates the duration_seconds expression
    inventory: dict[str, Any] | None = None,  # evaluates the inventory expression
    sbom: dict[str, Any] | None = None,  # the merged SBOM payload (Print SBOM / Export SBOM read this)
    frameworks: Iterable[str] | None = None,  # evaluates the frameworks expression
    care: dict[str, Any] | None = None,  # evaluates the care expression
    dashboard: Iterable[str] | None = None,  # evaluates the dashboard expression
    dashboard_inputs: dict[str, Any] | None = None,  # evaluates the dashboard_inputs expression
    language_file_counts: dict[str, Any] | None = None,  # evaluates the language_file_counts expression
) -> dict[str, Any]:  # closes the multiline block
    """Aggregate findings into a scored, human-readable report.

    ``findings`` may contain duplicates across scanners; they are always merged
    first, so the score reflects unique issues. ``frameworks`` selects the
    compliance frameworks whose controls the findings are mapped onto. ``care``
    is the raw maintenance statistics blob; it never changes the score.
    """
    raw_findings = list(findings)  # builds the list collection
    findings = merge_findings(raw_findings)  # runs the merge_findings() call
    selected_frameworks = list(frameworks) if frameworks is not None else []  # builds the list collection
    selected_dashboard = dashboard_module.validate(dashboard)  # validates the dashboard selection
    repo = repo or {}  # copies the repo value into repo
    scanner_status = scanner_status or {}  # copies the scanner_status value into scanner_status
    warnings = list(warnings or [])  # builds the list collection

    # One sweep over the merged findings gathers everything the report needs,
    # so the list is not walked twenty times: raw/caps charge maths, the
    # category/severity counts, the per-tool severity tallies and the
    # cross-tool corroborated count all land in a single pass.
    raw: dict[str, float] = {key: 0.0 for key in config.CAPS}  # evaluates the raw expression
    counts: dict[str, dict[str, int]] = {  # evaluates the counts expression
        category: {sev: 0 for sev in config.SEVERITY_ORDER} for category in config.CAPS  # evaluates the category expression
    }  # closes the multiline block
    tool_counts: dict[str, dict[str, int]] = {}  # per-tool severity tallies (for _tool_breakdown)
    corroborated = 0  # findings detected by two or more tools

    for finding in findings:  # loops over the collection
        category = finding.category if finding.category in config.CAPS else "code"  # copies the finding.category value into category
        raw[category] += finding.weight  # evaluates the raw expression
        counts[category][finding.severity] = counts[category].get(finding.severity, 0) + 1  # fetches the value
        if len(dict.fromkeys(finding.tools)) > 1:  # evaluates the branch condition
            corroborated += 1  # counts one more cross-tool confirmation
        for tool in finding.tools:  # loops over the tools
            per_tool = tool_counts.setdefault(  # runs the setdefault() call
                tool, {sev: 0 for sev in config.SEVERITY_ORDER} | {"total": 0}  # the severity tallies
            )  # closes the multiline block
            per_tool[finding.severity] = per_tool.get(finding.severity, 0) + 1  # fetches the value
            per_tool["total"] += 1  # evaluates the per_tool expression

    # Context normalisation: the cap table widens where the scan's measured
    # context explains part of the finding count (big dependency surfaces,
    # active maintenance). Categories with no measured context keep the plain
    # cap exactly, so the model degrades to the previous behaviour.
    care_summary = summarize_care(care) if care else None  # runs the summarize_care() call
    packages = (inventory or {}).get("components")  # the SBOM component count
    files_count = sum(int(v or 0) for v in (language_file_counts or {}).values()) or None  # the scanned file count
    caps_eff, context_summary = normalised_caps(  # runs the normalised_caps() call
        int(packages) if isinstance(packages, (int, float)) else None,  # the surface count
        files_count,  # the scanned file count
        care_summary,  # the maintenance blob
    )  # closes the normalisation call

    applied = {category: min(total, caps_eff[category]) for category, total in raw.items()}  # takes the smallest value
    total_penalty = sum(applied.values())  # adds up the values
    score = max(0, min(100, int(round(100 - total_penalty))))  # takes the largest value
    band_label, band_colour = _band(score)  # runs the _band() call

    critical = sum(counts[category]["critical"] for category in RISK_CATEGORIES)  # re-sums the criticals
    high = sum(counts[category]["high"] for category in RISK_CATEGORIES)  # re-sums the highs
    failed = [  # assigns the computed value to failed
        name  # evaluates the name expression
        for name, status in scanner_status.items()  # loops over the collection
        if status.get("status") not in {"ok", "skipped"}  # evaluates the branch condition
    ]  # closes the multiline block
    required_failed = [name for name in failed if name in config.REQUIRED_TOOLS]  # assigns the computed value to required_failed
    optional_failed = [name for name in failed if name not in config.REQUIRED_TOOLS]  # assigns the computed value to optional_failed
    if optional_failed:  # evaluates the branch condition
        labels = ", ".join(config.TOOL_LABELS.get(name, name) for name in sorted(optional_failed))  # sorts the values
        warnings.append(  # adds an item to the list
            f"Optional scanner{'s' if len(optional_failed) != 1 else ''} did not complete: "  # runs the len() call
            f"{labels}. The remaining scanners still produced the result below."  # supplies the literal text
        )  # closes the multiline block

    skipped = [  # assigns the computed value to skipped
        name for name, status in scanner_status.items() if status.get("status") == "skipped"  # walks the key/value pairs
    ]  # closes the multiline block
    if skipped:  # evaluates the branch condition
        labels = ", ".join(config.TOOL_LABELS.get(name, name) for name in skipped)  # sets the labels text
        warnings.append(  # adds an item to the list
            f"Not run this time: {labels}. Their coverage is not included in this score."  # maps the Not run this time: {labe dictionary entry
        )  # closes the multiline block

    secure = score >= config.SECURE_MIN_SCORE and critical == 0 and not required_failed  # copies the score value into secure

    if secure:  # evaluates the branch condition
        reason = (  # assigns the computed value to reason
            f"The weighted score is {score}/100, above the {config.SECURE_MIN_SCORE} pass mark, "  # supplies the literal text
            "and no critical-severity findings were reported."  # supplies the literal text
        )  # closes the multiline block
    elif critical:  # checks the alternate condition
        reason = (  # assigns the computed value to reason
            f"{critical} critical-severity finding{'s' if critical != 1 else ''} were reported. "  # evaluates the f expression
            "A repository with critical risk is never marked secure, whatever the aggregate score."  # supplies the literal text
        )  # closes the multiline block
    elif required_failed:  # checks the alternate condition
        reason = (  # assigns the computed value to reason
            "A required scanner did not complete ("  # supplies the literal text
            + ", ".join(sorted(required_failed))  # waits for the thread
            + "), so the result cannot be treated as a clean bill of health."  # executes the statement
        )  # closes the multiline block
    elif score < config.SECURE_MIN_SCORE:  # checks the alternate condition
        reason = (  # assigns the computed value to reason
            f"The weighted score is {score}/100, below the {config.SECURE_MIN_SCORE} pass mark "  # supplies the literal text
            f"({high} high and {critical} critical findings included)."  # supplies the literal text
        )  # closes the multiline block
    else:  # pragma: no cover - defensive  # covers the remaining branch
        reason = f"The weighted score is {score}/100."  # sets the reason text

    groups = _group_findings(  # runs the _group_findings() call
        findings, config.TOP_RISK_LIMIT,  # the merged sweep set and the row limit
        charges=effective_charges(findings, caps_eff).shares,  # the shared per-finding shares
    )  # closes the multiline block

    by_tool = _tool_breakdown(findings, scanner_status, tool_counts=tool_counts)  # consumes the shared tallies
    tool_names = list(by_tool)  # builds the list collection
    ordered_status = {  # assigns the computed value to ordered_status
        tool: scanner_status[tool] for tool in config.ALL_TOOLS if tool in scanner_status  # evaluates the tool expression
    }  # closes the multiline block
    ordered_status.update(  # refreshes the layout
        {name: status for name, status in scanner_status.items() if name not in ordered_status}  # walks the key/value pairs
    )  # closes the multiline block

    confidence = compute_confidence(findings, scanner_status, corroborated=corroborated)  # runs the compute_confidence() call
    dedupe = {  # assigns the computed value to dedupe
        "raw": len(raw_findings),  # maps the raw dictionary entry
        "merged": len(findings),  # maps the merged dictionary entry
        "removed": max(0, len(raw_findings) - len(findings)),  # maps the removed dictionary entry
        "corroborated": corroborated,  # the count gathered in the single sweep
    }  # closes the multiline block

    framework_payloads, finding_map = compliance.map_all(  # the one matching sweep
        findings, selected_frameworks  # runs the map_all() call
    )  # closes the multiline block

    report = {  # builds the report dictionary
        "app_version": config.APP_VERSION,  # maps the app_version dictionary entry
        "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),  # maps the generated_at dictionary entry
        "repo": repo,  # maps the repo dictionary entry
        "languages": languages or [],  # maps the languages dictionary entry
        "language_file_counts": dict(language_file_counts or {}),  # maps the language_file_counts dictionary entry
        "score": score,  # maps the score dictionary entry
        "band": band_label,  # maps the band dictionary entry
        "band_colour": band_colour,  # maps the band_colour dictionary entry
        "verdict": "SECURE" if secure else "INSECURE",  # maps the verdict dictionary entry
        "verdict_reason": reason,  # maps the verdict_reason dictionary entry
        "secure_threshold": config.SECURE_MIN_SCORE,  # maps the secure_threshold dictionary entry
        "explanation": explanation_text(),  # maps the explanation dictionary entry
        "confidence": confidence,  # maps the confidence dictionary entry
        "dedupe": dedupe,  # maps the dedupe dictionary entry
        "frameworks": framework_payloads,  # maps the frameworks dictionary entry
        "framework_by_finding": (  # maps the framework_by_finding dictionary entry
            finding_map if selected_frameworks  # evaluates the branch condition
            else {}  # covers the remaining branch
        ),  # closes the multiline block
        "care": care_summary,  # maps the care dictionary entry
        # The dashboard only reads the weekly commit blobs, so that slice is
        # all of ``care_raw`` that persists into the stored report.
        "care_raw": {"commit_activity": list((care or {}).get("commit_activity") or [])},  # maps the care_raw dictionary entry
        "dashboard_selection": selected_dashboard,  # maps the dashboard_selection dictionary entry
        "dashboard": {},  # payloads are built once the dict exists (see below)
        "dashboard_inputs": dict(dashboard_inputs or {}),  # maps the dashboard_inputs dictionary entry
        "penalties": {key: round(value, 2) for key, value in applied.items()},  # maps the penalties dictionary entry
        "raw_penalties": {key: round(value, 2) for key, value in raw.items()},  # maps the raw_penalties dictionary entry
        "caps": dict(caps_eff),  # the effective (context-normalised) cap table
        "context": context_summary,  # the persisted normalisation summary for the rescore
        "counts": counts,  # maps the counts dictionary entry
        "tools": tool_names,  # maps the tools dictionary entry
        "tool_labels": {name: config.TOOL_LABELS.get(name, name.title()) for name in tool_names},  # maps the tool_labels dictionary entry
        "by_tool": by_tool,  # maps the by_tool dictionary entry
        "totals": {  # maps the totals dictionary entry
            "findings": len(findings),  # maps the findings dictionary entry
            "critical": critical,  # maps the critical dictionary entry
            "high": high,  # maps the high dictionary entry
            "medium": sum(counts[c]["medium"] for c in counts),  # maps the medium dictionary entry
            "low": sum(counts[c]["low"] for c in counts),  # maps the low dictionary entry
            "unknown": sum(counts[c]["unknown"] for c in counts),  # maps the unknown dictionary entry
            # Per-category findings counts, so renderers never re-sum the
            # counts table (the values below are the same sums, precomputed).
            "by_category": {category: sum(values.values()) for category, values in counts.items()},  # maps the by_category dictionary entry
        },  # closes the multiline block
        "greatest_risks": groups,  # maps the greatest_risks dictionary entry
        "inventory": inventory,  # maps the inventory dictionary entry
        "sbom": dict(sbom or {}),  # the merged SBOM payload; empty when no SBOM scanner ran
        "scanner_status": ordered_status,  # maps the scanner_status dictionary entry
        "warnings": warnings,  # maps the warnings dictionary entry
        "duration_seconds": round(duration_seconds, 1),  # maps the duration_seconds dictionary entry
        "findings": [finding.to_dict() for finding in findings],  # maps the findings dictionary entry
    }  # closes the multiline block
    if selected_dashboard:  # evaluates the branch condition
        report["dashboard"] = dashboard_module.collect_metrics(  # builds the dashboard payloads
            report, selected_dashboard  # runs the collect_metrics() call
        )  # closes the multiline block
    return report  # returns the report to the caller


def _filter_framework_payloads(  # defines the _filter_framework_payloads() function
    frameworks: dict[str, dict[str, Any]],  # the already-built framework payloads
    finding_map: dict[str, dict[str, list[str]]],  # the already-built per-finding refs
    scored: list[Finding],  # the kept findings only
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, list[str]]]]:  # closes the multiline block
    """Rescore = filter, not re-match: rebuild the framework payloads from the
    stored per-finding control references instead of re-running the
    keyword matcher over the survivors.

    Returns ``(frameworks, finding_by_finding)`` shaped exactly like a fresh
    :func:`compliance.map_all` pass over ``scored``.
    """
    kept: dict[str, list[Finding]] = {}  # the surviving rows grouped by their map key
    for finding in scored:  # loops over the scoring set
        kept.setdefault(reportkeys.location_key(finding), []).append(finding)  # groups the rows

    fresh_map = {key: finding_map[key] for key in kept if key in finding_map}  # the filtered refs
    payloads: dict[str, dict[str, Any]] = {}  # the rebuilt payloads
    for key, entry in frameworks.items():  # loops over the selected frameworks
        label = entry.get("label", key)  # copies the entry value into label
        buckets: dict[str, dict[str, Any]] = {  # resets the buckets shape
            control["id"]: {  # evaluates the control["id"] expression
                "id": control["id"],  # maps the id dictionary entry
                "title": control.get("title", ""),  # maps the title dictionary entry
                "status": "clear",  # maps the status dictionary entry
                "affected": 0,  # maps the affected dictionary entry
                "worst": "",  # maps the worst dictionary entry
                "rule_ids": [],  # maps the rule_ids dictionary entry
                "examples": [],  # maps the examples dictionary entry
            }  # closes the multiline block
            for control in entry.get("controls") or []  # loops over the collection
        }  # closes the multiline block
        mapped_ids: set[int] = set()  # updates the stored value
        for row_key in kept:  # keeps the scoring-set walk order
            refs = (finding_map.get(row_key) or {}).get(label) or []  # the stored controls
            if not refs:  # evaluates the branch condition
                continue  # skips the unmapped rows
            for finding in kept[row_key]:  # loops over the keyed rows
                mapped_ids.add(id(finding))  # adds an item to the set
                for control_id in refs:  # loops over the mapped controls
                    bucket = buckets.get(control_id)  # fetches the bucket
                    if bucket is None:  # evaluates the branch condition
                        continue  # a stale ref guards itself
                    bucket["affected"] += 1  # evaluates the bucket expression
                    bucket["rule_ids"].append(finding.rule_id)  # adds an item to the list
                    if len(bucket["examples"]) < 3:  # evaluates the branch condition
                        bucket["examples"].append(f"{finding.title} ({finding.location or 'location n/a'})")  # adds an item to the list
                    if not bucket["worst"] or reportkeys.severity_rank(finding.severity) < reportkeys.severity_rank(bucket["worst"]):  # evaluates the branch condition
                        bucket["worst"] = finding.severity  # copies the finding.severity value into bucket["worst"]
        for bucket in buckets.values():  # loops over the collection
            if bucket["affected"]:  # evaluates the branch condition
                bucket["status"] = "affected"  # sets the bucket["status"] text
            else:  # covers the remaining branch
                bucket.pop("rule_ids", None)  # runs the pop() call
                bucket.pop("examples", None)  # runs the pop() call
        payloads[key] = {  # assigns the computed value to payloads[key]
            "key": entry.get("key", key),  # maps the key dictionary entry
            "label": label,  # maps the label dictionary entry
            "description": entry.get("description", ""),  # maps the description dictionary entry
            "controls": list(buckets.values()),  # maps the controls dictionary entry
            "affected_controls": sum(1 for b in buckets.values() if b["status"] == "affected"),  # maps the affected_controls dictionary entry
            "total_controls": len(buckets),  # maps the total_controls dictionary entry
            "unmapped": len(scored) - len(mapped_ids),  # the arithmetic complement
        }  # closes the multiline block
    return payloads, fresh_map  # returns both structures


def rescore_report(report: dict[str, Any], omitted: Iterable[str] | None = None) -> dict[str, Any]:
    """Recompute score, band and verdict with chosen risk groups excluded.

    The report's ``omitted_groups`` list names the risk themes (the
    ``GREATEST RISKS`` rows) the user judged mitigated elsewhere. Everything
    that is a property of the *scan* (tools, care, inventory, confidence,
    de-duplication) is kept as scanned; everything that is a consequence of
    the *scoring set* (score, band, verdict, counts, totals, penalties,
    greatest risks, framework mapping and per-finding omitted flags) is
    recomputed, so removing a finding from a capped category can also free
    cap space for its neighbours.
    """
    if omitted is None:  # an explicit empty list must clear the choice, not re-apply it
        omitted_set: set[str] = set(report.get("omitted_groups") or [])  # fetches the excluded set
    else:  # covers the remaining branch
        omitted_set = {str(key) for key in omitted}  # normalises the caller's choice
    report["omitted_groups"] = sorted(omitted_set)  # stores the live choice

    field_names = {field.name for field in dataclasses.fields(Finding)}  # rebuilds the objects
    objects: list[Finding] = []  # evaluates the objects expression
    for entry in report.get("findings") or []:  # loops over the collection
        payload = {key: value for key, value in entry.items() if key in field_names}  # strips markers
        payload["tools"] = list(entry.get("tools") or [entry.get("source") or "unknown-tool"])  # restores the tools
        payload["locations"] = list(entry.get("locations") or [])  # restores the locations
        objects.append(Finding(**payload))  # runs the Finding() call

    scored = [  # assigns the computed value to scored
        finding for finding in objects  # walks the collection
        if finding_group_key(finding) not in omitted_set  # keeps only the counted ones
    ]

    # The omission math needs the pre-omission state only through
    # effective_charges below, so the surviving weights and the category /
    # severity counts are gathered here (the exclusions are exactly the
    # themes whose findings are left out of ``raw``).
    raw: dict[str, float] = {key: 0.0 for key in config.CAPS}  # the surviving weights
    counts: dict[str, dict[str, int]] = {  # rebuilds the category/severity table
        category: {sev: 0 for sev in config.SEVERITY_ORDER} for category in config.CAPS  # evaluates the counts expression
    }  # closes the multiline block
    for finding in objects:  # walks every finding (scored or excluded)
        if finding_group_key(finding) in omitted_set:  # evaluates the branch condition
            continue  # the excluded weight is not survived raw
        category = finding.category if finding.category in config.CAPS else "code"  # copies the category value
        raw[category] += float(finding.weight or 0.0)  # the surviving weight
        counts[category][finding.severity] = counts[category].get(finding.severity, 0) + 1  # bumps the count

    # The pro-rata maths shared with build_report: one pass through
    # effective_charges gives every finding (kept or excluded) its effective
    # charge under the context-normalised caps persisted at build time (the
    # plain caps when no context was measured). Survivors' charges sum to the
    # applied category penalty, and an omitted theme's charges sum to what
    # the omission credits - identical values to the previous in-line version,
    # but from the single implementation the recommendations ranker shares.
    caps_eff = dict((report.get("context") or {}).get("effective_caps") or config.CAPS)  # the persisted cap table
    charge_sweep = effective_charges(objects, caps_eff)  # the shared per-finding shares
    theme_refund: dict[str, dict[str, float]] = {}  # visible refunded points per theme key
    applied: dict[str, float] = {category: 0.0 for category in config.CAPS}  # the surviving charge
    for finding, charge in zip(objects, charge_sweep.shares):  # the shared sweep
        category = finding.category if finding.category in config.CAPS else "code"  # copies the category value
        if finding_group_key(finding) in omitted_set:  # evaluates the branch condition
            per_category = theme_refund.setdefault(category, {})  # fetches the per-theme map
            per_category[finding_group_key(finding)] = (  # assigns the computed value
                per_category.get(finding_group_key(finding), 0.0) + charge  # the credited share
            )  # closes the multiline block
        else:  # covers the remaining branch
            applied[category] += charge  # the surviving contribution
    applied = {category: round(charge, 2) for category, charge in applied.items()}  # the rounded write
    score = max(0, min(100, int(round(100 - sum(applied.values())))))  # recomputes the score
    band_label, band_colour = _band(score)  # re-picks the band
    critical = sum(counts[category]["critical"] for category in RISK_CATEGORIES)  # re-sums the criticals
    high = sum(counts[category]["high"] for category in RISK_CATEGORIES)  # re-sums the highs

    scanner_status = report.get("scanner_status") or {}  # copies the status value
    required_failed = [  # re-evaluates the required-tool rule
        name for name, status in scanner_status.items()  # walks the status entries
        if status.get("status") not in {"ok", "skipped"} and name in config.REQUIRED_TOOLS  # evaluates the branch condition
    ]  # closes the required_failed list
    # A reviewer's omission is an explicit trust decision: it covers the risk
    # of an incomplete required-scanner step, so the incomplete-scanner veto
    # is set aside once exclusions exist (without exclusions, the strict rule
    # from build_report is untouched).
    required_override = bool(required_failed and omitted_set)  # was the veto set aside?
    if required_override:  # evaluates the branch condition
        required_failed = []  # the reviewer's coverage judgement wins
    secure = score >= config.SECURE_MIN_SCORE and critical == 0 and not required_failed  # recomputes the verdict rule

    if critical:  # checks the alternate condition
        reason = (  # assigns the computed value to reason
            f"{critical} critical-severity finding{'s' if critical != 1 else ''} were reported. "  # evaluates the f expression
            "A repository with critical risk is never marked secure, whatever the aggregate score."  # supplies the literal text
        )  # closes the reason build
    elif required_failed:  # evaluates the branch condition
        reason = (  # assigns the computed value to reason
            "A required scanner did not complete ("  # supplies the literal text
            + ", ".join(sorted(required_failed))  # waits for the thread
            + "), so the result cannot be treated as a clean bill of health."  # executes the statement
        )  # closes the reason build
    elif score >= config.SECURE_MIN_SCORE:  # evaluates the branch condition
        reason = (  # assigns the computed value to reason
            f"The weighted score is {score}/100, above the {config.SECURE_MIN_SCORE} pass mark, "  # supplies the literal text
            "and no critical-severity findings were reported."  # supplies the literal text
        )  # closes the reason build
    else:  # covers the remaining branch
        reason = (  # assigns the computed value to reason
            f"The weighted score is {score}/100, below the {config.SECURE_MIN_SCORE} pass mark "  # supplies the literal text
            f"({high} high and {critical} critical findings included)."  # evaluates the f expression
        )  # closes the reason build

    selected_frameworks = list((report.get("frameworks") or {}).keys())  # keeps the ticked frameworks
    groups = _group_findings(  # re-groups every theme
        objects, config.TOP_RISK_LIMIT,  # the whole finding set and the row limit
        charges=charge_sweep.shares,  # the shared shares, so the rows stay current
    )  # closes the multiline block
    for group in groups:  # loops over the collection
        group["omitted"] = group["key"] in omitted_set  # keeps omitted themes visible and tickable
        group["refund"] = round(  # what the omission actually credited, per theme
            (theme_refund.get(group["category"]) or {}).get(group["key"], 0.0), 2)  # pro-rata share

    # Rescore = filter, not re-match: only findings were dropped, so the
    # already-built framework payloads and per-finding references are filtered
    # by the scoring set. The full keyword re-match happens only when the
    # stored structures are missing (defensive fallback for hand-built reports).
    stored_map = report.get("framework_by_finding") or {}  # the per-finding refs from build
    if selected_frameworks and stored_map:  # the filterable case
        framework_payloads, finding_map_kept = _filter_framework_payloads(  # the filter pass
            report.get("frameworks") or {}, stored_map, scored  # runs the filter call
        )  # closes the multiline block
    elif selected_frameworks:  # covers the remaining branch
        framework_payloads, finding_map_kept = compliance.map_all(scored, selected_frameworks)  # the defensive re-match
    else:  # covers the remaining branch
        framework_payloads, finding_map_kept = {}, {}  # no frameworks: empty structures
    report.update({  # writes every recomputed block back
        "score": score,  # maps the score dictionary entry
        "band": band_label,  # maps the band dictionary entry
        "band_colour": band_colour,  # maps the band_colour dictionary entry
        "verdict": "SECURE" if secure else "INSECURE",  # maps the verdict dictionary entry
        "verdict_reason": reason + (  # appends the omission note
            "" if not omitted_set else f" {len(omitted_set)} risk "  # evaluates the count text
            f"{'theme' if len(omitted_set) == 1 else 'themes'} excluded from the score at "
            "the reviewer's request (mitigated elsewhere)."
            + (" The incomplete required-scanner step is accepted by the "
               "reviewer's exclusions." if required_override else "")  # names the veto lift
        ),  # closes the reason appendix
        "penalties": {key: round(value, 2) for key, value in applied.items()},  # maps the penalties entry
        "raw_penalties": {key: round(value, 2) for key, value in raw.items()},  # maps the raw entry
        "counts": counts,  # maps the counts entry
        "totals": {  # replaces the totals block
            "findings": len(scored),  # counts only the scoring set
            "critical": critical,  # maps the critical dictionary entry
            "high": high,  # maps the high dictionary entry
            "medium": sum(counts[c]["medium"] for c in counts),  # maps the medium entry
            "low": sum(counts[c]["low"] for c in counts),  # maps the low entry
            "unknown": sum(counts[c]["unknown"] for c in counts),  # maps the unknown entry
            # Per-category findings counts, so renderers never re-sum the
            # counts table (the values below are the same sums, precomputed).
            "by_category": {category: sum(values.values()) for category, values in counts.items()},  # maps the by_category dictionary entry
        },  # closes the totals block
        "greatest_risks": groups,  # maps the greatest_risks entry
        "frameworks": framework_payloads,  # the filtered (or re-matched) payloads
        "framework_by_finding": finding_map_kept,  # the filtered per-finding refs
    })  # closes the update pair
    for entry in report["findings"]:  # refreshes the per-finding flags
        entry["omitted"] = finding_group_key({  # builds a dict-based lookup
            "category": entry.get("category"),  # maps the category dictionary entry
            "rule_id": entry.get("rule_id"),  # maps the rule_id dictionary entry
            "title": entry.get("title"),  # maps the title dictionary entry
        }) in omitted_set  # compares with the chosen set
    if report.get("dashboard_selection"):  # rebuilds the dashboard payloads
        report["dashboard"] = dashboard_module.collect_metrics(  # refreshes the widgets
            report, report["dashboard_selection"]  # runs the collect_metrics() call
        )  # closes the rebuild pair
    return report  # returns the report to the caller


# --------------------------------------------------------------------------
# Confidence model
# --------------------------------------------------------------------------

# How much each signal contributes to the 0-100 confidence figure. Confidence
# is about *how trustworthy this report is*; it says nothing about how secure
# the repository is - a clean repo and a wrecked repo can both have high
# confidence if the right scanners ran and agreed with each other.
CONFIDENCE_WEIGHTS = {  # assigns the computed value to CONFIDENCE_WEIGHTS
    "reliability": 45,       # did the selected scanners complete?  # maps the reliability dictionary entry
    "corroboration": 20,     # did independent tools agree on the same issues?  # maps the corroboration dictionary entry
    "severity_quality": 20,  # are severities known, or filed as "unknown"?  # maps the severity_quality dictionary entry
    "tool_breadth": 15,      # how many distinct scanners contributed?  # maps the tool_breadth dictionary entry
}  # closes the multiline block

CONFIDENCE_BANDS: tuple[tuple[int, str, str], ...] = (  # evaluates the CONFIDENCE_BANDS expression
    (80, "High confidence", "#22c55e"),  # executes the statement
    (60, "Moderate confidence", "#f59e0b"),  # executes the statement
    (0, "Low confidence", "#ef4444"),  # executes the statement
)  # closes the multiline block


def compute_confidence(  # defines the compute_confidence() function
    findings: list[Finding],  # evaluates the findings expression
    scanner_status: dict[str, dict[str, Any]] | None = None,  # evaluates the scanner_status expression
    corroborated: int | None = None,  # optional pre-computed cross-tool count
) -> dict[str, Any]:  # closes the multiline block
    """Estimate how much this report can be trusted, from 0 to 100.

    Four weighted signals:

    * *reliability* - whether the scanners that were supposed to run actually
      completed (required tools count double).
    * *corroboration* - the share of findings independently reported by two or
      more tools. When nothing at all was found the signal is neutral rather
      than perfect, because absence of findings cannot be cross-checked.
    * *severity quality* - findings whose severity the tool could not rate
      (unknown) downgrade the model less when they are rare.
    * *tool breadth* - a verdict built on one scanner carries less weight than
      one built on many; the scale reaches full weight at five running tools.
    """
    status_map = scanner_status or {}  # copies the scanner_status value into status_map
    run = [  # assigns the computed value to run
        (name, status)  # executes the statement
        for name, status in status_map.items()  # loops over the collection
        if status.get("status") != "skipped"  # evaluates the branch condition
    ]  # closes the multiline block
    if not run:  # evaluates the branch condition
        return {  # returns the value to the caller
            "score": 0,  # maps the score dictionary entry
            "band": "No data",  # maps the band dictionary entry
            "band_colour": "#8ba3c2",  # maps the band_colour dictionary entry
            "factors": [],  # maps the factors dictionary entry
            "headline": "No scanner ran, so there is nothing to have confidence in.",  # maps the headline dictionary entry
        }  # closes the multiline block

    ok_weight = 0  # assigns the computed value to ok_weight
    total_weight = 0  # assigns the computed value to total_weight
    ok_count = 0  # assigns the computed value to ok_count
    failed_state_counts: dict[str, int] = {}  # evaluates the failed_state_counts expression
    details: list[str] = []  # evaluates the details expression
    for name, status in run:  # loops over the collection
        weight = 2.0 if name in config.REQUIRED_TOOLS else 1.0  # assigns the computed value to weight
        total_weight += weight  # evaluates the total_weight expression
        state = str(status.get("status") or "unknown")  # runs the str() call
        label = config.TOOL_LABELS.get(name, name.title())  # fetches the value
        if state == "ok":  # evaluates the branch condition
            ok_weight += weight  # evaluates the ok_weight expression
            ok_count += 1  # evaluates the ok_count expression
        elif state == "partial":  # checks the alternate condition
            # A partial run produced real results, but not full coverage, so it
            # is credited half way rather than treated as a total loss.
            ok_weight += weight * 0.5  # evaluates the ok_weight expression
            details.append(f"{label} only produced partial results")  # adds an item to the list
        elif state == "error":  # checks the alternate condition
            first_detail = next(  # runs the next() call
                (str(d) for d in status.get("details") or [] if d), ""  # runs the str() call
            )  # closes the multiline block
            clue = first_detail.split(".")[0].strip()[:60]  # runs the split() call
            details.append(  # adds an item to the list
                f"{label} failed" + (f" ({clue})" if clue else "")  # supplies the literal text
            )  # closes the multiline block
        else:  # covers the remaining branch
            details.append(f"{label} did not complete (status: {state})")  # adds an item to the list
        failed_state_counts[state] = failed_state_counts.get(state, 0) + 1  # fetches the value
    reliability = ok_weight / total_weight if total_weight else 0.0  # copies the ok_weight value into reliability

    if findings:  # evaluates the branch condition
        if corroborated is None:  # evaluates the branch condition
            corroborated = sum(1 for finding in findings if len(dict.fromkeys(finding.tools)) > 1)  # counts the items
        corroboration = corroborated / len(findings)  # counts the items
        unknown_share = sum(  # adds up the values
            1 for finding in findings if finding.severity == "unknown"  # executes the statement
        ) / len(findings)  # closes the multiline block
    else:  # covers the remaining branch
        # No findings at all: nothing to agree on, so credit a neutral portion
        # of this signal instead of pretending the tools cross-checked every
        # (nonexistent) issue.
        corroboration = 0.7  # assigns the computed value to corroboration
        unknown_share = 0.0  # assigns the computed value to unknown_share
    severity_quality = 1.0 - min(1.0, unknown_share * 1.5)  # takes the smallest value
    tool_breadth = min(1.0, ok_count / 5)  # takes the smallest value

    scores = {  # assigns the computed value to scores
        "reliability": reliability,  # maps the reliability dictionary entry
        "corroboration": corroboration,  # maps the corroboration dictionary entry
        "severity_quality": severity_quality,  # maps the severity_quality dictionary entry
        "tool_breadth": tool_breadth,  # maps the tool_breadth dictionary entry
    }  # closes the multiline block
    factor_copy = {  # assigns the computed value to factor_copy
        "reliability": ("Scanner reliability", round(reliability * 100)),  # maps the reliability dictionary entry
        "corroboration": (  # maps the corroboration dictionary entry
            "Cross-tool corroboration",  # supplies the literal text
            round(corroboration * 100),  # runs the round() call
        ),  # closes the multiline block
        "severity_quality": ("Severity precision", round(severity_quality * 100)),  # maps the severity_quality dictionary entry
        "tool_breadth": ("Tool breadth", round(tool_breadth * 100)),  # maps the tool_breadth dictionary entry
    }  # closes the multiline block
    factors = [  # assigns the computed value to factors
        {  # executes the statement
            "key": key,  # maps the key dictionary entry
            "label": factor_copy[key][0],  # maps the label dictionary entry
            "score": factor_copy[key][1],  # maps the score dictionary entry
            "weight": CONFIDENCE_WEIGHTS[key],  # maps the weight dictionary entry
            "contribution": round(CONFIDENCE_WEIGHTS[key] * factor_copy[key][1] / 100, 1),  # maps the contribution dictionary entry
        }  # closes the multiline block
        for key in CONFIDENCE_WEIGHTS  # loops over the collection
    ]  # closes the multiline block
    score = int(round(sum(factor["contribution"] for factor in factors)))  # adds up the values
    score = max(0, min(100, score))  # takes the largest value
    for threshold, label, colour in CONFIDENCE_BANDS:  # loops over the collection
        if score >= threshold:  # evaluates the branch condition
            band, band_colour = label, colour  # copies the label value into band, band_colour
            break  # exits the loop early

    notes = list(details)  # builds the list collection
    if findings and corroboration < 0.4:  # evaluates the branch condition
        notes.append("Few findings were independently corroborated by a second tool")  # adds an item to the list
    if unknown_share >= 0.2:  # evaluates the branch condition
        notes.append("Some findings carry no tool-reported severity")  # adds an item to the list
    if ok_count < 3:  # evaluates the branch condition
        notes.append("Only a handful of scanners completed, so coverage is thin")  # adds an item to the list
    headline = (  # assigns the computed value to headline
        f"{band} ({score}/100): "  # maps the {band} ({score}/100):  dictionary entry
        + (  # executes the statement
            f"{ok_count} of {len(run)} running scanners completed fully"  # supplies the literal text
            + (  # executes the statement
                f" ({failed_state_counts['partial']} partial)"  # evaluates the f expression
                if failed_state_counts.get("partial")  # evaluates the branch condition
                else ""  # covers the remaining branch
            )  # closes the multiline block
            if run  # evaluates the branch condition
            else "no scanners ran"  # covers the remaining branch
        )  # closes the multiline block
        + "."  # executes the statement
    )  # closes the multiline block
    return {  # returns the value to the caller
        "score": score,  # maps the score dictionary entry
        "band": band,  # maps the band dictionary entry
        "band_colour": band_colour,  # maps the band_colour dictionary entry
        "factors": factors,  # maps the factors dictionary entry
        "notes": notes,  # maps the notes dictionary entry
        "headline": headline,  # maps the headline dictionary entry
    }  # closes the multiline block


# --------------------------------------------------------------------------
# Severity pie chart (drawn by the UI on a Tkinter Canvas)
# --------------------------------------------------------------------------


def severity_pie_slices(  # defines the severity_pie_slices() function
    totals: dict[str, Any],  # evaluates the totals expression
) -> list[tuple[str, int, str, float]]:  # closes the multiline block
    """Wedges for the dashboard pie chart: (key, count, colour, fraction).

    ``key`` is a severity name or "clean" when nothing was found. The fractions
    sum to 1.0 so the wedges tile a full circle exactly.
    """
    total = sum(int(totals.get(sev, 0)) for sev in config.SEVERITY_ORDER)  # adds up the values
    if total <= 0:  # evaluates the branch condition
        return [("clean", 0, config.SEVERITY_COLOURS["clean"], 1.0)]  # returns the value to the caller
    slices: list[tuple[str, int, str, float]] = []  # evaluates the slices expression
    for severity in config.SEVERITY_ORDER:  # loops over the collection
        count = int(totals.get(severity, 0))  # runs the int() call
        if count:  # evaluates the branch condition
            slices.append(  # adds an item to the list
                (  # executes the statement
                    severity,  # evaluates the severity expression
                    count,  # evaluates the count expression
                    config.SEVERITY_COLOURS[severity],  # evaluates the config.SEVERITY_COLOURS expression
                    count / total,  # evaluates the count expression
                )  # closes the multiline block
            )  # closes the multiline block
    return slices  # returns the slices to the caller


def _tool_breakdown(  # defines the _tool_breakdown() function
    findings: list[Finding],  # evaluates the findings expression
    scanner_status: dict[str, dict[str, Any]],  # evaluates the scanner_status expression
    tool_counts: dict[str, dict[str, int]] | None = None,  # optional shared per-tool tallies
) -> dict[str, dict[str, int]]:  # closes the multiline block
    """Per-tool counts; a finding detected by three tools counts for all three.

    ``tool_counts`` is the per-tool severity tally built once by
    :func:`build_report`'s single sweep; without it (direct calls) the map is
    reproduced here with today's second walk.
    """
    names = [  # assigns the computed value to names
        name  # evaluates the name expression
        for name, status in scanner_status.items()  # loops over the status entries
        if status.get("status") != "skipped"  # evaluates the branch condition
    ]  # closes the multiline block
    for finding in findings:  # loops over the collection
        for tool in finding.tools:  # loops over the collection
            if tool not in names:  # evaluates the branch condition
                names.append(tool)  # adds an item to the list

    ordered = [tool for tool in config.ALL_TOOLS if tool in names]  # assigns the computed value to ordered
    ordered.extend(tool for tool in names if tool not in ordered)  # adds several items to the list

    if tool_counts is None:  # evaluates the branch condition
        tool_counts = {}  # the reproduced tally map
        for finding in findings:  # walks the findings
            for tool in finding.tools:  # loops over the tools
                bucket = tool_counts.setdefault(  # runs the setdefault() call
                    tool, {sev: 0 for sev in config.SEVERITY_ORDER} | {"total": 0}  # evaluates the tool expression
                )  # closes the multiline block
                bucket[finding.severity] = bucket.get(finding.severity, 0) + 1  # fetches the value
                bucket["total"] += 1  # evaluates the bucket expression

    breakdown: dict[str, dict[str, int]] = {}  # the per-tool rows
    for name in ordered:  # loops over the collection
        bucket = tool_counts.get(name) or {sev: 0 for sev in config.SEVERITY_ORDER} | {"total": 0}  # fetches the tallies
        breakdown[name] = {**{sev: 0 for sev in config.SEVERITY_ORDER}, "total": 0}  # the blank row
        breakdown[name].update({sev: bucket.get(sev, 0) for sev in config.SEVERITY_ORDER})  # the severity counts
        breakdown[name]["total"] = bucket.get("total", 0)  # the row total
    return breakdown  # returns the breakdown to the caller


def _format_weight(value: float) -> str:  # defines the _format_weight() function
    """Points as they read today: ``12``, ``1.5`` and ``0.3``, no trailing zero."""
    return f"{value:g}"  # the generic float format


def _severity_row(table: dict[str, float]) -> str:  # defines the _severity_row() function
    """One weight table as the printed ``15/10/5/1`` severity row."""
    return "/".join(  # the "15/10/5/1" shape
        _format_weight(table[sev])  # the formatted points
        for sev in ("critical", "high", "medium", "low")  # the printed slices
    )  # closes the multiline block


def explanation_text() -> str:  # defines the explanation_text() function
    """The score explainer, generated from the weight/cap tables.

    The numbers are read from :data:`config.WEIGHTS` and :data:`config.CAPS`
    at build time (an integer-valued weight prints as a whole number) so the
    stored report can never quietly contradict the tuning tables.
    """
    weights = config.WEIGHTS  # copies the config value into weights
    caps = config.CAPS  # copies the config value into caps

    caps_text = ", ".join(  # the "dependencies 45, secrets 25" shape
        f"{label} {_format_weight(caps[category])}"  # the formatted cap
        for label, category in (  # the print-order pairs
            ("dependencies", "vulnerability"),  # the CVE block
            ("secrets", "secret"),  # the credential block
            ("IaC", "misconfiguration"),  # the infrastructure block
            ("code", "code"),  # the code block
            ("licences", "license"),  # the FOSSology block
        )  # closes the multiline block
    )  # closes the multiline block

    return (  # returns the value to the caller
        "Every finding subtracts points from a perfect 100. Dependency CVEs cost "  # supplies the literal text
        f"{_format_weight(weights['vulnerability']['critical'])} (critical), "  # supplies the literal text
        f"{_format_weight(weights['vulnerability']['high'])} (high), "  # supplies the literal text
        f"{_format_weight(weights['vulnerability']['medium'])} (medium) or "  # supplies the literal text
        f"{_format_weight(weights['vulnerability']['low'])} (low) and are de-duplicated across "  # supplies the literal text
        "Trivy, Grype and OSV-Scanner. GuardDog supply-chain patterns are charged in the same "  # supplies the literal text
        f"category. Committed secrets cost the most ({_severity_row(weights['secret'])}) and are "  # supplies the literal text
        "de-duplicated across Trivy, GitLeaks, TruffleHog and Checkov's secret checks. "  # supplies the literal text
        f"Infrastructure misconfigurations cost {_severity_row(weights['misconfiguration'])}, and "  # supplies the literal text
        f"code findings from CodeQL or Semgrep are weighted by severity "  # supplies the literal text
        f"({_severity_row(weights['code'])}). Each category is capped ({caps_text}) "
        "so one noisy scanner cannot bury the result. Large dependency surfaces and active "
        "maintenance effort widen the dependency and code caps — a scan's SBOM size, file "
        "count and Care-and-Feeding pulse scale the tolerance (never below "
        f"{min(knobs.get('relief_floor') or 1.0 for knobs in config.SCORING_CONTEXT.values()):g}"
        f"x the plain cap) — while committed secrets stay charged in full. "
        "Syft only inventories the SBOM, so it never "  # supplies the literal text
        "removes points directly. A merged finding is charged once but names every tool that "  # supplies the literal text
        f"detected it. A score of {config.SECURE_MIN_SCORE}+ with zero critical findings is "  # supplies the literal text
        "reported as secure."  # supplies the literal text
    )  # closes the multiline block


# Public alias - the historical private name kept until callers migrate.
_explanation_text = explanation_text  # copies the explanation_text value into _explanation_text


def _group_findings(  # defines the _group_findings() function
    findings: list[Finding],  # evaluates the findings expression
    limit: int,  # evaluates the limit expression
    charges: list[float] | None = None,  # optional shared per-finding shares, aligned with findings
) -> list[dict[str, Any]]:  # closes the multiline block
    """Collapse findings into distinct risk themes, worst first.

    ``charges`` (from :func:`effective_charges`) carries each finding's
    effective charge; when present it is persisted per theme as ``charge``,
    the number the recommendations tab ranks without redoing the cap maths.
    """  # keeps the docstring text
    groups: dict[tuple[str, str], dict[str, Any]] = {}  # evaluates the groups expression

    for index, finding in enumerate(findings):  # loops over the collection
        if finding.category == "code-quality":  # evaluates the branch condition
            continue  # skips to the next loop iteration
        key = (finding.category, finding.rule_id or finding.title)  # assigns the computed value to key
        group = groups.get(key)  # fetches the value
        if group is None:  # evaluates the branch condition
            groups[key] = {  # assigns the computed value to groups[key]
                "category": finding.category,  # maps the category dictionary entry
                "rule_id": finding.rule_id,  # maps the rule_id dictionary entry
                "title": finding.title,  # maps the title dictionary entry
                "severity": finding.severity,  # maps the severity dictionary entry
                "count": 1,  # maps the count dictionary entry
                "penalty": finding.weight,  # maps the penalty dictionary entry
                "detail": finding.detail,  # maps the detail dictionary entry
                "reference": finding.reference,  # maps the reference dictionary entry
                "tools": list(finding.tools),  # maps the tools dictionary entry
                "tool_labels": finding.tool_labels,  # maps the tool_labels dictionary entry
                "locations": list(finding.locations),  # maps the locations dictionary entry
                "package": str(finding.package or ""),  # the named package (first non-empty wins)
                "charge": charges[index] if charges is not None else 0.0,  # the pro-rata share
            }  # closes the multiline block
        else:  # covers the remaining branch
            group["count"] += 1  # evaluates the group expression
            group["penalty"] += finding.weight  # evaluates the group expression
            if charges is not None:  # evaluates the branch condition
                group["charge"] += charges[index]  # accumulates the effective charge
            if not group["package"] and finding.package:  # evaluates the branch condition
                group["package"] = str(finding.package)  # names the affected package
            if severity_rank(finding.severity) < severity_rank(group["severity"]):  # evaluates the branch condition
                group["severity"] = finding.severity  # copies the finding.severity value into group["severity"]
                group["detail"] = finding.detail  # copies the finding.detail value into group["detail"]
            group["tools"] = list(dict.fromkeys([*group["tools"], *finding.tools]))  # builds the list collection
            group["tool_labels"] = [  # assigns the computed value to group["tool_labels"]
                config.TOOL_LABELS.get(tool, tool.title()) for tool in group["tools"]  # fetches the value
            ]  # closes the multiline block
            for location in finding.locations:  # loops over the collection
                if location and len(group["locations"]) < 3 and location not in group["locations"]:  # evaluates the branch condition
                    group["locations"].append(location)  # adds an item to the list

    ordered = sorted(  # sorts the values
        groups.values(),  # walks the stored values
        key=lambda g: (-g["penalty"], severity_rank(g["severity"]), -g["count"]),  # runs the severity_rank() call
    )  # closes the multiline block
    for group in ordered:  # loops over the collection
        group["penalty"] = round(group["penalty"], 2)  # runs the round() call
        if charges is not None:  # evaluates the branch condition
            group["charge"] = round(group["charge"], 2)  # rounds the persisted charge for display
        group["why"] = CATEGORY_WHY.get(group["category"], "")  # fetches the value
        group["key"] = finding_group_key(group)  # stable omission key (shared builder)
        group["omitted"] = False  # flips True when the user excludes the theme
    return ordered[:limit]  # returns the ordered to the caller


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def finding_group_key(finding: Finding | dict[str, Any]) -> str:  # defines the finding_group_key() function
    """Stable identity of a greatest-risk row (category + rule), UI-shared."""
    return reportkeys.finding_group_key(finding)  # returns the shared builder


def render_report_text(report: dict[str, Any]) -> str:  # defines the render_report_text() function
    """Plain-text report used by both the popup and the CLI."""  # keeps the docstring text
    lines: list[str] = []  # evaluates the lines expression
    repo = report.get("repo") or {}  # fetches the value
    name = repo.get("full_name") or repo.get("input_url") or "repository"  # fetches the value

    lines.append(f"{name}")  # adds an item to the list
    if repo.get("description"):  # evaluates the branch condition
        lines.append(repo["description"])  # adds an item to the list
    if report.get("languages"):  # evaluates the branch condition
        lines.append("Languages scanned: " + ", ".join(report["languages"]))  # adds an item to the list
    lines.append("")  # adds an item to the list

    lines.append(f"SECURITY SCORE   {report['score']} / 100   [{report['band'].upper()}]")  # adds an item to the list
    lines.append(f"VERDICT          {report['verdict']}")  # adds an item to the list
    lines.append(f"WHY              {report['verdict_reason']}")  # adds an item to the list
    lines.append("")  # adds an item to the list

    confidence = report.get("confidence") or {}  # fetches the value
    if confidence:  # evaluates the branch condition
        lines.append(f"CONFIDENCE      {confidence['score']:>4} / 100   [{confidence['band'].upper()}]")  # adds an item to the list
        for factor in confidence.get("factors") or []:  # loops over the collection
            bar = ("#" * int(round(factor["score"] / 10))).ljust(10, ".")  # runs the int() call
            lines.append(  # adds an item to the list
                f"  {factor['label']:<26}{bar} {factor['score']:>3}%  "  # evaluates the f expression
                f"(weight {factor['weight']})"  # evaluates the f expression
            )  # closes the multiline block
        for note in confidence.get("notes") or []:  # loops over the collection
            lines.append("  - " + note)  # adds an item to the list
        lines.append("")  # adds an item to the list

    lines.append("WHAT THE SCORE MEANS")  # adds an item to the list
    for chunk in _wrap(report["explanation"], 96):  # loops over the collection
        lines.append("  " + chunk)  # adds an item to the list
    lines.append("")  # adds an item to the list

    lines.append("WHERE THE POINTS WENT")  # adds an item to the list
    lines.append(f"  {'Category':<32}{'Findings':>9}{'Penalty':>10}{'Cap':>8}")  # adds an item to the list
    by_category = (report.get("totals") or {}).get("by_category") or {}  # the precomputed per-category counts
    for category in SCORING_CATEGORIES:  # loops over the collection
        count = by_category.get(category)  # reads the precomputed count
        if count is None:  # evaluates the branch condition
            count = sum(report["counts"][category].values())  # the legacy re-sum fallback
        if category in ("code-quality", "license") and count == 0:  # evaluates the branch condition
            continue  # skips to the next loop iteration
        label = CATEGORY_LABELS[category]  # copies the CATEGORY_LABELS value into label
        penalty = report["penalties"][category]  # copies the report value into penalty
        cap = report["caps"][category]  # copies the report value into cap
        lines.append(f"  {label:<32}{count:>9}{penalty:>10.1f}{cap:>8.0f}")  # adds an item to the list
    lines.append(f"  {'TOTAL':<32}{report['totals']['findings']:>9}{sum(report['penalties'].values()):>10.1f}")  # adds an item to the list
    context = report.get("context") or {}  # the persisted normalisation summary
    for category, factor_block in (context.get("factors") or {}).items():  # loops over the relieved categories
        label = CATEGORY_LABELS.get(category, category)  # copies the CATEGORY_LABELS value into label
        bits: list[str] = []  # the context parts worth naming
        if context.get("packages") and category == "vulnerability":  # evaluates the branch condition
            bits.append(f"{context['packages']} packages")  # the dependency-surface note
        if context.get("files") and category == "code":  # evaluates the branch condition
            bits.append(f"{context['files']} files")  # the codebase note
        if factor_block.get("pulse"):  # evaluates the branch condition
            bits.append(f"maintenance pulse {factor_block['pulse']:g}")  # the Care note
        if bits:  # evaluates the branch condition
            lines.append(  # adds an item to the list
                f"  - {label} cap relieved x{factor_block['factor']:g} "  # supplies the literal text
                f"({', '.join(bits)}): cap {config.CAPS[category]:g} -> "  # supplies the literal text
                f"{factor_block['effective_cap']:g}"  # the effective ceiling
            )  # closes the multiline block
    lines.append("")  # adds an item to the list

    dedupe = report.get("dedupe") or {}  # fetches the value
    if dedupe.get("raw", 0) > 0:  # evaluates the branch condition
        lines.append("DE-DUPLICATION")  # adds an item to the list
        lines.append(  # adds an item to the list
            f"  {dedupe['raw']} raw findings from all tools collapsed into "  # evaluates the f expression
            f"{dedupe['merged']} unique issues; {dedupe['removed']} duplicate report(s) "  # runs the report() call
            f"removed. {dedupe['corroborated']} issue(s) corroborated by 2+ tools."  # runs the issue() call
        )  # closes the multiline block
        lines.append("")  # adds an item to the list

    inventory = report.get("inventory")  # fetches the value
    if inventory:  # evaluates the branch condition
        lines.append("SBOM INVENTORY (SYFT)")  # adds an item to the list
        ecosystems = inventory.get("ecosystems") or {}  # fetches the value
        eco_text = ", ".join(f"{key} {value}" for key, value in ecosystems.items()) or "none"  # sets the eco_text text
        lines.append(  # adds an item to the list
            f"  {inventory.get('components', 0)} components catalogued ({eco_text}); "  # fetches the value
            f"{inventory.get('unversioned', 0)} without a resolved version."  # fetches the value
        )  # closes the multiline block
        for component in (inventory.get("top_packages") or [])[:10]:  # loops over the collection
            version = component.get("version") or "?"  # fetches the value
            lines.append(  # adds an item to the list
                f"  - {component.get('name') or '?'} {version}  ({component.get('type') or 'package'})"  # fetches the value
            )  # closes the multiline block
        lines.append("")  # adds an item to the list

    care_lines = [  # the shared pair rows, padded like the legacy text
        f"{label:<23}{value}" if label else value  # the join rule from care.render_pairs
        for label, value in care.render_pairs(report.get("care") or {})  # runs the render_pairs() call
    ]  # closes the multiline block
    if care_lines:  # evaluates the branch condition
        lines.append("CARE AND FEEDING (repository maintenance)")  # adds an item to the list
        for care_line in care_lines:  # loops over the collection
            lines.append("  " + care_line)  # adds an item to the list
        lines.append("")  # adds an item to the list

    dashboard_lines = dashboard_module.render_text(report.get("dashboard") or {})  # runs the render_text() call
    if dashboard_lines:  # evaluates the branch condition
        lines.append("DASHBOARD (selected metrics)")  # adds an item to the list
        for dashboard_line in dashboard_lines:  # loops over the collection
            lines.append("  " + dashboard_line)  # adds an item to the list
        lines.append("")  # adds an item to the list

    risks = report.get("greatest_risks") or []  # fetches the value
    lines.append("GREATEST RISKS IDENTIFIED")  # adds an item to the list
    if not risks:  # evaluates the branch condition
        lines.append("  None. No selected scanner produced a security finding.")  # adds an item to the list
    for index, risk in enumerate(risks, 1):  # loops over the collection
        suffix = f"  (x{risk['count']})" if risk["count"] > 1 else ""  # sets the suffix text
        omission = "   [excluded from scoring]" if risk.get("omitted") else ""  # sets the omission marker
        lines.append(  # adds an item to the list
            f"  {index}. [{risk['severity'].upper()}] {risk['title']}{suffix}"  # uppercases the text
            f"   -{risk['penalty']:.1f} pts{omission}"  # evaluates the f expression
        )  # closes the multiline block
        lines.append(f"     {CATEGORY_LABELS.get(risk['category'], risk['category'])} \u00b7 {risk['rule_id']}")  # adds an item to the list
        tools = risk.get("tool_labels") or []  # fetches the value
        if tools:  # evaluates the branch condition
            lines.append(f"     Identified by: {', '.join(tools)}")  # adds an item to the list
        if risk.get("detail"):  # evaluates the branch condition
            for chunk in _wrap(risk["detail"], 88):  # loops over the collection
                lines.append("     " + chunk)  # adds an item to the list
        for location in risk.get("locations") or []:  # loops over the collection
            lines.append(f"     \u2192 {location}")  # adds an item to the list
        if risk.get("reference"):  # evaluates the branch condition
            lines.append(f"     \u2192 {risk['reference']}")  # adds an item to the list
        lines.append("")  # adds an item to the list

    totals = report["totals"]  # copies the report value into totals
    lines.append("FINDINGS BY SEVERITY")  # adds an item to the list
    lines.append(  # adds an item to the list
        f"  Critical {totals['critical']}   High {totals['high']}   "  # evaluates the f expression
        f"Medium {totals['medium']}   Low {totals['low']}   Unknown {totals['unknown']}"  # evaluates the f expression
    )  # closes the multiline block
    lines.append("")  # adds an item to the list

    lines.append("FINDINGS BY TOOL")  # adds an item to the list
    lines.append(  # adds an item to the list
        f"  {'Tool':<14}{'Critical':>9}{'High':>6}{'Medium':>8}{'Low':>6}{'Unknown':>9}{'Total':>7}"  # evaluates the f expression
    )  # closes the multiline block
    labels = report.get("tool_labels") or {}  # fetches the value
    for key, stats in (report.get("by_tool") or {}).items():  # loops over the collection
        lines.append(  # adds an item to the list
            f"  {labels.get(key, key.title()):<14}{stats.get('critical', 0):>9}"  # fetches the value
            f"{stats.get('high', 0):>6}{stats.get('medium', 0):>8}"  # fetches the value
            f"{stats.get('low', 0):>6}{stats.get('unknown', 0):>9}{stats.get('total', 0):>7}"  # fetches the value
        )  # closes the multiline block
    lines.append("")  # adds an item to the list

    frameworks = report.get("frameworks") or {}  # fetches the value
    if frameworks:  # evaluates the branch condition
        lines.append("COMPLIANCE FRAMEWORK MAPPING")  # adds an item to the list
        lines.append(  # adds an item to the list
            "  Controls show entries whose scan surface the findings touch this run; "  # supplies the literal text
            "'clear' means the control area was scanned and produced no finding, NOT proof of compliance."  # executes the statement
        )  # closes the multiline block
        for framework in frameworks.values():  # loops over the collection
            lines.append("")  # adds an item to the list
            lines.append(  # adds an item to the list
                f"  [{framework['label']}]  {framework['affected_controls']} of "  # evaluates the f expression
                f"{framework['total_controls']} controls touched"  # evaluates the f expression
                + (f"; {framework['unmapped']} finding(s) outside the map" if framework["unmapped"] else "")  # runs the finding() call
            )  # closes the multiline block
            for control in framework["controls"]:  # loops over the collection
                if control["status"] == "affected":  # evaluates the branch condition
                    lines.append(  # adds an item to the list
                        f"    ! {control['id']:<16}{control['title'][:56]:<58}"  # evaluates the f expression
                        f"{control['affected']:>4} finding(s)"  # runs the finding() call
                        f"{'  (worst: ' + control['worst'] + ')' if control['worst'] else ''}"  # evaluates the f expression
                    )  # closes the multiline block
                    for example in control.get("examples") or []:  # loops over the collection
                        lines.append(f"        - {example}")  # adds an item to the list

    all_findings = report.get("findings") or []  # fetches the value
    if all_findings:  # evaluates the branch condition
        shown = all_findings[: config.MAX_LISTED_FINDINGS]  # copies the all_findings value into shown
        lines.append(  # adds an item to the list
            f"ALL FINDINGS (showing {len(shown)} of {len(all_findings)}, worst first by tool order)"  # supplies the literal text
        )  # closes the multiline block
        for item in sorted(  # loops over the collection
            shown,  # evaluates the shown expression
            key=lambda f: (  # copies the lambda value into key
                severity_rank(f.get("severity", "unknown")),  # runs the severity_rank() call
                f.get("category", ""),  # fetches the value
                f.get("location", ""),  # fetches the value
            ),  # closes the multiline block
        ):  # closes the multiline block
            severity = str(item.get("severity", "unknown")).upper()  # runs the str() call
            title = _ellipsis(item.get("title", ""), 58)  # runs the _ellipsis() call
            tools = ", ".join(item.get("tool_labels") or [])  # sets the tools text
            location = item.get("location") or "location not reported"  # fetches the value
            lines.append(f"  [{severity:<8}] {title:<58}  \u00b7  {tools}  \u00b7  {location}")  # adds an item to the list
        if len(all_findings) > len(shown):  # evaluates the branch condition
            lines.append(  # adds an item to the list
                f"  \u2026 {len(all_findings) - len(shown)} more findings are in the JSON report."  # supplies the literal text
            )  # closes the multiline block
        lines.append("")  # adds an item to the list

    lines.append("SCANNERS")  # adds an item to the list
    for name_key, status in (report.get("scanner_status") or {}).items():  # loops over the collection
        state = status.get("status", "unknown")  # fetches the value
        elapsed = status.get("duration_seconds")  # fetches the value
        elapsed_text = f"{elapsed:.1f}s" if isinstance(elapsed, (int, float)) else "n/a"  # sets the elapsed_text text
        label = (report.get("tool_labels") or {}).get(  # fetches the value
            name_key, config.TOOL_LABELS.get(name_key, name_key.title())  # fetches the value
        )  # closes the multiline block
        lines.append(f"  {label:<14}{state:<10}{elapsed_text:>8}")  # adds an item to the list
        for detail in status.get("details") or []:  # loops over the collection
            lines.append(f"    - {detail}")  # adds an item to the list

    if report.get("warnings"):  # evaluates the branch condition
        lines.append("")  # adds an item to the list
        lines.append("WARNINGS")  # adds an item to the list
        for warning in report["warnings"]:  # loops over the collection
            for chunk in _wrap(warning, 92):  # loops over the collection
                lines.append("  " + chunk)  # adds an item to the list

    lines.append("")  # adds an item to the list
    lines.append(f"Report generated {report['generated_at']} by {config.APP_NAME} {config.APP_VERSION}")  # adds an item to the list
    return "\n".join(lines)  # returns the value to the caller


def _ellipsis(text: Any, limit: int) -> str:  # defines the _ellipsis() function
    """Shared verbatim clip (see :mod:`textutil`)."""  # keeps the docstring text
    return textutil.clip_raw(text, limit)  # returns the clipped value


def _wrap(text: str, width: int) -> list[str]:  # defines the _wrap() function
    words = str(text).split()  # runs the str() call
    lines: list[str] = []  # evaluates the lines expression
    current = ""  # sets the current text
    for word in words:  # loops over the collection
        if current and len(current) + len(word) + 1 > width:  # evaluates the branch condition
            lines.append(current)  # adds an item to the list
            current = word  # copies the word value into current
        else:  # covers the remaining branch
            current = f"{current} {word}".strip()  # sets the current text
    if current:  # evaluates the branch condition
        lines.append(current)  # adds an item to the list
    return lines or [""]  # returns the lines to the caller


# Public alias - the UI reuses the same word wrapper so text matches the CLI.
wrap_text = _wrap  # copies the _wrap value into wrap_text


def write_report_json(report: dict[str, Any], path: str | Path) -> Path:  # defines the write_report_json() function
    path = Path(path)  # creates the path object
    path.parent.mkdir(parents=True, exist_ok=True)  # creates the folder
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")  # writes the text file
    return path  # returns the path to the caller
