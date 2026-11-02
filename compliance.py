"""Map scanner findings onto the controls of selected compliance frameworks.

The mapping is deliberately keyword-based and transparent: every control states
which finding categories (and, optionally, which rule-title keywords) it covers,
so a mapping shown in the report can be traced by hand. A control is reported as
``affected`` when at least one finding maps to it, ``clear`` when the framework
was selected but no finding touched it in *this* scan - which is evidence of a
scanned-but-not-failed check, never proof of compliance.

Nothing here imports Tkinter, so the CLI can ask for a framework mapping too.
"""

from __future__ import annotations  # imports annotations from the __future__ module

from dataclasses import dataclass  # imports dataclass from the dataclasses module
from typing import Any, Iterable  # imports Any, Iterable from the typing module

import reportkeys  # imports the shared keys/ranks registry
from reportkeys import severity_rank as _rank  # the shared severity ordering alias

SEVERITY_RANK: dict[str, int] = reportkeys.SEVERITY_RANKS  # the shared severity table

# Keyword families reused across frameworks. A control matches when one of its
# keywords appears in the finding's rule id or title (case-insensitive), in
# addition to the category check.
_INJECTION = (  # assigns the computed value to _INJECTION
    "inject", "sql", "sqli", "ssrf", "command", "cmd", "shell", "eval",  # supplies the literal text
    "exec", "os.system", "subprocess", "deserializ", "deserialis",  # supplies the literal text
    "path traversal", "open redirect", "template", "unsafe",  # supplies the literal text
)  # closes the multiline block
_CRYPTO = (  # assigns the computed value to _CRYPTO
    "crypto", "ssl", "tls", "cert", "jwt", "md5", "sha", "random",  # supplies the literal text
    "hash", "encrypt", "decrypt", "weak-", "cve-2013", "httponly",  # supplies the literal text
    "samesite", "cookie",  # supplies the literal text
)  # closes the multiline block
_MALWARE = ("malicious", "supply", "typosquat", "install-script",  # assigns the computed value to _MALWARE
            "postinstall", "backdoor", "exfiltrat")  # supplies the literal text
_LOGGING = ("log", "information", "disclosure", "stack", "debug", "trace",  # assigns the computed value to _LOGGING
            "verbose", "banner", "comment")  # supplies the literal text
_CONFIG = ("config", "misconfig", "permission", "privileg", "healthcheck",  # assigns the computed value to _CONFIG
           "user for the container", "add ", "exposure", "port", "firewall",  # supplies the literal text
           "encryption", "default password", "image", "entrypoint", "user",  # supplies the literal text
           "root", "cache", "header", "csp", "hsts", "plain-http",  # web-audit and kubescape shapes
           "token-permission", "pinned", "branch-protection", "signed-release",  # scorecard check families
           "security-policy", "sast", "binary-artifact", "dangerous-workflow",  # scorecard check families
           "code-review", "maintained", "packaging", "fuzzing", "license",  # scorecard check families
           "api key", "credential", "kubescape")  # supply the literal text


@dataclass(frozen=True)  # applies the dataclass decorator
class Control:  # defines the Control class
    """One mapped control: an id, a title, and what kinds of findings it covers."""  # keeps the docstring text

    id: str  # evaluates the id expression
    title: str  # evaluates the title expression
    categories: tuple[str, ...]  # evaluates the categories expression
    keywords: tuple[str, ...] = ()  # evaluates the keywords expression
    kinds: tuple[str, ...] = ()  # evaluates the kinds expression


@dataclass(frozen=True)  # applies the dataclass decorator
class Framework:  # defines the Framework class
    """A compliance framework and its list of relevant controls."""  # keeps the docstring text

    key: str  # evaluates the key expression
    label: str  # evaluates the label expression
    description: str  # evaluates the description expression
    controls: tuple[Control, ...]  # evaluates the controls expression


_FR = (  # assigns the computed value to _FR
    # --- NIST Risk Management Framework (NIST CSF / SP 800-53 families) ---
    Framework(  # runs the Framework() call
        key="nist-rmf",  # sets the key text
        label="NIST RMF",  # sets the label text
        description="NIST SP 800-53 control families mapped onto risk findings",  # sets the description text
        controls=(  # assigns the computed value to controls
            Control("RA-5", "Vulnerability scanning & remediation", ("vulnerability",)),  # runs the Control() call
            Control("SI-10", "Information input validation", ("code",), _INJECTION),  # runs the Control() call
            Control("SA-11", "Developer security testing", ("code", "code-quality")),  # runs the Control() call
            Control("IA-5", "Authenticator management (no shared/committed credentials)", ("secret",)),  # runs the Control() call
            Control("CM-8", "System component inventory (with licence obligations tracked)",  # FOSSology licence findings
                    ("license",)),  # runs the Control() call
            Control("SR-4", "Supply chain risk management (component provenance)", ("license",)),  # runs the Control() call
            Control("CM-6", "Configuration settings (any flagged IaC or container default)",  # catch-all: every misconfig
                    ("misconfiguration",)),  # runs the Control() call
            Control("SC-8", "Transmission confidentiality & integrity", ("code",), _CRYPTO),  # runs the Control() call
        ),  # closes the multiline block
    ),  # closes the multiline block
    Framework(  # runs the Framework() call
        key="nist-csf",  # sets the key text
        label="NIST CSF",  # sets the label text
        description="NIST Cybersecurity Framework 1.1 subcategories",  # sets the description text
        controls=(  # assigns the computed value to controls
            Control("ID.RA-1", "Vulnerability identification", ("vulnerability",)),  # runs the Control() call
            Control("ID.AM-2", "Software platforms and services inventoried", ("license",)),  # runs the Control() call
            Control("PR.AC-1", "Identity and credential management", ("secret",)),  # runs the Control() call
            Control("PR.DS-1", "Data-at-rest protection", ("secret", "code"), _CRYPTO),  # runs the Control() call
            Control("PR.IP-1", "Baseline configuration", ("misconfiguration",)),  # runs the Control() call
            Control("PR.IP-6", "Secure development lifecycle", ("code", "code-quality")),  # runs the Control() call
            Control("DE.CM-8", "Vulnerability / disclosure detection", ("vulnerability",)),  # runs the Control() call
        ),  # closes the multiline block
    ),  # closes the multiline block
    Framework(  # runs the Framework() call
        key="hipaa",  # sets the key text
        label="HIPAA",  # sets the label text
        description="HIPAA Security Rule safeguard sections",  # sets the description text
        controls=(  # assigns the computed value to controls
            Control("164.308(a)(1)(ii)(A)", "Risk analysis", ("vulnerability",)),  # runs the Control() call
            Control("164.308(a)(1)(ii)(B)", "Risk management", ("misconfiguration",)),  # runs the Control() call
            Control("164.308(a)(5)(ii)(B)", "Protection from malicious software", ("vulnerability",), _MALWARE),  # runs the Control() call
            Control("164.308(a)(5)(ii)(D)", "Password management", ("secret",)),  # runs the Control() call
            Control("164.312(a)(1)", "Access control", ("secret", "code"), ("auth", "authentic", "token", "session")),  # runs the Control() call
            Control("164.312(c)(1)", "Data integrity", ("code",)),  # runs the Control() call
            Control("164.312(e)(1)", "Transmission security", ("code",), _CRYPTO),  # runs the Control() call
        ),  # closes the multiline block
    ),  # closes the multiline block
    Framework(  # runs the Framework() call
        key="gdpr",  # sets the key text
        label="GDPR",  # sets the label text
        description="GDPR Article 32 security-of-processing articles",  # sets the description text
        controls=(  # assigns the computed value to controls
            Control("Art. 5(1)(f)", "Integrity and confidentiality of processing", ("secret",)),  # runs the Control() call
            Control("Art. 32(1)", "Appropriate technical measures (overall risk posture)", ("vulnerability",)),  # runs the Control() call
            Control("Art. 32(1)(a)", "Pseudonymisation and encryption", ("code",), _CRYPTO),  # runs the Control() call
            Control("Art. 32(1)(b)", "Confidentiality, integrity, availability and resilience", ("misconfiguration",)),  # runs the Control() call
            Control("Art. 32(2)", "Regular testing and evaluation of technical measures", ("code", "code-quality")),  # runs the Control() call
        ),  # closes the multiline block
    ),  # closes the multiline block
    Framework(  # runs the Framework() call
        key="cmmc",  # sets the key text
        label="CMMC",  # sets the label text
        description="CMMC 2.0 practices (NIST SP 800-171 numbering)",  # sets the description text
        controls=(  # assigns the computed value to controls
            Control("3.11.2", "Periodic vulnerability scanning", ("vulnerability",)),  # runs the Control() call
            Control("3.14.1", "Flaw remediation", ("code", "code-quality")),  # runs the Control() call
            Control("3.14.2", "Malicious code protection", ("vulnerability",), _MALWARE),  # runs the Control() call
            Control("3.4.2", "Security configuration settings", ("misconfiguration",)),  # runs the Control() call
            Control("3.5.7", "Password management", ("secret",)),  # runs the Control() call
            Control("3.13.16", "Protect confidentiality of CUI at rest", ("secret", "code"), _CRYPTO),  # runs the Control() call
        ),  # closes the multiline block
    ),  # closes the multiline block
    Framework(  # runs the Framework() call
        key="iso",  # sets the key text
        label="ISO 27001",  # sets the label text
        description="ISO/IEC 27001:2022 Annex A control sets",  # sets the description text
        controls=(  # assigns the computed value to controls
            Control("A.8.8", "Management of technical vulnerabilities", ("vulnerability",)),  # runs the Control() call
            Control("A.8.28", "Secure coding principles", ("code", "code-quality")),  # runs the Control() call
            Control("A.8.9", "Configuration management", ("misconfiguration",)),  # runs the Control() call
            Control("A.8.12", "Data leakage prevention", ("secret",)),  # runs the Control() call
            Control("A.5.31", "Legal, statutory and contractual requirements (licences)", ("license",)),  # runs the Control() call
            Control("A.8.7", "Protection against malware", ("vulnerability",), _MALWARE),  # runs the Control() call
            Control("A.8.24", "Use of cryptography", ("code",), _CRYPTO),  # runs the Control() call
        ),  # closes the multiline block
    ),  # closes the multiline block
    Framework(  # runs the Framework() call
        key="iso-42001",  # sets the key text
        label="ISO 42001",  # sets the label text
        description="ISO/IEC 42001:2023 Annex A AI-management sections",  # sets the description text
        controls=(  # assigns the computed value to controls
            # Section-level entries: Annex A of ISO/IEC 42001 groups its
            # technical requirements into the themes A.2-A.10, and the
            # keyword mapping connects scanner findings to those themes.
            Control("A.4", "AI system resources (infrastructure and data) - hardening", ("misconfiguration",)),  # runs the Control() call
            Control("A.5", "Assessing impacts of AI systems", ("code", "code-quality"),
                    ("impact", "assess", "bias", "fairness", "evaluat", "safety")),  # runs the Control() call
            Control("A.6", "AI system life cycle (verification, validation and testing)",  # catch-all: every
                    ("vulnerability", "code", "code-quality")),  # vulnerability lives here
            Control("A.7", "Data for AI systems (quality, PII and data handling)", ("secret",)),  # runs the Control() call
            Control("A.8", "Information for interested parties (transparency and documentation)", ("code", "code-quality"), _LOGGING),  # runs the Control() call
            Control("A.9", "Use of AI systems (oversight and deployment)", ("misconfiguration",),
                    ("deplo", "exposure", "port", "firewall", "permission", "privileg", "image")),  # runs the Control() call
            Control("A.10", "Third-party and supplier relationships (supply chain)", ("vulnerability",), _MALWARE),  # runs the Control() call
        ),  # closes the multiline block
    ),  # closes the multiline block
    Framework(  # runs the Framework() call
        key="pci",  # sets the key text
        label="PCI DSS",  # sets the label text
        description="PCI DSS requirements for systems that touch card data",  # sets the description text
        controls=(  # assigns the computed value to controls
            Control("Req 5.2/5.3", "Anti-malware mechanisms", ("vulnerability",), _MALWARE),  # runs the Control() call
            Control("Req 6.3.x", "Fix vulnerable components", ("vulnerability",)),  # runs the Control() call
            Control("Req 6.5.x", "Secure coding techniques", ("code", "code-quality")),  # runs the Control() call
            Control("Req 11.3.x", "Internal & external vulnerability scans", ("vulnerability",)),  # runs the Control() call
            Control("Req 8.x", "Authentication and credential management", ("secret",)),  # runs the Control() call
            Control("Req 2.2.x", "Secure system configurations", ("misconfiguration",)),  # runs the Control() call
        ),  # closes the multiline block
    ),  # closes the multiline block
    Framework(  # runs the Framework() call
        key="soc2",  # sets the key text
        label="SOC 2 Type 2",  # sets the label text
        description="AICPA Trust Services Criteria (CC series)",  # sets the description text
        controls=(  # assigns the computed value to controls
            Control("CC6.1", "Logical access security", ("secret",)),  # runs the Control() call
            Control("CC6.6", "Boundary protection / system configuration", ("misconfiguration",)),  # runs the Control() call
            Control("CC6.8", "Prevention of unauthorised or malicious software", ("vulnerability",), _MALWARE),  # runs the Control() call
            Control("CC7.1", "Vulnerability detection and mitigation", ("vulnerability",)),  # runs the Control() call
            Control("CC8.1", "Change management and code review", ("code", "code-quality")),  # runs the Control() call
        ),  # closes the multiline block
    ),  # closes the multiline block
)  # closes the multiline block

FRAMEWORKS: dict[str, Framework] = {framework.key: framework for framework in _FR}  # evaluates the FRAMEWORKS expression
FRAMEWORK_LABELS: dict[str, str] = {framework.key: framework.label for framework in _FR}  # evaluates the FRAMEWORK_LABELS expression
FRAMEWORK_DESCRIPTIONS: dict[str, str] = {  # evaluates the FRAMEWORK_DESCRIPTIONS expression
    framework.key: framework.description for framework in _FR  # evaluates the framework.key expression
}  # closes the multiline block
ALL_FRAMEWORKS: tuple[str, ...] = tuple(FRAMEWORKS)  # runs the tuple() call


def normalize_frameworks(names: Iterable[str] | None) -> list[str]:  # defines the normalize_frameworks() function
    """Validate a framework selection, keeping the definition order."""  # keeps the docstring text
    if names is None:  # evaluates the branch condition
        return []  # returns the value to the caller
    selected: list[str] = []  # evaluates the selected expression
    for raw in names:  # loops over the collection
        key = str(raw).strip().lower().replace(" ", "-")  # runs the str() call
        if key in FRAMEWORKS and key not in selected:  # evaluates the branch condition
            selected.append(key)  # adds an item to the list
    return selected  # returns the selected to the caller


def _matches(control: Control, finding_text: str) -> bool:  # defines the _matches() function
    if not control.keywords:  # evaluates the branch condition
        return True  # returns the True to the caller
    return any(keyword in finding_text for keyword in control.keywords)  # returns the any to the caller


def _match_controls(framework: Framework, text: str, finding: Any) -> list[Control]:  # defines the _match_controls() function
    """Which of a framework's controls does this finding touch (in order)?

    ``text`` is the finding's pre-lowercased search text, built once per
    finding by :func:`map_all` so the sweep never re-cleans it per control.
    """
    matched: list[Control] = []  # evaluates the matched expression
    for control in framework.controls:  # loops over the collection
        if finding.category not in control.categories:  # evaluates the branch condition
            continue  # skips to the next loop iteration
        if control.kinds and finding.kind not in control.kinds:  # evaluates the branch condition
            continue  # skips to the next loop iteration
        if not _matches(control, text):  # evaluates the branch condition
            continue  # skips to the next loop iteration
        matched.append(control)  # adds an item to the list
    return matched  # returns the matched to the caller


def _finding_key(finding: Any) -> str:  # defines the _finding_key() function
    """Stable identity joining a finding row to its framework mapping."""
    return reportkeys.location_key(finding)  # returns the shared row key


def map_all(  # defines the map_all() function
    findings: Iterable[Any],  # evaluates the findings expression
    framework_keys: Iterable[str],  # evaluates the framework_keys expression
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, list[str]]]]:  # closes the multiline block
    """One matching sweep producing BOTH consumer structures.

    Returns ``(frameworks, finding_map)``: the per-framework control
    payloads :func:`map_findings` used to return, and the per-finding
    ``rule_id|file|line`` -> ``{framework label: [control ids]}`` map
    :func:`findings_control_map` used to compute with a second, independent
    pass. Each finding's search text is lowered exactly once, and every
    framework walks the findings exactly once - previously
    ``O(frameworks x controls x keywords x findings)`` twice per report.
    """
    keys = normalize_frameworks(framework_keys)  # runs the selection pass
    items = list(findings)  # materialises the sweep set (also fixes generator reuse)
    texts: dict[int, str] = {  # builds the per-finding search texts
        id(item): f"{item.rule_id} {item.title} {item.detail}".lower()  # the matched text
        for item in items  # runs the comprehension
    }  # closes the multiline block

    frameworks: dict[str, dict[str, Any]] = {}  # the grouped control payloads
    finding_map: dict[str, dict[str, list[str]]] = {}  # the per-finding control refs
    for key in keys:  # loops over the selected frameworks
        framework = FRAMEWORKS[key]  # copies the FRAMEWORKS value into framework
        buckets: dict[str, dict[str, Any]] = {  # evaluates the buckets expression
            control.id: {  # evaluates the control.id expression
                "id": control.id,  # maps the id dictionary entry
                "title": control.title,  # maps the title dictionary entry
                "status": "clear",  # maps the status dictionary entry
                "affected": 0,  # maps the affected dictionary entry
                "worst": "",  # maps the worst dictionary entry
                "rule_ids": [],  # maps the rule_ids dictionary entry
                "examples": [],  # maps the examples dictionary entry
            }  # closes the multiline block
            for control in framework.controls  # loops over the collection
        }  # closes the multiline block
        mapped_ids: set[int] = set()  # updates the stored value

        for item in items:  # loops over the pre-computed sweep set
            matched = _match_controls(framework, texts[id(item)], item)  # runs the match pass
            for control in matched:  # loops over the collection
                bucket = buckets[control.id]  # copies the buckets value into bucket
                bucket["affected"] += 1  # evaluates the bucket expression
                bucket["rule_ids"].append(item.rule_id)  # adds an item to the list
                if len(bucket["examples"]) < 3:  # evaluates the branch condition
                    bucket["examples"].append(f"{item.title} ({item.location or 'location n/a'})")  # adds an item to the list
                if not bucket["worst"] or _rank(item.severity) < _rank(bucket["worst"]):  # evaluates the branch condition
                    bucket["worst"] = item.severity  # copies the item.severity value into bucket["worst"]
            if matched:  # evaluates the branch condition
                mapped_ids.add(id(item))  # adds an item to the set (unmapped maths)
                ref = finding_map.setdefault(  # runs the setdefault() call
                    _finding_key(item), {}  # the row identity
                )  # closes the multiline block
                ref[framework.label] = [control.id for control in matched]  # assigns the computed value to ref[framework.label]

        for bucket in buckets.values():  # loops over the collection
            if bucket["affected"]:  # evaluates the branch condition
                bucket["status"] = "affected"  # sets the bucket["status"] text
            else:  # covers the remaining branch
                bucket.pop("rule_ids", None)  # runs the pop() call
                bucket.pop("examples", None)  # runs the pop() call

        frameworks[key] = {  # assigns the computed value to frameworks[key]
            "key": key,  # maps the key dictionary entry
            "label": framework.label,  # maps the label dictionary entry
            "description": framework.description,  # maps the description dictionary entry
            "controls": list(buckets.values()),  # maps the controls dictionary entry
            "affected_controls": sum(1 for b in buckets.values() if b["status"] == "affected"),  # maps the affected_controls dictionary entry
            "total_controls": len(buckets),  # maps the total_controls dictionary entry
            "unmapped": len(items) - len(mapped_ids),  # the arithmetic complement, not a second sweep
        }  # closes the multiline block
    return frameworks, finding_map  # returns both structures


def findings_control_map(  # defines the findings_control_map() function
    findings: Iterable[Any],  # evaluates the findings expression
    framework_keys: Iterable[str],  # evaluates the framework_keys expression
) -> dict[str, dict[str, list[str]]]:  # closes the multiline block
    """Per-finding control references, keyed ``rule_id|file|line``.

    Used by the CSV exporter so each finding row can name the controls of the
    selected frameworks it affects, e.g. ``{"PCI DSS": ["Req 8.x"]}``.
    """
    _frameworks, finding_map = map_all(findings, framework_keys)  # the shared sweep
    return finding_map  # returns the result to the caller


def map_findings(  # defines the map_findings() function
    findings: Iterable[Any],  # evaluates the findings expression
    framework_keys: Iterable[str],  # evaluates the framework_keys expression
) -> dict[str, dict[str, Any]]:  # closes the multiline block
    """Group findings under each selected framework's controls.

    ``findings`` items only need the ``category``, ``kind``, ``rule_id``,
    ``title``, ``detail``, ``location`` and ``severity`` attributes, so both
    :class:`scoring.Finding` objects and re-loaded JSON dicts work.

    Returns one entry per selected framework::

        {"label": "PCI DSS",
         "description": ...,
         "controls": [{"id", "title", "status", "affected", "worst",
                        "rule_ids", "examples"}...],
         "affected_controls": n, "total_controls": n, "unmapped": n}
    """
    frameworks, _finding_map = map_all(findings, framework_keys)  # the shared sweep
    return frameworks  # returns the grouped payload


def worst_control(control_entry: dict[str, Any]) -> str:  # defines the worst_control() function
    """Severity string used for sorting control rows in the UI."""  # keeps the docstring text
    return control_entry.get("worst") or ""  # returns the control_entry.get to the caller


def summarize(frameworks: dict[str, dict[str, Any]] | None) -> dict[str, Any]:  # defines the summarize() function
    """Small helper for rendering: counts per framework, affected controls first."""  # keeps the docstring text
    summary = []  # assigns the computed value to summary
    for entry in (frameworks or {}).values():  # loops over the collection
        affected = [c for c in entry["controls"] if c["status"] == "affected"]  # assigns the computed value to affected
        affected.sort(key=lambda c: (_rank(c.get("worst") or "unknown"), -c["affected"]))  # sorts the values
        summary.append(  # adds an item to the list
            {  # executes the statement
                "key": entry["key"],  # maps the key dictionary entry
                "label": entry["label"],  # maps the label dictionary entry
                "affected_controls": entry["affected_controls"],  # maps the affected_controls dictionary entry
                "total_controls": entry["total_controls"],  # maps the total_controls dictionary entry
                "worst": next((c["worst"] for c in affected), ""),  # maps the worst dictionary entry
                "top_controls": affected[:4],  # maps the top_controls dictionary entry
                "unmapped": entry["unmapped"],  # maps the unmapped dictionary entry
            }  # closes the multiline block
        )  # closes the multiline block
    return summary  # returns the summary to the caller
