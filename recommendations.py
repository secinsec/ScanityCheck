"""Rank the report's open findings into the twenty-five most valuable remediations.

Pure data, no Tkinter, in the same spirit as ``dashboard.py``: the GUI, the
text report and the PDF can all consume the same payload list.

Each entry is a candidate remediation theme - upgrade the vulnerable
packages, rotate the committed credentials, harden the flagged
configuration, patch the code defects - ranked by the score points the
affected findings currently carry. The impact projection deliberately
follows the same refund rule the reviewer-omission feature uses: removing a
finding from the score returns its stated points, clamped so the running
projection never exceeds 100 and never drops below the clean score.

Filler guidance, clearly labeled as general best practice, is appended when
the report carries fewer open themes than the tab has slots.
"""

from __future__ import annotations  # imports annotations from the __future__ module

from typing import Any  # evaluates the typing expression

import config  # imports the config module
import reportkeys  # imports the shared theme-key/category registry
import scoring  # imports the scoring module

# Action wording per finding category. A theme's title names the concrete
# objects (package, credential family, control id) gathered from its findings.
_ACTION_TEMPLATES = {  # assigns the computed value to _ACTION_TEMPLATES
    "vulnerability": "Upgrade or pin the vulnerable packages",  # maps the entry
    "secret": "Rotate and purge the committed credentials",  # maps the entry
    "misconfiguration": "Harden the flagged configuration files",  # maps the entry
    "code": "Fix the flagged code-security defects",  # maps the entry
    "license": "Re-licence or replace the flagged components",  # maps the entry
    "code-quality": "Clear the maintainability findings that invite bugs",  # maps the entry
}  # closes the block

# Broad, honest hygiene guidance for reports with fewer themes than slots.
_FILLER_TEMPLATES = (  # assigns the computed value to _FILLER_TEMPLATES
    ("Add a security policy",  # supplies the title text
     "Publish a SECURITY.md stating supported versions, how to report issues "  # supplies the body text
     "and the expected response time."),  # supplies the body text
    ("Pin build dependencies and actions",  # supplies the title text
     "Anchor every CI dependency and GitHub action to a full hash so the "  # supplies the body text
     "pipeline cannot be poisoned."),  # supplies the body text
    ("Add automated scanning to CI",  # supplies the title text
     "Run the same scanners on every push so regressions surface before "  # supplies the body text
     "release instead of during audits."),  # supplies the body text
    ("Trim the default network exposure",  # supplies the title text
     "Close management endpoints and sample-only ports on anything "  # supplies the body text
     "internet-facing."),  # supplies the body text
    ("Enable two-person review on risky changes",  # supplies the title text
     "Require an approving review for changes to auth, crypto and build "  # supplies the body text
     "scripts."),  # supplies the body text
    ("Publish an SBOM with every release",  # supplies the title text
     "Ship a machine-readable component list so consumers can react to new "  # supplies the body text
     "advisories quickly."),  # supplies the body text
    ("Log and alert on security-relevant events",  # supplies the title text
     "Write authentication, permission and config changes to an alerted log; "  # supplies the body text
     "undetected change is undetected risk."),  # supplies the body text
    ("Define an incident-response runbook",  # supplies the title text
     "Write down who rotates which credential, in which order, with what "  # supplies the body text
     "customer communication, before it is needed."),  # supplies the body text
    ("Prune stale code and unused dependencies",  # supplies the title text
     "Dead code and idle dependencies carry attack surface nobody patches."),  # supplies the body text
    ("Document the secrets-handling boundaries",  # supplies the title text
     "State where credentials may live and where they may not, and check the "  # supplies the body text
     "boundary in CI."),  # supplies the body text
    ("Schedule recurring dependency reviews",  # supplies the title text
     "Put a recurring calendar entry on upgrading the riskiest dependencies "  # supplies the body text
     "instead of waiting for an audit."),  # supplies the body text
)  # closes the block


def _theme_key(finding: dict[str, Any]) -> str:  # defines the _theme_key() function
    """Theme id shared with the greatest-risks rows and the omission feature."""
    return reportkeys.finding_group_key(finding)  # the shared builder


def _themes_from_persisted(  # defines the _themes_from_persisted() function
    report: dict[str, Any],  # evaluates the report expression
    findings: list[dict[str, Any]],  # evaluates the findings expression
) -> tuple[dict[str, dict[str, Any]], dict[str, float]] | None:  # closes the multiline block
    """Build the theme map from the report's persisted greatest-risks rows.

    The scoring report already groups every open finding into themes (
    ``greatest_risks`` carries the category, rule/title, instance count,
    tools, sample locations, package and - since the charge pass lived there
    - each theme's effective charge). When those rows cover exactly this
    open finding set the re-grouping walk is skipped and the rows become the
    themes directly; anything else (hand-built reports, older rows, open
    themes the rows do not know) returns ``None`` so the caller falls back
    to walking the findings.
    """
    rows = report.get("greatest_risks") or []  # the persisted theme rows
    if not rows:  # evaluates the branch condition
        return None  # nothing persisted to reuse
    row_keys = {row.get("key") for row in rows}  # the persisted identities
    if not all(row.get("key") and row.get("charge") is not None for row in rows):  # evaluates the branch condition
        return None  # the rows predate the charge persistence
    open_keys = {  # evaluates the open_keys expression
        reportkeys.finding_group_key(finding) for finding in findings  # the live theme ids
    }  # closes the multiline block
    if row_keys != open_keys:  # evaluates the branch condition
        return None  # the rows no longer match the report state (post-omission edits)

    themes: dict[str, dict[str, Any]] = {}  # evaluates the themes expression
    totals: dict[str, float] = {}  # evaluates the totals expression
    for row in rows:  # loops over the persisted rows
        key = str(row.get("key"))  # copies the row value into key
        themes[key] = {  # stores the theme block
            "key": key,  # maps the key dictionary entry
            "category": str(row.get("category") or ""),  # maps the category dictionary entry
            "rule_id": str(row.get("rule_id") or ""),  # maps the rule_id dictionary entry
            "title": str(row.get("title") or ""),  # maps the title dictionary entry
            "action": _ACTION_TEMPLATES.get(str(row.get("category") or ""), "Remediate the flagged findings"),  # picks the action
            "instances": int(row.get("count") or 0),  # counts the findings
            "locations": list(row.get("locations") or []),  # sample locations for the fixer
            # The rows carry tool display labels, exactly the values the
            # findings walk would have collected.
            "tools": list(row.get("tool_labels") or []),  # who identified it
            "worst": str(row.get("severity") or "unknown"),  # the worst rating
            "package": str(row.get("package") or ""),  # the named package
        }  # closes the block
        totals[key] = float(row.get("charge") or 0.0)  # the persisted effective charge
    return themes, totals  # returns the pair


def build_recommendations(report: dict[str, Any], limit: int = 25) -> list[dict[str, Any]]:
    """Return up to ``limit`` remediation actions, biggest impact first.

    Themes group the report's open (non-omitted) findings the same way the
    greatest-risks rows do, so one row here means "fix all N instances of
    this issue". ``impact`` is the theme's charged share of the score - under
    a binding category cap that is its pro-rata slice of the charge, the same
    effective value the reviewer-omission refunds pay - and
    ``score_projection`` walks the cumulative post-fix score, while
    ``instances``/``locations``/``tools`` summarise what the fix touches.
    """
    findings = [f for f in report.get("findings") or [] if not f.get("omitted")]  # the open find set
    score_before = int(report.get("score") or 0)  # the live rescoring base

    # One shared charge pass: every open finding's effective value under the
    # report's own (context-normalised) cap table — the same budgets the
    # reviewer-omission refunds pay from.
    sweep = scoring.effective_charges(findings, report.get("caps") or config.CAPS)  # runs the shared switch

    themes: dict[str, dict[str, Any]] | None = None  # the persisted fast path, when it fires
    totals: dict[str, float] = {}  # evaluates the totals expression
    if len(findings) <= len(report.get("greatest_risks") or []):  # evaluates the cheap pre-check
        browsed = _themes_from_persisted(  # runs the persisted builder
            report, sweep.findings  # evaluates the arguments
        )  # closes the multiline block
        if browsed is not None:  # evaluates the branch condition
            themes, totals = browsed  # unpacks the persisted pair

    if themes is None:  # the fallback: walk the findings, as always
        themes = {}  # resets the theme map
        totals = {}  # resets the totals
        for charge, finding in zip(sweep.shares, sweep.findings):  # pairs the shares
            category = finding.get("category") or "code"  # copies the category value
            key = _theme_key(finding)  # builds the theme key
            # The charged share mirrors the omission math: under a binding cap,
            # a finding's effective value is its pro-rata slice of the category
            # charge and not its raw headline weight.
            share = charge  # the shared arithmetic already applied the cap spread
            theme = themes.get(key)  # fetches the theme
            if theme is None:  # evaluates the branch condition
                policy = {}  # evaluates the policy expression
                rule = str(finding.get("rule_id") or "")  # fetches the rule value
                title = str(finding.get("title") or "")  # fetches the title value
                themes[key] = {  # stores the theme block
                    "key": key,  # maps the key dictionary entry
                    "category": category,  # maps the category dictionary entry
                    "rule_id": rule,  # maps the rule_id dictionary entry
                    "title": title,  # maps the title dictionary entry
                    "action": _ACTION_TEMPLATES.get(category, "Remediate the flagged findings"),  # picks the action
                    "instances": 0,  # counts the findings
                    "locations": [],  # sample locations for the fixer
                    "tools": [],  # who identified it
                    "worst": finding.get("severity") or "unknown",  # the worst rating
                    "package": str(finding.get("package") or ""),  # the named package
                }  # closes the block
                theme = themes[key]  # copies the theme value into theme
            theme["instances"] += 1  # bumps the instance count
            if theme["package"] == "" and finding.get("package"):  # evaluates the branch condition
                theme["package"] = str(finding.get("package"))  # names the package
            totals[key] = totals.get(key, 0.0) + share  # accumulates the charged share
            severity = str(finding.get("severity") or "unknown")  # fetches the severity value
            if scoring.severity_rank(severity) < scoring.severity_rank(theme["worst"]):  # evaluates the branch condition
                theme["worst"] = severity  # keeps the worst rating on top
            tools = list(dict.fromkeys([  # builds the tools collect
                *theme["tools"],  # keeps every tool attribution in order
                *list(finding.get("tool_labels") or [finding.get("tool") or "unknown-tool"]),  # maps the attribution list
            ]))  # closes the tools collect
            theme["tools"] = tools  # writes the tools list back
            for location in finding.get("locations") or []:  # loops over the sample spots
                if location and location not in theme["locations"] and len(theme["locations"]) < 3:  # evaluates the branch condition
                    theme["locations"].append(location)  # samples the location

    ranked = sorted(themes.values(), key=lambda theme: -totals.get(theme["key"], 0.0))  # ranks the themes

    result: list[dict[str, Any]] = []  # evaluates the result expression
    remaining = max(0, 100 - score_before)  # the points the theme can still return
    for theme in ranked:  # loops over the collection
        if len(result) >= limit:  # evaluates the branch condition
            break  # stops at the tenth slot
        key = theme["key"]  # copies the key value
        impact = round(min(totals.get(key, 0.0), remaining), 1)  # clamps the projection
        cap_bound = remaining <= 0.0  # whether the ceiling already absorbs this theme
        if impact <= 0.0 and not cap_bound:  # evaluates the branch condition
            continue  # a zero-weight hint gives nothing and hides nothing
        prior = sum(row["impact"] for row in result)  # walks the collected refunds
        remaining = max(0.0, remaining - impact)  # spends the capacity
        result.append({  # stores the recommendation row
            "rank": len(result) + 1,  # one-based position
            "key": key,  # maps the key dictionary entry
            "category": theme["category"],  # maps the category dictionary entry
            "action": theme["action"],  # maps the action dictionary entry
            "subject": _theme_subject(theme),  # concise subject line
            "impact": impact,  # score points returned by the fix
            "capped": cap_bound or impact <= 0.0,  # flagged when the fix cannot move the score
            "score_projection": round(min(100, max(score_before, score_before + prior + impact)), 1),  # the post-fix walk
            "instances": theme["instances"],  # maps the instances entry
            "worst": theme["worst"],  # maps the worst entry
            "package": theme["package"],  # maps the package entry
            "locations": list(theme["locations"]),  # maps the locations entry
            "tools": list(theme["tools"]),  # maps the tools entry
            "general": False,  # this row comes from real findings
        })  # closes the row build

    # Pad the list with clearly-labeled general best practice so the tab
    # always shows ten rows worth reading on thin or cleaned-up reports.
    if len(result) < limit:  # evaluates the branch condition
        used = {row["subject"].lower() for row in result}  # dedupes names
        for title, summary in _FILLER_TEMPLATES:  # loops over the filler pool
            if len(result) >= limit:  # evaluates the branch condition
                break  # stops at the tenth slot
            if title.lower() in used:  # evaluates the branch condition
                continue  # skips a duplicate safety blanket
            used.add(title.lower())  # avoids a return match
            result.append({  # stores the filler row
                "rank": len(result) + 1,  # one-based position
                "key": f"general|{title}",  # a stable non-finding key
                "category": "general",  # no scoring category
                "action": title,  # maps the action dictionary entry
                "subject": title,  # the title doubles as the subject
                "impact": 0.0,  # the filler never promises points
                "capped": False,  # the filler is not cap-bound
                "score_projection": None,  # no projection for non-scored rows
                "instances": 0,  # no findings behind it
                "worst": "unknown",  # no severity claim
                "package": "",  # maps the package dictionary entry
                "locations": [],  # maps the locations entry
                "tools": [],  # maps the tools entry
                "general": True,  # labeled: not tied to a specific finding
            })  # closes the row build
    return result[:limit]  # returns the ranked list


def _theme_subject(theme: dict[str, Any]) -> str:  # defines the _theme_subject() function
    """A single human-readable subject line for one remediation theme."""
    parts: list[str] = []  # builds the phrase list
    rule = str(theme.get("rule_id") or "").strip()  # reads the rule id
    title = str(theme.get("title") or "").strip()  # reads the title
    if rule and rule != title:  # evaluates the branch condition
        parts.append(rule)  # keeps the id for traceability
    if title:  # evaluates the branch condition
        parts.append(title)  # adds the human title
    package = str(theme.get("package") or "").strip()  # reads the package name
    if package and package.lower() not in " ".join(parts).lower():  # evaluates the branch condition
        parts.append(f"({package})")  # names the affected package
    suffix = (", ".join(parts) or "flagged findings")[:120]  # caps the length
    return f"{_ACTION_TEMPLATES.get(theme.get('category') or 'code', 'Remediate the flagged findings')} - {suffix}"  # returns the line
