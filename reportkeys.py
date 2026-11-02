"""Shared report identity keys, severities and categories - one implementation.

The scoring, compliance and recommendations modules each used to carry a
near-identical copy of the finding-theme key, the severity rank table and the
scoring category list. This module is the single authoritative source so the
omission keys, CSV joins and severity orderings can never silently diverge.

Import direction is deliberate: this module only imports :mod:`config`, so
``scoring`` (which imports ``compliance``) and ``compliance`` can both import
it without creating a cycle.
"""

from __future__ import annotations  # imports annotations from the __future__ module

from typing import Any  # imports Any from the typing module

from config import SEVERITY_ORDER  # copies the canonical severity order

# The six weighted scoring categories, in report/print order.
SCORING_CATEGORIES: tuple[str, ...] = (  # assigns the computed value to SCORING_CATEGORIES
    "vulnerability",  # dependency CVEs
    "secret",  # committed credentials
    "misconfiguration",  # IaC / container defaults
    "code",  # code-level security findings
    "license",  # open-source licence compliance (FOSSology findings)
    "code-quality",  # maintainability, scored at its own flat weight
)  # closes the multiline block

# The categories whose severities feed the critical/high totals and the
# zero-critical "secure" rule - the licence chatter is compliance context,
# not a security veto, so it and code-quality stay out of the risk set.
RISK_CATEGORIES: tuple[str, ...] = (  # assigns the computed value to RISK_CATEGORIES
    "vulnerability",  # dependency CVEs
    "secret",  # committed credentials
    "misconfiguration",  # IaC / container defaults
    "code",  # code-level security findings
)  # closes the multiline block

# Severity -> band index. Lower is worse; an unknown severity sorts last.
SEVERITY_RANKS: dict[str, int] = {  # assigns the computed value to SEVERITY_RANKS
    severity: index for index, severity in enumerate(SEVERITY_ORDER)  # pairs the order
}  # closes the multiline block


def severity_rank(severity: str) -> int:  # defines the severity_rank() function
    """Lower is worse; unknown severities rank after every known one."""
    return SEVERITY_RANKS.get(severity, len(SEVERITY_ORDER))  # returns the rank lookup


def finding_group_key(finding: Any) -> str:  # defines the finding_group_key() function
    """Stable identity of a risk theme: ``category|rule-or-title``.

    Works for :class:`scoring.Finding` objects and row dictionaries alike, so
    the omissions UI, the greatest-risks rows and the recommendations tab all
    name a theme with the very same string.
    """
    if isinstance(finding, dict):  # evaluates the branch condition
        category = str(finding.get("category") or "")  # reads the dict value
        rule_id = str(finding.get("rule_id") or "")  # reads the dict value
        title = str(finding.get("title") or "")  # reads the dict value
    else:  # covers the remaining branch
        category = finding.category  # reads the attribute
        rule_id = finding.rule_id  # reads the attribute
        title = finding.title  # reads the attribute
    return f"{category}|{rule_id or title}"  # returns the built key


def location_key(finding: Any) -> str:  # defines the location_key() function
    """Row identity inside framework mappings: ``rule_id|file|line``.

    Used to join a per-finding row (CSV export, per-finding control map) back
    to the framework mapping computed once by :func:`compliance.map_all`.
    """
    if isinstance(finding, dict):  # evaluates the branch condition
        rule_id = str(finding.get("rule_id") or "")  # reads the dict value
        file_id = str(finding.get("file") or "")  # reads the dict value
        line = str(finding.get("line") or 0)  # reads the dict value
    else:  # covers the remaining branch
        rule_id = str(finding.rule_id)  # reads the attribute
        file_id = str(finding.file)  # reads the attribute
        line = str(getattr(finding, "line", 0) or 0)  # reads the attribute
    return f"{rule_id}|{file_id}|{line}"  # returns the built key
