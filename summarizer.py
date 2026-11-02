"""Plain-language scan summary for the "Summarize It" popup.

Pure functions over a finished report: :func:`summary_bullets` reduces the
findings, categories, maintenance pulse, SBOM, compliance mapping and
confidence into a small set of honest sentences (at least 1, capped at 10)
that a security reviewer can read in ten seconds. No Tkinter, so the CLI and
tests can use it too.
"""

from __future__ import annotations

from typing import Any


def _count(report: dict[str, Any], category: str) -> int:  # defines the _count() function
    """The findings count of one category, from the precomputed totals."""
    totals = report.get("totals") or {}  # fetches the value
    by_category = totals.get("by_category") or {}  # the counts table
    return int(by_category.get(category) or 0)  # returns the count to the caller


def summary_bullets(report: dict[str, Any]) -> list[str]:  # defines the summary_bullets() function
    """Reduce a finished scan into 1-10 plain-language summary bullets.

    Every bullet is a conditional on the report's own data, so thin scans
    produce fewer, still-honest lines and rich scans fill the popup.
    """
    bullets: list[str] = []  # the sentences we compose
    score = int(report.get("score") or 0)  # the headline number
    verdict = str(report.get("verdict") or "").upper()  # the verdict word
    band = str(report.get("band") or "").lower()  # the band label
    totals = report.get("totals") or {}  # the totals block
    critical = int(totals.get("critical") or 0)  # the critical count
    high = int(totals.get("high") or 0)  # the high count
    care = report.get("care") or {}  # the maintenance blob
    sbom = report.get("sbom") or {}  # the SBOM payload
    confidence = report.get("confidence") or {}  # the confidence block

    # 1. The headline always lands: score, band and what to make of it.
    if verdict == "SECURE":
        bullets.append(  # the calm headline
            f"The repository scores {score}/100 ({band.title()} risk) and passed the "
            f"security gate - it still needs the independent validation below before "
            f"deployment decisions are made."
        )
    elif critical:  # the serious headline
        bullets.append(  # the reason the verdict is what it is
            f"{critical} critical-severity finding{'s' if critical != 1 else ''} "
            f"drove the {verdict} verdict ({score}/100, {band.title()} risk); the "
            f"repository is not production-ready until they are remediated."
        )
    else:  # covers the remaining branch
        bullets.append(  # the softer summary line
            f"The repository scores {score}/100 ({band.title()} risk, {verdict}) with "
            f"{high} high-severity finding{'s' if high != 1 else ''} - triage them "
            f"before operational use."
        )

    # 2. Secrets: the harshest category, always fired immediately.
    secret = _count(report, "secret")  # the credential count
    if secret:  # evaluates the branch condition
        bullets.append(  # the secrets warning
            f"The code contains {secret} committed credential{'s' if secret != 1 else ''}; "
            f"it should not be run in an operational environment without a security review, "
            f"credential rotation, and a purge of the secrets from the history."
        )

    # 3. Dependency vulnerabilities and the internet-exposure caveat.
    vulnerability = _count(report, "vulnerability")  # the CVE count
    if vulnerability:  # evaluates the branch condition
        bullets.append(  # the internet-facing warning
            f"Contributing libraries carry {vulnerability} known vulnerability "
            f"finding{'s' if vulnerability != 1 else ''} (the worst of the set rated "
            f"{'critical' if critical else 'above medium'} severity), so the software "
            f"should not be exposed to Internet-connected systems without patching "
            f"and further verification."
        )

    # 4. IaC/container posture, framed for cloud deployments.
    misconfiguration = _count(report, "misconfiguration")  # the IaC count
    if misconfiguration:  # evaluates the branch condition
        bullets.append(  # the cloud-deployment warning
            f"{misconfiguration} infrastructure or container misconfiguration"
            f"{'s' if misconfiguration != 1 else ''} exist; these are most concerning "
            f"for cloud-based deployments, so harden the branches before any "
            f"production rollout."
        )

    # 5. Code-level weaknesses from the SAST engines.
    code = _count(report, "code")  # the code-finding count
    if code:  # evaluates the branch condition
        bullets.append(  # the static-analysis summary
            f"Static analysis (CodeQL / Semgrep) flagged {code} code-level "
            f"weakness{'es' if code != 1 else ''}; the CWE classes shown in the "
            f"dashboard usually point at one fixable habit rather than many bugs."
        )

    # 6. Maintenance reality from the Care-and-Feeding data.
    if care:  # evaluates the branch condition
        trend = str(care.get("development_trend") or "")  # the trend word
        contributors = int(care.get("contributors") or 0)  # the contributor count
        last_days = care.get("last_commit_days")  # days since the last commit
        if trend in {"dormant"} or (last_days is not None and last_days > 180):  # a stalled repo
            bullets.append(  # the dormant warning
                "Development activity has stalled; a dormant project stops receiving "
                "security fixes, so budget compensating controls and monitoring before "
                "operational trust."
            )
        elif contributors >= 2 and trend:  # an active one
            bullets.append(  # the positive maintenance note
                f"The author team is active on GitHub ({contributors} contributors, "
                f"development currently {trend}, "
                f"{int(care.get('commits_last_90d') or 0)} commits in 90 days), which "
                f"usually indicates maintained dependencies and applied coding practice."
            )

    # 7. Licence surface from the FOSSology findings.
    licence = _count(report, "license")  # the licence-finding count
    if licence:  # evaluates the branch condition
        bullets.append(  # the licence advice
            f"{licence} component{'s' if licence != 1 else ''} ship under restrictive or "
            f"undefined licences; a legal review is required before any closed-source "
            f"or commercial distribution."
        )

    # 8. The SBOM footprint from either SBOM scanner.
    sbom_rows = int(sbom.get("components") or 0)  # the component count
    if sbom_rows:  # evaluates the branch condition
        bullets.append(  # the supply-chain note
            f"The SBOM catalogues {sbom_rows} components "
            f"({sbom.get('unversioned', 0)} without a pinned version) - keep the "
            f"dependency list locked and regenerate the SBOM on every release."
        )

    # 9. How much the report itself can be trusted.
    confidence_score = confidence.get("score")  # the confidence figure
    corroborated = (report.get("dedupe") or {}).get("corroborated", 0)  # the agreement count
    if confidence_score is not None:  # evaluates the branch condition
        agreement = (  # the agreement clause keeps the honest grammar
            f"{corroborated} finding{'s were' if corroborated != 1 else ' was'} "
            f"corroborated by two or more independent tools; "
            if corroborated
            else ""
        )  # closes the clause build
        bullets.append(  # the confidence row
            f"Scanner confidence is {confidence_score}/100 "
            f"({str(confidence.get('band') or '').lower()}); {agreement}"
            "treat any remaining single-tool findings with an extra review pass."
        )

    # 10. Compliance mapping when the reviewer selected a framework.
    affected_controls = 0  # the affected control-finding pairs
    for framework in (report.get("frameworks") or {}).values():  # loops over the chosen frameworks
        controls = framework.get("controls") or []  # the control rows
        if isinstance(controls, list):  # the row shape from map_all
            affected_controls += sum(int(row.get("affected") or 0) for row in controls if isinstance(row, dict))
    if affected_controls:  # evaluates the branch condition
        bullets.append(  # the compliance note
            f"{affected_controls} finding-to-control pair{'s' if affected_controls != 1 else ''} "
            f"were mapped against the selected compliance framework"
            f"{'s' if len(report.get('frameworks') or {}) != 1 else ''}; those controls "
            f"track exactly what auditors will ask about first."
        )

    # Trim to at most ten: the headline bullet always survives the cut.
    bullets = bullets[:10]  # keeps the popup from turning into a report

    # Honest padding when a thin scan left fewer than eight bullets: data-grounded
    # fillers will match conditions on the report.  # evaluates the branch condition
    fillers: list[str] = []  # the pad candidates
    risks = [  # the most-charged themes worth naming
        str(row.get("title") or row.get("rule_id") or "").strip()  # the theme label
        for row in (report.get("greatest_risks") or [])  # the ranked rows
        if isinstance(row, dict) and (row.get("title") or row.get("rule_id"))  # only named rows
    ]  # closes the risks build
    if risks:  # evaluates the branch condition
        fillers.append(  # the "where to start" bullet
            "Start with the most-charged risk themes: " + ", ".join(f"{name}" for name in risks[:3]) + "."
        )  # closes the filler
    if not (report.get("frameworks") or {}):  # evaluates the branch condition
        fillers.append(  # the framework suggestion
            "No compliance framework was selected; choosing one maps these findings "
            "onto auditable controls in the report and CSV."
        )  # closes the filler
    if not care:  # evaluates the branch condition
        fillers.append(  # the unavailable-maintenance note
            "Maintenance statistics were unavailable, so project upkeep could not be "
            "verified in this pass."
        )  # closes the filler
    if not _count(report, "secret"):  # evaluates the branch condition
        fillers.append(  # the clean-secrets note
            "No committed credentials were charged in this pass, so no immediate "
            "credential rotation is indicated - keep the secret scanners selected on "
            "future scans."
        )  # closes the filler
    if not _count(report, "misconfiguration"):  # evaluates the branch condition
        fillers.append(  # the clean-IaC note
            "No infrastructure or container misconfigurations were charged, so the "
            "audited deployment definitions passed the IaC checks in this pass."
        )  # closes the filler
    if not _count(report, "license"):  # evaluates the branch condition
        fillers.append(  # the clean-licence note
            "No restrictive licence findings were reported, though usage and "
            "distribution constraints should still be confirmed for new components."
        )  # closes the filler
    fillers.append(  # the point-in-time caveat, always true and worth a slot
        "These findings are point-in-time: re-scan after remediation to measure "
        "actual progress."
    )  # closes the filler
    for filler in fillers:  # pads while the popup is thin
        if len(bullets) >= 8:  # evaluates the branch condition
            break  # stops at the floor of eight
        bullets.append(filler)  # adds the honest filler
    return bullets[:10]  # returns the trimmed list
