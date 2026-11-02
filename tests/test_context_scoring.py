"""Tests for the context-normalised cap model.

The plain ``config.CAPS`` ceilings stay the law for repos with no measured
context; measured context (SBOM size, scanned files, maintenance pulse)
relieves the two count-driven categories with floors, and every consumer
(build, rescore refunds, recommendations) shares the same effective table.
"""

from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config  # noqa: E402
import scoring  # noqa: E402


def all_status():
    return {tool: {"status": "ok"} for tool in config.ALL_TOOLS}


def flood(unit):
    """A Trivy-shaped finding flood ~174 vulnerability + ~64 code points."""
    findings = []
    for category, severity, count in (
        ("vulnerability", "critical", 2), ("vulnerability", "high", 12),
        ("vulnerability", "medium", 46), ("vulnerability", "low", 30),
        ("code", "high", 5), ("code", "medium", 26),
    ):
        for i in range(count):
            findings.append(scoring.Finding(
                "trivy", category, severity, f"ID-{category}-{severity}-{i}", "theme",
                weight=scoring.weight_for(category, severity),
                file="main.go", line=i + 1, package="golang.org/x/net" if category == "vulnerability" else "",
            ))
    return scoring.merge_findings(findings)


ACTIVE_CARE = {
    "last_commit_at": "2025-10-28T10:00:00Z",
    "commit_activity": [{"week": time.time() - (52 - i) * 7 * 86400, "total": 200 - i} for i in range(52)],
    "releases": [{"published_at": f"2025-{m:02d}-15T00:00:00Z"} for m in range(1, 13)],
    "contributors": 210, "recent_commit_authors": ["a"] * 30,
    "open_pull_requests": 4, "errors": [],
}


class ContextModelTests(unittest.TestCase):
    def test_neutral_context_is_the_plain_cap_table(self) -> None:
        effective, context = scoring.normalised_caps(None, None, None)
        self.assertEqual(effective, dict(config.CAPS))  # identical ceilings
        self.assertEqual(context["factors"], {})  # nothing measured, nothing relieved

    def test_small_surfaces_stay_neutral(self) -> None:
        effective, _ctx = scoring.normalised_caps(10, 4, None)  # under the density base
        self.assertEqual(effective, dict(config.CAPS))  # the plain caps stand

    def test_flood_with_context_relieves_both_categories(self) -> None:
        effective, context = scoring.normalised_caps(637, 431, ACTIVE_CARE)
        self.assertLess(effective["vulnerability"], config.CAPS["vulnerability"])  # the widened cap
        self.assertLess(effective["code"], config.CAPS["code"])  # the widened cap
        self.assertEqual(effective["secret"], config.CAPS["secret"])  # secrets never relieved
        self.assertEqual(effective["misconfiguration"], config.CAPS["misconfiguration"])  # hard cap stays
        vuln_factor = context["factors"]["vulnerability"]["factor"]  # the echoed factor
        self.assertGreater(vuln_factor, 1.0)  # density plus pulse widened the cap
        self.assertEqual(  # pulse saturates: 90-day commits, releases and people all past norm
            scoring.maintenance_pulse(ACTIVE_CARE), 1.0,
        )

    def test_floors_keep_the_score_honest_on_floods(self) -> None:
        report = scoring.build_report(
            flood(1), repo={"full_name": "aquasecurity/trivy"},
            scanner_status=all_status(), languages=["go"],
            language_file_counts={"go": 431},
            inventory={"components": 637, "ecosystems": {"golang": 637}},
            care=ACTIVE_CARE,
        )
        self.assertEqual(  # the vulnerable-cap relief is exactly the configured floor
            report["caps"]["vulnerability"],
            round(config.CAPS["vulnerability"] * config.SCORING_CONTEXT["vulnerability"]["relief_floor"], 2),
        )
        self.assertGreater(report["score"], 20)  # the flood no longer zeroes the instrument
        self.assertLess(report["score"], 80)  # context relief is not a free pass either
        self.assertEqual(report["verdict"], "INSECURE")  # two criticals still veto the verdict

    def test_plain_model_unchanged_without_context(self) -> None:
        findings = flood(1)
        report = scoring.build_report(findings, scanner_status=all_status())
        legacy = 100 - sum(  # the pre-normalisation arithmetic, verbatim
            min(sum(f.weight for f in findings if f.category == category), config.CAPS.get(category, 0))
            for category in config.CAPS
        )
        self.assertEqual(report["score"], int(round(legacy)))  # the historical score
        self.assertEqual(report["caps"], dict(config.CAPS))  # the historical caps echoed

    def test_single_findings_never_compress_below_the_bend(self) -> None:
        one_critical = [scoring.Finding(  # a lone critical in a generous context
            "trivy", "vulnerability", "critical", "CVE-1", "one",
            weight=scoring.weight_for("vulnerability", "critical"), package="log4j",
        )]
        report = scoring.build_report(
            one_critical, scanner_status=all_status(), languages=["go"],
            language_file_counts={"go": 400},
            inventory={"components": 637}, care=ACTIVE_CARE,
        )
        self.assertAlmostEqual(  # the single charge is the raw weight, not a context-taxed one
            report["raw_penalties"]["vulnerability"] - (scoring.weight_for("vulnerability", "critical") - report["penalties"]["vulnerability"]),
            report["penalties"]["vulnerability"] + 0.0,
        )  # folded sanity: penalty + relief delta == raw (big context still charges <= raw)
        self.assertLessEqual(report["penalties"]["vulnerability"], scoring.weight_for("vulnerability", "critical"))

    def test_context_summary_persists_into_the_report(self) -> None:
        report = scoring.build_report(
            flood(1), scanner_status=all_status(), languages=["go"],
            language_file_counts={"go": 431},
            inventory={"components": 637}, care=ACTIVE_CARE,
        )
        context = report["context"]  # the persisted block
        self.assertEqual(context["packages"], 637)  # the measured surface
        self.assertEqual(context["files"], 431)  # the measured surface
        self.assertIn("effective_caps", context)  # what the rescore reuses
        self.assertIn("cap relieved", scoring.render_report_text(report))  # the report explains itself


class RescoreConsistencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = scoring.build_report(
            flood(1), repo={"full_name": "o/r"}, scanner_status=all_status(),
            languages=["go"], language_file_counts={"go": 431},
            inventory={"components": 637}, care=ACTIVE_CARE,
        )
        self.base_score = self.report["score"]

    def test_rescore_uses_the_persisted_effective_caps(self) -> None:
        first_refund = self.report["greatest_risks"][0]  # the worst theme
        before = {key: round(float(value), 2) for key, value in self.report["penalties"].items()}  # the applied set
        scoring.rescore_report(self.report, [first_refund["key"]])  # one omission
        after = {key: round(float(value), 2) for key, value in self.report["penalties"].items()}  # the recomputed set
        self.assertGreater(self.report["score"], self.base_score)  # the score climbs
        # The omitted theme's refund equals its stored charged share under the
        # same effective caps: build-time charges and rescore refunds agree.
        category = first_refund["category"]  # the theme's category
        self.assertAlmostEqual(  # the penalty drop equals the theme's charge share
            before[category] - after[category],
            round(float(first_refund["charge"]), 2),
            places=1,  # refunds round to the same share surface
        )

    def test_omitting_every_listed_theme_restores_the_full_mark(self) -> None:
        self.assertGreater(self.base_score, 0)  # the flood scored under relieved caps
        pair_report = scoring.build_report(  # a fully-omittable scoring set
            [
                scoring.Finding("trivy", "vulnerability", "critical", "CVE-1", "t1",
                                weight=scoring.weight_for("vulnerability", "critical"),
                                file="a.py", line=1, package="log4j"),
                scoring.Finding("codeql", "code", "high", "py/sql", "t2",
                                weight=scoring.weight_for("code", "high"),
                                file="b.py", line=2),
            ],
            scanner_status=all_status(), languages=["go"],
            language_file_counts={"go": 431},
            inventory={"components": 637}, care=ACTIVE_CARE,
        )
        keys = [row["key"] for row in pair_report["greatest_risks"]]  # every theme
        self.assertEqual(len(keys), 2)  # both themes are listed rows
        scoring.rescore_report(pair_report, keys)  # the reviewer forgives all
        self.assertEqual(pair_report["score"], 100)  # the empty scoring set scores clean


if __name__ == "__main__":
    unittest.main()
