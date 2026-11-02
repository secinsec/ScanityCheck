"""Tests for the Recommendations ranker: themes, ordering and projections."""

from __future__ import annotations  # imports annotations from the __future__ module

import sys  # imports the sys module
import unittest  # imports the unittest module
from pathlib import Path  # imports the pathlib module

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # inserts the repo root

import config  # noqa: E402  # imports config
import recommendations  # noqa: E402  # imports recommendations
import scoring  # noqa: E402  # imports scoring


def all_status():
    return {tool: {"status": "ok"} for tool in config.ALL_TOOLS}  # all scanners ok


def sample_report():
    findings = [  # three heavy themes and a small one
        scoring.Finding("gitleaks", "secret", "high", "generic-api-key", "api key committed",
                        weight=10.0, file="a.py"),  # a heavy theme (10 rows)
        scoring.Finding("gitleaks", "secret", "high", "generic-api-key", "api key committed",
                        weight=10.0, file="b.py"),  # the same theme repeats
        scoring.Finding("trivy", "vulnerability", "critical", "CVE-1", "log4j RCE",
                        weight=12.0, package="log4j", cwe="CWE-502"),  # a theme worth 12
        scoring.Finding("codeql", "code", "high", "py/sql", "sql injection in handler",
                        weight=5.0, cwe="CWE-089", file="app.py", line=10),  # a code theme
        scoring.Finding("checkov", "misconfiguration", "low", "CKV_DOCKER_2", "HEALTHCHECK",
                        weight=0.2, file="Dockerfile"),  # a small theme
    ]  # closes the list build
    return scoring.build_report(findings, scanner_status=all_status())  # runs the build


class RecommendationTests(unittest.TestCase):  # the ranker tests class
    def setUp(self) -> None:  # builds the report once
        self.report = sample_report()  # runs the sample builder

    def test_list_is_capped_at_twenty_five(self) -> None:  # runs the cap test
        findings = [  # thirty distinct heavy themes
            scoring.Finding("trivy", "vulnerability", "high", f"CVE-{index}", f"vuln {index}",
                            weight=5.0, package=f"pkg-{index}")  # builds the theme row
            for index in range(30)  # walks thirty
        ]  # closes the list build
        report = scoring.build_report(findings, scanner_status=all_status())  # builds the report
        recs = recommendations.build_recommendations(report)  # runs the ranker
        self.assertEqual(len(recs), 25)  # stopped at twenty-five
        self.assertTrue(all(not r["general"] for r in recs))  # all finding-backed
        self.assertEqual(recs[-1]["score_projection"], 92.5)  # 25 of the 30 shares walked
        self.assertGreaterEqual(recs[8]["impact"], recs[24]["impact"])  # early rows carry more points

    def test_fewer_themes_pad_with_general_rows(self) -> None:
        recs = recommendations.build_recommendations(self.report)  # runs the ranker
        specific = [r for r in recs if not r["general"]]  # finding-backed rows
        general = [r for r in recs if r["general"]]  # best-practice rows
        self.assertEqual(specific[0]["key"], "secret|generic-api-key")  # the heaviest theme tops
        self.assertEqual(specific[0]["instances"], 2)  # both api-key findings share the row
        self.assertGreaterEqual(specific[0]["impact"], specific[1]["impact"])  # descending impact
        self.assertTrue(all(r["impact"] >= 0 for r in recs))  # no negative hype
        # The fillers stop when the pool is exhausted: four themes plus the
        # eleven-item pool caps the list at fifteen, short of twenty-five.
        self.assertEqual(len(recs), 15)  # four finding rows + the filler pool
        self.assertEqual(len(general), 11)  # pool exhaustion is labeled honestly

    def test_projection_walks_toward_the_ceiling(self) -> None:
        recs = recommendations.build_recommendations(self.report)  # runs the ranker
        projections = [r["score_projection"] for r in recs if not r["general"]]  # the walked scores
        self.assertEqual(sorted(projections), projections)  # non-decreasing
        for projection in projections:  # walks the walk
            self.assertLessEqual(projection, 100)  # never past the ceiling
            self.assertGreaterEqual(projection, self.report["score"] - 1e-9)  # never below start

    def test_impact_matches_the_row_weights(self) -> None:
        recs = recommendations.build_recommendations(self.report)  # runs the ranker
        top = recs[0]  # the heaviest theme
        self.assertAlmostEqual(top["impact"], 20.0, places=1)  # 2 x 10 api-key rows
        self.assertEqual(top["category"], "secret")  # the category rides along
        self.assertEqual(top["worst"], "high")  # the worst rating rides along
        self.assertEqual(top["tools"], ["GitLeaks"])  # attribution stays usable

    def test_omitted_findings_leave_the_ranking(self) -> None:
        self.report["findings"][0]["omitted"] = True  # an api-key row taken out
        self.report["findings"][1]["omitted"] = True  # the whole theme gone
        recs = recommendations.build_recommendations(self.report)  # re-ranks
        keys = [r["key"] for r in recs if not r["general"]]  # the remaining keys
        self.assertNotIn("secret|generic-api-key", keys)  # the retired theme is gone
        specific = recs[0]  # the new number one
        self.assertEqual(specific["key"], "vulnerability|CVE-1")  # the critical theme tops

    def test_a_mega_theme_never_sterilises_the_list(self) -> None:
        heavy = scoring.Finding("secret", "secret", "high", "spam-key", "api keys everywhere",
                                weight=60.0, file="a.py")  # one theme far over the cap
        small = scoring.Finding("code", "code", "high", "py/sql", "sql injection",
                                weight=5.0, cwe="CWE-089", file="app.py", line=1)  # a small theme
        report = scoring.build_report([heavy, small], scanner_status=all_status())  # capped run
        recs = recommendations.build_recommendations(report)  # runs the ranker
        specific = [r for r in recs if not r["general"]]  # finding-backed rows
        self.assertEqual(len(specific), 2)  # both themes stay listed
        first, second = specific[0], specific[1]  # by impact
        self.assertEqual(first["key"], "secret|spam-key")  # the mega theme tops
        self.assertAlmostEqual(first["impact"], 25.0)  # pro-rata: cap times its raw share
        self.assertEqual(first["score_projection"], 95)  # the walked score after its fix
        self.assertEqual(second["impact"], 5.0)  # the unbound code theme still pays full value
        self.assertEqual(second["score_projection"], 100)  # the walk completes the ceiling
    def test_a_heavily_omitted_report_returns_only_fillers(self) -> None:  # the all-omitted case
        for finding in self.report["findings"]:  # omissions everywhere
            finding["omitted"] = True  # flags the whole scoring set
        recs = recommendations.build_recommendations(self.report)  # runs the ranker
        self.assertTrue(all(r["general"] for r in recs))  # only the safety blanket rows
        self.assertEqual(recs[0]["impact"], 0.0)  # no phantom points

    def test_placeholder_for_clean_reports(self) -> None:
        report = scoring.build_report([], scanner_status=all_status())  # nothing found
        recs = recommendations.build_recommendations(report)  # runs the ranker
        self.assertTrue(recs)  # still guides the fixer
        self.assertTrue(all(r["general"] for r in recs))  # through general advice only


if __name__ == "__main__":  # runs the module
    unittest.main(verbosity=2)  # starts the runner
