"""Tests for reviewer omissions: ticking a risk row removes it from scoring."""

from __future__ import annotations  # imports annotations from the __future__ module

import sys  # imports the sys module
import unittest  # imports the unittest module
from pathlib import Path  # imports the pathlib module

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # inserts the repo root

import config  # noqa: E402  # imports config
import dashboard  # noqa: E402  # imports the dashboard module
import scoring  # noqa: E402  # imports the scoring module


def all_status():
    return {tool: {"status": "ok"} for tool in config.ALL_TOOLS}


def sample_findings():
    return [  # a critical vulnerability plus a code finding worth 5 points
        scoring.Finding(  # builds the Finding row
            "trivy", "vulnerability", "critical", "CVE-1", "log4j RCE",
            weight=scoring.weight_for("vulnerability", "critical"),  # 12.0
            package="log4j", cwe="CWE-502",  # sets the package text
        ),  # closes the row
        scoring.Finding(  # builds the Finding row
            "codeql", "code", "high", "py/sql", "sql injection in handler",
            weight=scoring.weight_for("code", "high"),  # 5.0
            cwe="CWE-089", file="app.py", line=10,  # sets the location
        ),  # closes the row
    ]  # closes the list build


class RescoreTests(unittest.TestCase):  # class RescoreTests
    def setUp(self) -> None:  # defines the setUp() function
        self.report = scoring.build_report(  # builds the report
            sample_findings(), scanner_status=all_status()  # runs the build_report() call
        )  # closes the report build
        self.base_score = self.report["score"]  # saves the untouched score

    def tearDown(self) -> None:  # defines the tearDown() function
        pass  # keeps the block syntactically empty

    def test_group_keys_are_present_and_sent_to_the_ui(self) -> None:
        keys = {risk["key"] for risk in self.report["greatest_risks"]}  # collects the keys
        self.assertEqual(len(keys), 2)  # one per distinct risk theme
        ids = [risk.get("omitted") for risk in self.report["greatest_risks"]]  # flags present
        self.assertTrue(all(flag is False or flag is True for flag in ids))  # explicit booleans

    def test_omitting_the_critical_lands_the_score_above_the_pass_mark(self) -> None:
        key = scoring.finding_group_key(self.report["findings"][0])  # the critical theme
        scoring.rescore_report(self.report, [key])  # excludes the critical theme
        self.assertGreater(self.report["score"], self.base_score)  # score rises
        self.assertEqual(self.report["score"], self.base_score + 12)  # freed by the cap
        self.assertEqual(self.report["verdict"], "SECURE")  # no critical remains counted
        self.assertIn("excluded from the score", self.report["verdict_reason"])  # honest verdict note
        self.assertEqual(self.report["totals"]["findings"], 1)  # only the code finding counts
        self.assertEqual(self.report["penalties"]["vulnerability"], 0.0)  # category emptied
        omitted_flags = {f["rule_id"]: f["omitted"] for f in self.report["findings"]}  # marker map
        self.assertEqual(omitted_flags, {"CVE-1": True, "py/sql": False})  # the flag rides each row

    def test_findings_keep_exact_penalty_after_full_omy_removal_cycle(self) -> None:
        key = scoring.finding_group_key(self.report["findings"][0])  # the critical theme
        scoring.rescore_report(self.report, [key])  # excludes it
        self.assertEqual(self.report["penalties"]["code"], 5.0)  # code penalty stays exact
        # Round-trip: removing the exclusion restores the original score.
        scoring.rescore_report(self.report, [])  # re-includes everything
        self.assertEqual(self.report["score"], self.base_score)  # back to the scan truth
        self.assertEqual(self.report["verdict_reason"].count("excluded"), 0)  # note dropped

    def test_omitted_finding_refunds_its_capped_share(self) -> None:
        # Two code findings of 30 points each: the cap binds at 40, so each
        # finding's EFFECTIVE charge is 20 (40 x 30/60). Excluding one refunds
        # that share - not the raw headline weight - and the score change is
        # tied to the risk's real charged value.
        heavy = scoring.Finding(  # builds the Finding row
            "codeql", "code", "high", "py/inject1", "injection one",
            weight=30.0, cwe="CWE-089", file="a.py", line=1,  # sets the weights
        )  # closes the row
        heavy2 = scoring.Finding(  # builds the Finding row
            "semgrep", "code", "high", "py/inject2", "injection two",
            weight=30.0, cwe="CWE-089", file="b.py", line=2,  # sets the weights
        )  # closes the row
        report = scoring.build_report([heavy, heavy2], scanner_status=all_status())  # capped run
        self.assertEqual(report["score"], 60)  # 100 - the 40 cap
        scoring.rescore_report(report, ["code|py/inject1"])  # drops theme one
        self.assertEqual(report["penalties"]["code"], 20.0)  # cap 40 x the surviving 30/60 share
        self.assertEqual(report["score"], 80)  # +20: exactly the omitted theme's charge
        rows = {risk["key"]: risk for risk in report["greatest_risks"]}  # the visible rows
        self.assertFalse(rows["code|py/inject2"]["omitted"])  # the survivor stays listed
        self.assertAlmostEqual(rows["code|py/inject2"]["penalty"], 30.0)  # with its raw weight shown
        self.assertAlmostEqual(rows["code|py/inject1"]["refund"], 20.0)  # the credited share

    def test_refunds_scale_with_the_omitted_risk_value(self) -> None:
        # Three secret themes of different sizes against a binding cap: the
        # score deltas must be PROPORTIONAL to each theme's raw weight, the
        # exact complaint reported by the user (one delta for everything).
        secrets = [  # three differently-sized secret themes
            scoring.Finding("gitleaks", "secret", "high", "big-leak", "big leak",
                            weight=30.0, file="a.py"),  # the heavy theme
            scoring.Finding("gitleaks", "secret", "high", "mid-leak", "mid leak",
                            weight=20.0, file="b.py"),  # the medium theme
            scoring.Finding("gitleaks", "secret", "high", "small-leak", "small leak",
                            weight=10.0, file="c.py"),  # the light theme
        ]  # closes the list build
        report = scoring.build_report(secrets, scanner_status=all_status())  # capped run
        self.assertEqual(report["penalties"]["secret"], 25.0)  # raw 60, cap 25  # asserts the cap
        scoring.rescore_report(report, ["secret|big-leak"])  # omits the heavy theme
        delta_heavy = report["score"] - 75  # the points returned
        fresh_mid = scoring.build_report(secrets, scanner_status=all_status())  # fresh copy
        scoring.rescore_report(fresh_mid, ["secret|mid-leak"])  # omits the medium theme
        delta_mid = fresh_mid["score"] - 75  # the points returned
        fresh_small = scoring.build_report(secrets, scanner_status=all_status())  # fresh copy
        scoring.rescore_report(fresh_small, ["secret|small-leak"])  # omits the light theme
        delta_small = fresh_small["score"] - 75  # the points returned
        self.assertAlmostEqual(delta_heavy / delta_mid, 1.5, delta=0.25)  # ~30 vs ~20 (rounding drift)
        self.assertAlmostEqual(delta_heavy / delta_small, 3.0, delta=0.35)  # ~30 vs ~10

    def test_refund_never_drives_a_category_below_zero(self) -> None:
        # Three 20-point secrets against a 25-point cap: the cap binds. Two
        # omissions refund their pro-rata share (25 x 40/60 = 16.67), leaving
        # the survivor's share charged; omitting all three refunds everything.
        secrets = [  # three heavy secret rows
            scoring.Finding("gitleaks", "secret", "high", f"leak-{index}", f"aws key {index}",
                            weight=20.0, file=f"f{index}.py")  # builds the secret row
            for index in range(3)  # walks the trio
        ]  # closes the list build
        report = scoring.build_report(secrets, scanner_status=all_status())  # capped run
        self.assertEqual(report["penalties"]["secret"], 25.0)  # cap applied
        scoring.rescore_report(report, ["secret|leak-0", "secret|leak-1"])  # drops two themes
        self.assertAlmostEqual(report["penalties"]["secret"], 8.33, places=2)  # the last 20-point share
        self.assertEqual(report["score"], 92)  # rounded from the pro-rata write
        scoring.rescore_report(report, ["secret|leak-0", "secret|leak-1", "secret|leak-2"])  # drops all
        self.assertEqual(report["penalties"]["secret"], 0.0)  # clamped at the floor
        self.assertEqual(report["score"], 100)  # the whole category is refunded

    def test_omitted_risks_stay_listed_and_flagged(self) -> None:
        key = scoring.finding_group_key(self.report["findings"][0])  # the critical theme
        scoring.rescore_report(self.report, [key])  # excludes it
        rows = {risk["key"]: risk for risk in self.report["greatest_risks"]}  # the visible rows
        self.assertIn(key, rows)  # the omitted row stays visible
        self.assertTrue(rows[key]["omitted"])  # flagged for the UI checkbox
        self.assertAlmostEqual(rows[key]["penalty"], 12.0)  # its raw weight still reads

    def test_dashboard_counts_follow_the_scoring_set(self) -> None:
        key = scoring.finding_group_key(self.report["findings"][0])  # the critical theme
        scoring.rescore_report(self.report, [key])  # excludes it
        payloads = dashboard.collect_metrics(  # rebuilds the widgets
            self.report, ["severity_counts", "total_vulnerabilities"]  # picks two metrics
        )  # closes the rebuild call
        labels = {label: value for label, value, _c in payloads["severity_counts"].get("rows", [])}  # bar map
        self.assertNotIn("CRITICAL", labels)  # the omitted critical left the chart
        self.assertEqual(payloads["total_vulnerabilities"]["value"], 0)  # vulnerabilities dropped

    def test_rescore_never_runs_without_effects_on_show_panes(self) -> None:
        # The report dict stays the same object so app-side references remain valid.
        key = "vulnerability|CVE-1"  # a hand-built key
        before = id(self.report)  # the object identity
        scoring.rescore_report(self.report, [key])  # rescore in place
        self.assertEqual(id(self.report), before)  # same object: the UI keeps it


if __name__ == "__main__":  # runs the module
    unittest.main(verbosity=2)  # starts the runner
