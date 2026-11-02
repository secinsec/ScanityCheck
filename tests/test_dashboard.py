"""Tests for the selectable dashboard: payloads, kinds, PDF/ASCII rendering.

Synthetic findings cover the engine-supplied signals (CVSS, EPSS, CISA KEV,
publication dates) added for the dashboard, plus the repo-file inputs
(collected from a tiny npm lockfile) for containers/depth/deprecated.

"""
from __future__ import annotations

import json
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config  # noqa: E402
import dashboard  # noqa: E402
import exports  # noqa: E402
import scoring  # noqa: E402
import scanners  # noqa: E402


def finding(
    source, category, severity, rule_id, title, file, line,
    *, package="", cwe="", kind="", cvss=0.0, epss=0.0, kev=False, published="",
):
    return scoring.Finding(
        source, category, severity, rule_id, title,
        location=f"{file}:{line}",
        weight=scoring.weight_for(category, severity),
        file=file, line=line, package=package, cwe=cwe, kind=kind,
        cvss=cvss, epss=epss, kev=kev, published=published,
    )


def all_status():
    return {tool: {"status": "ok"} for tool in config.ALL_TOOLS}


def sample_findings():
    return [
        finding("trivy", "vulnerability", "critical", "CVE-2021-3121", "react CVE",
                "package-lock.json", 1, package="react", cwe="CWE-79",
                cvss=9.1, kev=True, published="2021-01-01"),
        finding("grype", "vulnerability", "high", "CVE-2020-7753", "typo CVE",
                "requirements.txt", 1, package="django", cwe="CWE-502",
                cvss=7.5, epss=0.42, published="2020-10-01"),
        finding("osv", "vulnerability", "medium", "GHSA-1234", "osv CVE",
                "app/main.py", 20, cwe="CWE-89", published="2019-02-02"),
        finding("gitleaks", "secret", "critical", "aws key", "AWS key",
                "app/settings.py", 4, kind="aws"),
        finding("checkov", "misconfiguration", "unknown", "CKV_DOCKER_2", "HEALTHCHECK",
                "Dockerfile", 1),
    ]


def shutil_report(tmp: Path) -> dict:
    report = scoring.build_report(
        sample_findings(),
        repo={"full_name": "o/r"},
        scanner_status=all_status(),
        languages=["python", "javascript"],
        language_file_counts={"python": 4, "javascript": 2},
        dashboard_inputs={"containers": 2, "api_specs": ["api/openapi.json"],
                          "dep_tree_depth": 5, "deprecated": ["fsevents"]},
    )
    report["language_file_counts"] = {"python": 4, "javascript": 2}
    return report


class ValidationTests(unittest.TestCase):
    def test_every_requested_metric_exists(self) -> None:
        required = (
            "total_vulnerabilities", "severity_counts", "by_cwe", "by_scanner",
            "by_language", "top_files", "cvss_scores", "epss_scores", "kev_status",
            "oldest_10", "languages_detected", "ownership_changes", "secrets_total",
            "recurring_types", "containers_count", "dep_tree_depth",
            "deprecated_packages", "api_listing", "heat_map", "internet_exposure",
        )
        for key in required:
            self.assertIn(key, config.DASHBOARD_METRICS)

    def test_validate_keeps_order_and_drops_unknowns(self) -> None:
        chosen = dashboard.validate(["heat_map", "bogus", "kev_status", "kev_status"])
        order = [k for k in ("kev_status", "heat_map")]
        self.assertEqual(chosen, order)
        self.assertEqual(dashboard.validate(None), [])


class PayloadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.report = shutil_report(self.dir)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_empty_selection_means_no_dashboard(self) -> None:
        report = scoring.build_report([], scanner_status=all_status())
        self.assertEqual(report["dashboard"], {})
        self.assertEqual(report["dashboard_selection"], [])
        self.assertEqual(dashboard.render_text({}), [])

    def test_selection_builds_payloads_with_each_kind(self) -> None:
        selection = config.DASHBOARD_ALL
        report = scoring.build_report(
            sample_findings(), scanner_status=all_status(), dashboard=selection,
            dashboard_inputs={"containers": 2, "api_specs": ["openapi.json"],
                              "dep_tree_depth": 4, "deprecated": []},
        )
        payloads = report["dashboard"]
        for key in selection:
            self.assertIn(key, payloads)
        self.assertEqual(payloads["total_vulnerabilities"]["kind"], "number")
        self.assertEqual(payloads["total_vulnerabilities"]["value"], 3)
        self.assertEqual(payloads["secrets_total"]["value"], 1)
        self.assertEqual(payloads["severity_counts"]["kind"], "bar")
        top_cwe = payloads["by_cwe"]["rows"][0][0]
        self.assertEqual(top_cwe, "CWE-79")
        bars_by_scanner = dict(
            (label, value) for label, value, _c in payloads["by_scanner"]["rows"]
        )
        self.assertEqual(bars_by_scanner.get("Trivy"), 1)
        self.assertEqual(payloads["kev_status"]["kind"], "number")
        self.assertEqual(payloads["kev_status"]["value"], 1)
        oldest = payloads["oldest_10"]["rows"]
        self.assertEqual(oldest[0][1], "2019-02-02")
        self.assertEqual(payloads["containers_count"]["value"], 2)
        self.assertEqual(payloads["dep_tree_depth"]["value"], 4)
        self.assertEqual(payloads["heat_map"]["kind"], "heat")
        self.assertTrue(payloads["heat_map"]["rows"])
        self.assertEqual(payloads["api_listing"]["rows"][0][0], "openapi.json")
        self.assertEqual(payloads["languages_detected"]["kind"], "donut")

    def test_notifier_metrics_present_honest_placeholders(self) -> None:
        payloads = dashboard.collect_metrics(
            {**self.report, "dashboard_inputs": {}},
            ["ownership_changes", "internet_exposure"],
        )
        self.assertEqual(payloads["ownership_changes"]["kind"], "na")
        self.assertEqual(payloads["internet_exposure"]["kind"], "na")

    def test_render_text_contains_selected_widgets_only(self) -> None:
        payloads = dashboard.collect_metrics(self.report, ["total_vulnerabilities", "kev_status"])
        lines = dashboard.render_text(payloads)
        joined = "\n".join(lines)
        self.assertIn("TOTAL VULNERABILITIES", joined)
        self.assertIn("CISA KEV STATUS", joined)
        payloads_all = dashboard.collect_metrics(self.report, config.DASHBOARD_ALL)
        joined_all = "\n".join(dashboard.render_text(payloads_all))
        self.assertIn("RISK HEAT MAP", joined_all)
        self.assertIn("VULNERABILITIES BY SCANNER", joined_all)


class RepoInputsTests(unittest.TestCase):
    def test_collect_repo_inputs_reads_lockfile_and_containers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Dockerfile").write_text("FROM scratch\n")
            (root / "api" ).mkdir()
            (root / "api" / "openapi.json").write_text('{"openapi": "3.0.0"}')
            (root / "package-lock.json").write_text(json.dumps({
                "packages": {
                    "": {"dependencies": {"a": "1"}},
                    "node_modules/a": {"dependencies": {"b": "2"}},
                    "node_modules/b": {"deprecated": "yes", "name": "b"},
                    "node_modules/c": {},
                }
            }))
            inputs = dashboard.collect_repo_inputs(root)
        self.assertEqual(inputs["containers"], 1)
        self.assertEqual(inputs["api_specs"], ["api/openapi.json"])
        self.assertEqual(inputs["dep_tree_depth"], 1)  # a -> b
        self.assertEqual(inputs["deprecated"], ["b"])

    def test_cycle_in_lockfile_does_not_hang(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package-lock.json").write_text(json.dumps({
                "packages": {
                    "node_modules/a": {"dependencies": {"b": "1"}},
                    "node_modules/b": {"dependencies": {"a": "1"}},
                }
            }))
            inputs = dashboard.collect_repo_inputs(root)
        self.assertEqual(inputs["dep_tree_depth"], 1)  # a -> b, cycle cut

    def test_missing_lockfile_is_safe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            inputs = dashboard.collect_repo_inputs(Path(tmp))
        self.assertIsNone(inputs["dep_tree_depth"])
        self.assertEqual(inputs["deprecated"], [])


class GitHistoryWidgetTests(unittest.TestCase):
    """The four Git-history value widgets fed by the Care-and-Feeding blob."""

    CARE = {
        "last_commit_days": 3.0,
        "commits_last_90d": 120,
        "commits_last_year": 640,
        "contributors": 7,
        "contributors_recent": 4,
    }

    def quarter_history(self, weeks: list[int]) -> list[dict]:
        """Weekly commit_activity items, oldest first, matching GitHub's shape."""
        now = time.time()
        return [
            {"week": now - (51 - index) * 7 * 86400, "total": value}
            for index, value in enumerate(weeks)
        ]

    def test_active_and_dormant_classification(self) -> None:
        active = dashboard.collect_metrics(
            {"care": self.CARE, "repo": {"archived": False}},
            ["repo_activity_ratio"],
        )["repo_activity_ratio"]
        self.assertEqual(active["kind"], "number")
        self.assertEqual(active["value"], "Active")
        self.assertEqual(active["colour"], "#22c55e")

        dormant = dashboard.collect_metrics(
            {"care": {**self.CARE, "commits_last_90d": 0, "last_commit_days": 400.0},
             "repo": {"archived": True}},
            ["repo_activity_ratio"],
        )["repo_activity_ratio"]
        self.assertEqual(dormant["value"], "Dormant")
        self.assertEqual(dormant["colour"], "#f87171")

    def test_activity_widget_is_honest_without_care_data(self) -> None:
        payload = dashboard.collect_metrics({}, ["repo_activity_ratio"])["repo_activity_ratio"]
        self.assertEqual(payload["kind"], "na")

    def test_churn_index_multiplies_activity_size_people(self) -> None:
        report = {
            "care": self.CARE,
            "language_file_counts": {"python": 4, "javascript": 2},
        }
        payload = dashboard.collect_metrics(report, ["churn_value_index"])["churn_value_index"]
        self.assertEqual(payload["kind"], "number")
        self.assertEqual(payload["value"], 120 * 6 * 7)
        self.assertIn("120 commits", payload["caption"])

    def test_churn_index_honest_when_nothing_scanned(self) -> None:
        payload = dashboard.collect_metrics({"care": self.CARE}, ["churn_value_index"])
        self.assertEqual(payload["churn_value_index"]["kind"], "na")

    def test_quarter_curve_is_chronological_with_newest_labelled(self) -> None:
        report = {"care_raw": {"commit_activity": self.quarter_history(
            [10] * 13 + [12] * 13 + [15] * 13 + [18] * 13,
        )}}
        payload = dashboard.collect_metrics(report, ["authored_volume_trend"])["authored_volume_trend"]
        self.assertEqual(payload["kind"], "bar")
        self.assertEqual([label for label, _v, _c in payload["rows"]],
                         ["Q1 (oldest)", "Q2", "Q3", "Q4 (newest)"])
        self.assertEqual([value for _l, value, _c in payload["rows"]], [130, 156, 195, 234])
        self.assertIn("33%", payload["note"])  # 234 of 715 commits

    def test_trend_widget_is_honest_without_weeks(self) -> None:
        payload = dashboard.collect_metrics({}, ["authored_volume_trend"])["authored_volume_trend"]
        self.assertEqual(payload["kind"], "na")

    def test_hotspot_share_flags_concentration(self) -> None:
        report = {"findings": [
            {"file": "hot1.py"}, {"file": "hot1.py"}, {"file": "hot1.py"},
            {"file": "hot2.py"}, {"file": "hot2.py"}, {"file": "hot2.py"},
            {"file": "hot3.py"}, {"file": "hot3.py"},
            {"file": "wide.py"}, {"file": "edge.py"},
        ]}
        payload = dashboard.collect_metrics(report, ["cost_of_change_proxy"])["cost_of_change_proxy"]
        self.assertEqual(payload["kind"], "donut")
        rows = dict((label, value) for label, value, _c in payload["rows"])
        self.assertEqual(rows["Top 3 hotspots"], 80)  # 8 of 10 findings
        self.assertEqual(rows["Everything else"], 20)
        self.assertIn("concentrated", payload["note"])

    def test_hotspot_widget_honest_when_clean(self) -> None:
        payload = dashboard.collect_metrics({}, ["cost_of_change_proxy"])["cost_of_change_proxy"]
        self.assertEqual(payload["kind"], "na")


class EngineSignalTests(unittest.TestCase):
    def test_merge_keeps_strongest_cvss_and_kev(self) -> None:
        merged = scoring.merge_findings([
            finding("trivy", "vulnerability", "high", "CVE-2020-7753", "django",
                    "requirements.txt", 1, package="django", cvss=7.5),
            finding("grype", "vulnerability", "high", "CVE-2020-7753", "django",
                    "requirements.txt", 1, package="django", cvss=9.0,
                    epss=0.5, kev=True, published="2020-10-01"),
        ])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].cvss, 9.0)
        self.assertEqual(merged[0].epss, 0.5)
        self.assertTrue(merged[0].kev)
        self.assertEqual(merged[0].published, "2020-10-01")

    def test_trivy_parser_reads_cvss_and_cwe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trivy.json"
            path.write_text(json.dumps({"Results": [{
                "Target": "package-lock.json",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2021-3121",
                    "PkgName": "react",
                    "InstalledVersion": "16.0.0",
                    "Severity": "CRITICAL",
                    "CVSS": {"nvd": {"V3Score": 9.8}},
                    "CweIDs": ["CWE-79"],
                    "Title": "stego impact",
                }],
            }]}))
            findings = scoring.parse_trivy_report(path)
        self.assertEqual(findings[0].cvss, 9.8)
        self.assertEqual(findings[0].cwe, "CWE-79")

    def test_grype_parser_reads_kev_epss_and_dates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "grype.json"
            path.write_text(json.dumps({"matches": [{
                "artifact": {"name": "django", "version": "3.0"},
                "vulnerability": {
                    "id": "CVE-2020-7753",
                    "severity": "high",
                    "cvss": [{"version": "3.x", "metrics": {"baseScore": 8.2}}],
                    "epss": [{"cve": "CVE-2020-7753", "score": 0.31}],
                    "known_exploited": True,
                    "published": "2020-10-01T00:00:00Z",
                    "cwes": [{"cwe": "CWE-79"}],
                },
            }]}))
            findings = scoring.parse_grype_report(path)
        self.assertEqual(findings[0].cvss, 8.2)
        self.assertAlmostEqual(findings[0].epss, 0.31)
        self.assertTrue(findings[0].kev)
        self.assertEqual(findings[0].published, "2020-10-01T00:00:00Z")
        self.assertEqual(findings[0].cwe, "CWE-79")


class ExportRenderingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.report = scoring.build_report(
            sample_findings(), scanner_status=all_status(),
            dashboard=config.DASHBOARD_ALL,
            dashboard_inputs={"containers": 2, "api_specs": ["openapi.json"],
                              "dep_tree_depth": 4, "deprecated": ["fsevents"]},
        )
        self.report["language_file_counts"] = {"python": 4, "javascript": 2}

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_report_text_has_dashboard_section(self) -> None:
        text = scoring.render_report_text(self.report)
        self.assertIn("DASHBOARD (selected metrics)", text)
        self.assertIn("TOTAL VULNERABILITIES:", text)
        self.assertIn("RISK HEAT MAP:", text)
        self.assertIn("PACKAGES THAT CHANGED OWNERSHIP:", text)
        self.assertIn("not assessable", text)

    def test_pdf_draws_dashboard_graphics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.pdf"
            exports.write_report_pdf(self.report, path)
            raw = path.read_bytes()
        # the writer escapes ( and ) inside text runs
        text = raw.replace(b"\\(", b"(").replace(b"\\)", b")")
        self.assertIn(b"DASHBOARD (selected metrics)", text)
        # bars, heat cells and the number card are filled rectangles
        self.assertGreaterEqual(len(re.findall(rb" re f", raw)), 12)
        self.assertIn(b"TOTAL VULNERABILITIES", text)
        self.assertIn(b"CISA KEV STATUS", text)
        self.assertIn(b"RISK HEAT MAP", text)

    def test_pdf_without_dashboard_selection_has_no_section(self) -> None:
        plain = scoring.build_report(sample_findings(), scanner_status=all_status())
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "plain.pdf"
            exports.write_report_pdf(plain, path)
            raw = path.read_bytes()
        self.assertNotIn(b"DASHBOARD (selected metrics)", raw)

class ExplainerTests(unittest.TestCase):
    """Every dashboard section carries its explainer sentence(s)."""

    def test_every_metric_has_an_explainer(self) -> None:
        for key in config.DASHBOARD_METRICS:  # walks the tickable set
            text = dashboard.METRIC_EXPLAINERS.get(key, "")
            self.assertLessEqual(2, len(text.split()), f"{key} lacks an explainer")
            self.assertLessEqual(len(text), 420, f"{key} explainer is too long for two sentences")


if __name__ == "__main__":
    unittest.main(verbosity=2)
