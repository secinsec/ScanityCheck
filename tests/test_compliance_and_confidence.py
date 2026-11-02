"""Tests for cross-tool dedupe stats, compliance mapping and the confidence gauge.

Nothing here needs a scanner: the samples mirror the shapes the parsers emit.
"""

from __future__ import annotations  # imports annotations from the __future__ module

import sys  # imports the sys module
import tempfile  # imports the tempfile module
import unittest  # imports the unittest module
from pathlib import Path  # imports Path from the pathlib module

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # inserts text or data

import compliance  # noqa: E402  # imports the compliance module
import config  # noqa: E402  # imports the config module
import exports  # noqa: E402  # imports the exports module
import scoring  # noqa: E402  # imports the scoring module


def finding(  # defines the finding() function
    source: str,  # evaluates the source expression
    category: str,  # evaluates the category expression
    severity: str,  # evaluates the severity expression
    rule_id: str,  # evaluates the rule_id expression
    title: str,  # evaluates the title expression
    file: str = "app/db.py",  # evaluates the file expression
    line: int = 1,  # evaluates the line expression
    package: str = "",  # evaluates the package expression
    cwe: str = "",  # evaluates the cwe expression
    kind: str = "",  # evaluates the kind expression
) -> scoring.Finding:  # closes the multiline block
    return scoring.Finding(  # returns the scoring.Finding to the caller
        source,  # evaluates the source expression
        category,  # evaluates the category expression
        severity,  # evaluates the severity expression
        rule_id,  # evaluates the rule_id expression
        title,  # evaluates the title expression
        location=f"{file}:{line}",  # sets the location text
        detail="demo detail",  # sets the detail text
        weight=scoring.weight_for(category, severity),  # runs the weight_for() call
        file=file,  # copies the file value into file
        line=line,  # copies the line value into line
        package=package,  # copies the package value into package
        cwe=cwe,  # copies the cwe value into cwe
        kind=kind,  # copies the kind value into kind
    )  # closes the multiline block


def all_status(state: str = "ok", *, skipped: tuple[str, ...] = ()) -> dict:  # defines the all_status() function
    return {  # returns the value to the caller
        tool: {"status": "skipped" if tool in skipped else state, "duration_seconds": 0}  # evaluates the tool expression
        for tool in config.ALL_TOOLS  # loops over the collection
    }  # closes the multiline block


class DedupeStatsTests(unittest.TestCase):  # defines the DedupeStatsTests class
    """Feature 1: duplicates across tools must exist only once in the score."""  # keeps the docstring text

    def test_same_cve_from_three_tools_is_charged_once_and_counted(self) -> None:  # defines the test_same_cve_from_three_tools_is_charged_once_and_counted() function
        dupes = [  # assigns the computed value to dupes
            finding(  # runs the finding() call
                tool, "vulnerability", "high", "CVE-2021-23337", "lodash RCE",  # evaluates the tool expression
                file="package-lock.json", package="lodash",  # sets the file text
            )  # closes the multiline block
            for tool in ("trivy", "grype", "osv")  # loops over the collection
        ]  # closes the multiline block
        report = scoring.build_report(dupes)  # runs the build_report() call

        self.assertEqual(report["dedupe"]["raw"], 3)  # runs the assertEqual() call
        self.assertEqual(report["dedupe"]["merged"], 1)  # runs the assertEqual() call
        self.assertEqual(report["dedupe"]["removed"], 2)  # runs the assertEqual() call
        self.assertEqual(report["dedupe"]["corroborated"], 1)  # runs the assertEqual() call
        self.assertEqual(report["totals"]["findings"], 1)  # runs the assertEqual() call
        # Three separate high-severity CVEs would each cost 6 points; merged it
        # costs once.
        self.assertAlmostEqual(report["penalties"]["vulnerability"], 6.0)  # runs the assertAlmostEqual() call

    def test_unrelated_findings_are_never_collapsed(self) -> None:  # defines the test_unrelated_findings_are_never_collapsed() function
        pair = [  # assigns the computed value to pair
            finding("gitleaks", "secret", "critical", "AWS", "aws key",  # runs the finding() call
                    file="app/x.py", line=10, kind="aws"),  # sets the file text
            finding("trivy", "secret", "medium", "CKV_SECRET_6", "entropy",  # runs the finding() call
                    file="app/x.py", line=10, kind="general"),  # sets the file text
        ]  # closes the multiline block
        report = scoring.build_report(pair)  # runs the build_report() call
        self.assertEqual(report["dedupe"]["merged"], 2)  # runs the assertEqual() call
        self.assertEqual(report["totals"]["findings"], 2)  # runs the assertEqual() call


class ComplianceMappingTests(unittest.TestCase):  # defines the ComplianceMappingTests class
    """Feature 2: findings mapped onto the controls of selected frameworks."""  # keeps the docstring text

    def test_all_requested_frameworks_exist(self) -> None:  # defines the test_all_requested_frameworks_exist() function
        for label in ("nist", "csf", "hipaa", "gdpr", "cmmc", "iso", "pci", "soc", "42001"):  # loops over the collection
            self.assertTrue(  # runs the assertTrue() call
                any(label in key for key in compliance.ALL_FRAMEWORKS),  # runs the any() call
                f"missing framework family {label}",  # supplies the literal text
            )  # closes the multiline block

    def test_iso42001_controls_map_by_theme(self) -> None:  # defines the test_iso42001_controls_map_by_theme() function
        findings = [  # assigns the computed value to findings
            finding("trivy", "vulnerability", "high", "CVE-2021-23337", "lodash injection",  # lifecycle misses
                    file="package-lock.json", package="lodash"),  # sets the file text
            finding("gitleaks", "secret", "critical", "gitleaks:aws", "AWS key committed",  # data handling
                    file="app.py", kind="aws"),  # sets the file text
            finding("guarddog", "vulnerability", "high", "install-scripts:eval", "malicious install script",  # supply chain
                    file="setup.py", kind="malicious"),  # sets the file text
            finding("checkov", "misconfiguration", "unknown", "CKV_DOCKER_9", "port exposed in image",  # infrastructure
                    file="Dockerfile"),  # sets the file text
        ]  # closes the multiline block
        mapped = compliance.map_findings(findings, ["iso-42001"])  # runs the map_findings() call
        entry = mapped["iso-42001"]  # copies the mapped value into entry
        ids = [control["id"] for control in entry["controls"]]  # collects the control ids
        self.assertEqual(len(ids), len(set(ids)))  # the two A.6 rows coalesce into one bucket
        affected = {c["id"] for c in entry["controls"] if c["status"] == "affected"}  # the touched set
        self.assertIn("A.6", affected)  # lifecycle validation catch vulnerabilities  # runs the assertIn() call
        self.assertIn("A.7", affected)  # data/PII catch secrets  # runs the assertIn() call
        self.assertIn("A.10", affected)  # third-party catch malware  # runs the assertIn() call
        self.assertIn("A.4", affected)  # infrastructure catch the Dockerfile check  # runs the assertIn() call
        self.assertNotIn("A.5", affected)  # code-impact keywords were absent  # runs the assertNotIn() call

    def test_every_categorized_finding_hits_a_control_per_framework(self) -> None:
        # The mapping must be complete for the categories each framework
        # actually governs: hipaa deliberately leaves code-quality chatter
        # unmapped (maintainability is not a PHI control) while every other
        # framework captures all five categories.
        findings = [  # one finding of every category, generic titles
            finding("trivy", "vulnerability", "high", "CVE-X", "some vuln"),  # the scoring-awkward set
            finding("gitleaks", "secret", "high", "leak", "committed credential"),  # the secret set
            finding("checkov", "misconfiguration", "unknown", "CKV_1", "risky default"),  # the config set
            finding("codeql", "code", "medium", "py/bad", "bad pattern", cwe="CWE-000"),  # the code set
            finding("semgrep", "code-quality", "low", "qc/dup", "duplicated block"),  # the quality set
        ]  # closes the findings list
        for framework_key in compliance.ALL_FRAMEWORKS:  # walks every framework
            mapped = compliance.map_findings(findings, [framework_key])  # maps each
            entry = mapped[framework_key]  # fetches the entry
            expect_one = framework_key == "hipaa"  # quality stays unmapped there
            reason = f"{framework_key}: expected{'' if expect_one else ' no'} code-quality unmapping"
            self.assertEqual(entry["unmapped"], 1 if expect_one else 0, reason)  # the coverage bar

    def test_scorecard_and_webcheck_families_now_map(self) -> None:
        # The robustness audit found these families falling through the
        # keyword nets - each must land on its framework's configuration
        # controls now.
        findings = [  # one finding per late-arriving rule family
            finding("semgrep", "misconfiguration", "unknown",
                    "dockerfile.security.missing-user-entrypoint.missing-user",  # the audit leak
                    "missing user entrypoint", file="Dockerfile"),  # sets the file text
            finding("scorecard", "misconfiguration", "low", "Pinned-Dependencies", "not pinned",  # scorecard
                    file=""),  # sets the file text
            finding("webcheck", "misconfiguration", "high", "plain-http", "no TLS",  # the web audit
                    kind="web.plain-http"),  # closes the finding row
        ]  # closes the findings list
        mapped = compliance.map_findings(findings, ["nist-rmf", "soc2", "iso"])  # maps the trio
        for key, entry in mapped.items():  # walks the frameworks
            self.assertEqual(entry["unmapped"], 0, f"{key} left findings unmapped")  # all land
        rmf = {c["id"] for c in mapped["nist-rmf"]["controls"] if c["status"] == "affected"}  # the affected set
        self.assertIn("CM-6", rmf)  # the entrypoint pairs with configuration  # asserts the id

    def test_sampling_is_validated_and_ignores_unknown(self) -> None:  # defines the test_sampling_is_validated_and_ignores_unknown() function
        chosen = compliance.normalize_frameworks(["PCI", " bogus ", "pci", "iso"])  # runs the normalize_frameworks() call
        # 'pci' spelled twice collapses, unknown IDs are dropped, order kept.
        self.assertEqual(chosen, ["pci", "iso"])  # runs the assertEqual() call
        self.assertEqual(compliance.normalize_frameworks(None), [])  # runs the assertEqual() call

    def test_findings_land_on_expected_controls(self) -> None:  # defines the test_findings_land_on_expected_controls() function
        findings = [  # assigns the computed value to findings
            finding("trivy", "vulnerability", "high", "CVE-2021-23337", "lodash injection",  # runs the finding() call
                    file="package-lock.json", package="lodash"),  # sets the file text
            finding("gitleaks", "secret", "critical", "gitleaks:aws", "AWS key committed",  # runs the finding() call
                    file="app.py", kind="aws"),  # sets the file text
            finding("checkov", "misconfiguration", "unknown", "CKV_DOCKER_4", "Use COPY not ADD",  # runs the finding() call
                    file="Dockerfile"),  # sets the file text
        ]  # closes the multiline block
        mapped = compliance.map_findings(findings, ["pci"])  # runs the map_findings() call

        entry = mapped["pci"]  # copies the mapped value into entry
        self.assertEqual(entry["unmapped"], 0)  # runs the assertEqual() call
        affected = {c["id"]: c for c in entry["controls"] if c["status"] == "affected"}  # assigns the computed value to affected
        self.assertIn("Req 6.3.x", affected)   # dependency CVE  # runs the assertIn() call
        self.assertIn("Req 8.x", affected)     # secret  # runs the assertIn() call
        self.assertIn("Req 2.2.x", affected)   # misconfiguration  # runs the assertIn() call
        self.assertNotIn("CC7.1", affected)    # framework filtering works  # runs the assertNotIn() call

    def test_control_marking_clear_when_no_finding_touches_it(self) -> None:  # defines the test_control_marking_clear_when_no_finding_touches_it() function
        mapped = compliance.map_findings(  # runs the map_findings() call
            [finding("codeql", "code", "high", "py/sql", "sql injection", cwe="CWE-089")],  # runs the finding() call
            ["iso"],  # executes the statement
        )  # closes the multiline block
        iso = mapped["iso"]  # copies the mapped value into iso
        # A code finding maps to secure-coding controls, not vulnerability mgmt.
        self.assertIn(("A.8.28", "affected"), [(c["id"], c["status"]) for c in iso["controls"]])  # runs the assertIn() call
        clear = {c["id"] for c in iso["controls"] if c["status"] == "clear"}  # assigns the computed value to clear
        self.assertIn("A.8.8", clear)  # runs the assertIn() call
        self.assertEqual(iso["affected_controls"], 1)  # runs the assertEqual() call

    def test_report_includes_mapping_only_for_selected_frameworks(self) -> None:  # defines the test_report_includes_mapping_only_for_selected_frameworks() function
        report = scoring.build_report(  # runs the build_report() call
            [finding("gitleaks", "secret", "high", "aws", "aws key", kind="aws")],  # runs the finding() call
            scanner_status=all_status(),  # runs the all_status() call
            frameworks=["hipaa", "soc2"],  # assigns the computed value to frameworks
        )  # closes the multiline block
        self.assertEqual(set(report["frameworks"]), {"hipaa", "soc2"})  # runs the assertEqual() call
        # Without a selection there is simply no compliance section.
        empty = scoring.build_report(  # runs the build_report() call
            [finding("gitleaks", "secret", "high", "aws", "aws key", kind="aws")],  # runs the finding() call
            scanner_status=all_status(),  # runs the all_status() call
        )  # closes the multiline block
        self.assertEqual(empty["frameworks"], {})  # runs the assertEqual() call


class ConfidenceTests(unittest.TestCase):  # defines the ConfidenceTests class
    """Feature 4: gauge for how much the report itself can be trusted."""  # keeps the docstring text

    def test_full_ok_run_scores_high(self) -> None:  # defines the test_full_ok_run_scores_high() function
        result = scoring.compute_confidence([], all_status())  # runs the compute_confidence() call
        self.assertGreaterEqual(result["score"], 80)  # runs the assertGreaterEqual() call
        self.assertEqual(result["band"], "High confidence")  # runs the assertEqual() call
        self.assertEqual(  # runs the assertEqual() call
            sum(factor["weight"] for factor in result["factors"]),  # runs the sum() call
            100,  # executes the statement
            "factor weights must add up to 100",  # supplies the literal text
        )  # closes the multiline block

    def test_failed_required_scanner_costs_more_than_optional(self) -> None:  # defines the test_failed_required_scanner_costs_more_than_optional() function
        base = scoring.compute_confidence([], all_status())  # runs the compute_confidence() call
        optional = scoring.compute_confidence(  # runs the compute_confidence() call
            [], {**all_status(), "semgrep": {"status": "error"}}  # runs the all_status() call
        )  # closes the multiline block
        required = scoring.compute_confidence([], {**all_status(), "trivy": {"status": "error"}})  # runs the compute_confidence() call
        self.assertLess(optional["score"], base["score"])  # runs the assertLess() call
        self.assertLess(required["score"], optional["score"])  # runs the assertLess() call

    def test_partial_run_scores_halfway_between_ok_and_error(self) -> None:  # defines the test_partial_run_scores_halfway_between_ok_and_error() function
        base = scoring.compute_confidence([], all_status())  # runs the compute_confidence() call
        partial = scoring.compute_confidence([], {**all_status(), "trivy": {"status": "partial"}})  # runs the compute_confidence() call
        error = scoring.compute_confidence([], {**all_status(), "trivy": {"status": "error"}})  # runs the compute_confidence() call
        # A partial run earned real results, so it must sit between a clean run
        # and a failed one - a partial of a required tool counts half its weight.
        self.assertGreater(partial["score"], error["score"])  # runs the assertGreater() call
        self.assertLess(partial["score"], base["score"])  # runs the assertLess() call
        self.assertGreater(  # runs the assertGreater() call
            next(f for f in partial["factors"] if f["key"] == "reliability")["score"],  # runs the next() call
            next(f for f in error["factors"] if f["key"] == "reliability")["score"],  # runs the next() call
        )  # closes the multiline block
        self.assertTrue(  # runs the assertTrue() call
            any("partial results" in note for note in partial["notes"]),  # runs the any() call
            f"the partial note should be visible; notes were: {partial['notes']}",  # evaluates the f expression
        )  # closes the multiline block
        self.assertTrue(  # runs the assertTrue() call
            any("failed" in note for note in error["notes"]),  # runs the any() call
            f"error notes should name the failure; notes were: {error['notes']}",  # evaluates the f expression
        )  # closes the multiline block

    def test_error_note_carries_the_reason(self) -> None:  # defines the test_error_note_carries_the_reason() function
        result = scoring.compute_confidence(  # runs the compute_confidence() call
            [],  # executes the statement
            {  # executes the statement
                "codeql": {  # maps the codeql dictionary entry
                    "status": "error",  # maps the status dictionary entry
                    "duration_seconds": 0,  # maps the duration_seconds dictionary entry
                    "details": [  # maps the details dictionary entry
                        "CodeQL could not build a database for go (exit 1)."  # supplies the literal text
                    ],  # closes the multiline block
                },  # closes the multiline block
                "trivy": {"status": "skipped"},  # maps the trivy dictionary entry
            },  # closes the multiline block
        )  # closes the multiline block
        self.assertTrue(  # runs the assertTrue() call
            any("CodeQL failed" in note and "go (exit 1)" in note for note in result["notes"]),  # runs the any() call
            f"notes were: {result['notes']}",  # evaluates the f expression
        )  # closes the multiline block

    def test_corroboration_lifts_confidence(self) -> None:  # defines the test_corroboration_lifts_confidence() function
        dupes = scoring.merge_findings(  # runs the merge_findings() call
            [  # executes the statement
                finding(tool, "vulnerability", "high", "CVE-2021-23337", "lodash RCE",  # runs the finding() call
                        package="lodash")  # sets the package text
                for tool in ("trivy", "grype", "osv")  # loops over the collection
            ]  # closes the multiline block
        )  # closes the multiline block
        solo = [finding("trivy", "vulnerability", "high", "CVE-2021-23337", "lodash RCE",  # runs the finding() call
                        package="lodash")]  # sets the package text
        self.assertTrue(all(len(f.tools) == 3 for f in dupes))  # runs the assertTrue() call
        self.assertEqual(len(solo[0].tools), 1)  # runs the assertEqual() call
        self.assertGreater(  # runs the assertGreater() call
            scoring.compute_confidence(dupes, all_status())["score"],  # runs the compute_confidence() call
            scoring.compute_confidence(solo, all_status())["score"],  # runs the compute_confidence() call
        )  # closes the multiline block

    def test_unknown_severities_drag_confidence_down(self) -> None:  # defines the test_unknown_severities_drag_confidence_down() function
        unknowns = [  # assigns the computed value to unknowns
            finding("checkov", "misconfiguration", "unknown", f"CKV_{index}", "cfg check")  # runs the finding() call
            for index in range(10)  # loops over the collection
        ]  # closes the multiline block
        clean = [  # assigns the computed value to clean
            finding("checkov", "misconfiguration", f"{lv}", f"CKV_{index}", "cfg check")  # runs the finding() call
            for index, lv in enumerate(("low", "low", "low", "low", "low", "low",  # loops over the collection
                                        "medium", "medium", "high", "high"))  # supplies the literal text
        ]  # closes the multiline block
        self.assertLess(  # runs the assertLess() call
            scoring.compute_confidence(unknowns, all_status())["score"],  # runs the compute_confidence() call
            scoring.compute_confidence(clean, all_status())["score"],  # runs the compute_confidence() call
        )  # closes the multiline block

    def test_without_any_scanner_confidence_is_zero(self) -> None:  # defines the test_without_any_scanner_confidence_is_zero() function
        result = scoring.compute_confidence([], {"trivy": {"status": "skipped"}})  # runs the compute_confidence() call
        self.assertEqual(result["score"], 0)  # runs the assertEqual() call
        self.assertEqual(result["band"], "No data")  # runs the assertEqual() call

    def test_report_carries_confidence_block(self) -> None:  # defines the test_report_carries_confidence_block() function
        report = scoring.build_report([], scanner_status=all_status())  # runs the build_report() call
        self.assertIn("confidence", report)  # runs the assertIn() call
        self.assertTrue(0 <= report["confidence"]["score"] <= 100)  # runs the assertTrue() call


class PieSliceTests(unittest.TestCase):  # defines the PieSliceTests class
    """Feature 3: severity breakdown wedges for the dashboard pie."""  # keeps the docstring text

    def test_slices_tile_a_full_circle(self) -> None:  # defines the test_slices_tile_a_full_circle() function
        slices = scoring.severity_pie_slices(  # runs the severity_pie_slices() call
            {"critical": 1, "high": 2, "medium": 3, "low": 2, "unknown": 2}  # executes the statement
        )  # closes the multiline block
        self.assertAlmostEqual(sum(slice[3] for slice in slices), 1.0)  # runs the assertAlmostEqual() call
        by_key = {slice[0]: slice for slice in slices}  # assigns the computed value to by_key
        self.assertAlmostEqual(by_key["high"][3], 2 / 10)  # runs the assertAlmostEqual() call
        self.assertIn("medium", by_key)  # runs the assertIn() call

    def test_counts_drop_zero_severities(self) -> None:  # defines the test_counts_drop_zero_severities() function
        slices = scoring.severity_pie_slices({"critical": 0, "high": 4, "medium": 0,  # runs the severity_pie_slices() call
                                             "low": 0, "unknown": 0})  # maps the low dictionary entry
        self.assertEqual([slice[0] for slice in slices], ["high"])  # runs the assertEqual() call

    def test_clean_repo_is_a_single_green_wedge(self) -> None:  # defines the test_clean_repo_is_a_single_green_wedge() function
        slices = scoring.severity_pie_slices({"critical": 0, "high": 0, "medium": 0,  # runs the severity_pie_slices() call
                                             "low": 0, "unknown": 0})  # maps the low dictionary entry
        self.assertEqual(slices, [("clean", 0, config.SEVERITY_COLOURS["clean"], 1.0)])  # runs the assertEqual() call


class ReportRenderingTests(unittest.TestCase):  # defines the ReportRenderingTests class
    def test_text_report_has_new_sections(self) -> None:  # defines the test_text_report_has_new_sections() function
        dupes = [  # assigns the computed value to dupes
            finding(tool, "vulnerability", "high", "CVE-2021-23337", "lodash RCE",  # runs the finding() call
                    package="lodash")  # sets the package text
            for tool in ("trivy", "grype", "osv")  # loops over the collection
        ]  # closes the multiline block
        report = scoring.build_report(dupes + [  # runs the build_report() call
            finding("gitleaks", "secret", "high", "aws", "aws key", kind="aws"),  # runs the finding() call
        ], scanner_status=all_status(), frameworks=["pci"])  # closes the multiline block
        text = scoring.render_report_text(report)  # runs the render_report_text() call
        self.assertIn("CONFIDENCE", text)  # runs the assertIn() call
        self.assertIn("DE-DUPLICATION", text)  # runs the assertIn() call
        self.assertIn("COMPLIANCE FRAMEWORK MAPPING", text)  # runs the assertIn() call
        self.assertIn("PCI DSS", text)  # runs the assertIn() call
        self.assertIn("Req 8.x", text)  # runs the assertIn() call

    def test_pdf_contains_confidence_and_compliance(self) -> None:  # defines the test_pdf_contains_confidence_and_compliance() function
        dupes = [  # assigns the computed value to dupes
            finding(tool, "vulnerability", "high", "CVE-2021-23337", "lodash RCE",  # runs the finding() call
                    package="lodash")  # sets the package text
            for tool in ("trivy", "grype", "osv")  # loops over the collection
        ]  # closes the multiline block
        report = scoring.build_report(dupes, scanner_status=all_status(),  # runs the build_report() call
                                      frameworks=["iso"])  # assigns the computed value to frameworks
        with tempfile.TemporaryDirectory() as tmp:  # opens the context for the block
            path = Path(tmp) / "report.pdf"  # creates the path object
            exports.write_report_pdf(report, path)  # runs the write_report_pdf() call
            raw = path.read_bytes()  # reads the file as raw bytes
        self.assertIn(b"CONFIDENCE IN THIS REPORT", raw)  # runs the assertIn() call
        self.assertIn(b"COMPLIANCE FRAMEWORK MAPPING", raw)  # runs the assertIn() call
        self.assertIn(b"A.8.8", raw)  # runs the assertIn() call
        self.assertIn(b"De-duplication", raw)  # runs the assertIn() call


class SettingsVersionTests(unittest.TestCase):  # defines the SettingsVersionTests class
    def test_version_bumped_for_framework_settings(self) -> None:  # defines the test_version_bumped_for_framework_settings() function
        self.assertGreaterEqual(config.SETTINGS_VERSION, 4)  # runs the assertGreaterEqual() call
        self.assertEqual(  # runs the assertEqual() call
            tuple(sorted(compliance.ALL_FRAMEWORKS)),  # runs the tuple() call
            tuple(sorted(compliance.FRAMEWORKS)),  # runs the tuple() call
        )  # closes the multiline block


if __name__ == "__main__":  # runs the module entry point
    unittest.main(verbosity=2)  # runs the main() call
