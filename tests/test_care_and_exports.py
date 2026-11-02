"""Tests for the white "Branding White" PDF artwork, compliance appearing in
the CSV export, and the "Care and Feeding" maintenance section.

The GitHub fetcher itself is not exercised here (no network): `care.summarize`
runs on synthetic raw material mirroring real API responses, in UTC so the
tests do not depend on the host's time zone.
"""

from __future__ import annotations  # imports annotations from the __future__ module

import csv  # imports the csv module
import re  # imports the re module
import sys  # imports the sys module
import tempfile  # imports the tempfile module
import unittest  # imports the unittest module
from pathlib import Path  # imports Path from the pathlib module

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # inserts text or data

import care  # noqa: E402  # imports the care module
import config  # noqa: E402  # imports the config module
import exports  # noqa: E402  # imports the exports module
import scoring  # noqa: E402  # imports the scoring module

# Fixed "today" for deterministic age maths.
NOW = "2026-06-01T00:00:00Z"  # sets the NOW text


def finding(source, category, severity, rule_id, title, file, line, kind="", package="", cwe=""):  # defines the finding() function
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
        kind=kind,  # copies the kind value into kind
        package=package,  # copies the package value into package
        cwe=cwe,  # copies the cwe value into cwe
    )  # closes the multiline block


def all_status(state="ok"):  # defines the all_status() function
    return {  # returns the value to the caller
        tool: {"status": state, "duration_seconds": 0}  # evaluates the tool expression
        for tool in config.ALL_TOOLS  # loops over the collection
    }  # closes the multiline block


def care_raw(base: str = "2026-06-01T00:00:00Z") -> dict:  # defines the care_raw() function
    """Synthetic GitHub maintenance data, all dates relative to ``base``."""  # keeps the docstring text
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz  # imports datetime as _dt, timedelta as _td, timezone as _tz from the datetime module

    anchor = _dt.fromisoformat(base.replace("Z", "+00:00"))  # runs the fromisoformat() call

    def ago(days: int) -> str:  # defines the ago() function
        return (anchor - _td(days=days)).isoformat().replace("+00:00", "Z")  # returns the value to the caller

    def week(days: int, total: int) -> dict:  # defines the week() function
        return {"week": ago(days), "total": total}  # returns the value to the caller

    return {  # returns the value to the caller
        "last_commit_at": ago(4),  # maps the last_commit_at dictionary entry
        "commit_activity": [  # maps the commit_activity dictionary entry
            week(0, 1), week(7, 0), week(14, 2), week(21, 1),  # runs the week() call
            week(28, 12), week(35, 8), week(42, 15), week(49, 10),  # runs the week() call
            week(56, 30), week(63, 20), week(70, 40), week(77, 30),  # runs the week() call
        ],  # closes the multiline block
        "releases": [  # maps the releases dictionary entry
            {"published_at": ago(31)},  # runs the ago() call
            {"published_at": ago(121)},  # runs the ago() call
            {"published_at": ago(213)},  # runs the ago() call
        ],  # closes the multiline block
        "open_pull_requests": 3,  # maps the open_pull_requests dictionary entry
        "oldest_open_pr": {  # maps the oldest_open_pr dictionary entry
            "title": "Fix weak crypto",  # maps the title dictionary entry
            "created_at": ago(147),  # maps the created_at dictionary entry
            "html_url": "https://github.com/o/r/pull/2",  # maps the html_url dictionary entry
        },  # closes the multiline block
        "oldest_open_issue": {  # maps the oldest_open_issue dictionary entry
            "title": "Docs outdated",  # maps the title dictionary entry
            "created_at": ago(356),  # maps the created_at dictionary entry
            "html_url": "https://github.com/o/r/issues/7",  # maps the html_url dictionary entry
            "number": 7,  # maps the number dictionary entry
        },  # closes the multiline block
        "closed_issues_sample": [  # maps the closed_issues_sample dictionary entry
            {"created_at": ago(62), "closed_at": ago(60)},  # runs the ago() call
            {"created_at": ago(73), "closed_at": ago(67)},  # runs the ago() call
            {"created_at": ago(83), "closed_at": ago(53)},  # runs the ago() call
        ],  # closes the multiline block
        "closed_prs_sample": [  # maps the closed_prs_sample dictionary entry
            {"created_at": ago(70), "merged_at": ago(69), "closed_at": ""},  # runs the ago() call
            {"created_at": ago(61), "merged_at": "", "closed_at": ago(58)},  # runs the ago() call
            {"created_at": ago(78), "merged_at": ago(75), "closed_at": ago(73)},  # runs the ago() call
        ],  # closes the multiline block
        "contributors": 9,  # maps the contributors dictionary entry
        "recent_commit_authors": ["alice", "bob", "alice", "carol", "alice"],  # maps the recent_commit_authors dictionary entry
        "errors": ["contributors: could not be fetched (simulated)"],  # maps the errors dictionary entry
    }  # closes the multiline block


class CareSummaryTests(unittest.TestCase):  # defines the CareSummaryTests class
    def setUp(self) -> None:  # defines the setUp() function
        self.summary = care.summarize(care_raw(), NOW)  # saves the result on summary

    def test_last_commit_and_release_ages(self) -> None:  # defines the test_last_commit_and_release_ages() function
        self.assertEqual(self.summary["last_commit_days"], 4.0)  # runs the assertEqual() call
        self.assertEqual(self.summary["last_release_days"], 31.0)  # runs the assertEqual() call
        self.assertEqual(self.summary["releases_last_year"], 3)  # runs the assertEqual() call
        # Releases: May 1, Feb 1, Nov 1 -> gaps 90, 92 -> median 91.0
        self.assertEqual(self.summary["median_release_gap_days"], 91.0)  # runs the assertEqual() call

    def test_commit_frequency_and_trend(self) -> None:  # defines the test_commit_frequency_and_trend() function
        self.assertEqual(self.summary["commits_last_year"], 169)  # runs the assertEqual() call
        self.assertAlmostEqual(self.summary["commit_frequency_per_week"], round(169 / 12, 2))  # runs the assertAlmostEqual() call
        # Recent ~1/week (quiet stretch) vs ~15.75/week before -> slowing.
        self.assertEqual(self.summary["development_trend"], "slowing")  # runs the assertEqual() call
        self.assertEqual(self.summary["commits_last_7d"], 1)  # runs the assertEqual() call
        self.assertEqual(self.summary["commits_last_30d"], 16)  # runs the assertEqual() call

    def test_recency_distribution(self) -> None:  # defines the test_recency_distribution() function
        self.assertAlmostEqual(self.summary["pct_commits_last_30d"], round(100 * 16 / 169, 1))  # runs the assertAlmostEqual() call
        self.assertLess(self.summary["pct_commits_last_30d"], 10.0)  # runs the assertLess() call
        self.assertAlmostEqual(self.summary["pct_commits_last_90d"], 100.0)  # runs the assertAlmostEqual() call

    def test_pr_and_issue_metrics(self) -> None:  # defines the test_pr_and_issue_metrics() function
        self.assertEqual(self.summary["open_pull_requests"], 3)  # runs the assertEqual() call
        # Oldest PR: Jan 5 -> Jun 1 = 147 days.
        self.assertEqual(self.summary["oldest_open_pr_days"], 147.0)  # runs the assertEqual() call
        self.assertEqual(self.summary["oldest_open_pr_title"], "Fix weak crypto")  # runs the assertEqual() call
        # Oldest issue: Jun 10 2025 -> Jun 1 2026 = 356 days.
        self.assertEqual(self.summary["oldest_open_issue_days"], 356.0)  # runs the assertEqual() call
        # Issue closes: 2d, 6d, 31d -> median 6.
        self.assertEqual(self.summary["median_issue_close_days"], 6.0)  # runs the assertEqual() call
        # PR merges/closes: 1d, 3d, 3d -> median 3.
        self.assertEqual(self.summary["median_pr_close_days"], 3.0)  # runs the assertEqual() call
        self.assertEqual(self.summary["issues_closed_sampled"], 3)  # runs the assertEqual() call
        self.assertEqual(self.summary["prs_closed_sampled"], 3)  # runs the assertEqual() call

    def test_contributor_activity(self) -> None:  # defines the test_contributor_activity() function
        self.assertEqual(self.summary["contributors"], 9)  # runs the assertEqual() call
        self.assertEqual(self.summary["contributors_recent"], 3)  # runs the assertEqual() call
        self.assertEqual(self.summary["top_contributor_share"], 0.6)  # runs the assertEqual() call

    def test_render_skips_nothing_present_and_flags_notes(self) -> None:  # defines the test_render_skips_nothing_present_and_flags_notes() function
        lines = care.render_summarized(self.summary)  # runs the render_summarized() call
        joined = "\n".join(lines)  # sets the joined text
        for needle in (  # loops over the collection
            "Last commit",  # supplies the literal text
            "Last release",  # supplies the literal text
            "Commit frequency",  # supplies the literal text
            "Development trend",  # supplies the literal text
            "Open pull requests",  # supplies the literal text
            "Oldest open issue",  # supplies the literal text
            "Issue response time",  # supplies the literal text
            "PR response time",  # supplies the literal text
            "Contributor activity",  # supplies the literal text
            "Commit recency",  # supplies the literal text
            "contributors: could not be fetched",  # maps the contributors: could not  dictionary entry
        ):  # closes the multiline block
            with self.subTest(needle=needle):  # opens the context for the block
                self.assertIn(needle, joined)  # runs the assertIn() call

    def test_trend_labels(self) -> None:  # defines the test_trend_labels() function
        self.assertEqual(care._trend_label(10, 5), "accelerating")  # runs the assertEqual() call
        self.assertEqual(care._trend_label(5, 10), "slowing")  # runs the assertEqual() call
        self.assertEqual(care._trend_label(10, 10), "steady")  # runs the assertEqual() call
        self.assertEqual(care._trend_label(0, 0), "dormant")  # runs the assertEqual() call
        self.assertEqual(care._trend_label(10, 0), "restarting")  # runs the assertEqual() call

    def test_empty_raw_is_safe(self) -> None:  # defines the test_empty_raw_is_safe() function
        summary = care.summarize({}, NOW)  # runs the summarize() call
        self.assertEqual(summary["commits_last_year"], 0)  # runs the assertEqual() call
        self.assertEqual(summary["development_trend"], "dormant")  # runs the assertEqual() call
        lines = care.render_summarized(summary)  # runs the render_summarized() call
        self.assertEqual(len(lines), 3)  # "no release" note + frequency + dormant trend  # runs the assertEqual() call
        self.assertIn("none found", lines[0])  # runs the assertIn() call

    def test_report_carries_care_section(self) -> None:  # defines the test_report_carries_care_section() function
        from datetime import datetime, timezone  # imports datetime, timezone from the datetime module

        base_now = datetime.now(timezone.utc).isoformat()  # runs the now() call
        report = scoring.build_report(  # runs the build_report() call
            [finding("trivy", "vulnerability", "high", "CVE-2021-23337", "lodash", "x", 1)],  # runs the finding() call
            scanner_status=all_status(),  # runs the all_status() call
            care=care_raw(base=base_now),  # runs the care_raw() call
        )  # closes the multiline block
        self.assertIsNotNone(report["care"])  # runs the assertIsNotNone() call
        self.assertEqual(report["care"]["development_trend"], "slowing")  # runs the assertEqual() call
        text = scoring.render_report_text(report)  # runs the render_report_text() call
        self.assertIn("CARE AND FEEDING", text)  # runs the assertIn() call
        self.assertIn("Issue response time", text)  # runs the assertIn() call
        self.assertIn("Open pull requests", text)  # runs the assertIn() call


class ComplianceInExportsTests(unittest.TestCase):  # defines the ComplianceInExportsTests class
    """The compliance mapping must reach the CSV rows (PDF already shows it)."""  # keeps the docstring text

    def _report(self) -> dict:  # defines the _report() function
        pair = [  # assigns the computed value to pair
            finding("gitleaks", "secret", "critical", "aws", "aws key committed",  # runs the finding() call
                    "app/x.py", 10, kind="aws"),  # supplies the literal text
            finding("codeql", "code", "high", "py/sql", "SQL injection",  # runs the finding() call
                    "app/db.py", 33, cwe="CWE-089"),  # supplies the literal text
        ]  # closes the multiline block
        return scoring.build_report(pair, scanner_status=all_status(), frameworks=["pci", "iso"])  # returns the scoring.build_report to the caller

    def test_csv_rows_name_framework_and_controls(self) -> None:  # defines the test_csv_rows_name_framework_and_controls() function
        with tempfile.TemporaryDirectory() as tmp:  # opens the context for the block
            path = Path(tmp) / "report.csv"  # creates the path object
            exports.write_report_csv(self._report(), path)  # runs the write_report_csv() call
            rows = list(csv.reader(path.read_bytes().decode("utf-8-sig").splitlines()))  # builds the list collection
        header = rows[0]  # copies the rows value into header
        self.assertIn("Compliance Frameworks", header)  # runs the assertIn() call
        self.assertIn("Affected Controls", header)  # runs the assertIn() call
        aws_row = next(row for row in rows[1:] if "aws key" in row[2])  # runs the next() call
        self.assertIn("PCI DSS", aws_row[14])  # runs the assertIn() call
        self.assertIn("Req 8.x", aws_row[15])  # runs the assertIn() call
        sql_row = next(row for row in rows[1:] if "SQL injection" in row[2])  # runs the next() call
        self.assertIn("A.8.28", sql_row[15])  # runs the assertIn() call

    def test_csv_none_mapping_leaves_columns_empty(self) -> None:  # defines the test_csv_none_mapping_leaves_columns_empty() function
        report = scoring.build_report(  # runs the build_report() call
            [finding("gitleaks", "secret", "high", "aws", "aws key committed",  # runs the finding() call
                     "app/x.py", 10, kind="aws")],  # supplies the literal text
            scanner_status=all_status(),  # runs the all_status() call
        )  # closes the multiline block
        with tempfile.TemporaryDirectory() as tmp:  # opens the context for the block
            path = Path(tmp) / "report.csv"  # creates the path object
            exports.write_report_csv(report, path)  # runs the write_report_csv() call
            rows = list(csv.reader(path.read_bytes().decode("utf-8-sig").splitlines()))  # builds the list collection
        self.assertEqual(len(rows[0]), 16)  # columns kept for spreadsheet consistency  # runs the assertEqual() call
        self.assertEqual(rows[1][14], "")  # runs the assertEqual() call
        self.assertEqual(rows[1][15], "")  # runs the assertEqual() call


class WhiteBrandingPdfTests(unittest.TestCase):  # defines the WhiteBrandingPdfTests class
    def test_pdf_embeds_the_white_wordmark(self) -> None:  # defines the test_pdf_embeds_the_white_wordmark() function
        pair = [  # assigns the computed value to pair
            finding("gitleaks", "secret", "critical", "aws", "aws key committed",  # runs the finding() call
                    "app/x.py", 10, kind="aws"),  # supplies the literal text
        ]  # closes the multiline block
        report = scoring.build_report(pair, scanner_status=all_status(), frameworks=["pci"])  # runs the build_report() call
        with tempfile.TemporaryDirectory() as tmp:  # opens the context for the block
            path = Path(tmp) / "report.pdf"  # creates the path object
            exports.write_report_pdf(report, path)  # runs the write_report_pdf() call
            raw = path.read_bytes()  # reads the file as raw bytes
        self.assertIn(b"/Subtype /Image", raw)  # runs the assertIn() call
        self.assertIn(b"/ColorSpace /DeviceRGB", raw)  # runs the assertIn() call
        self.assertIn(b"/Im1 Do", raw)  # runs the assertIn() call
        self.assertIn(b"/Width 600 ", raw)  # 1800px wordmark averaged down 3x  # runs the assertIn() call
        self.assertIn(b"COMPLIANCE FRAMEWORK MAPPING", raw)  # runs the assertIn() call
        self.assertTrue(raw.startswith(b"%PDF-1.4"))  # runs the assertTrue() call
        self.assertTrue(raw.rstrip().endswith(b"%%EOF"))  # runs the assertTrue() call
        self.assertGreater(len(raw), 12000, "the embedded wordmark stream should be present")  # runs the assertGreater() call

    def test_pdf_without_artwork_falls_back_to_text(self) -> None:  # defines the test_pdf_without_artwork_falls_back_to_text() function
        original = config.BRANDING_WHITE  # copies the config.BRANDING_WHITE value into original
        config.BRANDING_WHITE = "_definitely-missing.png"  # sets the config.BRANDING_WHITE text
        report = scoring.build_report(  # runs the build_report() call
            [finding("gitleaks", "secret", "critical", "aws", "aws key committed",  # runs the finding() call
                     "app/x.py", 10, kind="aws")],  # supplies the literal text
            scanner_status=all_status(),  # runs the all_status() call
        )  # closes the multiline block
        try:  # watches for errors in the block
            with tempfile.TemporaryDirectory() as tmp:  # opens the context for the block
                path = Path(tmp) / "report.pdf"  # creates the path object
                exports.write_report_pdf(report, path)  # runs the write_report_pdf() call
                raw = path.read_bytes()  # reads the file as raw bytes
            self.assertNotIn(b"/Subtype /Image", raw)  # runs the assertNotIn() call
            self.assertIn(b"ScanityCheck", raw)  # runs the assertIn() call
        finally:  # runs whether or not the block errored
            config.BRANDING_WHITE = original  # copies the original value into config.BRANDING_WHITE

    def test_long_care_lines_wrap_inside_the_page(self) -> None:  # defines the test_long_care_lines_wrap_inside_the_page() function
        raw = care_raw(base=NOW)  # runs the care_raw() call
        raw["oldest_open_issue"]["title"] = "V" * 120  # sets the raw["oldest_open_issue"]["title"] text
        raw["oldest_open_pr"]["title"] = "W" * 120  # sets the raw["oldest_open_pr"]["title"] text
        report = scoring.build_report(  # runs the build_report() call
            [finding("gitleaks", "secret", "critical", "aws", "aws key committed",  # runs the finding() call
                     "app/x.py", 10, kind="aws")],  # supplies the literal text
            scanner_status=all_status(),  # runs the all_status() call
            care=raw,  # copies the raw value into care
        )  # closes the multiline block
        with tempfile.TemporaryDirectory() as tmp:  # opens the context for the block
            path = Path(tmp) / "report.pdf"  # creates the path object
            exports.write_report_pdf(report, path)  # runs the write_report_pdf() call
            page_bytes = path.read_bytes()  # reads the file as raw bytes

        # Page content streams are plain text; every drawn run ends with `Tj`.
        runs = re.findall(rb"\(([^()]*)\) Tj", page_bytes)  # runs the findall() call
        self.assertTrue(runs)  # runs the assertTrue() call
        longest = max(len(run_bytes) for run_bytes in runs)  # takes the largest value
        self.assertLessEqual(  # runs the assertLessEqual() call
            longest,  # evaluates the longest expression
            106,  # executes the statement
            f"a PDF text run of {longest} chars would run past the right margin; "  # supplies the literal text
            f"the care lines must wrap: {runs[:12]}",  # maps the the care lines must wrap dictionary entry
        )  # closes the multiline block
        # The long value rows must actually wrap (several 60-100-char runs),
        # not be silently truncated at the page edge.
        wrapped_rows = [run for run in runs if 60 <= len(run) < 106]  # counts the items
        self.assertGreaterEqual(len(wrapped_rows), 2)  # runs the assertGreaterEqual() call


if __name__ == "__main__":  # runs the module entry point
    unittest.main(verbosity=2)  # runs the main() call
