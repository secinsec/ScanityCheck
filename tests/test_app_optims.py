"""Unit tests for the pure report-layout pieces extracted from app.py.

These cover ``report_view.build_report_segments`` (ordered sections,
omission-key splicing, care fallback/pairs) and ``report_view.batch_segments``
(same-tag coalescing, widget passthrough, text preservation).
"""

from __future__ import annotations  # imports annotations from the __future__ module

import unittest  # imports the unittest module
import tempfile  # the tmp history fixture
from unittest import mock  # imports the mock helper
from pathlib import Path  # imports Path for the source assertion

import app as appmod  # the real Tk module (kept for the export-open test)
import scoring  # imports the scoring module
import care  # imports the care module
import config  # imports the config module
import report_view  # imports the module under test


def sample_report() -> dict:  # defines the sample_report() fixture helper
    """A minimal complete report exercising every layout block."""
    return {  # builds the dictionary
        "repo": {"full_name": "acme/widget", "branch": "main", "file_count": 12},  # the header block
        "languages": ["python"],  # the language list
        "verdict": "INSECURE",  # the verdict
        "verdict_reason": "two critical findings remain open.",  # the reason line
        "confidence": {  # a full confidence block
            "score": 80,  # the score
            "band": "good",  # the band
            "factors": [{"label": "coverage", "score": 80}],  # the factor rows
            "headline": "tools corroborate",  # the headline
            "notes": ["note one", "note two"],  # the note rows
        },  # closes the mapping
        "explanation": "The score starts at 100 and subtracts weighted penalties.",  # the prose
        "counts": {  # per-category severity maps
            "vulnerability": {"high": 1},  # maps the vulnerability dictionary entry
            "secret": {},  # maps the secret dictionary entry
            "misconfiguration": {},  # maps the misconfiguration dictionary entry
            "code": {"critical": 1},  # maps the code dictionary entry
            "license": {},  # maps the license dictionary entry
            "code-quality": {},  # maps the code-quality dictionary entry
        },
        "penalties": {  # per-category penalties
            "vulnerability": 4.0,  # maps the vulnerability dictionary entry
            "secret": 0.0,  # maps the secret dictionary entry
            "misconfiguration": 0.0,  # maps the misconfiguration dictionary entry
            "code": 10.0,  # maps the code dictionary entry
            "license": 0.0,  # maps the license dictionary entry
            "code-quality": 0.0,  # maps the code-quality dictionary entry
        },
        "caps": {  # per-category caps
            "vulnerability": 35.0,  # maps the vulnerability dictionary entry
            "secret": 25.0,  # maps the secret dictionary entry
            "misconfiguration": 25.0,  # maps the misconfiguration dictionary entry
            "code": 30.0,  # maps the code dictionary entry
            "license": 8.0,  # maps the license dictionary entry
            "code-quality": 10.0,  # maps the code-quality dictionary entry
        },
        "totals": {"findings": 2, "critical": 1, "high": 1, "medium": 0, "low": 0, "unknown": 0},  # the totals
        "dedupe": {"raw": 4, "merged": 2, "removed": 1, "corroborated": 1},  # the dedupe block
        "inventory": {"components": 3, "unversioned": 1, "ecosystems": {"pip": 3}, "top_packages": [{"name": "flask", "version": "3.0", "type": "library"}]},  # the SBOM block
        "care": {"last_commit": "very recently"},  # the maintenance summary
        "greatest_risks": [  # two risk themes, one omittable
            {  # the first theme
                "key": "risk-1", "count": 2, "severity": "critical",  # the meta
                "title": "SQL injection", "penalty": 10.0, "category": "code",  # the identity
                "rule_id": "CWE-089", "tool_labels": ["CodeQL"],  # the attribution
                "detail": "sink at app.py:7", "locations": ["app.py:7"],  # the places
                "reference": "https://example.com",  # the reference
            },  # closes the entry
            {  # the second theme
                "key": "", "count": 1, "severity": "high",  # no stable key: not omittable
                "title": "Some warning", "penalty": 4.0, "category": "vulnerability",  # the identity
                "rule_id": "CVE-0000", "tool_labels": [],  # the attribution
                "detail": "", "locations": [],  # the places
            },  # closes the entry
        ],  # closes the list
        "by_tool": {"codeql": {"critical": 1, "high": 0, "medium": 0, "low": 0, "total": 1}},  # the tool table
        "tool_labels": {"codeql": "CodeQL"},  # the display names
        "frameworks": {},  # no framework mapping in this fixture
        "findings": [{"severity": "high", "title": "t" * 20, "rule_id": "R1", "tool_labels": ["CodeQL"], "location": "a.py:1", "category": "code"}],  # the findings list
        "scanner_status": {"codeql": {"status": "ok", "duration_seconds": 12.3, "details": ["ran"]}},  # the coverage block
        "warnings": ["one warning"],  # the warnings block
        "generated_at": "2026-01-01 00:00:00",  # the footer timestamp
        "duration_seconds": 42.0,  # the footer duration
    }  # closes the dictionary


class ContextNoteTests(unittest.TestCase):
    """The points table prints where the context normalisation relieved caps."""

    def test_context_factors_render_without_errors(self) -> None:
        report = sample_report()  # the base fixture carries every expected key
        report["context"] = {  # the persisted normalisation summary from a scan
            "packages": 637,
            "files": 431,
            "pulse": 1.0,
            "factors": {
                "vulnerability": {"density": 2.03, "pulse": 1.0, "factor": 3.16,
                                  "relief": 0.45, "effective_cap": 20.25},
                "code": {"density": 1.9, "pulse": 1.0, "factor": 1.8,
                         "relief": 0.55, "effective_cap": 22.26},
            },
            "effective_caps": dict(report["caps"]),
        }
        segments = report_view.build_report_segments(report)  # the full render
        text = "".join(segment[0] for segment in segments if isinstance(segment[0], str))
        self.assertIn("cap relieved", text)  # the context note landed
        self.assertIn("637 packages", text)  # the surface-size reason


class OpenAfterExportTests(unittest.TestCase):
    """"Print Report" hands the saved PDF to the system viewer."""

    def setUp(self) -> None:
        import app as appmod  # the Tk module still imports around a test-suite run

        self.app = appmod.App()  # a real instance; every dialog gets patched out
        self.app._report = {
            "repo": {"full_name": "acme/widget"},
            "score": 90, "band": "Low", "verdict": "SECURE",
        }  # the minimal fields the name generator reads

    def tearDown(self) -> None:
        self.app.destroy()

    def test_pdf_export_opens_the_saved_file(self) -> None:
        import os
        from unittest import mock as _mock

        opened: list[str] = []
        with _mock.patch.object(appmod.filedialog, "asksaveasfilename", return_value=r"C:\tmp\report.pdf"), \
             _mock.patch.object(appmod.exports, "write_report_pdf", return_value="PDF ok"), \
             _mock.patch.object(appmod.os, "startfile", side_effect=lambda target: opened.append(target)):
            self.app.export_pdf()
        self.assertEqual(len(opened), 1)
        self.assertTrue(opened[0].lower().endswith("report.pdf"))
        self.assertTrue(str(opened[0]).endswith("report.pdf"))  # the absolute path went to the viewer

    def test_csv_export_does_not_open(self) -> None:
        from unittest import mock as _mock

        opened: list[str] = []
        with _mock.patch.object(appmod.filedialog, "asksaveasfilename", return_value=r"C:\tmp\r.csv"), \
             _mock.patch.object(appmod.exports, "write_report_csv", return_value="CSV ok"), \
             _mock.patch.object(appmod.os, "startfile", side_effect=lambda target: opened.append(target)):
            self.app.export_csv()
        self.assertEqual(opened, [])  # only the PDF auto-opens

    def test_missing_viewer_never_fails_the_export(self) -> None:
        from unittest import mock as _mock

        with _mock.patch.object(appmod.filedialog, "asksaveasfilename", return_value=r"C:\tmp\report.pdf"), \
             _mock.patch.object(appmod.exports, "write_report_pdf", return_value="PDF ok"), \
             _mock.patch.object(appmod.os, "startfile", side_effect=OSError("no viewer")):
            self.app.export_pdf()  # must not raise; the note lands in the activity log only


class RenameTypoRegressionTests(unittest.TestCase):
    """The resize debounces call self methods; a misspelling only fails at
    runtime inside a Tk callback (it once shipped as AttributeError on
    tkinter.tkapp). These run purely on the source and the module surface."""

    def test_no_misspelled_debounce_calls(self) -> None:
        source = (
            (Path(__file__).resolve().parent.parent / "app.py")
            .read_text(encoding="utf-8", errors="replace")
        )
        self.assertNotIn("self.after_debounced(", source)  # the helper is _after_debounced

    def test_debounce_helper_exists_on_the_class(self) -> None:
        import app  # the Tk module still imports around a test-suite run

        self.assertTrue(hasattr(app.App, "_after_debounced"))


class BuildSegmentsTests(unittest.TestCase):  # the build tests
    def test_every_segment_is_plain_text_in_pure_mode(self) -> None:  # defines the test
        """Without a checkbox hook the builder emits only (str, tags) pairs."""
        segments = report_view.build_report_segments(sample_report())  # runs the build
        self.assertTrue(segments)  # something must be composed
        for text, tags in segments:  # loops over the segments
            self.assertIsInstance(text, str)  # no widget slots without the hook
            self.assertIsInstance(tags, tuple)  # tags stay tuples in pure mode

    def test_section_order_matches_the_report_layout(self) -> None:  # defines the test
        """The major section banners appear exactly once and in order."""
        pairs = [("Last commit", "recently")]  # one care pair so the section prints

        def render_pairs(summary: dict) -> list:  # defines the fake
            return list(pairs)  # returns the pairs

        with mock.patch.object(care, "render_pairs", render_pairs):  # pins the pair view
            segments = report_view.build_report_segments(sample_report(), ())  # runs the build
        text = "".join(s[0] for s in segments)  # the visible report text
        order = [  # the banners in print order
            "acme/widget\n",  # the title
            "VERDICT: INSECURE\n",  # the verdict
            "WHAT THE SCORE MEANS\n",  # the prose section
            "WHERE THE POINTS WENT\n",  # the points table
            "DE-DUPLICATION\n",  # the merge stats
            "SBOM INVENTORY (SYFT)\n",  # the inventory
            "CARE AND FEEDING (repository maintenance)\n",  # the maintenance section
            "GREATEST RISKS IDENTIFIED\n",  # the risks
            "FINDINGS BY SEVERITY\n",  # the severity table
            "FINDINGS BY TOOL\n",  # the tool table
            "SCANNER COVERAGE\n",  # the coverage table
            "WARNINGS\n",  # the warnings
        ]  # closes the list
        cursor = 0  # the scan cursor
        for banner in order:  # loops over the expected banners
            found = text.find(banner, cursor)  # the next occurrence after the cursor
            self.assertGreaterEqual(found, 0, banner)  # each banner must appear
            cursor = found + len(banner)  # keeps the order strict

    def test_category_labels_come_from_scoring_registry(self) -> None:  # defines the test
        """Table rows read scoring.CATEGORY_LABELS, not a report-embedded copy."""
        segments = report_view.build_report_segments(sample_report(), ())  # runs the build
        text = "".join(s[0] for s in segments)  # the visible text
        self.assertIn(scoring.CATEGORY_LABELS["code"], text)  # the label from the public registry
        self.assertIn(scoring.CATEGORY_LABELS["vulnerability"], text)  # likewise for the dependency row

    def test_batching_preserves_byte_layout_invariant(self) -> None:  # defines the test
        """Batching never loses text and coalesces internal runs only."""
        segments = report_view.build_report_segments(sample_report(), ())  # composes
        batched = report_view.batch_segments(segments)  # coalesces
        self.assertEqual("".join(s[0] for s in segments), "".join(s[0] for s in batched))  # bytes identical
        self.assertLessEqual(len(batched), len(segments))  # runs only ever shrink
        for i in range(1, len(batched)):  # walks the batched pairs
            left, right = batched[i - 1], batched[i]  # the adjacent pair
            same_tags = report_view._tag_key(left[1]) == report_view._tag_key(right[1])  # tag equality
            self.assertFalse(  # consecutive same-tag *text* neighbours are impossible
                same_tags and isinstance(left[0], str) and isinstance(right[0], str),  # the buggy shape
                "consecutive same-tag text runs must coalesce",  # the failure story
            )

    def test_reports_with_keyed_risks_keep_segment_growth_linear(self) -> None:  # defines the test
        """A bigger report yields proportionally more segments, no explosion."""
        small = report_view.build_report_segments(sample_report(), ())  # two risk themes
        report = sample_report()  # the fixture report
        report["greatest_risks"] = [  # one hundred omittable themes
            {**report["greatest_risks"][0], "key": f"risk-{n}", "title": f"theme {n}"}  # a synthetic theme
            for n in range(100)  # runs the count
        ]  # closes the list
        big = report_view.build_report_segments(report, ())  # runs the build
        self.assertGreater(len(big), len(small))  # more themes, more segments
        self.assertLess(len(big), len(small) * 200)  # still linear-ish, no blowup

    def test_omission_rows_splice_in_order_via_hook(self) -> None:  # defines the test
        """The checkbox hook's segments land before the numbered risk row."""
        markers: list[str] = []  # records the hook's calls

        def hook(key: str, ticked: bool) -> list:  # defines the hook
            markers.append(key)  # records the call
            return [(f"<[BOX:{key}:{ticked}]>", ())]  # a benign marker segment

        segments = report_view.build_report_segments(sample_report(), (), hook)  # runs the build
        text = "".join(str(s[0]) for s in segments)  # the composed story
        self.assertEqual(markers, ["risk-1"])  # only the keyed theme gets a box
        box = text.find("<[BOX:risk-1:False]>")  # the marker position
        row = text.find("1. [CRITICAL] ", box)  # the numbered row after it
        self.assertGreater(row, box)  # the row follows its own checkbox
        second = text.find("2. [HIGH] ", row)  # the next theme's row
        self.assertGreater(second, row)  # and comes later

    def test_omitted_group_flags_credits(self) -> None:  # defines the test
        """An omitted theme gets the excluded-marker treatment from rescore."""
        report = sample_report()  # the fixture report
        report["greatest_risks"][0]["omitted"] = True  # the reviewer excluded it
        report["greatest_risks"][0]["refund"] = 3.5  # the credited points
        segments = report_view.build_report_segments(report, ("risk-1",))  # runs the build
        text = "".join(s[0] for s in segments)  # the visible text
        self.assertIn("excluded", text)  # the exclusion note shows
        self.assertIn("\u22123.5 pts credited", text)  # the true refund shows

    def test_code_quality_row_skips_when_empty(self) -> None:  # defines the test
        """The code-quality row only prints when it has findings."""
        segments = report_view.build_report_segments(sample_report(), ())  # runs the build
        text = "".join(s[0] for s in segments)  # the visible text
        self.assertNotIn(scoring.CATEGORY_LABELS["code-quality"], text)  # skipped

    def test_warnings_and_coverage_render(self) -> None:  # defines the test
        """Trailer blocks survive the extraction untouched."""
        segments = report_view.build_report_segments(sample_report(), ())  # runs the build
        text = "".join(s[0] for s in segments)  # the visible text
        self.assertIn("one warning", text)  # the wrapped warning
        self.assertIn("CodeQL", text)  # the coverage label
        self.assertIn("2026-01-01 00:00:00", text)  # the footer stamp


class CareRowsTests(unittest.TestCase):  # the care-section tests
    def test_fallback_uses_render_summarized_strings(self) -> None:  # defines the test
        """Without care.render_pairs the legacy string rows are kept verbatim."""
        lines = ["maintenance is healthy", "- commit trend: slowing"]  # plausible legacy lines

        def render_pairs(summary: dict) -> None:  # defines the absent-API stand-in
            raise AttributeError("render_pairs is gone")  # the old module didn't have it

        with mock.patch.object(care, "render_pairs", None):  # removes the structured hook
            with mock.patch.object(care, "render_summarized", return_value=lines) as legacy:  # pins the legacy
                segments = report_view.build_report_segments(sample_report(), ())  # runs the build
        legacy.assert_called_once()  # the legacy view produced the rows
        text = "".join(s[0] for s in segments)  # the visible text
        self.assertIn("maintenance is healthy\n", text)  # a body line verbatim
        self.assertIn("- commit trend: slowing\n", text)  # a muted line verbatim

    def test_pairs_mode_used_when_the_hook_exists(self) -> None:  # defines the test
        """When care offers render_pairs, pairs render instead of strings."""
        pairs = [("Last commit", "2026-01-01"), ("- detail", "fine")]  # a plausible pair view

        def render_pairs(summary: dict) -> list:  # defines the fake
            return list(pairs)  # returns the pairs

        with mock.patch.object(care, "render_pairs", render_pairs, create=True):  # installs the hook
            rows = report_view._care_rows({})  # builds the rows through the fake
            segments = report_view.build_report_segments(sample_report(), ())  # and the full build
        self.assertEqual(rows, [("Last commit", "2026-01-01"), ("- detail", "fine")])  # the pairs are kept
        text = "".join(s[0] for s in segments)  # the visible text
        self.assertIn("Last commit: 2026-01-01\n", text)  # a pair line renders

    def test_broken_pairs_hook_falls_back(self) -> None:  # defines the test
        """A broken render_pairs must not kill the whole report render."""

        def render_pairs(summary: dict) -> list:  # defines the fake
            raise RuntimeError("boom")  # explodes

        with mock.patch.object(care, "render_pairs", render_pairs):  # installs the hook
            with mock.patch.object(  # pins the legacy view the fallback trusts
                care, "render_summarized", return_value=["legacy line"]  # the rows it yields
            ):  # closes the patch
                rows = report_view._care_rows({})  # builds the rows
        self.assertEqual(rows, [(None, "legacy line")])  # the fallback produced the legacy rows

    def test_pairs_hook_absent_falls_back_to_summarized(self) -> None:  # defines the test
        """Without the module attribute at all, the legacy path is used."""
        with mock.patch.object(care, "render_pairs", None, create=True):  # removes the hook
            with mock.patch.object(care, "render_summarized", return_value=["x"]) as r:  # pins the legacy
                rows = report_view._care_rows({})  # builds the rows
        self.assertEqual(rows, [(None, "x")])  # legacy rows carry the None heading
        r.assert_called_once()  # the legacy view was used


class BatchSegmentsTests(unittest.TestCase):  # the batching tests
    def test_consecutive_same_tag_run_coalesces(self) -> None:  # defines the test
        """Two same-tag neighbours become one insert with identical bytes."""
        segments = [  # the composed order
            ("line one\n", ("body",)),  # the first line
            ("line two\n", ("body",)),  # the second line with the same tags
            ("line three\n", ("body",)),  # the third again
        ]  # closes the list
        batched = report_view.batch_segments(segments)  # coalesces
        self.assertEqual(len(batched), 1)  # one run
        self.assertEqual(batched[0][0], "line one\nline two\nline three\n")  # texts joined exactly
        self.assertEqual(batched[0][1], ("body",))  # tags preserved

    def test_differing_tags_stay_separate(self) -> None:  # defines the test
        """Runs split exactly at tag-set boundaries, in order."""
        segments = [  # the composed order
            ("a\n", ("body",)),  # a body run
            ("muted bit\n", ("muted",)),  # a different tag set
            ("b\n", ("body",)),  # the original tag set again
        ]  # closes the list
        batched = report_view.batch_segments(segments)  # coalesces
        self.assertEqual(len(batched), 3)  # no merge across tag sets
        tags = [b[1] for b in batched]  # the tag sets in order
        self.assertEqual(tags, [("body",), ("muted",), ("body",)])  # order kept exactly

    def test_strings_and_tuples_merge_alike(self) -> None:  # defines the test
        """A bare-string tag and a one-tuple of it pool into one run."""
        segments = [  # the composed order
            ("a\n", "body"),  # string-tag form
            ("b\n", ("body",)),  # the same tag as a tuple
        ]  # closes the list
        batched = report_view.batch_segments(segments)  # coalesces
        self.assertEqual(len(batched), 1)  # one run
        self.assertEqual(batched[0][0], "a\nb\n")  # texts joined exactly

    def test_widget_slots_break_runs_and_pass_through(self) -> None:  # defines the test
        """(None, widget) slots insert exactly where they sit, unmerged."""
        sentinel = object()  # stands in for any live widget
        segments = [  # the composed order
            ("before\n", ("body",)),  # a text run
            (None, sentinel),  # an embedded control
            ("after\n", ("body",)),  # a text run on the other side
        ]  # closes the list
        batched = report_view.batch_segments(segments)  # coalesces
        self.assertEqual(len(batched), 3)  # the widget splits the runs
        self.assertIs(batched[1][1], sentinel)  # the widget rides through untouched
        self.assertIsNone(batched[1][0])  # the text slot stays None
        self.assertEqual(batched[0][0], "before\n")  # the first run exact
        self.assertEqual(batched[2][0], "after\n")  # the last run exact

    def test_empty_segments_flatten_to_nothing(self) -> None:  # defines the test
        """An empty list batches to an empty list."""
        self.assertEqual(report_view.batch_segments([]), [])  # closes the loop

class UrlHistoryTests(unittest.TestCase):
    """The URL field remembers the last ten scanned targets."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.history = Path(self.tmp.name) / "url_history.json"
        self._patch = mock.patch.object(config, "URL_HISTORY_FILE", self.history)
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self.tmp.cleanup()

    def test_history_rotates_capped_ten_newest_first(self) -> None:
        for index in range(12):
            appmod._remember_url(f"https://example.com/repo-{index}")
        entries = appmod._load_url_history()
        self.assertEqual(len(entries), 10)  # the cap
        self.assertEqual(entries[0], "https://example.com/repo-11")  # newest first
        self.assertNotIn("https://example.com/repo-0", entries)  # the oldest dropped

    def test_remember_promotes_duplicates_to_the_front(self) -> None:
        for url in ("https://a/x", "https://b/y", "https://a/x"):
            appmod._remember_url(url)
        entries = appmod._load_url_history()
        self.assertEqual(entries[0], "https://a/x")  # re-promoted
        self.assertEqual(entries[1], "https://b/y")  # order preserved
        self.assertEqual(len(entries), 2)  # no duplicates stored

    def test_double_click_opens_the_dropdown_and_picking_fills_the_field(self) -> None:
        import tkinter as tk

        self.app = appmod.App()
        self.app._remember_url("https://example.com/mea-culpa")
        self.app._url_history = appmod._load_url_history()
        try:
            self.app.update()  # construction no longer pops the list on its own
            self.assertIsNone(self.app._url_drop)  # focus alone stays quiet
            self.assertIn("Double-Button-1", str(self.app.url_entry.bind()))  # the real trigger is wired
            self.app._show_url_history()  # the exact helper the double-click invokes
            self.app.update()
            self.assertIsNotNone(self.app._url_drop)  # the dropdown opened on the double-click path
            listbox = self.app._url_drop.listbox
            self.assertEqual(listbox.get(0, "end")[-1], "https://example.com/mea-culpa")
            listbox.selection_set(0)  # the user clicks the first row
            self.app._pick_url_history(listbox)
            self.assertEqual(self.app.url_var.get(), "https://example.com/mea-culpa")
            self.assertIsNone(self.app._url_drop)  # the dropdown closed after the pick
        finally:
            self.app.destroy()

    def test_clicking_elsewhere_closes_the_open_dropdown(self) -> None:
        import tkinter as tk
        from types import SimpleNamespace

        self.app = appmod.App()
        self.app._remember_url("https://example.com/mea-culpa")
        self.app._url_history = appmod._load_url_history()
        try:
            self.app._show_url_history()
            drop = self.app._url_drop
            self.assertIsNotNone(drop)  # the list is open

            fake_inside = SimpleNamespace(widget=drop.listbox)  # a click inside the list
            self.app._drop_global_click(fake_inside)
            self.assertIsNotNone(self.app._url_drop)  # list clicks never close it

            fake_on_entry = SimpleNamespace(widget=self.app.url_entry)  # a click on the field
            self.app._drop_global_click(fake_on_entry)
            self.assertIsNotNone(self.app._url_drop)  # field clicks never close it

            frame = tk.Frame(self.app)
            frame.grid()
            fake_outside = SimpleNamespace(widget=frame)  # a click anywhere else
            self.app._drop_global_click(fake_outside)
            self.assertIsNone(self.app._url_drop)  # the list collapses
        finally:
            self.app.destroy()

class WindowIconTests(unittest.TestCase):
    """The AppIcon graphic lands on every window (titlebar + taskbar)."""

    def test_icon_loads_and_anchors(self) -> None:
        import tkinter as tk

        root = tk.Tk()
        root.withdraw()
        try:
            icon = appmod._set_window_icon(root)
            self.assertIsNotNone(icon)  # the asset exists in the project root
            self.assertIsInstance(icon, tk.PhotoImage)  # an image object was registered
            self.assertGreater(icon.width(), 0)  # it carries real pixels
        finally:
            root.destroy()

    def test_missing_icon_falls_back_silently(self) -> None:
        import tkinter as tk
        from unittest import mock as _mock

        root = tk.Tk()
        root.withdraw()
        try:
            with _mock.patch.object(config, "APP_ICON", "does-not-exist.png"):
                icon = appmod._set_window_icon(root)
            self.assertIsNone(icon)  # a missing asset keeps the default icon
        finally:
            root.destroy()


if __name__ == "__main__":  # runs the module entry point
    unittest.main()  # runs the tests
