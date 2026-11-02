"""Tests for the Summarize It feature: bullet composition and the popup."""

from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config  # noqa: E402
import exports  # noqa: E402
import summarizer  # noqa: E402
import app as appmod  # noqa: E402


def all_status():
    return {tool: {"status": "ok"} for tool in config.ALL_TOOLS}


def rich_report():
    """A report with every category, Care data and an SBOM payload."""
    return {  # the finished report shape the scanner pipeline produces
        "repo": {"full_name": "acme/widget"},
        "score": 52, "band": "High", "verdict": "INSECURE",
        "verdict_reason": "2 critical-severity findings were reported.",
        "totals": {"critical": 2, "high": 6, "medium": 10, "low": 30, "unknown": 1,
                   "by_category": {"vulnerability": 30, "secret": 4, "misconfiguration": 8,
                                   "code": 6, "license": 0, "code-quality": 1}},
        "counts": {},
        "care": {"development_trend": "steady", "contributors": 7, "commits_last_90d": 60,
                 "last_commit_days": 2, "err": []},
        "sbom": {"tools": "syft", "components": 220, "unversioned": 9, "ecosystems": {"golang": 220},
                 "all_components": [{"name": "gin", "version": "1.9.0", "type": "framework",
                                     "purl": "pkg:golang/gin@1.9.0", "file": ""}]},
        "dedupe": {"corroborated": 4},
        "confidence": {"score": 82, "band": "Moderate confidence"},
        "frameworks": {"nist-rmf": {"controls": [{"id": "RA-5", "status": "affected", "affected": 3}]}},
        "greatest_risks": [
            {"title": "SQL injection", "rule_id": "py/sql"},
            {"title": "Log injection", "rule_id": "py/log"},
            {"title": "Deserialisation", "rule_id": "py/deser"},
        ],
    }


class BulletTests(unittest.TestCase):
    def test_rich_report_yields_between_eight_and_ten_bullets(self) -> None:
        bullets = summarizer.summary_bullets(rich_report())
        self.assertGreaterEqual(len(bullets), 8)  # the floor for a rich scan
        self.assertLessEqual(len(bullets), 10)  # the headline-kept cap
        joined = "\n".join(bullets)
        self.assertIn("52/100", joined)  # the score headline
        self.assertIn("4 committed credentials", joined)  # the secrets bullet
        self.assertIn("Internet-connected systems", joined)  # the exposure caveat
        self.assertIn("cloud-based deployments", joined)  # the IaC framing
        self.assertIn("7 contributors", joined)  # the maintenance praise
        self.assertIn("220 components", joined)  # the SBOM note
        self.assertIn("82/100", joined)  # the confidence note
        self.assertEqual(len(bullets), 9)  # the crafted set just under the cap

    def test_thin_reports_pad_with_risk_theme_names(self) -> None:
        report = {  # a thin scan with named risk themes but few data bullets
            "score": 88, "verdict": "INSECURE", "band": "Low",
            "totals": {"critical": 0, "high": 1, "by_category": {"vulnerability": 1}},
            "care": None, "frameworks": {},
            "greatest_risks": [
                {"title": "Log injection", "rule_id": "py/log"},
                {"title": "Open redirect", "rule_id": "py/redir"},
            ],
        }  # closes the fixture
        bullets = summarizer.summary_bullets(report)
        self.assertGreaterEqual(len(bullets), 8)  # the honest filler reached the floor
        self.assertIn("Start with the most-charged risk themes", "\n".join(bullets))  # the named pad
        self.assertIn("Log injection", "\n".join(bullets))  # the theme names landed

    def test_bare_report_still_reads_as_one_to_ten(self) -> None:
        bullets = summarizer.summary_bullets({"score": 95, "verdict": "SECURE",
                                              "band": "Very Low", "totals": {}})
        self.assertGreaterEqual(len(bullets), 1)  # at least the headline
        self.assertLessEqual(len(bullets), 10)  # never a wall of text
        self.assertIn("95/100", bullets[0])  # the headline opens the list


class PopupTests(unittest.TestCase):
    def test_popup_carries_bullets_and_the_brand_header(self) -> None:
        import tkinter as tk

        self.app = appmod.App()
        self.app._report = rich_report()

        def pump(seconds=1.0):
            end = time.time() + seconds
            while time.time() < end:
                try:
                    self.app.update()
                except tk.TclError:
                    break
                time.sleep(0.02)

        try:
            pump(1.0)
            self.app.summarize_report()
            pump(0.8)
            popups = [child for child in self.app.winfo_children() if isinstance(child, tk.Toplevel)]
            self.assertTrue(popups, "the summary popup opened")
            texts: list[tk.Text] = []
            labels: list[str] = []

            def walk(widget):
                if isinstance(widget, tk.Text):
                    texts.append(widget)
                if isinstance(widget, tk.Label):
                    labels.append(str(widget.cget("text")))
                for kid in widget.winfo_children():
                    walk(kid)

            walk(popups[0])
            self.assertTrue(texts, "the bullets render in a Text widget")
            content = texts[0].get("1.0", "end")
            self.assertIn("●", content)  # the brand-green markers
            self.assertIn("52/100", content)  # the headline sentence
            self.assertIn("acme/widget", "\n".join(labels))  # the repo title sits under the logo
            self.assertIn("https://github.com/acme/widget", "\n".join(labels))  # the GitHub path line
            buttons = [
                str(child.cget("text")) for child in walk_all(popups[0])
                if isinstance(child, tk.Button)  # only buttons carry captions
            ]
            self.assertIn("Print", buttons)  # the summary print action exists next to Close
            self.assertIn("Close", buttons)
        finally:
            self.app.destroy()

    def test_print_summary_uses_the_dialog_and_report_template(self) -> None:
        import tempfile
        from unittest import mock as _mock
        from types import SimpleNamespace

        self.app = appmod.App()
        self.app._report = rich_report()
        bullets = summarizer.summary_bullets(self.app._report)
        calls: list[str] = []

        def fake_dialog(**_kwargs):
            calls.append("dialog")
            return "C:\\tmp\\summary.pdf"

        writer_paths: list[str] = []

        def fake_writer(*args):  # the patched writer receives (report, bullets, path)
            writer_paths.append(args[-1])  # keeps the dialog-path
            return f"Summary PDF saved to {args[-1]}"

        with _mock.patch.object(appmod.filedialog, "asksaveasfilename", side_effect=fake_dialog), \
             _mock.patch.object(appmod.exports, "write_summary_pdf", side_effect=fake_writer):
            self.app._ask = SimpleNamespace()  # the attribute the dialog patch lands on
            self.app._print_summary_pdf(bullets)
        self.assertEqual(calls, ["dialog"])  # the save dialog fired once
        self.assertTrue(writer_paths)  # the writer path received the dialog-path

    def test_summary_pdf_writer_matches_the_report_template(self) -> None:
        import tempfile

        bullets = summarizer.summary_bullets(rich_report())
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "summary.pdf"
            exports.write_summary_pdf(rich_report(), bullets, path)
            data = path.read_bytes()
        self.assertGreater(len(data), 2500)  # a real, styled document
        text_probe = data.decode("latin-1", errors="ignore")  # the streams are literal
        self.assertIn("SCAN SUMMARY", text_probe)  # the section banner
        self.assertIn("52/100", text_probe)  # the headline sentence
        self.assertIn("https://github.com/acme/widget", text_probe)  # the repository path line


def walk_all(widget):
    """Every descendant widget, flattened for simple assertions."""
    found: list = []
    for kid in widget.winfo_children():
        found.append(kid)
        found.extend(walk_all(kid))
    return found


    def test_ask_export_drops_topmost_popups_while_the_dialog_is_open(self) -> None:
        import tkinter as tk
        from unittest import mock as _mock

        self.app = appmod.App()
        self.app._report = rich_report()
        bullets = summarizer.summary_bullets(self.app._report)
        states: list[str] = []  # the popup's topmost state at dialog time

        popup = tk.Toplevel(self.app)
        popup.title("Scan Summary")
        popup.attributes("-topmost", True)  # the state the bug reports about

        def spy_dialog(**_kwargs):
            states.append("topmost" if popup.attributes("-topmost") else "normal")
            return "C:\\tmp\\summary.pdf"

        try:
            self.app.update()
            with _mock.patch.object(appmod.filedialog, "asksaveasfilename", side_effect=spy_dialog), \
                 _mock.patch.object(appmod.exports, "write_summary_pdf", return_value="ok"):
                self.app._print_summary_pdf(bullets)
            self.assertEqual(states, ["normal"])  # the dialog ran with the flag dropped
            self.assertEqual(popup.attributes("-topmost"), "1")  # restored afterwards
        finally:
            popup.destroy()
            self.app.destroy()

    def test_the_sum_button_is_registered_in_the_report_cluster(self) -> None:
        import tkinter as tk
        import time

        self.app = appmod.App()
        try:
            self.app.update()
            cluster = self.app._report_buttons()
            self.assertIn(self.app.sum_button, cluster)  # the button joins the cluster
        finally:
            self.app.destroy()


if __name__ == "__main__":
    unittest.main(verbosity=2)
