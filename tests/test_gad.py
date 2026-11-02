"""Tests for the Check GAD (GitHub Advisory Database) feature.

The network sits behind an injectable ``fetch`` boundary, so the sweep, the
rate-limit handling and the popup/print wiring are fully testable offline.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config  # noqa: E402
import exports  # noqa: E402
import gad  # noqa: E402
import app as appmod  # noqa: E402


REPORT_WITH_SBOM = {  # a report whose SBOM carries pinned components
    "repo": {"full_name": "acme/widget"},
    "score": 90, "band": "Low", "verdict": "SECURE",
    "sbom": {"tools": "syft", "components": 3,
             "all_components": [
                 {"name": "flask", "version": "3.0.0", "type": "library",
                  "purl": "pkg:pypi/flask@3.0.0", "file": ""},
                 {"name": "requests", "version": "2.31.0", "type": "library",
                  "purl": "pkg:pypi/requests@2.31.0", "file": ""},
                 {"name": "pinless", "version": "", "type": "library",
                  "purl": "pkg:pypi/pinless", "file": ""},
             ]},
}

ADVISORY_PAYLOAD = [  # the shape the /advisories endpoint returns
    {"ghsa_id": "GHSA-abcd-1234", "cve_id": "CVE-2024-1234",
     "severity": "HIGH", "summary": "escape in widget rendering",
     "url": "https://github.com/advisories/GHSA-abcd-1234",
     "published_at": "2024-05-01T00:00:00Z", "withdrawn_at": None},
    {"ghsa_id": "GHSA-withdrawn-0", "withdrawn_at": "2024-01-01"},  # withdrawn: never a hit
]


class GadLayerTests(unittest.TestCase):
    def test_components_are_uniqued_from_sbom_and_inventory(self) -> None:
        report = {**REPORT_WITH_SBOM,
                  "inventory": {"all_components": [{"name": "flask", "version": "3.0.0"}]}}
        rows = gad.advisory_components(report)
        self.assertEqual([r["name"] for r in rows], ["flask", "requests"])  # pinless skipped, dup deduped

    def test_sweep_hits_and_rate_limit_early_stop(self) -> None:
        calls: list[str] = []

        def fetch(url, token):
            calls.append(url)
            if "flask" in url:
                return 200, ADVISORY_PAYLOAD
            message = "HTTP 403: rate limit"
            raise RuntimeError(message)

        with mock.patch.dict("os.environ", {"GITHUB_TOKEN": "tok-1"}, clear=False):
            result = gad.check_gad(REPORT_WITH_SBOM, checks=10, fetch=fetch)
        self.assertEqual(len(calls), 2)  # flask hit, requests hit the limit, sweep stopped
        self.assertTrue(result["rate_limited"])  # the flag that stops the sweep
        self.assertEqual(result["checked"], 1)  # only one endpoint fully answered
        self.assertEqual(len(result["hits"]), 1)  # the withdrawn advisory is excluded
        hit = result["hits"][0]
        self.assertEqual(hit["ghsa"], "GHSA-abcd-1234")  # the matching advisory
        self.assertEqual(hit["severity"], "high")  # the GHSA band
        self.assertIn("GITHUB_TOKEN", " ".join(result["errors"]))  # the token advice
        self.assertTrue(result["token"])  # the token was present

    def test_hits_sort_worst_severity_first(self) -> None:
        routes = {  # two components, two severities, arrival order irrelevant
            "flask": [{"ghsa_id": "GHSA-low-1", "severity": "LOW", "summary": "s", "withdrawn_at": None}],
            "requests": [{"ghsa_id": "GHSA-crit-1", "severity": "CRITICAL", "summary": "w", "withdrawn_at": None}],
        }

        def fetch(url, token):
            for name, payload in routes.items():
                if name in url:
                    return 200, payload
            return 200, []

        result = gad.check_gad(REPORT_WITH_SBOM, checks=10, fetch=fetch)
        severities = [hit["severity"] for hit in result["hits"]]
        self.assertEqual(severities[0], "critical")  # worst first
        self.assertEqual(severities[1], "low")


class GadButtonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = appmod.App()
        self.app._report = {**REPORT_WITH_SBOM}
        self.alerts: list[str] = []

    def tearDown(self) -> None:
        self.app.destroy()

    def test_gad_runs_without_any_sbom_by_using_the_cve_findings(self) -> None:
        report = {  # NO SBOM payload at all - findings only
            "repo": {"full_name": "acme/widget"},
            "findings": [
                {"rule_id": "CVE-2024-1234", "package": "react"},
                {"rule_id": "GHSA-py-sql", "package": "flask"},
            ],
        }
        seen_urls: list[str] = []

        def fetch(url, token):
            seen_urls.append(url)
            return 200, [{"ghsa_id": "GHSA-x", "severity": "high", "summary": "s", "withdrawn_at": None}]

        result = gad.check_gad(report, fetch=fetch)
        self.assertGreater(len(seen_urls), 0)  # lookups actually ran without any SBOM
        self.assertTrue(any("cve_id=CVE-2024-1234" in url for url in seen_urls))  # the cve tier fired
        self.assertEqual(result["hits"][0]["ghsa"], "GHSA-x")  # the hits came back

    def test_package_name_fallback_when_neither_sbom_nor_cves_exist(self) -> None:
        report = {  # findings carry package names but no versions and no CVEs
            "repo": {"full_name": "acme/widget"},
            "findings": [{"rule_id": "CKV-AWS-1", "package": "boto3"}],
        }
        seen_urls: list[str] = []

        def fetch(url, token):
            seen_urls.append(url)
            return 200, []

        gad.check_gad(report, fetch=fetch)
        self.assertTrue(any("/advisories?affects=boto3" in url for url in seen_urls))  # the loose tier

    def test_uncapped_sweep_checks_every_invoked_component(self) -> None:
        report = {"repo": {"full_name": "acme/widget"}, "sbom": {"tools": "syft",
                  "all_components": [{"name": f"pkg-{i}", "version": "1.0.0",
                                      "type": "library", "purl": f"pkg:npm/pkg-{i}@1.0.0",
                                      "file": ""} for i in range(30)]}}
        calls: list[str] = []

        def fetch(url, token):
            calls.append(url)
            return 200, []

        result = gad.check_gad(report, fetch=fetch)
        self.assertEqual(len(calls), 30)  # every component queried, no 25-cap
        self.assertEqual(result["considered"], 30)  # the honest considered count

    def test_progress_callback_fires_from_zero_to_total(self) -> None:
        report = {"repo": {"full_name": "acme/widget"}, "sbom": {"tools": "syft",
                  "all_components": [{"name": f"pkg-{i}", "version": "1.0.0",
                                      "type": "library", "purl": "pkg:npm/pkg-{i}@1.0.0",
                                      "file": ""} for i in range(5)]}}
        events: list[tuple[int, int]] = []

        def fetch(url, token):
            return 200, []

        gad.check_gad(report, fetch=fetch, progress=lambda done, total: events.append((done, total)))
        self.assertEqual(events[0], (0, 5))  # the zero state
        self.assertEqual(events[-1], (5, 5))  # the final completion
        self.assertEqual([e[0] for e in events], sorted(e[0] for e in events))  # monotone progress

    def test_button_joins_the_report_cluster(self) -> None:
        self.assertIn(self.app.gad_button, self.app._report_buttons())  # disabled until a scan lands

    def test_check_without_an_sbom_alerts_like_the_sbom_buttons(self) -> None:
        self.app._report = {"score": 90, "verdict": "SECURE"}  # no SBOM payload at all
        with mock.patch.object(appmod.messagebox, "showerror") as alert:
            self.app.check_gad()
        self.assertEqual(alert.call_count, 1)  # the error dialog fired
        self.assertIn("SBOM scan", alert.call_args[0][1])  # it names the missing prerequisite

    def test_results_open_in_a_themed_popup_with_print_and_close(self) -> None:
        import tkinter as tk
        import time

        results = {  # the finished sweep the worker would return
            "checked": 2, "considered": 2, "hits": [
                {"ghsa": "GHSA-abcd-1234", "severity": "high", "summary": "escape in widget",
                 "package": "flask@3.0.0", "url": "https://github.com/advisories/GHSA-x",
                 "published": "2024-05-01"},
            ], "errors": [], "rate_limited": False, "token": True,
        }
        self.app._show_gad_popup(results)
        deadline = time.time() + 2.0
        popup = None
        while time.time() < deadline:
            self.app.update()
            pops = [c for c in self.app.winfo_children() if isinstance(c, tk.Toplevel)]
            if pops:
                popup = pops[0]
                break
            time.sleep(0.05)
        try:
            self.assertIsNotNone(popup, "the results popup opened")
            texts: list[tk.Text] = []
            buttons: list[str] = []

            def walk(widget):
                if isinstance(widget, tk.Text):
                    texts.append(widget)
                if isinstance(widget, tk.Button):
                    buttons.append(str(widget.cget("text")))
                for kid in widget.winfo_children():
                    walk(kid)

            walk(popup)
            self.assertTrue(texts, "the hits render in a Text widget")
            content = texts[0].get("1.0", "end")
            self.assertIn("GHSA-abcd-1234", content)  # the advisory id
            self.assertIn("●", content)  # the brand markers
            self.assertIn("Print", buttons)  # the print action
            self.assertIn("Close", buttons)  # the close action
        finally:
            popup.destroy()

    def test_print_routes_through_the_writer_with_a_preset_name(self) -> None:
        from unittest import mock as _mock

        results = {"checked": 1, "considered": 1, "hits": [], "errors": [], "rate_limited": False, "token": True}
        writer_paths: list[str] = []
        with _mock.patch.object(appmod.filedialog, "asksaveasfilename",
                                return_value="C:\\tmp\\gad.pdf"), \
             _mock.patch.object(appmod.exports, "write_gad_pdf",
                                side_effect=lambda r, res, p: writer_paths.append(p) or "ok"):
            self.app._print_gad_pdf(results)
        self.assertEqual(len(writer_paths), 1)  # the writer received the dialog path


class GadPdfTests(unittest.TestCase):
    def test_pdf_writes_the_sweep_in_the_report_template(self) -> None:
        import tempfile

        results = {"checked": 2, "considered": 3, "hits": [
            {"ghsa": "GHSA-abcd-1234", "severity": "high", "summary": "escape in widget",
             "package": "flask@3.0.0", "url": "https://github.com/advisories/GHSA-abcd-1234",
             "published": "2024-05-01"},
        ], "errors": ["note one"], "rate_limited": True, "token": False}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gad.pdf"
            exports.write_gad_pdf(REPORT_WITH_SBOM, results, path)
            data = path.read_bytes()
        probe = data.decode("latin-1", errors="ignore")  # the streams are literal
        self.assertGreater(len(data), 2500)  # a real, styled document
        self.assertIn("GITHUB ADVISORY DATABASE", probe)  # the section banner
        self.assertIn("GHSA-abcd-1234", probe)  # the advisory id
        self.assertIn("rate limit", probe)  # the honest note


if __name__ == "__main__":
    unittest.main(verbosity=2)
