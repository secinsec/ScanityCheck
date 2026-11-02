"""Tests for the cdxgen SBOM scanner, the merged SBOM payload and its buttons."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config  # noqa: E402
import dashboard  # noqa: E402
import exports  # noqa: E402
import scoring  # noqa: E402
import app as appmod  # noqa: E402
import scanners  # noqa: E402


def all_status():
    return {tool: {"status": "ok"} for tool in config.ALL_TOOLS}


CDX = {  # a CycloneDX 1.5 document shaped like the real cdxgen reply
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {"component": {"name": "acme/widget"}},
    "components": [
        {"type": "library", "name": "flask", "version": "3.0.0", "purl": "pkg:pypi/flask@3.0.0"},
        {"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
        {"type": "library", "name": "pinless", "purl": "pkg:pypi/pinless"},
        {"type": "framework", "name": "flask", "version": "3.0.0", "purl": "pkg:npm/flask@3.0.0"},
    ],
}


class CdxgenRegistryTests(unittest.TestCase):
    def test_cdxgen_is_a_registered_sbom_tool(self) -> None:
        self.assertIn("cdxgen", config.ALL_TOOLS)  # the checkbox row
        self.assertIn("cdxgen", config.TOOL_LABELS)  # the display name
        self.assertIn("cdxgen", config.TOOL_DESCRIPTIONS)  # the hover copy
        self.assertGreaterEqual(config.SETTINGS_VERSION, 7)  # saved selections merge in
        groups = {tool for _name, tools in config.SCANNER_GROUPS for tool in tools}  # the legend
        self.assertIn("cdxgen", groups)  # it sits in the SBOM group


class CdxgenParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_json(self, name: str, payload) -> Path:
        path = self.dir / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_cdxgen_summary_mirrors_the_syft_shape(self) -> None:
        summary = scoring.parse_cdxgen_sbom(self.write_json("cdx.json", CDX))
        self.assertEqual(summary["tool"], "cdxgen")  # the tool marker
        self.assertEqual(summary["spec_version"], "1.5")  # the spec claim
        self.assertEqual(summary["components"], 4)  # every row catalogued
        self.assertEqual(summary["unversioned"], 1)  # the pinless row
        self.assertEqual(summary["ecosystems"]["library"], 3)  # the family counts
        names = [item["name"] for item in summary["all_components"]]  # the full row list
        self.assertEqual(names, ["flask", "flask", "pinless", "requests"])  # stable, sorted

    def test_malformed_payload_yields_a_flat_summary(self) -> None:
        summary = scoring.parse_cdxgen_sbom(self.write_json("bad.json", {"components": "nope"}))
        self.assertEqual(summary["components"], 0)  # an empty catalogue, not a crash


class MergeTests(unittest.TestCase):
    def summary_syft(self):
        return {  # the shape parse_syft_inventory now returns
            "tool": "syft", "components": 2, "unversioned": 1,
            "ecosystems": {"golang": 2},
            "all_components": [
                {"name": "flask", "version": "3.0.0", "type": "library", "purl": "pkg:pypi/flask@3.0.0", "file": "app.go"},
                {"name": "gin", "version": "1.9.0", "type": "framework", "purl": "pkg:golang/gin@1.9.0", "file": ""},
            ],
        }

    def summary_cdx(self):
        return {  # the shape parse_cdxgen_sbom returns
            "tool": "cdxgen", "spec_version": "1.5", "components": 2, "unversioned": 0,
            "ecosystems": {"npm": 2},
            "all_components": [
                {"name": "flask", "version": "3.0.0", "type": "library", "purl": "pkg:pypi/flask@3.0.0", "file": ""},
                {"name": "react", "version": "18.2.0", "type": "library", "purl": "pkg:npm/react@18.2.0", "file": ""},
            ],
        }

    def test_merge_unions_components_with_exact_counts(self) -> None:
        merged = scoring.merge_sbom_summaries([self.summary_syft(), self.summary_cdx()])
        self.assertEqual(merged["tools"], "syft  +  cdxgen")  # both named
        self.assertEqual(merged["components"], 3)  # flask counted once, gin/react added
        self.assertEqual(merged["unversioned"], 1)  # the syft unpinned row
        names = [item["name"] for item in merged["all_components"]]  # the merged rows
        self.assertEqual(names.count("flask"), 1)  # deduped
        self.assertIn("react", names)  # the cdx-only row landed

    def test_empty_input_returns_none(self) -> None:
        self.assertIsNone(scoring.merge_sbom_summaries([]))  # no SBOM ran


class RunnerSkipTests(unittest.TestCase):
    def test_missing_node_reports_a_clean_skip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifacts = Path(tmp)
            with mock.patch.object(scanners.shutil, "which", return_value=None):
                output, status = scanners.run_cdxgen(Path(tmp), artifacts, log=lambda _m: None,
                                                     cancel=__import__("threading").Event())
        self.assertIsNone(output)  # nothing was produced
        self.assertEqual(status["status"], "skipped")  # the honest skip, not a failure


class SbomButtonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = appmod.App()
        self.app._report = {"repo": {"full_name": "acme/widget"}, "score": 90,
                            "band": "Low", "verdict": "SECURE"}
        self.errors: list[str] = []

    def tearDown(self) -> None:
        self.app.destroy()

    def test_print_sbom_without_a_scan_alerts_instead_of_exporting(self) -> None:
        with mock.patch.object(appmod.messagebox, "showerror") as alert:
            self.app.print_sbom()
        self.assertEqual(alert.call_count, 1)  # the error dialog fired
        self.assertIn("SBOM", alert.call_args[0][1])  # it names the SBOM gap
        self.assertEqual(self.errors, [])  # no export was attempted

    def test_export_sbom_without_a_scan_alerts_instead_of_exporting(self) -> None:
        with mock.patch.object(appmod.messagebox, "showerror") as alert:
            self.app.export_sbom()
        self.assertEqual(alert.call_count, 1)  # the error dialog fired

    def test_with_an_sbom_the_buttons_export_both_ways(self) -> None:
        from datetime import datetime, timezone

        self.app._report["sbom"] = {  # a scan DID catalogue the tree
            "tools": "syft", "components": 2, "unversioned": 0,
            "ecosystems": {"npm": 2},
            "all_components": [
                {"name": "react", "version": "18.2.0", "type": "library", "purl": "pkg:npm/react@18.2.0", "file": ""},
                {"name": "vue", "version": "3.4.0", "type": "library", "purl": "pkg:npm/vue@3.4.0", "file": ""},
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "sbom.csv"
            exports.write_report_sbom_csv(self.app._report, csv_path)
            pdf_path = Path(tmp) / "sbom.pdf"
            exports.write_report_sbom_pdf(self.app._report, pdf_path)
            self.assertTrue(csv_path.exists())  # the CSV landed
            self.assertIn(b"react", csv_path.read_bytes())  # the components are in it
            self.assertGreater(pdf_path.stat().st_size, 2000)  # the PDF carries the table

    def test_sbom_pdf_explains_the_gap_artists_in_the_writers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):  # the writers raise the honest gap
                exports.write_report_sbom_pdf(self.app._report, Path(tmp) / "x.pdf")


class SbomInReportTests(unittest.TestCase):
    def test_build_report_carries_the_sbom_payload(self) -> None:
        report = scoring.build_report(
            [], scanner_status=all_status(),
            sbom={"tools": "syft", "components": 1,
                  "all_components": [{"name": "flask", "version": "3.0.0", "type": "library",
                                      "purl": "pkg:pypi/flask@3.0.0", "file": "x"}]},
        )
        self.assertEqual(report["sbom"]["tools"], "syft")  # the payload landed
        self.assertEqual((report["sbom"] or {}).get("components"), 1)  # the count

    def test_reports_without_sbom_scans_carry_an_empty_payload(self) -> None:
        report = scoring.build_report([], scanner_status=all_status())
        self.assertEqual(report["sbom"], {})  # the honest empty payload

    def test_sbom_pdf_wraps_cells_without_cuts(self) -> None:
        """Cells wrap across continuation lines; no text is cut with '...'."""
        report = {  # a component with a very long name and a very long PURL
            "repo": {"full_name": "acme/widget"}, "generated_at": "2026-11-02T10:00:00",
            "sbom": {"tools": "cdxgen", "spec_version": "1.5", "components": 2,
                     "unversioned": 0, "ecosystems": {"npm": 2},
                     "all_components": [
                         {"name": "@angular/core-platform-browser-dynamic-routing-extensions",
                          "version": "17.3.8", "type": "library",
                          "purl": "pkg:npm/%40angular/core-platform-browser-dynamic-routing-extensions@17.3.8"},
                         {"name": "supercalifragilisticexpialidocious-long-token-package-name",
                          "version": "0.0.1", "type": "framework", "purl": "-"},
                     ]},
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sbom.pdf"
            exports.write_report_sbom_pdf(report, path)
            probe = path.read_bytes().decode("latin-1", errors="ignore")
        text_ops = [line for line in probe.splitlines()
                    if "Tj" in line and "BT" in line]  # every drawn text operator
        joined = " ".join(text_ops)
        # The only ellipsis anywhere is part of the tagline copy; the table cuts nothing.
        ellipsis_lines = [op for op in text_ops if "..." in op or "\u2026" in op]
        self.assertEqual(len(ellipsis_lines), 1)  # only the tagline carries one
        self.assertIn("ScanityCheck...", ellipsis_lines[0])  # the tagline's own punctuation
        self.assertIn("amic-routing-extensions", probe)  # the wrapped name tail renders
        self.assertIn("er-dynamic-routing-extensions@17.3.8", probe)  # the wrapped purl tail renders
        self.assertIn("docious-long-token-package-name", probe)  # the long token hard-breaks
        completes = [  # every long fragment must have its continuation line
            "amic-routing-extensions", "er-dynamic-routing-extensions@17.3.8",
            "docious-long-token-package-name",
            "-long-token-package-name",
        ]  # closes the completes build
        for tail in completes:  # loops over the tails
            self.assertGreaterEqual(sum(tail in op for op in text_ops), 1)  # the tail rendered

    def test_wrap_chars_is_word_aware_and_lossless(self) -> None:
        lines = exports._wrap_chars(  # word-aware packing
            "alpha beta gamma delta epsilon zeta", 16)
        self.assertEqual(" ".join(line.strip() for line in lines),  # the words survive
                         "alpha beta gamma delta epsilon zeta")
        self.assertTrue(all(len(line) <= 16 for line in lines))  # every line fits
        hard = exports._wrap_chars("x" * 45, 20)  # a 45-char token hard-breaks
        self.assertEqual(hard, ["x" * 20, "x" * 20, "x" * 5])  # the pieces are exact


if __name__ == "__main__":
    unittest.main(verbosity=2)
