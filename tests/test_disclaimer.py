"""Tests for the pre-launch legal disclaimer gate.

Building the gate is separated from its mainloop so the whole flow — including
the "closed without agreeing" path and the acceptance-stamp merge — is testable
offline with a fake screen.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config  # noqa: E402
import app as appmod  # noqa: E402


class DisclaimerScreenTests(unittest.TestCase):
    def test_screen_carries_the_full_text_read_only(self) -> None:
        import tkinter as tk

        gate = tk.Tk()
        gate.withdraw()  # keeps the test window off the screen
        try:
            calls: list[bool] = []
            appmod._build_disclaimer_screen(gate, lambda agreed: calls.append(agreed))
            gate.update_idletasks()
            texts = []  # walk the widget tree for the one read-only Text widget
            # walk the widget tree for the one read-only Text widget
            found: list[tk.Text] = []

            def walk(widget):
                if isinstance(widget, tk.Text):
                    found.append(widget)
                for kid in widget.winfo_children():
                    walk(kid)

            walk(gate)
            self.assertEqual(len(found), 1, "the disclaimer body is one Text widget")
            body = found[0]
            self.assertEqual(body.cget("state"), "disabled")  # it is not an editor
            self.assertIn("Legal Disclaimer & Authorized Use:", body.get("1.0", "end"))  # the heading
            self.assertIn("solely responsible", body.get("1.0", "end"))  # the authorisation clause
            self.assertIn("assume no liability", body.get("1.0", "end"))  # the closing clause
            self.assertEqual(calls, [])  # nothing accepts without the user
        finally:
            gate.destroy()


class GateFlowTests(unittest.TestCase):
    def _run_gate(self, agreed: bool) -> bool:
        """Drive _show_disclaimer_gate with a screen that presses itself."""
        with mock.patch.object(appmod, "_build_disclaimer_screen") as build:
            build.side_effect = lambda gate, on_accept: on_accept(agreed)

            def stamp(version):  # traces the acceptance record
                stamp.calls.append(version)

            stamp.calls = []
            with mock.patch.object(appmod, "_record_disclaimer_acceptance", side_effect=stamp):
                result = appmod._show_disclaimer_gate()
        return result, stamp.calls

    def test_agreement_returns_true_and_stamps_the_settings(self) -> None:
        result, stamps = self._run_gate(True)
        self.assertTrue(result)  # consent only flows through the button
        self.assertEqual(stamps, [config.LEGAL_DISCLAIMER_VERSION])  # the version stamp was recorded

    def test_a_decline_never_stamps_anything(self) -> None:
        result, stamps = self._run_gate(False)
        self.assertFalse(result)  # the closed gate is a refusal
        self.assertEqual(stamps, [])  # no acceptance was recorded


class AcceptanceStampTests(unittest.TestCase):
    def test_stamp_merges_into_existing_settings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp)
            settings = cache / "settings.json"
            settings.write_text(json.dumps({"tools": ["codeql"], "last_url": "https://x"}), encoding="utf-8")
            with mock.patch.object(config, "SETTINGS_FILE", settings), \
                 mock.patch.object(config, "CACHE_DIR", cache):
                appmod._record_disclaimer_acceptance(config.LEGAL_DISCLAIMER_VERSION)
            payload = json.loads(settings.read_text(encoding="utf-8"))
            self.assertEqual(payload["tools"], ["codeql"])  # prior choices survived the merge
            self.assertEqual(payload["last_url"], "https://x")  # prior choices survived the merge
            self.assertIn("disclaimer_accepted_at", payload)  # the acceptance went into the file
            self.assertEqual(payload["disclaimer_version"], config.LEGAL_DISCLAIMER_VERSION)  # versioned


if __name__ == "__main__":
    unittest.main(verbosity=2)
