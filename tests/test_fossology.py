"""Tests for the FOSSology licence-compliance scanner.

The runner talks to a FOSSology server's REST v1 API (upload -> schedule ->
poll -> licence fetch); the network is faked at the ``_fossology_http``
boundary so the whole flow is exercised offline. The parser, policy and
scoring/compliance/dashboard integration are tested against the same canned
normalised report the runner would write.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config  # noqa: E402
import dashboard  # noqa: E402
import reportkeys  # noqa: E402
import scanners  # noqa: E402
import scoring  # noqa: E402
import compliance  # noqa: E402


def all_status():
    return {tool: {"status": "ok"} for tool in config.ALL_TOOLS}


# A server reply shaped like the /uploads/{id}/licenses summary: two agents
# (Nomos and Ojo) agreeing, one plausible variant shape, and one bare string.
LICENSES_REPLY = {
    "scanner": {
        "nomos": {
            "findings": {
                "app/main.go": [
                    {"license": {"name": "GPL-3.0-only"}},
                    {"license": {"name": "Apache-2.0"}},
                ],
                "vendor/lib/borrowed.c": [{"license": {"name": "LGPL-2.1-only"}}],
                "docs/schema-bin": ["NOASSERTION"],
            },
        },
        "ojo": {
            "findings": {
                "app/main.go": [{"license": {"name": "GPL-3.0-only"}}],
            },
        },
    },
}

# The upload/schedule/poll replies in REST v1 shape.
UPLOAD_REPLY = {"message": "file uploaded", "code": 201}
SCHEDULE_REPLY = {"message": "job scheduled", "jobId": 7}

policy_findings = [  # (licence name, expected severity or None)
    ("GPL-3.0-only", "high"),
    ("AGPL-3.0-or-later", "high"),
    ("GPL-2.1-only", "medium"),  # near-copyleft family
    ("LGPL-3.0", "medium"),
    ("MPL-2.0", "medium"),
    ("MIT", None),  # permissive: never a finding
    ("Apache-2.0", None),
    ("NOASSERTION", "low"),  # the server could not name a licence
    ("Zeta-Custom-TBD", "low"),  # unrecognised, not permissive
]


class PolicyTests(unittest.TestCase):
    def test_policy_severities_match_the_table(self) -> None:
        for name, expected in policy_findings:
            self.assertEqual(scoring.fossology_severity(name), expected, name)

    def test_empty_names_stay_unflagged(self) -> None:
        self.assertIsNone(scoring.fossology_severity("NULL"))
        self.assertIsNone(scoring.fossology_severity(""))


class ParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.report = self.root / "fossology.json"
        self.report.write_text(json.dumps({
            "licenses": [
                {"name": "GPL-3.0-only", "files": ["app/main.go"]},
                {"name": "LGPL-2.1-only", "files": ["vendor/lib/borrowed.c", "vendor/lib/other.c"]},
                {"name": "NOASSERTION", "files": ["docs/schema-bin"]},
                {"name": "Apache-2.0", "files": ["app/main.go"]},
            ],
            "mix": {"GPL-3.0-only": 1, "Apache-2.0": 3},
        }, indent=2), encoding="utf-8")
        (self.root / "app").mkdir()
        (self.root / "app" / "main.go").write_text("package main\n")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_flagged_families_become_findings(self) -> None:
        findings = scoring.parse_fossology_report(self.report, self.root)
        by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual(set(by_rule), {"GPL-3.0-only", "LGPL-2.1-only", "NOASSERTION"})
        self.assertEqual(by_rule["GPL-3.0-only"].severity, "high")  # strong copyleft
        self.assertEqual(by_rule["LGPL-2.1-only"].severity, "medium")
        self.assertEqual(by_rule["NOASSERTION"].severity, "low")
        for finding in findings:  # every row is a licence finding
            self.assertEqual(finding.category, "license")
            self.assertEqual(finding.source, "fossology")
        self.assertIn("app/main.go", by_rule["GPL-3.0-only"].locations[0])  # the sample path

    def test_permissive_families_only_live_in_the_mix(self) -> None:
        findings = scoring.parse_fossology_report(self.report, self.root)
        self.assertNotIn("Apache-2.0", {finding.rule_id for finding in findings})

    def test_licence_weights_come_from_the_config_table(self) -> None:
        finding = scoring.parse_fossology_report(self.report, self.root)[0]
        self.assertEqual(  # the charge reads config.WEIGHTS["license"]
            finding.weight, config.WEIGHTS["license"][finding.severity],
        )


class RunnerFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "repo"
        self.root.mkdir()
        (self.root / "app").mkdir()
        (self.root / "app" / "main.go").write_text("package main\n")
        self.artifacts = Path(self.tmp.name) / "artifacts"
        self.artifacts.mkdir()
        self.calls: list[str] = []

        def fake_http(method, url, token, *, data=b"", content_type="", cancel=None, timeout=30, what=""):
            self.calls.append(f"{method} {url}")
            if "/uploads" in url and method == "POST":
                return 201, {"location": "/api/v1/uploads/42"}, json.dumps(UPLOAD_REPLY).encode()
            if "/jobs/analysis" in url:
                return 201, {"location": "/api/v1/jobs/7"}, json.dumps(SCHEDULE_REPLY).encode()
            if "/jobs/7" in url:
                return 200, {}, json.dumps({"status": "completed", "eta": 0}).encode()
            if "/licenses" in url:
                return 200, {}, json.dumps(LICENSES_REPLY).encode()
            raise AssertionError(f"unexpected call {method} {url}")

        self._patch = mock.patch.object(scanners, "_fossology_http", fake_http)
        self._patch.start()
        self._env = mock.patch.dict(os.environ, {
            "FOSSOLOGY_SERVER": "https://foss.example/",
            "FOSSOLOGY_TOKEN": "token-1",
        })
        self._env.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self._env.stop()
        self.tmp.cleanup()

    def test_full_flow_writes_a_normalised_report(self) -> None:
        output, status = scanners.run_fossology(
            self.root, self.artifacts,
            log=lambda _msg: None, cancel=threading.Event(),
            file_paths=[self.root / "app" / "main.go"],
        )
        self.assertEqual(status["status"], "ok")
        self.assertIsNotNone(output)
        self.assertIn("POST https://foss.example/api/v1/uploads", self.calls[0])
        self.assertIn("/api/v1/jobs/analysis", " ".join(self.calls))
        self.assertIn("/api/v1/uploads/42/licenses", " ".join(self.calls))
        payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(payload["mix"]["GPL-3.0-only"], 1)
        self.assertEqual(payload["upload"], {"uploadId": 42, "jobId": 7})
        self.assertEqual(  # Apache stays a licence row (the parser decides findings)
            scoring.fossology_severity("Apache-2.0"), None,
        )

    def test_findings_flow_from_the_runner_report(self) -> None:
        output, status = scanners.run_fossology(
            self.root, self.artifacts, log=lambda _msg: None,
            cancel=threading.Event(),
            file_paths=[self.root / "app" / "main.go"],
        )
        findings = scoring.parse_fossology_report(output, self.root)
        self.assertIn("GPL-3.0-only", {finding.rule_id for finding in findings})


class UnconfiguredTests(unittest.TestCase):
    def test_unconfigured_server_reports_a_clean_skip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = {key: value for key, value in os.environ.items()
                   if key not in config.FOSSOLOGY_TOKEN_ENVS and key != config.FOSSOLOGY_SERVER_ENV}
            with mock.patch.dict(os.environ, env, clear=True):
                output, status = scanners.run_fossology(
                    Path(tmp), Path(tmp) / "artifacts",
                    log=lambda _msg: None, cancel=threading.Event(),
                )
        self.assertIsNone(output)
        self.assertEqual(status["status"], "skipped")
        self.assertIn("FOSSOLOGY_SERVER", status["details"][0])


class ScoringIntegrationTests(unittest.TestCase):
    def test_licence_category_scores_with_its_own_cap(self) -> None:
        findings = scoring.merge_findings([
            scoring.Finding("fossology", "license", "high", "GPL-3.0-only", "Licence GPL-3.0-only appears on 2 file(s)",
                            weight=scoring.weight_for("license", "high"), file="app/main.go", line=0,
                            kind="fossology.GPL-3.0-only"),
        ] + [  # a flood of low licence findings to prove the cap binds well before zero
            scoring.Finding("fossology", "license", "low", f"CUSTOM-LICENCE-{i}", "Licence row",
                            weight=scoring.weight_for("license", "low"), file="vendor/x", line=i,
                            kind=f"fossology.CUSTOM-LICENCE-{i}")
            for i in range(40)
        ])
        report = scoring.build_report(findings, scanner_status=all_status())
        self.assertEqual(report["caps"]["license"], config.CAPS["license"])  # plain cap (no context relief)
        self.assertGreater(report["score"], 80)  # a licence flood cannot bury the instrument
        self.assertNotIn("license", reportkeys.RISK_CATEGORIES)  # licence counts never veto the verdict

    def test_licence_rows_map_into_compliance_controls(self) -> None:
        finding = scoring.Finding("fossology", "license", "high", "GPL-3.0-only", "Licence GPL-3.0-only appears on 2 file(s)",
                                  weight=scoring.weight_for("license", "high"), file="app/main.go", line=0,
                                  kind="fossology.GPL-3.0-only")
        frameworks, per_finding = compliance.map_all([finding], ["iso", "nist-rmf"])
        controls = {
            row.get("id") for row in frameworks["iso"].get("controls") or []  # the control rows
            if row.get("status") == "affected"  # the mapped controls carry the licence
        }  # closes the controls build
        self.assertIn("A.5.31", controls)  # the ISO licence control
        nist = {  # the RMF payload in the same shape
            row.get("id") for row in frameworks["nist-rmf"].get("controls") or []
            if row.get("status") == "affected"  # the mapped controls carry the licence
        }  # closes the nist build
        self.assertIn("SR-4", nist)  # the RMF supply-chain control
        self.assertTrue(list(per_finding.values()))  # the per-finding map stays populated


class DashboardMixTests(unittest.TestCase):
    def test_license_mix_donut_from_dashboard_inputs(self) -> None:
        report = {
            "findings": [],
            "dashboard_inputs": {"license_mix": {"GPL-3.0-only": 7, "Apache-2.0": 40, "MIT": 120}},
        }
        payloads = dashboard.collect_metrics(report, ["license_mix"])
        payload = payloads["license_mix"]
        self.assertEqual(payload["kind"], "donut")
        names = {row[0] for row in payload["rows"]}
        self.assertIn("Apache-2.0", names)  # MIT (120) is the largest slice
        self.assertTrue(all(isinstance(row[1], int) for row in payload["rows"]))

    def test_absent_mix_is_an_honest_note(self) -> None:
        payloads = dashboard.collect_metrics({"findings": [], "dashboard_inputs": {}}, ["license_mix"])
        self.assertEqual(payloads["license_mix"]["kind"], "na")
        self.assertIn("FOSSOLOGY_SERVER", payloads["license_mix"]["note"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
