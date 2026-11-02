"""Tests for Syft, Checkov, GuardDog and the CSV/PDF exporters.

Samples mirror the real JSON captured from Syft 1.55.0, Checkov 3.4.0 and
GuardDog 2.2.0. Nothing here downloads or executes a scanner.
"""

from __future__ import annotations  # imports annotations from the __future__ module

import csv  # imports the csv module
import json  # imports the json module
import sys  # imports the sys module
import tempfile  # imports the tempfile module
import unittest  # imports the unittest module
from pathlib import Path  # imports Path from the pathlib module

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # inserts text or data

import config  # noqa: E402  # imports the config module
import exports  # noqa: E402  # imports the exports module
import scoring  # noqa: E402  # imports the scoring module


def write_json(directory: Path, *parts: str, payload=None) -> Path:  # defines the write_json() function
    """Write JSON to ``directory/<parts>``; the last positional may be the payload."""  # keeps the docstring text
    if payload is None:  # evaluates the branch condition
        *parts, payload = parts  # spreads the collected values
    path = directory.joinpath(*parts)  # builds the child path
    path.parent.mkdir(parents=True, exist_ok=True)  # creates the folder
    path.write_text(json.dumps(payload), encoding="utf-8")  # writes the text file
    return path  # returns the path to the caller


SYFT_SAMPLE = {  # assigns the computed value to SYFT_SAMPLE
    "artifacts": [  # maps the artifacts dictionary entry
        {  # executes the statement
            "name": "flask",  # maps the name dictionary entry
            "version": "0.12.2",  # maps the version dictionary entry
            "type": "python",  # maps the type dictionary entry
            "language": "python",  # maps the language dictionary entry
            "purl": "pkg:pypi/flask@0.12.2",  # maps the purl dictionary entry
            "locations": [{"path": "/requirements.txt"}],  # maps the locations dictionary entry
        },  # closes the multiline block
        {  # executes the statement
            "name": "lodash",  # maps the name dictionary entry
            "version": "",  # maps the version dictionary entry
            "type": "npm",  # maps the type dictionary entry
            "language": "javascript",  # maps the language dictionary entry
            "locations": [{"path": "/package-lock.json"}],  # maps the locations dictionary entry
        },  # closes the multiline block
        {  # executes the statement
            "name": "requests",  # maps the name dictionary entry
            "version": "2.19.0",  # maps the version dictionary entry
            "type": "python",  # maps the type dictionary entry
            "language": "python",  # maps the language dictionary entry
            "locations": [{"path": "/requirements.txt"}],  # maps the locations dictionary entry
        },  # closes the multiline block
    ]  # closes the multiline block
}  # closes the multiline block

CHECKOV_SAMPLE = {  # assigns the computed value to CHECKOV_SAMPLE
    "check_type": "dockerfile",  # maps the check_type dictionary entry
    "results": {  # maps the results dictionary entry
        "failed_checks": [  # maps the failed_checks dictionary entry
            {  # executes the statement
                "check_id": "CKV_DOCKER_4",  # maps the check_id dictionary entry
                "check_name": "Ensure that COPY is used instead of ADD in Dockerfiles",  # maps the check_name dictionary entry
                "check_result": {  # maps the check_result dictionary entry
                    "result": "FAILED",  # maps the result dictionary entry
                    "results_configuration": [{"instruction": "ADD", "startline": 1}],  # maps the results_configuration dictionary entry
                },  # closes the multiline block
                "file_path": "/Dockerfile",  # maps the file_path dictionary entry
                "file_line_range": [2, 2],  # maps the file_line_range dictionary entry
                "severity": None,  # maps the severity dictionary entry
                "short_description": "Use COPY instead of ADD.",  # maps the short_description dictionary entry
                "guideline": "https://docs.prismacloud.io/example",  # maps the guideline dictionary entry
            },  # closes the multiline block
            {  # executes the statement
                "check_id": "CKV_DOCKER_2",  # maps the check_id dictionary entry
                "check_name": "Ensure that HEALTHCHECK instructions have been added",  # maps the check_name dictionary entry
                "check_result": {"result": "FAILED", "results_configuration": []},  # maps the check_result dictionary entry
                "file_path": "/Dockerfile",  # maps the file_path dictionary entry
                "file_line_range": [1, 1],  # maps the file_line_range dictionary entry
                "severity": "LOW",  # maps the severity dictionary entry
            },  # closes the multiline block
            # Same file and line as the first check, but a different policy:
            # the two must not be collapsed into one finding.
            {  # executes the statement
                "check_id": "CKV_DOCKER_9",  # maps the check_id dictionary entry
                "check_name": "Another check on the same line",  # maps the check_name dictionary entry
                "file_path": "/Dockerfile",  # maps the file_path dictionary entry
                "file_line_range": [2, 2],  # maps the file_line_range dictionary entry
                "severity": "HIGH",  # maps the severity dictionary entry
            },  # closes the multiline block
        ]  # closes the multiline block
    },  # closes the multiline block
}  # closes the multiline block

CHECKOV_SECRET_SAMPLE = {  # assigns the computed value to CHECKOV_SECRET_SAMPLE
    "check_type": "secrets",  # maps the check_type dictionary entry
    "results": {  # maps the results dictionary entry
        "failed_checks": [  # maps the failed_checks dictionary entry
            {  # executes the statement
                "check_id": "CKV_SECRET_6",  # maps the check_id dictionary entry
                "check_name": "Base64 High Entropy String",  # maps the check_name dictionary entry
                "file_path": "/app/settings.py",  # maps the file_path dictionary entry
                "file_line_range": [12, 12],  # maps the file_line_range dictionary entry
                "severity": "MEDIUM",  # maps the severity dictionary entry
            }  # closes the multiline block
        ]  # closes the multiline block
    },  # closes the multiline block
}  # closes the multiline block

GUARDDOG_SAMPLE = {  # assigns the computed value to GUARDDOG_SAMPLE
    "scans": [  # maps the scans dictionary entry
        {  # executes the statement
            "ecosystem": "pypi",  # maps the ecosystem dictionary entry
            "result": {  # maps the result dictionary entry
                "issues": 2,  # maps the issues dictionary entry
                "errors": {},  # maps the errors dictionary entry
                "path": "/repo",  # maps the path dictionary entry
                "results": {  # maps the results dictionary entry
                    "exec-base64": [  # maps the exec-base64 dictionary entry
                        {  # executes the statement
                            "location": "evil.py:2",  # maps the location dictionary entry
                            "code": "exec(base64.b64decode(...))",  # maps the code dictionary entry
                            "message": "Base64-encoded payload executed.",  # maps the message dictionary entry
                        }  # closes the multiline block
                    ],  # closes the multiline block
                    "shady-links": [  # maps the shady-links dictionary entry
                        {  # executes the statement
                            "location": "setup.py:9",  # maps the location dictionary entry
                            "code": "https://example.invalid/payload",  # maps the code dictionary entry
                            "message": "Suspicious download URL.",  # maps the message dictionary entry
                        }  # closes the multiline block
                    ],  # closes the multiline block
                    "obfuscation": [],  # maps the obfuscation dictionary entry
                },  # closes the multiline block
            },  # closes the multiline block
        },  # closes the multiline block
        {  # executes the statement
            "ecosystem": "npm",  # maps the ecosystem dictionary entry
            "result": {  # maps the result dictionary entry
                "issues": 1,  # maps the issues dictionary entry
                "errors": {},  # maps the errors dictionary entry
                "results": {  # maps the results dictionary entry
                    "exec-base64": [  # maps the exec-base64 dictionary entry
                        {  # executes the statement
                            "location": "postinstall.js:4",  # maps the location dictionary entry
                            "code": "eval(Buffer.from(...))",  # maps the code dictionary entry
                            "message": "Encoded payload in install script.",  # maps the message dictionary entry
                        }  # closes the multiline block
                    ]  # closes the multiline block
                },  # closes the multiline block
            },  # closes the multiline block
        },  # closes the multiline block
    ]  # closes the multiline block
}  # closes the multiline block


class NewParserTests(unittest.TestCase):  # defines the NewParserTests class
    def setUp(self) -> None:  # defines the setUp() function
        self.tmp = tempfile.TemporaryDirectory()  # saves the result on tmp
        self.root = Path(self.tmp.name)  # saves the result on root
        self.dir = self.root / "repo"  # saves the result on dir
        self.dir.mkdir(parents=True, exist_ok=True)  # creates the folder

    def tearDown(self) -> None:  # defines the tearDown() function
        self.tmp.cleanup()  # runs the cleanup() call

    def test_syft_inventory_summarises_components(self) -> None:  # defines the test_syft_inventory_summarises_components() function
        path = write_json(self.dir, "syft.json", SYFT_SAMPLE)  # runs the write_json() call
        inventory = scoring.parse_syft_inventory(path, self.dir)  # runs the parse_syft_inventory() call

        self.assertEqual(inventory["components"], 3)  # runs the assertEqual() call
        self.assertEqual(inventory["unversioned"], 1)  # runs the assertEqual() call
        self.assertEqual(inventory["ecosystems"]["python"], 2)  # runs the assertEqual() call
        self.assertEqual(inventory["ecosystems"]["javascript"], 1)  # runs the assertEqual() call
        names = [item["name"] for item in inventory["top_packages"]]  # assigns the computed value to names
        self.assertIn("flask", names)  # runs the assertIn() call
        self.assertNotIn("lodash", names)  # unversioned packages are not ranked  # runs the assertNotIn() call

    def test_checkov_maps_severity_location_and_distinct_checks(self) -> None:  # defines the test_checkov_maps_severity_location_and_distinct_checks() function
        path = write_json(self.dir, "checkov", "results_json.json", CHECKOV_SAMPLE)  # runs the write_json() call
        findings = scoring.parse_checkov_report(path.parent, self.dir)  # runs the parse_checkov_report() call

        self.assertEqual(len(findings), 3)  # runs the assertEqual() call
        by_id = {finding.rule_id: finding for finding in findings}  # assigns the computed value to by_id
        add = by_id["CKV_DOCKER_4"]  # copies the by_id value into add
        self.assertEqual(add.source, "checkov")  # runs the assertEqual() call
        self.assertEqual(add.category, "misconfiguration")  # runs the assertEqual() call
        self.assertEqual(add.severity, "unknown")  # runs the assertEqual() call
        self.assertEqual(add.file, "Dockerfile")  # runs the assertEqual() call
        self.assertEqual(add.location, "Dockerfile:2")  # runs the assertEqual() call
        self.assertEqual(add.kind, "CKV_DOCKER_4")  # runs the assertEqual() call

        self.assertEqual(by_id["CKV_DOCKER_2"].severity, "low")  # runs the assertEqual() call
        self.assertEqual(by_id["CKV_DOCKER_9"].severity, "high")  # runs the assertEqual() call

    def test_checkov_directory_merges_multiple_frameworks_and_secrets(self) -> None:  # defines the test_checkov_directory_merges_multiple_frameworks_and_secrets() function
        write_json(self.dir, "checkov", "results_json.json", CHECKOV_SAMPLE)  # runs the write_json() call
        write_json(self.dir, "checkov", "results_secrets_json.json", CHECKOV_SECRET_SAMPLE)  # runs the write_json() call
        findings = scoring.parse_checkov_report(self.dir / "checkov", self.dir)  # runs the parse_checkov_report() call
        self.assertEqual(len(findings), 4)  # runs the assertEqual() call
        secret = next(f for f in findings if f.rule_id == "CKV_SECRET_6")  # runs the next() call
        self.assertEqual(secret.category, "secret")  # runs the assertEqual() call
        self.assertEqual(secret.file, "app/settings.py")  # runs the assertEqual() call
        self.assertEqual(secret.location, "app/settings.py:12")  # runs the assertEqual() call

    def test_guarddog_parses_both_ecosystems_and_keeps_files_apart(self) -> None:  # defines the test_guarddog_parses_both_ecosystems_and_keeps_files_apart() function
        path = write_json(self.dir, "guarddog.json", GUARDDOG_SAMPLE)  # runs the write_json() call
        findings = scoring.parse_guarddog_report(path, self.dir)  # runs the parse_guarddog_report() call

        self.assertEqual(len(findings), 3)  # runs the assertEqual() call
        execs = [f for f in findings if f.rule_id.endswith("exec-base64")]  # checks the text suffix
        self.assertEqual(len(execs), 2)  # same rule, different files  # runs the assertEqual() call
        self.assertEqual({f.file for f in execs}, {"evil.py", "postinstall.js"})  # runs the assertEqual() call
        self.assertTrue(all(f.severity == "critical" for f in execs))  # runs the assertTrue() call

        shady = next(f for f in findings if "shady-links" in f.rule_id)  # runs the next() call
        self.assertEqual(shady.severity, "high")  # runs the assertEqual() call
        self.assertEqual(shady.category, "vulnerability")  # runs the assertEqual() call
        self.assertEqual(shady.location, "setup.py:9")  # runs the assertEqual() call
        self.assertIn("Suspicious download URL", shady.detail)  # runs the assertIn() call

        # The same rule in different files must be charged separately.
        self.assertEqual(len(scoring.merge_findings(execs)), 2)  # runs the assertEqual() call


class ExportTests(unittest.TestCase):  # defines the ExportTests class
    def _report(self) -> dict:  # defines the _report() function
        finding = scoring.Finding(  # runs the Finding() call
            "checkov",  # supplies the literal text
            "misconfiguration",  # supplies the literal text
            "high",  # supplies the literal text
            "CKV_DOCKER_4",  # supplies the literal text
            "Use COPY, not ADD",  # supplies the literal text
            location="Dockerfile:2",  # sets the location text
            file="Dockerfile",  # sets the file text
            line=2,  # assigns the computed value to line
            detail="The Dockerfile uses ADD with a remote URL.",  # sets the detail text
            reference="https://example.invalid/rule",  # sets the reference text
            weight=scoring.weight_for("misconfiguration", "high"),  # runs the weight_for() call
            kind="CKV_DOCKER_4",  # sets the kind text
        )  # closes the multiline block
        return scoring.build_report(  # returns the scoring.build_report to the caller
            [finding],  # executes the statement
            repo={"full_name": "owner/repo", "description": "Demo"},  # assigns the computed value to repo
            scanner_status={  # assigns the computed value to scanner_status
                "trivy": {"status": "ok", "duration_seconds": 1.0},  # maps the trivy dictionary entry
                "codeql": {"status": "ok", "duration_seconds": 2.0},  # maps the codeql dictionary entry
                "checkov": {"status": "ok", "duration_seconds": 0.5},  # maps the checkov dictionary entry
            },  # closes the multiline block
            inventory=scoring.parse_syft_inventory(  # runs the parse_syft_inventory() call
                write_json(  # runs the write_json() call
                    Path(tempfile.mkdtemp()),  # runs the Path() call
                    "syft.json",  # supplies the literal text
                    SYFT_SAMPLE,  # evaluates the SYFT_SAMPLE expression
                )  # closes the multiline block
            ),  # closes the multiline block
        )  # closes the multiline block

    def test_csv_has_bom_header_and_one_row_per_finding(self) -> None:  # defines the test_csv_has_bom_header_and_one_row_per_finding() function
        with tempfile.TemporaryDirectory() as tmp:  # opens the context for the block
            path = Path(tmp) / "report.csv"  # creates the path object
            exports.write_report_csv(self._report(), path)  # runs the write_report_csv() call
            raw = path.read_bytes()  # reads the file as raw bytes
            self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))  # runs the assertTrue() call
            rows = list(csv.reader(raw.decode("utf-8-sig").splitlines()))  # builds the list collection
            self.assertEqual(rows[0][0], "Severity")  # runs the assertEqual() call
            self.assertEqual(rows[0][3], "Tools")  # runs the assertEqual() call
            self.assertEqual(len(rows), 2)  # runs the assertEqual() call
            self.assertEqual(rows[1][0], "HIGH")  # runs the assertEqual() call
            self.assertEqual(rows[1][2], "Use COPY, not ADD")  # runs the assertEqual() call
            self.assertEqual(rows[1][3], "Checkov")  # runs the assertEqual() call
            self.assertIn("Dockerfile:2", rows[1])  # runs the assertIn() call

    def test_pdf_is_a_well_formed_document(self) -> None:  # defines the test_pdf_is_a_well_formed_document() function
        with tempfile.TemporaryDirectory() as tmp:  # opens the context for the block
            path = Path(tmp) / "report.pdf"  # creates the path object
            exports.write_report_pdf(self._report(), path)  # runs the write_report_pdf() call
            raw = path.read_bytes()  # reads the file as raw bytes
            self.assertTrue(raw.startswith(b"%PDF-1.4"))  # runs the assertTrue() call
            self.assertTrue(raw.rstrip().endswith(b"%%EOF"))  # runs the assertTrue() call
            self.assertIn(b"/Type /Catalog", raw)  # runs the assertIn() call
            self.assertIn(b"/Type /Page", raw)  # runs the assertIn() call
            self.assertIn(b"xref", raw)  # runs the assertIn() call
            self.assertTrue(b"SECURE" in raw or b"INSECURE" in raw)  # runs the assertTrue() call

    def test_report_text_contains_inventory_and_new_tools(self) -> None:  # defines the test_report_text_contains_inventory_and_new_tools() function
        text = scoring.render_report_text(self._report())  # runs the render_report_text() call
        self.assertIn("SBOM INVENTORY (SYFT)", text)  # runs the assertIn() call
        self.assertIn("flask", text)  # runs the assertIn() call
        self.assertIn("Checkov", text)  # runs the assertIn() call


class RegistryTests(unittest.TestCase):  # defines the RegistryTests class
    def test_new_scanners_are_selectable_and_settings_bumped(self) -> None:  # defines the test_new_scanners_are_selectable_and_settings_bumped() function
        for tool in ("syft", "checkov", "guarddog"):  # loops over the collection
            self.assertIn(tool, config.ALL_TOOLS)  # runs the assertIn() call
            self.assertIn(tool, config.TOOL_LABELS)  # runs the assertIn() call
        self.assertGreaterEqual(config.SETTINGS_VERSION, 3)  # runs the assertGreaterEqual() call


if __name__ == "__main__":  # runs the module entry point
    unittest.main(verbosity=2)  # runs the main() call
