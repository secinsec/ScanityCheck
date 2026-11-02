"""Tests for the scoring model and input parsing. No network access needed."""  # keeps the docstring text

from __future__ import annotations  # imports annotations from the __future__ module

import json  # imports the json module
import sys  # imports the sys module
import tempfile  # imports the tempfile module
import unittest  # imports the unittest module
from pathlib import Path  # imports Path from the pathlib module

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # inserts text or data

import config  # noqa: E402  # imports the config module
import scanners  # noqa: E402  # imports the scanners module
import scoring  # noqa: E402  # imports the scoring module


def write_json(directory: Path, name: str, payload: dict) -> Path:  # defines the write_json() function
    path = directory / name  # copies the directory value into path
    path.write_text(json.dumps(payload), encoding="utf-8")  # writes the text file
    return path  # returns the path to the caller


TRIVY_SAMPLE = {  # assigns the computed value to TRIVY_SAMPLE
    "Results": [  # maps the Results dictionary entry
        {  # executes the statement
            "Target": "package-lock.json",  # maps the Target dictionary entry
            "Class": "lang-pkgs",  # maps the Class dictionary entry
            "Vulnerabilities": [  # maps the Vulnerabilities dictionary entry
                {  # executes the statement
                    "VulnerabilityID": "CVE-2021-23337",  # maps the VulnerabilityID dictionary entry
                    "PkgName": "lodash",  # maps the PkgName dictionary entry
                    "InstalledVersion": "4.17.20",  # maps the InstalledVersion dictionary entry
                    "FixedVersion": "4.17.21",  # maps the FixedVersion dictionary entry
                    "Severity": "CRITICAL",  # maps the Severity dictionary entry
                    "Title": "Command injection in lodash",  # maps the Title dictionary entry
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-23337",  # maps the PrimaryURL dictionary entry
                },  # closes the multiline block
                {  # executes the statement
                    "VulnerabilityID": "CVE-2021-23337",  # maps the VulnerabilityID dictionary entry
                    "PkgName": "lodash",  # maps the PkgName dictionary entry
                    "InstalledVersion": "4.17.20",  # maps the InstalledVersion dictionary entry
                    "Severity": "CRITICAL",  # maps the Severity dictionary entry
                    "Title": "Command injection in lodash",  # maps the Title dictionary entry
                },  # duplicate should be collapsed  # closes the multiline block
                {  # executes the statement
                    "VulnerabilityID": "CVE-2020-8203",  # maps the VulnerabilityID dictionary entry
                    "PkgName": "lodash",  # maps the PkgName dictionary entry
                    "InstalledVersion": "4.17.20",  # maps the InstalledVersion dictionary entry
                    "Severity": "HIGH",  # maps the Severity dictionary entry
                    "Title": "Prototype pollution in lodash",  # maps the Title dictionary entry
                },  # closes the multiline block
            ],  # closes the multiline block
        },  # closes the multiline block
        {  # executes the statement
            "Target": "config/settings.py",  # maps the Target dictionary entry
            "Class": "secret",  # maps the Class dictionary entry
            "Secrets": [  # maps the Secrets dictionary entry
                {  # executes the statement
                    "RuleID": "aws-access-key-id",  # maps the RuleID dictionary entry
                    "Title": "AWS Access Key ID",  # maps the Title dictionary entry
                    "Severity": "CRITICAL",  # maps the Severity dictionary entry
                    "StartLine": 12,  # maps the StartLine dictionary entry
                }  # closes the multiline block
            ],  # closes the multiline block
        },  # closes the multiline block
        {  # executes the statement
            "Target": "Dockerfile",  # maps the Target dictionary entry
            "Class": "config",  # maps the Class dictionary entry
            "Misconfigurations": [  # maps the Misconfigurations dictionary entry
                {  # executes the statement
                    "ID": "DS002",  # maps the ID dictionary entry
                    "Title": "Image user should not be root",  # maps the Title dictionary entry
                    "Severity": "MEDIUM",  # maps the Severity dictionary entry
                    "Status": "FAIL",  # maps the Status dictionary entry
                    "CauseMetadata": {"StartLine": 3},  # maps the CauseMetadata dictionary entry
                },  # closes the multiline block
                {  # executes the statement
                    "ID": "DS001",  # maps the ID dictionary entry
                    "Title": "Passing",  # maps the Title dictionary entry
                    "Severity": "HIGH",  # maps the Severity dictionary entry
                    "Status": "PASS",  # maps the Status dictionary entry
                },  # closes the multiline block
            ],  # closes the multiline block
        },  # closes the multiline block
    ]  # closes the multiline block
}  # closes the multiline block

SARIF_SAMPLE = {  # assigns the computed value to SARIF_SAMPLE
    "runs": [  # maps the runs dictionary entry
        {  # executes the statement
            "tool": {  # maps the tool dictionary entry
                "driver": {  # maps the driver dictionary entry
                    "name": "CodeQL",  # maps the name dictionary entry
                    "rules": [  # maps the rules dictionary entry
                        {  # executes the statement
                            "id": "py/sql-injection",  # maps the id dictionary entry
                            "name": "py/sql-injection",  # maps the name dictionary entry
                            "shortDescription": {"text": "Uncontrolled data used in SQL query"},  # maps the shortDescription dictionary entry
                            "helpUri": "https://codeql.github.com/codeql-query-help/python/py-sql-injection/",  # maps the helpUri dictionary entry
                            "properties": {  # maps the properties dictionary entry
                                "tags": ["security", "external/cwe/cwe-089"],  # maps the tags dictionary entry
                                "security-severity": "9.8",  # maps the security-severity dictionary entry
                            },  # closes the multiline block
                            "defaultConfiguration": {"level": "error"},  # maps the defaultConfiguration dictionary entry
                        },  # closes the multiline block
                        {  # executes the statement
                            "id": "py/unused-import",  # maps the id dictionary entry
                            "name": "py/unused-import",  # maps the name dictionary entry
                            "shortDescription": {"text": "Unused import"},  # maps the shortDescription dictionary entry
                            "properties": {"tags": ["maintainability"]},  # maps the properties dictionary entry
                            "defaultConfiguration": {"level": "note"},  # maps the defaultConfiguration dictionary entry
                        },  # closes the multiline block
                    ],  # closes the multiline block
                }  # closes the multiline block
            },  # closes the multiline block
            "results": [  # maps the results dictionary entry
                {  # executes the statement
                    "ruleId": "py/sql-injection",  # maps the ruleId dictionary entry
                    "level": "error",  # maps the level dictionary entry
                    "message": {"text": "This SQL query depends on a user-provided value."},  # maps the message dictionary entry
                    "locations": [  # maps the locations dictionary entry
                        {  # executes the statement
                            "physicalLocation": {  # maps the physicalLocation dictionary entry
                                "artifactLocation": {"uri": "app/db.py"},  # maps the artifactLocation dictionary entry
                                "region": {"startLine": 42},  # maps the region dictionary entry
                            }  # closes the multiline block
                        }  # closes the multiline block
                    ],  # closes the multiline block
                },  # closes the multiline block
                {  # executes the statement
                    "ruleId": "py/sql-injection",  # maps the ruleId dictionary entry
                    "level": "error",  # maps the level dictionary entry
                    "message": {"text": "This SQL query depends on a user-provided value."},  # maps the message dictionary entry
                    "locations": [  # maps the locations dictionary entry
                        {  # executes the statement
                            "physicalLocation": {  # maps the physicalLocation dictionary entry
                                "artifactLocation": {"uri": "app/db.py"},  # maps the artifactLocation dictionary entry
                                "region": {"startLine": 42},  # maps the region dictionary entry
                            }  # closes the multiline block
                        }  # closes the multiline block
                    ],  # closes the multiline block
                },  # duplicate  # closes the multiline block
                {  # executes the statement
                    "ruleId": "py/unused-import",  # maps the ruleId dictionary entry
                    "level": "note",  # maps the level dictionary entry
                    "message": {"text": "Unused import os."},  # maps the message dictionary entry
                    "locations": [  # maps the locations dictionary entry
                        {  # executes the statement
                            "physicalLocation": {  # maps the physicalLocation dictionary entry
                                "artifactLocation": {"uri": "app/db.py"},  # maps the artifactLocation dictionary entry
                                "region": {"startLine": 3},  # maps the region dictionary entry
                            }  # closes the multiline block
                        }  # closes the multiline block
                    ],  # closes the multiline block
                },  # closes the multiline block
            ],  # closes the multiline block
        }  # closes the multiline block
    ]  # closes the multiline block
}  # closes the multiline block


class RepoUrlTests(unittest.TestCase):  # defines the RepoUrlTests class
    def test_full_url(self) -> None:  # defines the test_full_url() function
        ref = scanners.parse_repo_url("https://github.com/pallets/flask")  # runs the parse_repo_url() call
        self.assertEqual((ref.owner, ref.repo), ("pallets", "flask"))  # runs the assertEqual() call

    def test_git_suffix_and_slash(self) -> None:  # defines the test_git_suffix_and_slash() function
        ref = scanners.parse_repo_url("https://github.com/pallets/flask.git/")  # runs the parse_repo_url() call
        self.assertEqual(ref.full_name, "pallets/flask")  # runs the assertEqual() call

    def test_tree_ref(self) -> None:  # defines the test_tree_ref() function
        ref = scanners.parse_repo_url("https://github.com/pallets/flask/tree/2.3.x")  # runs the parse_repo_url() call
        self.assertEqual(ref.ref, "2.3.x")  # runs the assertEqual() call

    def test_ssh_and_short_form(self) -> None:  # defines the test_ssh_and_short_form() function
        self.assertEqual(scanners.parse_repo_url("git@github.com:a/b.git").full_name, "a/b")  # runs the assertEqual() call
        self.assertEqual(scanners.parse_repo_url("a/b").full_name, "a/b")  # runs the assertEqual() call

    def test_garbage_rejected(self) -> None:  # defines the test_garbage_rejected() function
        for value in ("", "not a url", "https://gitlab.com/a/b"):  # loops over the collection
            with self.subTest(value=value), self.assertRaises(scanners.ScanError):  # opens the context for the block
                scanners.parse_repo_url(value)  # runs the parse_repo_url() call


class ParsingTests(unittest.TestCase):  # defines the ParsingTests class
    def setUp(self) -> None:  # defines the setUp() function
        self.tmp = tempfile.TemporaryDirectory()  # saves the result on tmp
        self.dir = Path(self.tmp.name)  # saves the result on dir

    def tearDown(self) -> None:  # defines the tearDown() function
        self.tmp.cleanup()  # runs the cleanup() call

    def test_trivy_dedupes_and_maps_categories(self) -> None:  # defines the test_trivy_dedupes_and_maps_categories() function
        path = write_json(self.dir, "trivy.json", TRIVY_SAMPLE)  # runs the write_json() call
        findings = scoring.parse_trivy_report(path)  # runs the parse_trivy_report() call
        categories = sorted({f.category for f in findings})  # sorts the values
        self.assertEqual(categories, ["misconfiguration", "secret", "vulnerability"])  # runs the assertEqual() call
        # Two CVEs (one duplicated), one secret, one failing misconfig (PASS filtered).
        self.assertEqual(len(findings), 4)  # runs the assertEqual() call

        by_rule = {f.rule_id: f for f in findings}  # assigns the computed value to by_rule
        self.assertEqual(by_rule["CVE-2021-23337"].severity, "critical")  # runs the assertEqual() call
        self.assertEqual(by_rule["CVE-2021-23337"].weight, 12.0)  # runs the assertEqual() call
        self.assertEqual(by_rule["aws-access-key-id"].category, "secret")  # runs the assertEqual() call
        self.assertEqual(by_rule["DS002"].category, "misconfiguration")  # runs the assertEqual() call

    def test_codeql_severity_and_quality_split(self) -> None:  # defines the test_codeql_severity_and_quality_split() function
        path = write_json(self.dir, "codeql.json", SARIF_SAMPLE)  # runs the write_json() call
        findings = scoring.parse_codeql_sarif(path, "python")  # runs the parse_codeql_sarif() call
        self.assertEqual(len(findings), 2)  # duplicate location removed  # runs the assertEqual() call

        sql = next(f for f in findings if f.rule_id == "py/sql-injection")  # runs the next() call
        self.assertEqual(sql.category, "code")  # runs the assertEqual() call
        self.assertEqual(sql.severity, "critical")  # 9.8 CVSS  # runs the assertEqual() call
        self.assertEqual(sql.location, "app/db.py:42")  # runs the assertEqual() call

        quality = next(f for f in findings if f.rule_id == "py/unused-import")  # runs the next() call
        self.assertEqual(quality.category, "code-quality")  # runs the assertEqual() call
        self.assertEqual(quality.weight, config.CODE_QUALITY_WEIGHT)  # runs the assertEqual() call


class ScoreTests(unittest.TestCase):  # defines the ScoreTests class
    def setUp(self) -> None:  # defines the setUp() function
        self.tmp = tempfile.TemporaryDirectory()  # saves the result on tmp
        self.dir = Path(self.tmp.name)  # saves the result on dir
        self.findings = scoring.parse_trivy_report(write_json(self.dir, "t.json", TRIVY_SAMPLE))  # saves the result on findings
        self.findings += scoring.parse_codeql_sarif(write_json(self.dir, "c.sarif", SARIF_SAMPLE))  # runs the parse_codeql_sarif() call
        self.ok_status = {"trivy": {"status": "ok"}, "codeql": {"status": "ok"}}  # stores the mapping on ok_status

    def tearDown(self) -> None:  # defines the tearDown() function
        self.tmp.cleanup()  # runs the cleanup() call

    def test_known_score(self) -> None:  # defines the test_known_score() function
        report = scoring.build_report(self.findings, scanner_status=self.ok_status)  # runs the build_report() call
        # vulns 12 + 6 = 18, secret 15, misconfig 1, code 10, quality 0.2
        self.assertAlmostEqual(report["raw_penalties"]["vulnerability"], 18.0)  # runs the assertAlmostEqual() call
        self.assertAlmostEqual(report["penalties"]["secret"], 15.0)  # runs the assertAlmostEqual() call
        self.assertEqual(report["score"], round(100 - (18 + 15 + 1 + 10 + 0.2)))  # runs the assertEqual() call
        self.assertEqual(report["verdict"], "INSECURE")  # runs the assertEqual() call
        self.assertIn("critical", report["verdict_reason"])  # runs the assertIn() call

    def test_clean_repo_is_secure(self) -> None:  # defines the test_clean_repo_is_secure() function
        report = scoring.build_report([], scanner_status=self.ok_status)  # runs the build_report() call
        self.assertEqual(report["score"], 100)  # runs the assertEqual() call
        self.assertEqual(report["band"], "Very Low")  # 100 sits in the green band  # runs the assertEqual() call
        self.assertEqual(report["verdict"], "SECURE")  # runs the assertEqual() call

    def test_failed_scanner_forces_insecure(self) -> None:  # defines the test_failed_scanner_forces_insecure() function
        status = {"trivy": {"status": "error"}, "codeql": {"status": "ok"}}  # assigns the computed value to status
        report = scoring.build_report([], scanner_status=status)  # runs the build_report() call
        self.assertEqual(report["verdict"], "INSECURE")  # runs the assertEqual() call
        self.assertIn("did not complete", report["verdict_reason"])  # runs the assertIn() call

    def test_caps_apply(self) -> None:  # defines the test_caps_apply() function
        findings = [  # assigns the computed value to findings
            scoring.Finding("trivy", "vulnerability", "critical", f"CVE-{i}", f"pkg{i}")  # runs the Finding() call
            for i in range(20)  # loops over the collection
        ]  # closes the multiline block
        for finding in findings:  # loops over the collection
            finding.weight = scoring.weight_for(finding.category, finding.severity)  # runs the weight_for() call
        report = scoring.build_report(findings, scanner_status=self.ok_status)  # runs the build_report() call
        self.assertAlmostEqual(report["penalties"]["vulnerability"], config.CAPS["vulnerability"])  # runs the assertAlmostEqual() call
        self.assertEqual(report["score"], 100 - int(config.CAPS["vulnerability"]))  # runs the assertEqual() call
        self.assertEqual(report["score"], 55)  # runs the assertEqual() call

    def test_score_never_negative(self) -> None:  # defines the test_score_never_negative() function
        findings = []  # assigns the computed value to findings
        for index in range(40):  # loops over the collection
            findings.append(scoring.Finding("trivy", "vulnerability", "critical", f"C{index}", "p"))  # adds an item to the list
            findings.append(scoring.Finding("trivy", "secret", "critical", f"S{index}", "p"))  # adds an item to the list
            findings.append(scoring.Finding("codeql", "code", "critical", f"Q{index}", "p"))  # adds an item to the list
        for finding in findings:  # loops over the collection
            finding.weight = scoring.weight_for(finding.category, finding.severity)  # runs the weight_for() call
        report = scoring.build_report(findings, scanner_status=self.ok_status)  # runs the build_report() call
        self.assertEqual(report["score"], 0)  # runs the assertEqual() call
        self.assertEqual(report["band"], "Critical")  # 0-19 on the new spectrum  # runs the assertEqual() call

    def test_band_scale_matches_the_spectrum(self) -> None:  # the four tick-mark bounds
        for score, label in (  # walks the documented boundaries
            (100, "Very Low"), (90, "Very Low"),  # green: 90-100
            (89, "Low"), (80, "Low"),  # light green: 80-89
            (79, "Moderate"), (70, "Moderate"),  # light yellow: 70-79
            (69, "Elevated"), (60, "Elevated"),  # yellow: 60-69
            (59, "High"), (40, "High"),  # orange: 40-59
            (39, "Very High"), (20, "Very High"),  # red: 20-39
            (19, "Critical"), (0, "Critical"),  # dark red: 0-19
        ):  # closes the walk
            self.assertEqual(scoring._band(score)[0], label)  # bands follow the screenshot scale

    def test_greatest_risks_are_grouped_and_ordered(self) -> None:  # defines the test_greatest_risks_are_grouped_and_ordered() function
        report = scoring.build_report(self.findings, scanner_status=self.ok_status)  # runs the build_report() call
        risks = report["greatest_risks"]  # copies the report value into risks
        self.assertTrue(risks)  # runs the assertTrue() call
        self.assertEqual(risks[0]["category"], "secret")  # 15 points, worst single theme  # runs the assertEqual() call
        self.assertNotIn("code-quality", [risk["category"] for risk in risks])  # runs the assertNotIn() call
        penalties = [risk["penalty"] for risk in risks]  # assigns the computed value to penalties
        self.assertEqual(penalties, sorted(penalties, reverse=True))  # runs the assertEqual() call

    def test_report_text_has_required_sections(self) -> None:  # defines the test_report_text_has_required_sections() function
        report = scoring.build_report(self.findings, scanner_status=self.ok_status)  # runs the build_report() call
        text = scoring.render_report_text(report)  # runs the render_report_text() call
        for heading in (  # loops over the collection
            "SECURITY SCORE",  # supplies the literal text
            "VERDICT",  # supplies the literal text
            "WHAT THE SCORE MEANS",  # supplies the literal text
            "GREATEST RISKS IDENTIFIED",  # supplies the literal text
            "SCANNERS",  # supplies the literal text
        ):  # closes the multiline block
            self.assertIn(heading, text)  # runs the assertIn() call
        self.assertIn("CVE-2021-23337", text)  # runs the assertIn() call


class LanguageDetectionTests(unittest.TestCase):  # defines the LanguageDetectionTests class
    def test_detects_top_two_languages(self) -> None:  # defines the test_detects_top_two_languages() function
        with tempfile.TemporaryDirectory() as tmp:  # opens the context for the block
            root = Path(tmp)  # creates the path object
            (root / "app").mkdir()  # creates the folder
            (root / "node_modules" / "lib").mkdir(parents=True)  # creates the folder
            for index in range(5):  # loops over the collection
                (root / "app" / f"m{index}.py").write_text("pass\n", encoding="utf-8")  # writes the text file
            for index in range(2):  # loops over the collection
                (root / "app" / f"w{index}.ts").write_text("export {}\n", encoding="utf-8")  # writes the text file
            (root / "node_modules" / "lib" / "ignored.ts").write_text("x\n", encoding="utf-8")  # writes the text file

            languages, counts = scanners.detect_languages(root)  # runs the detect_languages() call
            self.assertEqual(languages, ["python", "javascript-typescript"])  # runs the assertEqual() call
            self.assertEqual(counts["javascript-typescript"], 2)  # runs the assertEqual() call

    def test_workflow_only_repo_uses_actions(self) -> None:  # defines the test_workflow_only_repo_uses_actions() function
        with tempfile.TemporaryDirectory() as tmp:  # opens the context for the block
            root = Path(tmp)  # creates the path object
            (root / ".github" / "workflows").mkdir(parents=True)  # creates the folder
            (root / ".github" / "workflows" / "ci.yml").write_text("on: push\n", encoding="utf-8")  # writes the text file
            languages, _ = scanners.detect_languages(root)  # runs the detect_languages() call
            self.assertEqual(languages, ["actions"])  # runs the assertEqual() call


if __name__ == "__main__":  # runs the module entry point
    unittest.main(verbosity=2)  # runs the main() call
