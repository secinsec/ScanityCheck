"""Tests for Nuclei, Kubescape, OpenSSF Scorecard and OSS-Fuzz.

Samples mirror the real shapes captured from Nuclei 3.11.1, Kubescape v4
posture output, the public scorecard.dev API and the synthetic OSS-Fuzz
coverage document the runner writes. Nothing here downloads or executes a
scanner, and no network access is needed.
"""

from __future__ import annotations  # imports annotations from the __future__ module

import json  # imports the json module
import sys  # imports the sys module
import tempfile  # imports the tempfile module
import unittest  # imports the unittest module
from pathlib import Path  # imports Path from the pathlib module

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # inserts text or data

import config  # noqa: E402  # imports the config module
import scoring  # noqa: E402  # imports the scoring module


def write_json(directory: Path, name: str, payload) -> Path:  # defines the write_json() function
    path = directory / name  # copies the directory value into path
    path.write_text(json.dumps(payload), encoding="utf-8")  # writes the text file
    return path  # returns the path to the caller


def write_text(directory: Path, name: str, text: str) -> Path:  # defines the write_text() function
    path = directory / name  # copies the directory value into path
    path.write_text(text, encoding="utf-8")  # writes the text file
    return path  # returns the path to the caller


NUCLEI_JSONL = "\n".join(  # joins the collected lines
    [
        json.dumps(  # builds a critical CVE template hit
            {  # executes the statement
                "template-id": "CVE-2021-44228",  # maps the template-id dictionary entry
                "info": {  # maps the info dictionary entry
                    "name": "Apache Log4j2 JNDI RCE",  # maps the name dictionary entry
                    "severity": "critical",  # maps the severity dictionary entry
                    "reference": [  # maps the reference dictionary entry
                        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"  # supplies the literal text
                    ],  # closes the multiline block
                    "classification": {  # maps the classification dictionary entry
                        "cve-id": ["CVE-2021-44228"],  # maps the cve-id dictionary entry
                        "cwe-id": ["CWE-502"],  # maps the cwe-id dictionary entry
                    },  # closes the multiline block
                },  # closes the multiline block
                "matcher-status": True,  # maps the matcher-status dictionary entry
                "matched-at": "https://demo.example.com:8443/page",  # maps the matched-at dictionary entry
                "host": "https://demo.example.com:8443",  # maps the host dictionary entry
                "url": "https://demo.example.com:8443",  # maps the url dictionary entry
                "type": "http",  # maps the type dictionary entry
            }  # closes the multiline block
        ),  # closes the multiline block
        json.dumps(  # builds a low, no-CVE template hit
            {  # executes the statement
                "template-id": "missing-security-headers",  # maps the template-id dictionary entry
                "info": {"name": "Missing security header", "severity": "low"},  # maps the info dictionary entry
                "matcher-status": True,  # maps the matcher-status dictionary entry
                "matched-at": "http://demo.example.com/index",  # maps the matched-at dictionary entry
            }  # closes the multiline block
        ),  # closes the multiline block
        # Duplicate of the first hit: must be de-duplicated per template+host.
        json.dumps(  # builds the duplicate first hit
            {  # executes the statement
                "template-id": "CVE-2021-44228",  # maps the template-id dictionary entry
                "info": {"name": "Apache Log4j2 JNDI RCE", "severity": "critical"},  # maps the info dictionary entry
                "matcher-status": True,  # maps the matcher-status dictionary entry
                "matched-at": "https://demo.example.com:8443/again",  # maps the matched-at dictionary entry
            }  # closes the multiline block
        ),  # closes the multiline block
        # Non-matching template line: must be skipped entirely.
        json.dumps(  # builds a non-matching hit
            {  # executes the statement
                "template-id": "tech-detect",  # maps the template-id dictionary entry
                "info": {"name": "Tech detect", "severity": "info"},  # maps the info dictionary entry
                "matcher-status": False,  # maps the matcher-status dictionary entry
                "matched-at": "http://demo.example.com/",  # maps the matched-at dictionary entry
            }  # closes the multiline block
        ),  # closes the multiline block
        # A hit without matched-at: host and url are the fallbacks.
        json.dumps(  # builds a host-only hit
            {  # executes the statement
                "template-id": "tech-detect",  # maps the template-id dictionary entry
                "info": {"name": "Tech detection", "severity": "info"},  # maps the info dictionary entry
                "matcher-status": True,  # maps the matcher-status dictionary entry
                "host": "demo.example.com",  # maps the host dictionary entry
                "url": "http://demo.example.com",  # maps the url dictionary entry
            }  # closes the multiline block
        ),  # closes the multiline block
        "this line is not JSON at all",  # the parser must tolerate dirty lines  # supplies the literal text
    ]  # closes the multiline block
) + "\n"  # closes the join

KUBESCAPE_SAMPLE = {  # assigns the computed value to KUBESCAPE_SAMPLE
    "results": [  # maps the results dictionary entry
        {  # executes the statement
            "conclusions": {"postureScore": 42.0},  # ignored shape  # maps the conclusions dictionary entry
            "results": {  # maps the results dictionary entry
                "posture": {  # maps the posture dictionary entry
                    "frameworks": [  # maps the frameworks dictionary entry
                        {  # executes the statement
                            "name": "NSA",  # maps the name dictionary entry
                            "controls": [  # maps the controls dictionary entry
                                {  # failed critical with resource context  # executes the statement
                                    "id": "C-0016",  # maps the id dictionary entry
                                    "name": "Container root allowed",  # maps the name dictionary entry
                                    "severity": "Critical",  # maps the severity dictionary entry
                                    "ruleStatus": "Failed",  # maps the ruleStatus dictionary entry
                                    "messages": [  # maps the messages dictionary entry
                                        "Container is not set to run as root"  # supplies the literal text
                                    ],  # closes the multiline block
                                    "object": {  # maps the object dictionary entry
                                        "kind": "Deployment",  # maps the kind dictionary entry
                                        "namespace": "prod",  # maps the namespace dictionary entry
                                        "name": "api",  # maps the name dictionary entry
                                    },  # closes the multiline block
                                },  # closes the multiline block
                                {  # failed important, path-based location  # executes the statement
                                    "id": "C-0076",  # maps the id dictionary entry
                                    "name": "Resource limits",  # maps the name dictionary entry
                                    "severity": "Important",  # maps the severity dictionary entry
                                    "status": "FailedEvidence",  # maps the status dictionary entry
                                    "reason": "No CPU/memory limits set.",  # maps the reason dictionary entry
                                    "path": "/work/k8s/deployment.yaml",  # maps the path dictionary entry
                                },  # closes the multiline block
                                {  # passed control: must never become a finding  # executes the statement
                                    "id": "C-0051",  # maps the id dictionary entry
                                    "name": "Immutable file systems",  # maps the name dictionary entry
                                    "severity": "Low",  # maps the severity dictionary entry
                                    "ruleStatus": "Success",  # maps the ruleStatus dictionary entry
                                },  # closes the multiline block
                            ],  # closes the multiline block
                        },  # closes the multiline block
                        {  # second framework re-reports the same control  # executes the statement
                            "name": "MITRE",  # maps the name dictionary entry
                            "controls": [  # maps the controls dictionary entry
                                {  # duplicate: same control, same resource  # executes the statement
                                    "id": "C-0016",  # maps the id dictionary entry
                                    "name": "Container root allowed",  # maps the name dictionary entry
                                    "severity": "Critical",  # maps the severity dictionary entry
                                    "ruleStatus": "Failed",  # maps the ruleStatus dictionary entry
                                    "object": {  # maps the object dictionary entry
                                        "kind": "Deployment",  # maps the kind dictionary entry
                                        "namespace": "prod",  # maps the namespace dictionary entry
                                        "name": "api",  # maps the name dictionary entry
                                    },  # closes the multiline block
                                },  # closes the multiline block
                            ],  # closes the multiline block
                        },  # closes the multiline block
                    ],  # closes the multiline block
                },  # closes the multiline block
            },  # closes the multiline block
        },  # closes the multiline block
    ],  # closes the multiline block
    "controlsFailed": 2,  # bare summary counters are ignored  # maps the controlsFailed dictionary entry
}  # closes the multiline block

SCORECARD_SAMPLE = {  # assigns the computed value to SCORECARD_SAMPLE
    "date": "2026-03-01",  # maps the date dictionary entry
    "repo": {"name": "github.com/owner/repo", "commit": "abc123"},  # maps the repo dictionary entry
    "score": 7.1,  # maps the score dictionary entry
    "checks": [  # maps the checks dictionary entry
        {  # a 0 score is the worst rating  # executes the statement
            "name": "Maintained",  # maps the name dictionary entry
            "score": 0,  # maps the score dictionary entry
            "reason": "repo last touched years ago",  # maps the reason dictionary entry
            "details": [  # maps the details dictionary entry
                "Warn: last commit was 400 days ago",  # supplies the literal text
                "Info: no recent release",  # supplies the literal text
                "Debug: internal note",  # supplies the literal text
                "Warn: stale issues",  # supplies the literal text
                "Warn: too much to list",  # supplies the literal text
                "Warn: past the four-note cap",  # beyond the four-note cap  # supplies the literal text
            ],  # closes the multiline block
            "documentation": {  # maps the documentation dictionary entry
                "url": "https://pkg.go.dev/github.com/ossf/scorecard/checks",  # maps the url dictionary entry
                "short": "Check if the repository is actively maintained",  # supplies the literal text
            },  # closes the multiline block
        },  # closes the multiline block
        {  # a mid-range failing check  # executes the statement
            "name": "Code-Review",  # maps the name dictionary entry
            "score": 5,  # maps the score dictionary entry
            "reason": "some recent changesets lack review",  # maps the reason dictionary entry
            "details": None,  # optional field  # maps the details dictionary entry
            "documentation": {"url": "https://pkg.go.dev/review", "short": "Code review"},  # maps the documentation dictionary entry
        },  # closes the multiline block
        {  # passing checks never become findings  # executes the statement
            "name": "Binary-Artifacts",  # maps the name dictionary entry
            "score": 9,  # maps the score dictionary entry
            "reason": "no binary artifacts in the repo",  # maps the reason dictionary entry
        },  # closes the multiline block
        {  # perfect score: ignored  # executes the statement
            "name": "Security-Policy",  # maps the name dictionary entry
            "score": 10,  # maps the score dictionary entry
            "reason": "security policy file found",  # maps the reason dictionary entry
        },  # closes the multiline block
    ],  # closes the multiline block
}  # closes the multiline block

OSSFUZZ_FUZZED = {  # assigns the computed value to OSSFUZZ_FUZZED
    "fuzzed": True,  # maps the fuzzed dictionary entry
    "project": "flask",  # maps the project dictionary entry
    "engines": ["libfuzzer"],  # maps the engines dictionary entry
    "sanitizers": ["address"],  # maps the sanitizers dictionary entry
    "note": "flask is registered in google/oss-fuzz and is continuously fuzzed.",  # maps the note dictionary entry
}  # closes the multiline block

OSSFUZZ_NOT_FUZZED = {  # assigns the computed value to OSSFUZZ_NOT_FUZZED
    "fuzzed": False,  # maps the fuzzed dictionary entry
    "note": "flask is not registered in google/oss-fuzz",  # maps the note dictionary entry
}  # closes the multiline block


class NucleiParserTests(unittest.TestCase):  # defines the NucleiParserTests class
    def setUp(self) -> None:  # defines the setUp() function
        self.tmp = tempfile.TemporaryDirectory()  # saves the result on tmp
        self.root = Path(self.tmp.name)  # saves the result on root
        self.dir = self.root / "repo"  # saves the result on dir
        self.dir.mkdir(parents=True, exist_ok=True)  # creates the folder

    def tearDown(self) -> None:  # defines the tearDown() function
        self.tmp.cleanup()  # runs the cleanup() call

    def test_nuclei_categories_severity_hosts_and_dedupe(self) -> None:  # defines the test_nuclei_categories_severity_hosts_and_dedupe() function
        path = write_text(self.dir, "nuclei.jsonl", NUCLEI_JSONL)  # runs the write_text() call
        findings = scoring.parse_nuclei_report(path, self.dir)  # runs the parse_nuclei_report() call

        # 3 hits survive: the CVE template, the header check and tech-detect.
        self.assertEqual(len(findings), 3)  # runs the assertEqual() call
        self.assertEqual(all(f.source == "nuclei" for f in findings), True)  # runs the assertEqual() call

        log4j = next(f for f in findings if f.rule_id == "CVE-2021-44228")  # runs the next() call
        self.assertEqual(log4j.category, "vulnerability")  # a CVE makes it a vuln  # runs the assertEqual() call
        self.assertEqual(log4j.severity, "critical")  # runs the assertEqual() call
        self.assertEqual(log4j.cwe, "CWE-502")  # runs the assertEqual() call
        self.assertEqual(log4j.file, "demo.example.com:8443")  # host:port extraction  # runs the assertEqual() call
        self.assertEqual(log4j.location, "demo.example.com:8443/page")  # scheme stripped  # runs the assertEqual() call
        self.assertEqual(log4j.line, 0)  # remote findings have no line  # runs the assertEqual() call
        self.assertEqual(log4j.reference, "https://nvd.nist.gov/vuln/detail/CVE-2021-44228")  # runs the assertEqual() call
        self.assertEqual(log4j.kind, "CVE-2021-44228")  # runs the assertEqual() call

        headers = next(f for f in findings if f.rule_id == "missing-security-headers")  # runs the next() call
        self.assertEqual(headers.category, "misconfiguration")  # no CVE, so not a vuln  # runs the assertEqual() call
        self.assertEqual(headers.severity, "low")  # runs the assertEqual() call
        self.assertEqual(headers.file, "demo.example.com")  # runs the assertEqual() call

        # A second hit of the same template on the same host collapses.
        self.assertEqual(len([f for f in findings if f.rule_id == "CVE-2021-44228"]), 1)  # runs the assertEqual() call

    def test_nuclei_info_severity_becomes_unknown(self) -> None:  # defines the test_nuclei_info_severity_becomes_unknown() function
        path = write_text(self.dir, "nuclei.jsonl", NUCLEI_JSONL)  # runs the write_text() call
        findings = scoring.parse_nuclei_report(path)  # runs the parse_nuclei_report() call
        detect = next(f for f in findings if f.rule_id == "tech-detect")  # runs the next() call
        self.assertEqual(detect.severity, "unknown")  # "info" ratings are unknown  # runs the assertEqual() call
        self.assertEqual(detect.file, "demo.example.com")  # host/url fallback still resolves  # runs the assertEqual() call


class KubescapeParserTests(unittest.TestCase):  # defines the KubescapeParserTests class
    def setUp(self) -> None:  # defines the setUp() function
        self.tmp = tempfile.TemporaryDirectory()  # saves the result on tmp
        self.root = Path(self.tmp.name)  # saves the result on root
        self.dir = self.root / "my-repo"  # saves the result on dir
        self.dir.mkdir(parents=True, exist_ok=True)  # creates the folder

    def tearDown(self) -> None:  # defines the tearDown() function
        self.tmp.cleanup()  # runs the cleanup() call

    def test_kubescape_failed_controls_only_with_kubescape_severities(self) -> None:  # defines the test_kubescape_failed_controls_only_with_kubescape_severities() function
        path = write_json(self.dir, "kubescape.json", KUBESCAPE_SAMPLE)  # runs the write_json() call
        findings = scoring.parse_kubescape_report(path, self.dir)  # runs the parse_kubescape_report() call

        # The passed control, the summary counter and the duplicate must all
        # disappear: one finding per unique failed control.
        self.assertEqual(len(findings), 2)  # runs the assertEqual() call
        by_id = {finding.rule_id: finding for finding in findings}  # assigns the computed value to by_id

        root_check = by_id["C-0016"]  # copies the by_id value into root_check
        self.assertEqual(root_check.category, "misconfiguration")  # runs the assertEqual() call
        self.assertEqual(root_check.severity, "critical")  # runs the assertEqual() call
        self.assertEqual(root_check.title, "Container root allowed")  # runs the assertEqual() call
        self.assertEqual(root_check.file, "Deployment/prod/api")  # nested object context  # runs the assertEqual() call
        self.assertEqual(root_check.line, 0)  # runs the assertEqual() call
        self.assertEqual(root_check.kind, "kubescape")  # runs the assertEqual() call
        self.assertIn("not set to run as root", root_check.detail)  # first failed message  # runs the assertIn() call

        limits = by_id["C-0076"]  # copies the by_id value into limits
        self.assertEqual(limits.severity, "high")  # Kubescape Important maps to high  # runs the assertEqual() call
        self.assertEqual(limits.file, "work/k8s/deployment.yaml")  # relative path  # runs the assertEqual() call
        self.assertIn("No CPU/memory limits", limits.detail)  # reason fallback  # runs the assertIn() call

    def test_kubescape_file_falls_back_to_scan_root(self) -> None:  # defines the test_kubescape_file_falls_back_to_scan_root() function
        path = write_json(self.dir, "kubescape.json", {  # runs the write_json() call
            "controlsFailed": 1,  # maps the controlsFailed dictionary entry
            "results": [  # maps the results dictionary entry
                {  # executes the statement
                    "controls": [  # maps the controls dictionary entry
                        {  # flat v2-ish shape with no resource context  # executes the statement
                            "controlID": "C-0120",  # maps the controlID dictionary entry
                            "controlName": "Privilege escalation",  # maps the controlName dictionary entry
                            "severity": "Medium",  # maps the severity dictionary entry
                            "ruleStatus": "Failed",  # maps the ruleStatus dictionary entry
                            "messages": ["Host mount present."],  # maps the messages dictionary entry
                        },  # closes the multiline block
                    ],  # closes the multiline block
                },  # closes the multiline block
            ],  # closes the multiline block
        })  # closes the multiline block
        findings = scoring.parse_kubescape_report(path, self.dir)  # runs the parse_kubescape_report() call

        self.assertEqual(len(findings), 1)  # runs the assertEqual() call
        finding = findings[0]  # copies the findings[0] value into finding
        self.assertEqual(finding.file, "my-repo")  # without a resource: scan-root name  # runs the assertEqual() call
        self.assertEqual(finding.title, "Privilege escalation")  # controlName used  # runs the assertEqual() call
        self.assertEqual(finding.severity, "medium")  # runs the assertEqual() call

    def test_kubescape_unknown_shapes_are_tolerated(self) -> None:  # defines the test_kubescape_unknown_shapes_are_tolerated() function
        path = write_json(self.dir, "kubescape.json", {"unexpected": {"deep": [1, 2, None]}})  # runs the write_json() call
        self.assertEqual(scoring.parse_kubescape_report(path), [])  # runs the assertEqual() call
        empty = self.dir / "empty.json"  # copies the self.dir value into empty
        empty.write_text("", encoding="utf-8")  # writes the text file
        self.assertEqual(scoring.parse_kubescape_report(empty), [])  # runs the assertEqual() call


class ScorecardParserTests(unittest.TestCase):  # defines the ScorecardParserTests class
    def setUp(self) -> None:  # defines the setUp() function
        self.tmp = tempfile.TemporaryDirectory()  # saves the result on tmp
        self.root = Path(self.tmp.name)  # saves the result on root
        self.dir = self.root / "repo"  # saves the result on dir
        self.dir.mkdir(parents=True, exist_ok=True)  # creates the folder

    def tearDown(self) -> None:  # defines the tearDown() function
        self.tmp.cleanup()  # runs the cleanup() call

    def test_scorecard_only_failing_checks_become_findings(self) -> None:  # defines the test_scorecard_only_failing_checks_become_findings() function
        path = write_json(self.dir, "scorecard.json", SCORECARD_SAMPLE)  # runs the write_json() call
        findings = scoring.parse_scorecard_report(path, self.dir)  # runs the parse_scorecard_report() call

        # Scores 9 and 10 are healthy: only the 0 and the 5 remain.
        self.assertEqual(len(findings), 2)  # runs the assertEqual() call
        by_name = {finding.rule_id: finding for finding in findings}  # assigns the computed value to by_name

        maintained = by_name["Maintained"]  # copies the by_name value into maintained
        self.assertEqual(maintained.category, "misconfiguration")  # runs the assertEqual() call
        self.assertEqual(maintained.severity, "medium")  # a 0 is the worst score  # runs the assertEqual() call
        self.assertEqual(maintained.title, "Maintained 0/10")  # runs the assertEqual() call
        self.assertEqual(maintained.file, "")  # repository-level signal  # runs the assertEqual() call
        self.assertEqual(maintained.line, 0)  # runs the assertEqual() call
        self.assertEqual(maintained.kind, "scorecard.Maintained")  # unique per check  # runs the assertEqual() call
        self.assertIn("repo last touched years ago", maintained.detail)  # runs the assertIn() call
        self.assertIn("Warn: last commit", maintained.detail)  # readable notes included  # runs the assertIn() call
        self.assertNotIn("Debug:", maintained.detail)  # only Warn/Info notes  # runs the assertNotIn() call
        self.assertNotIn("past the four-note cap", maintained.detail)  # capped at four notes  # runs the assertNotIn() call

        review = by_name["Code-Review"]  # copies the by_name value into review
        self.assertEqual(review.severity, "low")  # 1-6 is low  # runs the assertEqual() call
        self.assertEqual(review.title, "Code-Review 5/10")  # runs the assertEqual() call
        self.assertEqual(review.reference, "https://pkg.go.dev/review")  # npm-optional doc URL  # runs the assertEqual() call
        self.assertEqual(  # the misconfig merge key must stay unique per check  # runs the assertEqual() call
            len({f"{f.category}|{f.file}|{f.line}|{f.kind}" for f in findings}),  # counts the unique keys
            len(findings),  # executes the statement
        )  # closes the multiline block

    def test_scorecard_payload_without_checks_is_tolerated(self) -> None:  # defines the test_scorecard_payload_without_checks_is_tolerated() function
        path = write_json(self.dir, "scorecard.json", {"score": None})  # runs the write_json() call
        self.assertEqual(scoring.parse_scorecard_report(path), [])  # runs the assertEqual() call


class OssFuzzParserTests(unittest.TestCase):  # defines the OssFuzzParserTests class
    def setUp(self) -> None:  # defines the setUp() function
        self.tmp = tempfile.TemporaryDirectory()  # saves the result on tmp
        self.root = Path(self.tmp.name)  # saves the result on root
        self.dir = self.root / "repo"  # saves the result on dir
        self.dir.mkdir(parents=True, exist_ok=True)  # creates the folder

    def tearDown(self) -> None:  # defines the tearDown() function
        self.tmp.cleanup()  # runs the cleanup() call

    def test_fuzzed_projects_yield_no_findings(self) -> None:  # defines the test_fuzzed_projects_yield_no_findings() function
        path = write_json(self.dir, "ossfuzz.json", OSSFUZZ_FUZZED)  # runs the write_json() call
        self.assertEqual(scoring.parse_ossfuzz_report(path, self.dir), [])  # fuzzing is a positive signal  # runs the assertEqual() call

    def test_not_fuzzed_projects_yield_one_informational_finding(self) -> None:  # defines the test_not_fuzzed_projects_yield_one_informational_finding() function
        path = write_json(self.dir, "ossfuzz.json", OSSFUZZ_NOT_FUZZED)  # runs the write_json() call
        findings = scoring.parse_ossfuzz_report(path, self.dir)  # runs the parse_ossfuzz_report() call

        self.assertEqual(len(findings), 1)  # runs the assertEqual() call
        finding = findings[0]  # copies the findings[0] value into finding
        self.assertEqual(finding.source, "ossfuzz")  # runs the assertEqual() call
        self.assertEqual(finding.category, "code")  # runs the assertEqual() call
        self.assertEqual(finding.severity, "low")  # runs the assertEqual() call
        self.assertEqual(finding.rule_id, "ossfuzz-coverage")  # runs the assertEqual() call
        self.assertEqual(finding.title, "No OSS-Fuzz continuous fuzzing")  # runs the assertEqual() call
        self.assertEqual(finding.file, "")  # runs the assertEqual() call
        self.assertEqual(finding.line, 0)  # runs the assertEqual() call
        self.assertEqual(finding.kind, "ossfuzz")  # runs the assertEqual() call
        self.assertIn("not registered", finding.detail)  # runner note carried over  # runs the assertIn() call

    def test_falsy_and_dirty_payloads_are_ignored(self) -> None:  # defines the test_falsy_and_dirty_payloads_are_ignored() function
        path = write_json(self.dir, "ossfuzz.json", None)  # runs the write_json() call
        self.assertEqual(scoring.parse_ossfuzz_report(path), [])  # runs the assertEqual() call


class RegistryTests(unittest.TestCase):  # defines the RegistryTests class
    def test_hardening_scanners_are_registered_and_settings_bumped(self) -> None:  # defines the test_hardening_scanners_are_registered_and_settings_bumped() function
        for tool in ("nuclei", "kubescape", "scorecard", "ossfuzz", "fossology"):  # loops over the collection
            self.assertIn(tool, config.ALL_TOOLS)  # runs the assertIn() call
            self.assertIn(tool, config.TOOL_LABELS)  # runs the assertIn() call
            self.assertIn(tool, config.TOOL_DESCRIPTIONS)  # runs the assertIn() call
        self.assertGreaterEqual(config.SETTINGS_VERSION, 6)  # saved selections must merge on load  # runs the assertGreaterEqual() call
        # Insertion order drives the UI and reports: the four follow GuardDog,
        # FOSSology rides with the binary-less pair, and CodeQL still comes last.
        labels = tuple(config.TOOL_LABELS)  # copies the tuple() call
        self.assertEqual(  # runs the assertEqual() call
            labels.index("guarddog") + 1,  # counts the items
            labels.index("fossology"),  # FOSSology rides right after GuardDog
        )  # closes the multiline block
        self.assertEqual(  # the Nuclei block follows the binary-less pair
            labels.index("fossology") + 1,  # counts the items
            labels.index("nuclei"),  # executes the statement
        )  # closes the multiline block

    def test_scanner_groups_cover_the_registry_exactly_once(self) -> None:
        grouped = [tool for _name, tools in config.SCANNER_GROUPS for tool in tools]  # the flattened legend
        self.assertEqual(len(grouped), len(set(grouped)))  # no tool appears twice
        self.assertEqual(sorted(grouped), sorted(config.ALL_TOOLS))  # every tool is grouped
        # The functional legend drives the row: each group is a real label.
        self.assertTrue(all(name.strip() for name, _tools in config.SCANNER_GROUPS))


if __name__ == "__main__":  # runs the module entry point
    unittest.main(verbosity=2)  # runs the main() call
