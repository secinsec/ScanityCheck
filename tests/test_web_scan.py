"""Tests for website scan mode: dispatch, web-audit parsing and verdict rules.

No network is used anywhere: the web-audit document the runner would write is
built as a local fixture, the scanners that touch the network are faked, and
the dispatch test swaps module functions and restores them.
"""

from __future__ import annotations  # imports annotations from the __future__ module

import json  # imports the json module
import sys  # imports the sys module
import tempfile  # imports the tempfile module
import unittest  # imports the unittest module
from pathlib import Path  # imports the pathlib module

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # inserts the repo root

import config  # noqa: E402  # imports config
import scoring  # noqa: E402  # imports scoring
import scanners  # noqa: E402  # imports scanners


def write_json(directory: Path, name: str, payload) -> Path:  # defines the write_json() function
    path = directory / name  # copies the directory value into path
    path.write_text(json.dumps(payload), encoding="utf-8")  # writes the text file
    return path  # returns the path to the caller


def webcheck_payload(**overrides):
    """A default https page with every hardening header present."""
    page = {  # the fetched page block
        "final_url": "https://example.com/",  # maps the final_url dictionary entry
        "scheme": "https",  # maps the scheme dictionary entry
        "status": "200",  # maps the status dictionary entry
        "headers": {  # all five hardening headers present
            "Content-Security-Policy": "default-src 'self'",  # maps the header dictionary entry
            "Strict-Transport-Security": "max-age=63072000",  # maps the header dictionary entry
            "X-Content-Type-Options": "nosniff",  # maps the header dictionary entry
            "X-Frame-Options": "DENY",  # maps the header dictionary entry
            "Referrer-Policy": "no-referrer",  # maps the header dictionary entry
        },  # closes the multiline block
        "body": "<html>hello</html>",  # maps the body dictionary entry
    }  # closes the multiline block
    payload = {  # the full document
        "url": "https://example.com",  # maps the url dictionary entry
        "page": page,  # maps the page dictionary entry
        "probes": [],  # maps the probes dictionary entry
    }  # closes the multiline block
    payload.update(overrides)  # applies the overrides
    return payload  # returns the payload to the caller


class TargetTests(unittest.TestCase):  # class TargetTests
    def test_github_urls_dispatch_to_the_repo_pipeline(self) -> None:
        kind, target = scanners.parse_target("https://github.com/o/r")  # parses the URL
        self.assertEqual(kind, "repo")  # asserts kind == "repo"
        self.assertEqual(target.full_name, "o/r")  # asserts the full name

    def test_bare_domains_default_to_https(self) -> None:
        kind, target = scanners.parse_target("example.com")  # parses the bare domain
        self.assertEqual(kind, "web")  # asserts kind == "web"
        self.assertEqual(target, "https://example.com")  # asserts the normalized URL

    def test_full_web_addresses_keep_their_path(self) -> None:
        kind, target = scanners.parse_target("https://site.io/docs/page")  # parses the URL
        self.assertEqual(kind, "web")  # asserts kind == "web"
        self.assertEqual(target, "https://site.io/docs/page")  # asserts the path survived

    def test_garbage_still_raises_the_repo_hint(self) -> None:
        with self.assertRaises(scanners.ScanError):  # watches the raises on garbage
            scanners.parse_target("not a url!!")  # parses the garbage text


class WebAuditParserTests(unittest.TestCase):  # class WebAuditParserTests
    def setUp(self) -> None:  # defines the setUp() function
        self.tmp = tempfile.TemporaryDirectory()  # builds the temp directory
        self.dir = Path(self.tmp.name)  # copies the dir value into self.dir

    def tearDown(self) -> None:  # defines the tearDown() function
        self.tmp.cleanup()  # removes the temp directory

    def test_a_hardened_https_page_costs_nothing(self) -> None:
        path = write_json(self.dir, "webcheck.json", webcheck_payload())  # writes the payload
        self.assertEqual(scoring.parse_webcheck_report(path), [])  # clean pages are free

    def test_missing_headers_become_low_misconfigurations(self) -> None:
        payload = webcheck_payload()  # builds the payload
        payload["page"]["headers"] = {"Server": "nginx"}  # no hardening at all
        path = write_json(self.dir, "webcheck.json", payload)  # writes the payload
        findings = scoring.parse_webcheck_report(path)  # parses the document
        kinds = sorted(finding.kind for finding in findings)  # collects the kind values
        self.assertEqual(  # asserts the five header rules checked independently
            kinds,  # compares with the expected set
            ["web.headers.csp", "web.headers.frame", "web.headers.hsts", "web.headers.nosniff", "web.headers.referrer"],
        )  # closes the assertion list
        self.assertTrue(all(f.category == "misconfiguration" for f in findings))  # asserts the category
        self.assertTrue(all(f.severity == "low" for f in findings))  # asserts the low rating
        self.assertTrue(all(f.source == "webcheck" for f in findings))  # asserts the source

    def test_plain_http_is_a_high_transport_finding(self) -> None:
        payload = webcheck_payload(page={  # builds the payload
            "final_url": "http://example.com/",  # maps an http final URL
            "scheme": "http",  # maps the http scheme
            "status": "200",  # maps the status dictionary entry
            "headers": {  # hardening present on http still
                "Content-Security-Policy": "default-src 'self'",  # maps the header dictionary entry
                "X-Content-Type-Options": "nosniff",  # maps the header dictionary entry
                "X-Frame-Options": "DENY",  # maps the header dictionary entry
                "Referrer-Policy": "no-referrer",  # maps the header dictionary entry
            },  # closes the multiline block
            "body": "",  # maps the body dictionary entry
        })  # closes the payload build
        path = write_json(self.dir, "webcheck.json", payload)  # writes the payload
        findings = scoring.parse_webcheck_report(path)  # parses the document
        self.assertEqual([f.rule_id for f in findings], ["plain-http"])  # only the transport rule
        self.assertEqual(findings[0].severity, "high")  # asserts the high rating
        self.assertEqual(findings[0].category, "misconfiguration")  # asserts the category

    def test_exposed_env_file_is_a_high_secret(self) -> None:
        payload = webcheck_payload(probes=[  # a real env file and an SPA fall-back
            {"name": ".env", "path": "example.com/.env", "status": "200",
             "body": "DB_PASSWORD=hunter2\nAWS_KEY=zz\nSMTP_HOST=mail.example.com\nSECRET_TOKEN=abcd"},  # exposes
            {"name": ".git/config", "path": "example.com/.git/config", "status": "200", "body": "<html>404 fall-back</html>"},  # SPA echo
        ])  # closes the probes list
        path = write_json(self.dir, "webcheck.json", payload)  # writes the payload
        findings = scoring.parse_webcheck_report(path)  # parses the document
        self.assertEqual(len(findings), 1)  # only the real env file counts
        self.assertEqual(findings[0].category, "secret")  # asserts the category
        self.assertEqual(findings[0].severity, "high")  # asserts the severity
        self.assertEqual(findings[0].rule_id, "exposed-env")  # asserts the rule id
        self.assertEqual(findings[0].location, "example.com/.env")  # asserts the location

    def test_exposed_git_history_is_detected(self) -> None:
        payload = webcheck_payload(probes=[  # a genuine .git directory
            {"name": ".git/config", "path": "example.com/.git/config", "status": "200", "body": "[core]\n\trepositoryformatversion = 0"},
        ])  # closes the probes list
        path = write_json(self.dir, "webcheck.json", payload)  # writes the payload
        findings = scoring.parse_webcheck_report(path)  # parses the document
        self.assertEqual(len(findings), 1)  # one finding
        self.assertEqual(findings[0].rule_id, "exposed-git")  # asserts the rule id

    def test_missing_and_404_probes_are_ignored(self) -> None:
        payload = webcheck_payload(probes=[  # the normal no-leak case
            {"name": ".env", "path": "x/.env", "status": "404", "body": ""},  # absent
            {"name": ".git/config", "path": "x/.git/config", "status": "403", "body": ""},  # protected
        ])  # closes the probes list
        path = write_json(self.dir, "webcheck.json", payload)  # writes the payload
        self.assertEqual(scoring.parse_webcheck_report(path), [])  # nothing penalised

    def test_dirty_documents_yield_nothing(self) -> None:
        path = self.dir / "broken.json"  # a non-JSON file
        path.write_text("<html>oops</html>", encoding="utf-8")  # writes the dirt
        self.assertEqual(scoring.parse_webcheck_report(path), [])  # tolerated


class WebsiteVerdictTests(unittest.TestCase):  # class WebsiteVerdictTests
    def test_skipped_required_scanners_do_not_force_insecure(self) -> None:
        status = {  # every source scanner marked not applicable
            tool: {"status": "skipped", "duration_seconds": 0,  # skips one tool
                   "details": ["Not applicable: website scan."]}  # adds the detail text
            for tool in config.ALL_TOOLS  # loops over the collection
        }  # closes the status dict
        status["webcheck"] = {"status": "ok", "duration_seconds": 0.1, "details": []}  # the audit ran
        report = scoring.build_report(  # builds the report
            [],  # no findings: a clean site
            repo={"input_url": "https://example.com", "full_name": "example.com"},  # web metadata
            scanner_status=status,  # copies the status value into the call
        )  # closes the report build
        self.assertNotIn("required", report["verdict_reason"].lower())  # no carve-out trigger
        self.assertEqual(report["verdict"], "SECURE")  # a clean website can pass
        self.assertEqual(report["scanner_status"]["codeql"]["status"], "skipped")  # skipped kept


class DispatchTests(unittest.TestCase):  # class DispatchTests
    def test_scan_target_routes_by_kind(self) -> None:
        calls: list[str] = []  # records the routed pipelines

        def fake_repo(url, **kwargs) -> dict:  # defines the fake_repo() function
            calls.append("repo")  # adds an item to the list
            return {"verdict": "SECURE"}  # returns a stub report

        def fake_web(url, **kwargs) -> dict:  # defines the fake_web() function
            calls.append("web")  # adds an item to the list
            return {"verdict": "SECURE"}  # returns a stub report

        original_repo, original_web = scanners.scan_repository, scanners.scan_website  # saves the originals
        scanners.scan_repository, scanners.scan_website = fake_repo, fake_web  # swaps the functions
        try:  # keeps the swap deterministic
            quiet, flag = (lambda line: None), __import__("threading").Event()  # a quiet logger and cancel flag
            scanners.scan_target("https://github.com/o/r", log=quiet, cancel=flag)  # routes a repo
            scanners.scan_target("https://example.com", log=quiet, cancel=flag)  # routes a website
        finally:  # restores the originals
            scanners.scan_repository, scanners.scan_website = original_repo, original_web  # closes the swap
        self.assertEqual(calls, ["repo", "web"])  # asserts the routing order


class WebsitePipelineTests(unittest.TestCase):  # class WebsitePipelineTests
    def setUp(self) -> None:  # defines the setUp() function
        self.tmp = tempfile.TemporaryDirectory()  # builds the temp directory
        self.dir = Path(self.tmp.name)  # copies the dir value into self.dir

        def fake_fetch(url, cancel, **kwargs) -> dict:  # defines the fake_fetch() function
            return {  # an https page with no hardening headers
                "final_url": url,  # maps the final_url dictionary entry
                "scheme": "https",  # maps the scheme dictionary entry
                "status": "200",  # maps the status dictionary entry
                "headers": {},  # no hardening at all
                "body": "<html>site</html>",  # maps the body dictionary entry
            }  # closes the dict build

        def fake_probe(url, name, cancel, **kwargs) -> dict:  # defines the fake_probe() function
            return {"name": name, "path": name, "status": "404", "body": ""}  # nothing exposed

        self.originals = (scanners._fetch_web_page, scanners._probe_web_dotfile)  # saves the originals
        scanners._fetch_web_page, scanners._probe_web_dotfile = fake_fetch, fake_probe  # swaps the fetches

    def tearDown(self) -> None:  # defines the tearDown() function
        scanners._fetch_web_page, scanners._probe_web_dotfile = self.originals  # restores the fetches
        self.tmp.cleanup()  # removes the temp directory

    def test_website_scan_runs_audit_and_marks_source_tools_not_applicable(self) -> None:
        def fake_nuclei(root, artifacts, *, log, cancel, targets) -> tuple[Path, dict]:  # a canned nuclei
            output = Path(artifacts) / "nuclei.jsonl"  # a file the parser can read
            output.write_text("", encoding="utf-8")  # empty (clean) output
            return output, {"status": "ok", "duration_seconds": 1.0, "details": []}  # ok status

        original_nuclei = scanners.run_nuclei  # saves the original
        scanners.run_nuclei = fake_nuclei  # swaps it
        try:  # keeps the swap scoped
            with tempfile.TemporaryDirectory() as cache:  # points WORK_DIR at a temp cache
                original_work, original_tools = config.WORK_DIR, config.TOOLS_DIR  # saves the cache dirs
                config.WORK_DIR = Path(cache)  # redirects the work dir
                try:  # keeps the redirect scoped
                    report = scanners.scan_website(  # runs the pipeline
                        "https://example.com",  # the live target
                        log=lambda line: None,  # a quiet logger
                        cancel=__import__("threading").Event(),  # a fresh cancel flag
                        tools=["nuclei", "kubescape"],  # a mixed selection
                    )  # closes the scan call
                finally:  # restores the cache dirs
                    config.WORK_DIR, config.TOOLS_DIR = original_work, original_tools  # closes the redirect
        finally:  # restores the runner
            scanners.run_nuclei = original_nuclei  # closes the swap

        self.assertEqual(report["scan_kind"], "website")  # the report knows its mode
        self.assertEqual(report["scanner_status"]["webcheck"]["status"], "ok")  # the audit ran
        self.assertEqual(report["scanner_status"]["nuclei"]["status"], "ok")  # nuclei ran too
        self.assertEqual(report["scanner_status"]["codeql"]["status"], "skipped")  # not applicable
        self.assertIn("website scan", " ".join(report["scanner_status"]["codeql"]["details"]))  # honest detail
        self.assertFalse(report["scanner_status"]["nuclei"]["status"] == "error")  # no false failures
        header_findings = [f for f in report["findings"] if f["rule_id"].startswith("missing-")]  # header rules
        self.assertEqual(len(header_findings), 5)  # the headers were absent
        self.assertNotIn("required", report["verdict_reason"].lower())  # verdict stayed clean


if __name__ == "__main__":  # runs the module
    unittest.main(verbosity=2)  # starts the runner
