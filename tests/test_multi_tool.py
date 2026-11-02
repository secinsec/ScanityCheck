"""Parser, cross-tool de-duplication and attribution tests for the new scanners.

The samples mirror the real output captured from Grype 0.121.0, OSV-Scanner
2.7.0, GitLeaks 8.30.1, TruffleHog 3.99.7 and Semgrep CE. No binaries or
network access are needed.
"""

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


def write_json(directory: Path, name: str, payload) -> Path:  # defines the write_json() function
    path = directory / name  # copies the directory value into path
    path.write_text(json.dumps(payload), encoding="utf-8")  # writes the text file
    return path  # returns the path to the caller


SEMGREP_SAMPLE = {  # assigns the computed value to SEMGREP_SAMPLE
    "results": [  # maps the results dictionary entry
        {  # executes the statement
            "check_id": "python.lang.security.audit.sql-injection",  # maps the check_id dictionary entry
            "path": "app/db.py",  # maps the path dictionary entry
            "start": {"line": 10},  # maps the start dictionary entry
            "extra": {  # maps the extra dictionary entry
                "severity": "ERROR",  # maps the severity dictionary entry
                "message": "User input reaches a SQL query.",  # maps the message dictionary entry
                "metadata": {"category": "security", "cwe": ["CWE-89: SQL Injection"]},  # maps the metadata dictionary entry
            },  # closes the multiline block
        },  # closes the multiline block
        {  # executes the statement
            "check_id": "dockerfile.security.missing-user.missing-user",  # maps the check_id dictionary entry
            "path": "Dockerfile",  # maps the path dictionary entry
            "start": {"line": 5},  # maps the start dictionary entry
            "extra": {  # maps the extra dictionary entry
                "severity": "WARNING",  # maps the severity dictionary entry
                "message": "Container may run as root.",  # maps the message dictionary entry
                "metadata": {"category": "security", "technology": ["dockerfile"]},  # maps the metadata dictionary entry
            },  # closes the multiline block
        },  # closes the multiline block
        {  # executes the statement
            "check_id": "python.lang.correctness.unused-import",  # maps the check_id dictionary entry
            "path": "app/db.py",  # maps the path dictionary entry
            "start": {"line": 1},  # maps the start dictionary entry
            "extra": {  # maps the extra dictionary entry
                "severity": "INFO",  # maps the severity dictionary entry
                "message": "Unused import.",  # maps the message dictionary entry
                "metadata": {"category": "best-practice"},  # maps the metadata dictionary entry
            },  # closes the multiline block
        },  # closes the multiline block
        # Same rule and location twice: must collapse into one finding.
        {  # executes the statement
            "check_id": "python.lang.security.audit.sql-injection",  # maps the check_id dictionary entry
            "path": "app/db.py",  # maps the path dictionary entry
            "start": {"line": 10},  # maps the start dictionary entry
            "extra": {  # maps the extra dictionary entry
                "severity": "ERROR",  # maps the severity dictionary entry
                "message": "User input reaches a SQL query.",  # maps the message dictionary entry
                "metadata": {"category": "security", "cwe": ["CWE-89: SQL Injection"]},  # maps the metadata dictionary entry
            },  # closes the multiline block
        },  # closes the multiline block
    ]  # closes the multiline block
}  # closes the multiline block

GRYPE_SAMPLE = {  # assigns the computed value to GRYPE_SAMPLE
    "matches": [  # maps the matches dictionary entry
        {  # executes the statement
            "vulnerability": {  # maps the vulnerability dictionary entry
                "id": "GHSA-35jh-r3h4-6jhm",  # maps the id dictionary entry
                "severity": "High",  # maps the severity dictionary entry
                "relatedVulnerabilities": [{"id": "CVE-2021-23337"}],  # maps the relatedVulnerabilities dictionary entry
                "description": "Command injection in lodash.",  # maps the description dictionary entry
                "fix": {"versions": ["4.17.21"]},  # maps the fix dictionary entry
                "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"],  # maps the urls dictionary entry
            },  # closes the multiline block
            "artifact": {  # maps the artifact dictionary entry
                "name": "lodash",  # maps the name dictionary entry
                "version": "4.17.20",  # maps the version dictionary entry
                "locations": [{"path": "/package-lock.json"}],  # maps the locations dictionary entry
            },  # closes the multiline block
        },  # closes the multiline block
        {  # executes the statement
            "vulnerability": {"id": "CVE-2022-0001", "severity": "Low"},  # maps the vulnerability dictionary entry
            "artifact": {"name": "minimist", "version": "1.2.0", "locations": []},  # maps the artifact dictionary entry
        },  # closes the multiline block
        # Same CVE, same package, second advisory id: de-duplicated.
        {  # executes the statement
            "vulnerability": {  # maps the vulnerability dictionary entry
                "id": "CVE-2021-23337",  # maps the id dictionary entry
                "severity": "Critical",  # maps the severity dictionary entry
                "relatedVulnerabilities": [],  # maps the relatedVulnerabilities dictionary entry
            },  # closes the multiline block
            "artifact": {  # maps the artifact dictionary entry
                "name": "lodash",  # maps the name dictionary entry
                "version": "4.17.20",  # maps the version dictionary entry
                "locations": [{"path": "/package-lock.json"}],  # maps the locations dictionary entry
            },  # closes the multiline block
        },  # closes the multiline block
    ]  # closes the multiline block
}  # closes the multiline block

OSV_SAMPLE = {  # assigns the computed value to OSV_SAMPLE
    "results": [  # maps the results dictionary entry
        {  # executes the statement
            "source": {"path": "requirements.txt"},  # maps the source dictionary entry
            "packages": [  # maps the packages dictionary entry
                {  # executes the statement
                    "package": {"name": "flask", "version": "0.12.2"},  # maps the package dictionary entry
                    "vulnerabilities": [  # maps the vulnerabilities dictionary entry
                        {  # executes the statement
                            "id": "GHSA-abc-1234",  # maps the id dictionary entry
                            "aliases": ["CVE-2019-1010083"],  # maps the aliases dictionary entry
                            "summary": "Flask denial of service.",  # maps the summary dictionary entry
                            "database_specific": {"severity": "HIGH"},  # maps the database_specific dictionary entry
                            "references": [{"url": "https://osv.dev/GHSA-abc-1234"}],  # maps the references dictionary entry
                        },  # closes the multiline block
                        {  # executes the statement
                            "id": "GHSA-xyz-9999",  # maps the id dictionary entry
                            "aliases": [],  # maps the aliases dictionary entry
                            "summary": "Unscored advisory.",  # maps the summary dictionary entry
                        },  # closes the multiline block
                    ],  # closes the multiline block
                }  # closes the multiline block
            ],  # closes the multiline block
        }  # closes the multiline block
    ]  # closes the multiline block
}  # closes the multiline block


class ParserTests(unittest.TestCase):  # defines the ParserTests class
    def setUp(self) -> None:  # defines the setUp() function
        self.tmp = tempfile.TemporaryDirectory()  # saves the result on tmp
        self.root = Path(self.tmp.name)  # saves the result on root
        self.dir = self.root / "repo"  # saves the result on dir
        self.dir.mkdir(parents=True, exist_ok=True)  # creates the folder

    def tearDown(self) -> None:  # defines the tearDown() function
        self.tmp.cleanup()  # runs the cleanup() call

    def test_semgrep_severity_categories_and_dedupe(self) -> None:  # defines the test_semgrep_severity_categories_and_dedupe() function
        path = write_json(self.dir, "semgrep.json", SEMGREP_SAMPLE)  # runs the write_json() call
        findings = scoring.parse_semgrep_report(path, self.dir)  # runs the parse_semgrep_report() call
        self.assertEqual(len(findings), 3)  # runs the assertEqual() call

        by_rule = {finding.rule_id: finding for finding in findings}  # assigns the computed value to by_rule
        sql = by_rule["python.lang.security.audit.sql-injection"]  # copies the by_rule value into sql
        self.assertEqual(sql.source, "semgrep")  # runs the assertEqual() call
        self.assertEqual(sql.category, "code")  # runs the assertEqual() call
        self.assertEqual(sql.severity, "high")  # runs the assertEqual() call
        self.assertEqual(sql.file, "app/db.py")  # runs the assertEqual() call
        self.assertEqual(sql.location, "app/db.py:10")  # runs the assertEqual() call
        self.assertEqual(sql.cwe, "CWE-89")  # runs the assertEqual() call

        docker = by_rule["dockerfile.security.missing-user.missing-user"]  # copies the by_rule value into docker
        self.assertEqual(docker.category, "misconfiguration")  # runs the assertEqual() call
        self.assertEqual(docker.severity, "medium")  # runs the assertEqual() call

        unused = by_rule["python.lang.correctness.unused-import"]  # copies the by_rule value into unused
        self.assertEqual(unused.category, "code-quality")  # runs the assertEqual() call
        self.assertEqual(unused.severity, "low")  # runs the assertEqual() call

    def test_grype_maps_severity_fix_and_relative_path(self) -> None:  # defines the test_grype_maps_severity_fix_and_relative_path() function
        path = write_json(self.dir, "grype.json", GRYPE_SAMPLE)  # runs the write_json() call
        findings = scoring.parse_grype_report(path, self.dir)  # runs the parse_grype_report() call
        self.assertEqual(len(findings), 2)  # runs the assertEqual() call

        lodash = next(f for f in findings if f.package == "lodash")  # runs the next() call
        self.assertEqual(lodash.source, "grype")  # runs the assertEqual() call
        self.assertEqual(lodash.rule_id, "CVE-2021-23337")  # canonical CVE, not GHSA  # runs the assertEqual() call
        self.assertIn("GHSA-35jh-r3h4-6jhm", lodash.aliases)  # runs the assertIn() call
        self.assertEqual(lodash.severity, "high")  # runs the assertEqual() call
        self.assertEqual(lodash.file, "package-lock.json")  # runs the assertEqual() call
        self.assertEqual(lodash.location, "package-lock.json")  # runs the assertEqual() call
        self.assertIn("Fixed in 4.17.21", lodash.detail)  # runs the assertIn() call

        minimist = next(f for f in findings if f.package == "minimist")  # runs the next() call
        self.assertEqual(minimist.severity, "low")  # runs the assertEqual() call
        self.assertEqual(minimist.location, "")  # runs the assertEqual() call
        self.assertIn("No fix available", minimist.detail)  # runs the assertIn() call

    def test_grype_recovers_cve_from_epss_and_urls(self) -> None:  # defines the test_grype_recovers_cve_from_epss_and_urls() function
        sample = {  # assigns the computed value to sample
            "matches": [  # maps the matches dictionary entry
                {  # executes the statement
                    "vulnerability": {  # maps the vulnerability dictionary entry
                        "id": "GHSA-35jh-r3h4-6jhm",  # maps the id dictionary entry
                        "severity": "High",  # maps the severity dictionary entry
                        "epss": [{"cve": "CVE-2021-23337"}],  # maps the epss dictionary entry
                        "urls": [  # maps the urls dictionary entry
                            "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",  # maps the https://nvd.nist.gov/vul dictionary entry
                        ],  # closes the multiline block
                    },  # closes the multiline block
                    "artifact": {  # maps the artifact dictionary entry
                        "name": "lodash",  # maps the name dictionary entry
                        "version": "4.17.20",  # maps the version dictionary entry
                        "locations": [{"path": "/package-lock.json"}],  # maps the locations dictionary entry
                    },  # closes the multiline block
                }  # closes the multiline block
            ]  # closes the multiline block
        }  # closes the multiline block
        path = write_json(self.dir, "grype-real.json", sample)  # runs the write_json() call
        findings = scoring.parse_grype_report(path, self.dir)  # runs the parse_grype_report() call
        self.assertEqual(len(findings), 1)  # runs the assertEqual() call
        self.assertEqual(findings[0].rule_id, "CVE-2021-23337")  # runs the assertEqual() call

        trivy = scoring.Finding(  # runs the Finding() call
            "trivy",  # supplies the literal text
            "vulnerability",  # supplies the literal text
            "high",  # supplies the literal text
            "CVE-2021-23337",  # supplies the literal text
            "lodash 4.17.20",  # supplies the literal text
            package="lodash",  # sets the package text
            weight=scoring.weight_for("vulnerability", "high"),  # runs the weight_for() call
        )  # closes the multiline block
        merged = scoring.merge_findings([trivy, *findings])  # runs the merge_findings() call
        self.assertEqual(len(merged), 1)  # runs the assertEqual() call
        self.assertEqual(merged[0].tools, ["trivy", "grype"])  # runs the assertEqual() call

    def test_parser_accepts_cp1252_bytes(self) -> None:  # defines the test_parser_accepts_cp1252_bytes() function
        payload = {  # assigns the computed value to payload
            "results": [  # maps the results dictionary entry
                {  # executes the statement
                    "check_id": "rules.sqli",  # maps the check_id dictionary entry
                    "path": "app.py",  # maps the path dictionary entry
                    "start": {"line": 12},  # maps the start dictionary entry
                    "extra": {"message": "unsafe query \u2019quote\u2019", "severity": "ERROR"},  # maps the extra dictionary entry
                }  # closes the multiline block
            ],  # closes the multiline block
            "errors": [],  # maps the errors dictionary entry
        }  # closes the multiline block
        path = Path(self.dir) / "semgrep-cp1252.json"  # creates the path object
        path.write_bytes(json.dumps(payload, ensure_ascii=False).encode("cp1252"))  # writes the raw bytes out
        findings = scoring.parse_semgrep_report(path, self.dir)  # runs the parse_semgrep_report() call
        self.assertEqual(len(findings), 1)  # runs the assertEqual() call
        self.assertEqual(findings[0].file, "app.py")  # runs the assertEqual() call

    def test_osv_alias_canonicalisation_and_fallback_severity(self) -> None:  # defines the test_osv_alias_canonicalisation_and_fallback_severity() function
        path = write_json(self.dir, "osv.json", OSV_SAMPLE)  # runs the write_json() call
        findings = scoring.parse_osv_report(path, self.dir)  # runs the parse_osv_report() call
        self.assertEqual(len(findings), 2)  # runs the assertEqual() call

        flask = next(f for f in findings if f.rule_id == "CVE-2019-1010083")  # runs the next() call
        self.assertEqual(flask.source, "osv")  # runs the assertEqual() call
        self.assertEqual(flask.severity, "high")  # runs the assertEqual() call
        self.assertEqual(flask.file, "requirements.txt")  # runs the assertEqual() call
        self.assertEqual(flask.location, "requirements.txt")  # runs the assertEqual() call

        unscored = next(f for f in findings if f.rule_id == "GHSA-xyz-9999")  # runs the next() call
        self.assertEqual(unscored.severity, "medium")  # documented fallback  # runs the assertEqual() call

    def test_gitleaks_severity_and_location(self) -> None:  # defines the test_gitleaks_severity_and_location() function
        sample = [  # assigns the computed value to sample
            {  # executes the statement
                "RuleID": "private-key",  # maps the RuleID dictionary entry
                "Description": "Private key detected",  # maps the Description dictionary entry
                "StartLine": 3,  # maps the StartLine dictionary entry
                "File": str(self.dir / "keys" / "id_rsa"),  # maps the File dictionary entry
                "Tags": [],  # maps the Tags dictionary entry
            },  # closes the multiline block
            {  # executes the statement
                "RuleID": "generic-api-key",  # maps the RuleID dictionary entry
                "Description": "Generic API key",  # maps the Description dictionary entry
                "StartLine": 7,  # maps the StartLine dictionary entry
                "File": str(self.dir / "app.py"),  # maps the File dictionary entry
                "Tags": [],  # maps the Tags dictionary entry
            },  # closes the multiline block
        ]  # closes the multiline block
        path = write_json(self.dir, "gitleaks.json", sample)  # runs the write_json() call
        findings = scoring.parse_gitleaks_report(path, self.dir)  # runs the parse_gitleaks_report() call
        self.assertEqual(len(findings), 2)  # runs the assertEqual() call

        key = next(f for f in findings if f.rule_id == "private-key")  # runs the next() call
        self.assertEqual(key.severity, "critical")  # runs the assertEqual() call
        self.assertEqual(key.kind, "private-key")  # runs the assertEqual() call
        self.assertEqual(key.file, "keys/id_rsa")  # runs the assertEqual() call
        self.assertEqual(key.location, "keys/id_rsa:3")  # runs the assertEqual() call

        generic = next(f for f in findings if f.rule_id == "generic-api-key")  # runs the next() call
        self.assertEqual(generic.severity, "high")  # runs the assertEqual() call
        self.assertEqual(generic.location, "app.py:7")  # runs the assertEqual() call
        self.assertIn("redacted", generic.detail.lower())  # runs the assertIn() call

    def test_trufflehog_skips_log_lines_and_maps_verification(self) -> None:  # defines the test_trufflehog_skips_log_lines_and_maps_verification() function
        app = self.dir / "creds.py"  # copies the self.dir value into app
        app.parent.mkdir(parents=True, exist_ok=True)  # creates the folder
        app.write_text("x\n", encoding="utf-8")  # writes the text file
        lines = [  # assigns the computed value to lines
            {"level": "info-0", "msg": "running source", "source_type": "SOURCE_TYPE_FILESYSTEM"},  # executes the statement
            {  # executes the statement
                "DetectorName": "Github",  # maps the DetectorName dictionary entry
                "Verified": True,  # maps the Verified dictionary entry
                "SourceMetadata": {"Data": {"Filesystem": {"file": str(app), "line": 3}}},  # maps the SourceMetadata dictionary entry
                "ExtraData": {"rotation_guide": "https://howtorotate.com/docs/tutorials/github/"},  # maps the ExtraData dictionary entry
            },  # closes the multiline block
            {  # executes the statement
                "DetectorName": "AWS",  # maps the DetectorName dictionary entry
                "Verified": False,  # maps the Verified dictionary entry
                "SourceMetadata": {"Data": {"Filesystem": {"file": str(app), "line": 5}}},  # maps the SourceMetadata dictionary entry
            },  # closes the multiline block
            {"level": "info-0", "msg": "finished scanning"},  # executes the statement
        ]  # closes the multiline block
        path = self.dir / "trufflehog.jsonl"  # copies the self.dir value into path
        path.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")  # writes the text file

        findings = scoring.parse_trufflehog_report(path, self.dir)  # runs the parse_trufflehog_report() call
        self.assertEqual(len(findings), 2)  # runs the assertEqual() call

        github = next(f for f in findings if f.rule_id == "Github")  # runs the next() call
        self.assertEqual(github.severity, "critical")  # verified  # runs the assertEqual() call
        self.assertEqual(github.kind, "github")  # runs the assertEqual() call
        self.assertEqual(github.location, "creds.py:3")  # runs the assertEqual() call
        self.assertIn("verified", github.detail.lower())  # runs the assertIn() call

        aws = next(f for f in findings if f.rule_id == "AWS")  # runs the next() call
        self.assertEqual(aws.severity, "medium")  # unverified, not a private key  # runs the assertEqual() call
        self.assertIn("never sent to third parties", aws.detail)  # runs the assertIn() call


class MergeTests(unittest.TestCase):  # defines the MergeTests class
    def test_same_cve_from_three_tools_is_charged_once(self) -> None:  # defines the test_same_cve_from_three_tools_is_charged_once() function
        trivy = scoring.Finding(  # runs the Finding() call
            "trivy",  # supplies the literal text
            "vulnerability",  # supplies the literal text
            "high",  # supplies the literal text
            "CVE-2021-23337",  # supplies the literal text
            "lodash 4.17.20",  # supplies the literal text
            package="lodash",  # sets the package text
            weight=scoring.weight_for("vulnerability", "high"),  # runs the weight_for() call
        )  # closes the multiline block
        grype = scoring.Finding(  # runs the Finding() call
            "grype",  # supplies the literal text
            "vulnerability",  # supplies the literal text
            "critical",  # supplies the literal text
            "CVE-2021-23337",  # supplies the literal text
            "lodash 4.17.20",  # supplies the literal text
            package="lodash",  # sets the package text
            weight=scoring.weight_for("vulnerability", "critical"),  # runs the weight_for() call
        )  # closes the multiline block
        osv = scoring.Finding(  # runs the Finding() call
            "osv",  # supplies the literal text
            "vulnerability",  # supplies the literal text
            "medium",  # supplies the literal text
            "GHSA-35jh-r3h4-6jhm",  # supplies the literal text
            "lodash 4.17.20",  # supplies the literal text
            package="lodash",  # sets the package text
            aliases=["CVE-2021-23337"],  # assigns the computed value to aliases
            weight=scoring.weight_for("vulnerability", "medium"),  # runs the weight_for() call
        )  # closes the multiline block

        merged = scoring.merge_findings([trivy, grype, osv])  # runs the merge_findings() call
        self.assertEqual(len(merged), 1)  # runs the assertEqual() call
        finding = merged[0]  # copies the merged value into finding
        self.assertEqual(finding.tools, ["trivy", "grype", "osv"])  # runs the assertEqual() call
        self.assertEqual(finding.severity, "critical")  # runs the assertEqual() call
        self.assertEqual(finding.weight, 12.0)  # runs the assertEqual() call

        report = scoring.build_report(  # runs the build_report() call
            [trivy, grype, osv],  # executes the statement
            scanner_status={  # assigns the computed value to scanner_status
                "trivy": {"status": "ok"},  # maps the trivy dictionary entry
                "grype": {"status": "ok"},  # maps the grype dictionary entry
                "osv": {"status": "ok"},  # maps the osv dictionary entry
                "codeql": {"status": "ok"},  # maps the codeql dictionary entry
            },  # closes the multiline block
        )  # closes the multiline block
        self.assertAlmostEqual(report["raw_penalties"]["vulnerability"], 12.0)  # runs the assertAlmostEqual() call
        self.assertEqual(report["by_tool"]["trivy"]["total"], 1)  # runs the assertEqual() call
        self.assertEqual(report["by_tool"]["grype"]["total"], 1)  # runs the assertEqual() call
        self.assertEqual(report["by_tool"]["osv"]["total"], 1)  # runs the assertEqual() call
        self.assertEqual(  # runs the assertEqual() call
            report["greatest_risks"][0]["tool_labels"],  # evaluates the report expression
            ["Trivy", "Grype", "OSV-Scanner"],  # executes the statement
        )  # closes the multiline block

    def test_same_secret_from_two_tools_is_merged(self) -> None:  # defines the test_same_secret_from_two_tools_is_merged() function
        gitleaks = scoring.Finding(  # runs the Finding() call
            "gitleaks",  # supplies the literal text
            "secret",  # supplies the literal text
            "high",  # supplies the literal text
            "aws-access-token",  # supplies the literal text
            "AWS key",  # supplies the literal text
            location="app.py:7",  # sets the location text
            file="app.py",  # sets the file text
            line=7,  # assigns the computed value to line
            kind="aws",  # sets the kind text
            weight=scoring.weight_for("secret", "high"),  # runs the weight_for() call
        )  # closes the multiline block
        trufflehog = scoring.Finding(  # runs the Finding() call
            "trufflehog",  # supplies the literal text
            "secret",  # supplies the literal text
            "medium",  # supplies the literal text
            "AWS",  # supplies the literal text
            "AWS credential",  # supplies the literal text
            location="app.py:7",  # sets the location text
            file="app.py",  # sets the file text
            line=7,  # assigns the computed value to line
            kind="aws",  # sets the kind text
            weight=scoring.weight_for("secret", "medium"),  # runs the weight_for() call
        )  # closes the multiline block
        other = scoring.Finding(  # runs the Finding() call
            "gitleaks",  # supplies the literal text
            "secret",  # supplies the literal text
            "high",  # supplies the literal text
            "generic-api-key",  # supplies the literal text
            "API key",  # supplies the literal text
            location="app.py:12",  # sets the location text
            file="app.py",  # sets the file text
            line=12,  # assigns the computed value to line
            kind="generic",  # sets the kind text
            weight=scoring.weight_for("secret", "high"),  # runs the weight_for() call
        )  # closes the multiline block

        merged = scoring.merge_findings([gitleaks, trufflehog, other])  # runs the merge_findings() call
        self.assertEqual(len(merged), 2)  # runs the assertEqual() call
        aws = next(f for f in merged if f.kind == "aws")  # runs the next() call
        self.assertEqual(aws.tools, ["gitleaks", "trufflehog"])  # runs the assertEqual() call
        self.assertEqual(aws.severity, "high")  # runs the assertEqual() call

    def test_code_findings_merge_across_codeql_and_semgrep(self) -> None:  # defines the test_code_findings_merge_across_codeql_and_semgrep() function
        codeql = scoring.Finding(  # runs the Finding() call
            "codeql",  # supplies the literal text
            "code",  # supplies the literal text
            "high",  # supplies the literal text
            "py/sql-injection",  # supplies the literal text
            "SQL injection",  # supplies the literal text
            location="app/db.py:10",  # sets the location text
            file="app/db.py",  # sets the file text
            line=10,  # assigns the computed value to line
            cwe="CWE-89",  # sets the cwe text
            weight=scoring.weight_for("code", "high"),  # runs the weight_for() call
        )  # closes the multiline block
        semgrep = scoring.Finding(  # runs the Finding() call
            "semgrep",  # supplies the literal text
            "code",  # supplies the literal text
            "medium",  # supplies the literal text
            "python.lang.security.audit.sql-injection",  # supplies the literal text
            "SQL injection",  # supplies the literal text
            location="app/db.py:10",  # sets the location text
            file="app/db.py",  # sets the file text
            line=10,  # assigns the computed value to line
            cwe="CWE-89",  # sets the cwe text
            weight=scoring.weight_for("code", "medium"),  # runs the weight_for() call
        )  # closes the multiline block
        merged = scoring.merge_findings([codeql, semgrep])  # runs the merge_findings() call
        self.assertEqual(len(merged), 1)  # runs the assertEqual() call
        self.assertEqual(merged[0].tools, ["codeql", "semgrep"])  # runs the assertEqual() call
        self.assertEqual(merged[0].severity, "high")  # runs the assertEqual() call


class VerdictAndRenderingTests(unittest.TestCase):  # defines the VerdictAndRenderingTests class
    def test_optional_failure_is_a_warning_not_a_failed_verdict(self) -> None:  # defines the test_optional_failure_is_a_warning_not_a_failed_verdict() function
        status = {  # assigns the computed value to status
            "trivy": {"status": "ok"},  # maps the trivy dictionary entry
            "codeql": {"status": "ok"},  # maps the codeql dictionary entry
            "grype": {"status": "error", "details": ["Grype exited with code 1."]},  # maps the grype dictionary entry
        }  # closes the multiline block
        report = scoring.build_report([], scanner_status=status)  # runs the build_report() call
        self.assertEqual(report["verdict"], "SECURE")  # runs the assertEqual() call
        self.assertTrue(any("Grype" in warning for warning in report["warnings"]))  # runs the assertTrue() call
        self.assertEqual(report["by_tool"].get("grype", {}).get("total", 0), 0)  # runs the assertEqual() call

    def test_required_failure_still_forces_insecure(self) -> None:  # defines the test_required_failure_still_forces_insecure() function
        status = {  # assigns the computed value to status
            "trivy": {"status": "error"},  # maps the trivy dictionary entry
            "codeql": {"status": "ok"},  # maps the codeql dictionary entry
            "grype": {"status": "ok"},  # maps the grype dictionary entry
        }  # closes the multiline block
        report = scoring.build_report([], scanner_status=status)  # runs the build_report() call
        self.assertEqual(report["verdict"], "INSECURE")  # runs the assertEqual() call
        self.assertIn("required scanner", report["verdict_reason"])  # runs the assertIn() call

    def test_skipped_tools_are_not_counted_as_by_tool_rows(self) -> None:  # defines the test_skipped_tools_are_not_counted_as_by_tool_rows() function
        status = {  # assigns the computed value to status
            "trivy": {"status": "ok"},  # maps the trivy dictionary entry
            "codeql": {"status": "ok"},  # maps the codeql dictionary entry
            "semgrep": {"status": "skipped"},  # maps the semgrep dictionary entry
        }  # closes the multiline block
        report = scoring.build_report([], scanner_status=status)  # runs the build_report() call
        self.assertNotIn("semgrep", report["by_tool"])  # runs the assertNotIn() call
        self.assertIn("FINDINGS BY TOOL", scoring.render_report_text(report))  # runs the assertIn() call
        self.assertTrue(  # runs the assertTrue() call
            any(  # runs the any() call
                "Not run this time" in warning and "Semgrep CE" in warning  # supplies the literal text
                for warning in report["warnings"]  # loops over the collection
            )  # closes the multiline block
        )  # closes the multiline block

    def test_text_names_tool_and_location(self) -> None:  # defines the test_text_names_tool_and_location() function
        finding = scoring.Finding(  # runs the Finding() call
            "semgrep",  # supplies the literal text
            "code",  # supplies the literal text
            "high",  # supplies the literal text
            "python.lang.security.audit.sql-injection",  # supplies the literal text
            "SQL injection",  # supplies the literal text
            location="app/db.py:10",  # sets the location text
            file="app/db.py",  # sets the file text
            line=10,  # assigns the computed value to line
            cwe="CWE-89",  # sets the cwe text
            detail="User input reaches a SQL query.",  # sets the detail text
            weight=scoring.weight_for("code", "high"),  # runs the weight_for() call
        )  # closes the multiline block
        report = scoring.build_report(  # runs the build_report() call
            [finding],  # executes the statement
            scanner_status={"trivy": {"status": "ok"}, "codeql": {"status": "ok"}},  # assigns the computed value to scanner_status
        )  # closes the multiline block
        text = scoring.render_report_text(report)  # runs the render_report_text() call
        self.assertIn("Identified by: Semgrep CE", text)  # runs the assertIn() call
        self.assertIn("app/db.py:10", text)  # runs the assertIn() call
        self.assertIn("FINDINGS BY TOOL", text)  # runs the assertIn() call
        self.assertIn("ALL FINDINGS", text)  # runs the assertIn() call
        self.assertIn("Semgrep CE", text)  # runs the assertIn() call


class ToolSelectionTests(unittest.TestCase):  # defines the ToolSelectionTests class
    def test_default_is_every_scanner(self) -> None:  # defines the test_default_is_every_scanner() function
        self.assertEqual(scanners.normalize_tools(None), list(config.ALL_TOOLS))  # runs the assertEqual() call

    def test_normalises_case_and_display_order(self) -> None:  # defines the test_normalises_case_and_display_order() function
        self.assertEqual(  # runs the assertEqual() call
            scanners.normalize_tools(["codeql", "TRIVY", "trivy"]),  # runs the normalize_tools() call
            ["codeql", "trivy"],  # executes the statement
        )  # closes the multiline block

    def test_unknown_tool_is_rejected(self) -> None:  # defines the test_unknown_tool_is_rejected() function
        with self.assertRaises(scanners.ScanError):  # opens the context for the block
            scanners.normalize_tools(["trivy", "not-a-scanner"])  # runs the normalize_tools() call

    def test_empty_selection_is_rejected(self) -> None:  # defines the test_empty_selection_is_rejected() function
        with self.assertRaises(scanners.ScanError):  # opens the context for the block
            scanners.normalize_tools([])  # runs the normalize_tools() call


if __name__ == "__main__":  # runs the module entry point
    unittest.main(verbosity=2)  # runs the main() call

