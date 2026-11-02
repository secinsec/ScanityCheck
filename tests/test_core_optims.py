"""Focused unit tests for the core performance/structure refactor slice.

Covers the pieces the optimisation pass touched:

* the lazy dashboard aggregate (equivalence with the eager values, memoization
  and the skipped-work property),
* the single framework-match sweep producing exactly the two structures the
  old two-pass implementation produced,
* the shared finding-group/location key builders staying consistent across
  scoring, compliance and the omission toggling round-trip,
* the shared clip/charge helpers behaving like the private ones they replace.
"""

from __future__ import annotations  # imports annotations from the __future__ module

import sys  # imports the sys module
import unittest  # imports the unittest module
from collections import Counter  # imports the Counter class
from pathlib import Path  # imports Path from the pathlib module
from unittest import mock  # imports the mock helper

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # inserts the repo root

import care  # noqa: E402  # imports the care module
import compliance  # noqa: E402  # imports the compliance module
import config  # noqa: E402  # imports the config module
import dashboard  # noqa: E402  # imports the dashboard module
import scoring  # noqa: E402  # imports the scoring module
import textutil  # noqa: E402  # imports the shared text helpers



def all_status() -> dict:  # defines the all_status() function
    return {tool: {"status": "ok"} for tool in config.ALL_TOOLS}  # everything completed


def finding(  # defines the finding() function
    source: str,  # evaluates the source expression
    category: str,  # evaluates the category expression
    severity: str,  # evaluates the severity expression
    rule_id: str,  # evaluates the rule_id expression
    title: str,  # evaluates the title expression
    file: str = "app/main.py",  # evaluates the file expression
    line: int = 1,  # evaluates the line expression
    package: str = "",  # evaluates the package expression
    cwe: str = "",  # evaluates the cwe expression
    kind: str = "",  # evaluates the kind expression
    cvss: float = 0.0,  # evaluates the cvss expression
    epss: float = 0.0,  # evaluates the epss expression
    kev: bool = False,  # evaluates the kev expression
    published: str = "",  # evaluates the published expression
) -> scoring.Finding:  # closes the multiline block
    return scoring.Finding(  # returns the scoring.Finding to the caller
        source, category, severity, rule_id, title,  # walks the arguments
        location=f"{file}:{line}",  # sets the location text
        weight=scoring.weight_for(category, severity),  # runs the weight_for() call
        file=file, line=line, package=package, cwe=cwe, kind=kind,  # sets the row shape
        cvss=cvss, epss=epss, kev=kev, published=published,  # fetches the engine signals
    )  # closes the multiline block


def synthetic_report() -> dict:  # defines the synthetic_report() function
    """A small-but-every-widget report build, the lazy-equivalence fixture."""
    findings = [  # evaluates the findings expression
        finding("trivy", "vulnerability", "critical", "CVE-2021-3121", "react CVE",
                "package-lock.json", 1, package="react", cwe="CWE-79",
                cvss=9.1, kev=True, published="2021-01-01"),  # the KEV row
        finding("grype", "vulnerability", "high", "CVE-2020-7753", "django CVE",
                "requirements.txt", 1, package="django", cwe="CWE-502",
                cvss=7.5, epss=0.42, published="2020-10-01"),  # the dated row
        finding("osv", "vulnerability", "medium", "GHSA-1234", "osv CVE",
                "app/main.py", 20, cwe="CWE-89", published="2019-02-02"),  # the third vuln
        finding("gitleaks", "secret", "critical", "aws key", "AWS key",
                "app/settings.py", 4, kind="aws"),  # the secret row
        finding("checkov", "misconfiguration", "unknown", "CKV_DOCKER_2", "HEALTHCHECK",
                "Dockerfile", 1),  # the infra row
        finding("codeql", "code", "high", "py/sql", "sql injection in handler",
                "app/main.py", 10, cwe="CWE-089"),  # the code row
    ]  # closes the list build
    return scoring.build_report(  # returns the built report
        findings,  # runs the build_report() call
        scanner_status=all_status(),  # runs the all_status() call
        languages=["python", "javascript"],  # assigns the languages value
        language_file_counts={"python": 4, "javascript": 2},  # sets the counts
        dashboard_inputs={"containers": 2, "api_specs": ["openapi.json"],
                          "dep_tree_depth": 4, "deprecated": ["fsevents"]},  # the repo inputs
    )  # closes the multiline block


class LazyDashboardCounterTests(unittest.TestCase):  # the lazy counter tests class
    def test_every_widget_matches_the_fully_ticked_selection(self) -> None:
        report = synthetic_report()  # runs the synthetic builder
        everything = dashboard.collect_metrics(report, config.DASHBOARD_ALL)  # the eager reference
        for key in config.DASHBOARD_ALL:  # walks every widget key
            with self.subTest(key=key):  # opens the context per key
                solo = dashboard.collect_metrics(report, [key])  # the single-widget call
                self.assertEqual(solo[key], everything[key])  # the payload equality

    def test_counters_compute_at_most_once_and_only_when_ticked(self) -> None:
        report = synthetic_report()  # runs the synthetic builder
        uses: Counter = Counter()  # the per-aggregate hit tally
        real_get = dashboard._Metrics.get  # the real accessor

        def counting_get(self, name: str):  # defines the counting wrapper
            if name not in self._cache:  # only real computations hit the tally
                uses[name] += 1  # tallies one more computation
            return real_get(self, name)  # the memoized result

        with mock.patch.object(dashboard._Metrics, "get", counting_get):  # spies the access
            payloads = dashboard.collect_metrics(report, ["heat_map", "kev_status"])  # two widgets
        used = {name for name, count in uses.items() if count}  # the touched aggregates
        self.assertIn("heat_rows", used)  # the heat widget's aggregate
        self.assertIn("kev_findings", used)  # the KEV widget's aggregate
        self.assertNotIn("language_counts", used)  # nothing else is computed
        self.assertNotIn("epss_values", used)  # ...
        for name, count in uses.items():  # walks the tally
            self.assertLessEqual(count, 1, f"{name} was computed {count} time(s)")  # once per aggregate

        # And the payloads are still complete for their widgets.
        self.assertEqual(payloads["heat_map"]["kind"], "heat")  # the heat payload
        self.assertEqual(payloads["kev_status"]["kind"], "number")  # the KEV payload

    def test_heat_rows_equal_the_naive_double_loop(self) -> None:
        report = synthetic_report()  # runs the synthetic builder
        findings = [f for f in report["findings"] if not f.get("omitted")]  # the widget input
        sev_counts = Counter(str(f.get("severity") or "unknown") for f in findings)  # the severity counter
        file_counts = Counter(f.get("file") or "?known location" for f in findings)  # the file counter
        top_files = [name for name, _ in file_counts.most_common(10)]  # the hottest files
        heat_sevs = [sev for sev in dashboard._SEV_ORDER if sev_counts.get(sev)]  # the drawn columns
        expected = []  # the legacy value
        for file_id in top_files:  # the naive per-file rescan
            buckets = Counter(  # evaluates the buckets expression
                f.get("severity") for f in findings  # walks the findings
                if f.get("file") == file_id and f.get("severity")  # filters the rows
            )  # closes the multiline block
            expected.append(  # adds the legacy row
                (dashboard._clip(file_id, 40), {sev: buckets.get(sev, 0) for sev in heat_sevs})  # the pair
            )  # closes the append
        store = dashboard._Metrics(findings, report)  # the lazy aggregate
        self.assertEqual(store.get("heat_rows"), expected)  # the value equality

    def test_collect_repo_inputs_uses_file_paths_instead_of_walking(self) -> None:
        with tempfile_dir() as tmp:  # opens the scratch root
            root = Path(tmp)  # the repository root
            (root / "Dockerfile").write_text("FROM scratch\n")  # a container the list omits
            (root / "bogus.lock").write_text("x")  # a walker-only distraction
            spec = root / "api"  # the spec folder
            spec.mkdir()  # creates the folder
            (spec / "swagger.yaml").write_text("swagger: '2.0'")  # the spec file
            inputs = dashboard.collect_repo_inputs(  # the screened call
                root, file_paths=[spec / "swagger.yaml"]  # only one path given
            )  # closes the multiline block
        self.assertEqual(inputs["containers"], 0)  # the unlisted Dockerfile is not seen
        self.assertEqual(inputs["api_specs"], ["api/swagger.yaml"])  # the listed spec, root-relative


class tempfile_dir:  # defines the tiny context helper
    """A labelled temp directory (keeps this module stdlib-only reading)."""

    def __enter__(self) -> str:  # defines the enter hook
        import tempfile  # imports the tempfile module
        self._handle = tempfile.TemporaryDirectory()  # creates the folder
        return self._handle.name  # returns the path

    def __exit__(self, *exc: object) -> None:  # defines the exit hook
        self._handle.cleanup()  # cleans the folder


def legacy_map_all(findings, framework_keys):  # defines the legacy two-pass matcher
    """The pre-refactor implementation, inlined for the equality check."""
    keys = compliance.normalize_frameworks(framework_keys)  # the selection pass
    frameworks = {}  # the grouped payloads
    finding_map = {}  # the per-finding refs
    for key in keys:  # loops over the frameworks
        framework = compliance.FRAMEWORKS[key]  # fetches the framework
        buckets = {  # the per-control buckets
            control.id: {"id": control.id, "title": control.title, "status": "clear",
                         "affected": 0, "worst": "", "rule_ids": [], "examples": []}
            for control in framework.controls  # walks the controls
        }  # closes the multiline block
        mapped_ids = set()  # the mapped identity set
        for item in findings:  # the first full walk
            text = f"{item.rule_id} {item.title} {item.detail}".lower()  # the rebuilt search text
            matched = []  # the matched controls
            for control in framework.controls:  # the per-control matching
                if item.category not in control.categories:  # evaluates the branch condition
                    continue  # skips the row
                if control.kinds and item.kind not in control.kinds:  # evaluates the branch condition
                    continue  # skips the row
                if control.keywords and not any(
                        keyword in text for keyword in control.keywords):  # the keyword pass
                    continue  # skips the row
                matched.append(control)  # adds the control
            for control in matched:  # the bucket fill
                bucket = buckets[control.id]  # fetches the bucket
                bucket["affected"] += 1  # bumps the count
                bucket["rule_ids"].append(item.rule_id)  # appends the rule
                if len(bucket["examples"]) < 3:  # evaluates the branch condition
                    bucket["examples"].append(f"{item.title} ({item.location or 'location n/a'})")  # caps the samples
                if not bucket["worst"] or compliance._rank(item.severity) < compliance._rank(bucket["worst"]):  # the worst rank
                    bucket["worst"] = item.severity  # keeps the worst
            if matched:  # evaluates the branch condition
                mapped_ids.add(id(item))  # marks the finding mapped
                entry = finding_map.setdefault(  # runs the setdefault() call
                    f"{item.rule_id}|{item.file}|{item.line}", {}  # the legacy key shape
                )  # closes the multiline block
                entry[framework.label] = [c.id for c in matched]  # stores the refs
        for bucket in buckets.values():  # the status pass
            if bucket["affected"]:  # evaluates the branch condition
                bucket["status"] = "affected"  # flips to affected
            else:  # covers the remaining branch
                bucket.pop("rule_ids", None)  # drops the empty lists
                bucket.pop("examples", None)  # drops the empty lists
        frameworks[key] = {  # the legacy payload
            "key": key, "label": framework.label, "description": framework.description,
            "controls": list(buckets.values()),
            "affected_controls": sum(1 for b in buckets.values() if b["status"] == "affected"),
            "total_controls": len(buckets),
            "unmapped": sum(1 for item in findings if id(item) not in mapped_ids),  # the second sweep
        }  # closes the multiline block
    return frameworks, finding_map  # returns both structures


class SingleMatchPassTests(unittest.TestCase):  # the single-sweep tests class
    FIXTURE = [  # one finding of every category plus keyword-driven cases
        finding("trivy", "vulnerability", "high", "CVE-2021-23337", "lodash injection",
                "package-lock.json", 0, package="lodash"),  # the vuln row
        finding("gitleaks", "secret", "critical", "gitleaks:aws", "AWS key committed",
                "app.py", 10, kind="aws"),  # the secret row
        finding("checkov", "misconfiguration", "unknown", "CKV_DOCKER_9",
                "port exposed in image", "Dockerfile", 0),  # the infra row
        finding("guarddog", "vulnerability", "high", "install-scripts:eval",
                "malicious install script", "setup.py", 0, kind="malicious"),  # the supply row
        finding("codeql", "code", "medium", "py/bad", "bad pattern",
                "app/db.py", 33, cwe="CWE-000"),  # the code row
        finding("semgrep", "code-quality", "low", "qc/dup", "duplicated block",
                "app/db.py", 40),  # the quality row
    ]  # closes the list build

    def test_map_all_matches_the_legacy_two_pass(self) -> None:
        legacy_frameworks, legacy_map = legacy_map_all(self.FIXTURE, compliance.ALL_FRAMEWORKS)  # the old pass
        frameworks, finding_map = compliance.map_all(self.FIXTURE, compliance.ALL_FRAMEWORKS)  # the new pass
        self.assertEqual(frameworks, legacy_frameworks)  # the grouped payload equality
        self.assertEqual(finding_map, legacy_map)  # the per-finding ref equality

    def test_wrappers_match_their_legacy_outputs_per_framework(self) -> None:
        for framework_key in compliance.ALL_FRAMEWORKS:  # walks every framework
            with self.subTest(framework=framework_key):  # opens the per-framework context
                mapped = compliance.map_findings(self.FIXTURE, [framework_key])  # the grouped wrapper
                refs = compliance.findings_control_map(self.FIXTURE, [framework_key])  # the refs wrapper
                frameworks, finding_map = compliance.map_all(self.FIXTURE, [framework_key])  # the sweep
                self.assertEqual(mapped, frameworks)  # the wrapper agreement
                self.assertEqual(refs, finding_map)  # the wrapper agreement


class SharedKeyBuilderTests(unittest.TestCase):  # the key-builder tests class
    def test_group_key_agrees_across_shapes_and_modules(self) -> None:
        row = scoring.Finding("trivy", "vulnerability", "high", "CVE-1", "title")  # the object form
        payload = row.to_dict()  # the dict form
        self.assertEqual(
            scoring.finding_group_key(row), reportkeys_key("group", row))  # the builder agreement
        self.assertEqual(
            scoring.finding_group_key(payload), scoring.finding_group_key(row))  # the shape agreement
        self.assertEqual(
            recommendations_key(payload), scoring.finding_group_key(row))  # the module agreement

    def test_omission_toggle_hits_the_right_groups(self) -> None:
        findings = [  # two secrets plus a code theme
            finding("gitleaks", "secret", "high", "big-leak", "big leak", file="a.py"),  # the secret
            finding("codeql", "code", "high", "py/sql", "sql injection",
                    file="app.py", line=10, cwe="CWE-089"),  # the code
        ]  # closes the list build
        report = scoring.build_report(findings, scanner_status=all_status())  # runs the build
        keys = {risk["key"] for risk in report["greatest_risks"]}  # the visible keys
        self.assertEqual(keys, {"secret|big-leak", "code|py/sql"})  # the expected themes

        big = scoring.finding_group_key(report["findings"][0])  # the dict-built key
        self.assertIn(big, keys)  # the key names a real theme
        scoring.rescore_report(report, [big])  # excludes the theme
        flags = {finding["rule_id"]: finding["omitted"] for finding in report["findings"]}  # the flags
        self.assertEqual(flags, {"big-leak": True, "py/sql": False})  # the right rows flipped
        rows = {risk["key"]: risk for risk in report["greatest_risks"]}  # the refreshed rows
        self.assertTrue(rows["secret|big-leak"]["omitted"])  # the theme stays listed, flagged
        self.assertFalse(rows["code|py/sql"]["omitted"])  # the survivor untouched

        scoring.rescore_report(report, [])  # re-includes everything (empty list clears the choice)
        flags = {finding["rule_id"]: finding["omitted"] for finding in report["findings"]}  # the flags
        self.assertEqual(set(flags.values()), {False})  # the round-trip clears the flags

    def test_location_key_reaches_the_csv_join(self) -> None:  # the location-map test
        row = {"rule_id": "CVE-1", "file": "", "line": 0}  # the dict row shape
        self.assertEqual(reportkeys_key("location", row), "CVE-1||0")  # the shared key
        self.assertEqual(compliance._finding_key(  # the compliance alias
            scoring.Finding("trivy", "vulnerability", "high", "CVE-1", "t")),  # the object form
            "CVE-1||0")  # the joined value


def reportkeys_key(kind: str, finding) -> str:  # defines the module import helper
    """The shared builder straight from reportkeys."""
    import reportkeys  # imports the shared registry

    if kind == "location":  # evaluates the branch condition
        return reportkeys.location_key(finding)  # the row identity key
    return reportkeys.finding_group_key(finding)  # the theme key


def recommendations_key(finding) -> str:  # defines the recommendations helper
    import recommendations  # imports the ranker module

    return recommendations._theme_key(finding)  # returns the theme key


class SharedChargeTests(unittest.TestCase):  # the shared charge maths tests class
    def test_effective_charges_match_the_legacy_recommendations_maths(self) -> None:
        findings = [  # a capped category plus unbound ones
            scoring.Finding("gitleaks", "secret", "high", f"leak-{index}", "aws key",
                            weight=20.0, file=f"f{index}.py")  # three heavy secrets
            for index in range(3)  # walks the trio
        ] + [  # closes the capped slice
            scoring.Finding("codeql", "code", "high", "py/sql", "sql", file="a.py"),  # an unbound one
        ]  # closes the list build
        legacy_raw: dict[str, float] = {}  # the legacy accumulation
        for item in findings:  # loops over the collection
            category = item.category  # reads the category
            legacy_raw[category] = legacy_raw.get(category, 0.0) + float(item.weight or 0.0)  # accumulates
        legacy_shares = []  # the legacy per-finding shares
        for item in findings:  # loops over the collection
            category = item.category  # reads the category
            weight = float(item.weight or 0.0)  # reads the weight
            legacy_shares.append(  # appends the share
                (min(legacy_raw[category], config.CAPS.get(category, legacy_raw[category])) *  # the applied
                 (weight / legacy_raw[category]))  # the raw share
                if legacy_raw[category] > config.CAPS.get(category, weight)  # cap-bound
                else weight  # unbound
            )  # closes the append
        sweep = scoring.effective_charges(findings, config.CAPS)  # the shared pass
        self.assertEqual(sweep.raw, legacy_raw)  # the raw equality
        self.assertEqual(sweep.shares, legacy_shares)  # the share equality

    def test_recommendations_and_refunds_agree_widget_for_widget(self) -> None:
        findings = [  # three capped secret themes
            scoring.Finding("gitleaks", "secret", "high", f"leak-{index}", "aws key",
                            weight=20.0, file=f"f{index}.py")  # builds the theme row
            for index in range(3)  # walks the trio
        ]  # closes the list build
        report = scoring.build_report(findings, scanner_status=all_status())  # runs the build
        recs = {row["key"]: row for row in recommendations_build(report)}  # the ranked themes
        for index in range(3):  # walks the themes
            key = f"secret|leak-{index}"  # the theme key
            row = next(  # the matching risk row
                risk for risk in report["greatest_risks"] if risk["key"] == key  # filters the rows
            )  # closes the next call
            self.assertAlmostEqual(  # the impact/charge agreement
                recs[key]["impact"], round(row["charge"], 1), places=1  # the shared arithmetic
            )  # closes the assertion


def recommendations_build(report):  # defines the import helper
    """The recommendations ranker, imported lazily for clarity."""
    import recommendations  # imports the ranker module

    return recommendations.build_recommendations(report)  # returns the ranked list


class CareRenderPairsTests(unittest.TestCase):  # the care pair tests class
    SUMMARY = {  # a dense summary covering both pair shapes
        "last_commit_at": "2026-06-01T00:00:00Z",  # the commit stamp
        "last_commit_days": 0.0,  # the fresh age
        "release_count": 0,  # the honest empty release count
        "commits_last_year": 100,  # the yearly total
        "commit_frequency_per_week": 2.0,  # the cadence
        "development_trend": "steady",  # the trend
        "weekly_avg_recent": 2.0,  # the recent average
        "weekly_avg_prior": 2.0,  # the prior average
        "median_issue_close_days": 5.0,  # the closure median
        "issues_closed_sampled": 3,  # the sample size
        "notes": ["contributors: unavailable"],  # the API note
    }  # closes the summary

    def test_pairs_join_back_to_the_legacy_lines(self) -> None:
        pairs = care.render_pairs(self.SUMMARY)  # the structured rows
        self.assertTrue(all(isinstance(pair, tuple) and len(pair) == 2 for pair in pairs))  # the shape
        self.assertEqual(  # the joined equality
            care.render_summarized(self.SUMMARY),  # the padded render
            [f"{label:<23}{value}" if label else value for label, value in pairs],  # the join rule
        )  # closes the assertion
        self.assertEqual(pairs[-1], ("", "- contributors: unavailable"))  # the full-width note row
        self.assertEqual(  # the disclaimer is a full-width row
            pairs[-2][0], "", "the time-to-close disclaimer has no label column")  # the shape check

    def test_empty_release_becomes_a_labelled_row(self) -> None:  # the release-row test
        summary = {key: value for key, value in self.SUMMARY.items() if key != "notes"}  # drops the notes
        pairs = care.render_pairs(summary)  # the structured rows
        self.assertIn(("Last release", "none found on this repository"), pairs)  # the honest row


class ExplanationTableTests(unittest.TestCase):  # the config-driven explainer tests class
    def test_numbers_follow_the_weight_and_cap_tables(self) -> None:
        text = scoring.explanation_text()  # the generated explainer
        for category, label in (  # the table walks
            ("secret", "secrets cost the most"),  # the credential block
            ("misconfiguration", "Infrastructure misconfigurations"),  # the infra block
            ("code", "CodeQL or Semgrep"),  # the code block
        ):  # closes the multiline block
            weights = "/".join(  # the printed severity row
                f"{weight:g}" for weight in (  # walks the four slices
                    config.WEIGHTS[category][sev]  # the table value
                    for sev in ("critical", "high", "medium", "low")  # the printed slices
                )  # closes the multiline block
            )  # closes the multiline block
            self.assertIn(weights, text, f"{label} weights missing from the explainer")  # the table echo
        vuln = config.WEIGHTS["vulnerability"]  # the verbatim sentence table
        self.assertIn(  # the CVE sentence numbers
            f"{vuln['critical']:g} (critical), {vuln['high']:g} (high), "  # the formatted weights
            f"{vuln['medium']:g} (medium) or {vuln['low']:g} (low)", text)  # closes the assertion
        self.assertIn(f"dependencies {config.CAPS['vulnerability']:g}", text)  # the cap echo
        self.assertIn(f"secrets {config.CAPS['secret']:g}", text)  # the cap echo


def mock_placeholder() -> None:  # defines the unused helper
    """Kept out: the mock import above lives with the counting test."""  # keeps the docstring text


if __name__ == "__main__":  # runs the module
    unittest.main(verbosity=2)  # starts the runner

