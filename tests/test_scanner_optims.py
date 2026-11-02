"""Optimisation tests for the shared download/process helpers and fan-out.

Everything runs offline: the network helpers are patched out and the
subprocess helpers only shell out to the local Python interpreter.
"""

from __future__ import annotations  # imports annotations from the __future__ module

import hashlib  # imports the hashlib module
import os  # imports the os module
import sys  # imports the sys module
import tempfile  # imports the tempfile module
import threading  # imports the threading module
import unittest  # imports the unittest module
import urllib.error  # imports the urllib.error module
import zipfile  # imports the zipfile module
from contextlib import contextmanager  # imports contextmanager from the contextlib module
from pathlib import Path  # imports Path from the pathlib module
from typing import Any  # imports Any from the typing module
from unittest import mock  # imports mock from the unittest module

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # inserts text or data

import bootstrap  # noqa: E402  # imports the bootstrap module
import config  # noqa: E402  # imports the config module
import netproc  # noqa: E402  # imports the netproc module
import scanners  # noqa: E402  # imports the scanners module


class _QuietLog:
    """Collects the fake download logs without talking to the app."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def __call__(self, message: str) -> None:
        self.lines.append(str(message))


class _FakeHeaders:
    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def get(self, name: str, default: str | None = None) -> str | None:
        return self._values.get(name, default)


class _FakeResponse:
    """A urllib response replaying a scripted byte budget, then can raise."""

    def __init__(self, chunks: list[bytes], raise_after: Exception | None = None) -> None:
        self._chunks = chunks
        self._raise_after = raise_after
        self.status = 200
        self.headers = _FakeHeaders({})

    def read(self, size: int = -1) -> bytes:
        try:
            chunk = self._chunks.pop(0)
        except IndexError:
            if self._raise_after is not None:
                error = self._raise_after
                self._raise_after = None
                raise error
            return b""
        return chunk if size < 0 else chunk[:size]

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(f"https://x/{code}", code, "nope", None, None)


class DownloadRobustnessTests(unittest.TestCase):
    """download(): Range resume, transient retries and the .part lifecycle."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dest = Path(self.tmp.name) / "tool.zip"
        self.content = b"HEAD" + b"x" * 4096 + b"TAIL"
        self.log = _QuietLog()
        self.cancel = threading.Event()
        self.url = "https://github.com/example/tool/zip"

    def test_resume_carrys_over_the_part_file(self) -> None:
        seen: list[dict[str, str]] = []

        @contextmanager
        def fake_get(url, headers, timeout=None):
            seen.append(dict(headers or {}))
            if len(seen) == 1:
                yield _FakeResponse([self.content[:512]], OSError("connection dropped"))
            response2 = _FakeResponse([self.content[512:]])
            response2.status = 206  # the server accepted the Range request
            yield response2

        with mock.patch.object(bootstrap, "_http_get", fake_get):
            with mock.patch.object(bootstrap.time, "sleep", lambda seconds: None):
                bootstrap.download(self.url, self.dest, log=self.log, cancel=self.cancel, what="tool")
        self.assertEqual(self.dest.read_bytes(), self.content)
        self.assertFalse(self.dest.with_suffix(".zip.part").exists())
        self.assertEqual(seen[1]["Range"], "bytes=512-")

    def test_416_restarts_from_a_clean_part(self) -> None:
        part = self.dest.with_suffix(self.dest.suffix + ".part")
        part.write_bytes(self.content[:512])  # a leftover resume state
        seen: list[dict[str, str]] = []

        @contextmanager
        def fake_get(url, headers, timeout=None):
            seen.append(dict(headers or {}))
            if len(seen) == 1:
                raise _http_error(416)  # the server refuses the resume attempt
            yield _FakeResponse([self.content])

        with mock.patch.object(bootstrap, "_http_get", fake_get):
            bootstrap.download(self.url, self.dest, log=self.log, cancel=self.cancel, what="tool")
        self.assertEqual(self.dest.read_bytes(), self.content)
        self.assertNotIn("Range", seen[1])

    def test_transient_5xx_is_retried(self) -> None:
        statuses = [503, 200]

        @contextmanager
        def fake_get(url, headers, timeout=None):
            code = statuses.pop(0)
            if code != 200:
                raise _http_error(code)
            yield _FakeResponse([self.content])

        with mock.patch.object(bootstrap, "_http_get", fake_get):
            with mock.patch.object(bootstrap.time, "sleep", lambda seconds: None):
                bootstrap.download(self.url, self.dest, log=self.log, cancel=self.cancel, what="tool")
        self.assertEqual(self.dest.read_bytes(), self.content)

    def test_404_stays_fatal_and_cleans_up(self) -> None:
        @contextmanager
        def fake_get(url, headers, timeout=None):
            raise _http_error(404)
            yield None  # never reached

        with mock.patch.object(bootstrap, "_http_get", fake_get):
            with self.assertRaises(bootstrap.ScanError):
                bootstrap.download(self.url, self.dest, log=self.log, cancel=self.cancel, what="tool")
        self.assertFalse(self.dest.with_suffix(self.dest.suffix + ".part").exists())


class ChecksumTests(unittest.TestCase):
    """Plumbing for the per-tool digest field on the pinned specs."""

    def test_pinned_specs_use_runtime_checksum_sources(self) -> None:
        self.assertEqual(bootstrap.TOOL_SPECS["nuclei"].checksum_object, config.NUCLEI_ZIP)
        self.assertTrue(bootstrap.TOOL_SPECS["nuclei"].checksum_url)
        self.assertTrue(bootstrap.TOOL_SPECS["kubescape"].checksum_url)
        for key in ("grype", "gitleaks", "trufflehog", "osv", "syft"):
            self.assertEqual(bootstrap.TOOL_SPECS[key].checksum_url, "")

    def test_verify_checksum_matches_the_published_digest(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        archive = Path(tmp.name) / "tool.zip"
        payload = b"binary bytes"
        archive.write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        checksum_file = Path(tmp.name) / "checksums.txt"
        checksum_file.write_text(f"{digest}  other.zip\n{digest}  tool.zip\n", encoding="utf-8")
        spec = bootstrap.ToolSpec(
            key="tool", label="Tool", kind="zip", url="u", archive="tool.zip",
            executable="tool.exe", min_bytes=1, version="1",
            checksum_url=str(checksum_file), checksum_object="tool.zip",
        )
        logs: list[str] = []

        @contextmanager
        def fake_get(url, headers, timeout=None):
            yield _FakeResponse([checksum_file.read_bytes()])

        with mock.patch.object(bootstrap, "_http_get", fake_get):
            self.assertTrue(bootstrap._verify_checksum(archive, spec, logs.append))

    def test_verify_checksum_refuses_a_mismatch(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        checksum_file = Path(tmp.name) / "checksums.txt"
        checksum_file.write_text("aa11  tool.zip\n", encoding="utf-8")
        spec = bootstrap.ToolSpec(
            key="tool", label="Tool", kind="zip", url="u", archive="tool.zip",
            executable="tool.exe", min_bytes=1, version="1",
            checksum_url=str(checksum_file), checksum_object="tool.zip",
        )
        tampered = Path(tmp.name) / "tool.zip"
        tampered.write_bytes(b"tampered")
        logs: list[str] = []

        @contextmanager
        def fake_get(url, headers, timeout=None):
            yield _FakeResponse([checksum_file.read_bytes()])

        with mock.patch.object(bootstrap, "_http_get", fake_get):
            with self.assertRaises(bootstrap.ToolError):
                bootstrap._verify_checksum(tampered, spec, logs.append)

    def test_verify_checksum_skips_tools_without_a_checksum(self) -> None:
        spec = bootstrap.ToolSpec(
            key="tool", label="Tool", kind="zip", url="u", archive="tool.zip",
            executable="tool.exe", min_bytes=1, version="1",
        )
        archive = Path("nowhere.zip")
        self.assertFalse(bootstrap._verify_checksum(archive, spec, lambda m: None))


class RunSilentTailTests(unittest.TestCase):
    def test_run_silent_keeps_the_tail_from_a_huge_output(self) -> None:
        marker = "ENDMARKER"
        cmd = [sys.executable, "-c", f"print('A' * 100000); print({marker!r})"]
        code, tail = bootstrap.run_silent(cmd, timeout=60, cancel=threading.Event())
        self.assertEqual(code, 0)
        self.assertIn(marker, tail)
        self.assertLessEqual(len(tail), 4000)


class ZipSlipTests(unittest.TestCase):
    def test_sibling_directory_entry_is_refused(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        archive_path = Path(tmp.name) / "evil.zip"
        target = Path(tmp.name) / "out"
        weapon = zipfile.ZipFile(archive_path, "w")
        weapon.writestr("../tools2/payload.txt", "boom")
        weapon.close()
        with self.assertRaises(bootstrap.ScanError):
            bootstrap.extract_zip(archive_path, target)
        self.assertFalse((Path(tmp.name) / "tools2").exists())

    def test_plain_zip_still_extracts(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        archive_path = Path(tmp.name) / "ok.zip"
        target = Path(tmp.name) / "out"
        bundle = zipfile.ZipFile(archive_path, "w")
        bundle.writestr("folder/inner.txt", "fine")
        bundle.close()
        bootstrap.extract_zip(archive_path, target)
        self.assertTrue((target / "folder" / "inner.txt").exists())


class SharedWalkTests(unittest.TestCase):
    """The single shared tree walk and the derived IaC skip decision."""

    def _tree(self, with_iac: bool) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "src").mkdir()
        (root / "src" / "main.py").write_text("x = 1", encoding="utf-8")
        (root / "src" / "helper.py").write_text("y = 2", encoding="utf-8")
        (root / "node_modules" / "leftpad").mkdir(parents=True)
        (root / "node_modules" / "leftpad" / "index.js").write_text("", encoding="utf-8")
        if with_iac:
            (root / "deploy").mkdir()
            (root / "deploy" / "main.tf").write_text('', encoding="utf-8")
        return root

    def test_iter_tree_skips_config_skip_dirs(self) -> None:
        root = self._tree(with_iac=False)
        names = [str(path.relative_to(root)) for path in scanners._iter_tree(root)]
        self.assertNotIn("node_modules", " ".join(names))
        self.assertEqual(len(names), 2)

    def test_detect_languages_consumes_the_shared_list(self) -> None:
        root = self._tree(with_iac=False)
        shared = list(scanners._iter_tree(root))
        languages, counts = scanners.detect_languages(root, file_paths=shared)
        self.assertEqual(languages, ["python"])
        self.assertEqual(counts["python"], 2)

    def test_detect_languages_still_walks_without_a_list(self) -> None:
        root = self._tree(with_iac=False)
        languages, _counts = scanners.detect_languages(root)
        self.assertEqual(languages, ["python"])

    def test_has_iac_files_is_conservative(self) -> None:
        self.assertTrue(scanners._has_iac_files([Path("repo/deploy/main.tf")]))
        self.assertTrue(scanners._has_iac_files([Path("repo/chart/values.yaml")]))
        self.assertTrue(scanners._has_iac_files([Path("repo/Dockerfile")]))
        self.assertTrue(scanners._has_iac_files([Path("repo/.github/workflows/ci.yml")]))
        self.assertFalse(scanners._has_iac_files([Path("repo/app.py"), Path("repo/a.txt")]))


class OsvCommandTests(unittest.TestCase):
    def test_sbom_pass_then_fallback_to_source_scan(self) -> None:
        """SBOM feed is preferred; the plain source scan stays the fallback."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        artifacts = Path(tmp.name) / "artifacts"
        artifacts.mkdir()
        root = Path(tmp.name) / "repo"
        root.mkdir()
        sbom = Path(tmp.name) / "syft.json"
        sbom.write_text("{}", encoding="utf-8")
        output = artifacts / "osv.json"
        calls: list[list[str]] = []

        def fake_run_command(cmd, **kwargs):
            calls.append(list(cmd))
            outcome = {"returncode": 0 if "--sbom" in cmd else 127, "tail": "", "duration": 0.1}
            if "--sbom" not in cmd:
                output.write_text('{"results": []}', encoding="utf-8")
            return scanners.CommandResult(**outcome)

        with mock.patch.object(scanners, "ensure_tool", lambda key, log, cancel: Path("osv.exe")):
            with mock.patch.object(scanners, "run_command", fake_run_command):
                _output, status = scanners.run_osv(
                    root, artifacts, log=lambda m: None, cancel=threading.Event(), sbom=sbom
                )
        self.assertEqual(len(calls), 2)
        self.assertIn("--sbom", calls[0])
        self.assertIn("-r", calls[1])
        self.assertEqual(status["status"], "ok")

    def test_source_shape_without_an_sbom(self) -> None:
        command = scanners._osv_source_command(Path("osv.exe"), Path("osv.json"), Path("repo"))
        self.assertEqual(command[1:3], ["scan", "source"])


class CareFeedingTests(unittest.TestCase):
    def test_last_commit_comes_from_the_commit_sample(self) -> None:
        """The separate per_page=1 round trip is gone; the sample carries it."""
        calls: list[str] = []
        newest = {"commit": {"committer": {"date": "2026-05-01T00:00:00Z"}}}
        oldest = {"commit": {"committer": {"date": "2026-04-01T00:00:00Z"}}}

        def fake_json(path, headers, query=None, log=None):
            calls.append(path)
            if path.endswith("/commits"):
                payload: Any = [newest, oldest]
            else:
                payload = []
            return payload, {"link": "", "status": "200"}

        with mock.patch.object(scanners, "_github_json", fake_json):
            with mock.patch.object(scanners, "_github_token", lambda: "token"):
                data = scanners.fetch_care_and_feeding(scanners.RepoRef(owner="o", repo="r"))
        self.assertEqual(data["last_commit_at"], "2026-05-01T00:00:00Z")
        commit_calls = [path for path in calls if path.endswith("/commits")]
        self.assertEqual(len(commit_calls), 1)
        self.assertEqual(data["recent_commit_authors"], [])

    def test_failed_metric_becomes_an_error_note(self) -> None:
        def failing_json(path, headers, query=None, log=None):
            raise urllib.error.URLError("rate limited")

        with mock.patch.object(scanners, "_github_json", failing_json):
            data = scanners.fetch_care_and_feeding(scanners.RepoRef(owner="o", repo="r"))
        self.assertTrue(any("could not be fetched" in note for note in data["errors"]))


class CodeqlSuiteTests(unittest.TestCase):
    def test_ladder_keeps_the_bare_pack_last(self) -> None:
        candidates = scanners._codeql_suite_candidates("python")
        self.assertEqual(len(candidates), 3)
        self.assertTrue(candidates[-1].endswith("codeql/python-queries"))

    def test_run_codeql_analyzes_once_when_suites_resolve(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        artifacts = Path(tmp.name) / "artifacts"
        artifacts.mkdir()
        root = Path(tmp.name) / "repo"
        root.mkdir()
        saw: list[list[str]] = []

        def fake_run_command(cmd, **kwargs):
            saw.append(list(cmd))
            if "resolve" in cmd:
                return scanners.CommandResult(returncode=0, tail="", duration=0.1)
            if "analyze" in cmd:
                Path(cmd[-1]).write_text("{}", encoding="utf-8")
                return scanners.CommandResult(returncode=0, tail="", duration=1.0)
            return scanners.CommandResult(returncode=0, tail="", duration=2.0)

        with mock.patch.object(scanners, "ensure_codeql", lambda log, cancel: Path("codeql.exe")):
            with mock.patch.object(scanners, "run_command", fake_run_command):
                sarif_files, status = scanners.run_codeql(
                    root, artifacts, ["python"], log=lambda m: None, cancel=threading.Event()
                )
        self.assertEqual(status["status"], "ok")
        self.assertEqual(len(sarif_files), 1)
        analyze_runs = [cmd for cmd in saw if "analyze" in cmd]
        self.assertEqual(len(analyze_runs), 1)
        self.assertTrue(any("resolve" in cmd for cmd in saw))


class FanOutTests(unittest.TestCase):
    """scan_repository pools the optional tools and keeps the semantics."""

    def _fake_pipeline(self, with_iac: bool) -> dict[str, Any]:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        cache = Path(tmp.name) / "cache"
        old_work, old_tools = config.WORK_DIR, config.TOOLS_DIR
        config.WORK_DIR, config.TOOLS_DIR = cache / "work", cache
        self.addCleanup(setattr, config, "WORK_DIR", old_work)
        self.addCleanup(setattr, config, "TOOLS_DIR", old_tools)

        root = Path(tmp.name) / "tree"
        root.mkdir()
        (root / "app.py").write_text("x = 1", encoding="utf-8")
        if with_iac:
            (root / "chart.yaml").write_text("kind: test", encoding="utf-8")

        ran: dict[str, str] = {}

        def fake_download_repo(ref, dest, **kwargs):
            if kwargs.get("file_paths") is not None:
                kwargs["file_paths"][:] = list(scanners._iter_tree(root))
            return root

        def fake_metadata(ref):
            return {"full_name": ref.full_name, "web_url": ref.web_url}

        def fake_care(ref, log=None):
            return {}

        def runner_for(name: str):
            def runner(root_path, artifacts_path, **kwargs):
                ran[name] = "ran"
                output = artifacts_path / f"{name}.json"
                output.write_text("{}", encoding="utf-8")
                return output, {"status": "ok", "duration_seconds": 0.1, "details": [f"{name} fake"]}
            return runner

        def fake_codeql(root_path, artifacts_path, languages, *, log, cancel):
            ran["codeql"] = "ran"
            return [], {"status": "skipped", "duration_seconds": 0.0, "details": ["no languages"]}

        tools = ["codeql", "trivy", "syft", "grype", "osv", "checkov", "kubescape"]
        patches = [
            mock.patch.object(scanners, "fetch_repo_metadata", fake_metadata),
            mock.patch.object(scanners, "fetch_care_and_feeding", fake_care),
            mock.patch.object(scanners, "download_repo", fake_download_repo),
            mock.patch.object(scanners.dashboards, "collect_repo_inputs", lambda root_path, **kw: {}),
            mock.patch.object(scanners, "run_codeql", fake_codeql),
        ]
        for name in ("trivy", "syft", "grype", "osv", "checkov", "kubescape"):
            patches.append(mock.patch.object(scanners, f"run_{name}", runner_for(name)))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        return {
            "ran": ran,
            "interesting": {name: False for name in tools},
            "report": None,
            "with_iac": with_iac,
        }

    def _run(self, with_iac: bool) -> tuple[dict[str, Any], dict[str, str]]:
        state = self._fake_pipeline(with_iac)
        report = scanners.scan_repository(
            "https://github.com/o/r",
            log=lambda m: None,
            cancel=threading.Event(),
            tools=["codeql", "trivy", "syft", "grype", "osv", "checkov", "kubescape"],
        )
        return report, state["ran"]

    def test_status_rows_assemble_in_display_order(self) -> None:
        report, ran = self._run(with_iac=True)
        self.assertEqual(list(report["scanner_status"]), list(config.ALL_TOOLS))
        for tool in ("trivy", "syft", "grype", "osv", "checkov", "kubescape"):
            self.assertEqual(report["scanner_status"][tool]["status"], "ok")
            self.assertIn(tool, ran)
        self.assertEqual(report["scanner_status"]["codeql"]["status"], "skipped")
        self.assertIn("codeql", ran)

    def test_no_iac_skips_checkov_and_kubescape(self) -> None:
        report, ran = self._run(with_iac=False)
        for tool in ("checkov", "kubescape"):
            self.assertEqual(report["scanner_status"][tool]["status"], "skipped")
            self.assertNotIn(tool, ran)
            self.assertTrue(report["scanner_status"][tool]["details"])
        self.assertEqual(report["scanner_status"]["trivy"]["status"], "ok")

    def test_cancelled_scan_raises(self) -> None:
        state = self._fake_pipeline(with_iac=True)
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(scanners.ScanCancelled):
            scanners.scan_repository(
                "https://github.com/o/r",
                log=lambda m: None,
                cancel=cancel,
                tools=["codeql", "trivy"],
            )


class NetprocHelpersTests(unittest.TestCase):
    def test_shared_helpers_live_in_one_place(self) -> None:
        self.assertTrue(callable(netproc._http_get))
        self.assertTrue(callable(netproc._github_token))
        self.assertTrue(callable(netproc._kill_tree))
        self.assertTrue(callable(netproc._tar_fallback_extract))
        self.assertIs(scanners._http_get, netproc._http_get)
        self.assertIs(bootstrap._http_get, netproc._http_get)


if __name__ == "__main__":
    unittest.main()
