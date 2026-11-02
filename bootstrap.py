"""Download and install the optional scanner binaries.

The app never needs pip beyond its own venvs, Docker or Git for the core
scanners: each tool is either a single executable (or a small archive) that is
fetched once into ``~/.repo-security-scorer/tools`` or a Python package that
gets its own managed virtual environment (Semgrep CE, Checkov, GuardDog).
OpenSSF Scorecard and OSS-Fuzz never reach this module - they answer straight
from public HTTP records, with no binary to install.

Nothing in this module imports :mod:`scanners`; that keeps the tool bootstrap
free of circular imports.
"""

from __future__ import annotations  # imports annotations from the __future__ module

import hashlib  # imports the hashlib module
import http.client  # imports the http.client module (transient download errors)
import json  # imports the json module
import os  # imports the os module
import shutil  # imports the shutil module
import subprocess  # imports the subprocess module
import sys  # imports the sys module
import tempfile  # imports the tempfile module
import threading  # imports the threading module
import time  # imports the time module
import urllib.error  # imports the urllib.error module
import zipfile  # imports the zipfile module
from dataclasses import dataclass  # imports dataclass from the dataclasses module
from pathlib import Path  # imports Path from the pathlib module
from typing import Callable  # imports Callable from the typing module

import config  # imports the config module
from errors import ScanCancelled, ScanError, ToolError  # imports ScanCancelled, ScanError, ToolError from the errors module
from netproc import (  # imports ( from the netproc module
    _github_token as _github_token,  # single home for the shared helper
    _http_get as _http_get,  # single home for the shared helper
    _kill_tree as _kill_tree,  # single home for the shared helper
    _tar_fallback_extract as _tar_fallback_extract,  # single home for the shared helper
)  # closes the multiline block

LogFn = Callable[[str], None]  # copies the Callable value into LogFn
Cancel = threading.Event  # copies the threading.Event value into Cancel

# Transient download retry behaviour. Failed attempts keep the .part file so
# the next attempt resumes with a Range request instead of starting over.
DOWNLOAD_ATTEMPTS = 3  # total tries, including the first  # assigns the computed value to DOWNLOAD_ATTEMPTS
DOWNLOAD_BACKOFF_SECONDS = 2.0  # sleeps are scaled by the attempt number  # assigns the computed value to DOWNLOAD_BACKOFF_SECONDS
RETRYABLE_STATUS = frozenset({500, 502, 503, 504, 429})  # server-side hiccups  # gathers the values into a set


# --------------------------------------------------------------------------
# Download helpers (also used by the CodeQL/Trivy bootstrap in scanners.py)
# --------------------------------------------------------------------------


def _transient_failure(exc: BaseException) -> bool:  # defines the _transient_failure() function
    """True for the low-level hiccups worth one more attempt with resume."""
    if isinstance(exc, urllib.error.HTTPError):  # evaluates the branch condition
        return exc.code in RETRYABLE_STATUS  # returns the in-RETRYABLE_STATUS to the caller
    return isinstance(  # returns the isinstance to the caller
        exc,  # evaluates the exc expression
        (  # executes the statement
            urllib.error.URLError,  # connection / DNS problems
            TimeoutError,  # covers socket timeouts
            http.client.HTTPException,  # truncated bodies (IncompleteRead)
            ConnectionError,  # mid-stream resets  # executes the statement
            OSError,  # misc socket-layer failures  # executes the statement
        ),  # closes the multiline block
    )  # closes the multiline block


def _download_one(  # defines the _download_one() function
    url: str,  # evaluates the url expression
    partial: Path,  # evaluates the partial expression
    headers: dict[str, str],  # evaluates the headers expression
    *,  # spreads the collected values
    log: LogFn,  # evaluates the log expression
    cancel: Cancel,  # evaluates the cancel expression
    what: str,  # evaluates the what expression
) -> None:  # closes the multiline block
    """One streaming pass; resumes on top of an existing .part when allowed."""
    resume_from = partial.stat().st_size if partial.exists() else 0  # reads the file metadata
    attempt_headers = dict(headers)  # copies the headers dict
    if resume_from:  # evaluates the branch condition
        attempt_headers["Range"] = f"bytes={resume_from}-"  # sets the attempt_headers["Range"] text
    with _http_get(url, attempt_headers, timeout=config.DOWNLOAD_TIMEOUT_SECONDS) as response:  # opens the context for the block
        status = int(getattr(response, "status", 200) or 200)  # fetches the value
        if resume_from and status != 206:  # evaluates the branch condition
            # The server ignored Range (or answered 416-shaped): start fresh.
            resume_from = 0  # copies the resume_from value into resume_from
            partial.unlink(missing_ok=True)  # deletes the file
        total = int(response.headers.get("Content-Length") or 0) + resume_from  # runs the int() call
        done = resume_from  # copies the resume_from value into done
        last_report = -1  # assigns the computed value to last_report
        with partial.open("ab" if resume_from else "wb") as handle:  # opens the context for the block
            while True:  # loops while the condition holds
                if cancel.is_set():  # evaluates the branch condition
                    raise ScanCancelled("Download cancelled.")  # raises the ScanCancelled error
                chunk = response.read(1024 * 256)  # runs the read() call
                if not chunk:  # evaluates the branch condition
                    break  # exits the loop early
                handle.write(chunk)  # runs the write() call
                done += len(chunk)  # runs the len() call
                percent = int(done * 100 / total) if total else 0  # runs the int() call
                if percent >= last_report + 10:  # evaluates the branch condition
                    last_report = percent  # copies the percent value into last_report
                    if total:  # evaluates the branch condition
                        log(f"  {what}: {percent}% of {total / 1_048_576:.0f} MB")  # runs the log() call
                    else:  # covers the remaining branch
                        log(f"  {what}: {done / 1_048_576:.0f} MB")  # runs the log() call


def download(  # defines the download() function
    url: str,  # evaluates the url expression
    dest: Path,  # evaluates the dest expression
    *,  # spreads the collected values
    log: LogFn,  # evaluates the log expression
    cancel: Cancel,  # evaluates the cancel expression
    what: str,  # evaluates the what expression
    attempts: int = DOWNLOAD_ATTEMPTS,  # evaluates the attempts expression
) -> None:  # closes the multiline block
    """Stream a URL to disk with progress logging, resume and retry.

    First-time behaviour is identical to the original streaming download.
    When a ``.part`` file exists from an interrupted attempt the download
    resumes with a ``Range`` header (a refusing server just restarts), and
    transient URLError/5xx/timeout failures keep the ``.part`` for another
    attempt instead of deleting it. Hard 404/auth failures, cancellation and
    exhausting the attempts raise exactly as before.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)  # creates the folder
    partial = dest.with_suffix(dest.suffix + ".part")  # runs the with_suffix() call
    headers = {"Accept": "application/octet-stream"}  # assigns the computed value to headers
    token = _github_token()  # runs the _github_token() call
    if token and "github.com" in url:  # evaluates the branch condition
        headers["Authorization"] = f"Bearer {token}"  # sets the headers["Authorization"] text

    log(f"Downloading {what}...")  # runs the log() call
    started = time.monotonic()  # runs the monotonic() call
    last_error: Exception | None = None  # evaluates the last_error expression
    for attempt in range(1, attempts + 1):  # loops over the collection
        try:  # watches for errors in the block
            _download_one(url, partial, headers, log=log, cancel=cancel, what=what)  # runs the _download_one() call
            partial.replace(dest)  # swaps the text
            elapsed = max(time.monotonic() - started, 0.1)  # takes the largest value
            size_mb = dest.stat().st_size / 1_048_576  # reads the file metadata
            log(f"  {what} downloaded in {elapsed:.1f}s ({size_mb:.0f} MB)")  # runs the log() call
            return  # returns to the caller
        except ScanCancelled:  # handles the raised error
            raise  # the .part survives so a retry can resume later  # evaluates the raise expression
        except urllib.error.HTTPError as exc:  # handles the raised error
            last_error = exc  # copies the exc value into last_error
            if exc.code in (416, 400) and attempt < attempts:  # evaluates the branch condition
                # The server refused the resume attempt (Range-free retries
                # can see a 400-shaped proxy error): restart from a clean part.
                partial.unlink(missing_ok=True)  # deletes the file
                continue  # skips to the next loop iteration
            if exc.code == 404:  # evaluates the branch condition
                partial.unlink(missing_ok=True)  # deletes the file
                raise ScanError(  # raises the ScanError error
                    f"Download returned 404 for {url}. The release may have moved."  # supplies the literal text
                ) from exc  # closes the multiline block
            if exc.code in (401, 403):  # evaluates the branch condition
                partial.unlink(missing_ok=True)  # deletes the file
                raise ScanError(  # raises the ScanError error
                    "The download was rejected (HTTP "  # supplies the literal text
                    f"{exc.code}). If you are rate-limited, set a GITHUB_TOKEN environment variable."  # supplies the literal text
                ) from exc  # closes the multiline block
            if _transient_failure(exc) and attempt < attempts:  # evaluates the branch condition
                log(  # runs the log() call
                    f"  {what}: HTTP {exc.code} (attempt {attempt}/{attempts}); "  # evaluates the f expression
                    f"retrying in {attempt * DOWNLOAD_BACKOFF_SECONDS:.0f}s..."  # evaluates the f expression
                )  # closes the multiline block
                time.sleep(attempt * DOWNLOAD_BACKOFF_SECONDS)  # sleeps briefly; the .part is kept
                continue  # skips to the next loop iteration
            partial.unlink(missing_ok=True)  # deletes the file
            raise ScanError(f"Download failed: HTTP {exc.code} from {url}") from exc  # raises the ScanError error
        except Exception as exc:  # noqa: BLE001 - classify network failures per attempt  # handles the raised error
            last_error = exc  # copies the exc value into last_error
            if _transient_failure(exc) and attempt < attempts:  # evaluates the branch condition
                reason = getattr(exc, "reason", "") or exc  # runs the getattr() call
                log(  # runs the log() call
                    f"  {what}: interrupted ({reason}), attempt {attempt}/{attempts}; "  # evaluates the f expression
                    f"resuming in {attempt * DOWNLOAD_BACKOFF_SECONDS:.0f}s..."  # evaluates the f expression
                )  # closes the multiline block
                time.sleep(attempt * DOWNLOAD_BACKOFF_SECONDS)  # sleeps briefly; the .part is kept
                continue  # skips to the next loop iteration
            reason = getattr(exc, "reason", "") or exc  # runs the getattr() call
            partial.unlink(missing_ok=True)  # deletes the file
            raise ScanError(f"Network error while downloading {what}: {reason}") from exc  # raises the ScanError error

    raise ScanError(f"Network error while downloading {what}: {last_error}")  # raises the ScanError error


def extract_zip(archive: Path, target: Path) -> None:  # defines the extract_zip() function
    """Extract a zip, refusing entries that would escape ``target``.

    Path.is_relative_to (3.9+) is the safe comparison: a startswith() check
    on the raw string also accepted siblings such as ``target\\../``
    confusion or a neighbouring ``target2`` folder.
    """
    target = target.resolve()  # runs the resolve() call
    with zipfile.ZipFile(archive) as bundle:  # opens the context for the block
        for member in bundle.infolist():  # loops over the collection
            member_path = (target / member.filename).resolve()  # runs the resolve() call
            if not member_path.is_relative_to(target):  # evaluates the branch condition
                raise ScanError("Refusing to extract a zip entry outside the target folder.")  # raises the ScanError error
            bundle.extract(member, target)  # runs the extract() call


def extract_tar(archive: Path, target: Path, *, log: LogFn, cancel: Cancel) -> bool:  # defines the extract_tar() function
    """Extract a .tar.gz with the system bsdtar when possible; False means fall back."""  # keeps the docstring text
    tar_exe = shutil.which("tar")  # locates the executable on PATH
    if not tar_exe:  # evaluates the branch condition
        return False  # returns the False to the caller
    try:  # watches for errors in the block
        code, _ = run_silent(  # runs the run_silent() call
            [tar_exe, "-xzf", str(archive), "-C", str(target)],  # runs the str() call
            timeout=config.SCAN_TIMEOUT_SECONDS,  # copies the config.SCAN_TIMEOUT_SECONDS value into timeout
            cancel=cancel,  # copies the cancel value into cancel
        )  # closes the multiline block
        return code == 0  # returns the code to the caller
    except Exception:  # handles the raised error
        return False  # returns the False to the caller


# _kill_tree moved to netproc.py (shared with scanners.py); imported above.


def run_silent(  # defines the run_silent() function
    cmd: list[str],  # evaluates the cmd expression
    *,  # spreads the collected values
    timeout: int,  # evaluates the timeout expression
    cancel: Cancel,  # evaluates the cancel expression
    env_overrides: dict[str, str] | None = None,  # evaluates the env_overrides expression
) -> tuple[int, str]:  # closes the multiline block
    """Run a helper command, returning (exit code, tail of combined output)."""  # keeps the docstring text
    env = os.environ.copy()  # runs the copy() call
    env.setdefault("NO_COLOR", "1")  # runs the setdefault() call
    env.update(env_overrides or {})  # refreshes the layout
    kwargs: dict[str, object] = {}  # evaluates the kwargs expression
    if os.name == "nt":  # evaluates the branch condition
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)  # runs the getattr() call

    # Write to a file instead of a pipe: pip's progress output easily exceeds
    # the OS pipe buffer, and a parent that waits without reading deadlocks it.
    with tempfile.TemporaryFile(mode="w+b") as sink:  # opens the context for the block
        process = subprocess.Popen(  # opens the file handle
            [str(part) for part in cmd],  # runs the str() call
            stdout=sink,  # copies the sink value into stdout
            stderr=subprocess.STDOUT,  # copies the subprocess.STDOUT value into stderr
            stdin=subprocess.DEVNULL,  # copies the subprocess.DEVNULL value into stdin
            env=env,  # copies the env value into env
            **kwargs,  # spreads the collected values
        )  # closes the multiline block
        started = time.monotonic()  # runs the monotonic() call
        cancelled = False  # assigns the False literal to cancelled
        timed_out = False  # assigns the False literal to timed_out
        while process.poll() is None:  # loops while the condition holds
            if cancel.is_set():  # evaluates the branch condition
                cancelled = True  # assigns the True literal to cancelled
                _kill_tree(process)  # runs the _kill_tree() call
                break  # exits the loop early
            if time.monotonic() - started > timeout:  # evaluates the branch condition
                timed_out = True  # assigns the True literal to timed_out
                _kill_tree(process)  # runs the _kill_tree() call
                break  # exits the loop early
            time.sleep(0.25)  # runs the sleep() call

        exit_code = process.poll()  # runs the poll() call
        if exit_code is None:  # evaluates the branch condition
            _kill_tree(process)  # runs the _kill_tree() call
            exit_code = process.poll()  # runs the poll() call
        # Only the tail matters: reading the whole pip output (tens of MB)
        # into memory after every install is wasted work, so cap the read at
        # the last 64 KB - still far more than the returned 4000 characters.
        sink.seek(0, os.SEEK_END)  # runs the seek() call
        sink.seek(max(sink.tell() - 65_536, 0))  # walks back to the tail
        output = sink.read().decode("utf-8", "replace")  # runs the read() call

    if cancelled:  # evaluates the branch condition
        raise ScanCancelled("Tool installation cancelled.")  # raises the ScanCancelled error
    if timed_out:  # evaluates the branch condition
        raise ToolError(f"Tool installation timed out after {timeout}s.")  # raises the ToolError error
    return int(exit_code or 0), output[-4000:]  # returns the int to the caller


# --------------------------------------------------------------------------
# Binary tool specs
# --------------------------------------------------------------------------


@dataclass(frozen=True)  # applies the dataclass decorator
class ToolSpec:  # defines the ToolSpec class
    key: str  # evaluates the key expression
    label: str  # evaluates the label expression
    kind: str  # "zip" | "tar" | "exe"  # evaluates the kind expression
    url: str  # evaluates the url expression
    archive: str  # evaluates the archive expression
    executable: str  # evaluates the executable expression
    min_bytes: int = 1_000_000  # evaluates the min_bytes expression
    version: str = ""  # evaluates the version expression
    # Companion checksum asset for the pinned release, e.g. Nuclei's
    # ``nuclei_<v>_checksums.txt`` / Kubescape's ``checksums.sha256``. The
    # digest is resolved at runtime from the published file (never a
    # hardcoded sha256), so an empty pair simply keeps the size-floor check
    # - which is what the floating "latest" tools (CodeQL, Trivy) use.
    checksum_url: str = ""  # evaluates the checksum_url expression
    checksum_object: str = ""  # evaluates the checksum_object expression


# Pinned releases: a security tool that silently changes output format is worse
# than one that is a few weeks old. URLs are stable GitHub release assets.
TOOL_SPECS: dict[str, ToolSpec] = {  # evaluates the TOOL_SPECS expression
    "grype": ToolSpec(  # maps the grype dictionary entry
        key="grype",  # sets the key text
        label="Grype",  # sets the label text
        kind="zip",  # sets the kind text
        url="https://github.com/anchore/grype/releases/download/v0.121.0/grype_0.121.0_windows_amd64.zip",  # sets the url text
        archive="grype.zip",  # sets the archive text
        executable="grype.exe",  # sets the executable text
        min_bytes=10_000_000,  # assigns the computed value to min_bytes
        version="0.121.0",  # sets the version text
    ),  # closes the multiline block
    "gitleaks": ToolSpec(  # maps the gitleaks dictionary entry
        key="gitleaks",  # sets the key text
        label="GitLeaks",  # sets the label text
        kind="zip",  # sets the kind text
        url="https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_windows_x64.zip",  # sets the url text
        archive="gitleaks.zip",  # sets the archive text
        executable="gitleaks.exe",  # sets the executable text
        min_bytes=5_000_000,  # assigns the computed value to min_bytes
        version="8.30.1",  # sets the version text
    ),  # closes the multiline block
    "trufflehog": ToolSpec(  # maps the trufflehog dictionary entry
        key="trufflehog",  # sets the key text
        label="TruffleHog",  # sets the label text
        kind="tar",  # sets the kind text
        url="https://github.com/trufflesecurity/trufflehog/releases/download/v3.99.7/trufflehog_3.99.7_windows_amd64.tar.gz",  # sets the url text
        archive="trufflehog.tar.gz",  # sets the archive text
        executable="trufflehog.exe",  # sets the executable text
        min_bytes=20_000_000,  # assigns the computed value to min_bytes
        version="3.99.7",  # sets the version text
    ),  # closes the multiline block
    "osv": ToolSpec(  # maps the osv dictionary entry
        key="osv",  # sets the key text
        label="OSV-Scanner",  # sets the label text
        kind="exe",  # sets the kind text
        url="https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_windows_amd64.exe",  # sets the url text
        archive="osv-scanner.exe",  # sets the archive text
        executable="osv-scanner.exe",  # sets the executable text
        min_bytes=20_000_000,  # assigns the computed value to min_bytes
        version="2.7.0",  # sets the version text
    ),  # closes the multiline block
    "syft": ToolSpec(  # maps the syft dictionary entry
        key="syft",  # sets the key text
        label="Syft",  # sets the label text
        kind="zip",  # sets the kind text
        url="https://github.com/anchore/syft/releases/download/v1.55.0/syft_1.55.0_windows_amd64.zip",  # sets the url text
        archive="syft.zip",  # sets the archive text
        executable="syft.exe",  # sets the executable text
        min_bytes=10_000_000,  # assigns the computed value to min_bytes
        version="1.55.0",  # sets the version text
    ),  # closes the multiline block
    "nuclei": ToolSpec(  # maps the nuclei dictionary entry
        key="nuclei",  # sets the key text
        label="Nuclei",  # sets the label text
        kind="zip",  # sets the kind text
        url=config.NUCLEI_DOWNLOAD_URL,  # sets the url text
        archive=config.NUCLEI_ZIP,  # sets the archive text
        executable="nuclei.exe",  # sets the executable text
        min_bytes=20_000_000,  # assigns the computed value to min_bytes
        version=config.NUCLEI_VERSION,  # sets the version text
        checksum_url=config.NUCLEI_CHECKSUM_URL,  # sets the checksum_url text
        checksum_object=config.NUCLEI_CHECKSUM_OBJECT,  # sets the checksum_object text
    ),  # closes the multiline block
    "kubescape": ToolSpec(  # maps the kubescape dictionary entry
        key="kubescape",  # sets the key text
        label="Kubescape",  # sets the label text
        kind="exe",  # sets the kind text
        url=config.KUBESCAPE_DOWNLOAD_URL,  # sets the url text
        archive="kubescape.exe",  # sets the archive text
        executable="kubescape.exe",  # sets the executable text
        min_bytes=150_000_000,  # assigns the computed value to min_bytes
        version=config.KUBESCAPE_VERSION,  # sets the version text
        checksum_url=config.KUBESCAPE_CHECKSUM_URL,  # sets the checksum_url text
        checksum_object=config.KUBESCAPE_CHECKSUM_OBJECT,  # sets the checksum_object text
    ),  # closes the multiline block
}  # closes the multiline block


def tool_dir(key: str) -> Path:  # defines the tool_dir() function
    return config.TOOLS_DIR / key  # returns the config.TOOLS_DIR to the caller


def tool_executable(key: str) -> Path:  # defines the tool_executable() function
    spec = TOOL_SPECS.get(key)  # fetches the value
    if not spec:  # evaluates the branch condition
        raise ToolError(f"Unknown tool '{key}'.")  # raises the ToolError error
    return tool_dir(key) / spec.executable  # returns the tool_dir to the caller


def _verify_checksum(archive: Path, spec: ToolSpec, log: LogFn) -> bool:  # defines the _verify_checksum() function
    """Compare the archive digest with the release's published checksum file.

    True means verified. A missing/unfetchable checksum source returns False
    (the size-floor check stays in charge - which is how the floating
    "latest" tools such as CodeQL/Trivy always ran), while a definite
    mismatch is refused outright: a security tool whose digest does not
    match its own published release must not run.
    """
    if not spec.checksum_url or not spec.checksum_object:  # evaluates the branch condition
        return False  # no published checksum for this tool  # evaluates the return expression
    try:  # watches for errors in the block
        with _http_get(spec.checksum_url, {"Accept": "text/plain"}) as response:  # opens the context for the block
            lines = response.read().decode("utf-8", "replace").splitlines()  # reads the text file
    except Exception as exc:  # noqa: BLE001 - a flaky checksum fetch must not block install  # handles the raised error
        log(f"  {spec.label}: checksum file could not be fetched ({exc}); keeping the size check only.")  # runs the log() call
        return False  # returns the False to the caller
    for line in lines:  # loops over the collection
        parts = line.split(None, 1)  # splits the digest from the artifact name
        if len(parts) != 2:  # evaluates the branch condition
            continue  # skips to the next loop iteration
        digest = parts[0].lower()  # copies the parts[0] value into digest
        name = parts[1].strip().rsplit("/", 1)[-1]  # keeps the bare artifact name
        if name != spec.checksum_object:  # evaluates the branch condition
            continue  # skips to the next loop iteration
        actual = hashlib.sha256(archive.read_bytes()).hexdigest()  # assigns the computed value
        if digest == actual:  # evaluates the branch condition
            log(f"  {spec.label} sha256 verified against the published checksum file.")  # runs the log() call
            return True  # returns the True to the caller
        raise ToolError(  # raises the ToolError error
            f"{spec.label} failed the published checksum comparison "  # supplies the literal text
            f"({spec.checksum_object} does not match) - refusing to install it."  # supplies the literal text
        )  # closes the multiline block
    log(  # runs the log() call
        f"  {spec.label}: the published checksum file does not list "  # supplies the literal text
        f"'{spec.checksum_object}'; keeping the size check only."  # supplies the literal text
    )  # closes the multiline block
    return False  # returns the False to the caller


def ensure_tool(key: str, log: LogFn, cancel: Cancel) -> Path:  # defines the ensure_tool() function
    """Return the executable for a binary scanner, downloading it once if needed."""  # keeps the docstring text
    spec = TOOL_SPECS.get(key)  # fetches the value
    if not spec:  # evaluates the branch condition
        raise ToolError(f"Unknown tool '{key}'.")  # raises the ToolError error
    if os.name != "nt":  # evaluates the branch condition
        raise ToolError(  # raises the ToolError error
            f"Automatic {spec.label} setup is only implemented on Windows hosts. "  # supplies the literal text
            f"Install {spec.label} manually and point RSS_{key.upper()}_PATH at it."  # supplies the literal text
        )  # closes the multiline block

    executable = tool_executable(key)  # runs the tool_executable() call
    if executable.exists():  # evaluates the branch condition
        return executable  # returns the executable to the caller

    target = tool_dir(key)  # runs the tool_dir() call
    target.mkdir(parents=True, exist_ok=True)  # creates the folder
    archive = target / spec.archive  # copies the target value into archive

    if spec.kind == "exe":  # evaluates the branch condition
        if not archive.exists() or archive.stat().st_size < spec.min_bytes:  # evaluates the branch condition
            download(spec.url, archive, log=log, cancel=cancel, what=f"{spec.label} {spec.version}")  # runs the download() call
        _verify_checksum(archive, spec, log)  # verifies when the release publishes a checksum  # runs the _verify_checksum() call
        executable.parent.mkdir(parents=True, exist_ok=True)  # creates the folder
        if archive != executable:  # evaluates the branch condition
            archive.replace(executable)  # swaps the text
        log(f"{spec.label} ready: {executable}")  # runs the log() call
        return executable  # returns the executable to the caller

    if not archive.exists() or archive.stat().st_size < spec.min_bytes:  # evaluates the branch condition
        download(spec.url, archive, log=log, cancel=cancel, what=f"{spec.label} {spec.version}")  # runs the download() call
    _verify_checksum(archive, spec, log)  # verifies when the release publishes a checksum  # runs the _verify_checksum() call

    log(f"Extracting {spec.label}...")  # runs the log() call
    if spec.kind == "zip":  # evaluates the branch condition
        extract_zip(archive, target)  # runs the extract_zip() call
    else:  # covers the remaining branch
        if not extract_tar(archive, target, log=log, cancel=cancel):  # evaluates the branch condition
            try:  # watches for errors in the block
                _tar_fallback_extract(archive, target)  # runs the _tar_fallback_extract() call
            except Exception as exc:  # handles the raised error
                raise ToolError(f"Could not extract {spec.label}: {exc}") from exc  # raises the ToolError error

    if not executable.exists():  # evaluates the branch condition
        matches = [path for path in target.rglob(spec.executable) if path.is_file()]  # walks matching files
        if not matches:  # evaluates the branch condition
            raise ToolError(f"{spec.label} archive did not contain {spec.executable}.")  # raises the ToolError error
        shutil.copy2(matches[0], executable)  # runs the copy2() call

    archive.unlink(missing_ok=True)  # deletes the file
    log(f"{spec.label} ready: {executable}")  # runs the log() call
    return executable  # returns the executable to the caller


# --------------------------------------------------------------------------
# Managed Python virtual environments (Semgrep, Checkov, GuardDog)
# --------------------------------------------------------------------------


def tool_venv(key: str) -> Path:  # defines the tool_venv() function
    return tool_dir(key) / "venv"  # returns the tool_dir to the caller


def _venv_paths(venv: Path) -> tuple[Path, Path]:  # defines the _venv_paths() function
    """Return (python executable, scripts directory) for a virtual environment."""  # keeps the docstring text
    if os.name == "nt":  # evaluates the branch condition
        return venv / "Scripts" / "python.exe", venv / "Scripts"  # returns the venv to the caller
    return venv / "bin" / "python", venv / "bin"  # returns the venv to the caller


def _ensure_pip_venv(  # defines the _ensure_pip_venv() function
    key: str,  # evaluates the key expression
    label: str,  # evaluates the label expression
    package: str,  # evaluates the package expression
    version: str,  # evaluates the version expression
    *,  # spreads the collected values
    log: LogFn,  # evaluates the log expression
    cancel: Cancel,  # evaluates the cancel expression
) -> Path:  # closes the multiline block
    """Install ``package`` into a private venv once; return its Python."""  # keeps the docstring text
    venv = tool_venv(key)  # runs the tool_venv() call
    python, _ = _venv_paths(venv)  # runs the _venv_paths() call
    marker = venv / ".installed"  # copies the venv value into marker

    if python.exists() and marker.exists():  # evaluates the branch condition
        return python  # returns the python to the caller

    venv.parent.mkdir(parents=True, exist_ok=True)  # creates the folder
    if not python.exists():  # evaluates the branch condition
        log(f"Creating a private environment for {label} (first run only)...")  # runs the log() call
        code, tail = run_silent(  # runs the run_silent() call
            [sys.executable, "-m", "venv", str(venv)],  # runs the str() call
            timeout=300,  # assigns the computed value to timeout
            cancel=cancel,  # copies the cancel value into cancel
        )  # closes the multiline block
        if code != 0:  # evaluates the branch condition
            raise ToolError(  # raises the ToolError error
                f"Could not create the {label} virtual environment.\n" + tail.strip()  # supplies the literal text
            )  # closes the multiline block

    python, _ = _venv_paths(venv)  # runs the _venv_paths() call
    if not python.exists():  # evaluates the branch condition
        raise ToolError(f"The {label} virtual environment is incomplete: {python} is missing.")  # raises the ToolError error

    requirement = f"{package}=={version}" if version else package  # sets the requirement text
    log(f"Installing {label} {version or ''} (first run only, this can take a minute)...".replace("  ", " "))  # runs the log() call
    code, tail = run_silent(  # runs the run_silent() call
        [  # executes the statement
            str(python),  # runs the str() call
            "-m",  # supplies the literal text
            "pip",  # supplies the literal text
            "install",  # supplies the literal text
            "--disable-pip-version-check",  # supplies the literal text
            "--no-input",  # supplies the literal text
            "--upgrade",  # supplies the literal text
            requirement,  # evaluates the requirement expression
        ],  # closes the multiline block
        timeout=1200,  # assigns the computed value to timeout
        cancel=cancel,  # copies the cancel value into cancel
        env_overrides={  # assigns the computed value to env_overrides
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",  # maps the PIP_DISABLE_PIP_VERSION_ dictionary entry
            "PYTHONUTF8": "1",  # maps the PYTHONUTF8 dictionary entry
            "PYTHONIOENCODING": "utf-8",  # maps the PYTHONIOENCODING dictionary entry
        },  # closes the multiline block
    )  # closes the multiline block
    if code != 0:  # evaluates the branch condition
        raise ToolError(f"Could not install {label}.\n" + tail.strip())  # raises the ToolError error

    marker.write_text(requirement, encoding="utf-8")  # writes the text file
    log(f"{label} ready: {python}")  # runs the log() call
    return python  # returns the python to the caller


def semgrep_root() -> Path:  # defines the semgrep_root() function
    return tool_dir("semgrep")  # returns the tool_dir to the caller


def semgrep_executable() -> Path:  # defines the semgrep_executable() function
    venv = semgrep_root() / "venv"  # runs the semgrep_root() call
    if os.name == "nt":  # evaluates the branch condition
        return venv / "Scripts" / "semgrep.exe"  # returns the venv to the caller
    return venv / "bin" / "semgrep"  # returns the venv to the caller


def ensure_semgrep(log: LogFn, cancel: Cancel) -> Path:  # defines the ensure_semgrep() function
    """Install Semgrep CE into a private venv on first use, then reuse it."""  # keeps the docstring text
    managed = semgrep_executable()  # runs the semgrep_executable() call
    if managed.exists():  # evaluates the branch condition
        return managed  # returns the managed to the caller

    on_path = shutil.which("semgrep")  # locates the executable on PATH
    if on_path:  # evaluates the branch condition
        log(f"Using Semgrep already installed on PATH: {on_path}")  # runs the log() call
        return Path(on_path)  # returns the Path to the caller

    python = _ensure_pip_venv(  # runs the _ensure_pip_venv() call
        "semgrep", "Semgrep CE", "semgrep", "", log=log, cancel=cancel  # supplies the literal text
    )  # closes the multiline block
    if not managed.exists():  # evaluates the branch condition
        raise ToolError(  # raises the ToolError error
            f"Semgrep was installed but {managed} is missing. "  # supplies the literal text
            "Remove the tools/semgrep folder and try again."  # supplies the literal text
        )  # closes the multiline block
    return managed  # returns the managed to the caller


def checkov_script() -> Path:  # defines the checkov_script() function
    venv = tool_venv("checkov")  # runs the tool_venv() call
    if os.name == "nt":  # evaluates the branch condition
        # pip writes an extensionless shim on Windows; it must be launched
        # through the venv's python, since there is no checkov.exe.
        return venv / "Scripts" / "checkov"  # returns the venv to the caller
    return venv / "bin" / "checkov"  # returns the venv to the caller


def ensure_checkov(log: LogFn, cancel: Cancel) -> tuple[Path, Path]:  # defines the ensure_checkov() function
    """Install Checkov into a private venv; return (python, checkov script)."""  # keeps the docstring text
    python = _ensure_pip_venv(  # runs the _ensure_pip_venv() call
        "checkov",  # supplies the literal text
        "Checkov",  # supplies the literal text
        "checkov",  # supplies the literal text
        config.CHECKOV_VERSION,  # evaluates the config.CHECKOV_VERSION expression
        log=log,  # copies the log value into log
        cancel=cancel,  # copies the cancel value into cancel
    )  # closes the multiline block
    script = checkov_script()  # runs the checkov_script() call
    if not script.exists():  # evaluates the branch condition
        raise ToolError(  # raises the ToolError error
            f"Checkov was installed but {script} is missing. "  # supplies the literal text
            "Remove the tools/checkov folder and try again."  # supplies the literal text
        )  # closes the multiline block
    return python, script  # returns the python to the caller


def guarddog_python() -> Path:  # defines the guarddog_python() function
    return _venv_paths(tool_venv("guarddog"))[0]  # returns the _venv_paths to the caller


def ensure_guarddog(log: LogFn, cancel: Cancel) -> Path:  # defines the ensure_guarddog() function
    """Install GuardDog into a private venv; return its Python."""  # keeps the docstring text
    return _ensure_pip_venv(  # returns the _ensure_pip_venv to the caller
        "guarddog",  # supplies the literal text
        "GuardDog",  # supplies the literal text
        "guarddog",  # supplies the literal text
        config.GUARDDOG_VERSION,  # evaluates the config.GUARDDOG_VERSION expression
        log=log,  # copies the log value into log
        cancel=cancel,  # copies the cancel value into cancel
    )  # closes the multiline block

