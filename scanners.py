"""Repo download plus runners for all supported scanners.

Nothing outside the Python standard library is required. Every scanner is
either a plain executable downloaded once into ``~/.repo-security-scorer``
(CodeQL, Trivy, Grype, OSV-Scanner, GitLeaks, TruffleHog, Syft, Nuclei,
Kubescape) or installed into a private virtual environment (Semgrep CE,
Checkov, GuardDog):

* CodeQL CLI bundle from github/codeql-action releases (win64 tarball)
* Trivy release binary from aquasecurity/trivy releases
* Grype, GitLeaks, TruffleHog, Syft, Nuclei, Kubescape from their GitHub releases
* OSV-Scanner release binary from google/osv-scanner
* Semgrep CE, Checkov and GuardDog from PyPI, in managed venvs
* OpenSSF Scorecard and OSS-Fuzz answer straight from public HTTP records, so
  they need no binary at all
* FOSSology talks to a user-provided FOSSology server's REST v1 API (Nomos and
  Ojo licence agents), so it also needs no binary - only FOSSOLOGY_SERVER and
  FOSSOLOGY_TOKEN in the environment

The repository itself is fetched as a source zip from codeload.github.com, so
Git does not need to be installed.

Non-repository addresses take the website path instead: :func:`scan_target`
dispatches to :func:`scan_website`, which fetches the live page, probes a few
classic exposed files, and (when selected) runs Nuclei's DAST templates against
the address.
"""

from __future__ import annotations  # imports annotations from the __future__ module

import json  # imports the json module
import os  # imports the os module
import re  # imports the re module
import shutil  # imports the shutil module
import subprocess  # imports the subprocess module
import threading  # imports the threading module
import time  # imports the time module
import urllib.error  # imports the urllib.error module
import urllib.parse  # imports the urllib.parse module
import urllib.request  # imports the urllib.request module
import zipfile  # imports the zipfile module (the FOSSology source archive)
from concurrent.futures import ThreadPoolExecutor  # imports ThreadPoolExecutor for the scanner fan-out
from dataclasses import dataclass  # imports dataclass from the dataclasses module
from pathlib import Path  # imports Path from the pathlib module
from typing import Any, Callable, Iterable, Iterator  # imports Any, Callable, Iterable, Iterator from the typing module

import config  # imports the config module
import dashboard as dashboards  # avoids the scan_repository 'dashboard' parameter shadow
import scoring  # imports the scoring module
from bootstrap import (  # imports ( from the bootstrap module
    download,  # evaluates the download expression
    ensure_checkov,  # evaluates the ensure_checkov expression
    ensure_guarddog,  # evaluates the ensure_guarddog expression
    ensure_semgrep,  # evaluates the ensure_semgrep expression
    ensure_tool,  # evaluates the ensure_tool expression
    extract_tar,  # evaluates the extract_tar expression
    extract_zip,  # evaluates the extract_zip expression
)  # closes the multiline block
from errors import ScanCancelled, ScanError, ToolError  # imports ScanCancelled, ScanError, ToolError from the errors module
from netproc import (  # imports ( from the netproc module
    _github_token as _github_token,  # single home for the shared helper
    _http_get as _http_get,  # single home for the shared helper
    _kill_tree as _kill_tree,  # single home for the shared helper
    _tar_fallback_extract as _tar_fallback_extract,  # single home for the shared helper
)  # closes the multiline block

LogFn = Callable[[str], None]  # copies the Callable value into LogFn
Cancel = threading.Event  # copies the threading.Event value into Cancel


# --------------------------------------------------------------------------
# Repository URL handling
# --------------------------------------------------------------------------

_REPO_PATTERNS = (  # assigns the computed value to _REPO_PATTERNS
    re.compile(r"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?"  # runs the compile() call
               r"(?:/(?:tree|blob)/(?P<ref>[^\s?#]+))?/?$", re.IGNORECASE),  # maps the (?:/(?:tree|blob)/(?P<re dictionary entry
    re.compile(r"^git@github\.com:(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?/?$", re.IGNORECASE),  # runs the compile() call
    re.compile(r"^(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)$"),  # runs the compile() call
)  # closes the multiline block


@dataclass  # applies the dataclass decorator
class RepoRef:  # defines the RepoRef class
    owner: str  # evaluates the owner expression
    repo: str  # evaluates the repo expression
    ref: str | None = None  # evaluates the ref expression

    @property  # applies the property decorator
    def full_name(self) -> str:  # defines the full_name() function
        return f"{self.owner}/{self.repo}"  # returns the f to the caller

    @property  # applies the property decorator
    def web_url(self) -> str:  # defines the web_url() function
        return f"https://github.com/{self.full_name}"  # returns the f to the caller


def parse_repo_url(value: str) -> RepoRef:  # defines the parse_repo_url() function
    """Accept a GitHub URL, ``git@`` URL, or bare ``owner/repo``."""  # keeps the docstring text
    text = (value or "").strip()  # trims the whitespace
    if not text:  # evaluates the branch condition
        raise ScanError("Enter a GitHub repository URL first.")  # raises the ScanError error
    text = text.split("#")[0].split("?")[0]  # runs the split() call

    for pattern in _REPO_PATTERNS:  # loops over the collection
        match = pattern.match(text)  # runs the match() call
        if match:  # evaluates the branch condition
            owner = match.group("owner")  # runs the group() call
            repo = match.group("repo")  # runs the group() call
            if repo.endswith(".git"):  # evaluates the branch condition
                repo = repo[:-4]  # copies the repo value into repo
            ref = match.groupdict().get("ref")  # builds the dict mapping
            if ref:  # evaluates the branch condition
                ref = urllib.parse.unquote(ref)  # runs the unquote() call
            return RepoRef(owner=owner, repo=repo, ref=ref)  # returns the RepoRef to the caller

    raise ScanError(  # raises the ScanError error
        "That does not look like a GitHub repository. Try https://github.com/owner/repo"  # maps the That does not look like  dictionary entry
    )  # closes the multiline block


def parse_target(value: str) -> tuple[str, Any]:  # defines the parse_target() function
    """Classify an input as a repository or a plain website.

    Returns ``("repo", RepoRef)`` when the text matches any of the GitHub
    patterns; otherwise, when it is a usable http(s) address, it returns
    ``("web", "https://host/path")`` with the scheme defaulted and fragments
    stripped. Anything else re-raises the repository hint so the caller's
    error message stays the same for genuinely broken input.
    """
    text = (value or "").strip()  # trims the whitespace
    if not text:  # evaluates the branch condition
        raise ScanError("Enter a GitHub repository URL or website address first.")  # raises the ScanError error
    try:  # watches for errors in the block
        return "repo", parse_repo_url(text)  # returns the tuple to the caller
    except ScanError as exc:  # handles the raised error
        candidate = text.split("#")[0].split("?")[0]  # strips the fragments
        if "://" not in candidate:  # a bare ``example.com`` gets https by default
            candidate = f"https://{candidate}"  # assigns the computed value
        parts = urllib.parse.urlsplit(candidate)  # splits the URL apart
        if parts.scheme not in {"http", "https"} or not parts.netloc or " " in parts.netloc:  # evaluates the branch condition
            raise exc  # not a repo and not an address: keep the original hint
        return "web", f"{parts.scheme}://{parts.netloc}{parts.path}".rstrip("/")  # returns the tuple to the caller


def fetch_repo_metadata(ref: RepoRef) -> dict[str, Any]:  # defines the fetch_repo_metadata() function
    """Best-effort repo metadata; never fatal."""  # keeps the docstring text
    headers = {"Authorization": f"Bearer {_github_token()}"} if _github_token() else {}  # runs the _github_token() call
    try:  # watches for errors in the block
        with _http_get(f"{config.GITHUB_API}/repos/{ref.full_name}", headers) as response:  # opens the context for the block
            data = json.load(response)  # reads JSON data from the stream
    except Exception:  # handles the raised error
        return {"full_name": ref.full_name, "web_url": ref.web_url}  # returns the value to the caller

    return {  # returns the value to the caller
        "full_name": data.get("full_name") or ref.full_name,  # maps the full_name dictionary entry
        "web_url": data.get("html_url") or ref.web_url,  # maps the web_url dictionary entry
        "description": data.get("description") or "",  # maps the description dictionary entry
        "stars": data.get("stargazers_count"),  # maps the stars dictionary entry
        "language": data.get("language") or "",  # maps the language dictionary entry
        "default_branch": data.get("default_branch") or "",  # maps the default_branch dictionary entry
        "archived": bool(data.get("archived")),  # maps the archived dictionary entry
        "private": bool(data.get("private")),  # maps the private dictionary entry
        "pushed_at": data.get("pushed_at") or "",  # maps the pushed_at dictionary entry
        "license": ((data.get("license") or {}).get("spdx_id")) or "",  # maps the license dictionary entry
    }  # closes the multiline block


PULL_CLOSED_SAMPLE = 30      # closed PRs sampled for the resolution median  # assigns the computed value to PULL_CLOSED_SAMPLE
ISSUE_CLOSED_SAMPLE = 30     # closed issues sampled for the resolution median  # assigns the computed value to ISSUE_CLOSED_SAMPLE
RECENT_COMMIT_SAMPLE = 30    # latest commits sampled for author activity  # assigns the computed value to RECENT_COMMIT_SAMPLE


def _retry_after_delay(exc: urllib.error.HTTPError) -> float:  # defines the _retry_after_delay() function
    """Seconds to wait after a 403/429, honouring Retry-After modestly."""
    raw = exc.headers.get("Retry-After") if exc.headers is not None else None  # fetches the value
    try:  # watches for errors in the block
        value = float(raw)  # runs the float() call
    except (TypeError, ValueError):  # handles the raised error
        value = 0.0  # covers the remaining branch
    return min(max(value, 2.0), 30.0)  # keeps the wait sane either way


def _github_json(  # defines the _github_json() function
    path: str,  # evaluates the path expression
    headers: dict[str, str],  # evaluates the headers expression
    query: dict[str, str | int] | None = None,  # evaluates the query expression
    *,  # spreads the collected values
    log: LogFn | None = None,  # evaluates the log expression
) -> tuple[Any, dict[str, str]]:  # closes the multiline block
    """GET one GitHub API endpoint; returns (payload, response headers).

    A 403/429 answer is retried once after Retry-After (GitHub's rate-limit
    replies are also 403s); the one retry is silent unless a log drains by.
    """
    url = f"{config.GITHUB_API}{path}"  # sets the url text
    params = urllib.parse.urlencode(query or {})  # runs the urlencode() call
    if params:  # evaluates the branch condition
        url += f"?{params}"  # evaluates the url expression
    try:  # watches for errors in the block
        with _http_get(url, headers=headers) as response:  # opens the context for the block
            payload = json.load(response)  # reads JSON data from the stream
            page_info = {"link": response.headers.get("link", "") or "", "status": str(response.status or 200)}  # fetches the value
        return payload, page_info  # returns the payload to the caller
    except urllib.error.HTTPError as exc:  # handles the raised error
        if exc.code not in (403, 429):  # evaluates the branch condition
            raise  # nothing rate-limit-like: the caller's handler decides  # evaluates the raise expression
        delay = _retry_after_delay(exc)  # runs the _retry_after_delay() call
        if log:  # evaluates the branch condition
            log(f"  GitHub API answered HTTP {exc.code} for {path}; retrying once in {delay:.0f}s.")  # runs the log() call
        time.sleep(delay)  # waits the shared delay
        with _http_get(url, headers=headers) as response:  # opens the context for the block
            payload = json.load(response)  # reads JSON data from the stream
            page_info = {"link": response.headers.get("link", "") or "", "status": str(response.status or 200)}  # fetches the value
        return payload, page_info  # returns the payload to the caller


def fetch_care_and_feeding(ref: RepoRef, log: LogFn | None = None) -> dict[str, Any]:  # defines the fetch_care_and_feeding() function
    """Collect repository maintenance statistics; every metric is optional.

    Data that matters for the Care-and-Feeding section: last release and
    release cadence, weekly commit history (which also provides the recency
    distribution and the development trend), open pull requests and the
    oldest one, the oldest open issue, recent resolution times for issues
    and PRs, contributor activity, author diversity and the last commit
    date (derived from the sample; that skips the old per_page=1 call).

    The endpoints are independent, so they fan out over a small thread pool;
    each fetcher only builds its own fragment which the main thread merges
    in a deterministic order, and one failed metric must turn into an
    error note - never an exception.
    """
    if log:  # evaluates the branch condition
        log("Fetching maintenance statistics (Care and Feeding)...")  # runs the log() call
    headers = {"Authorization": f"Bearer {_github_token()}"} if _github_token() else {}  # runs the _github_token() call
    data: dict[str, Any] = {}  # evaluates the data expression
    errors: list[str] = []  # evaluates the errors expression
    base = f"/repos/{ref.owner}/{ref.repo}"  # sets the base text

    # Errors keep the metric name so care.summarize's notes stay readable;
    # the fragment-based merge below keeps the notes in this order.
    def attempt(metric: str, fetch) -> dict[str, Any]:  # defines the attempt() function
        try:  # watches for errors in the block
            return fetch()  # runs the fetch() call
        except Exception as exc:  # noqa: BLE001 - maintenance stats must never fail a scan  # handles the raised error
            gh_message = getattr(exc, "reason", "") or exc  # runs the getattr() call
            return {"__errors__": [f"{metric}: could not be fetched ({gh_message})"]}  # returns the built dict

    def _commit_activity() -> dict[str, Any]:  # defines the _commit_activity() function
        stats = None  # assigns the None literal to stats
        for _ in range(3):  # loops over the collection
            payload, page_info = _github_json(  # runs the _github_json() call
                f"{base}/stats/commit_activity", headers, log=log  # supplies the literal text
            )  # closes the multiline block
            if page_info.get("status") not in {"202", "204"} and isinstance(payload, list):  # evaluates the branch condition
                stats = payload  # copies the payload value into stats
                break  # exits the loop early
            time.sleep(2.0)  # runs the sleep() call
        if stats:  # evaluates the branch condition
            return {"commit_activity": [item for item in stats if isinstance(item, dict)]}  # returns the built list
        return {}  # returns the empty dict

    def _releases() -> dict[str, Any]:  # defines the _releases() function
        payload, _ = _github_json(f"{base}/releases", headers, {"per_page": 100}, log=log)  # runs the _github_json() call
        return {"releases": [  # returns the built dict
            {  # executes the statement
                "published_at": item.get("published_at") or "",  # maps the published_at dictionary entry
                "created_at": item.get("created_at") or "",  # maps the created_at dictionary entry
            }  # closes the multiline block
            for item in (payload or [])  # loops over the collection
            if isinstance(item, dict)  # evaluates the branch condition
        ]}  # closes the multiline block

    def _open_pull_requests() -> dict[str, Any]:  # defines the _open_pull_requests() function
        payload, page_info = _github_json(  # runs the _github_json() call
            f"{base}/pulls", headers,  # supplies the literal text
            {"state": "open", "sort": "created", "direction": "asc", "per_page": 1},  # executes the statement
            log=log,  # copies the log value into log
        )  # closes the multiline block
        count = 0  # assigns the computed value to count
        link = page_info.get("link") or ""  # fetches the value
        match = re.search(r"[?&]page=(\d+)>;\s*rel=\"last\"", link)  # runs the search() call
        if match:  # evaluates the branch condition
            count = int(match.group(1))  # runs the int() call
        elif isinstance(payload, list):  # checks the alternate condition
            count = len(payload)  # counts the items
        fragment: dict[str, Any] = {"open_pull_requests": count}  # evaluates the fragment expression
        if isinstance(payload, list) and payload:  # evaluates the branch condition
            fragment["oldest_open_pr"] = {  # assigns the computed value to fragment["oldest_open_pr"]
                "title": payload[0].get("title") or "",  # maps the title dictionary entry
                "created_at": payload[0].get("created_at") or "",  # maps the created_at dictionary entry
                "html_url": payload[0].get("html_url") or "",  # maps the html_url dictionary entry
            }  # closes the multiline block
        return fragment  # returns the fragment to the caller

    def _oldest_open_issue() -> dict[str, Any]:  # defines the _oldest_open_issue() function
        payload, _ = _github_json(  # runs the _github_json() call
            f"{base}/issues", headers,  # supplies the literal text
            {"state": "open", "sort": "created", "direction": "asc", "per_page": 1},  # executes the statement
            log=log,  # copies the log value into log
        )  # closes the multiline block
        for item in payload or []:  # loops over the collection
            if isinstance(item, dict) and not item.get("pull_request"):  # evaluates the branch condition
                return {"oldest_open_issue": {  # returns the built dict
                    "title": item.get("title") or "",  # maps the title dictionary entry
                    "created_at": item.get("created_at") or "",  # maps the created_at dictionary entry
                    "html_url": item.get("html_url") or "",  # maps the html_url dictionary entry
                    "number": item.get("number"),  # maps the number dictionary entry
                }}  # closes the multiline block
        return {}  # returns the empty dict

    def _closed_prs() -> dict[str, Any]:  # defines the _closed_prs() function
        payload, _ = _github_json(  # runs the _github_json() call
            f"{base}/pulls", headers,  # supplies the literal text
            {"state": "closed", "sort": "closed", "direction": "desc", "per_page": str(PULL_CLOSED_SAMPLE)},  # runs the str() call
            log=log,  # copies the log value into log
        )  # closes the multiline block
        return {"closed_prs_sample": [  # returns the built dict
            {  # executes the statement
                "created_at": item.get("created_at") or "",  # maps the created_at dictionary entry
                "merged_at": item.get("merged_at") or "",  # maps the merged_at dictionary entry
                "closed_at": item.get("closed_at") or "",  # maps the closed_at dictionary entry
            }  # closes the multiline block
            for item in (payload or [])  # loops over the collection
            if isinstance(item, dict)  # evaluates the branch condition
        ]}  # closes the multiline block

    def _closed_issues() -> dict[str, Any]:  # defines the _closed_issues() function
        payload, _ = _github_json(  # runs the _github_json() call
            f"{base}/issues", headers,  # supplies the literal text
            {"state": "closed", "sort": "closed", "direction": "desc", "per_page": str(ISSUE_CLOSED_SAMPLE)},  # runs the str() call
            log=log,  # copies the log value into log
        )  # closes the multiline block
        return {"closed_issues_sample": [  # returns the built dict
            {  # executes the statement
                "created_at": item.get("created_at") or "",  # maps the created_at dictionary entry
                "closed_at": item.get("closed_at") or "",  # maps the closed_at dictionary entry
            }  # closes the multiline block
            for item in (payload or [])  # loops over the collection
            if isinstance(item, dict)  # evaluates the branch condition
        ]}  # closes the multiline block

    def _contributors() -> dict[str, Any]:  # defines the _contributors() function
        payload, _ = _github_json(f"{base}/contributors", headers, {"per_page": 100}, log=log)  # runs the _github_json() call
        list_payload = payload if isinstance(payload, list) else []  # runs the isinstance() call
        return {  # returns the built dict
            "contributors": len(list_payload),  # counts the items
            "top_contributor": (list_payload[0].get("login") or "") if list_payload else "",  # fetches the value
        }  # closes the multiline block

    def _recent_commit_authors() -> dict[str, Any]:  # defines the _recent_commit_authors() function
        payload, _ = _github_json(  # runs the _github_json() call
            f"{base}/commits", headers, {"per_page": RECENT_COMMIT_SAMPLE}, log=log  # runs the RECENT_COMMIT_SAMPLE call
        )  # closes the multiline block
        authors = []  # assigns the computed value to authors
        for item in payload or []:  # loops over the collection
            if not isinstance(item, dict):  # evaluates the branch condition
                continue  # skips to the next loop iteration
            author = (item.get("author") or {}).get("login") or (  # fetches the value
                (item.get("commit") or {}).get("author") or {}  # fetches the value
            ).get("email") or ""  # closes the multiline block
            if author:  # evaluates the branch condition
                authors.append(author)  # adds an item to the list
        fragment: dict[str, Any] = {"recent_commit_authors": authors}  # evaluates the fragment expression
        if isinstance(payload, list) and payload:  # evaluates the branch condition
            # The sample is newest-first, so its first entry already carries
            # the last commit date; deriving it here removed the separate
            # per_page=1 round trip.
            commit = (payload[0].get("commit") or {}).get("committer") or {}  # fetches the value
            fragment["last_commit_at"] = commit.get("date") or ""  # fetches the value
        return fragment  # returns the fragment to the caller

    fetchers: list[tuple[str, Any]] = [  # evaluates the fetchers expression
        ("commit activity", _commit_activity),  # maps the commit activity dictionary entry
        ("releases", _releases),  # maps the releases dictionary entry
        ("open pull requests", _open_pull_requests),  # maps the open pull requests dictionary entry
        ("oldest open issue", _oldest_open_issue),  # maps the oldest open issue dictionary entry
        ("PR resolution sample", _closed_prs),  # maps the PR resolution sample dictionary entry
        ("issue resolution sample", _closed_issues),  # maps the issue resolution sample dictionary entry
        ("contributors", _contributors),  # maps the contributors dictionary entry
        ("recent commit authors", _recent_commit_authors),  # maps the recent commit authors dictionary entry
    ]  # closes the multiline block

    # The endpoints are independent: run them side by side, then merge the
    # fragments in submission order so the result stays deterministic.
    fragments: list[dict[str, Any]] = []  # evaluates the fragments expression
    with ThreadPoolExecutor(  # opens the pool context
        max_workers=max(1, min(config.CARE_ENDPOINT_WORKERS, len(fetchers))),  # runs the min() call
        thread_name_prefix="care",  # names the thread
    ) as pool:  # closes the multiline block
        submitted = [pool.submit(attempt, metric, fetch) for metric, fetch in fetchers]  # runs the submit() call
        for future in submitted:  # loops over the collection
            fragments.append(future.result())  # waits for the thread

    for fragment in fragments:  # loops over the collection
        errors.extend(fragment.pop("__errors__", []) or [])  # adds several items to the list
        data.update(fragment)  # refreshes the layout

    data["errors"] = errors  # copies the errors value into data["errors"]
    if errors and log:  # evaluates the branch condition
        log("  Some maintenance metrics were unavailable: " + "; ".join(errors))  # runs the log() call
    return data  # returns the data to the caller


def _ref_exists(ref: RepoRef, revision: str) -> bool | None:  # defines the _ref_exists() function
    """Ask the GitHub API whether a branch/tag ref exists before downloading.

    True/False only when the API actually answered (False means the ref is
    dead); None means "could not tell" and keeps today's behaviour, since
    any API hiccup must not change the scan.
    """
    token = _github_token()  # runs the _github_token() call
    headers = {"Authorization": f"Bearer {token}"} if token else {}  # builds the headers dict
    for path in (  # loops over the collection
        f"/repos/{ref.full_name}/branches/{urllib.parse.quote(revision, safe='')}",  # branches first
        f"/repos/{ref.full_name}/tags/{urllib.parse.quote(revision, safe='')}",  # some repos publish refs as tags
    ):  # closes the multiline block
        try:  # watches for errors in the block
            with _http_get(f"{config.GITHUB_API}{path}", headers) as response:  # opens the context for the block
                if response.status == 200:  # evaluates the branch condition
                    return True  # returns the True to the caller
        except urllib.error.HTTPError as exc:  # handles the raised error
            if exc.code == 404:  # evaluates the branch condition
                continue  # not this kind of ref; try the next  # skips to the next loop iteration
            return None  # rate limit or other problem: keep the download attempt  # evaluates the return expression
        except Exception:  # noqa: BLE001 - the check is strictly best-effort  # handles the raised error
            return None  # returns the None to the caller
    return False  # both lookups answered 404: the ref is dead  # evaluates the return expression


def download_repo(  # defines the download_repo() function
    ref: RepoRef,  # evaluates the ref expression
    dest: Path,  # evaluates the dest expression
    *,  # spreads the collected values
    log: LogFn,  # evaluates the log expression
    cancel: Cancel,  # evaluates the cancel expression
    metadata: dict[str, Any] | None = None,  # evaluates the metadata expression
    file_paths: list[Path] | None = None,  # evaluates the file_paths expression
) -> Path:  # closes the multiline block
    """Fetch and extract the repository zip; return the extracted root folder.

    When ``file_paths`` (a caller-owned list) is provided it is filled with
    the shared single tree walk - the same list then feeds the language
    detection and the dashboard inputs instead of each re-walking NTFS.
    """
    dest.mkdir(parents=True, exist_ok=True)  # creates the folder
    metadata = dict(metadata or fetch_repo_metadata(ref))  # builds the dict mapping
    branch = ref.ref or metadata.get("default_branch") or "main"  # fetches the value

    # If an explicit ref cannot be fetched (deleted branch, or a URL that
    # pointed at a subdirectory), fall back to the default branch.
    candidates: list[str] = [branch]  # evaluates the candidates expression
    for fallback in (metadata.get("default_branch"), "main", "master"):  # loops over the collection
        if fallback and fallback not in candidates:  # evaluates the branch condition
            candidates.append(fallback)  # adds an item to the list

    archive = dest / "source.zip"  # copies the dest value into archive
    last_error: Exception | None = None  # evaluates the last_error expression
    for index, candidate in enumerate(candidates):  # loops over the collection
        # A dead explicit ref should not cost a full repo download just to
        # 404: the API can say cheaply that it does not exist (variables in
        # the codeload URL would accept any nonsense). Anything the API
        # cannot answer confidently falls through to today's behaviour.
        if (  # evaluates the branch condition
            index == 0  # only the caller-requested ref
            and ref.ref  # an explicit ref was requested
            and candidate == ref.ref  # guards the first candidate
            and not re.fullmatch(r"[0-9a-fA-F]{7,40}", candidate)  # SHAs are always fetchable
        ):  # closes the multiline block
            exists = _ref_exists(ref, candidate)  # runs the _ref_exists() call
            if exists is False:  # evaluates the branch condition
                log(f"  Skipping ref '{candidate}': the GitHub API says it does not exist.")  # logs the skip
                continue  # skips to the next loop iteration
        try:  # watches for errors in the block
            download(  # runs the download() call
                _zip_url(ref, candidate),  # runs the _zip_url() call
                archive,  # evaluates the archive expression
                log=log,  # copies the log value into log
                cancel=cancel,  # copies the cancel value into cancel
                what=f"{ref.full_name} ({candidate})",  # sets the what text
            )  # closes the multiline block
            branch = candidate  # copies the candidate value into branch
            break  # exits the loop early
        except ScanError as exc:  # handles the raised error
            last_error = exc  # copies the exc value into last_error
            if cancel.is_set():  # evaluates the branch condition
                raise  # evaluates the raise expression
            if len(candidates) > 1:  # evaluates the branch condition
                log(f"  Could not fetch '{candidate}': {exc}")  # runs the log() call
                if candidate == branch and ref.ref:  # evaluates the branch condition
                    log("  Falling back to the repository's default branch.")  # runs the log() call
                else:  # covers the remaining branch
                    log("  Trying another branch...")  # runs the log() call
    else:  # covers the remaining branch
        raise ScanError(f"Could not download {ref.full_name}: {last_error}")  # raises the ScanError error

    extract_dir = dest / "repo"  # copies the dest value into extract_dir
    log("Extracting repository...")  # runs the log() call
    extract_zip(archive, extract_dir)  # runs the extract_zip() call
    archive.unlink(missing_ok=True)  # deletes the file

    roots = [entry for entry in extract_dir.iterdir() if entry.is_dir()]  # runs the iterdir() call
    root = roots[0] if len(roots) == 1 else extract_dir  # counts the items
    tree_files = list(_iter_tree(root))  # gathers the values into a set
    if file_paths is not None:  # evaluates the branch condition
        # The caller wants the shared single walk: hand over the list so the
        # count, the language detection and the dashboard inputs reuse it.
        file_paths[:] = tree_files  # clears the list
    file_count = len(tree_files)  # counts the items
    log(f"Repository ready: {file_count} files on branch '{branch}'.")  # runs the log() call

    metadata.update(  # refreshes the layout
        {  # executes the statement
            "input_url": ref.web_url,  # maps the input_url dictionary entry
            "branch": branch,  # maps the branch dictionary entry
            "file_count": file_count,  # maps the file_count dictionary entry
        }  # closes the multiline block
    )  # closes the multiline block
    return root  # returns the root to the caller


def _zip_url(ref: RepoRef, revision: str) -> str:  # defines the _zip_url() function
    """Codeload URL for a branch/tag, or a bare commit SHA."""  # keeps the docstring text
    if re.fullmatch(r"[0-9a-fA-F]{7,40}", revision):  # evaluates the branch condition
        return f"https://codeload.github.com/{ref.owner}/{ref.repo}/zip/{revision}"  # returns the f to the caller
    encoded = urllib.parse.quote(revision, safe="/")  # runs the quote() call
    return config.CODELOAD_URL.format(  # returns the config.CODELOAD_URL.format to the caller
        owner=ref.owner, repo=ref.repo, ref=f"refs/heads/{encoded}"  # copies the ref.owner value into owner
    )  # closes the multiline block


# --------------------------------------------------------------------------
# Shared tree walk, language detection
# --------------------------------------------------------------------------


def _iter_tree(root: Path) -> Iterator[Path]:  # defines the _iter_tree() function
    """One shared os.walk over the checkout, skipping tool-junk folders.

    A single walk (config.SKIP_DIRS honoured) feeds the file-count log line,
    the language detection, the dashboard inputs and the IaC skip check,
    instead of three separate rglob passes over an NTFS tree.
    """
    for current, dirs, files in os.walk(root):  # loops over the collection
        dirs[:] = [d for d in dirs if d.lower() not in config.SKIP_DIRS]  # lowercases the text
        for name in files:  # loops over the collection
            yield Path(current) / name  # yields the value incrementally


def _iter_source_files(root: Path) -> Iterable[Path]:  # defines the _iter_source_files() function
    """Compatibility wrapper: the shared walk is the only file walker now."""
    return _iter_tree(root)  # returns the generator to the caller


def _has_iac_files(file_paths: Iterable[Path]) -> bool:  # defines the _has_iac_files() function
    """True when the shared walk saw anything Checkov/Kubescape could read.

    Conservative by design: config.IAC_FILE_SUFFIXES also covers plain JSON
    and .yml workflow files, so a repo holding any IaC-shaped file skips
    nothing and the check only clears repos with zero candidates.
    """
    for path in file_paths:  # loops over the collection
        if path.suffix.lower() in config.IAC_FILE_SUFFIXES:  # evaluates the branch condition
            return True  # returns the True to the caller
        lowered = path.name.lower()  # lowercases the text
        if any(lowered.startswith(name) for name in config.IAC_FILE_NAMES):  # evaluates the branch condition
            return True  # returns the True to the caller
    return False  # returns the False to the caller


def detect_languages(  # defines the detect_languages() function
    root: Path,  # evaluates the root expression
    log: LogFn | None = None,  # evaluates the log expression
    *,  # spreads the collected values
    file_paths: Iterable[Path] | None = None,  # evaluates the file_paths expression
) -> tuple[list[str], dict[str, int]]:  # closes the multiline block
    """Pick the languages worth running CodeQL on, most code first.

    When ``file_paths`` is provided the given iterable is consumed directly
    (the shared single tree walk) and no second os.walk happens.
    """
    counts: dict[str, int] = {}  # evaluates the counts expression
    walking = _iter_tree(root) if file_paths is None else file_paths  # fetches the value
    for path in walking:  # loops over the collection
        language = config.EXTENSION_LANGUAGES.get(path.suffix.lower())  # fetches the value
        if language:  # evaluates the branch condition
            counts[language] = counts.get(language, 0) + 1  # fetches the value

    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))  # sorts the values
    chosen = [language for language, _ in ranked[: config.MAX_CODEQL_LANGUAGES]]  # assigns the computed value to chosen

    workflows = list((root / ".github" / "workflows").glob("*.y*ml"))  # builds the list collection
    if not chosen and workflows:  # evaluates the branch condition
        chosen = ["actions"]  # assigns the computed value to chosen

    if log and ranked:  # evaluates the branch condition
        summary = ", ".join(f"{lang} ({count} files)" for lang, count in ranked[:5])  # sets the summary text
        log(f"Detected languages: {summary}")  # runs the log() call
    return chosen, counts  # returns the chosen to the caller


# --------------------------------------------------------------------------
# Process execution
# --------------------------------------------------------------------------


@dataclass  # applies the dataclass decorator
class CommandResult:  # defines the CommandResult class
    returncode: int  # evaluates the returncode expression
    tail: str  # evaluates the tail expression
    duration: float  # evaluates the duration expression
    timed_out: bool = False  # evaluates the timed_out expression
    cancelled: bool = False  # evaluates the cancelled expression

    @property  # applies the property decorator
    def ok(self) -> bool:  # defines the ok() function
        return self.returncode == 0 and not self.timed_out and not self.cancelled  # returns the self.returncode to the caller


def run_command(  # defines the run_command() function
    cmd: list[str],  # evaluates the cmd expression
    *,  # spreads the collected values
    log: LogFn,  # evaluates the log expression
    cancel: Cancel,  # evaluates the cancel expression
    cwd: Path | None = None,  # evaluates the cwd expression
    timeout: int | None = None,  # evaluates the timeout expression
    visible: bool = True,  # evaluates the visible expression
    stdout_path: Path | None = None,  # evaluates the stdout_path expression
    env_overrides: dict[str, str] | None = None,  # evaluates the env_overrides expression
) -> CommandResult:  # closes the multiline block
    """Run a child process, streaming its output to ``log``.

    ``stdout_path`` mirrors raw stdout (JSONL tools such as TruffleHog write
    results there) while stderr is still merged into the same stream for
    diagnostics. ``env_overrides`` sets scanner-specific cache locations.
    """
    log(f"$ {' '.join(str(part) for part in cmd)}")  # runs the log() call
    started = time.monotonic()  # runs the monotonic() call
    env = os.environ.copy()  # runs the copy() call
    env.setdefault("NO_COLOR", "1")  # runs the setdefault() call
    env.setdefault("TERM", "dumb")  # runs the setdefault() call
    env.update(env_overrides or {})  # refreshes the layout

    kwargs: dict[str, Any] = {}  # evaluates the kwargs expression
    if os.name == "nt":  # evaluates the branch condition
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)  # runs the getattr() call

    process = subprocess.Popen(  # opens the file handle
        [str(part) for part in cmd],  # runs the str() call
        cwd=str(cwd) if cwd else None,  # runs the str() call
        stdout=subprocess.PIPE,  # copies the subprocess.PIPE value into stdout
        stderr=subprocess.STDOUT,  # copies the subprocess.STDOUT value into stderr
        stdin=subprocess.DEVNULL,  # copies the subprocess.DEVNULL value into stdin
        text=True,  # assigns the True literal to text
        encoding="utf-8",  # sets the encoding text
        errors="replace",  # sets the errors text
        bufsize=1,  # assigns the computed value to bufsize
        env=env,  # copies the env value into env
        **kwargs,  # spreads the collected values
    )  # closes the multiline block

    tail: list[str] = []  # evaluates the tail expression
    state = {"timed_out": False, "cancelled": False}  # assigns the computed value to state
    stop_monitor = threading.Event()  # runs the Event() call

    def monitor() -> None:  # defines the monitor() function
        while not stop_monitor.wait(0.3):  # loops while the condition holds
            if cancel.is_set():  # evaluates the branch condition
                state["cancelled"] = True  # assigns the True literal to state["cancelled"]
                _kill_tree(process)  # runs the _kill_tree() call
                return  # evaluates the return expression
            if timeout and time.monotonic() - started > timeout:  # evaluates the branch condition
                state["timed_out"] = True  # assigns the True literal to state["timed_out"]
                _kill_tree(process)  # runs the _kill_tree() call
                return  # evaluates the return expression

    watcher = threading.Thread(target=monitor, daemon=True)  # runs the Thread() call
    watcher.start()  # begins the scan/thread

    sink = None  # assigns the None literal to sink
    if stdout_path is not None:  # evaluates the branch condition
        stdout_path.parent.mkdir(parents=True, exist_ok=True)  # creates the folder
        sink = stdout_path.open("w", encoding="utf-8", errors="replace")  # opens the file handle

    try:  # watches for errors in the block
        assert process.stdout is not None  # verifies the assumption
        for raw_line in process.stdout:  # loops over the collection
            line = raw_line.rstrip("\r\n")  # runs the rstrip() call
            if sink is not None:  # evaluates the branch condition
                sink.write(line + "\n")  # runs the write() call
            if not line.strip():  # evaluates the branch condition
                continue  # skips to the next loop iteration
            if visible:  # evaluates the branch condition
                log(line)  # runs the log() call
            tail.append(line)  # adds an item to the list
            if len(tail) > 250:  # evaluates the branch condition
                del tail[:100]  # removes the variable or entry
    finally:  # runs whether or not the block errored
        if sink is not None:  # evaluates the branch condition
            sink.close()  # runs the close() call
        stop_monitor.set()  # updates the stored value
        watcher.join(timeout=2)  # waits for the thread

    returncode = process.wait()  # runs the wait() call
    duration = time.monotonic() - started  # runs the monotonic() call

    if state["cancelled"]:  # evaluates the branch condition
        raise ScanCancelled("Scan cancelled by user.")  # raises the ScanCancelled error
    if state["timed_out"]:  # evaluates the branch condition
        log(f"Timed out after {timeout}s.")  # runs the log() call
    log(f"  exit code {returncode} after {duration:.1f}s")  # runs the log() call

    return CommandResult(  # returns the CommandResult to the caller
        returncode=returncode,  # copies the returncode value into returncode
        tail="\n".join(tail[-40:]),  # sets the tail text
        duration=duration,  # copies the duration value into duration
        timed_out=state["timed_out"],  # copies the state value into timed_out
    )  # closes the multiline block


# --------------------------------------------------------------------------
# Tool bootstrap
# --------------------------------------------------------------------------


def _codeql_exe() -> Path:  # defines the _codeql_exe() function
    name = "codeql.exe" if os.name == "nt" else "codeql"  # sets the name text
    return config.TOOLS_DIR / "codeql" / name  # returns the config.TOOLS_DIR to the caller


def ensure_codeql(log: LogFn, cancel: Cancel) -> Path:  # defines the ensure_codeql() function
    executable = _codeql_exe()  # runs the _codeql_exe() call
    if executable.exists():  # evaluates the branch condition
        return executable  # returns the executable to the caller
    if os.name != "nt":  # evaluates the branch condition
        raise ToolError(  # raises the ToolError error
            "Automatic CodeQL setup is only implemented for Windows hosts. "  # supplies the literal text
            "Set up the CodeQL CLI manually and point CODEQL_PATH at it."  # supplies the literal text
        )  # closes the multiline block

    archive = config.TOOLS_DIR / f"codeql-bundle-{config.CODEQL_PLATFORM}.tar.gz"  # copies the config.TOOLS_DIR value into archive
    if not archive.exists() or archive.stat().st_size < 100_000_000:  # evaluates the branch condition
        url = config.CODEQL_BUNDLE_URL.format(platform=config.CODEQL_PLATFORM)  # runs the format() call
        download(url, archive, log=log, cancel=cancel, what="CodeQL CLI bundle")  # runs the download() call

    log("Extracting CodeQL bundle (first run only, roughly 1.5 GB on disk)...")  # runs the log() call
    config.TOOLS_DIR.mkdir(parents=True, exist_ok=True)  # creates the folder
    if not extract_tar(archive, config.TOOLS_DIR, log=log, cancel=cancel):  # evaluates the branch condition
        shutil.rmtree(config.TOOLS_DIR / "codeql", ignore_errors=True)  # deletes the folder tree
        _tar_fallback_extract(archive, config.TOOLS_DIR)  # runs the _tar_fallback_extract() call

    if not executable.exists():  # evaluates the branch condition
        raise ToolError(f"CodeQL bundle extracted but {executable} is missing.")  # raises the ToolError error
    # The extracted CLI is what we need; the 700 MB tarball is dead weight.
    archive.unlink(missing_ok=True)  # deletes the file
    log(f"CodeQL ready: {executable}")  # runs the log() call
    return executable  # returns the executable to the caller


def _trivy_exe() -> Path:  # defines the _trivy_exe() function
    return config.TOOLS_DIR / "trivy" / ("trivy.exe" if os.name == "nt" else "trivy")  # returns the config.TOOLS_DIR to the caller


def ensure_trivy(log: LogFn, cancel: Cancel) -> Path:  # defines the ensure_trivy() function
    executable = _trivy_exe()  # runs the _trivy_exe() call
    if executable.exists():  # evaluates the branch condition
        return executable  # returns the executable to the caller

    archive = config.TOOLS_DIR / "trivy.zip"  # copies the config.TOOLS_DIR value into archive
    if not archive.exists() or archive.stat().st_size < 10_000_000:  # evaluates the branch condition
        url = _resolve_trivy_asset()  # gathers the values into a set
        download(url, archive, log=log, cancel=cancel, what="Trivy")  # runs the download() call

    log("Extracting Trivy...")  # runs the log() call
    target = config.TOOLS_DIR / "trivy"  # copies the config.TOOLS_DIR value into target
    target.mkdir(parents=True, exist_ok=True)  # creates the folder
    extract_zip(archive, target)  # runs the extract_zip() call
    if not executable.exists():  # evaluates the branch condition
        matches = list(target.rglob("trivy.exe"))  # builds the list collection
        if not matches:  # evaluates the branch condition
            raise ToolError("Trivy archive did not contain trivy.exe.")  # raises the ToolError error
        shutil.copy2(matches[0], executable)  # runs the copy2() call
    archive.unlink(missing_ok=True)  # deletes the file
    log(f"Trivy ready: {executable}")  # runs the log() call
    return executable  # returns the executable to the caller


_TRIVY_ASSET_CACHE: dict[str, str] = {}  # in-process memo for the resolved asset URL  # assigns the computed value


def _resolve_trivy_asset() -> str:  # defines the _resolve_trivy_asset() function
    """Ask the GitHub API for the newest Windows Trivy zip (memoized)."""
    cached = _TRIVY_ASSET_CACHE.get("asset")  # fetches the value
    if cached:  # evaluates the branch condition
        return cached  # returns the cached to the caller
    token = _github_token()  # runs the _github_token() call
    headers = {"Authorization": f"Bearer {token}"} if token else {}  # builds the headers dict
    try:  # watches for errors in the block
        with _http_get(config.TRIVY_LATEST_API, headers) as response:  # opens the context for the block
            release = json.load(response)  # reads JSON data from the stream
        for asset in release.get("assets") or []:  # loops over the collection
            name = str(asset.get("name") or "")  # runs the str() call
            if name.endswith("windows-64bit.zip"):  # evaluates the branch condition
                resolved = str(asset.get("browser_download_url") or "")  # runs the str() call
                if resolved:  # evaluates the branch condition
                    _TRIVY_ASSET_CACHE["asset"] = resolved  # memoizes the resolved value
                    return resolved  # returns the str to the caller
    except (  # handles the raised error
        urllib.error.URLError,  # connection / DNS problems
        urllib.error.HTTPError,  # rate limits and auth errors
        OSError,  # socket-level hiccups
        ValueError,  # a non-JSON body
    ):  # closes the multiline block
        pass  # fall through to the pinned fallback version
    return (  # returns the value to the caller
        "https://github.com/aquasecurity/trivy/releases/download/"  # maps the https://github.com/aquas dictionary entry
        f"v{config.TRIVY_FALLBACK_VERSION}/trivy_{config.TRIVY_FALLBACK_VERSION}_windows-64bit.zip"  # supplies the literal text
    )  # closes the multiline block


# --------------------------------------------------------------------------
# Scanner wrappers
# --------------------------------------------------------------------------


def run_trivy(  # defines the run_trivy() function
    root: Path, artifacts: Path, *, log: LogFn, cancel: Cancel  # evaluates the root expression
) -> tuple[Path, dict[str, Any]]:  # closes the multiline block
    """Scan the checkout with Trivy; return the JSON report path and status."""  # keeps the docstring text
    executable = ensure_trivy(log, cancel)  # runs the ensure_trivy() call
    output = artifacts / "trivy.json"  # copies the artifacts value into output
    cache = config.TOOLS_DIR / "trivy-cache"  # copies the config.TOOLS_DIR value into cache
    cache.mkdir(parents=True, exist_ok=True)  # creates the folder

    result = run_command(  # runs the run_command() call
        [  # executes the statement
            str(executable),  # runs the str() call
            "fs",  # supplies the literal text
            "--format",  # supplies the literal text
            "json",  # supplies the literal text
            "--output",  # supplies the literal text
            str(output),  # runs the str() call
            "--scanners",  # supplies the literal text
            "vuln,secret,misconfig",  # supplies the literal text
            "--no-progress",  # supplies the literal text
            "--cache-dir",  # supplies the literal text
            str(cache),  # runs the str() call
            "--timeout",  # supplies the literal text
            "20m",  # supplies the literal text
            str(root),  # runs the str() call
        ],  # closes the multiline block
        log=log,  # copies the log value into log
        cancel=cancel,  # copies the cancel value into cancel
        timeout=config.SCAN_TIMEOUT_SECONDS,  # copies the config.SCAN_TIMEOUT_SECONDS value into timeout
    )  # closes the multiline block

    status: dict[str, Any] = {  # evaluates the status expression
        "status": "ok" if result.ok and output.exists() else "error",  # maps the status dictionary entry
        "duration_seconds": round(result.duration, 1),  # maps the duration_seconds dictionary entry
        "details": [f"trivy fs on {root.name}"],  # maps the details dictionary entry
    }  # closes the multiline block
    if status["status"] != "ok":  # evaluates the branch condition
        status["details"].append(f"Trivy exited with code {result.returncode}.")  # adds an item to the list
        if result.tail:  # evaluates the branch condition
            status["details"].append(result.tail.splitlines()[-1][:300])  # adds an item to the list
    return output, status  # returns the output to the caller


def _codeql_suite_candidates(language: str) -> list[str]:  # defines the _codeql_suite_candidates() function
    pack = config.LANGUAGE_PACKS[language]  # copies the config.LANGUAGE_PACKS value into pack
    return [  # returns the value to the caller
        f"codeql/{pack}-queries:codeql-suites/{pack}-security-extended.qls",  # maps the codeql/{pack}-queries:co dictionary entry
        f"codeql/{pack}-queries:codeql-suites/{pack}-security-and-quality.qls",  # maps the codeql/{pack}-queries:sco dictionary entry
        f"codeql/{pack}-queries",  # supplies the literal text
    ]  # closes the multiline block


def _discard_log(message: str) -> None:  # defines the _discard_log() function
    """Sink for the cheap pre-validation runs (no newline noise in the UI)."""
    del message  # marks the argument as intentionally unused


def _codeql_suite_resolves(executable: Path, suite: str, cancel: Cancel) -> bool:  # defines the _codeql_suite_resolves() function
    """Cheapest available pre-validation: does `codeql resolve queries` pass?

    A suite the CLI cannot resolve can never analyze, so the hopeless
    fallbacks drop out before any heavyweight `database analyze` re-run.
    """
    check = run_command(  # runs the run_command() call
        [str(executable), "resolve", "queries", suite, "--format=off"],  # executes the statement
        log=_discard_log,  # copies the log value into log
        cancel=cancel,  # copies the cancel value into cancel
        timeout=300,  # resolves in seconds, not minutes  # evaluates the timeout expression
        visible=False,  # assigns the False literal to visible
    )  # closes the multiline block
    return check.ok  # evaluates the check.ok expression


def run_codeql(  # defines the run_codeql() function
    root: Path,  # evaluates the root expression
    artifacts: Path,  # evaluates the artifacts expression
    languages: list[str],  # evaluates the languages expression
    *,  # spreads the collected values
    log: LogFn,  # evaluates the log expression
    cancel: Cancel,  # evaluates the cancel expression
) -> tuple[list[Path], dict[str, Any]]:  # closes the multiline block
    """Create and analyze a CodeQL database per language."""  # keeps the docstring text
    executable = ensure_codeql(log, cancel)  # runs the ensure_codeql() call
    started = time.monotonic()  # runs the monotonic() call
    sarif_files: list[Path] = []  # evaluates the sarif_files expression
    details: list[str] = []  # evaluates the details expression
    failures = 0  # assigns the computed value to failures

    if not languages:  # evaluates the branch condition
        return [], {  # returns the value to the caller
            "status": "skipped",  # maps the status dictionary entry
            "duration_seconds": 0.0,  # maps the duration_seconds dictionary entry
            "details": ["No CodeQL-supported language was detected in the repository."],  # maps the details dictionary entry
        }  # closes the multiline block

    for language in languages:  # loops over the collection
        database = artifacts / f"codeql-db-{language}"  # copies the artifacts value into database
        if database.exists():  # evaluates the branch condition
            shutil.rmtree(database, ignore_errors=True)  # deletes the folder tree

        create_cmd = [  # assigns the computed value to create_cmd
            str(executable),  # runs the str() call
            "database",  # supplies the literal text
            "create",  # supplies the literal text
            str(database),  # runs the str() call
            "--language",  # supplies the literal text
            language,  # evaluates the language expression
            "--source-root",  # supplies the literal text
            str(root),  # runs the str() call
            "--overwrite",  # supplies the literal text
        ]  # closes the multiline block
        if language not in config.BUILDLESS_LANGUAGES:  # evaluates the branch condition
            # No compiler needed: extract without a build.
            create_cmd += ["--build-mode", "none"]  # evaluates the create_cmd expression

        create = run_command(  # runs the run_command() call
            create_cmd, log=log, cancel=cancel, timeout=config.SCAN_TIMEOUT_SECONDS  # copies the log value into create_cmd, log
        )  # closes the multiline block
        if not create.ok:  # evaluates the branch condition
            failures += 1  # evaluates the failures expression
            details.append(  # adds an item to the list
                f"CodeQL could not build a database for {language} (exit {create.returncode})."  # supplies the literal text
            )  # closes the multiline block
            log(f"CodeQL database creation failed for {language}; continuing.")  # runs the log() call
            shutil.rmtree(database, ignore_errors=True)  # deletes the folder tree
            continue  # skips to the next loop iteration

        output = artifacts / f"codeql-{language}.sarif"  # copies the artifacts value into output
        # Pre-validate the suite ladder: a suite `resolve queries` rejects
        # can never analyze, so it drops out here instead of burning a full
        # `database analyze` (which only reads this same database - it is
        # NOT recreated between suites; recreate would mean a full
        # re-extraction). The analyze ladder itself is capped at two runs -
        # the preferred resolving suite, then the bare pack - so a flaky
        # analysis cannot cost three full sweep re-runs of the same pack.
        candidates = _codeql_suite_candidates(language)  # runs the _codeql_suite_candidates() call
        candidates = [  # assigns the computed value to candidates
            suite  # evaluates the suite expression
            for suite in candidates  # loops over the collection
            if _codeql_suite_resolves(executable, suite, cancel) or suite == candidates[-1]  # the bare pack is the guaranteed last resort  # evaluates the or-suite expression
        ]  # closes the multiline block
        ladder = candidates if len(candidates) < 3 else candidates[:1] + [candidates[-1]]  # at most two analyze runs  # assigns the computed value
        log(f"Running CodeQL security queries for {language} (this is the slow part)...")  # runs the log() call
        analyze: CommandResult | None = None  # evaluates the analyze expression
        for suite in ladder:  # loops over the collection
            candidate = run_command(  # runs the run_command() call
                [  # executes the statement
                    str(executable),  # runs the str() call
                    "database",  # supplies the literal text
                    "analyze",  # supplies the literal text
                    str(database),  # runs the str() call
                    suite,  # evaluates the suite expression
                    "--format",  # supplies the literal text
                    "sarif-latest",  # supplies the literal text
                    "--output",  # supplies the literal text
                    str(output),  # runs the str() call
                ],  # closes the multiline block
                log=log,  # copies the log value into log
                cancel=cancel,  # copies the cancel value into cancel
                timeout=config.SCAN_TIMEOUT_SECONDS,  # copies the config.SCAN_TIMEOUT_SECONDS value into timeout
                visible=False,  # assigns the False literal to visible
            )  # closes the multiline block
            analyze = candidate  # copies the candidate value into analyze
            if candidate.ok and output.exists():  # evaluates the branch condition
                break  # exits the loop early
            log(f"  Suite {suite} failed (exit {candidate.returncode}); trying a fallback.")  # runs the log() call

        if analyze is not None and analyze.ok and output.exists():  # evaluates the branch condition
            sarif_files.append(output)  # adds an item to the list
            details.append(f"CodeQL {language}: database + queries completed.")  # adds an item to the list
            log(f"CodeQL analysis complete for {language}.")  # runs the log() call
        else:  # covers the remaining branch
            failures += 1  # evaluates the failures expression
            details.append(f"CodeQL analysis failed for {language}.")  # adds an item to the list
            log(f"CodeQL analysis failed for {language}.")  # runs the log() call

        shutil.rmtree(database, ignore_errors=True)  # deletes the folder tree

    status = {  # assigns the computed value to status
        "status": "ok" if failures == 0 else ("error" if not sarif_files else "partial"),  # maps the status dictionary entry
        "duration_seconds": round(time.monotonic() - started, 1),  # maps the duration_seconds dictionary entry
        "details": details,  # maps the details dictionary entry
    }  # closes the multiline block
    return sarif_files, status  # returns the sarif_files to the caller


# --------------------------------------------------------------------------
# Additional scanner wrappers
# --------------------------------------------------------------------------


def _scanner_status(  # defines the _scanner_status() function
    name: str,  # evaluates the name expression
    result: CommandResult,  # evaluates the result expression
    output: Path,  # evaluates the output expression
    detail: str,  # evaluates the detail expression
    *,  # spreads the collected values
    allow_empty: bool = False,  # evaluates the allow_empty expression
    accept_nonzero: bool = False,  # evaluates the accept_nonzero expression
    paths: list[Path] | None = None,  # evaluates the paths expression
) -> dict[str, Any]:  # closes the multiline block
    """Judge success by the report file(s), not only by exit code.

    GitLeaks, TruffleHog and OSV-Scanner use non-zero exits for "findings
    found", so a readable report is the authoritative success signal.
    ``paths`` replaces the single ``output`` file with a directory of
    reports (Checkov writes one JSON per framework).
    """
    targets = paths if paths is not None else [output]  # copies the paths value into targets
    has_output = any(  # evaluates the any() call
        path.exists() and (allow_empty or path.stat().st_size > 0)  # checks the path exists
        for path in targets  # loops over the collection
    )  # closes the multiline block
    exit_ok = result.ok or (  # copies the result.ok value into exit_ok
        accept_nonzero and not result.timed_out and not result.cancelled and has_output  # evaluates the accept_nonzero expression
    )  # closes the multiline block
    ok = has_output and exit_ok  # copies the has_output value into ok
    status: dict[str, Any] = {  # evaluates the status expression
        "status": "ok" if ok else "error",  # maps the status dictionary entry
        "duration_seconds": round(result.duration, 1),  # maps the duration_seconds dictionary entry
        "details": [detail],  # maps the details dictionary entry
    }  # closes the multiline block
    if not ok:  # evaluates the branch condition
        label = config.TOOL_LABELS.get(name, name.title())  # fetches the value
        status["details"].append(f"{label} exited with code {result.returncode}.")  # adds an item to the list
        if result.timed_out:  # evaluates the branch condition
            status["details"].append("The scanner hit its time limit.")  # adds an item to the list
        last_line = next(  # runs the next() call
            (line for line in reversed(result.tail.splitlines()) if line.strip()), ""  # runs the reversed() call
        )  # closes the multiline block
        if last_line:  # evaluates the branch condition
            status["details"].append(last_line[:300])  # adds an item to the list
    return status  # returns the status to the caller


def run_grype(  # defines the run_grype() function
    root: Path,  # evaluates the root expression
    artifacts: Path,  # evaluates the artifacts expression
    *,  # spreads the collected values
    log: LogFn,  # evaluates the log expression
    cancel: Cancel,  # evaluates the cancel expression
    sbom: Path | None = None,  # evaluates the sbom expression
) -> tuple[Path, dict[str, Any]]:  # closes the multiline block
    """Scan dependencies with Grype (Anchore's vulnerability database).

    When Syft ran successfully, Grype consumes the same SBOM so both tools
    describe exactly the same component set; otherwise it scans the checkout.
    """
    executable = ensure_tool("grype", log, cancel)  # runs the ensure_tool() call
    output = artifacts / "grype.json"  # copies the artifacts value into output
    cache = config.TOOLS_DIR / "grype-db"  # copies the config.TOOLS_DIR value into cache
    cache.mkdir(parents=True, exist_ok=True)  # creates the folder
    target = f"sbom:{sbom}" if sbom else f"dir:{root}"  # sets the target text

    result = run_command(  # runs the run_command() call
        [str(executable), target, "-o", "json", "--file", str(output), "--quiet"],  # runs the str() call
        log=log,  # copies the log value into log
        cancel=cancel,  # copies the cancel value into cancel
        timeout=config.SCAN_TIMEOUT_SECONDS,  # copies the config.SCAN_TIMEOUT_SECONDS value into timeout
        visible=False,  # assigns the False literal to visible
        env_overrides={  # assigns the computed value to env_overrides
            "GRYPE_DB_CACHE_DIR": str(cache),  # maps the GRYPE_DB_CACHE_DIR dictionary entry
            "GRYPE_CHECK_FOR_APP_UPDATE": "false",  # maps the GRYPE_CHECK_FOR_APP_UPDA dictionary entry
        },  # closes the multiline block
    )  # closes the multiline block
    source = f"grype sbom from Syft on {root.name}" if sbom else f"grype dir on {root.name}"  # sets the source text
    status = _scanner_status("grype", result, output, source)  # runs the _scanner_status() call
    return output, status  # returns the output to the caller


def _osv_source_command(executable: Path, output: Path, root: Path) -> list[str]:  # defines the _osv_source_command() function
    """Exact source-scan command line (kept single so the shape stays tested)."""
    return [  # returns the value to the caller
        str(executable),  # runs the str() call
        "scan",  # supplies the literal text
        "source",  # supplies the literal text
        "-r",  # supplies the literal text
        "--format",  # supplies the literal text
        "json",  # supplies the literal text
        "--output-file",  # supplies the literal text
        str(output),  # runs the str() call
        str(root),  # runs the str() call
    ]  # closes the multiline block


def run_osv(  # defines the run_osv() function
    root: Path, artifacts: Path, *, log: LogFn, cancel: Cancel,  # evaluates the root expression
    sbom: Path | None = None,  # evaluates the sbom expression
) -> tuple[Path, dict[str, Any]]:  # closes the multiline block
    """Scan dependencies against the OSV database.

    When Syft produced an SBOM before this tool runs, OSV-Scanner is first
    pointed at that file. The pinned v2.7.0 CLI still ships the deprecated
    ``--sbom <file>`` flag, but only consumes files whose names follow the
    SPDX/CycloneDX spec (bom.json, *.spdx.json, *.cdx.json) - so the plain
    source scan stays the fall-back whenever the SBOM pass yields no report.
    """
    executable = ensure_tool("osv", log, cancel)  # runs the ensure_tool() call
    output = artifacts / "osv.json"  # copies the artifacts value into output

    if sbom is not None and sbom.exists():  # evaluates the branch condition
        result = run_command(  # runs the run_command() call
            [  # executes the statement
                str(executable),  # runs the str() call
                "scan",  # supplies the literal text
                "source",  # supplies the literal text
                "--sbom",  # supplies the literal text
                str(sbom),  # runs the str() call
                "--format",  # supplies the literal text
                "json",  # supplies the literal text
                "--output-file",  # supplies the literal text
                str(output),  # runs the str() call
            ],  # closes the multiline block
            log=log,  # copies the log value into log
            cancel=cancel,  # copies the cancel value into cancel
            timeout=config.SCAN_TIMEOUT_SECONDS,  # copies the config.SCAN_TIMEOUT_SECONDS value into timeout
            visible=False,  # assigns the False literal to visible
        )  # closes the multiline block
        if output.exists() and output.stat().st_size > 0:  # evaluates the branch condition
            status = _scanner_status(  # runs the _scanner_status() call
                "osv",  # supplies the literal text
                result,  # evaluates the result expression
                output,  # evaluates the output expression
                f"osv-scanner sbom ({sbom.name}) from {root.name}",  # supplies the literal text
                accept_nonzero=True,  # nonzero exit means findings were found  # assigns the True literal to accept_nonzero
            )  # closes the multiline block
            return output, status  # returns the output to the caller
        log("  OSV-Scanner could not consume the SBOM; falling back to the source scan.")  # logs the note
        output.unlink(missing_ok=True)  # deletes the file

    result = run_command(  # runs the run_command() call
        _osv_source_command(executable, output, root),  # runs the _osv_source_command() call
        log=log,  # copies the log value into log
        cancel=cancel,  # copies the cancel value into cancel
        timeout=config.SCAN_TIMEOUT_SECONDS,  # copies the config.SCAN_TIMEOUT_SECONDS value into timeout
        visible=False,  # assigns the False literal to visible
    )  # closes the multiline block
    status = _scanner_status(  # runs the _scanner_status() call
        "osv", result, output, f"osv-scanner scan source on {root.name}", accept_nonzero=True  # supplies the literal text
    )  # closes the multiline block
    return output, status  # returns the output to the caller


def run_gitleaks(  # defines the run_gitleaks() function
    root: Path, artifacts: Path, *, log: LogFn, cancel: Cancel  # evaluates the root expression
) -> tuple[Path, dict[str, Any]]:  # closes the multiline block
    """Scan the working tree for committed credentials with GitLeaks."""  # keeps the docstring text
    executable = ensure_tool("gitleaks", log, cancel)  # runs the ensure_tool() call
    output = artifacts / "gitleaks.json"  # copies the artifacts value into output

    result = run_command(  # runs the run_command() call
        [  # executes the statement
            str(executable),  # runs the str() call
            "dir",  # supplies the literal text
            str(root),  # runs the str() call
            "--report-format",  # supplies the literal text
            "json",  # supplies the literal text
            "--report-path",  # supplies the literal text
            str(output),  # runs the str() call
            "--no-banner",  # supplies the literal text
            "--redact",  # supplies the literal text
            "--exit-code",  # supplies the literal text
            "0",  # supplies the literal text
        ],  # closes the multiline block
        log=log,  # copies the log value into log
        cancel=cancel,  # copies the cancel value into cancel
        timeout=config.SCAN_TIMEOUT_SECONDS,  # copies the config.SCAN_TIMEOUT_SECONDS value into timeout
        visible=False,  # assigns the False literal to visible
    )  # closes the multiline block
    status = _scanner_status(  # runs the _scanner_status() call
        "gitleaks", result, output, f"gitleaks dir on {root.name}", accept_nonzero=True  # supplies the literal text
    )  # closes the multiline block
    return output, status  # returns the output to the caller


def run_trufflehog(  # defines the run_trufflehog() function
    root: Path, artifacts: Path, *, log: LogFn, cancel: Cancel  # evaluates the root expression
) -> tuple[Path, dict[str, Any]]:  # closes the multiline block
    """Scan for secrets with TruffleHog (verification disabled for privacy)."""  # keeps the docstring text
    executable = ensure_tool("trufflehog", log, cancel)  # runs the ensure_tool() call
    output = artifacts / "trufflehog.jsonl"  # copies the artifacts value into output

    result = run_command(  # runs the run_command() call
        [  # executes the statement
            str(executable),  # runs the str() call
            "filesystem",  # supplies the literal text
            str(root),  # runs the str() call
            "--json",  # supplies the literal text
            "--no-verification",  # supplies the literal text
            "--no-update",  # supplies the literal text
            "--concurrency=8",  # supplies the literal text
        ],  # closes the multiline block
        log=log,  # copies the log value into log
        cancel=cancel,  # copies the cancel value into cancel
        timeout=config.SCAN_TIMEOUT_SECONDS,  # copies the config.SCAN_TIMEOUT_SECONDS value into timeout
        visible=False,  # assigns the False literal to visible
        stdout_path=output,  # copies the output value into stdout_path
    )  # closes the multiline block
    status = _scanner_status(  # runs the _scanner_status() call
        "trufflehog",  # supplies the literal text
        result,  # evaluates the result expression
        output,  # evaluates the output expression
        f"trufflehog filesystem on {root.name} (verification disabled)",  # supplies the literal text
        allow_empty=True,  # assigns the True literal to allow_empty
        accept_nonzero=True,  # assigns the True literal to accept_nonzero
    )  # closes the multiline block
    return output, status  # returns the output to the caller


def run_semgrep(  # defines the run_semgrep() function
    root: Path, artifacts: Path, *, log: LogFn, cancel: Cancel  # evaluates the root expression
) -> tuple[Path, dict[str, Any]]:  # closes the multiline block
    """Scan code with the Semgrep CE community ruleset.

    The ``p/default`` registry pack is fetched by Semgrep itself on every
    invocation (no supported cache switch exists - see config.SEMGREP_CONFIG
    for the audit note); the pipeline runs Semgrep at most once per project
    scan, so the registry fetch happens once per project.
    """
    executable = ensure_semgrep(log, cancel)  # runs the ensure_semgrep() call
    output = artifacts / "semgrep.json"  # copies the artifacts value into output

    result = run_command(  # runs the run_command() call
        [  # executes the statement
            str(executable),  # runs the str() call
            "scan",  # supplies the literal text
            "--config",  # supplies the literal text
            config.SEMGREP_CONFIG,  # evaluates the config.SEMGREP_CONFIG expression
            "--json",  # supplies the literal text
            "--metrics=off",  # supplies the literal text
            "--disable-version-check",  # supplies the literal text
            "--quiet",  # supplies the literal text
            "--output",  # supplies the literal text
            str(output),  # runs the str() call
            str(root),  # runs the str() call
        ],  # closes the multiline block
        log=log,  # copies the log value into log
        cancel=cancel,  # copies the cancel value into cancel
        timeout=config.SCAN_TIMEOUT_SECONDS,  # copies the config.SCAN_TIMEOUT_SECONDS value into timeout
        visible=False,  # assigns the False literal to visible
        env_overrides={"SEMGREP_SEND_METRICS": "off"},  # assigns the computed value to env_overrides
    )  # closes the multiline block
    status = _scanner_status(  # runs the _scanner_status() call
        "semgrep", result, output, f"semgrep {config.SEMGREP_CONFIG} on {root.name}"  # supplies the literal text
    )  # closes the multiline block
    return output, status  # returns the output to the caller


def run_syft(  # defines the run_syft() function
    root: Path, artifacts: Path, *, log: LogFn, cancel: Cancel  # evaluates the root expression
) -> tuple[Path, dict[str, Any]]:  # closes the multiline block
    """Build an SBOM inventory with Syft (no scoring; optional Grype input)."""  # keeps the docstring text
    executable = ensure_tool("syft", log, cancel)  # runs the ensure_tool() call
    output = artifacts / "syft.json"  # copies the artifacts value into output

    result = run_command(  # runs the run_command() call
        [  # executes the statement
            str(executable),  # runs the str() call
            f"dir:{root}",  # maps the dir:{root} dictionary entry
            "-o",  # supplies the literal text
            "json",  # supplies the literal text
            "--file",  # supplies the literal text
            str(output),  # runs the str() call
            "--quiet",  # supplies the literal text
        ],  # closes the multiline block
        log=log,  # copies the log value into log
        cancel=cancel,  # copies the cancel value into cancel
        timeout=config.SCAN_TIMEOUT_SECONDS,  # copies the config.SCAN_TIMEOUT_SECONDS value into timeout
        visible=False,  # assigns the False literal to visible
        env_overrides={"SYFT_CHECK_FOR_APP_UPDATE": "false"},  # assigns the computed value to env_overrides
    )  # closes the multiline block
    status = _scanner_status("syft", result, output, f"syft dir on {root.name}")  # runs the _scanner_status() call
    return output, status  # returns the output to the caller


def run_checkov(  # defines the run_checkov() function
    root: Path, artifacts: Path, *, log: LogFn, cancel: Cancel  # evaluates the root expression
) -> tuple[Path, dict[str, Any]]:  # closes the multiline block
    """Scan IaC and container definitions with Checkov."""  # keeps the docstring text
    python, script = ensure_checkov(log, cancel)  # runs the ensure_checkov() call
    output_dir = artifacts / "checkov"  # copies the artifacts value into output_dir
    if output_dir.exists():  # evaluates the branch condition
        shutil.rmtree(output_dir, ignore_errors=True)  # deletes the folder tree
    output_dir.mkdir(parents=True, exist_ok=True)  # creates the folder

    result = run_command(  # runs the run_command() call
        [  # executes the statement
            str(python),  # runs the str() call
            str(script),  # runs the str() call
            "-d",  # supplies the literal text
            str(root),  # runs the str() call
            "--output",  # supplies the literal text
            "json",  # supplies the literal text
            "--output-file-path",  # supplies the literal text
            str(output_dir),  # runs the str() call
            "--compact",  # supplies the literal text
            "--quiet",  # supplies the literal text
            "--skip-download",  # supplies the literal text
            "--repo-id",  # supplies the literal text
            root.name or "repository",  # evaluates the root.name expression
        ],  # closes the multiline block
        log=log,  # copies the log value into log
        cancel=cancel,  # copies the cancel value into cancel
        timeout=config.SCAN_TIMEOUT_SECONDS,  # copies the config.SCAN_TIMEOUT_SECONDS value into timeout
        visible=False,  # assigns the False literal to visible
        env_overrides={"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},  # assigns the computed value to env_overrides
    )  # closes the multiline block

    reports = sorted(output_dir.glob("*.json"))  # sorts the values
    status = _scanner_status(  # runs the _scanner_status() call
        "checkov",  # supplies the literal text
        result,  # exit/tail/timed-out details come from the shared helper  # evaluates the result expression
        output_dir,  # evaluated only when no report list is given  # evaluates the output_dir expression
        f"checkov on {root.name} ({len(reports)} framework report(s))",  # supplies the literal text
        paths=reports,  # one JSON per framework  # copies the reports value into paths
        accept_nonzero=True,  # nonzero exit with reports is still a success  # assigns the True literal to accept_nonzero
    )  # closes the multiline block
    return output_dir, status  # returns the output_dir to the caller


_GUARDDOG_DRIVER = '''\
"""Run GuardDog's local source-code scanners and write one JSON document."""
import json
import sys

from guarddog.scanners import GoModuleScanner, NPMPackageScanner, PypiPackageScanner

root, output, *ecosystems = sys.argv[1:]
scanners = {
    "pypi": PypiPackageScanner,
    "npm": NPMPackageScanner,
    "go": GoModuleScanner,
}
scans = []
for ecosystem in ecosystems or ["pypi"]:
    factory = scanners.get(ecosystem)
    if factory is None:
        continue
    try:
        scans.append({"ecosystem": ecosystem, "result": factory().scan_local(root)})
    except Exception as exc:  # keep going: one ecosystem must not hide the others
        scans.append({"ecosystem": ecosystem, "error": repr(exc)})

with open(output, "w", encoding="utf-8") as handle:
    json.dump({"scans": scans}, handle)
'''


def _guarddog_ecosystems(root: Path) -> list[str]:  # defines the _guarddog_ecosystems() function
    """Pick the package ecosystems GuardDog's local rules should cover."""  # keeps the docstring text
    ecosystems: list[str] = []  # evaluates the ecosystems expression
    python_markers = (  # assigns the computed value to python_markers
        "requirements.txt",  # supplies the literal text
        "pyproject.toml",  # supplies the literal text
        "setup.py",  # supplies the literal text
        "setup.cfg",  # supplies the literal text
        "Pipfile",  # supplies the literal text
        "poetry.lock",  # supplies the literal text
    )  # closes the multiline block
    if any((root / marker).exists() for marker in python_markers):  # evaluates the branch condition
        ecosystems.append("pypi")  # adds an item to the list
    if (root / "package.json").exists():  # evaluates the branch condition
        ecosystems.append("npm")  # adds an item to the list
    if (root / "go.mod").exists():  # evaluates the branch condition
        ecosystems.append("go")  # adds an item to the list
    return ecosystems or ["pypi"]  # returns the ecosystems to the caller


def run_guarddog(  # defines the run_guarddog() function
    root: Path, artifacts: Path, *, log: LogFn, cancel: Cancel  # evaluates the root expression
) -> tuple[Path, dict[str, Any]]:  # closes the multiline block
    """Scan for malware and supply-chain patterns with GuardDog's local rules."""  # keeps the docstring text
    python = ensure_guarddog(log, cancel)  # runs the ensure_guarddog() call
    output = artifacts / "guarddog.json"  # copies the artifacts value into output
    driver = artifacts / "guarddog_scan.py"  # copies the artifacts value into driver
    driver.write_text(_GUARDDOG_DRIVER, encoding="utf-8")  # writes the text file
    ecosystems = _guarddog_ecosystems(root)  # runs the _guarddog_ecosystems() call

    # GuardDog shells out to `semgrep`; its own venv ships one, so make that
    # folder the first entry on PATH. PYTHONUTF8 stops its YAML rules from
    # crashing on Windows' default cp1252 codec.
    scripts_dir = str(python.parent)  # runs the str() call
    env = {  # assigns the computed value to env
        "PATH": scripts_dir + os.pathsep + os.environ.get("PATH", ""),  # maps the PATH dictionary entry
        "PYTHONUTF8": "1",  # maps the PYTHONUTF8 dictionary entry
        "PYTHONIOENCODING": "utf-8",  # maps the PYTHONIOENCODING dictionary entry
    }  # closes the multiline block

    result = run_command(  # runs the run_command() call
        [str(python), str(driver), str(root), str(output), *ecosystems],  # runs the str() call
        log=log,  # copies the log value into log
        cancel=cancel,  # copies the cancel value into cancel
        timeout=config.SCAN_TIMEOUT_SECONDS,  # copies the config.SCAN_TIMEOUT_SECONDS value into timeout
        visible=False,  # assigns the False literal to visible
        env_overrides=env,  # copies the env value into env_overrides
    )  # closes the multiline block
    status = _scanner_status(  # runs the _scanner_status() call
        "guarddog",  # supplies the literal text
        result,  # evaluates the result expression
        output,  # evaluates the output expression
        f"guarddog local scan on {root.name} ({', '.join(ecosystems)})",  # waits for the thread
        accept_nonzero=True,  # assigns the True literal to accept_nonzero
    )  # closes the multiline block
    return output, status  # returns the output to the caller


# --------------------------------------------------------------------------
# Hardening wrappers (Nuclei, Kubescape, Scorecard, OSS-Fuzz)
# --------------------------------------------------------------------------


def ensure_nuclei(log: LogFn, cancel: Cancel) -> Path:  # defines the ensure_nuclei() function
    """Return the pinned Nuclei binary, downloading it on first use."""  # keeps the docstring text
    return ensure_tool("nuclei", log, cancel)  # returns the ensure_tool to the caller


def _nuclei_targets(root: Path, ref: RepoRef | None = None) -> list[str]:  # defines the _nuclei_targets() function
    """Candidate live web endpoints that Nuclei should probe.

    (a) the ``homepage`` field of the repo's package.json when it is an
    http(s) URL, and (b) the conventional GitHub Pages site when the repo
    slug is known. Both are optional: with no candidate Nuclei is skipped.
    """  # keeps the docstring text
    targets: list[str] = []  # evaluates the targets expression
    package_json = root / "package.json"  # copies the root value into package_json
    if package_json.exists():  # evaluates the branch condition
        try:  # watches for errors in the block
            manifest = json.loads(  # parses the text into JSON data
                package_json.read_text(encoding="utf-8", errors="replace")  # creates the path object
            )  # closes the multiline block
            homepage = str(manifest.get("homepage") or "") if isinstance(manifest, dict) else ""  # fetches the value
        except (OSError, ValueError):  # handles the raised error
            homepage = ""  # covers the remaining branch
        parsed = urllib.parse.urlsplit(homepage)  # runs the urlsplit() call
        if parsed.scheme in {"http", "https"} and parsed.netloc:  # only live-looking URLs  # evaluates the branch condition
            targets.append(homepage.strip())  # adds an item to the list
    if ref is not None:  # evaluates the branch condition
        targets.append(f"https://{ref.owner}.github.io/{ref.repo}/")  # Pages convention  # adds an item to the list

    unique: list[str] = []  # evaluates the unique expression
    for target in targets:  # loops over the collection
        candidate = target.rstrip("/")  # trims the trailing slash
        if candidate and candidate not in unique:  # evaluates the branch condition
            unique.append(candidate)  # adds an item to the list
    return unique  # returns the unique to the caller


def run_nuclei(  # defines the run_nuclei() function
    root: Path,  # evaluates the root expression
    artifacts: Path,  # evaluates the artifacts expression
    *,  # spreads the collected values
    log: LogFn,  # evaluates the log expression
    cancel: Cancel,  # evaluates the cancel expression
    targets: list[str],  # evaluates the targets expression
) -> tuple[Path | None, dict[str, Any]]:  # closes the multiline block
    """Probe the repo's live web endpoints with Nuclei's DAST templates."""  # keeps the docstring text
    if not targets:  # evaluates the branch condition
        return None, {  # returns the value to the caller
            "status": "skipped",  # maps the status dictionary entry
            "duration_seconds": 0,  # maps the duration_seconds dictionary entry
            "details": [  # maps the details dictionary entry
                "No web endpoint detected: no package.json homepage and no "  # supplies the literal text
                "GitHub Pages candidate."  # supplies the literal text
            ],  # closes the multiline block
        }  # closes the multiline block

    executable = ensure_nuclei(log, cancel)  # runs the ensure_nuclei() call
    targets_file = artifacts / "nuclei-targets.txt"  # copies the artifacts value into targets_file
    targets_file.write_text("\n".join(targets) + "\n", encoding="utf-8")  # writes the text file
    output = artifacts / "nuclei.jsonl"  # copies the artifacts value into output

    result = run_command(  # runs the run_command() call
        [  # executes the statement
            str(executable),  # runs the str() call
            "-l",  # supplies the literal text
            str(targets_file),  # runs the str() call
            "-j",  # supplies the literal text
            "-silent",  # supplies the literal text
            "-no-color",  # supplies the literal text
            "-rl",  # supplies the literal text
            "40",  # supplies the literal text
            "-c",  # supplies the literal text
            "15",  # supplies the literal text
            "-timeout",  # supplies the literal text
            "10",  # supplies the literal text
            "-o",  # supplies the literal text
            str(output),  # runs the str() call
        ],  # closes the multiline block
        log=log,  # copies the log value into log
        cancel=cancel,  # copies the cancel value into cancel
        timeout=config.SCAN_TIMEOUT_SECONDS,  # copies the config.SCAN_TIMEOUT_SECONDS value into timeout
        visible=False,  # assigns the False literal to visible
    )  # closes the multiline block
    status = _scanner_status(  # runs the _scanner_status() call
        "nuclei",  # supplies the literal text
        result,  # evaluates the result expression
        output,  # evaluates the output expression
        f"nuclei -j against {len(targets)} endpoint(s): {', '.join(targets)}",  # supplies the literal text
        allow_empty=True,  # a clean run may legitimately produce no lines  # assigns the True literal to allow_empty
        accept_nonzero=True,  # assigns the True literal to accept_nonzero
    )  # closes the multiline block
    return output, status  # returns the output to the caller


def run_kubescape(  # defines the run_kubescape() function
    root: Path, artifacts: Path, *, log: LogFn, cancel: Cancel  # evaluates the root expression
) -> tuple[Path, dict[str, Any]]:  # closes the multiline block
    """Scan Kubernetes/IaC definitions against the NSA + MITRE frameworks.

    Kubescape exits non-zero whenever the compliance score is below 100, so
    a readable report - not the exit code - is the success signal. The first
    run also downloads its control definitions from the internet.
    """
    executable = ensure_tool("kubescape", log, cancel)  # runs the ensure_tool() call
    output = artifacts / "kubescape.json"  # copies the artifacts value into output

    result = run_command(  # runs the run_command() call
        [  # executes the statement
            str(executable),  # runs the str() call
            "scan",  # supplies the literal text
            str(root),  # runs the str() call
            "--format",  # supplies the literal text
            "json",  # supplies the literal text
            "--output",  # supplies the literal text
            str(output),  # runs the str() call
        ],  # closes the multiline block
        log=log,  # copies the log value into log
        cancel=cancel,  # copies the cancel value into cancel
        timeout=config.SCAN_TIMEOUT_SECONDS,  # copies the config.SCAN_TIMEOUT_SECONDS value into timeout
        visible=False,  # assigns the False literal to visible
        env_overrides={  # assigns the computed value to env_overrides
            "KUBESCAPE_SKIP_UPDATE_CHECK": "true",  # maps the KUBESCAPE_SKIP_UPDATE_CHE dictionary entry
            "PYTHONUTF8": "1",  # maps the PYTHONUTF8 dictionary entry
            "PYTHONIOENCODING": "utf-8",  # maps the PYTHONIOENCODING dictionary entry
        },  # closes the multiline block
    )  # closes the multiline block
    status = _scanner_status(  # runs the _scanner_status() call
        "kubescape",  # supplies the literal text
        result,  # evaluates the result expression
        output,  # evaluates the output expression
        f"kubescape scan on {root.name}",  # supplies the literal text
        accept_nonzero=True,  # nonzero exit means the compliance score is below 100  # assigns the True literal to accept_nonzero
    )  # closes the multiline block
    return output, status  # returns the output to the caller


def run_scorecard(  # defines the run_scorecard() function
    slug: str, artifacts: Path, *, log: LogFn, cancel: Cancel  # evaluates the slug expression
) -> tuple[Path | None, dict[str, Any]]:  # closes the multiline block
    """Fetch the project's published OpenSSF Scorecard result (pure REST).

    Only public GitHub projects with a published scorecard.dev snapshot have
    data; a 404 means "skipped", other network problems mean "error", and
    neither is ever fatal for the scan.
    """
    output = artifacts / "scorecard.json"  # copies the artifacts value into output
    started = time.monotonic()  # runs the monotonic() call
    try:  # watches for errors in the block
        download(  # runs the download() call
            config.SCORECARD_API.format(slug),  # evaluates the config.SCORECARD_API.format expression
            output,  # evaluates the output expression
            log=log,  # copies the log value into log
            cancel=cancel,  # copies the cancel value into cancel
            what="OpenSSF Scorecard data",  # sets the what text
        )  # closes the multiline block
    except ScanCancelled:  # handles the raised error
        raise  # evaluates the raise expression
    except ScanError as exc:  # handles the raised error
        if "404" in str(exc):  # evaluates the branch condition
            return None, {  # no published snapshot for this project yet  # returns the value to the caller
                "status": "skipped",  # maps the status dictionary entry
                "duration_seconds": 0,  # maps the duration_seconds dictionary entry
                "details": ["No published Scorecard result for this repository."],  # maps the details dictionary entry
            }  # closes the multiline block
        return None, {  # returns the value to the caller
            "status": "error",  # maps the status dictionary entry
            "duration_seconds": round(time.monotonic() - started, 1),  # maps the duration_seconds dictionary entry
            "details": [str(exc)],  # maps the details dictionary entry
        }  # closes the multiline block
    return output, {  # returns the value to the caller
        "status": "ok",  # maps the status dictionary entry
        "duration_seconds": round(time.monotonic() - started, 1),  # maps the duration_seconds dictionary entry
        "details": [f"Scorecard API returned data for {slug}."],  # maps the details dictionary entry
    }  # closes the multiline block


def _ossfuzz_field(lines_text: str) -> dict[str, Any]:  # defines the _ossfuzz_field() function
    """Light YAML-ish reader for an oss-fuzz ``project.yaml``.

    Only ``key: value`` scalars and ``- item`` list members are read; values
    such as ``fuzzing_engines: [libfuzzer]`` are split on commas. Anything
    more exotic is ignored - no YAML dependency is wanted here.
    """
    fields: dict[str, Any] = {}  # evaluates the fields expression
    current: str | None = None  # evaluates the current expression
    for line in lines_text.splitlines():  # loops over the collection
        scalar = re.match(r"^(\w+):\s*(.+)$", line)  # runs the match() call
        if scalar:  # evaluates the branch condition
            current = scalar.group(1)  # copies the scalar.group value into current
            fields[current] = scalar.group(2).strip()  # fetches the value
            continue  # skips to the next loop iteration
        member = line.strip()  # trims the whitespace
        if current and member.startswith("- ") and member[2:].strip():  # a list member  # evaluates the branch condition
            entries = fields.setdefault(current, [])  # fetches the value
            if isinstance(entries, list):  # evaluates the branch condition
                entries.append(member[2:].strip())  # adds an item to the list
    return fields  # returns the fields to the caller


def _ossfuzz_list(value: Any) -> list[str]:  # defines the _ossfuzz_list() function
    """Read a list field that may be ``[a, b]`` on one line or dash items."""
    if isinstance(value, str) and value.strip():  # inline ``[libfuzzer]`` style  # evaluates the branch condition
        raw = value.strip().lstrip("[").rstrip("]")  # trims the whitespace
        return [part.strip() for part in raw.split(",") if part.strip()]  # returns the built list
    if isinstance(value, list):  # evaluates the branch condition
        return [str(item) for item in value if str(item).strip()]  # returns the built list
    return []  # returns the empty list


def run_ossfuzz(  # defines the run_ossfuzz() function
    slug: str, artifacts: Path, *, log: LogFn, cancel: Cancel  # evaluates the slug expression
) -> tuple[Path | None, dict[str, Any]]:  # closes the multiline block
    """Report OSS-Fuzz coverage from the public google/oss-fuzz registry.

    The issues dashboard has no public API, so the reliable public signal is
    whether ``projects/<slug>/project.yaml`` exists: if it does the project is
    continuously fuzzed, otherwise it is not. Either way a small synthetic
    ``ossfuzz.json`` document is written and the check never fails the scan.
    """
    started = time.monotonic()  # runs the monotonic() call
    scratch = artifacts / "ossfuzz-project.yaml"  # copies the artifacts value into scratch
    output = artifacts / "ossfuzz.json"  # copies the artifacts value into output
    try:  # watches for errors in the block
        try:  # watches for errors in the block
            download(  # runs the download() call
                config.OSSFUZZ_PROJECT_URL.format(slug),  # evaluates the config.OSSFUZZ_PROJECT_URL.format expression
                scratch,  # evaluates the scratch expression
                log=log,  # copies the log value into log
                cancel=cancel,  # copies the cancel value into cancel
                what="OSS-Fuzz project entry",  # sets the what text
            )  # closes the multiline block
            fields = _ossfuzz_field(scratch.read_text(encoding="utf-8", errors="replace"))  # fetches the value
            engines = _ossfuzz_list(fields.get("fuzzing_engines"))  # runs the _ossfuzz_list() call
            sanitizers = _ossfuzz_list(fields.get("sanitizers"))  # runs the _ossfuzz_list() call
            payload = {  # builds the dict
                "fuzzed": True,  # the project.yaml exists, so it is fuzzed  # maps the fuzzed dictionary entry
                "project": slug,  # maps the project dictionary entry
                "engines": engines,  # maps the engines dictionary entry
                "sanitizers": sanitizers,  # maps the sanitizers dictionary entry
                "note": f"{slug} is registered in google/oss-fuzz and is continuously fuzzed.",  # maps the note dictionary entry
            }  # closes the multiline block
            detail = f"{slug} is fuzzed by OSS-Fuzz (engines: {', '.join(engines) or 'unknown'})."
        except ScanCancelled:  # handles the raised error
            raise  # evaluates the raise expression
        except ScanError:  # a 404 simply means the project is not on OSS-Fuzz  # handles the raised error
            payload = {  # builds the dict
                "fuzzed": False,  # maps the fuzzed dictionary entry
                "note": f"{slug} is not registered in google/oss-fuzz",  # maps the note dictionary entry
            }  # closes the multiline block
            detail = f"{slug} is not fuzzed by OSS-Fuzz."  # sets the detail text

        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")  # writes the text file
        return output, {  # returns the value to the caller
            "status": "ok",  # maps the status dictionary entry
            "duration_seconds": round(time.monotonic() - started, 1),  # maps the duration_seconds dictionary entry
            "details": [detail],  # maps the details dictionary entry
        }  # closes the multiline block
    except ScanCancelled:  # handles the raised error
        raise  # evaluates the raise expression
    except Exception as exc:  # noqa: BLE001 - coverage data must never fail a scan  # handles the raised error
        return None, {  # returns the value to the caller
            "status": "error",  # maps the status dictionary entry
            "duration_seconds": round(time.monotonic() - started, 1),  # maps the duration_seconds dictionary entry
            "details": [f"Could not fetch OSS-Fuzz data: {exc}"],  # maps the details dictionary entry
        }  # closes the multiline block
    finally:  # runs whether or not the block errored
        scratch.unlink(missing_ok=True)  # deletes the file
        scratch.with_suffix(scratch.suffix + ".part").unlink(missing_ok=True)  # deletes the partial temp


# --------------------------------------------------------------------------
# cdxgen (CycloneDX SBOM generator, run through Node.js)
# --------------------------------------------------------------------------


def run_cdxgen(  # defines the run_cdxgen() function
    root: Path, artifacts: Path, *, log: LogFn, cancel: Cancel
) -> tuple[Path | None, dict[str, Any]]:
    """Generate a CycloneDX SBOM for the tree with cdxgen (no scoring).

    cdxgen is Node-based, so the scan needs Node.js 18+ on the PATH; without
    it the scanner reports itself skipped, never a failure. The runner writes
    the raw CycloneDX document and the catalogue becomes the report's SBOM
    payload (the Print SBOM / Export SBOM buttons read it).
    """
    started = time.monotonic()  # runs the monotonic() call
    output = artifacts / "cdxgen-sbom.json"  # the CycloneDX document
    if not shutil.which("node") or not shutil.which("npx"):  # evaluates the branch condition
        return None, {  # returns the honest skip
            "status": "skipped",
            "duration_seconds": 0,
            "details": ["Node.js 18+ (with npx) is required for cdxgen; install Node and re-select it."],
        }  # closes the skip block

    result = run_command(  # runs the run_command() call
        [  # executes the statement
            "npx",  # the Node package runner
            "-y",  # auto-installs the pinned package once
            config.CDXGEN_NPX_PACKAGE,  # the pinned cdxgen package
            "--spec-version",  # supplies the literal text
            config.CDXGEN_SPEC_VERSION,  # the CycloneDX spec the report expects
            "-o",  # supplies the literal text
            str(output),  # the output document
            str(root),  # scans the checked-out tree
        ],  # closes the command list
        log=log,  # copies the log value into log
        cancel=cancel,  # copies the cancel value into cancel
        timeout=config.SCAN_TIMEOUT_SECONDS,  # assigns the computed value to timeout
        visible=False,  # assigns the False literal to visible
        env_overrides={"CDXGEN_DEBUG_MODE": ""},  # keeps the tool quiet but standard
    )  # closes the multiline block
    status = _scanner_status("cdxgen", result, output, "cdxgen SBOM generation")  # the shared status shape
    return output, status  # returns the output to the caller


# --------------------------------------------------------------------------
# FOSSology licence compliance (REST v1 against a user-provided server)
# --------------------------------------------------------------------------


def fossology_credentials() -> tuple[str, str] | None:  # defines the fossology_credentials() function
    """(base URL, bearer token) from the environment, or None unconfigured."""
    base = os.environ.get(config.FOSSOLOGY_SERVER_ENV) or ""  # fetches the env value
    token = ""  # assigns the token text
    for name in config.FOSSOLOGY_TOKEN_ENVS:  # loops over the env names
        token = os.environ.get(name) or token  # fetches the first set value
    if not base.strip() or not token.strip():  # evaluates the branch condition
        return None  # nothing configured: the caller reports a clean skip
    return base.strip().rstrip("/"), token.strip()  # returns the pair to the caller


def _fossology_http(  # defines the _fossology_http() function
    method: str,  # evaluates the method expression
    url: str,  # evaluates the url expression
    token: str,  # evaluates the token expression
    *,  # spreads the collected values
    data: bytes = b"",  # evaluates the data expression
    content_type: str = "",  # evaluates the content_type expression
    cancel: Cancel,  # evaluates the cancel expression
    timeout: int = 30,  # evaluates the timeout expression
    what: str = "FOSSology call",  # evaluates the what expression
) -> tuple[int, dict[str, str], bytes]:  # closes the multiline block
    """One REST v1 call; HTTP failures become friendly ScanErrors."""
    if cancel.is_set():  # evaluates the branch condition
        raise ScanCancelled("Scan cancelled.")  # raises the ScanCancelled error
    headers = {  # assigns the headers dict
        "User-Agent": config.USER_AGENT,  # identifies the launcher politely
        "Authorization": f"Bearer {token}",  # the FOSSology API token
    }  # closes the headers block
    if content_type:  # evaluates the branch condition
        headers["Content-Type"] = content_type  # sets the content_type header
    try:  # watches for errors in the block
        with urllib.request.urlopen(  # runs the urlopen() call
            urllib.request.Request(url, data=data or None, headers=headers, method=method),  # the request object
            timeout=timeout,  # the request timeout
        ) as response:  # closes the reply when done
            body = response.read()  # reads the body bytes
            head = {key: value for key, value in response.headers.items()}  # copies the headers
            return response.status, head, body  # returns the triple to the caller
    except urllib.error.HTTPError as exc:  # handles the HTTPError branch
        detail = exc.read(400).decode("utf-8", errors="replace")  # keeps a short server message
        raise ScanError(f"{what}: HTTP {exc.code}: {detail.strip()}") from exc  # raises the friendly error
    except (urllib.error.URLError, TimeoutError, OSError) as exc:  # handles the network branch
        raise ScanError(f"{what}: could not reach the FOSSology server ({exc})") from exc  # raises the friendly error
    finally:  # runs whether or not the block errored
        if cancel.is_set():  # evaluates the branch condition
            raise ScanCancelled("Scan cancelled.")  # raises the ScanCancelled error


def _fossology_id(location: str, body: bytes, keys: tuple[str, ...]) -> int | None:  # defines the _fossology_id() function
    """Pull a numeric id out of a Location header or a JSON reply."""
    if location:  # evaluates the branch condition
        digits = re.search(r"(\d+)\s*$", location)  # the trailing number of the path
        if digits:  # evaluates the branch condition
            return int(digits.group(1))  # returns the extracted id
    try:  # watches for errors in the block
        payload = json.loads(body.decode("utf-8", errors="replace"))  # reads the reply JSON
    except (json.JSONDecodeError, ValueError):  # handles the read error
        return None  # covers the remaining branch
    if isinstance(payload, dict):  # evaluates the branch condition
        for key in keys:  # loops over the plausible keys
            value = payload.get(key)  # fetches the value
            if isinstance(value, int):  # evaluates the branch condition
                return value  # returns the extracted id
    return None  # covers the remaining branch


def _zip_tree(root: Path, archive: Path, file_paths: list[Path], cancel: Cancel) -> None:  # defines the _zip_tree() function
    """Zip the checked-out tree for the FOSSology upload, once, shared walk."""
    if file_paths:  # the shared pre-scan walk already knows every file
        paths = list(file_paths)  # materialises the shared list
    else:  # covers the remaining branch
        skip = config.SKIP_DIRS  # copies the config.SKIP_DIRS value into skip
        paths = [  # walks only when the caller has no shared walk
            path for path in root.rglob("*")
            if path.is_file() and not any(part in skip for part in path.relative_to(root).parts)  # the skip filter
        ]  # closes the paths build
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:  # writes the archive
        for path in paths:  # loops over the files
            if cancel.is_set():  # evaluates the branch condition
                raise ScanCancelled("Scan cancelled.")  # raises the ScanCancelled error
            try:  # watches for unreadable files
                bundle.write(path, path.relative_to(root).as_posix())  # adds the file entry
            except OSError:  # covers the remaining branch
                continue  # a vanished temp file is not worth a scan failure


def _fossology_upload(base: str, token: str, archive: Path, log: LogFn, cancel: Cancel) -> int:  # defines the _fossology_upload() function
    """Upload the source archive as a new session upload; returns its id."""
    size = archive.stat().st_size  # reads the archive size
    if size > config.FOSSOLOGY_MAX_ARCHIVE_BYTES:  # evaluates the branch condition
        limit = config.FOSSOLOGY_MAX_ARCHIVE_BYTES // (1024 * 1024)  # converts the limit to MB
        raise ScanError(  # raises the friendly error
            f"The zipped source tree is {size // (1024 * 1024)} MB, above the "
            f"{limit} MB FOSSology upload cap."
        )  # closes the message
    boundary = f"----ScanityCheck{time.time_ns():x}"  # the multipart fence
    name = archive.name  # the archive file name
    body = (  # builds the multipart body
        f"--{boundary}\r\n"  # opens the first part
        f"Content-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"  # names the part
        "Content-Type: application/octet-stream\r\n\r\n"  # closes this part's headers
    )  # closes the header text
    payload = body.encode("utf-8") + archive.read_bytes() + f"\r\n--{boundary}--\r\n".encode("utf-8")  # joins the parts
    status, headers, body_bytes = _fossology_http(  # runs the upload call
        "POST",  # the upload verb
        f"{base}/api/v1/uploads?folderId={config.FOSSOLOGY_FOLDER_ID}",  # the uploads endpoint
        token,  # evaluates the token expression
        data=payload,  # the multipart body
        content_type=f"multipart/form-data; boundary={boundary}",  # the fence type
        cancel=cancel,  # copies the cancel value into cancel
        timeout=60 * 20,  # the upload timeout (large archives)
        what="FOSSology upload",  # the friendly label
    )  # closes the call
    if status != 201:  # evaluates the branch condition
        raise ScanError(f"FOSSology upload: unexpected status {status}.")  # raises the friendly error
    upload_id = _fossology_id(headers.get("location") or "", body_bytes, ("uploadId", "upload_id", "id"))  # the upload id
    if upload_id is None:  # evaluates the branch condition
        raise ScanError("FOSSology upload: the reply carried no upload id.")  # raises the friendly error
    log(f"FOSSology accepted the {size // (1024 * 1024)} MB archive as upload {upload_id}.")  # logs the step
    return upload_id  # returns the id to the caller


def _fossology_schedule(base: str, token: str, upload_id: int, cancel: Cancel) -> int:  # defines the _fossology_schedule() function
    """Schedule the Nomos/Ojo agents; falls back to the per-upload endpoint."""
    analyse = json.dumps({"analysis": {"upload": upload_id, "agents": config.FOSSOLOGY_AGENTS}}).encode("utf-8")  # the job body
    try:  # the modern documented endpoint first
        status, headers, body_bytes = _fossology_http(  # runs the schedule call
            "POST",  # the schedule verb
            f"{base}/api/v1/jobs/analysis",  # the analysis endpoint
            token,  # evaluates the token expression
            data=analyse,  # the JSON body
            content_type="application/json",  # the content type
            cancel=cancel,  # copies the cancel value into cancel
            what="FOSSology agent schedule",  # the friendly label
        )  # closes the call
        if status != 201:  # evaluates the branch condition
            raise ScanError  # raises the ScanError error
    except ScanError:  # covers the remaining branch
        status, headers, body_bytes = _fossology_http(  # runs the fallback call
            "POST",  # the fallback verb
            f"{base}/api/v1/uploads/{upload_id}/jobs/scan",  # the per-upload endpoint
            token,  # evaluates the token expression
            data=json.dumps({"agents": config.FOSSOLOGY_AGENTS}).encode("utf-8"),  # the agents body
            content_type="application/json",  # the content type
            cancel=cancel,  # copies the cancel value into cancel
            what="FOSSology agent schedule",  # the friendly label
        )  # closes the call
    job_id = _fossology_id(headers.get("location") or "", body_bytes, ("jobId", "job_id", "id"))  # the job id
    if job_id is None:  # evaluates the branch condition
        raise ScanError("FOSSology agent schedule: the reply carried no job id.")  # raises the friendly error
    return job_id  # returns the id to the caller


def _fossology_wait(base: str, token: str, job_id: int, log: LogFn, cancel: Cancel) -> None:  # defines the _fossology_wait() function
    """Poll the agent job until it completes, fails, or the budget expires."""
    deadline = time.monotonic() + config.FOSSOLOGY_TIMEOUT_SECONDS  # the time budget
    while True:  # loops the poll cadence
        time.sleep(config.FOSSOLOGY_POLL_SECONDS)  # waits a polite beat
        status, _headers, job_body = _fossology_http(  # runs the poll call
            "GET",  # the poll verb
            f"{base}/api/v1/jobs/{job_id}",  # the job endpoint
            token,  # evaluates the token expression
            cancel=cancel,  # copies the cancel value into cancel
            what="FOSSology job status",  # the friendly label
        )  # closes the call
        try:  # watches for unreadable replies
            state = str(json.loads(job_body.decode("utf-8", errors="replace")).get("status") or "").lower()  # the job state
        except (json.JSONDecodeError, ValueError, AttributeError):  # handles the read error
            continue  # one unreadable poll is not worth a scan failure
        if state in {"completed", "complete", "finished"}:  # evaluates the branch condition
            return  # the agents are done
        if state in {"failure", "failed", "cancelled"}:  # evaluates the branch condition
            raise ScanError(f"FOSSology agents failed on the server (status {state}).")  # raises the friendly error
        if time.monotonic() > deadline:  # evaluates the branch condition
            raise ScanError(  # raises the ScanError error
                f"FOSSology agents did not finish within {config.FOSSOLOGY_TIMEOUT_SECONDS // 60} minutes."
            )  # closes the message
        log(f"FOSSology job {job_id} still {state or 'unqueued'}...")  # keeps the user posted


def _fossology_license_name(item: Any) -> str:  # defines the _fossology_license_name() function
    """The SPDX name inside one findings element, whatever shape it arrives."""
    if isinstance(item, str):  # a bare licence string
        return item.strip()  # returns the cleaned name
    if not isinstance(item, dict):  # evaluates the branch condition
        return ""  # covers the remaining branch
    licence = item.get("license") or item.get("licenseName") or item.get("spdx")  # the usual shapes
    if isinstance(licence, dict):  # evaluates the branch condition
        licence = licence.get("name") or licence.get("spdx") or ""  # the nested shapes
    return str(licence or "").strip()  # returns the cleaned name


def _fossology_collect(payload: dict[str, Any]) -> dict[str, list[str]]:  # defines the _fossology_collect() function
    """path -> first licence name, out of any plausible agent-summary shape."""
    merged: dict[str, list[str]] = {}  # evaluates the merged expression
    scanners = payload.get("scanner") if isinstance(payload, dict) else None  # the agent block
    blocks = scanners if isinstance(scanners, dict) else {  # tolerate a flat document
        "agents": payload  # the unshaped document
    }  # closes the blocks build
    for info in blocks.values():  # loops over the agent blocks
        if not isinstance(info, dict):  # evaluates the branch condition
            continue  # covers the remaining branch
        findings = info.get("findings")  # fetches the value
        if not isinstance(findings, dict):  # evaluates the branch condition
            continue  # covers the remaining branch
        for path, items in findings.items():  # loops over the findings
            names: list[str] = []  # dedupes the agent agreement per file
            for item in items or []:  # loops over the elements
                name = _fossology_license_name(item)  # runs the _fossology_license_name() call
                if name and name not in names:  # evaluates the branch condition
                    names.append(name)  # adds the name to the list
            if not names:  # evaluates the branch condition
                continue  # covers the remaining branch
            entry = merged.setdefault(str(path), [])  # the file's licence list
            for name in names:  # loops over the names
                if name not in entry:  # evaluates the branch condition
                    entry.append(name)  # unifies the agent reporting
    return merged  # returns the licence map


def run_fossology(  # defines the run_fossology() function
    root: Path,  # the checked-out tree
    artifacts: Path,  # the per-scan artefacts folder
    *,  # spreads the collected values
    log: LogFn,  # evaluates the log expression
    cancel: Cancel,  # evaluates the cancel expression
    file_paths: list[Path] | None = None,  # the shared pre-scan walk
) -> tuple[Path | None, dict[str, Any]]:  # closes the multiline block
    """Scan the tree's licences through a FOSSology server (Nomos/Ojo).

    The runner posts one zip of the tree, schedules the licence agents, waits
    for the job and normalises the agent summaries into ``fossology.json``;
    making findings is the parser's job (:func:`scoring.parse_fossology_report`),
    so the conversion stays testable without a server. Without a configured
    server the scanner reports itself skipped, never a failure.
    """
    started = time.monotonic()  # runs the monotonic() call
    output = artifacts / "fossology.json"  # the normalised report
    archive = artifacts / "fossology-src.zip"  # the uploaded archive
    credentials = fossology_credentials()  # runs the fossology_credentials() call
    if not credentials:  # evaluates the branch condition
        return None, {  # returns the honest skip
            "status": "skipped",
            "duration_seconds": 0,
            "details": ["No FOSSology server configured: set FOSSOLOGY_SERVER and "
                        "FOSSOLOGY_TOKEN to enable licence scanning."],
        }  # closes the skip block
    base, token = credentials  # unpacks the pair
    try:  # watches for errors in the block
        log("FOSSology: zipping the source tree for upload...")  # keeps the user posted
        _zip_tree(root, archive, file_paths or [], cancel)  # runs the _zip_tree() call
        upload_id = _fossology_upload(base, token, archive, log, cancel)  # runs the upload
        job_id = _fossology_schedule(base, token, upload_id, cancel)  # schedules the agents
        log(f"FOSSology: licence agents running (job {job_id})...")  # keeps the user posted
        _fossology_wait(base, token, job_id, log, cancel)  # waits for the job
        _status_pair, _headers, lic_body = _fossology_http(  # runs the licence fetch
            "GET",  # the fetch verb
            f"{base}/api/v1/uploads/{upload_id}/licenses",  # the licence endpoint
            token,  # evaluates the token expression
            cancel=cancel,  # copies the cancel value into cancel
            timeout=120,  # the licence fetch timeout
            what="FOSSology licence fetch",  # the friendly label
        )  # closes the call
        try:  # watches for an unreadable summary
            lic_payload = json.loads(lic_body.decode("utf-8", errors="replace"))  # reads the JSON
        except (json.JSONDecodeError, ValueError) as exc:  # handles the read error
            raise ScanError(f"FOSSology licence summary was not valid JSON ({exc}).") from exc  # raises the friendly error
        lic_map = _fossology_collect(lic_payload if isinstance(lic_payload, dict) else {})  # the path->licence map
        mix: dict[str, int] = {}  # licence -> distinct file count
        licences: list[dict[str, Any]] = []  # one row per licence family
        for path, names in sorted(lic_map.items()):  # loops over the findings
            for name in names:  # loops over the licence names
                row = next((item for item in licences if item["name"] == name), None)  # the family row
                if row is None:  # evaluates the branch condition
                    row = {"name": name, "files": [], "agents": []}  # stores the row
                    licences.append(row)  # adds the row to the list
                if len(row["files"]) < 40:  # caps the stored sample
                    row["files"].append(str(path))  # adds the sample path
                mix[name] = mix.get(name, 0) + 1  # counts one more file
        mix = dict(sorted(mix.items(), key=lambda item: -item[1]))  # the busiest licences first
        output.write_text(json.dumps({  # writes the normalised report
            "licenses": licences,  # the licence families with sample paths
            "mix": mix,  # the donut-ready licence mix
            "upload": {"uploadId": upload_id, "jobId": job_id},  # the server-side pointers
        }, indent=2), encoding="utf-8")  # closes the write
        flagged = sum(  # the count of licenses the policy flags
            1 for row in licences
            if scoring.fossology_severity(row["name"]) is not None  # runs the scoring.fossology_severity() call
        )  # closes the count
        return output, {  # returns the ok status
            "status": "ok",
            "duration_seconds": round(time.monotonic() - started, 1),
            "details": [
                f"FOSSology found {len(lic_map)} licensed file(s) across "
                f"{len(mix)} licence(s); {flagged} licence(s) fall under the "
                "configured policy."
            ],  # the human-readable summary
        }  # closes the ok block
    except ScanCancelled:  # handles the cancel branch
        raise  # propagates the cancellation
    except Exception as exc:  # noqa: BLE001 - an optional tool must never fail a scan
        return None, {  # returns the error status
            "status": "error",
            "duration_seconds": round(time.monotonic() - started, 1),
            "details": [f"FOSSology scan could not complete: {exc}"],
        }  # closes the error block
    finally:  # runs whether or not the block errored
        archive.unlink(missing_ok=True)  # drops the uploaded archive


# --------------------------------------------------------------------------
# Website audit (plain-web targets - no source checkout involved)
# --------------------------------------------------------------------------


def _fetch_web_page(url: str, cancel: Cancel, *, timeout: int | None = None) -> dict[str, Any]:
    """Fetch page headers and a small body snippet for the web audit."""
    request = urllib.request.Request(  # runs the Request() call
        url,  # evaluates the url expression
        headers={"User-Agent": config.USER_AGENT},  # identifies the launcher politely
    )  # closes the multiline block
    opened = urllib.request.urlopen(request, timeout=timeout or config.HTTP_TIMEOUT_SECONDS)  # fetches the page
    with opened:  # closes the body when done
        final_url = str(opened.geturl())  # follows the redirect chains
        headers = {key: value for key, value in opened.headers.items()}  # copies the headers
        body = opened.read(262_144).decode("utf-8", errors="replace")  # keeps a 256 KB snippet
    if cancel.is_set():  # respects the stop button between fetches
        raise ScanCancelled("Scan cancelled by user.")  # raises the ScanCancelled error
    parts = urllib.parse.urlsplit(final_url)  # splits the final URL apart
    return {  # returns the built dict
        "final_url": final_url,  # maps the final_url dictionary entry
        "scheme": parts.scheme,  # maps the scheme dictionary entry
        "status": "200",  # urllib raises on error codes, so a reply is a 200
        "headers": headers,  # maps the headers dictionary entry
        "body": body,  # maps the body dictionary entry
    }  # returns the built dict


def _probe_web_dotfile(url: str, name: str, cancel: Cancel, *, timeout: int | None = None) -> dict[str, Any]:
    """Ask for one sensitive path; the reply is judged by the parser."""
    probe = f"{url.rstrip('/')}/{name}"  # joins the URL modulo a trailing slash
    request = urllib.request.Request(  # runs the Request() call
        probe,  # evaluates the probe expression
        headers={"User-Agent": config.USER_AGENT},  # identifies the launcher politely
    )  # closes the multiline block
    try:  # watches for errors in the block
        opened = urllib.request.urlopen(request, timeout=timeout or config.HTTP_TIMEOUT_SECONDS)  # fetches the probe
        with opened:  # closes the body when done
            status = "200"  # urllib raises on error codes, so a reply is a 200
            body = opened.read(65_536).decode("utf-8", errors="replace")  # keeps a small snippet
    except urllib.error.HTTPError as exc:  # dotted files answer 403/404 when absent
        status = str(exc.code)  # keeps the code for the parser
        body = ""  # nothing to inspect on an error reply
    if cancel.is_set():  # respects the stop button between probes
        raise ScanCancelled("Scan cancelled by user.")  # raises the ScanCancelled error
    parts = urllib.parse.urlsplit(url)  # splits the URL apart
    return {  # returns the built dict
        "name": name,  # maps the name dictionary entry
        "path": f"{parts.netloc}/{name}",  # human-readable location label
        "status": status,  # maps the status dictionary entry
        "body": body,  # maps the body dictionary entry
    }  # returns the built dict


def run_web_check(url: str, artifacts: Path, *, log: LogFn, cancel: Cancel) -> tuple[Path, dict[str, Any]]:
    """Fetch the live site and probe a few classic exposed secrets.

    The runner writes a structured ``webcheck.json``; making findings is the
    parser's job (:func:`scoring.parse_webcheck_report`), so the audit logic
    stays testable without a network.
    """
    started = time.monotonic()  # runs the monotonic() call
    output = artifacts / "webcheck.json"  # copies the artifacts value into output
    page = _fetch_web_page(str(url), cancel)  # fetches the live page
    probes = [  # evaluates the probes expression
        _probe_web_dotfile(str(url), ".env", cancel),  # environment secrets
        _probe_web_dotfile(str(url), ".git/config", cancel),  # full source history
    ]  # closes the multiline block
    payload = {"url": url, "page": page, "probes": probes}  # builds the document
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")  # writes the text file
    return output, {  # returns the tuple to the caller
        "status": "ok",  # a fetched page is a completed audit
        "duration_seconds": round(time.monotonic() - started, 1),  # measures the duration
        "details": [f"Fetched {page.get('final_url')} (status {page.get('status')})."],  # adds the detail text
    }  # returns the tuple to the caller


# --------------------------------------------------------------------------
# End-to-end pipeline
# --------------------------------------------------------------------------


def normalize_tools(tools: Iterable[str] | None) -> list[str]:  # defines the normalize_tools() function
    """Validate a scanner selection and return it in display order."""  # keeps the docstring text
    if tools is None:  # evaluates the branch condition
        return list(config.DEFAULT_TOOLS)  # returns the list to the caller

    selected: list[str] = []  # evaluates the selected expression
    for raw in tools:  # loops over the collection
        key = str(raw).strip().lower()  # runs the str() call
        if not key:  # evaluates the branch condition
            continue  # skips to the next loop iteration
        if key not in config.ALL_TOOLS:  # evaluates the branch condition
            raise ScanError(  # raises the ScanError error
                f"Unknown scanner '{raw}'. Choose from: {', '.join(config.ALL_TOOLS)}."  # waits for the thread
            )  # closes the multiline block
        if key not in selected:  # evaluates the branch condition
            selected.append(key)  # adds an item to the list

    if not selected:  # evaluates the branch condition
        raise ScanError("No scanners were selected - pick at least one scanner to run.")  # raises the ScanError error
    return [tool for tool in config.ALL_TOOLS if tool in selected]  # returns the value to the caller


def scan_repository(  # defines the scan_repository() function
    url: str,  # evaluates the url expression
    *,  # spreads the collected values
    log: LogFn,  # evaluates the log expression
    cancel: Cancel,  # evaluates the cancel expression
    keep_artifacts: bool = True,  # evaluates the keep_artifacts expression
    tools: Iterable[str] | None = None,  # evaluates the tools expression
    frameworks: Iterable[str] | None = None,  # evaluates the frameworks expression
    dashboard: Iterable[str] | None = None,  # evaluates the dashboard expression
) -> dict[str, Any]:  # closes the multiline block
    """Download a repo, run the selected scanners, and return a scored report.

    ``frameworks`` names the compliance frameworks whose controls the findings
    should be mapped onto; it never changes the score itself. ``dashboard``
    selects the dashboard metric widgets to build (also score-free).
    """
    started = time.monotonic()  # runs the monotonic() call
    ref = parse_repo_url(url)  # runs the parse_repo_url() call
    selected = normalize_tools(tools)  # runs the normalize_tools() call
    repo_slug = ref.full_name  # Scorecard/OSS-Fuzz ask the records by owner/repo  # copies the ref.full_name value into repo_slug
    log(f"Target: {ref.full_name}")  # runs the log() call
    log(  # runs the log() call
        "Scanners: "  # maps the Scanners:  dictionary entry
        + ", ".join(config.TOOL_LABELS.get(tool, tool) for tool in selected)  # waits for the thread
    )  # closes the multiline block

    stamp = time.strftime("%Y%m%d-%H%M%S")  # formats the timestamp
    workdir = config.WORK_DIR / f"{ref.owner}-{ref.repo}-{stamp}"  # copies the config.WORK_DIR value into workdir
    artifacts = workdir / "artifacts"  # copies the workdir value into artifacts
    artifacts.mkdir(parents=True, exist_ok=True)  # creates the folder

    warnings: list[str] = []  # evaluates the warnings expression
    findings: list[scoring.Finding] = []  # evaluates the findings expression
    inventory: dict[str, Any] | None = None  # evaluates the inventory expression
    inventory_holder: dict[str, Any] = {}  # filled by the Syft pool task  # evaluates the inventory_holder expression
    cdxgen_holder: dict[str, Any] = {}  # filled by the cdxgen pool task  # evaluates the cdxgen_holder expression
    syft_sbom: Path | None = None  # evaluates the syft_sbom expression
    scanner_status: dict[str, dict[str, Any]] = {  # evaluates the scanner_status expression
        tool: {  # evaluates the tool expression
            "status": "skipped",  # maps the status dictionary entry
            "duration_seconds": 0,  # maps the duration_seconds dictionary entry
            "details": ["Not selected for this scan."],  # maps the details dictionary entry
        }  # closes the multiline block
        for tool in config.ALL_TOOLS  # loops over the collection
        if tool not in selected  # evaluates the branch condition
    }  # closes the multiline block

    # Pool tasks share these structures; the app drains log() from a
    # thread-safe queue, so only the mutable scan state needs a lock.
    state_lock = threading.Lock()  # evaluates the threading.Lock() call
    shared: dict[str, Any] = {"syft_sbom": None}  # the Syft -> Grype/OSV hand-off  # assigns the computed value

    def ingest(name: str, output: Path, status: dict[str, Any], parser) -> None:  # defines the ingest() function
        """Record a scanner's status and parse its report when it succeeded."""
        with state_lock:  # the pool tasks touch the shared dicts/lists
            scanner_status[name] = status  # copies the status value into scanner_status[name]
            ok = status["status"] == "ok"  # fetches the value
        if not ok:  # evaluates the branch condition
            return  # evaluates the return expression
        label = config.TOOL_LABELS.get(name, name.title())  # fetches the value
        try:  # watches for errors in the block
            parsed = list(parser(output))  # builds the list collection
        except Exception as exc:  # noqa: BLE001 - one bad report must not kill the scan  # handles the raised error
            with state_lock:  # the pool tasks touch the shared dicts/lists
                status["status"] = "error"  # sets the status["status"] text
                status["details"].append(f"Could not parse {label} output: {exc}")  # adds an item to the list
                warnings.append(f"{label} output could not be parsed: {exc}")  # adds an item to the list
            return  # evaluates the return expression
        with state_lock:  # the pool tasks touch the shared dicts/lists
            findings.extend(parsed)  # adds several items to the list
        log(f"{label} reported {len(parsed)} finding{'s' if len(parsed) != 1 else ''}.")  # runs the log() call

    def run_tool(name: str, label: str, intro: str, runner, parser) -> dict[str, Any] | None:  # defines the run_tool() function
        """Run one scanner; a startup failure becomes a status, not a crash.

        Safe on pool workers: shared state only changes under the lock, the
        cancel callback is checked before the subprocess starts and after
        every stop, and ScanCancelled still propagates to stop everything.
        """
        if cancel.is_set():  # evaluates the branch condition
            raise ScanCancelled("Scan cancelled.")  # raises the ScanCancelled error
        log(intro)  # runs the log() call
        try:  # watches for errors in the block
            output, status = runner(root, artifacts, log=log, cancel=cancel)  # runs the runner() call
        except ScanCancelled:  # handles the raised error
            raise  # evaluates the raise expression
        except Exception as exc:  # noqa: BLE001 - optional tools must not kill the scan  # handles the raised error
            detail = f"Could not start {label}: {exc}"  # sets the detail text
            with state_lock:  # the pool tasks touch the shared dicts/lists
                scanner_status[name] = {  # assigns the computed value to scanner_status[name]
                    "status": "error",  # maps the status dictionary entry
                    "duration_seconds": 0,  # maps the duration_seconds dictionary entry
                    "details": [detail],  # maps the details dictionary entry
                }  # closes the multiline block
                warnings.append(f"{label} could not run: {exc}")  # adds an item to the list
            log(detail)  # runs the log() call
            return scanner_status[name]  # returns the scanner_status to the caller
        ingest(name, output, status, parser)  # runs the ingest() call
        return status  # returns the status to the caller

    try:  # watches for errors in the block
        metadata = fetch_repo_metadata(ref)  # runs the fetch_repo_metadata() call
        if metadata.get("archived"):  # evaluates the branch condition
            warnings.append("The repository is archived, so its dependencies are unlikely to be patched.")  # adds an item to the list
        if metadata.get("private"):  # evaluates the branch condition
            warnings.append("Repository is private; results are only as complete as your token's access.")  # adds an item to the list

        tree_files: list[Path] = []  # one shared walk fills this list  # evaluates the tree_files expression
        root = download_repo(  # runs the download_repo() call
            ref,  # evaluates the ref expression
            workdir,  # evaluates the workdir expression
            log=log,  # copies the log value into log
            cancel=cancel,  # copies the cancel value into cancel
            metadata=metadata,  # copies the metadata value into metadata
            file_paths=tree_files,  # the same walk feeds every consumer below  # copies the file_paths value
        )  # closes the multiline block

        # --- Care and feeding (maintenance statistics) ------------------
        care_raw = fetch_care_and_feeding(ref, log=log)  # runs the fetch_care_and_feeding() call
        try:  # the dashboard module gains the shared walk; tolerate an older signature  # watches for errors in the block
            dash_inputs = dashboards.collect_repo_inputs(root, file_paths=tree_files)  # runs the collect_repo_inputs() call
        except TypeError:  # covers the remaining branch
            dash_inputs = dashboards.collect_repo_inputs(root)  # runs the collect_repo_inputs() call

        languages, language_counts = detect_languages(root, log, file_paths=tree_files)  # runs the detect_languages() call
        if not languages and "codeql" in selected:  # evaluates the branch condition
            warnings.append(  # adds an item to the list
                "No CodeQL-supported language was detected, so CodeQL could not analyse this repo."  # supplies the literal text
            )  # closes the multiline block

        # Compute the Nuclei endpoints once per scan and pass the same list
        # into both the preview log and the runner closure.
        nuclei_targets = _nuclei_targets(root, ref) if "nuclei" in selected else []  # evaluates the nuclei_targets expression
        if "nuclei" in selected:  # evaluates the branch condition
            log(f"Web endpoint candidates for Nuclei: {', '.join(nuclei_targets) or 'none'}")  # runs the log() call

        # Skip IaC-less scans: with no .yml/.yaml/.tf/.hcl/Dockerfile/... in
        # the shared walk, Kubescape and Checkov have nothing to read, so the
        # default all-tools scan does not pay Kubescape's minimum pass.
        if not _has_iac_files(tree_files):  # evaluates the branch condition
            for tool in ("checkov", "kubescape"):  # loops over the collection
                if tool in selected:  # evaluates the branch condition
                    scanner_status[tool] = {  # assigns the computed value to scanner_status[tool]
                        "status": "skipped",  # maps the status dictionary entry
                        "duration_seconds": 0,  # maps the duration_seconds dictionary entry
                        "details": [  # maps the details dictionary entry
                            "No IaC definitions (.yml/.yaml/.tf/.hcl/Dockerfile/Containerfile) "  # supplies the literal text
                            "were found in this repository.",  # supplies the literal text
                        ],  # closes the multiline block
                    }  # closes the multiline block
                    log(f"{config.TOOL_LABELS[tool]} skipped: no IaC definitions in the repository.")  # runs the log() call

        if cancel.is_set():  # evaluates the branch condition
            raise ScanCancelled("Scan cancelled.")  # raises the ScanCancelled error

        # --- CodeQL (the heaviest tool runs before the pooled batch) -----
        if "codeql" in selected:  # evaluates the branch condition
            if cancel.is_set():  # evaluates the branch condition
                raise ScanCancelled("Scan cancelled.")  # raises the ScanCancelled error
            log("Running CodeQL (data-flow security queries)...")  # runs the log() call
            try:  # watches for errors in the block
                sarif_files, codeql_status = run_codeql(  # runs the run_codeql() call
                    root, artifacts, languages, log=log, cancel=cancel  # copies the log value into root, artifacts, languages, log
                )  # closes the multiline block
            except ScanCancelled:  # handles the raised error
                raise  # evaluates the raise expression
            except Exception as exc:  # noqa: BLE001  # handles the raised error
                scanner_status["codeql"] = {  # assigns the computed value to scanner_status["codeql"]
                    "status": "error",  # maps the status dictionary entry
                    "duration_seconds": 0,  # maps the duration_seconds dictionary entry
                    "details": [f"Could not start CodeQL: {exc}"],  # maps the details dictionary entry
                }  # closes the multiline block
                warnings.append(f"CodeQL could not run: {exc}")  # adds an item to the list
            else:  # covers the remaining branch
                scanner_status["codeql"] = codeql_status  # copies the codeql_status value into scanner_status["codeql"]
                for sarif_path in sarif_files:  # loops over the collection
                    language = sarif_path.stem.replace("codeql-", "")  # swaps the text
                    try:  # watches for errors in the block
                        parsed = scoring.parse_codeql_sarif(sarif_path, language, root)  # runs the parse_codeql_sarif() call
                        findings.extend(parsed)  # adds several items to the list
                        log(f"CodeQL reported {len(parsed)} findings for {language}.")  # runs the log() call
                    except Exception as exc:  # noqa: BLE001  # handles the raised error
                        warnings.append(f"Could not parse CodeQL results for {language}: {exc}")  # adds an item to the list
                        codeql_status["status"] = "partial"  # sets the codeql_status["status"] text
                if codeql_status["status"] == "error":  # evaluates the branch condition
                    warnings.append(  # adds an item to the list
                        "CodeQL did not complete, so code-level data-flow coverage is missing."  # supplies the literal text
                    )  # closes the multiline block

        # --- Optional-tool pool ------------------------------------------
        # Everything else selected runs through a bounded worker pool. Semantics
        # are unchanged: one status dict per tool, try/except isolation per
        # tool, the same parsers. Grype and OSV want the Syft SBOM, so those
        # tasks wait on the syft task instead of racing into an empty hand-off
        # (Syft therefore still finishes before both of them).
        def finish_syft() -> None:  # defines the finish_syft() function
            """Inventory the SBOM with Syft; feeds Grype and OSV when it succeeds."""
            try:  # watches for errors in the block
                if cancel.is_set():  # evaluates the branch condition
                    raise ScanCancelled("Scan cancelled.")  # raises the ScanCancelled error
                log("Running Syft (SBOM inventory; its output also feeds Grype)...")  # runs the log() call
                try:  # watches for errors in the block
                    syft_output, syft_status = run_syft(  # runs the run_syft() call
                        root, artifacts, log=log, cancel=cancel  # copies the log value into root, artifacts, log
                    )  # closes the multiline block
                except ScanCancelled:  # handles the raised error
                    raise  # evaluates the raise expression
                except Exception as exc:  # noqa: BLE001  # handles the raised error
                    with state_lock:  # the pool tasks touch the shared dicts/lists
                        scanner_status["syft"] = {  # assigns the computed value to scanner_status["syft"]
                            "status": "error",  # maps the status dictionary entry
                            "duration_seconds": 0,  # maps the duration_seconds dictionary entry
                            "details": [f"Could not start Syft: {exc}"],  # maps the details dictionary entry
                        }  # closes the multiline block
                        warnings.append(f"Syft could not run: {exc}")  # adds an item to the list
                    return  # evaluates the return expression
                with state_lock:  # the pool tasks touch the shared dicts/lists
                    scanner_status["syft"] = syft_status  # copies the syft_status value into scanner_status["syft"]
                    if syft_status["status"] == "ok":  # evaluates the branch condition
                        shared["syft_sbom"] = syft_output  # publishes the SBOM hand-off  # copies the syft_output value
                    else:  # covers the remaining branch
                        warnings.append(  # adds an item to the list
                            "Syft did not complete, so the SBOM inventory is missing and "  # supplies the literal text
                            "Grype scanned the checkout directly."  # supplies the literal text
                        )  # closes the multiline block
                if syft_status["status"] == "ok":  # evaluates the branch condition
                    try:  # watches for errors in the block
                        inventory_local = scoring.parse_syft_inventory(syft_output, root)  # runs the parse_syft_inventory() call
                    except Exception as exc:  # noqa: BLE001  # handles the raised error
                        with state_lock:  # the pool tasks touch the shared dicts/lists
                            syft_status["status"] = "error"  # sets the syft_status["status"] text
                            syft_status["details"].append(f"Could not read the Syft SBOM: {exc}")  # adds an item to the list
                            warnings.append(f"Syft's SBOM could not be read: {exc}")  # adds an item to the list
                            shared["syft_sbom"] = None  # stores the missing hand-off
                        return  # evaluates the return expression
                    with state_lock:  # the pool tasks touch the shared dicts/lists
                        inventory_holder["value"] = inventory_local  # copies the inventory_local value
                        log(  # runs the log() call
                            f"Syft catalogued {inventory_local['components']} components "  # evaluates the f expression
                            f"({inventory_local['unversioned']} without a version)."  # evaluates the f expression
                        )  # closes the multiline block
            finally:  # runs whether or not the block errored
                syft_done.set()  # releases Grype and OSV either way  # runs the set() call

        def finish_grype() -> None:  # defines the finish_grype() function
            sbom = shared["syft_sbom"]  # published by finish_syft before this wakes  # fetches the value
            grype_runner = run_grype  # copies the run_grype value into grype_runner
            if sbom is not None:  # evaluates the branch condition
                grype_runner = lambda r, a, *, log, cancel: run_grype(  # noqa: E731  # runs the run_grype() call
                    r, a, log=log, cancel=cancel, sbom=sbom  # copies the log value into r, a, log
                )  # closes the multiline block
            run_tool(  # runs the run_tool() call
                "grype",  # supplies the literal text
                "Grype",  # supplies the literal text
                "Running Grype (dependency CVEs from the Anchore database; "  # supplies the literal text
                + (  # executes the statement
                    "using Syft's SBOM"  # executes the statement
                    if sbom is not None  # evaluates the branch condition
                    else "first run downloads the database"  # covers the remaining branch
                )  # closes the multiline block
                + ")...",  # executes the statement
                grype_runner,  # evaluates the grype_runner expression
                lambda path: scoring.parse_grype_report(path, root),  # defines the small inline helper
            )  # closes the multiline block

        def finish_osv() -> None:  # defines the finish_osv() function
            sbom = shared["syft_sbom"]  # published by finish_syft before this wakes  # fetches the value
            osv_runner = run_osv  # copies the run_osv value into osv_runner
            if sbom is not None:  # evaluates the branch condition
                osv_runner = lambda r, a, *, log, cancel: run_osv(  # noqa: E731  # runs the run_osv() call
                    r, a, log=log, cancel=cancel, sbom=sbom  # copies the log value into r, a, log
                )  # closes the multiline block
            run_tool(  # runs the run_tool() call
                "osv",  # supplies the literal text
                "OSV-Scanner",  # supplies the literal text
                "Running OSV-Scanner (dependency CVEs from the OSV database)...",  # supplies the literal text
                osv_runner,  # evaluates the osv_runner expression
                lambda path: scoring.parse_osv_report(path, root),  # defines the small inline helper
            )  # closes the multiline block

        def finish_trivy() -> None:  # defines the finish_trivy() function
            status = run_tool(  # runs the run_tool() call
                "trivy",  # supplies the literal text
                "Trivy",  # supplies the literal text
                "Running Trivy (dependency CVEs, secrets, IaC misconfigurations)...",  # supplies the literal text
                run_trivy,  # evaluates the run_trivy expression
                lambda path: scoring.parse_trivy_report(path, root),  # defines the small inline helper
            )  # closes the multiline block
            if status and status["status"] != "ok":  # evaluates the branch condition
                with state_lock:  # the pool tasks touch the shared dicts/lists
                    warnings.append(  # adds an item to the list
                        "Trivy did not complete, so dependency, secret and IaC coverage is incomplete."  # supplies the literal text
                    )  # closes the multiline block

        def finish_gitleaks() -> None:  # defines the finish_gitleaks() function
            run_tool(  # runs the run_tool() call
                "gitleaks",  # supplies the literal text
                "GitLeaks",  # supplies the literal text
                "Running GitLeaks (committed secrets)...",  # supplies the literal text
                run_gitleaks,  # evaluates the run_gitleaks expression
                lambda path: scoring.parse_gitleaks_report(path, root),  # defines the small inline helper
            )  # closes the multiline block

        def finish_trufflehog() -> None:  # defines the finish_trufflehog() function
            run_tool(  # runs the run_tool() call
                "trufflehog",  # supplies the literal text
                "TruffleHog",  # supplies the literal text
                "Running TruffleHog (committed secrets, verification disabled)...",  # supplies the literal text
                run_trufflehog,  # evaluates the run_trufflehog expression
                lambda path: scoring.parse_trufflehog_report(path, root),  # defines the small inline helper
            )  # closes the multiline block

        def finish_semgrep() -> None:  # defines the finish_semgrep() function
            run_tool(  # runs the run_tool() call
                "semgrep",  # supplies the literal text
                "Semgrep CE",  # supplies the literal text
                "Running Semgrep CE (pattern-based code security; first run installs "  # supplies the literal text
                "Semgrep and downloads the community ruleset)...",  # supplies the literal text
                run_semgrep,  # evaluates the run_semgrep expression
                lambda path: scoring.parse_semgrep_report(path, root),  # defines the small inline helper
            )  # closes the multiline block

        def finish_checkov() -> None:  # defines the finish_checkov() function
            status = run_tool(  # runs the run_tool() call
                "checkov",  # supplies the literal text
                "Checkov",  # supplies the literal text
                "Running Checkov (IaC and container misconfigurations; first run "  # supplies the literal text
                "installs Checkov into a private environment)...",  # supplies the literal text
                run_checkov,  # evaluates the run_checkov expression
                lambda path: scoring.parse_checkov_report(path, root),  # defines the small inline helper
            )  # closes the multiline block
            if status and status["status"] != "ok":  # evaluates the branch condition
                with state_lock:  # the pool tasks touch the shared dicts/lists
                    warnings.append(  # adds an item to the list
                        "Checkov did not complete, so IaC/container coverage is incomplete."  # supplies the literal text
                    )  # closes the multiline block

        def finish_guarddog() -> None:  # defines the finish_guarddog() function
            status = run_tool(  # runs the run_tool() call
                "guarddog",  # supplies the literal text
                "GuardDog",  # supplies the literal text
                "Running GuardDog (malware and supply-chain patterns; first run "  # supplies the literal text
                "installs GuardDog into a private environment)...",  # supplies the literal text
                run_guarddog,  # evaluates the run_guarddog expression
                lambda path: scoring.parse_guarddog_report(path, root),  # defines the small inline helper
            )  # closes the multiline block
            if status and status["status"] != "ok":  # evaluates the branch condition
                with state_lock:  # the pool tasks touch the shared dicts/lists
                    warnings.append(  # adds an item to the list
                        "GuardDog did not complete, so supply-chain malware coverage is incomplete."  # supplies the literal text
                    )  # closes the multiline block

        def finish_nuclei() -> None:  # defines the finish_nuclei() function
            status = run_tool(  # runs the run_tool() call
                "nuclei",  # supplies the literal text
                "Nuclei",  # supplies the literal text
                "Running Nuclei (active DAST template scans against the repo's live "  # supplies the literal text
                "web site; first run downloads the ~50 MB binary)...",  # supplies the literal text
                lambda r, a, *, log, cancel: run_nuclei(  # noqa: E731  # runs the run_nuclei() call
                    r, a, log=log, cancel=cancel, targets=nuclei_targets  # copies the log value into r, a, log
                ),  # closes the multiline block
                lambda path: scoring.parse_nuclei_report(path, root),  # defines the small inline helper
            )  # closes the multiline block
            if status and status["status"] == "error":  # evaluates the branch condition
                with state_lock:  # the pool tasks touch the shared dicts/lists
                    warnings.append(  # adds an item to the list
                        "Nuclei did not complete, so active web-testing coverage is incomplete."  # supplies the literal text
                    )  # closes the multiline block

        def finish_kubescape() -> None:  # defines the finish_kubescape() function
            status = run_tool(  # runs the run_tool() call
                "kubescape",  # supplies the literal text
                "Kubescape",  # supplies the literal text
                "Running Kubescape (Kubernetes/IaC misconfigurations against the NSA "  # supplies the literal text
                "and MITRE frameworks; first run downloads a ~300 MB binary plus the "  # supplies the literal text
                "control definitions and exits non-zero when the compliance score "  # supplies the literal text
                "is below 100)...",  # supplies the literal text
                run_kubescape,  # evaluates the run_kubescape expression
                lambda path: scoring.parse_kubescape_report(path, root),  # defines the small inline helper
            )  # closes the multiline block
            if status and status["status"] == "error":  # evaluates the branch condition
                with state_lock:  # the pool tasks touch the shared dicts/lists
                    warnings.append(  # adds an item to the list
                        "Kubescape did not complete, so Kubernetes/IaC coverage is incomplete."  # supplies the literal text
                    )  # closes the multiline block

        def finish_scorecard() -> None:  # defines the finish_scorecard() function
            run_tool(  # runs the run_tool() call
                "scorecard",  # supplies the literal text
                "OpenSSF Scorecard",  # supplies the literal text
                "Running OpenSSF Scorecard (asks the public scorecard.dev record about "  # supplies the literal text
                "the repository's security posture - no binary)...",  # supplies the literal text
                lambda r, a, *, log, cancel: run_scorecard(  # noqa: E731  # runs the run_scorecard() call
                    repo_slug, a, log=log, cancel=cancel  # copies the log value into r, a, log
                ),  # closes the multiline block
                lambda path: scoring.parse_scorecard_report(path, root),  # defines the small inline helper
            )  # closes the multiline block

        def finish_ossfuzz() -> None:  # defines the finish_ossfuzz() function
            run_tool(  # runs the run_tool() call
                "ossfuzz",  # supplies the literal text
                "OSS-Fuzz",  # supplies the literal text
                "Running OSS-Fuzz coverage check (asks the public google/oss-fuzz "  # supplies the literal text
                "registry whether the project is continuously fuzzed - no binary; "  # supplies the literal text
                "the issues dashboard has no public API)...",  # supplies the literal text
                lambda r, a, *, log, cancel: run_ossfuzz(  # noqa: E731  # runs the run_ossfuzz() call
                    repo_slug, a, log=log, cancel=cancel  # copies the log value into r, a, log
                ),  # closes the multiline block
                lambda path: scoring.parse_ossfuzz_report(path, root),  # defines the small inline helper
            )  # closes the multiline block

        def finish_cdxgen() -> None:  # defines the finish_cdxgen() function
            """Catalogue the tree into a CycloneDX SBOM with cdxgen."""
            if cancel.is_set():  # evaluates the branch condition
                raise ScanCancelled("Scan cancelled.")  # raises the ScanCancelled error
            log("Running cdxgen (CycloneDX SBOM; needs Node.js)...")  # keeps the user posted
            try:  # watches for errors in the block
                cdx_output, cdx_status = run_cdxgen(  # runs the run_cdxgen() call
                    root, artifacts, log=log, cancel=cancel  # copies the log value into root, artifacts, log
                )  # closes the multiline block
            except ScanCancelled:  # handles the raised error
                raise  # propagates the cancellation
            except Exception as exc:  # noqa: BLE001  # handles the raised error
                with state_lock:  # the pool tasks touch the shared dicts/lists
                    scanner_status["cdxgen"] = {  # assigns the computed value to scanner_status["cdxgen"]
                        "status": "error",  # maps the status dictionary entry
                        "duration_seconds": 0,  # maps the duration_seconds dictionary entry
                        "details": [f"Could not start cdxgen: {exc}"],  # maps the details dictionary entry
                    }  # closes the multiline block
                    warnings.append(f"cdxgen could not run: {exc}")  # adds an item to the list
                return  # evaluates the return expression
            with state_lock:  # the pool tasks touch the shared dicts/lists
                scanner_status["cdxgen"] = cdx_status  # copies the cdx_status value into scanner_status["cdxgen"]
            if cdx_status["status"] == "ok":  # evaluates the branch condition
                try:  # watches for a broken SBOM document
                    cdx_summary = scoring.parse_cdxgen_sbom(cdx_output)  # runs the parse call
                except Exception as exc:  # noqa: BLE001  # handles the read error
                    with state_lock:  # the pool tasks touch the shared dicts/lists
                        cdx_status["status"] = "error"  # sets the status text
                        cdx_status["details"].append(f"Could not read the cdxgen SBOM: {exc}")  # adds the note
                        warnings.append(f"The cdxgen SBOM could not be read: {exc}")  # adds an item to the list
                    return  # evaluates the return expression
                with state_lock:  # the pool tasks touch the shared dicts/lists
                    cdxgen_holder["value"] = cdx_summary  # publishes the summary
                log(  # runs the log() call
                    f"cdxgen catalogued {cdx_summary['components']} components "  # evaluates the f expression
                    f"({cdx_summary['unversioned']} without a version)."  # evaluates the f expression
                )  # closes the log call
            elif cdx_status["status"] == "error":  # evaluates the branch condition
                with state_lock:  # the pool tasks touch the shared dicts/lists
                    warnings.append(  # adds an item to the list
                        "cdxgen did not complete, so CycloneDX SBOM coverage is missing."  # supplies the literal text
                    )  # closes the warning block

        def finish_fossology() -> None:  # defines the finish_fossology() function
            status = run_tool(  # runs the run_tool() call
                "fossology",  # supplies the literal text
                "FOSSology",  # supplies the literal text
                "Running FOSSology (licence compliance through the FOSSOLOGY_SERVER "  # supplies the literal text
                "REST API: Nomos/Ojo agents; skipped with a note when unconfigured)...",  # supplies the literal text
                lambda r, a, *, log, cancel: run_fossology(  # noqa: E731  # runs the run_fossology() call
                    r, a, log=log, cancel=cancel, file_paths=tree_files  # the shared pre-scan walk
                ),  # closes the runner lambda
                lambda path: scoring.parse_fossology_report(path, root),  # defines the small inline helper
            )  # closes the multiline block
            if status and status.get("status") == "ok":  # evaluates the branch condition
                try:  # the mix feeds the dashboard; a missing one is not fatal  # watches for errors in the block
                    mix = (json.loads((artifacts / "fossology.json").read_text(encoding="utf-8")) or {}).get("mix")  # fetches the mix
                except Exception:  # noqa: BLE001  # handles the read error
                    mix = None  # covers the remaining branch
                if isinstance(mix, dict) and mix:  # evaluates the branch condition
                    with state_lock:  # the pool tasks touch the shared dicts
                        dash_inputs["license_mix"] = mix  # publishes the licence mix
                    log(  # runs the log() call
                        "FOSSology licence mix: "  # supplies the literal text
                        + ", ".join(f"{name} ({count})" for name, count in list(mix.items())[:6])  # the top families
                        + ("..." if len(mix) > 6 else "")  # the truncation note
                    )  # closes the log call
            elif status and status.get("status") == "error":  # evaluates the branch condition
                with state_lock:  # the pool tasks touch the shared dicts/lists
                    warnings.append(  # adds an item to the list
                        "FOSSology did not complete, so licence coverage is incomplete."  # supplies the literal text
                    )  # closes the warning block

        syft_selected = "syft" in selected  # evaluates the "syft" in selected expression
        syft_done = threading.Event()  # the Syft -> Grype/OSV ordering gate  # runs the Event() call
        finishers: list[tuple[str, Callable[[], None]]] = []  # evaluates the finishers expression
        if "trivy" in selected:  # evaluates the branch condition
            finishers.append(("trivy", finish_trivy))  # adds an item to the list
        if syft_selected:  # evaluates the branch condition
            finishers.append(("syft", finish_syft))  # syft goes first so SBOM waits are short
        if "cdxgen" in selected:  # evaluates the branch condition
            finishers.append(("cdxgen", finish_cdxgen))  # the CycloneDX SBOM parallel task
        if "osv" in selected:  # evaluates the branch condition
            finishers.append(("osv", finish_osv))  # adds an item to the list
        if "grype" in selected:  # evaluates the branch condition
            finishers.append(("grype", finish_grype))  # adds an item to the list
        if "gitleaks" in selected:  # evaluates the branch condition
            finishers.append(("gitleaks", finish_gitleaks))  # adds an item to the list
        if "trufflehog" in selected:  # evaluates the branch condition
            finishers.append(("trufflehog", finish_trufflehog))  # adds an item to the list
        if "semgrep" in selected:  # evaluates the branch condition
            finishers.append(("semgrep", finish_semgrep))  # adds an item to the list
        if "checkov" in selected and scanner_status.get("checkov", {}).get("status") != "skipped":  # evaluates the branch condition
            finishers.append(("checkov", finish_checkov))  # adds an item to the list
        if "guarddog" in selected:  # evaluates the branch condition
            finishers.append(("guarddog", finish_guarddog))  # adds an item to the list
        if "kubescape" in selected and scanner_status.get("kubescape", {}).get("status") != "skipped":  # evaluates the branch condition
            finishers.append(("kubescape", finish_kubescape))  # adds an item to the list
        if "nuclei" in selected:  # evaluates the branch condition
            finishers.append(("nuclei", finish_nuclei))  # adds an item to the list
        if "scorecard" in selected:  # evaluates the branch condition
            finishers.append(("scorecard", finish_scorecard))  # adds an item to the list
        if "ossfuzz" in selected:  # evaluates the branch condition
            finishers.append(("ossfuzz", finish_ossfuzz))  # adds an item to the list
        if "fossology" in selected:  # evaluates the branch condition
            finishers.append(("fossology", finish_fossology))  # adds an item to the list

        def pooled(work, *, wait_syft: bool = False):  # defines the pooled() function
            """Worker body: optional Syft gate, then the tool's own isolation."""
            def task() -> None:  # defines the task() function
                if wait_syft:  # evaluates the branch condition
                    syft_done.wait()  # waits for the SBOM hand-off
                if cancel.is_set():  # checks the stop button again after the wait
                    raise ScanCancelled("Scan cancelled.")  # raises the ScanCancelled error
                work()  # runs the work() call
            return task  # returns the task to the caller

        tasks = [  # assigns the computed value to tasks
            pooled(  # runs the pooled() call
                work,  # evaluates the work expression
                wait_syft=syft_selected and name in {"grype", "osv"},  # evaluates the wait_syft expression
            )  # closes the multiline block
            for name, work in finishers  # loops over the collection
        ]  # closes the multiline block

        cancel_error: BaseException | None = None  # evaluates the cancel_error expression
        if tasks:  # evaluates the branch condition
            worker_count = min(config.SCANNER_POOL_WORKERS, len(tasks))  # evaluates the min() call
            with ThreadPoolExecutor(  # opens the pool context
                max_workers=worker_count,  # evaluates the worker_count expression
                thread_name_prefix="scan",  # names the thread
            ) as pool:  # closes the multiline block
                futures = {pool.submit(task): name for (name, _), task in zip(finishers, tasks)}  # runs the submit() call
                for future, name in futures.items():  # loops over the collection
                    try:  # watches for errors in the block
                        future.result()  # waits for the thread
                    except ScanCancelled as exc:  # handles the raised error
                        cancel_error = cancel_error or exc  # re-raised after the pool drains  # evaluates the exc expression
                    except Exception as exc:  # noqa: BLE001 - one task must never sink the pool  # handles the raised error
                        with state_lock:  # the pool tasks touch the shared dicts/lists
                            label = config.TOOL_LABELS.get(name, name.title())  # fetches the value
                            scanner_status.setdefault(  # evaluates the setdefault() call
                                name,  # evaluates the name expression
                                {  # executes the statement
                                    "status": "error",  # maps the status dictionary entry
                                    "duration_seconds": 0,  # maps the duration_seconds dictionary entry
                                    "details": [f"Could not run {label}: {exc}"],  # maps the details dictionary entry
                                },  # closes the multiline block
                            )  # closes the multiline block
                            warnings.append(f"{label} could not run: {exc}")  # adds an item to the list

        if cancel_error is not None:  # evaluates the branch condition
            raise cancel_error  # the ScanCancelled path still stops the whole scan  # evaluates the cancel_error expression

        inventory = inventory_holder.get("value")  # fetches the value
        syft_sbom = shared["syft_sbom"]  # kept for the artifacts/debug shape  # fetches the value
        sbom_payload = scoring.merge_sbom_summaries(  # the merged Print/Export SBOM payload
            [summary for summary in (inventory, cdxgen_holder.get("value")) if isinstance(summary, dict)]
        )  # closes the merge call

        # Deterministic assembly: record the rows in the display order after
        # the pool finishes (pool completion order is not).
        scanner_status = {  # assigns the computed value
            **{tool: scanner_status[tool] for tool in config.ALL_TOOLS if tool in scanner_status},  # the known order
            **{name: status for name, status in scanner_status.items() if name not in config.ALL_TOOLS},  # any extras
        }

        report = scoring.build_report(  # runs the build_report() call
            findings,  # evaluates the findings expression
            repo=metadata,  # copies the metadata value into repo
            scanner_status=scanner_status,  # copies the scanner_status value into scanner_status
            warnings=warnings,  # copies the warnings value into warnings
            languages=languages,  # copies the languages value into languages
            duration_seconds=time.monotonic() - started,  # runs the monotonic() call
            inventory=inventory,  # copies the inventory value into inventory
            sbom=sbom_payload,  # copies the sbom value into sbom
            frameworks=frameworks,  # copies the frameworks value into frameworks
            care=care_raw,  # copies the care_raw value into care
            dashboard=dashboard,  # copies the dashboard value into dashboard
            dashboard_inputs=dash_inputs,  # copies the dash_inputs value into dashboard_inputs
            language_file_counts=language_counts,  # copies the language_counts value into language_file_counts
        )  # closes the multiline block
        report["language_file_counts"] = language_counts  # copies the language_counts value into report["language_file_counts"]
        report["artifacts_dir"] = str(artifacts)  # runs the str() call
        report["workdir"] = str(workdir)  # runs the str() call

        if keep_artifacts:  # evaluates the branch condition
            scoring.write_report_json(report, artifacts / "report.json")  # runs the write_report_json() call

        log(  # runs the log() call
            f"Done in {report['duration_seconds']:.1f}s - score {report['score']}/100 "  # evaluates the f expression
            f"({report['band']}), verdict {report['verdict']}."  # evaluates the f expression
        )  # closes the multiline block
        return report  # returns the report to the caller

    except ScanCancelled:  # handles the raised error
        raise  # evaluates the raise expression
    except ScanError:  # handles the raised error
        raise  # evaluates the raise expression
    except Exception as exc:  # noqa: BLE001 - surface anything unexpected in the UI  # handles the raised error
        raise ScanError(f"Unexpected failure: {exc}") from exc  # raises the ScanError error
    finally:  # runs whether or not the block errored
        if not keep_artifacts:  # evaluates the branch condition
            shutil.rmtree(workdir, ignore_errors=True)  # deletes the folder tree


def scan_website(  # defines the scan_website() function
    url: str,  # evaluates the url expression
    *,  # spreads the collected values
    log: LogFn,  # evaluates the log expression
    cancel: Cancel,  # evaluates the cancel expression
    keep_artifacts: bool = True,  # evaluates the keep_artifacts expression
    tools: Iterable[str] | None = None,  # evaluates the tools expression
    frameworks: Iterable[str] | None = None,  # evaluates the frameworks expression
    dashboard: Iterable[str] | None = None,  # evaluates the dashboard expression
) -> dict[str, Any]:  # closes the multiline block
    """Scan a live website instead of a source repository.

    There is no source checkout, so every source-side scanner is recorded as
    skipped ("not applicable") and the score is built only from the checks
    that can work against a running site: Nuclei's DAST templates (when the
    user ticks it) and the local web header/dotfile audit. Skipped is a
    neutral status, so the verdict comes from the web findings alone - a
    website scan can end SECURE without CodeQL ever running.
    """
    started = time.monotonic()  # runs the monotonic() call
    if cancel.is_set():  # respects the stop button straight away
        raise ScanCancelled("Scan cancelled.")  # raises the ScanCancelled error
    target, normalized = parse_target(url)  # re-classifies the input safely
    if target != "web":  # a repository slipped into the web pipeline
        raise ScanError(f"{url} is a repository; use the repository scan instead.")  # raises the ScanError error
    log(f"Website scan: {normalized}")  # logs the target

    stamp = time.strftime("%Y%m%d-%H%M%S")  # formats the timestamp
    host = urllib.parse.urlsplit(normalized).netloc.split(":")[0]  # strips the port
    workdir = config.WORK_DIR / f"web-{host}-{stamp}"  # names the scratch folder
    artifacts = workdir / "artifacts"  # copies the workdir value into artifacts
    artifacts.mkdir(parents=True, exist_ok=True)  # creates the folder

    # Only web-capable checks run; the source-only row is ignored with a note.
    wanted = set(normalize_tools(tools))  # keeps the user's selection honest
    web_tools = ("nuclei",)  # the only selectable tool that applies to a site
    if not wanted & set(web_tools):  # evaluates the branch condition
        log("No web-capable scanner selected; running the built-in web audit only.")  # logs the note
    findings: list[scoring.Finding] = []  # evaluates the findings expression
    warnings: list[str] = []  # evaluates the warnings expression
    scanner_status: dict[str, dict[str, Any]] = {  # pre-seeds every selectable tool
        tool: {  # evaluates the tool expression
            "status": "skipped",  # skipped is neutral for the verdict
            "duration_seconds": 0,  # no time was spent
            "details": ["Not applicable: this was a website scan with no source checkout."],  # adds the detail text
        }  # closes the multiline block
        for tool in config.ALL_TOOLS  # loops over the collection
        if tool != "nuclei"  # the one scanner that does apply
    }  # closes the multiline block

    def ingest(name: str, output: Path, status: dict[str, Any], parser) -> None:  # defines the ingest() function
        """Record a scanner's status and parse its report when it succeeded."""  # keeps the docstring text
        scanner_status[name] = status  # copies the status value into scanner_status[name]
        if status["status"] != "ok":  # evaluates the branch condition
            return  # evaluates the return expression
        label = config.TOOL_LABELS.get(name, name.title())  # fetches the value
        try:  # watches for errors in the block
            parsed = list(parser(output))  # builds the list collection
        except Exception as exc:  # noqa: BLE001 - one bad report must not kill the scan  # handles the raised error
            status["status"] = "error"  # sets the status["status"] text
            status["details"].append(f"Could not parse {label} output: {exc}")  # adds an item to the list
            warnings.append(f"{label} output could not be parsed: {exc}")  # adds an item to the list
            return  # evaluates the return expression
        findings.extend(parsed)  # adds several items to the list
        log(f"{label} reported {len(parsed)} finding{'s' if len(parsed) != 1 else ''}.")  # logs the count

    # --- Web audit ---------------------------------------------------
    if cancel.is_set():  # respects the stop button between tools
        raise ScanCancelled("Scan cancelled.")  # raises the ScanCancelled error
    log("Running the built-in web audit (hardening headers and exposed-dotfile probes)...")  # logs the intro
    try:  # watches for errors in the block
        web_output, web_status = run_web_check(normalized, artifacts, log=log, cancel=cancel)  # runs the audit
        ingest("webcheck", web_output, web_status, scoring.parse_webcheck_report)  # parses the audit
    except ScanCancelled:  # handles the raised error
        raise  # evaluates the raise expression
    except Exception as exc:  # noqa: BLE001 - a broken site must not kill the scan  # handles the raised error
        scanner_status["webcheck"] = {  # assigns the computed value to scanner_status["webcheck"]
            "status": "error",  # maps the status dictionary entry
            "duration_seconds": round(time.monotonic() - started, 1),  # measures the duration
            "details": [f"Could not fetch {normalized}: {exc}"],  # adds the detail text
        }  # closes the multiline block
        warnings.append(f"The web audit could not reach the site: {exc}")  # adds an item to the list

    # --- Nuclei ------------------------------------------------------
    if "nuclei" in wanted:  # evaluates the branch condition
        if cancel.is_set():  # respects the stop button between tools
            raise ScanCancelled("Scan cancelled.")  # raises the ScanCancelled error
        log("Running Nuclei against the live site (first run downloads the ~50 MB binary)...")  # logs the intro
        try:  # watches for errors in the block
            nuclei_output, nuclei_status = run_nuclei(  # runs the run_nuclei() call
                workdir, artifacts, log=log, cancel=cancel, targets=[normalized]  # copies the normalized value into targets
            )  # closes the multiline block
            if nuclei_output is not None:  # evaluates the branch condition
                ingest("nuclei", nuclei_output, nuclei_status, scoring.parse_nuclei_report)  # parses the output
            else:  # covers the remaining branch
                scanner_status["nuclei"] = nuclei_status  # skipped: no targets (never for a site)
        except ScanCancelled:  # handles the raised error
            raise  # evaluates the raise expression
        except Exception as exc:  # noqa: BLE001 - keep the scan alive  # handles the raised error
            scanner_status["nuclei"] = {  # assigns the computed value to scanner_status["nuclei"]
                "status": "error",  # maps the status dictionary entry
                "duration_seconds": 0,  # no meaningful duration
                "details": [f"Could not start Nuclei: {exc}"],  # adds the detail text
            }  # closes the multiline block
            warnings.append(f"Nuclei could not run: {exc}")  # adds an item to the list
    else:  # covers the remaining branch
        scanner_status.setdefault("nuclei", {  # evaluates the setdefault() call
            "status": "skipped",  # maps the status dictionary entry
            "duration_seconds": 0,  # no time was spent
            "details": ["Not selected for this scan."],  # adds the detail text
        })  # closes the multiline block

    metadata = {  # builds the metadata dict
        "input_url": url,  # maps the input_url dictionary entry
        "full_name": urllib.parse.urlsplit(normalized).netloc,  # names the site
        "scan_kind": "website",  # marks the report shape
    }  # closes the multiline block
    report = scoring.build_report(  # runs the build_report() call
        findings,  # evaluates the findings expression
        repo=metadata,  # copies the metadata value into repo
        scanner_status=scanner_status,  # copies the scanner_status value into scanner_status
        warnings=warnings,  # copies the warnings value into warnings
        languages=[],  # a website has no source languages
        duration_seconds=time.monotonic() - started,  # measures the duration
        frameworks=frameworks,  # copies the frameworks value into frameworks
        dashboard=dashboard,  # copies the dashboard value into dashboard
    )  # closes the multiline block
    report["artifacts_dir"] = str(artifacts)  # runs the str() call
    report["workdir"] = str(workdir)  # runs the str() call
    report["scan_kind"] = "website"  # UI-visible report shape marker

    if keep_artifacts:  # evaluates the branch condition
        scoring.write_report_json(report, artifacts / "report.json")  # runs the write_report_json() call

    log(  # runs the log() call
        f"Done in {report['duration_seconds']:.1f}s - score {report['score']}/100 "  # evaluates the f expression
        f"({report['band']}), verdict {report['verdict']}."  # evaluates the f expression
    )  # closes the multiline block
    return report  # returns the report to the caller


def scan_target(  # defines the scan_target() function
    url: str,  # evaluates the url expression
    *,  # spreads the collected values
    log: LogFn,  # evaluates the log expression
    cancel: Cancel,  # evaluates the cancel expression
    keep_artifacts: bool = True,  # evaluates the keep_artifacts expression
    tools: Iterable[str] | None = None,  # evaluates the tools expression
    frameworks: Iterable[str] | None = None,  # evaluates the frameworks expression
    dashboard: Iterable[str] | None = None,  # evaluates the dashboard expression
) -> dict[str, Any]:  # closes the multiline block
    """Dispatch an input to the repository scanner or the website scanner."""
    kind, _target = parse_target(url)  # classifies the input once
    if kind == "repo":  # evaluates the branch condition
        return scan_repository(  # runs the scan_repository() call
            url,  # evaluates the url expression
            log=log,  # copies the log value into log
            cancel=cancel,  # copies the cancel value into cancel
            keep_artifacts=keep_artifacts,  # copies the keep_artifacts value into keep_artifacts
            tools=tools,  # copies the tools value into tools
            frameworks=frameworks,  # copies the frameworks value into frameworks
            dashboard=dashboard,  # copies the dashboard value into dashboard
        )  # closes the multiline block
    return scan_website(  # runs the scan_website() call
        url,  # evaluates the url expression
        log=log,  # copies the log value into log
        cancel=cancel,  # copies the cancel value into cancel
        keep_artifacts=keep_artifacts,  # copies the keep_artifacts value into keep_artifacts
        tools=tools,  # copies the tools value into tools
        frameworks=frameworks,  # copies the frameworks value into frameworks
        dashboard=dashboard,  # copies the dashboard value into dashboard
    )  # closes the multiline block


def cleanup_old_workdirs(max_age_hours: int = 48, log: LogFn | None = None) -> None:  # defines the cleanup_old_workdirs() function
    """Remove stale scratch folders so the cache does not grow without bound."""  # keeps the docstring text
    if not config.WORK_DIR.exists():  # evaluates the branch condition
        return  # evaluates the return expression
    cutoff = time.time() - max_age_hours * 3600  # runs the time() call
    removed = 0  # assigns the computed value to removed
    for entry in config.WORK_DIR.iterdir():  # loops over the collection
        try:  # watches for errors in the block
            if entry.is_dir() and entry.stat().st_mtime < cutoff:  # evaluates the branch condition
                shutil.rmtree(entry, ignore_errors=True)  # deletes the folder tree
                removed += 1  # evaluates the removed expression
        except OSError:  # handles the raised error
            continue  # skips to the next loop iteration
    if removed and log:  # evaluates the branch condition
        log(f"Cleaned up {removed} old scan folder(s).")  # runs the log() call
