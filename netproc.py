"""Shared network and process helpers for scanners and bootstrap.

One home for the small pieces both pipeline modules used to carry verbatim:
the urllib GET wrapper, the GitHub token reader, the Windows ``taskkill``
tree-kill and the tarfile fallback extraction (safe extraction with
``filter="data"`` where the running Python supports it).
"""

from __future__ import annotations  # imports annotations from the __future__ module

import os  # imports the os module
import subprocess  # imports the subprocess module
import tarfile  # imports the tarfile module
import urllib.request  # imports the urllib.request module
from pathlib import Path  # imports Path from the pathlib module

import config  # imports the config module


def _http_get(url: str, headers: dict[str, str] | None = None, timeout: int | None = None):  # defines the _http_get() function
    """Open one HTTP request with the app's user agent; caller closes it."""
    request = urllib.request.Request(  # runs the Request() call
        url,  # evaluates the url expression
        headers={  # assigns the computed value to headers
            "User-Agent": config.USER_AGENT,  # maps the User-Agent dictionary entry
            "Accept": "application/vnd.github+json",  # maps the Accept dictionary entry
            **(headers or {}),  # spreads the collected values
        },  # closes the multiline block
    )  # closes the multiline block
    return urllib.request.urlopen(request, timeout=timeout or config.HTTP_TIMEOUT_SECONDS)  # returns the urllib.request.urlopen to the caller


def _github_token() -> str:  # defines the _github_token() function
    """Best-effort GitHub token for API/binary download rate limits."""
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""  # returns the os.environ.get to the caller


def _kill_tree(process: subprocess.Popen) -> None:  # defines the _kill_tree() function
    """Kill a child and its whole tree; on Windows via ``taskkill /F /T``."""
    if process.poll() is not None:  # evaluates the branch condition
        return  # evaluates the return expression
    try:  # watches for errors in the block
        if os.name == "nt":  # evaluates the branch condition
            subprocess.run(  # runs the run() call
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],  # runs the str() call
                stdout=subprocess.DEVNULL,  # copies the subprocess.DEVNULL value into stdout
                stderr=subprocess.DEVNULL,  # copies the subprocess.DEVNULL value into stderr
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),  # runs the getattr() call
            )  # closes the multiline block
        else:  # covers the remaining branch
            process.terminate()  # runs the terminate() call
    except Exception:  # handles the raised error
        pass  # keeps the block syntactically empty
    try:  # watches for errors in the block
        process.wait(timeout=10)  # runs the wait() call
    except Exception:  # handles the raised error
        pass  # keeps the block syntactically empty


def _tar_fallback_extract(archive: Path, target: Path) -> None:  # defines the _tar_fallback_extract() function
    """Extract a .tar.gz with tarfile; refuses escape paths when supported.

    ``filter="data"`` keeps absolute paths and ``..`` members out where the
    running Python understands it; an older interpreter (plain extractall)
    degrades instead of failing a tool the bsdtar fast path could not unpack.
    """
    with tarfile.open(archive, "r:gz") as bundle:  # opens the context for the block
        try:  # watches for errors in the block
            bundle.extractall(target, filter="data")  # type: ignore[call-arg]  # runs the extractall() call
        except TypeError:  # Python < 3.12  # handles the raised error
            bundle.extractall(target)  # runs the extractall() call
