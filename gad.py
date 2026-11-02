"""Quick GitHub Advisory Database lookup for the scanned repository.

Pure functions over the report's SBOM inventory: every pinned component
(name@version) is checked against GitHub's published /advisories endpoint
(the GHSA database behind https://github.com/advisories). The sweep fans
out over a worker pool, so even fully-uncapped sweeps stay quick. No
Tkinter here: the CLI and tests can drive it offline by injecting the
``fetch`` callable.
"""

from __future__ import annotations

import json  # imports the json module
import os  # imports the os module
import re  # reads the CVE ids out of the finding rows
import urllib.error  # imports the urllib.error module
import urllib.parse  # imports the urllib.parse module
import urllib.request  # imports the urllib.request module
from concurrent.futures import ThreadPoolExecutor, as_completed  # the fan-out pool
from typing import Any

import config

GITHUB_TOKEN_ENVS: tuple[str, ...] = ("GITHUB_TOKEN", "GH_TOKEN")  # the accepted token names
SEVERITY_ORDER = ("critical", "high", "moderate", "low")  # worst first, for sorting


def _github_token() -> str:  # defines the _github_token() function
    """The user's GitHub token from the environment, or an empty string."""
    for name in GITHUB_TOKEN_ENVS:  # loops over the accepted names
        token = os.environ.get(name) or ""  # fetches the first set value
        if token.strip():  # evaluates the branch condition
            return token.strip()  # returns the token to the caller
    return ""  # unauthenticated lookups are fine, just rate limited harder


def _get_json(url: str, token: str) -> tuple[int, Any]:  # defines the _get_json() function
    """One GET against GitHub's advisory API; returns (status, parsed body)."""
    headers = {  # the request shape the API documents
        "User-Agent": config.USER_AGENT,  # identifies the launcher politely
        "Accept": "application/vnd.github+json",  # the JSON accept header
    }  # closes the headers block
    if token:  # evaluates the branch condition
        headers["Authorization"] = f"Bearer {token}"  # raises the rate limit with a token
    request = urllib.request.Request(url, headers=headers, method="GET")  # the request object
    try:  # watches for the HTTP errors the caller understands
        with urllib.request.urlopen(request, timeout=config.HTTP_TIMEOUT_SECONDS) as response:  # opens
            return response.status, json.load(response)  # returns the parsed pair
    except urllib.error.HTTPError as exc:  # handles the HTTPError branch
        detail = exc.read(300).decode("utf-8", errors="replace")  # keeps the server message
        raise RuntimeError(f"HTTP {exc.code}: {detail.strip()}") from exc  # raises the friendly error


def advisory_components(report: dict[str, Any]) -> list[dict[str, str]]:
    """The pinned components worth checking, from the SBOM or Syft inventory.

    Legacy helper kept for callers that only ever wanted tier one; the
    full-suite lookup is :func:`gad_targets`.
    """
    sbom = report.get("sbom") or {}  # the merged SBOM payload
    inventory = report.get("inventory") or {}  # the Syft summary
    rows: list[dict[str, str]] = []  # the union, in stored order
    seen: set[tuple[str, str]] = set()  # the dedupe keys
    for source in (sbom.get("all_components"), inventory.get("all_components")):  # both sightings
        for component in source or []:  # loops over the rows
            if not isinstance(component, dict):  # evaluates the branch condition
                continue  # skips the malformed rows
            name = str(component.get("name") or "").strip()  # the component name
            version = str(component.get("version") or "").strip()  # the pinned version
            if not name or not version:  # unpinned rows match every advisory by name alone
                continue  # too noisy: only exact name@version pairs are checked
            key = (name.lower(), version)  # the identity key
            if key in seen:  # evaluates the branch condition
                continue  # one check per component
            seen.add(key)  # marks the row checked
            rows.append({"name": name, "version": version})  # keeps the pair
    return rows  # returns the capped-capable list


def gad_targets(report: dict[str, Any]) -> dict[str, list[Any]]:  # defines the gad_targets() function
    """Every lookup target the Advisory Database can answer for, no SBOM needed.

    Three independent sources, used in this order of precision:

    * ``components`` - pinned (name@version) pairs from the SBOM payload or
      the Syft inventory: the most precise ``affects=`` queries.
    * ``cves``       - the CVE identifiers the CVE scanners already reported;
      each is checked cve_id-wise, no SBOM required at all.
    * ``packages``   - plain package names from the findings, checked
      name-wise (any version) when the first two tiers are unavailable.
    """
    sbom = report.get("sbom") or {}  # the merged SBOM payload
    inventory = report.get("inventory") or {}  # the Syft summary
    findings = [row for row in (report.get("findings") or []) if isinstance(row, dict)]  # the finding rows

    components: list[dict[str, str]] = []  # the pinned pairs
    seen: set[tuple[str, str]] = set()  # the dedupe keys
    for source in (sbom.get("all_components"), inventory.get("all_components")):  # both sightings
        for component in source or []:  # loops over the rows
            if not isinstance(component, dict):  # evaluates the branch condition
                continue  # skips the malformed rows
            name = str(component.get("name") or "").strip()  # the component name
            version = str(component.get("version") or "").strip()  # the pinned version
            if not name or not version:  # unpinned rows match every advisory by name alone
                continue  # too noisy in tier one: they fall to the package tier
            key = (name.lower(), version)  # the identity key
            if key in seen:  # evaluates the branch condition
                continue  # one check per component
            seen.add(key)  # marks the row checked
            components.append({"name": name, "version": version})  # keeps the pair

    cves: list[dict[str, str]] = []  # the CVE identifiers from the findings
    cve_seen: set[str] = set()  # the CVE dedupe keys
    packages: list[dict[str, str]] = []  # the plain names from the findings
    package_seen: set[str] = set()  # the package dedupe keys
    for finding in findings:  # walks the finding rows once
        rule_ids = "  ".join(  # every identifier-ish string on the row
            [str(finding.get("rule_id") or ""), str(finding.get("title") or "")]
        )  # closes the rule build
        for match in re.finditer(r"CVE-\d{4}-\d{4,}", rule_ids):  # runs the CVE regex
            cve_id = match.group(0).upper()  # the canonical CVE id
            if cve_id not in cve_seen:  # evaluates the branch condition
                cve_seen.add(cve_id)  # marks the CVE checked
                cves.append({"cve": cve_id, "package": str(finding.get("package") or "")})  # the query row
        package = str(finding.get("package") or "").strip()  # the affected package name
        if package and package.lower() not in package_seen:  # evaluates the branch condition
            package_seen.add(package.lower())  # marks the package checked
            packages.append({"name": package})  # the loose tier row

    return {"components": components, "cves": cves, "packages": packages}  # returns the tiers


def check_gad(  # defines the check_gad() function
    report: dict[str, Any],  # the finished report
    *,  # spreads the collected values
    checks: int | None = None,  # the safety-valve cap (very high by default)
    fetch: Any = None,  # the HTTP fetcher, injectable for offline tests
    progress: Any = None,  # the (done, total) callback, painted by the UI
) -> dict[str, Any]:
    """Check the repository's findings against the GitHub Advisory Database.

    Independent of the SBOM: the sweep runs over pinned SBOM components when
    they exist, otherwise (or additionally) over the CVE identifiers the
    scanners reported, and finally over plain package names when nothing
    else is available. Returns ``{"checked", "hits", "errors",
    "rate_limited", "considered", "token", "sources"}`` with hits sorted
    worst severity first; the lookups fan out eight-wide and GitHub's own
    rate limit is the real-world budget (note added on a 403/429).
    """
    progress = progress or (lambda done, total: None)  # the default no-op callback
    if fetch is None:  # the default fetcher unless tests inject one
        def fetch(url: str, token: str) -> tuple[int, Any]:  # the real network fetch
            return _get_json(url, token)  # runs the _get_json() call

    targets = gad_targets(report)  # the three-tier target list
    token = _github_token()  # reads the environment once, once per run
    hits: list[dict[str, Any]] = []  # the matched advisories
    errors: list[str] = []  # the per-target notes the popup prints in mute
    rate_limited = False  # whether GitHub stopped the sweep
    checked = 0  # how many endpoints were actually queried

    considered = 0  # how many targets we COULD have checked (honesty)
    queries: list[dict[str, Any]] = []  # the assembled endpoint queries, precision order
    for component in targets["components"]:  # tier 1: the pinned pairs
        pair = f"{component['name']}@{component['version']}"  # the affects pair
        queries.append({  # the tier-one query
            "url": f"{config.GITHUB_API}/advisories?affects={urllib.parse.quote(pair, safe='')}",  # the endpoint
            "label": pair,  # the error label
            "package": pair,  # the hit label
        })  # closes the query build
        considered += 1  # counts the target
    for cve_row in targets["cves"]:  # tier 2: the CVE ids, no SBOM required
        queries.append({  # the tier-two query
            "url": f"{config.GITHUB_API}/advisories?cve_id={urllib.parse.quote(cve_row['cve'], safe='')}",  # cve id
            "label": f"{cve_row['cve']} (from the finding set)",  # the error label
            "package": cve_row.get("package") or cve_row["cve"],  # the hit label
        })  # closes the query build
        considered += 1  # counts the target
    if not queries and targets["packages"]:  # tier 3 only when nothing better exists
        for package_row in targets["packages"]:  # the loose tier
            queries.append({  # the tier-three query
                "url": f"{config.GITHUB_API}/advisories?affects={urllib.parse.quote(package_row['name'], safe='')}",  # by name
                "label": f"{package_row['name']} (version unknown; any version)",  # the honest note
                "package": package_row["name"],  # the hit label
            })  # closes the query build
            considered += 1  # counts the target

    component_budget = checks if checks is not None else config.GAD_MAX_CHECKS  # the safety-valve cap
    if len(queries) > component_budget + config.GAD_MAX_CVE_CHECKS:  # the runaway valve
        queries = queries[: component_budget + config.GAD_MAX_CVE_CHECKS]  # truncates only absurdly long lists
    total = len(queries)  # the queries in this sweep
    called = {"done": 0}  # a mutable counter shared with the worker closures

    def announce() -> None:  # the progress callback, after every queried target
        called["done"] += 1  # counts one more completed lookup
        progress(called["done"], total)  # the caller paints its own progress

    def sweep_one(query: dict[str, Any]) -> None:  # the per-query worker body
        try:  # every path below ends in the same progress announcement
            try:  # watches for the network errors
                status, payload = fetch(query["url"], token)  # runs the injected fetch call
            except RuntimeError as exc:  # handles the HTTP error branch
                text = str(exc)  # the raw text for the rate check
                if "HTTP 403" in text or "HTTP 429" in text:  # evaluates the branch condition
                    rate_limited["state"] = True  # marks the sweep rate-bound once
                    if len(errors) == 0 or not any("Rate limited" in note for note in errors):  # only the first note
                        errors.append("Rate limited by GitHub; set GITHUB_TOKEN to raise the "
                                      "search budget.")  # the token advice
                    return  # a 403 yields no advisory rows
                errors.append(f"{query['label']}: {exc}")  # any other failure is a per-target note
                return  # continues with the siblings
            except Exception as exc:  # noqa: BLE001  # handles the network branch
                errors.append(f"{query['label']}: {exc}")  # the note
                return  # continues with the siblings
            if not isinstance(payload, list):  # evaluates the branch condition
                return  # covers the unexpected shape
            for advisory in payload:  # loops over the matching advisories
                if not isinstance(advisory, dict) or advisory.get("withdrawn_at"):  # withdrawn rows never count
                    continue  # skips the withdrawn rows
                hit = {  # builds the popup row
                    "ghsa": str(advisory.get("ghsa_id") or ""),  # the advisory id
                    "cve": str(advisory.get("cve_id") or ""),  # the CVE alias when present
                    "severity": str(advisory.get("severity") or "unknown").lower(),  # worst-affected rating
                    "summary": str(advisory.get("summary") or ""),  # the one-line description
                    "url": str(advisory.get("url") or ""),  # the advisory link
                    "published": str(advisory.get("published_at") or "")[:10],  # the publish date
                    "package": query["package"],  # the target we checked
                }  # closes the row build
                hits.append(hit)  # adds the hit to the list
                checked["value"] += 1  # one more endpoint answered with advisories
        finally:  # every completion advances the progress callback
            announce()  # counts one more completed lookup

    checked = {"value": 0}  # how many endpoints were actually queried
    rate_limited = {"state": False}  # whether GitHub stopped the sweep
    progress(0, total)  # paints the zero state before the sweep starts
    if total:  # evaluates the branch condition
        worker_count = min(config.GAD_MAX_WORKERS, total)  # the fan-out width
        with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="gad") as pool:  # the fan-out
            for _future in as_completed([pool.submit(sweep_one, query) for query in queries]):  # drains the pool
                pass  # the worker bodies own their progress reporting
    hits.sort(key=lambda hit: (  # sorts the hits worst first, then oldest
        SEVERITY_ORDER.index(hit["severity"]) if hit["severity"] in SEVERITY_ORDER else len(SEVERITY_ORDER),  # the rank
        hit["published"],  # the date tie-breaker
    ))  # closes the sort
    return {  # returns the popup-ready payload
        "checked": checked["value"],  # maps the checked dictionary entry
        "considered": considered,  # maps the considered dictionary entry
        "hits": hits,  # maps the hits dictionary entry
        "errors": errors,  # maps the errors dictionary entry
        "rate_limited": rate_limited["state"],  # maps the rate_limited dictionary entry
        "token": bool(token),  # whether a token lifted the budget
    }  # closes the payload