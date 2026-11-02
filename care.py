"""Repository maintenance statistics - the "Care and Feeding" section.

Data comes from the GitHub REST API (`scanners.fetch_care_and_feeding`); this
module turns that raw material into display-ready numbers so the report can
answer the maintenance questions users actually have:

    last commit / last release, commit and release cadence, whether
    development is speeding up or stalling, open pull requests (and the
    oldest one), the oldest open issue, how quickly issues and PRs get a
    first resolution, how many people actually contribute, and how much of
    the repo's activity is recent versus stale.

All math is pure and unit-testable: :func:`summarize` takes the raw dictionary
and an optional ``now`` (ISO string or datetime), and never touches the API.
Missing data is preserved as ``None`` and skipped by renderers rather than
shown as zeroes.
"""

from __future__ import annotations  # imports annotations from the __future__ module

import statistics  # imports the statistics module
from datetime import datetime, timezone  # imports datetime, timezone from the datetime module
from typing import Any  # imports Any from the typing module

import textutil  # imports the shared clip/clean helpers

PULLS_CLOSED_SAMPLE = 30  # assigns the computed value to PULLS_CLOSED_SAMPLE
ISSUES_CLOSED_SAMPLE = 30  # assigns the computed value to ISSUES_CLOSED_SAMPLE
RECENT_COMMITS_SAMPLE = 30  # assigns the computed value to RECENT_COMMITS_SAMPLE


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _parse_datetime(value: Any) -> datetime | None:  # defines the _parse_datetime() function
    if not value and value != 0:  # evaluates the branch condition
        return None  # returns nothing to the caller
    if isinstance(value, datetime):  # evaluates the branch condition
        return value  # returns the value to the caller
    if isinstance(value, (int, float)) and not isinstance(value, bool):  # evaluates the branch condition
        # GitHub's /stats/commit_activity uses Unix epoch seconds for `week`.
        try:  # watches for errors in the block
            return datetime.fromtimestamp(float(value), tz=timezone.utc)  # returns the datetime.fromtimestamp to the caller
        except (OverflowError, OSError, ValueError):  # handles the raised error
            return None  # returns nothing to the caller
    try:  # watches for errors in the block
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))  # returns the datetime.fromisoformat to the caller
    except ValueError:  # handles the raised error
        return None  # returns nothing to the caller


def _now(now: Any) -> datetime:  # defines the _now() function
    parsed = _parse_datetime(now) or datetime.now(timezone.utc)  # runs the _parse_datetime() call
    if parsed.tzinfo is None:  # evaluates the branch condition
        parsed = parsed.replace(tzinfo=timezone.utc)  # swaps the text
    return parsed  # returns the parsed to the caller


def _age_days(stamp: Any, now: datetime) -> float | None:  # defines the _age_days() function
    dt = _parse_datetime(stamp)  # runs the _parse_datetime() call
    if dt is None:  # evaluates the branch condition
        return None  # returns nothing to the caller
    if dt.tzinfo is None:  # evaluates the branch condition
        dt = dt.replace(tzinfo=timezone.utc)  # swaps the text
    # Floor so "today" reports 0 days, not 0.3; round to keep dates deterministic.
    days = (now - dt).total_seconds() / 86400.0  # runs the total_seconds() call
    return max(0.0, round(days, 1))  # returns the max to the caller


def _median_gap_days(stamps: list[Any]) -> float | None:  # defines the _median_gap_days() function
    """Median spacing between a chronological list of release dates."""  # keeps the docstring text
    parsed = sorted(dt for dt in (_parse_datetime(s) for s in stamps) if dt is not None)  # sorts the values
    if len(parsed) < 2:  # evaluates the branch condition
        return None  # returns nothing to the caller
    gaps = [  # assigns the computed value to gaps
        (later - earlier).total_seconds() / 86400.0  # runs the total_seconds() call
        for earlier, later in zip(parsed, parsed[1:])  # loops over the collection
    ]  # closes the multiline block
    return round(statistics.median(gaps), 1)  # returns the round to the caller


def _pair_median(  # defines the _pair_median() function
    sample: list[dict[str, Any]],  # evaluates the sample expression
    start_field: str,  # evaluates the start_field expression
    end_fields: tuple[str, ...],  # evaluates the end_fields expression
) -> float | None:  # closes the multiline block
    """Median days between one start field and whichever end field is set."""  # keeps the docstring text
    durations: list[float] = []  # evaluates the durations expression
    for item in sample:  # loops over the collection
        start = _parse_datetime(item.get(start_field))  # runs the _parse_datetime() call
        end = None  # assigns the None literal to end
        for field in end_fields:  # loops over the collection
            end = _parse_datetime(item.get(field))  # runs the _parse_datetime() call
            if end is not None:  # evaluates the branch condition
                break  # exits the loop early
        if start is None or end is None:  # evaluates the branch condition
            continue  # skips to the next loop iteration
        days = (end - start).total_seconds() / 86400.0  # runs the total_seconds() call
        if days >= 0:  # evaluates the branch condition
            durations.append(days)  # adds an item to the list
    return round(statistics.median(durations), 1) if durations else None  # returns the round to the caller


def _trend_label(recent: float, prior: float) -> str:  # defines the _trend_label() function
    """Compare the last four weeks of commit activity with the four before."""  # keeps the docstring text
    if recent <= 0 and prior <= 0:  # evaluates the branch condition
        return "dormant"  # returns the value to the caller
    if prior <= 0:  # evaluates the branch condition
        return "restarting"  # returns the value to the caller
    ratio = recent / prior  # copies the recent value into ratio
    if ratio >= 1.3:  # evaluates the branch condition
        return "accelerating"  # returns the value to the caller
    if ratio <= 0.7:  # evaluates the branch condition
        return "slowing"  # returns the value to the caller
    return "steady"  # returns the value to the caller


# ---------------------------------------------------------------------------
# Summariser
# ---------------------------------------------------------------------------


def summarize(raw: dict[str, Any] | None, now: Any = None) -> dict[str, Any]:  # defines the summarize() function
    """Convert raw GitHub API material into clean Care-and-Feeding numbers."""  # keeps the docstring text
    raw = raw or {}  # copies the raw value into raw
    moment = _now(now)  # runs the _now() call

    weeks: list[dict[str, Any]] = []  # evaluates the weeks expression
    for item in raw.get("commit_activity") or []:  # loops over the collection
        if isinstance(item, dict) and item.get("week"):  # evaluates the branch condition
            weeks.append(item)  # adds an item to the list
    weeks.sort(key=lambda item: item["week"])  # sorts the values
    weekly_total = sum(int(item.get("total") or 0) for item in weeks)  # adds up the values

    def weeks_within(max_age: float) -> int:  # defines the weeks_within() function
        count = 0  # assigns the computed value to count
        for item in weeks:  # loops over the collection
            age = _age_days(item["week"], moment)  # runs the _age_days() call
            if age is not None and age <= max_age:  # evaluates the branch condition
                count += int(item.get("total") or 0)  # runs the int() call
        return count  # returns the count to the caller

    recent_avg = round(weeks_within(28) / 4.0, 1)  # runs the round() call
    prior_total = sum(  # adds up the values
        int(item.get("total") or 0)  # runs the int() call
        for item in weeks  # loops over the collection
        if 28 < (_age_days(item["week"], moment) or -1) <= 56  # evaluates the branch condition
    )  # closes the multiline block
    prior_avg = round(prior_total / 4.0, 1)  # runs the round() call

    release_stamps = [  # assigns the computed value to release_stamps
        item.get("published_at") or item.get("created_at")  # fetches the value
        for item in (raw.get("releases") or [])  # loops over the collection
        if (item.get("published_at") or item.get("created_at"))  # evaluates the branch condition
    ]  # closes the multiline block
    last_release = release_stamps[0] if release_stamps else ""  # copies the release_stamps value into last_release
    year_ago = moment.timestamp() - 365 * 86400  # runs the timestamp() call
    releases_last_year = sum(  # adds up the values
        1  # executes the statement
        for stamp in release_stamps  # loops over the collection
        if (_parse_datetime(stamp) or datetime.min.replace(tzinfo=timezone.utc)).timestamp()  # evaluates the branch condition
        >= year_ago  # executes the statement
    )  # closes the multiline block

    oldest_pr = raw.get("oldest_open_pr") or {}  # fetches the value
    oldest_issue = raw.get("oldest_open_issue") or {}  # fetches the value
    recent_authors = [author for author in (raw.get("recent_commit_authors") or []) if author]  # fetches the value
    author_counts = [recent_authors.count(name) for name in set(recent_authors)]  # gathers the values into a set

    return {  # returns the value to the caller
        "last_commit_at": raw.get("last_commit_at") or "",  # maps the last_commit_at dictionary entry
        "last_commit_days": _age_days(raw.get("last_commit_at"), moment),  # maps the last_commit_days dictionary entry
        "last_release_at": last_release,  # maps the last_release_at dictionary entry
        "last_release_days": _age_days(last_release, moment),  # maps the last_release_days dictionary entry
        "release_count": len(release_stamps),  # maps the release_count dictionary entry
        "releases_last_year": releases_last_year,  # maps the releases_last_year dictionary entry
        "median_release_gap_days": _median_gap_days(release_stamps),  # maps the median_release_gap_days dictionary entry
        "commit_frequency_per_week": round(weekly_total / max(1, len(weeks)), 2)  # maps the commit_frequency_per_wee dictionary entry
        if weekly_total  # evaluates the branch condition
        else 0.0,  # covers the remaining branch
        "commits_last_year": weekly_total,  # maps the commits_last_year dictionary entry
        "commits_last_7d": weeks_within(7),  # maps the commits_last_7d dictionary entry
        "commits_last_30d": weeks_within(30),  # maps the commits_last_30d dictionary entry
        "commits_last_90d": weeks_within(91),  # maps the commits_last_90d dictionary entry
        "development_trend": _trend_label(recent_avg, prior_avg),  # maps the development_trend dictionary entry
        "weekly_avg_recent": recent_avg,  # maps the weekly_avg_recent dictionary entry
        "weekly_avg_prior": prior_avg,  # maps the weekly_avg_prior dictionary entry
        "open_pull_requests": raw.get("open_pull_requests"),  # maps the open_pull_requests dictionary entry
        "oldest_open_pr_days": _age_days(oldest_pr.get("created_at"), moment)  # maps the oldest_open_pr_days dictionary entry
        if oldest_pr  # evaluates the branch condition
        else None,  # covers the remaining branch
        "oldest_open_pr_title": oldest_pr.get("title") or "",  # maps the oldest_open_pr_title dictionary entry
        "oldest_open_pr_url": oldest_pr.get("html_url") or "",  # maps the oldest_open_pr_url dictionary entry
        "oldest_open_issue_days": _age_days(oldest_issue.get("created_at"), moment)  # maps the oldest_open_issue_days dictionary entry
        if oldest_issue  # evaluates the branch condition
        else None,  # covers the remaining branch
        "oldest_open_issue_title": oldest_issue.get("title") or "",  # maps the oldest_open_issue_title dictionary entry
        "oldest_open_issue_url": oldest_issue.get("html_url") or "",  # maps the oldest_open_issue_url dictionary entry
        "median_issue_close_days": _pair_median(  # maps the median_issue_close_days dictionary entry
            raw.get("closed_issues_sample") or [], "created_at", ("closed_at",)  # fetches the value
        ),  # closes the multiline block
        "issues_closed_sampled": len(raw.get("closed_issues_sample") or []),  # maps the issues_closed_sampled dictionary entry
        "median_pr_close_days": _pair_median(  # maps the median_pr_close_days dictionary entry
            raw.get("closed_prs_sample") or [], "created_at", ("merged_at", "closed_at")  # fetches the value
        ),  # closes the multiline block
        "prs_closed_sampled": len(raw.get("closed_prs_sample") or []),  # maps the prs_closed_sampled dictionary entry
        "contributors": raw.get("contributors"),  # maps the contributors dictionary entry
        "contributors_recent": len(set(recent_authors)),  # maps the contributors_recent dictionary entry
        "recent_commits_sampled": len(recent_authors),  # maps the recent_commits_sampled dictionary entry
        "top_contributor_share": round(max(author_counts) / len(recent_authors), 2)  # maps the top_contributor_share dictionary entry
        if author_counts  # evaluates the branch condition
        else None,  # covers the remaining branch
        "pct_commits_last_7d": round(100 * weeks_within(7) / weekly_total, 1)  # maps the pct_commits_last_7d dictionary entry
        if weekly_total  # evaluates the branch condition
        else None,  # covers the remaining branch
        "pct_commits_last_30d": round(100 * weeks_within(30) / weekly_total, 1)  # maps the pct_commits_last_30d dictionary entry
        if weekly_total  # evaluates the branch condition
        else None,  # covers the remaining branch
        "pct_commits_last_90d": round(100 * weeks_within(91) / weekly_total, 1)  # maps the pct_commits_last_90d dictionary entry
        if weekly_total  # evaluates the branch condition
        else None,  # covers the remaining branch
        "notes": list(raw.get("errors") or []),  # maps the notes dictionary entry
    }  # closes the multiline block


def trend_detail(summary: dict[str, Any]) -> str:  # defines the trend_detail() function
    """One-line expansion of the development-trend verdict."""  # keeps the docstring text
    trend = summary.get("development_trend", "")  # fetches the value
    recent = summary.get("weekly_avg_recent")  # fetches the value
    prior = summary.get("weekly_avg_prior")  # fetches the value
    if not trend:  # evaluates the branch condition
        return "not computable (no commit-history data)"  # returns the value to the caller
    if trend == "dormant":  # evaluates the branch condition
        return "no meaningful commit activity in the last several weeks"  # returns the value to the caller
    if trend == "restarting":  # evaluates the branch condition
        return f"coming back to life (~{recent:g} commits/week after a quiet stretch)"  # returns the f to the caller
    return f"~{recent:g}/week now vs ~{prior:g}/week in the four weeks before ({trend})"  # returns the f to the caller


def _trim(text: Any, limit: int) -> str:  # defines the _trim() function
    """Shared single-ellipsis clip (see :mod:`textutil`)."""  # keeps the docstring text
    return textutil.clip_raw(text, limit)  # returns the clipped value


def _days_text(days: Any) -> str:  # defines the _days_text() function
    """Ages render as whole days once they're roomy; fine-grained when fresh."""  # keeps the docstring text
    if days is None:  # evaluates the branch condition
        return ""  # returns the value to the caller
    if days >= 14:  # evaluates the branch condition
        return f"{int(round(days))}"  # returns the f to the caller
    return f"{days:g}"  # returns the f to the caller


def _ago_suffix(days: Any) -> str:  # defines the _ago_suffix() function
    if days is None:  # evaluates the branch condition
        return ""  # returns the value to the caller
    return f"  ({_days_text(days)} days ago)"  # returns the f to the caller


def render_pairs(summary: dict[str, Any]) -> list[tuple[str, str]]:  # defines the render_pairs() function
    """Care-and-Feeding rows as ``(label, value)`` pairs (missing data is skipped).

    The single layout source the text, the print/PDF and the report-pane
    renderers share: the value column carries the full sentence including any
    ``"  ·  "`` separated clauses, empty labels mark full-width rows (the
    time-to-close disclaimer and API error notes), and skipped fields simply
    produce no pair. :func:`render_summarized` pads these into today's
    fixed-width text lines, so the two views cannot drift apart.
    """  # keeps the docstring text
    pairs: list[tuple[str, str]] = []  # the labelled rows the renderers walk

    if summary.get("last_commit_at"):  # evaluates the branch condition
        pairs.append(  # adds a labelled row
            (  # executes the statement
                "Last commit",  # the fixed-width label column
                f"{str(summary['last_commit_at'])[:10]}"  # runs the str() call
                f"{_ago_suffix(summary.get('last_commit_days'))}",  # runs the _ago_suffix() call
            )  # closes the pair
        )  # closes the append

    if summary.get("last_release_at"):  # evaluates the branch condition
        extra_bits = ["~%g days between releases" % summary["median_release_gap_days"]] if summary.get("median_release_gap_days") else []  # fetches the value
        if summary.get("releases_last_year") is not None:  # evaluates the branch condition
            count = summary["releases_last_year"]  # copies the summary value into count
            extra_bits.insert(  # inserts text or data
                0,  # executes the statement
                f"{count} release{'s' if count != 1 else ''} in the last 12 months",  # evaluates the f expression
            )  # closes the multiline block
        extra = ("  ·  " + "  ·  ".join(extra_bits)) if extra_bits else ""  # waits for the thread
        pairs.append(  # adds a labelled row
            (  # executes the statement
                "Last release",  # the fixed-width label column
                f"{str(summary['last_release_at'])[:10]}"  # runs the str() call
                f"{_ago_suffix(summary.get('last_release_days'))}{extra}",  # runs the _ago_suffix() call
            )  # closes the pair
        )  # closes the append
    elif summary.get("release_count") == 0 and not summary.get("notes"):  # checks the alternate condition
        pairs.append(("Last release", "none found on this repository"))  # adds the honest empty row

    if summary.get("commits_last_year") is not None:  # evaluates the branch condition
        pairs.append(  # adds a labelled row
            (  # executes the statement
                "Commit frequency",  # the fixed-width label column
                f"~{summary.get('commit_frequency_per_week', 0):g} per week "  # fetches the value
                f"({summary.get('commits_last_year', 0)} commits in the last 52 weeks)",  # fetches the value
            )  # closes the pair
        )  # closes the append
        pairs.append(("Development trend", trend_detail(summary)))  # the verdict expansion

    if summary.get("open_pull_requests") is not None:  # evaluates the branch condition
        oldest = ""  # sets the oldest text
        if summary.get("oldest_open_pr_days") is not None:  # evaluates the branch condition
            title = _trim(summary.get("oldest_open_pr_title") or "untitled", 44)  # runs the _trim() call
            oldest = (  # assigns the computed value to oldest
                f"  ·  oldest: \"{title}\" is {_days_text(summary['oldest_open_pr_days'])} days old"  # maps the   ·  oldest: \ dictionary entry
            )  # closes the multiline block
        pairs.append(  # adds a labelled row
            (  # executes the statement
                "Open pull requests",  # the fixed-width label column
                f"{summary['open_pull_requests']}{oldest}",  # the count with the oldest note
            )  # closes the pair
        )  # closes the append

    if summary.get("oldest_open_issue_days") is not None:  # evaluates the branch condition
        title = _trim(summary.get("oldest_open_issue_title") or "untitled", 44)  # runs the _trim() call
        pairs.append(  # adds a labelled row
            (  # executes the statement
                "Oldest open issue",  # the fixed-width label column
                f"\"{title}\" is "  # supplies the literal text
                f"{_days_text(summary['oldest_open_issue_days'])} days old",  # runs the _days_text() call
            )  # closes the pair
        )  # closes the append

    if summary.get("median_issue_close_days") is not None:  # evaluates the branch condition
        pairs.append(  # adds a labelled row
            (  # executes the statement
                "Issue response time",  # the fixed-width label column
                f"median {summary['median_issue_close_days']:g} days "  # evaluates the f expression
                f"from open to closure ({summary.get('issues_closed_sampled', 0)} closed issues tracked)",  # runs the closure() call
            )  # closes the pair
        )  # closes the append
    if summary.get("median_pr_close_days") is not None:  # evaluates the branch condition
        pairs.append(  # adds a labelled row
            (  # executes the statement
                "PR response time",  # the fixed-width label column
                f"median {summary['median_pr_close_days']:g} days "  # evaluates the f expression
                f"from open to merge or close ({summary.get('prs_closed_sampled', 0)} PRs tracked)",  # runs the close() call
            )  # closes the pair
        )  # closes the append
    if summary.get("median_issue_close_days") or summary.get("median_pr_close_days"):  # evaluates the branch condition
        pairs.append(  # adds the full-width disclaimer row
            (  # executes the statement
                "",  # no label: this row spans the whole line
                "  -  note: time-to-close stands in for first-response time; paging every "  # supplies the literal text
                "issue's comments for the first reply would need dozens of extra API calls, "  # supplies the literal text
                "so closure is the honest, cheap proxy",  # supplies the literal text
            )  # closes the pair
        )  # closes the append

    if summary.get("contributors") is not None:  # evaluates the branch condition
        bits = []  # assigns the computed value to bits
        if summary.get("contributors_recent"):  # evaluates the branch condition
            bits.append(  # adds an item to the list
                f"{summary['contributors_recent']} different authors in the last "  # evaluates the f expression
                f"{summary.get('recent_commits_sampled', RECENT_COMMITS_SAMPLE)} commits"  # fetches the value
            )  # closes the multiline block
        if summary.get("top_contributor_share") is not None:  # evaluates the branch condition
            bits.append(  # adds an item to the list
                f"busiest author did {int(summary['top_contributor_share'] * 100)}% of them"  # runs the int() call
            )  # closes the multiline block
        extra = ("  ·  " + "  ·  ".join(bits)) if bits else ""  # waits for the thread
        pairs.append(  # adds a labelled row
            (  # executes the statement
                "Contributor activity",  # the fixed-width label column
                f"{summary['contributors']} contributors total{extra}",  # the total with the recent note
            )  # closes the pair
        )  # closes the append

    parts = []  # assigns the computed value to parts
    for key, label in (  # loops over the collection
        ("pct_commits_last_7d", "7d"),  # executes the statement
        ("pct_commits_last_30d", "30d"),  # executes the statement
        ("pct_commits_last_90d", "90d"),  # executes the statement
    ):  # closes the multiline block
        if summary.get(key) is not None:  # evaluates the branch condition
            parts.append(f"{summary[key]:g}% in {label}")  # adds an item to the list
    if parts:  # evaluates the branch condition
        pairs.append(  # adds a labelled row
            (  # executes the statement
                "Commit recency",  # the fixed-width label column
                "  ·  ".join(parts)  # waits for the thread
                + "  ·  share of the last 12 months' commits",  # executes the statement
            )  # closes the pair
        )  # closes the append

    for note in summary.get("notes") or []:  # loops over the collection
        pairs.append(("", f"- {note}"))  # adds the full-width API-error note

    return pairs  # returns the rows to the caller


def render_summarized(summary: dict[str, Any]) -> list[str]:  # defines the render_summarized() function
    """Human-readable Care-and-Feeding lines (see :func:`render_pairs`)."""  # keeps the docstring text
    lines: list[str] = []  # evaluates the lines expression
    for label, value in render_pairs(summary):  # walks the shared rows
        lines.append(f"{label:<23}{value}" if label else value)  # pads labelled rows, keeps full-width rows verbatim
    return lines  # returns the lines to the caller
