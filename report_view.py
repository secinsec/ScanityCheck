"""Pure report-layout builder for the ScanityCheck report pane.

``build_report_segments`` turns one finished scan report into an ordered
list of (text, tags) segments; the Tk layer only inserts them. Nothing
here touches a widget, so the layout is unit-testable, cacheable and
re-used on every tab switch. ``batch_segments`` merges consecutive
segments that share the same style tags into a single blob, which turns
hundreds of per-segment Tk insert calls into a handful per render.
"""

from __future__ import annotations  # imports annotations from the __future__ module

from typing import Any, Callable  # imports the typing names

import config  # imports the config module (tool registry, product strings)
import care  # imports the care module (maintenance statistics)
import scoring  # imports the scoring module (labels, wrapping, ranking)

# One (text, tags) cell.``text`` is normally a str; the app embeds live
# checkbox rows by passing a segment shaped (None, widget) which batches
# must carry through untouched.
Segment = tuple[Any, Any]  # the alias every builder below returns

# The app's hook: (omission key, currently ticked) -> segments to splice in.
CheckboxHook = Callable[[str, bool], list[Segment]]  # the callback type

REPORT_TABLE_ORDER = (  # the rows of the points table, in print order
    "vulnerability",  # the biggest weighted block
    "secret",  # committed credentials
    "misconfiguration",  # IaC and containers
    "code",  # code-level security findings
    "license",  # FOSSology licence findings, printed when present
    "code-quality",  # printed only when it has findings
)  # closes the tuple


def _tag_key(tags: Any) -> str | tuple[str, ...] | None:  # defines the _tag_key() helper
    """Hashable identity of a tag set; ``None`` marks run-breaking items."""
    if isinstance(tags, str):  # a bare string is one tag name on insert
        return (tags,)  # normalises so equal strings and 1-tuples merge
    if isinstance(tags, tuple):  # the ordinary case: a tuple of tag names
        try:  # watches for exotic (unhashable) members
            return tuple(tags)  # the hashable identity
        except TypeError:  # handles the raised error
            return None  # do not merge anything exotic
    return None  # widget slots and everything else never merge


def batch_segments(segments: list[Segment]) -> list[Segment]:  # defines the batch_segments() function
    """Coalesces consecutive same-tag text segments into one insert blob.

    ``Tk.Text.insert`` appends text exactly as given, so joining a run of
    same-tag segments with ``"".join`` yields a byte-identical layout —
    today's per-segment newlines stay inside their own texts and nothing
    gains or loses spacing. Widget embeddings and differing tag sets
    still insert separately, in order.
    """
    batched: list[Segment] = []  # the insert list the caller writes
    run_text: list[str] = []  # texts pooled into the pending run
    run_key: str | tuple[str, ...] | None = None  # identity of the pending run
    run_tags: Any = ()  # the original tags object, replayed on insert

    def flush() -> None:  # defines the small inline helper
        """Commits the pending run, if any, into the batched list."""
        nonlocal run_key  # the helper rebinds the run identity
        if run_key is not None and run_text:  # text runs insert as one blob
            batched.append(("".join(run_text), run_tags))  # same tags, exact texts
        run_text.clear()  # resets the pooled texts
        run_key = None  # closes the run

    for text, tags in segments:  # walks the composed order
        key = _tag_key(tags) if isinstance(text, str) else None  # only str text pools
        if key is None or key != run_key:  # a new style or a widget breaks the run
            flush()  # commits whatever was pooling
            if key is None:  # widget slot (or exotic pair): pass through solo
                batched.append((text, tags))  # order preserved exactly
            else:  # plain text: open a fresh run
                run_key = key  # remembers the run identity
                run_tags = tags  # replays the original tags object
                run_text.append(text)  # pools the first text
        else:  # same tags as the open run
            run_text.append(text)  # pools into the run
    flush()  # closes the final run
    return batched  # returns the coalesced list


def _care_rows(summary: dict[str, Any]) -> list[tuple[str | None, str]]:  # defines the _care_rows() function
    """Care data as (heading, value) pairs; the legacy strings use ``None``."""
    render = getattr(care, "render_pairs", None)  # the structured view when the care module offers it
    if callable(render):  # only trusts a present callable
        try:  # a broken pair view must not kill the report render
            pairs = render(summary)  # the care agent's structured output
        except Exception:  # handles the raised error
            pairs = None  # falls back to the legacy line strings
        if isinstance(pairs, list):  # accepts only the promised shape
            return [(str(label), str(value)) for label, value in pairs]  # normalises to text pairs
    return [(None, line) for line in care.render_summarized(summary)]  # today's summarised string rows


def build_report_segments(  # defines the build_report_segments() function
    report: dict[str, Any],  # the finished scan report dictionary
    omitted_groups: Any = (),  # the risk themes the reviewer excluded
    connect_checkbox: CheckboxHook | None = None,  # the app's live-widget hook (absent in tests)
) -> list[Segment]:  # closes the signature
    """Composes the report pane's ordered (text, tags) segments.

    The optional ``connect_checkbox`` hook lets the app splice its live
    "Omit from Report" checkbox rows into the flow; without it (tests,
    plain-text previews) those rows are simply absent and the visible
    text matches the with-checkbox render.
    """
    repo = report.get("repo") or {}  # fetches the value
    omitted = set(omitted_groups)  # makes the exclusion set for membership tests
    segments: list[Segment] = []  # evaluates the segments expression

    segments.append((f"{repo.get('full_name', 'repository')}\n", ("title",)))  # adds an item to the list
    subtitle = repo.get("description") or ""  # fetches the value
    bits = []  # assigns the computed value to bits
    if repo.get("branch"):  # evaluates the branch condition
        bits.append(f"branch {repo['branch']}")  # adds an item to the list
    if repo.get("file_count"):  # evaluates the branch condition
        bits.append(f"{repo['file_count']} files")  # adds an item to the list
    if report.get("languages"):  # evaluates the branch condition
        bits.append("languages: " + ", ".join(report["languages"]))  # adds an item to the list
    if subtitle:  # evaluates the branch condition
        segments.append((subtitle + "\n", ("subtitle",)))  # adds an item to the list
    if bits:  # evaluates the branch condition
        segments.append(("  ·  ".join(bits) + "\n", ("muted",)))  # adds an item to the list

    verdict_tag = "verdict_ok" if report["verdict"] == "SECURE" else "verdict_bad"  # sets the verdict_tag text
    segments.append((f"\nVERDICT: {report['verdict']}\n", (verdict_tag,)))  # adds an item to the list
    segments.append((f"{report['verdict_reason']}\n", ("body",)))  # adds an item to the list

    confidence = report.get("confidence") or {}  # fetches the value
    if confidence:  # evaluates the branch condition
        segments.append(  # adds an item to the list
            (  # executes the statement
                f"\nCONFIDENCE: {confidence['score']}/100  ({confidence['band']})\n",  # evaluates the f expression
                ("body",),  # executes the statement
            )  # closes the multiline block
        )  # closes the multiline block
        for factor in confidence.get("factors") or []:  # loops over the collection
            segments.append(  # adds an item to the list
                (  # executes the statement
                    f"   {factor['label']:<26}"  # evaluates the f expression
                    f"{('#'*int(round(factor['score']/10))).ljust(10, '.')} "  # runs the int() call
                    f"{factor['score']:>3}%\n",  # evaluates the f expression
                    ("body",),  # executes the statement
                )  # closes the multiline block
            )  # closes the multiline block
        headline = confidence.get("headline") or ""  # fetches the value
        if headline:  # evaluates the branch condition
            segments.append((f"   {headline}\n", ("muted",)))  # adds an item to the list
        for note in confidence.get("notes") or []:  # loops over the collection
            segments.append((f"   - {note}\n", ("muted",)))  # adds an item to the list

    segments.append(("\nWHAT THE SCORE MEANS\n", ("h",)))  # adds an item to the list
    for line in scoring.wrap_text(report["explanation"], 104):  # loops over the collection
        segments.append((line + "\n", ("body",)))  # adds an item to the list

    segments.append(("\nWHERE THE POINTS WENT\n", ("h",)))  # adds an item to the list
    header = f"{'Category':<34}{'Findings':>9}{'Penalty':>10}{'Cap':>8}\n"  # sets the header text
    segments.append((header, ("muted",)))  # adds an item to the list
    for category in REPORT_TABLE_ORDER:  # loops over the collection
        count = sum(report["counts"][category].values())  # adds up the values
        if category in ("code-quality", "license") and count == 0:  # evaluates the branch condition
            continue  # skips to the next loop iteration
        label = scoring.CATEGORY_LABELS[category]  # the public registry, not a report-embedded copy
        row = (  # assigns the computed value to row
            f"{label:<34}{count:>9}{report['penalties'][category]:>10.1f}"  # evaluates the f expression
            f"{report['caps'][category]:>8.0f}\n"  # evaluates the f expression
        )  # closes the multiline block
        segments.append((row, ("body",)))  # adds an item to the list
    total_penalty = sum(report["penalties"].values())  # adds up the values
    segments.append(  # adds an item to the list
        (  # executes the statement
            f"{'TOTAL':<34}{report['totals']['findings']:>9}{total_penalty:>10.1f}\n",  # evaluates the f expression
            ("body",),  # executes the statement
        )  # closes the pair
    )  # closes the multiline block
    context = report.get("context") or {}  # the persisted normalisation summary
    for category, factor_block in (context.get("factors") or {}).items():  # loops over the relieved categories
        label = scoring.CATEGORY_LABELS[category]  # the public registry, not a report-embedded copy
        bits: list[str] = []  # the context parts worth naming
        if context.get("packages") and category == "vulnerability":  # evaluates the branch condition
            bits.append(f"{context['packages']} packages")  # the dependency-surface note
        if context.get("files") and category == "code":  # evaluates the branch condition
            bits.append(f"{context['files']} files")  # the codebase note
        if factor_block.get("pulse"):  # evaluates the branch condition
            bits.append(f"maintenance pulse {factor_block['pulse']:g}")  # the Care note
        if bits:  # evaluates the branch condition
            segments.append(  # adds an item to the list
                (  # executes the statement
                    f"- {label} cap relieved x{factor_block['factor']:g} "  # supplies the literal text
                    f"({', '.join(bits)}): cap {report['caps'][category]:g} of "  # supplies the literal text
                    f"{config.CAPS[category]:g}\n",  # the plain ceiling for contrast
                    ("muted",),  # executes the statement
                )  # closes the pair
            )  # closes the multiline block

    dedupe = report.get("dedupe") or {}  # fetches the value
    if dedupe.get("raw", 0) > 0 and (dedupe.get("removed", 0) or dedupe.get("corroborated", 0)):  # evaluates the branch condition
        segments.append(("\nDE-DUPLICATION\n", ("h",)))  # adds an item to the list
        segments.append(  # adds an item to the list
            (  # executes the statement
                f"{dedupe['raw']} raw tool findings collapsed into {dedupe['merged']} "  # evaluates the f expression
                f"unique issues ({dedupe['removed']} duplicate report(s) removed; "  # runs the issues() call
                f"{dedupe['corroborated']} corroborated by 2+ tools). "  # evaluates the f expression
                "Each unique issue is charged once.\n",  # supplies the literal text
                ("body",),  # executes the statement
            )  # closes the multiline block
        )  # closes the multiline block

    inventory = report.get("inventory")  # fetches the value
    if inventory:  # evaluates the branch condition
        segments.append(("\nSBOM INVENTORY (SYFT)\n", ("h",)))  # adds an item to the list
        ecosystems = inventory.get("ecosystems") or {}  # fetches the value
        eco_text = ", ".join(f"{key} {value}" for key, value in ecosystems.items()) or "none"  # sets the eco_text text
        segments.append(  # adds an item to the list
            (  # executes the statement
                f"{inventory.get('components', 0)} components catalogued ({eco_text}); "  # fetches the value
                f"{inventory.get('unversioned', 0)} without a resolved version.\n",  # fetches the value
                ("body",),  # executes the statement
            )  # closes the multiline block
        )  # closes the multiline block
        for component in (inventory.get("top_packages") or [])[:10]:  # loops over the collection
            version = component.get("version") or "?"  # fetches the value
            segments.append(  # adds an item to the list
                (  # executes the statement
                    f"  {component.get('name') or '?'} {version}  "  # fetches the value
                    f"({component.get('type') or 'package'})\n",  # fetches the value
                    ("muted",),  # executes the statement
                )  # closes the multiline block
            )  # closes the multiline block

    care_rows = _care_rows(report.get("care") or {})  # pairs when care can produce them, plain lines otherwise
    if care_rows:  # evaluates the branch condition
        segments.append(("\nCARE AND FEEDING (repository maintenance)\n", ("h",)))  # adds an item to the list
        for label, value in care_rows:  # loops over the rows
            if label is None:  # legacy string row: keep today's tag heuristic
                text, tag = value, ("muted",) if value.startswith("- ") else ("body",)  # adds the row
            elif label:  # a labelled pair row
                text, tag = f"{label}: {value}", ("body",)  # the label/dialogue column
            else:  # an empty label marks a full-width sentence row
                text, tag = value, ("muted",) if value.startswith("- ") else ("body",)  # adds the row
            segments.append((text + "\n", tag))  # adds the row

    segments.append(("\nGREATEST RISKS IDENTIFIED\n", ("h",)))  # adds an item to the list
    segments.append((  # the reviewer disclaimer the feature needs
        "Select the checkbox next to findings that have been mitigated within "  # supplies the literal text
        "your host environment. Scan findings should only be excluded from the "  # supplies the literal text
        "final report upon verified confirmation that the associated "  # supplies the literal text
        "vulnerabilities have been remediated.\n\n", ("muted",),  # keeps the tone soft
    ))  # closes the disclaimer block
    risks = report.get("greatest_risks") or []  # fetches the value
    if not risks:  # evaluates the branch condition
        segments.append(("No security findings were reported.\n", ("muted",)))  # adds an item to the list
    for index, risk in enumerate(risks, 1):  # loops over the collection
        suffix = f"  (x{risk['count']})" if risk["count"] > 1 else ""  # sets the suffix text
        severity = risk["severity"]  # copies the risk value into severity
        key = risk.get("key") or ""  # the stable omission key of this theme
        if key and connect_checkbox is not None:  # tickable only when the theme has a stable key
            segments.extend(connect_checkbox(key, key in omitted))  # splices the live checkbox row in
        header_tag = ("muted",) if risk.get("omitted") else ("body",)  # dims the excluded row
        segments.append((f"{index}. [{severity.upper()}] ", ("body", f"sev_{severity}")))  # the risk rows start on their own line
        penalty_note = f"{risk['title']}{suffix}   \u2212{risk['penalty']:.1f} pts"  # builds the penalty line
        if risk.get("omitted"):  # evaluates the branch condition
            credited = risk.get("refund") if risk.get("refund") is not None else 0.0  # the credited points
            penalty_note += f"   [excluded \u00b7 \u2212{credited:.1f} pts credited]"  # the true refund, capped maths included
        segments.append((penalty_note + "\n", header_tag))  # adds the row text
        meta = scoring.CATEGORY_LABELS.get(risk["category"], risk["category"])  # the public registry, not a report-embedded copy
        segments.append((f"   {meta}  ·  {risk['rule_id']}\n", ("muted",)))  # adds an item to the list
        tool_labels = risk.get("tool_labels") or []  # fetches the value
        if tool_labels:  # evaluates the branch condition
            segments.append(  # adds an item to the list
                (f"   Identified by: {', '.join(tool_labels)}\n", ("muted",))  # waits for the thread
            )  # closes the multiline block
        if risk.get("detail"):  # evaluates the branch condition
            for line in scoring.wrap_text(risk["detail"], 100):  # loops over the collection
                segments.append((f"   {line}\n", ("muted",)))  # adds an item to the list
        for location in risk.get("locations") or []:  # loops over the collection
            segments.append((f"   \u2192 {location}\n", ("loc",)))  # adds an item to the list
        if risk.get("reference"):  # evaluates the branch condition
            segments.append((f"   \u2192 {risk['reference']}\n", ("link",)))  # adds an item to the list
        segments.append(("\n", ("body",)))  # adds an item to the list

    totals = report["totals"]  # copies the report value into totals
    segments.append(("\nFINDINGS BY SEVERITY\n", ("h",)))  # adds an item to the list
    segments.append(  # adds an item to the list
        (  # executes the statement
            f"Critical {totals['critical']}    High {totals['high']}    "  # evaluates the f expression
            f"Medium {totals['medium']}    Low {totals['low']}    "  # evaluates the f expression
            f"Unknown {totals['unknown']}\n",  # evaluates the f expression
            ("body",),  # executes the statement
        )  # closes the multiline block
    )  # closes the multiline block

    segments.append(("\nFINDINGS BY TOOL\n", ("h",)))  # adds an item to the list
    by_tool = report.get("by_tool") or {}  # fetches the value
    tool_labels = report.get("tool_labels") or {}  # fetches the value
    if not by_tool:  # evaluates the branch condition
        segments.append(("No scanner produced findings.\n", ("muted",)))  # adds an item to the list
    else:  # covers the remaining branch
        segments.append(  # adds an item to the list
            (  # executes the statement
                f"{'Tool':<16}{'Critical':>9}{'High':>6}{'Medium':>8}"  # evaluates the f expression
                f"{'Low':>6}{'Total':>7}\n",  # evaluates the f expression
                ("muted",),  # executes the statement
            )  # closes the multiline block
        )  # closes the multiline block
        for name, stats in by_tool.items():  # loops over the collection
            label = tool_labels.get(name, config.TOOL_LABELS.get(name, name.title()))  # fetches the value
            segments.append(  # adds an item to the list
                (  # executes the statement
                    f"{label:<16}{stats.get('critical', 0):>9}{stats.get('high', 0):>6}"  # fetches the value
                    f"{stats.get('medium', 0):>8}{stats.get('low', 0):>6}"  # fetches the value
                    f"{stats.get('total', 0):>7}\n",  # fetches the value
                    ("body",),  # executes the statement
                )  # closes the multiline block
            )  # closes the multiline block
        segments.append(  # adds an item to the list
            (  # executes the statement
                "A finding confirmed by several tools is listed for each of them but "  # supplies the literal text
                "counts once in the score.\n",  # supplies the literal text
                ("muted",),  # executes the statement
            )  # closes the multiline block
        )  # closes the multiline block

    frameworks = report.get("frameworks") or {}  # fetches the value
    if frameworks:  # evaluates the branch condition
        segments.append(("\nCOMPLIANCE FRAMEWORK MAPPING\n", ("h",)))  # adds an item to the list
        segments.append(  # adds an item to the list
            (  # executes the statement
                "'affected' = findings touch this control this run. 'clear' = scanned and "  # executes the statement
                "found nothing here, never proof of compliance.\n",  # supplies the literal text
                ("muted",),  # executes the statement
            )  # closes the multiline block
        )  # closes the multiline block
        for entry in frameworks.values():  # loops over the collection
            segments.append(  # adds an item to the list
                (  # executes the statement
                    f"\n{entry['label']}: "  # evaluates the f expression
                    f"{entry['affected_controls']} of {entry['total_controls']} controls "  # evaluates the f expression
                    f"touched"  # supplies the literal text
                    + (  # executes the statement
                        f"  ·  {entry['unmapped']} finding(s) outside the map"  # runs the finding() call
                        if entry["unmapped"]  # evaluates the branch condition
                        else ""  # covers the remaining branch
                    )  # closes the multiline block
                    + "\n",  # executes the statement
                    ("body",),  # executes the statement
                )  # closes the multiline block
            )  # closes the multiline block
            for control in entry["controls"]:  # loops over the collection
                if control["status"] != "affected":  # evaluates the branch condition
                    continue  # skips to the next loop iteration
                severity = control.get("worst") or ""  # fetches the value
                segments.append(  # adds an item to the list
                    (f"  [{severity.upper():<8}] ", ("body", f"sev_{severity.lower()}" if severity else "body"))  # uppercases the text
                )  # closes the multiline block
                segments.append(  # adds an item to the list
                    (  # executes the statement
                        f"{control['id']:<14} {control['title'][:70]}  "  # evaluates the f expression
                        f"·  {control['affected']} finding(s)\n",  # runs the finding() call
                        ("body",),  # executes the statement
                    )  # closes the multiline block
                )  # closes the multiline block
                for example in control.get("examples") or []:  # loops over the collection
                    segments.append((f"        - {example}\n", ("muted",)))  # adds an item to the list
            cleared = [  # assigns the computed value to cleared
                control for control in entry["controls"] if control["status"] == "clear"  # evaluates the control expression
            ]  # closes the multiline block
            if cleared:  # evaluates the branch condition
                ids = ", ".join(control["id"] for control in cleared)  # sets the ids text
                segments.append((f"  clear (no findings in this run): {ids}\n", ("muted",)))  # adds an item to the list

    findings = report.get("findings") or []  # fetches the value
    if findings:  # evaluates the branch condition
        shown = findings[: config.MAX_LISTED_FINDINGS]  # copies the findings value into shown
        segments.append(  # adds an item to the list
            (  # executes the statement
                f"\nALL FINDINGS  ({len(shown)} of {len(findings)} shown, worst first)\n",  # supplies the literal text
                ("h",),  # executes the statement
            )  # closes the multiline block
        )  # closes the multiline block
        ordered = sorted(  # sorts the values
            shown,  # evaluates the shown expression
            key=lambda item: (  # copies the lambda value into key
                scoring.severity_rank(item.get("severity", "unknown")),  # runs the severity_rank() call
                item.get("category", ""),  # fetches the value
                item.get("location", ""),  # fetches the value
            ),  # closes the multiline block
        )  # closes the multiline block
        for item in ordered:  # loops over the collection
            severity = str(item.get("severity", "unknown")).lower()  # runs the str() call
            title = str(item.get("title") or item.get("rule_id") or "")  # runs the str() call
            if len(title) > 64:  # evaluates the branch condition
                title = title[:63] + "\u2026"  # copies the title value into title
            tools_text = ", ".join(item.get("tool_labels") or [])  # sets the tools_text text
            location = item.get("location") or "location not reported"  # fetches the value
            segments.append(  # adds an item to the list
                (f"[{severity.upper():<8}] ", ("body", f"sev_{severity}"))  # uppercases the text
            )  # closes the multiline block
            segments.append(  # adds an item to the list
                (f"{title:<64}  ·  {tools_text}  ·  {location}\n", ("body",))  # executes the statement
            )  # closes the multiline block
        if len(findings) > len(shown):  # evaluates the branch condition
            segments.append(  # adds an item to the list
                (  # executes the statement
                    f"\u2026 {len(findings) - len(shown)} more findings are in the JSON report.\n",  # supplies the literal text
                    ("muted",),  # executes the statement
                )  # closes the multiline block
            )  # closes the multiline block

    segments.append(("\nSCANNER COVERAGE\n", ("h",)))  # adds an item to the list
    labels = report.get("tool_labels") or {}  # fetches the value
    for name, status in (report.get("scanner_status") or {}).items():  # loops over the collection
        elapsed = status.get("duration_seconds")  # fetches the value
        elapsed_text = f"{elapsed:.1f}s" if isinstance(elapsed, (int, float)) else "n/a"  # sets the elapsed_text text
        label = labels.get(name, config.TOOL_LABELS.get(name, name.title()))  # fetches the value
        segments.append(  # adds an item to the list
            (f"{label:<14}{status.get('status', '?'):<9}{elapsed_text}\n", ("body",))  # fetches the value
        )  # closes the multiline block
        for detail in status.get("details") or []:  # loops over the collection
            segments.append((f"   · {detail}\n", ("muted",)))  # adds an item to the list

    if report.get("warnings"):  # evaluates the branch condition
        segments.append(("\nWARNINGS\n", ("h",)))  # adds an item to the list
        for warning in report["warnings"]:  # loops over the collection
            for line in scoring.wrap_text(warning, 100):  # loops over the collection
                segments.append((line + "\n", ("muted",)))  # adds an item to the list

    segments.append(  # adds an item to the list
        (  # executes the statement
            f"\nGenerated {report['generated_at']} by {config.APP_NAME} "  # evaluates the f expression
            f"{config.APP_VERSION}  ·  {report.get('duration_seconds', 0):.0f}s total\n",  # fetches the value
            ("mono_hint",),  # executes the statement
        )  # closes the multiline block
    )  # closes the multiline block
    return segments  # returns the composed order
