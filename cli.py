"""Headless runner - useful for CI or a quick check without the window.

    python cli.py https://github.com/owner/repo
    python cli.py https://github.com/owner/repo --json report.json
    python cli.py https://github.com/owner/repo --csv findings.csv --pdf report.pdf
    python cli.py https://github.com/owner/repo --tools trivy,codeql

Exit code: 0 = secure, 1 = insecure, 2 = scan failed.
"""

from __future__ import annotations  # imports annotations from the __future__ module

import argparse  # imports the argparse module
import sys  # imports the sys module
import threading  # imports the threading module

import compliance  # imports the compliance module
import config  # imports the config module
import exports  # imports the exports module
import scanners  # imports the scanners module
import scoring  # imports the scoring module


def main(argv: list[str] | None = None) -> int:  # defines the main() function
    # Windows consoles default to cp1252, which cannot encode the arrows and
    # dots used in the report.
    for stream in (sys.stdout, sys.stderr):  # loops over the collection
        try:  # watches for errors in the block
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]  # runs the reconfigure() call
        except Exception:  # handles the raised error
            pass  # keeps the block syntactically empty

    parser = argparse.ArgumentParser(description=f"{config.APP_NAME} (headless)")  # runs the ArgumentParser() call
    parser.add_argument("url", help="GitHub repository URL or owner/repo")  # runs the add_argument() call
    parser.add_argument("--json", metavar="PATH", help="write the full JSON report here")  # runs the add_argument() call
    parser.add_argument("--csv", metavar="PATH", help="write one CSV row per finding here")  # runs the add_argument() call
    parser.add_argument("--pdf", metavar="PATH", help="write a printable PDF report here")  # runs the add_argument() call
    parser.add_argument("--quiet", action="store_true", help="suppress scanner progress output")  # runs the add_argument() call
    parser.add_argument(  # runs the add_argument() call
        "--no-artifacts", action="store_true", help="delete the working folder afterwards"  # supplies the literal text
    )  # closes the multiline block
    parser.add_argument(  # runs the add_argument() call
        "--tools",  # supplies the literal text
        metavar="LIST",  # sets the metavar text
        help=(  # assigns the computed value to help
            "comma-separated scanners to run (default: all). Available: "  # maps the comma-separated scanners dictionary entry
            + ", ".join(config.ALL_TOOLS)  # waits for the thread
        ),  # closes the multiline block
    )  # closes the multiline block
    parser.add_argument(  # runs the add_argument() call
        "--frameworks",  # supplies the literal text
        metavar="LIST",  # sets the metavar text
        help=(  # assigns the computed value to help
            "comma-separated compliance frameworks to map findings onto. "  # supplies the literal text
            "Available: " + ", ".join(compliance.FRAMEWORK_LABELS.values())  # maps the Available:  dictionary entry
        ),  # closes the multiline block
    )  # closes the multiline block
    parser.add_argument(  # runs the add_argument() call
        "--dashboard",  # supplies the literal text
        metavar="LIST",  # sets the metavar text
        help=(  # assigns the computed value to help
            "comma-separated dashboard metrics to include (default: none). "  # supplies the literal text
            "Available: " + ", ".join(config.DASHBOARD_METRICS)  # waits for the thread
        ),  # closes the multiline block
    )  # closes the multiline block
    args = parser.parse_args(argv)  # runs the parse_args() call

    selected = [part for part in (args.tools or "").split(",") if part.strip()] or None  # runs the split() call
    frameworks = [part for part in (args.frameworks or "").split(",") if part.strip()]  # runs the split() call
    dashboard_ids = [part for part in (args.dashboard or "").split(",") if part.strip()]  # runs the split() call
    bad = [name for name in frameworks if name not in compliance.FRAMEWORKS]  # assigns the computed value to bad
    bad += [name for name in dashboard_ids if name not in config.DASHBOARD_METRICS]  # validates the dashboard ids
    if bad:  # evaluates the branch condition
        print(f"error: unknown framework(s): {', '.join(bad)}. "  # runs the print() call
              f"Available: {', '.join(compliance.FRAMEWORK_LABELS)}", file=sys.stderr)  # waits for the thread
        return 2  # returns the value to the caller

    def log(line: str) -> None:  # defines the log() function
        if not args.quiet:  # evaluates the branch condition
            print(line, flush=True)  # runs the print() call

    try:  # watches for errors in the block
        report = scanners.scan_target(  # dispatches repo vs website
            args.url,  # evaluates the args.url expression
            log=log,  # copies the log value into log
            cancel=threading.Event(),  # runs the Event() call
            keep_artifacts=not args.no_artifacts,  # copies the not value into keep_artifacts
            tools=selected,  # copies the selected value into tools
            frameworks=frameworks or None,  # copies the frameworks value into frameworks
            dashboard=dashboard_ids or None,  # copies the dashboard value into dashboard
        )  # closes the multiline block
    except scanners.ScanError as exc:  # handles the raised error
        print(f"error: {exc}", file=sys.stderr)  # runs the print() call
        return 2  # returns the value to the caller

    print()  # runs the print() call
    print(scoring.render_report_text(report))  # runs the print() call

    if args.json:  # evaluates the branch condition
        scoring.write_report_json(report, args.json)  # runs the write_report_json() call
        print(f"\nJSON report written to {args.json}")  # runs the print() call

    if args.csv:  # evaluates the branch condition
        exports.write_report_csv(report, args.csv)  # runs the write_report_csv() call
        print(f"CSV report written to {args.csv}")  # runs the print() call

    if args.pdf:  # evaluates the branch condition
        exports.write_report_pdf(report, args.pdf)  # runs the write_report_pdf() call
        print(f"PDF report written to {args.pdf}")  # runs the print() call

    return 0 if report["verdict"] == "SECURE" else 1  # returns the value to the caller


if __name__ == "__main__":  # runs the module entry point
    raise SystemExit(main())  # raises the SystemExit error
