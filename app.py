"""ScanityCheck - a small Tkinter popup that scores a GitHub repo or website.

Enter a repository URL (or any other web address), choose the scanners, press
Scan, and the app downloads the source, runs the selected scanners locally, and
shows a weighted 0-100 score plus the biggest risks behind it. Every finding
names its scanner and location. A website address gets the built-in web audit
and optionally Nuclei's DAST templates instead of the source scanners.
"""

from __future__ import annotations  # imports annotations from the __future__ module

import json  # imports the json module
import os  # imports the os module
import queue  # imports the queue module
from pathlib import Path  # the gate resolves the branding asset next to this file
import subprocess  # imports the subprocess module
import sys  # imports the sys module
import threading  # imports the threading module
import time  # imports the time module
from datetime import datetime, timezone  # the disclaimer acceptance stamp
import tkinter as tk  # imports the tkinter module
from tkinter import filedialog, messagebox, ttk  # imports filedialog, messagebox, ttk from the tkinter module
import tkinter.font as tkfont  # the pixel-measuring font used by the donut legend
from typing import Any  # imports Any from the typing module

import config  # imports the config module
import care  # imports the care module
import compliance  # imports the compliance module
import dashboard  # imports the dashboard module widgets
import gad  # the GitHub Advisory Database quick-check
import exports  # imports the exports module
import report_view  # imports the pure report-layout builder module
import scanners  # imports the scanners module
import scoring  # imports the scoring module
import summarizer  # the plain-language report summariser

# --------------------------------------------------------------------------
# Palette (brand colours come from the ScanityCheck wordmark / logo graphics)
# --------------------------------------------------------------------------
BG = "#0b1220"  # sets the BG text
PANEL = "#111c2e"  # sets the PANEL text
PANEL_ALT = "#0e1828"  # sets the PANEL_ALT text
BORDER = "#1f3350"  # sets the BORDER text
TEXT = "#e6edf7"  # sets the TEXT text
MUTED = "#8ba3c2"  # sets the MUTED text
ACCENT = config.BRAND_GREEN  # copies the config.BRAND_GREEN value into ACCENT
ACCENT_HOVER = config.BRAND_GREEN_HOVER  # copies the config.BRAND_GREEN_HOVER value into ACCENT_HOVER
DANGER = "#ef4444"  # sets the DANGER text
OK = "#22c55e"  # sets the OK text

SEVERITY_COLOURS = {  # assigns the computed value to SEVERITY_COLOURS
    "critical": "#f87171",  # maps the critical dictionary entry
    "high": "#fb923c",  # maps the high dictionary entry
    "medium": "#fbbf24",  # maps the medium dictionary entry
    "low": "#38bdf8",  # maps the low dictionary entry
    "unknown": "#94a3b8",  # maps the unknown dictionary entry
}  # closes the multiline block

UI_FONT = "Segoe UI"  # sets the UI_FONT text
MONO_FONT = "Consolas"  # sets the MONO_FONT text

# Shared tints that used to be repeated as bare literals across the UI code.
DISABLED_GREY = "#4b5f7d"  # the greyed-out tint the dark theme uses everywhere
BLACK_INK = "#08130c"  # the near-black ink that reads on the logo-green pills (verdict badge pairing)
SCANNER_RING = "#7e9e4a"  # the muted green ring around the scanner-group boxes (brand green, softened)
TRACK_COLOUR = "#16233a"  # gauge track / heat base / tick-well tone in dashboards
SCAN_DISABLED_BG = "#1c3455"  # the Scan button's tint while a scan is running
ACTIVE_ROW_BG = "#1a2942"  # pressed-state tint of the dark flat buttons
SELECT_BG = "#365314"  # text selection highlight inside the text panes
VERDICT_SCANNING_BG = "#24344d"  # the verdict badge tint while no verdict exists

# Timing tunables: event-pump cadence plus every debounce the UI reschedules.
POLL_FIRST_MS = 100  # the startup schedule of the event pump
POLL_ACTIVE_MS = 100  # fast pump cadence while a scan runs or events are queued
POLL_IDLE_MS = 250  # back-off cadence once the pump has drained everything
RESIZE_DEBOUNCE_MS = 90  # shared debounce for gauge/reason/metric redraws
ELAPSED_TICK_MS = 500  # the header elapsed clock repaints twice a second
OMISSION_DEBOUNCE_MS = 150  # checkbox ticks coalesce before the rescore runs
CLEANUP_DEFER_MS = 1500  # old-workdir cleanup waits out the widget-painting burst
RISK_BOX_SLOT = "risk_box_slot"  # the marker tag for a replayable omission row

# Small visual and bookkeeping values with one home each.
LUMA_TEXT_THRESHOLD = 140  # perceived-brightness split for badge ink
CONFIDENCE_MARKS = (60, 80)  # the band ticks drawn on the confidence gauge
HEAT_CELL_MAX = 52.0  # widest heat-map cell before the grid squeezes
LOG_BUFFER_MAX = 4000  # buffered log lines before a bulk drop
LOG_BUFFER_DROP = 1000  # how many lines a bulk drop removes
LOG_VIEW_MAX = 1500  # visible rows before the log pane trims
LOG_VIEW_KEEP = 1000  # rows kept after the log pane trims
LOG_VIEW_TRIM = 500  # rows deleted from the pane in one trim

# One explanatory paragraph per scanner, shown on the About tab. Keys mirror
# config.TOOL_LABELS; the render order follows that registry.
SCANNER_PROFILES: dict[str, str] = {  # assigns the computed value to SCANNER_PROFILES
    "codeql": (  # maps the codeql dictionary entry
        "GitHub's CodeQL engine runs static data-flow queries (the security-extended suite) "  # supplies the literal text
        "over the checkout in the top detected languages: attacker-controlled input that "  # supplies the literal text
        "reaches a dangerous operation is reported as a live exploit chain. Compiled projects "  # supplies the literal text
        "need no compiler (--build-mode=none), so mixed repositories still get code coverage. "  # supplies the literal text
        "Its findings are charged as code findings - the most heavily weighted category - "  # supplies the literal text
        "and CodeQL is one of the two required scanners: if it fails, the verdict cannot be "  # supplies the literal text
        "trusted."  # supplies the literal text
    ),  # closes the codeql profile
    "trivy": (  # maps the trivy dictionary entry
        "Aquasecurity's Trivy runs a filesystem scan with its own bundled vulnerability "  # supplies the literal text
        "database and is the suite's single broadest engine: it reports known CVEs in "  # supplies the literal text
        "dependencies, committed secrets and infrastructure-as-code misconfigurations from "  # supplies the literal text
        "one run. It is the other required scanner, so its failure makes any run incomplete. "
        "Its three finding classes map to the dependency, secret and IaC categories at "
        "their standard weights."  # supplies the literal text
    ),  # closes the trivy profile
    "semgrep": (  # maps the semgrep dictionary entry
        "Semgrep CE is a community-edition pattern matcher: each run downloads the p/default "  # supplies the literal text
        "rule pack from the registry and sweeps the source for known-bad patterns - injection "  # supplies the literal text
        "shapes, unsafe deserialization, hardcoded crypto. It adds a second, faster opinion to "  # supplies the literal text
        "CodeQL's deep analysis; findings in the same file/line with the same CWE are merged "  # supplies the literal text
        "with CodeQL's, so the code category never double-charges one bug."  # supplies the literal text
    ),  # closes the semgrep profile
    "grype": (  # maps the grype dictionary entry
        "Grype is the Anchore vulnerability database - a second, independent CVE opinion for "  # supplies the literal text
        "the dependencies. When Syft has produced an SBOM it is fed straight to Grype for the "  # supplies the literal text
        "most exact package matching. Findings merge across Trivy, Grype and OSV-Scanner on "  # supplies the literal text
        "canonical CVE plus package, so one dependency flaw costs its weight once but names "  # supplies the literal text
        "every database that knew about it."  # supplies the literal text
    ),  # closes the grype profile
    "osv": (  # maps the osv dictionary entry
        "OSV-Scanner consults Google's OSV/GHSA database - a third vulnerability opinion on "  # supplies the literal text
        "the lockfiles and manifests it can parse. Severity ratings fall back to medium when "  # supplies the literal text
        "the database entry carries none, and the findings join the same dependency merge pool "  # supplies the literal text
        "as Trivy's and Grype's."  # supplies the literal text
    ),  # closes the osv profile
    "gitleaks": (  # maps the gitleaks dictionary entry
        "GitLeaks hunts committed credentials: cloud keys, API tokens, private keys and "  # supplies the literal text
        "similar, each report with its matched value redacted in every output surface. It "  # supplies the literal text
        "feeds the secret category - 15/10/5/1 points per critical/high/medium/low, capped "  # supplies the literal text
        "at 25 - and merges with TruffleHog's and Trivy's confirmations by file, line and "  # supplies the literal text
        "credential family."  # supplies the literal text
    ),  # closes the gitleaks profile
    "trufflehog": (  # maps the trufflehog dictionary entry
        "TruffleHog is the second secret engine, run with --no-verification: it never transmits "  # supplies the literal text
        "a discovered credential to a vendor to check if it works, which keeps the scan local "  # supplies the literal text
        "as promised, at the cost that most findings rate medium rather than critical. Private "  # supplies the literal text
        "keys still score as high."  # supplies the literal text
    ),  # closes the trufflehog profile
    "syft": (  # maps the syft dictionary entry
        "Syft builds the software bill of materials: every component the repository could "  # supplies the literal text
        "plausibly ship, with its version, packaged by ecosystem. It never subtracts points - "  # supplies the literal text
        "it is pure context for the report and SBOM section - and its output is fed to Grype so "  # supplies the literal text
        "the CVE matchers see precisely resolved packages."  # supplies the literal text
    ),  # closes the syft profile
    "checkov": (  # maps the checkov dictionary entry
        "Checkov reviews infrastructure-as-code: Dockerfiles, Kubernetes manifests and cloud "  # supplies the literal text
        "templates, looking for risky defaults - passwords, privileged containers, missing "  # supplies the literal text
        "healthchecks. Pinned to 3.4.0 inside its own private virtual environment for stable "  # supplies the literal text
        "output, it feeds the IaC/container misconfiguration category (8/4/1/0.2 points, capped "  # supplies the literal text
        "at 10)."  # supplies the literal text
    ),  # closes the checkov profile
    "guarddog": (  # maps the guarddog dictionary entry
        "GuardDog applies DataDog's malware rules to the local package manifests: install "  # supplies the literal text
        "scripts that exfiltrate, backdoored packages, typosquats. It is the supply-chain lens "  # supplies the literal text
        "of the suite - its findings land in the vulnerability and misconfiguration categories "  # supplies the literal text
        "and corroborate an install-script hit from Trivy when the two engines agree."  # supplies the literal text
    ),  # closes the guarddog profile
    "nuclei": (  # maps the nuclei dictionary entry
        "Nuclei is the only active tester: it runs ProjectDiscovery's DAST templates against the "  # supplies the literal text
        "repository's live web endpoint - the package homepage or the GitHub Pages site when one "  # supplies the literal text
        "can be inferred - at a polite request rate. CVE-template matches are charged as "  # supplies the literal text
        "vulnerabilities and merge with the dependency scanners; every other template hit counts "  # supplies the literal text
        "as a misconfiguration."  # supplies the literal text
    ),  # closes the nuclei profile
    "kubescape": (  # maps the kubescape dictionary entry
        "Kubescape grades Kubernetes and IaC definitions against the NSA and MITRE posture "  # supplies the literal text
        "frameworks, walking the checkout for manifests, charts and container defaults. Its first "  # supplies the literal text
        "run downloads the control definitions, and it exits non-zero purely because a compliance "  # supplies the literal text
        "score below 100 is still a success signal to this suite. Failed controls feed the IaC "  # supplies the literal text
        "misconfiguration category."  # supplies the literal text
    ),  # closes the kubescape profile
    "scorecard": (  # maps the scorecard dictionary entry
        "The OpenSSF Scorecard tab asks the public scorecard.dev record instead of running anything "  # supplies the literal text
        "locally: the project's published security posture, from branch protection to signed "  # supplies the literal text
        "releases to dangerous workflows. Checks scored 0-6 out of 10 become misconfiguration "  # supplies the literal text
        "findings (a zero rates medium, the rest low); seven or above stays clear. There is no "  # supplies the literal text
        "binary to install for this scanner."  # supplies the literal text
    ),  # closes the scorecard profile
    "ossfuzz": (  # maps the ossfuzz dictionary entry
        "The OSS-Fuzz check reads the public google/oss-fuzz project registry: whether the project "  # supplies the literal text
        "is continuously fuzzed at all, with which engines and sanitizers. Being fuzzed is purely "  # supplies the literal text
        "a positive signal (no points, the fact shows in the scanner status); not being registered "  # supplies the literal text
        "at all adds one low finding for the missing fuzz coverage. The issues dashboard has no "  # supplies the literal text
        "public API, so open bug counts are deliberately not claimed."  # supplies the literal text
    ),  # closes the ossfuzz profile
}  # closes the multiline block


def _enable_dpi_awareness() -> None:  # defines the _enable_dpi_awareness() function
    if os.name != "nt":  # evaluates the branch condition
        return  # evaluates the return expression
    try:  # watches for errors in the block
        import ctypes  # imports the ctypes module

        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # runs the SetProcessDpiAwareness() call
    except Exception:  # handles the raised error
        pass  # keeps the block syntactically empty


def _set_window_icon(window: tk.Tk | tk.Toplevel) -> tk.PhotoImage | None:  # defines the _set_window_icon() function
    """Apply the AppIcon graphic to a window's titlebar and taskbar button.

    The returned PhotoImage (or None when the asset is missing) must be kept
    alive by the caller, or Tcl drops the image and the icon reverts.
    """
    try:  # watches for a missing or unreadable asset
        icon = tk.PhotoImage(  # the full-resolution app icon
            file=str(Path(__file__).resolve().parent / config.APP_ICON)
        )  # loads once at native size
        window.iconphoto(True, icon)  # sets both the titlebar and the taskbar
        return icon  # returns the image for the caller to anchor
    except Exception:  # handles the read error
        return None  # branding missing or unreadable: keep the default icon


class App(tk.Tk):  # defines the App class
    def __init__(self) -> None:  # defines the __init__() function
        super().__init__()  # runs the super() call
        self._app_icon = _set_window_icon(self)  # the AppIcon graphic: titlebar + taskbar
        try:  # watches for a platform where Tcl refuses PNGs entirely
            self._logo_image = self._brand_image(config.BRANDING_LOGO, 8)  # the cached tray-icon variant
            if self._logo_image:  # evaluates the branch condition
                self.iconphoto(True, self._app_icon or self._logo_image)  # prefers the AppIcon graphic
        except Exception:  # handles the raised error
            pass  # branding graphic missing or unreadable: keep the default icon  # keeps the block syntactically empty

        self.title(config.APP_NAME)  # title-cases the text
        self.configure(bg=BG)  # updates the widget settings
        self.minsize(  # never demand more room than the screen has
            min(860, self.winfo_screenwidth()),
            min(660, self.winfo_screenheight()),
        )
        self._centre()  # runs the _centre() call

        self._events: queue.Queue[tuple[str, Any]] = queue.Queue()  # runs the Queue() call
        self._worker: threading.Thread | None = None  # evaluates the self._worker expression
        self._elapsed_after: str | None = None  # the handle cancelling the elapsed clock's tick
        self._scan_started: float | None = None  # the monotonic stamp the clock counts from
        self._page_fitted: tuple[int, int] = ()  # the last size the scroll page was fitted to
        self._cancel = threading.Event()  # saves the result on _cancel
        self._report: dict[str, Any] | None = None  # evaluates the self._report expression
        self._omitted_groups: set[str] = set()  # risk rows the reviewer excluded from the score
        self._risk_checkboxes: list[tk.Checkbutton] = []  # checkboxes embedded in the report text
        self._banner_hidden = False  # the score card starts visible everywhere
        self._log_buffer: list[str] = []  # evaluates the self._log_buffer expression
        self._log_lines = 0  # saves the result on _log_lines
        self._pane = "report"  # saves the result on _pane
        # Render caches: composed report segments and per-pane repaint flags.
        self._pane_dirty: dict[str, bool] = {  # assignment
            "report": True,  # the report pane repaints on its first visit
            "log": True,  # likewise for the activity log
            "dashboard": True,  # likewise for the metric dashboard
            "recommend": True,  # likewise for the remediations pane
            "about": True,  # the static About page renders exactly once
        }  # closes the mapping
        self._text_area_pane = ""  # empty until one pane owns the shared text widget
        self._segment_cache: dict[tuple[Any, ...], list] = {}  # keyed by report state, reused on tab switches
        self._about_segments: tuple[list, list] | None = None  # the strict About page, built lazily once
        self._last_status = ""  # the last string handed to the status bar
        self._heat_cache: dict[tuple[str, int], str] = {}  # memoised heat-map blends
        self._heat_base = self._hex_to_rgb(TRACK_COLOUR)  # the panel RGB parsed once, not per cell
        self._legend_font = tkfont.Font(font=(UI_FONT, 9))  # measures donut-legend entries in pixels
        self._explain_font = tkfont.Font(font=(UI_FONT, 8))  # measures dashboard explainer wraps
        self._dash_value_font = tkfont.Font(  # the big figure font the dashboard cards draw
            font=(UI_FONT, 24, "bold")  # one instance measures every card value precisely
        )  # closes the font build

        self.report_callback_exception = self._report_callback_exception  # saves the result on report_callback_exception

        self._build_styles()  # runs the _build_styles() call
        self._build_ui()  # runs the _build_ui() call
        self._restore_settings()  # runs the _restore_settings() call
        try:  # watches for a platform without the zoomed state
            self.state("zoomed")  # opens maximized to the desktop, title bar and taskbar intact
        except Exception:  # handles the raised error
            pass  # falls back to the centred geometry _centre computed
        self.after(POLL_FIRST_MS, self._drain_events)  # runs the after() call
        self.protocol("WM_DELETE_WINDOW", self._on_close)  # runs the protocol() call
        self.after(CLEANUP_DEFER_MS, self._start_cleanup)  # defers cleanup so widget painting never waits

    def _start_cleanup(self) -> None:  # defines the _start_cleanup() function
        """Sweeps stale scan work directories once the UI is fully painted."""
        threading.Thread(  # runs the Thread() call
            target=scanners.cleanup_old_workdirs,  # copies the scanners.cleanup_old_workdirs value into target
            kwargs={"log": lambda line: self._events.put(("log", line))},  # runs the put() call
            daemon=True,  # assigns the True literal to daemon
        ).start()  # closes the multiline block

    def _brand_image(self, path: str, factor: int) -> tk.PhotoImage | None:  # defines the _brand_image() function
        """Loads each branding PNG once and caches every subsample variant."""
        originals = getattr(self, "_image_originals", None)  # fetches the full-size cache
        if originals is None:  # evaluates the branch condition
            originals = self._image_originals = {}  # creates the cache once
        variants = getattr(self, "_image_variants", None)  # fetches the subsample cache
        if variants is None:  # evaluates the branch condition
            variants = self._image_variants = {}  # creates the cache once
        variant_key = (str(path), factor)  # one cache slot per size
        if variant_key in variants:  # evaluates the branch condition
            return variants[variant_key]  # returns the cached variant
        try:  # watches for a graphic missing or ill-formed
            original = originals.get(str(path))  # parses the PNG once, ever
            if original is None:  # evaluates the branch condition
                original = tk.PhotoImage(file=path)  # loads the PNG image for Tk
                originals[str(path)] = original  # keeps the original alive for the next variant
            image = original.subsample(factor)  # cheap resize off the cached original
            variants[variant_key] = image  # caches the variant
            return image  # returns the image to the caller
        except Exception:  # handles the raised error
            return None  # the caller falls back to text or the default icon

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def _centre(self) -> None:  # defines the _centre() call
        # Deliberately no update_idletasks() here: mapping the window before
        # its position request exists makes Windows apply cascade placement,
        # which can shove the window past the bottom of the screen.
        screen_w = self.winfo_screenwidth()  # reads the screen width
        screen_h = self.winfo_screenheight()  # reads the screen height
        # Fit the window on screen: never taller or wider than the display,
        # but open tall and wide so the bottom result pane has the room its
        # scrollable content needs.
        width = min(max(860, int(screen_w * 0.88)), screen_w - 40)  # assigns the computed value to width
        height = min(max(660, int(screen_h * 0.95)), screen_h - 30)  # assigns the computed value to height
        x, y = self._centred_origin(screen_w, screen_h, width, height)  # one helper holds the fitting math
        self.geometry(f"{width}x{height}+{x}+{y}")  # runs the geometry() call
        self.after(150, self._audit_on_screen)  # re-checks once the WM is done
        self.after(150, self._apply_title_bar_style)  # one timer paints the native bar once mapped

    def _centred_origin(  # defines the _centred_origin() helper
        self,  # evaluates the self expression
        screen_w: int,  # the display width in pixels
        screen_h: int,  # the display height in pixels
        width: int,  # the client width to centre
        height: int,  # the client height to centre
        *,  # spreads the collected values
        frame_left: int = 0,  # WM chrome width left of the client area (measured)
        titlebar: int = 0,  # WM chrome height above the client area (measured)
    ) -> tuple[int, int]:  # closes the signature
        """The shared math turning a client size plus screen into an origin."""
        return (  # returns the value to the caller
            max((screen_w - width) // 2 - frame_left, 0),  # clamps the horizontal origin
            max((screen_h - height) // 2 - 30 - titlebar, 0),  # clamps the vertical origin
        )  # closes the pair tuple

    def _apply_title_bar_style(self) -> None:
        """Style the native Windows title bar (best-effort, Windows 11+).

        Tk offers no title-bar API, so this talks to the Desktop Window
        Manager directly: caption background #111c2e, with the caption text
        and the minimize/maximize/close glyphs painted white. On Windows 10
        or older the attributes are simply ignored and the stock bar stays.
        """
        if os.name != "nt":  # evaluates the branch condition
            return  # non-Windows has no DWM
        try:  # watches for errors in the block
            import ctypes  # imports the ctypes module

            root_handle = ctypes.windll.user32.GetParent(self.winfo_id())  # the real frame handle
            if not root_handle:  # evaluates the branch condition
                return  # no frame yet: nothing to paint

            def colourref(hex_value: str) -> int:  # builds a COLORREF helper
                text = hex_value.lstrip("#")  # strips the hash
                red, green, blue = (  # splits the channels
                    int(text[0:2], 16), int(text[2:4], 16), int(text[4:6], 16),
                )  # closes the split
                return (blue << 16) | (green << 8) | red  # COLORREF = 0x00BBGGRR

            for attribute, hex_value in (  # caption background first, then text
                (35, "#111c2e"),  # DWMWA_CAPTION_COLOR: the bar background
                (36, "#ffffff"),  # DWMWA_TEXT_COLOR: title text + the min/max/close glyphs
            ):  # closes the pair list
                packed = ctypes.c_uint(colourref(hex_value) & 0xFFFFFFFF)  # packs the colour
                ctypes.windll.dwmapi.DwmSetWindowAttribute(  # runs the setter
                    root_handle, attribute, ctypes.byref(packed), ctypes.sizeof(packed)
                )  # closes the setter call
        except Exception:  # handles the raised error
            pass  # keep the stock title bar: cosmetics must never break the app

    def _audit_on_screen(self) -> None:  # defines the _audit_on_screen() function
        """Keeps the window fully on screen; Windows cascades first-show
        placement, which can offset the requested position."""
        if not self.winfo_exists() or not self.winfo_ismapped():  # evaluates the branch condition
            self.after(150, self._audit_on_screen)  # waits for the first map
            return  # returns nothing to the caller
        self.update_idletasks()  # flushes pending layout work
        screen_w = self.winfo_screenwidth()  # reads the screen width
        screen_h = self.winfo_screenheight()  # reads the screen height
        width = self.winfo_width()  # reads the mapped width
        height = self.winfo_height()  # reads the mapped height
        client_top = self.winfo_rooty()  # physical top of the client area
        client_left = self.winfo_rootx()  # physical left of the client area
        if client_top + height <= screen_h and client_left + width <= screen_w:  # evaluates the branch condition
            return  # already fits: nothing to correct
        # Pin to the screen corner once to measure the WM frame, then move
        # the window so its client area ends up centred and fully visible.
        self.geometry("+0+0")  # runs the geometry() call
        self.update_idletasks()  # flushes pending layout work
        titlebar = self.winfo_rooty()  # frame height above the client area
        frame_left = self.winfo_rootx()  # frame width left of the client area
        outer_x, outer_y = self._centred_origin(  # the one shared fitting helper
            screen_w, screen_h, width, height, frame_left=frame_left, titlebar=titlebar  # executes the statement
        )  # closes the pair unpack
        self.geometry(f"+{outer_x}+{outer_y}")  # runs the geometry() call

    def _build_styles(self) -> None:  # defines the _build_styles() function
        style = ttk.Style(self)  # sets up the styled theme
        style.theme_use("clam")  # runs the theme_use() call
        style.configure(  # updates the widget settings
            "RSS.Horizontal.TProgressbar",  # supplies the literal text
            troughcolor=PANEL_ALT,  # copies the PANEL_ALT value into troughcolor
            background=ACCENT,  # copies the ACCENT value into background
            bordercolor=PANEL_ALT,  # copies the PANEL_ALT value into bordercolor
            lightcolor=ACCENT,  # copies the ACCENT value into lightcolor
            darkcolor=ACCENT,  # copies the ACCENT value into darkcolor
            thickness=4,  # assigns the computed value to thickness
        )  # closes the multiline block

    def _build_ui(self) -> None:  # defines the _build_ui() function
        self.columnconfigure(0, weight=1)  # runs the columnconfigure() call
        # The header stays gridded in the root; everything beneath it lives
        # in one scrollable page, so the URL, scanner and framework rows can
        # leave the viewport while the details box takes over the screen.
        self.rowconfigure(1, weight=1)  # the scrolling page absorbs all slack
        page = tk.Frame(self, bg=BG)  # the two-column scroll container
        page.grid(row=1, column=0, sticky="nsew")  # under the always-visible header
        page.rowconfigure(0, weight=1)  # the canvas takes the page height
        page.columnconfigure(0, weight=1)  # and the full page width
        self._page_canvas = tk.Canvas(page, bg=BG, highlightthickness=0)  # the viewport onto the lower rows
        self._page_canvas.grid(row=0, column=0, sticky="nsew")  # fills the frame
        self._page_scroll = tk.Scrollbar(  # builds the scrollbar widget
            page, command=self._page_canvas.yview, bg=BG, troughcolor=BG, width=14  # the page's rail
        )  # closes the multiline block
        self._page_scroll.grid(row=0, column=1, sticky="ns")  # the rail rides the right edge
        self._page_canvas.configure(yscrollcommand=self._page_scroll.set)  # updates the widget settings
        self._page_content = tk.Frame(self._page_canvas, bg=BG)  # the single scrollable frame beneath the header
        self._page_content.columnconfigure(0, weight=1)  # runs the columnconfigure() call
        # The report pane (row 6) must absorb all vertical slack; the card's
        # dashboard widgets above it keep their natural height.
        self._page_content.rowconfigure(6, weight=1)  # runs the rowconfigure() call
        self._page_window = self._page_canvas.create_window(  # registers the content window
            (0, 0), window=self._page_content, anchor="nw"  # the content frame anchors top-left
        )  # closes the window build
        self._page_canvas.bind("<Configure>", self._fit_page)  # keeps the page fitted on resize
        self._page_content.bind("<Configure>", self._fit_page)  # keeps the page fitted on row churn
        self.bind_all("<MouseWheel>", self._on_page_wheel, add="+")  # the page wheel backs the pane wheels
        content = self._page_content  # the local alias for the row placements below

        # Header -------------------------------------------------------
        header = tk.Frame(self, bg=BG)  # builds the frame container
        header.grid(row=0, column=0, sticky="ew", padx=22, pady=(18, 6))  # places the widget in the grid
        header.columnconfigure(1, weight=1)  # runs the columnconfigure() call

        self.logo_image: tk.PhotoImage | None = self._brand_image(  # the wordmark, parsed once and cached per size
            config.BRANDING_WORDMARK, 5  # copies the factor value
        )  # closes the multiline block

        if self.logo_image:  # evaluates the branch condition
            tk.Label(  # runs the Label() call
                header,  # evaluates the header expression
                image=self.logo_image,  # copies the self.logo_image value into image
                bg=BG,  # copies the BG value into bg
            ).grid(row=0, column=0, sticky="w")  # closes the multiline block
        else:  # covers the remaining branch
            tk.Label(  # runs the Label() call
                header,  # evaluates the header expression
                text=config.APP_NAME,  # copies the config.APP_NAME value into text
                bg=BG,  # copies the BG value into bg
                fg=TEXT,  # copies the TEXT value into fg
                font=(UI_FONT, 16, "bold"),  # assigns the computed value to font
                anchor="w",  # sets the anchor text
            ).grid(row=0, column=0, sticky="w")  # closes the multiline block
        tk.Label(  # runs the Label() call
            header,  # evaluates the header expression
            text=f"{config.APP_TAGLINE}.",  # sets the text text from the brand copy
            bg=BG,  # copies the BG value into bg
            fg=config.BRAND_GREEN,  # the logo's green
            font=(UI_FONT, 11),  # slightly larger than the stock tagline
            anchor="w",  # sets the anchor text
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))  # closes the multiline block

        right_stack = tk.Frame(header, bg=BG)  # one cell holds the badge and the clock beneath it
        badge = tk.Label(  # builds the label widget
            right_stack,  # the badge belongs to the right stack, not the header grid
            text="LOCAL  ·  NO CODE LEAVES THIS MACHINE",  # sets the text text
            bg=PANEL,  # copies the PANEL value into bg
            fg=MUTED,  # copies the MUTED value into fg
            font=(UI_FONT, 8, "bold"),  # assigns the computed value to font
            padx=8,  # assigns the computed value to padx
            pady=3,  # assigns the computed value to pady
        )  # closes the multiline block
        badge.grid(row=0, column=0, sticky="e")  # the badge rides on top of the stack
        self.elapsed_label = tk.Label(  # builds the label widget
            right_stack,  # the clock lives under the badge strip
            text="",  # empty until a scan starts the count
            bg=BG,  # copies the BG value into bg
            fg=config.BRAND_GREEN,  # the logo's green
            font=(UI_FONT, 16, "bold"),  # the bigger clock, still the brand green
            anchor="e",  # the digits never shift off the right edge
        )  # closes the multiline block
        self.elapsed_label.grid(row=1, column=0, sticky="e", pady=(6, 0))  # packs the clock under the badge
        right_stack.grid(row=0, column=1, rowspan=2, sticky="e")  # the stack keeps the badge's corner spot

        # URL row ------------------------------------------------------
        url_row = tk.Frame(content, bg=BG)  # builds the frame container
        url_row.grid(row=0, column=0, sticky="ew", padx=22, pady=(10, 0))  # places the widget in the grid
        url_row.columnconfigure(0, weight=1)  # runs the columnconfigure() call

        tk.Label(  # runs the Label() call
            url_row, text="Repository or website URL", bg=BG, fg=MUTED, font=(UI_FONT, 9)  # repos and live sites  # sets the url_row, text text
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 4))  # closes the multiline block

        self.url_var = tk.StringVar()  # creates a shared text variable
        self.url_entry = tk.Entry(  # builds the entry widget
            url_row,  # evaluates the url_row expression
            textvariable=self.url_var,  # copies the self.url_var value into textvariable
            bg=PANEL_ALT,  # copies the PANEL_ALT value into bg
            fg=TEXT,  # copies the TEXT value into fg
            insertbackground=TEXT,  # copies the TEXT value into insertbackground
            selectbackground=PANEL,  # the selection well inside the dark field
            selectforeground=config.BRAND_GREEN,  # the picked text reads in brand green
            relief="flat",  # sets the relief text
            highlightthickness=1,  # the thin ring around the field
            highlightbackground=SCANNER_RING,  # the same muted green ring as the scanner group boxes
            highlightcolor=ACCENT,  # focus still lights the ring in full brand green
            font=(UI_FONT, 11),  # assigns the computed value to font
        )  # closes the multiline block
        self.url_entry.grid(row=1, column=0, sticky="ew", ipady=7, ipadx=8)  # places the widget in the grid
        self.url_entry.bind("<Return>", lambda _e: self.start_scan())  # wires the event handler
        self.url_entry.focus_set()  # the cursor waits in the field
        self._url_history = _load_url_history()  # the remembered scan targets
        self._url_drop = None  # the dropdown is built lazily on a double-click
        self.url_entry.bind("<Double-Button-1>", lambda _e: self._show_url_history())  # double-click opens the history
        self.bind_all("<Button-1>", self._drop_global_click, add="+")  # any click elsewhere closes the dropdown

        self.scan_button = tk.Button(  # builds the button widget
            url_row,  # evaluates the url_row expression
            text="Scan repository",  # sets the text text
            command=self.start_scan,  # copies the self.start_scan value into command
            bg=ACCENT,  # copies the ACCENT value into bg
            fg=BG,  # the near-black ink straight off the brand background
            activebackground=ACCENT_HOVER,  # copies the ACCENT_HOVER value into activebackground
            activeforeground=BG,  # the near-black ink straight off the brand background
            relief="flat",  # sets the relief text
            font=(UI_FONT, 10, "bold"),  # assigns the computed value to font
            padx=16,  # assigns the computed value to padx
            pady=7,  # assigns the computed value to pady
            cursor="hand2",  # sets the cursor text
            borderwidth=0,  # assigns the computed value to borderwidth
        )  # closes the multiline block
        self.scan_button.grid(row=1, column=1, padx=(10, 0))  # places the widget in the grid

        self.stop_button = tk.Button(  # builds the button widget
            url_row,  # evaluates the url_row expression
            text="Stop",  # sets the text text
            command=self.cancel_scan,  # copies the self.cancel_scan value into command
            bg=PANEL,  # copies the PANEL value into bg
            fg=MUTED,  # copies the MUTED value into fg
            activebackground=ACTIVE_ROW_BG,  # sets the activebackground text
            activeforeground=TEXT,  # copies the TEXT value into activeforeground
            relief="flat",  # sets the relief text
            font=(UI_FONT, 10),  # assigns the computed value to font
            padx=14,  # assigns the computed value to padx
            pady=7,  # assigns the computed value to pady
            state="disabled",  # sets the state text
            cursor="hand2",  # sets the cursor text
            borderwidth=0,  # assigns the computed value to borderwidth
            disabledforeground=DISABLED_GREY,  # sets the disabledforeground text
        )  # closes the multiline block
        self.stop_button.grid(row=1, column=2, padx=(8, 0))  # places the widget in the grid

        # Scanner selection -------------------------------------------
        self.tools_row = tk.Frame(content, bg=BG)  # builds the frame container
        self.tools_row.grid(row=1, column=0, sticky="ew", padx=22, pady=(10, 0))  # places the widget in the grid

        tk.Label(  # runs the Label() call
            self.tools_row,  # evaluates the self.tools_row expression
            text="Scanners",  # sets the text text
            bg=BG,  # copies the BG value into bg
            fg=TEXT,  # full-bright: the row lead-in reads first
            font=(UI_FONT, 9, "bold"),  # the row label, bolded
        ).grid(row=0, column=0, sticky="w", padx=(0, 10))  # closes the multiline block

        self.tool_vars: dict[str, tk.BooleanVar] = {}  # evaluates the self.tool_vars expression
        self.tool_checks: dict[str, tk.Checkbutton] = {}  # evaluates the self.tool_checks expression
        column = 1  # the group boxes share one row
        for group, tools in config.SCANNER_GROUPS:  # the functional legend, not a name wall
            box = tk.LabelFrame(  # one thin green box per functional group
                self.tools_row,  # evaluates the self.tools_row expression
                text=f" {group} ",  # the group name rides the border
                fg=config.BRAND_GREEN,  # the label text reads in the logo green
                bg=PANEL,  # the panel card tint inside the box
                font=(UI_FONT, 8, "bold"),  # the small-caps border caption
                highlightthickness=1,  # the thin ring
                highlightcolor=SCANNER_RING,  # the box ring, softened from the logo green
                highlightbackground=SCANNER_RING,  # the box ring, softened from the logo green
                bd=0,  # no double groove under the highlight ring
                relief="flat",  # flat inside the ring
                padx=8,  # assigns the computed value to padx
                pady=3,  # keeps the row compact
                cursor="",  # the frame is not itself interactive
            )  # closes the multiline block
            box.grid(row=0, column=column, sticky="w", padx=(0, 5), pady=(2, 0))  # beside its neighbours
            column += 1  # advances the row
            for index, tool in enumerate(tools):  # loops over the group's members
                var = tk.BooleanVar(value=tool in config.DEFAULT_TOOLS)  # creates a shared boolean variable
                check = self._check(  # one factory paints every dark-theme checkbox
                    box,  # the checkbox lives inside its group box
                    var,  # copies the var value into variable
                    config.TOOL_LABELS.get(tool, tool),  # fetches the value
                    bg=PANEL,  # the checkbox blends into the box's panel tint
                )  # closes the multiline block
                check.grid(row=0, column=index, sticky="w", padx=(0, 6))  # straight inside the box
                check.bind(  # wires the event handler
                    "<Enter>",  # supplies the literal text
                    lambda _e, name=tool: self._show_tool_description(name),  # defines the small inline helper
                )  # closes the multiline block
                check.bind("<Leave>", lambda _e: self._restore_status_hint())  # wires the event handler
                self.tool_vars[tool] = var  # saves the result on tool_vars[tool]
                self.tool_checks[tool] = check  # saves the result on tool_checks[tool]
                column += 1  # advances the row

        for offset, (text, tools) in enumerate(  # loops over the collection
            (("All", config.ALL_TOOLS), ("Required", config.REQUIRED_TOOLS), ("Clear", ()))  # all, the trusted pair, none selected
        ):  # closes the multiline block
            button = self._flat_button(  # one factory paints every flat accent button
                self.tools_row,  # evaluates the self.tools_row expression
                text,  # copies the text value into text
                lambda chosen=tools: self._select_tools(chosen),  # runs the _select_tools() call
            )  # closes the multiline block
            button.grid(row=0, column=column, sticky="w", padx=(2, 0))  # after the last group
            column += 1  # advances the row

        self.tools_hint = tk.Label(  # builds the label widget
            self.tools_row,  # evaluates the self.tools_row expression
            text="",  # sets the text text
            bg=BG,  # copies the BG value into bg
            fg=TEXT,  # white ink: the hover description must stay readable
            font=(UI_FONT, 9),  # assigns the computed value to font
            anchor="w",  # sets the anchor text
            wraplength=1600,  # long descriptions wrap instead of clipping
        )  # closes the multiline block
        self.tools_hint.grid(  # places the widget in the grid
            row=1, column=0, columnspan=column, sticky="w", padx=(0, 0), pady=(4, 0)  # its own row under the boxes
        )  # closes the multiline block
        def _wrap_to_row(event: tk.Event) -> None:  # the description wraps at the row's real width
            self.tools_hint.configure(wraplength=max(300, event.width - 30))  # tracks the visible width
        self.tools_row.bind("<Configure>", _wrap_to_row)  # fires on every resize

        # Framework selection -----------------------------------------
        # Framework maps never change the score: they re-organise the same
        # findings under the controls of a chosen regulation.
        self.frameworks_row = tk.Frame(content, bg=BG)  # builds the frame container
        self.frameworks_row.grid(row=2, column=0, sticky="ew", padx=22, pady=(8, 0))  # places the widget in the grid

        tk.Label(  # runs the Label() call
            self.frameworks_row,  # evaluates the self.frameworks_row expression
            text="Frameworks",  # sets the text text
            bg=BG,  # copies the BG value into bg
            fg=TEXT,  # full-bright: the row lead-in reads first
            font=(UI_FONT, 9, "bold"),  # the row label, bolded
        ).grid(row=0, column=0, sticky="w", padx=(0, 10))  # closes the multiline block

        self.framework_vars: dict[str, tk.BooleanVar] = {}  # evaluates the self.framework_vars expression
        self.framework_checks: dict[str, tk.Checkbutton] = {}  # evaluates the self.framework_checks expression
        for index, key in enumerate(compliance.ALL_FRAMEWORKS):  # loops over the collection
            var = tk.BooleanVar(value=False)  # creates a shared boolean variable
            check = self._check(  # one factory paints every dark-theme checkbox
                self.frameworks_row,  # evaluates the self.frameworks_row expression
                var,  # copies the var value into variable
                compliance.FRAMEWORK_LABELS[key],  # copies the compliance.FRAMEWORK_LABELS value into text
            )  # closes the multiline block
            check.grid(row=0, column=index + 1, sticky="w", padx=(0, 8))  # one straight row, like the scanners
            check.bind(  # wires the event handler
                "<Enter>",  # supplies the literal text
                lambda _e, name=key: self.frameworks_hint.configure(  # defines the small inline helper
                    text=compliance.FRAMEWORK_DESCRIPTIONS[name]  # copies the compliance.FRAMEWORK_DESCRIPTIONS value into text
                    + "  (mapping never changes the score)"  # executes the statement
                ),  # closes the multiline block
            )  # closes the multiline block
            check.bind("<Leave>", lambda _e: self._restore_frameworks_hint())  # wires the event handler
            self.framework_vars[key] = var  # saves the result on framework_vars[key]
            self.framework_checks[key] = check  # saves the result on framework_checks[key]

        clear_button = self._flat_button(  # one factory paints every flat accent button
            self.frameworks_row,  # evaluates the self.frameworks_row expression
            "Clear",  # sets the text text
            self._clear_frameworks,  # copies the self._clear_frameworks value into command
        )  # closes the multiline block
        clear_button.grid(row=0, column=len(compliance.ALL_FRAMEWORKS) + 1, sticky="w")  # after the last checkbox

        self.frameworks_hint = tk.Label(  # builds the label widget
            self.frameworks_row,  # evaluates the self.frameworks_row expression
            text="",  # sets the text text
            bg=BG,  # copies the BG value into bg
            fg=MUTED,  # copies the MUTED value into fg
            font=(UI_FONT, 9),  # assigns the computed value to font
            anchor="w",  # sets the anchor text
        )  # closes the multiline block
        self.frameworks_hint.grid(  # places the widget in the grid
            row=0, column=len(compliance.ALL_FRAMEWORKS) + 2, sticky="ew", padx=(10, 0)  # counts the items
        )  # closes the multiline block
        self.frameworks_row.columnconfigure(  # runs the columnconfigure() call
            len(compliance.ALL_FRAMEWORKS) + 2, weight=1  # runs the columnconfigure() call
        )  # closes the multiline block
        self._update_framework_count()  # runs the _update_framework_count() call

        # Status row ---------------------------------------------------
        status_row = tk.Frame(content, bg=BG)  # builds the frame container
        status_row.grid(row=3, column=0, sticky="ew", padx=22, pady=(10, 0))  # places the widget in the grid
        status_row.columnconfigure(0, weight=1)  # runs the columnconfigure() call

        self.progress = ttk.Progressbar(  # creates the progress widget
            status_row, style="RSS.Horizontal.TProgressbar", mode="determinate", maximum=100  # sets the status_row, style text
        )  # closes the multiline block
        self.progress.grid(row=0, column=0, sticky="ew")  # places the widget in the grid

        self.status_var = tk.StringVar(value="Ready. Paste a repository or website URL and press Scan.")  # creates a shared text variable
        self.status_label = tk.Label(  # builds the label widget
            status_row,  # evaluates the status_row expression
            textvariable=self.status_var,  # copies the self.status_var value into textvariable
            bg=BG,  # copies the BG value into bg
            fg=MUTED,  # copies the MUTED value into fg
            font=(UI_FONT, 9),  # assigns the computed value to font
            anchor="w",  # sets the anchor text
        )  # closes the multiline block
        self.status_label.grid(row=1, column=0, sticky="w", pady=(6, 0))  # places the widget in the grid

        # Tab strip (scrolls with the page; the header stays pinned) -------
        tab_strip = tk.Frame(content, bg=BG)  # builds the frame container
        tab_strip.grid(row=4, column=0, sticky="ew", padx=22, pady=(10, 0))  # places the widget in the grid
        tab_bar = tk.Frame(tab_strip, bg=BG)  # builds the frame container
        tab_bar.grid(row=0, column=0, sticky="ew")  # places the widget in the grid
        self.report_tab = self._tab_button(tab_bar, "Report", lambda: self._show_pane("report"))  # saves the result on report_tab
        self.log_tab = self._tab_button(tab_bar, "Activity log", lambda: self._show_pane("log"))  # saves the result on log_tab
        self.dash_tab = self._tab_button(tab_bar, "Dashboard", lambda: self._show_pane("dashboard"))  # saves the result on dash_tab
        self.recommend_tab = self._tab_button(tab_bar, "Remediations", lambda: self._show_pane("recommend"))  # saves the result on recommend_tab
        self.about_tab = self._tab_button(tab_bar, "About", lambda: self._show_pane("about"))  # runs the _tab_button() call
        tab_strip.columnconfigure(0, weight=1)  # pushes the banner toggle to the right edge

        self.banner_toggle = tk.Button(  # the toggle wears the solid brand pill, like Scan
            tab_strip,  # evaluates the tab_strip expression
            text="Hide score banner",  # the label _toggle_banner flips
            command=self._toggle_banner,  # flips the card visibility
            bg=ACCENT,  # the brand-green solid background
            fg=BG,  # the near-black ink straight off the brand background
            activebackground=ACCENT_HOVER,  # the pressed state
            activeforeground=BG,  # the near-black ink straight off the brand background
            relief="flat",  # sets the relief text
            font=(UI_FONT, 9, "bold"),  # a step above the ghost buttons
            padx=10,  # assigns the computed value to padx
            pady=4,  # assigns the computed value to pady
            cursor="hand2",  # sets the cursor text
            borderwidth=0,  # assigns the computed value to borderwidth
        )  # closes the multiline block
        self.banner_toggle.grid(row=0, column=1, sticky="e")  # places the widget in the grid

        # Score card ---------------------------------------------------
        self.card = tk.Frame(  # builds the frame container
            content,  # evaluates the content expression
            bg=PANEL,  # copies the PANEL value into bg
            highlightthickness=1,  # assigns the computed value to highlightthickness
            highlightbackground=BORDER,  # copies the BORDER value into highlightbackground
        )  # closes the multiline block
        self.card.grid(row=5, column=0, sticky="ew", padx=22, pady=(6, 10))  # places the widget in the grid
        self._build_card()  # runs the _build_card() call

        # Report -------------------------------------------------------
        report_frame = tk.Frame(  # builds the frame container
            content, bg=PANEL_ALT, highlightthickness=1, highlightbackground=BORDER  # copies the PANEL_ALT value into content, bg
        )  # closes the multiline block
        report_frame.grid(row=6, column=0, sticky="nsew", padx=22, pady=(0, 10))  # places the widget in the grid
        report_frame.columnconfigure(0, weight=1)  # runs the columnconfigure() call
        report_frame.rowconfigure(0, weight=1)  # runs the rowconfigure() call
        self.report_frame = report_frame  # saves the pane frame for swapping

        self.text_area = tk.Text(  # creates the text_area widget
            report_frame,  # evaluates the report_frame expression
            bg=PANEL_ALT,  # copies the PANEL_ALT value into bg
            fg=TEXT,  # copies the TEXT value into fg
            insertbackground=TEXT,  # copies the TEXT value into insertbackground
            relief="flat",  # sets the relief text
            font=(MONO_FONT, 9),  # assigns the computed value to font
            wrap="word",  # sets the wrap text
            padx=16,  # assigns the computed value to padx
            pady=12,  # assigns the computed value to pady
            spacing1=1,  # assigns the computed value to spacing1
            spacing3=1,  # assigns the computed value to spacing3
            state="disabled",  # sets the state text
            selectbackground=SELECT_BG,  # the shared selection highlight
        )  # closes the multiline block
        self.text_area.grid(row=0, column=0, sticky="nsew")  # places the widget in the grid
        scroll = tk.Scrollbar(  # builds the scrollbar widget
            report_frame, command=self.text_area.yview, bg=PANEL_ALT, troughcolor=PANEL_ALT, width=16  # an easily spotted drag bar
        )  # closes the multiline block
        scroll.grid(row=0, column=1, sticky="ns")  # places the widget in the grid
        self.text_area.configure(yscrollcommand=scroll.set)  # updates the widget settings
        self.text_scroll = scroll  # saves the scrollbar for pane swapping

        # Dashboard pane (lives inside the report frame so it grows with the
        # window; the tab bar swaps it with the text report) ----------------
        dash_holder = tk.Frame(report_frame, bg=PANEL_ALT)  # builds the frame container
        self.dash_holder = dash_holder  # saves the pane frame for swapping
        dash_holder.columnconfigure(0, weight=1)  # runs the columnconfigure() call
        dash_holder.rowconfigure(1, weight=1)  # runs the rowconfigure() call
        dash_holder.grid(  # places the widget in the grid
            row=0, column=0, columnspan=2, sticky="nsew"  # spans the text-area cells
        )  # closes the multiline block
        dash_holder.grid_remove()  # hides the pane until selected

        dash_bar = tk.Frame(dash_holder, bg=PANEL_ALT)  # builds the frame container
        dash_bar.grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 0))  # places the widget in the grid
        tk.Label(  # builds the label widget
            dash_bar, text="Metrics", bg=PANEL_ALT, fg=MUTED, font=(UI_FONT, 9)  # copies the text value into text
        ).grid(row=0, column=0, sticky="w")  # places the widget in the grid
        for offset, (text, command) in enumerate((  # quick-select buttons for the metric row
            ("All", self._select_all_metrics),  # ticks every metric widget
            ("Clear", self._clear_all_metrics),  # empties the dashboard selection
        )):  # closes the pair loop
            button = self._flat_button(  # one factory paints every flat accent button
                dash_bar,  # evaluates the dash_bar expression
                text,  # sets the text text
                command,  # copies the command value
                bg=PANEL_ALT,  # copies the PANEL_ALT value into bg
            )  # closes the multiline block
            button.grid(  # places the widget in the grid
                row=0, column=offset + 1, sticky="w"  # beside the Metrics label
            )  # closes the placement call
        self.dash_vars = {}  # starts the vars mapping
        self.dash_checks = {}  # starts the checks mapping
        for index, (key, (text, _hint)) in enumerate(config.DASHBOARD_METRICS.items()):  # walks the metrics
            var = tk.BooleanVar(value=True)  # every metric ticked by default
            row, col = divmod(index, 5)  # splits into five columns per row
            check = self._check(  # one factory paints every dark-theme checkbox
                dash_bar, var, text,  # wires the event
                command=self._render_metric_dashboard,  # redraws on change
                bg=PANEL_ALT, font=(UI_FONT, 9),  # compact dashboard sizing
                selectcolor=TRACK_COLOUR, pady=1,  # keeps checkboxes compact
            )  # closes the multiline block
            check.grid(row=row + 1, column=col + 2, sticky="w", padx=(0, 6))  # below the label and buttons
            self.dash_vars[key] = var  # saves the variable
            self.dash_checks[key] = check  # saves the check
        tk.Label(  # builds the hint label
            dash_bar,  # evaluates the dash_bar expression
            text="tick the metrics you want; everything unticked stays blank",  # sets the text text
            bg=PANEL_ALT, fg=MUTED, font=(UI_FONT, 8),  # assigns the font value into font
        ).grid(row=99, column=0, columnspan=8, sticky="w", pady=(2, 0))  # places the hint

        canvas_holder = tk.Frame(dash_holder, bg=PANEL_ALT)  # builds the frame container
        canvas_holder.grid(row=1, column=0, sticky="nsew", padx=14, pady=(6, 10))  # places the widget in the grid
        canvas_holder.rowconfigure(0, weight=1)  # runs the rowconfigure() call
        canvas_holder.columnconfigure(0, weight=1)  # runs the columnconfigure() call
        self.metric_canvas = tk.Canvas(  # creates the metric_canvas widget
            canvas_holder, bg=PANEL_ALT, highlightthickness=0  # copies the PANEL_ALT value into canvas_holder, bg
        )  # closes the multiline block
        self.metric_canvas.grid(row=0, column=0, sticky="nsew")  # places the widget in the grid
        dash_scroll = tk.Scrollbar(  # builds the scrollbar widget
            canvas_holder, command=self.metric_canvas.yview, bg=PANEL_ALT, troughcolor=PANEL_ALT, width=16  # an easily spotted drag bar
        )  # closes the multiline block
        dash_scroll.grid(row=0, column=1, sticky="ns")  # places the widget in the grid
        self.metric_canvas.configure(yscrollcommand=dash_scroll.set)  # updates the widget settings
        self.metric_canvas.bind(  # wires the wheel scrolling
            "<MouseWheel>",  # windows wheel event
            lambda event: self.metric_canvas.yview_scroll(int(-event.delta / 120), "units"),  # scrolls by wheel ticks
        )  # closes the multiline block
        self.metric_canvas.bind(  # wires the redraw on resize
            "<Configure>", self._on_metric_canvas_resize,  # redraws when the pane resizes
        )  # closes the multiline block

        # Recommendations pane (ranked remediation list from the findings) --
        recommend_holder = tk.Frame(report_frame, bg=PANEL_ALT)  # builds the frame container
        self.recommend_holder = recommend_holder  # saves the pane frame for swapping
        recommend_holder.columnconfigure(0, weight=1)  # runs the columnconfigure() call
        recommend_holder.rowconfigure(0, weight=1)  # runs the rowconfigure() call
        recommend_holder.grid(  # places the widget in the grid
            row=0, column=0, columnspan=2, sticky="nsew"  # shares the pane cells
        )  # closes the multiline block
        recommend_holder.grid_remove()  # hides the pane until selected
        self.recommend_area = tk.Text(  # creates the recommendations text pane
            recommend_holder,  # evaluates the recommend_holder expression
            bg=PANEL_ALT, fg=TEXT,  # copies the colours into the widget
            insertbackground=TEXT, relief="flat",  # copies the relief text
            font=(MONO_FONT, 9), wrap="word",  # copies the text font
            padx=16, pady=12, spacing1=1, spacing3=1,  # keeps the text readable
            state="disabled",  # locked like the report
            selectbackground=SELECT_BG,  # the shared selection highlight
        )  # closes the multiline block
        self.recommend_area.grid(row=0, column=0, sticky="nsew")  # places the widget in the grid
        recommend_scroll = tk.Scrollbar(  # builds the scrollbar widget
            recommend_holder, command=self.recommend_area.yview, bg=PANEL_ALT, troughcolor=PANEL_ALT, width=16  # an easily spotted drag bar
        )  # closes the multiline block
        recommend_scroll.grid(row=0, column=1, sticky="ns")  # places the widget in the grid
        self.recommend_area.configure(yscrollcommand=recommend_scroll.set)  # updates the widget settings
        self.recommend_area.bind(  # wires the wheel scrolling
            "<MouseWheel>",  # windows wheel event
            lambda event: self.recommend_area.yview_scroll(int(-event.delta / 120), "units"),  # scrolls by wheel ticks
        )  # closes the multiline block

        self._configure_tags()  # runs the _configure_tags() call
        self._configure_tags(self.recommend_area)  # share the report styling
        self._show_pane("report")  # runs the _show_pane() call
        self._set_report_placeholder()  # runs the _set_report_placeholder() call

        # Footer -------------------------------------------------------
        footer = tk.Frame(content, bg=BG)  # builds the frame container
        footer.grid(row=7, column=0, sticky="ew", padx=22, pady=(0, 16))  # places the widget in the grid
        footer.columnconfigure(0, weight=1)  # runs the columnconfigure() call

        self.hint_label = tk.Label(  # builds the label widget
            footer,  # evaluates the footer expression
            text="",  # sets the text text
            bg=BG,  # copies the BG value into bg
            fg=MUTED,  # copies the MUTED value into fg
            font=(UI_FONT, 9),  # assigns the computed value to font
            anchor="w",  # sets the anchor text
        )  # closes the multiline block
        self.hint_label.grid(row=0, column=0, columnspan=6, sticky="ew")  # places the widget in the grid

        self.copy_button = self._footer_button(footer, "Copy report", self.copy_report)  # saves the result on copy_button
        self.copy_button.grid(row=1, column=2, padx=(8, 0), pady=(6, 0))  # places the widget in the grid
        self.save_button = self._footer_button(footer, "Save JSON…", self.save_report)  # saves the result on save_button
        self.save_button.grid(row=1, column=3, padx=(8, 0), pady=(6, 0))  # places the widget in the grid
        self.csv_button = self._footer_button(footer, "Export CSV…", self.export_csv)  # saves the result on csv_button
        self.csv_button.grid(row=1, column=4, padx=(8, 0), pady=(6, 0))  # places the widget in the grid
        self.pdf_button = self._footer_button(footer, "Print Report", self.export_pdf)  # saves the result on pdf_button
        self.pdf_button.grid(row=1, column=5, padx=(8, 0), pady=(6, 0))  # places the widget in the grid
        self.sbom_pdf_button = self._footer_button(footer, "Print SBOM", self.print_sbom)  # renders the SBOM PDF
        self.sbom_pdf_button.grid(row=1, column=6, padx=(8, 0), pady=(6, 0))  # places the widget in the grid
        self.sbom_csv_button = self._footer_button(footer, "Export SBOM", self.export_sbom)  # exports the SBOM CSV
        self.sbom_csv_button.grid(row=1, column=7, padx=(8, 0), pady=(6, 0))  # places the widget in the grid
        self.sum_button = self._footer_button(footer, "Summarize It", self.summarize_report)  # opens the summary popup
        self.sum_button.grid(row=1, column=8, padx=(8, 0), pady=(6, 0))  # places the widget in the grid
        self.gad_button = self._footer_button(footer, "Check GAD", self.check_gad)  # opens the advisory sweep
        self.gad_button.grid(row=1, column=9, padx=(8, 0), pady=(6, 0))  # places the widget in the grid
        self.folder_button = self._footer_button(footer, "Open scan folder", self.open_folder)  # saves the result on folder_button
        self.folder_button.grid(row=1, column=10, padx=(8, 0), pady=(6, 0))  # places the widget in the grid
        for button in self._report_buttons():  # loops over the collection
            button.configure(state="disabled", disabledforeground=DISABLED_GREY)  # updates the widget settings

    def _fit_page(self, event: tk.Event | None = None) -> None:  # defines the _fit_page() function
        """Keeps the scrollable page at the canvas width, at least viewport tall."""  # keeps the docstring text
        canvas = getattr(self, "_page_canvas", None)  # fetches the value
        if canvas is None:  # evaluates the branch condition
            return  # nothing built yet, nothing to fit
        width = canvas.winfo_width()  # reads the mapped width
        height = canvas.winfo_height()  # reads the mapped height
        if width < 120 or height < 60:  # pre-map passes see provisional values
            return  # waits for real geometry instead of shaping to it
        wanted = (int(width), int(max(height, self._page_content.winfo_reqheight())))  # fill or len(rows)
        if getattr(self, "_page_fitted", ()) == wanted:  # evaluates the branch condition
            return  # the same size twice changes nothing, skip the refresh
        self._page_fitted = wanted  # remembers this pass so the pair settles
        canvas.itemconfigure(self._page_window, width=wanted[0], height=wanted[1])  # the frame fills or overflows
        canvas.configure(scrollregion=(0, 0, wanted[0], wanted[1]))  # the scrollbar sees the whole page

    def _on_page_wheel(self, event: tk.Event) -> None:  # defines the _on_page_wheel() function
        """Scrolls the lower page; panes and pop-up dialogs keep their wheel."""  # keeps the docstring text
        widget = event.widget  # the widget the wheel rolled over
        inner = (self.text_area, self.metric_canvas, self.recommend_area)  # the pane wheels
        hit_page = False  # flips only when the climb reaches the page frame
        hit_inner = False  # flips when the wheel sits inside a pane scroller
        while widget is not None:  # climbs while a manager is above the widget
            if widget in inner:  # evaluates the branch condition
                hit_inner = True  # the pane scrolls itself, two wheels fight otherwise
            if widget is self._page_content:  # evaluates the branch condition
                hit_page = True  # the wheel does belong to the page stack
                break  # closes the climb
            parent = widget.winfo_parent()  # the manager labelling the owner
            widget = self.nametowidget(parent) if parent else None  # saves the result on widget
        if not hit_page or hit_inner:  # evaluates the branch condition
            return  # a dialog or a pane owns the wheel instead
        self._page_canvas.yview_scroll(int(-event.delta / 120), "units")  # ticks the page rail by wheel notches

    def _report_buttons(self) -> tuple[tk.Button, ...]:  # defines the _report_buttons() function
        return (  # returns the value to the caller
            self.copy_button,  # evaluates the self.copy_button expression
            self.save_button,  # evaluates the self.save_button expression
            self.csv_button,  # evaluates the self.csv_button expression
            self.pdf_button,  # evaluates the self.pdf_button expression
            self.sbom_pdf_button,  # evaluates the self.sbom_pdf_button expression
            self.sbom_csv_button,  # evaluates the self.sbom_csv_button expression
            self.sum_button,  # evaluates the self.sum_button expression
            self.gad_button,  # evaluates the self.gad_button expression
            self.folder_button,  # evaluates the self.folder_button expression
        )  # closes the multiline block

    def _build_card(self) -> None:  # defines the _build_card() function
        self.card.columnconfigure(1, weight=1)  # runs the columnconfigure() call
        self.card.rowconfigure(0, weight=1)  # runs the rowconfigure() call

        score_box = tk.Frame(self.card, bg=PANEL)  # builds the frame container
        score_box.grid(row=0, column=0, sticky="w", padx=(22, 18), pady=(14, 6))  # places the widget in the grid

        tk.Label(  # runs the Label() call
            score_box,  # evaluates the score_box expression
            text="RISK SCORE",  # the headline above the big number
            bg=PANEL,  # copies the PANEL value into bg
            fg=config.BRAND_GREEN,  # the logo's green
            font=(UI_FONT, 10, "bold"),  # larger, brand-coloured label
        ).grid(row=0, column=0, columnspan=2, sticky="w")  # closes the multiline block

        self.score_label = tk.Label(  # builds the label widget
            score_box,  # evaluates the score_box expression
            text="--",  # sets the text text
            bg=PANEL,  # copies the PANEL value into bg
            fg=DISABLED_GREY,  # sets the fg text
            font=(UI_FONT, 44, "bold"),  # assigns the computed value to font
        )  # closes the multiline block
        self.score_label.grid(row=1, column=0, sticky="s")  # places the widget in the grid
        tk.Label(  # runs the Label() call
            score_box, text="/ 100", bg=PANEL, fg=MUTED, font=(UI_FONT, 10)  # sets the score_box, text text
        ).grid(row=1, column=1, sticky="s", padx=(4, 0), pady=(0, 8))  # closes the multiline block

        middle = tk.Frame(self.card, bg=PANEL)  # builds the frame container
        middle.grid(row=0, column=1, sticky="w", pady=(14, 6))  # places the widget in the grid

        self.verdict_label = tk.Label(  # builds the label widget
            middle,  # evaluates the middle expression
            text="NOT SCANNED",  # sets the text text
            bg=VERDICT_SCANNING_BG,  # the pre-scan badge tint
            fg=TEXT,  # copies the TEXT value into fg
            font=(UI_FONT, 11, "bold"),  # assigns the computed value to font
            padx=12,  # assigns the computed value to padx
            pady=4,  # assigns the computed value to pady
        )  # closes the multiline block
        self.verdict_label.grid(row=0, column=0, sticky="w")  # places the widget in the grid

        self.band_label = tk.Label(  # builds the label widget
            middle,  # evaluates the middle expression
            text="Run a scan to get a verdict",  # sets the text text
            bg=PANEL,  # copies the PANEL value into bg
            fg=MUTED,  # copies the MUTED value into fg
            font=(UI_FONT, 9),  # assigns the computed value to font
        )  # closes the multiline block
        self.band_label.grid(row=1, column=0, sticky="w", pady=(6, 0))  # places the widget in the grid

        counts = tk.Frame(self.card, bg=PANEL)  # builds the frame container
        counts.grid(row=0, column=2, sticky="e", padx=(0, 14), pady=(14, 6))  # places the widget in the grid
        self.count_labels: dict[str, tk.Label] = {}  # evaluates the self.count_labels expression
        for index, severity in enumerate(("critical", "high", "medium", "low")):  # loops over the collection
            tk.Label(  # runs the Label() call
                counts,  # evaluates the counts expression
                text=severity.upper(),  # uppercases the text
                bg=PANEL,  # copies the PANEL value into bg
                fg=SEVERITY_COLOURS[severity],  # copies the SEVERITY_COLOURS value into fg
                font=(UI_FONT, 8, "bold"),  # assigns the computed value to font
            ).grid(row=0, column=index, padx=(12, 0))  # closes the multiline block
            label = tk.Label(  # builds the label widget
                counts,  # evaluates the counts expression
                text="–",  # sets the text text
                bg=PANEL,  # copies the PANEL value into bg
                fg=TEXT,  # copies the TEXT value into fg
                font=(UI_FONT, 15, "bold"),  # assigns the computed value to font
            )  # closes the multiline block
            label.grid(row=1, column=index, padx=(12, 0))  # places the widget in the grid
            self.count_labels[severity] = label  # saves the result on count_labels[severity]

        # Dashboard pie chart: severity breakdown at a glance.
        self.pie_canvas = tk.Canvas(  # creates the drawing canvas
            self.card,  # evaluates the self.card expression
            bg=PANEL,  # copies the PANEL value into bg
            highlightthickness=0,  # assigns the computed value to highlightthickness
            width=250,  # assigns the computed value to width
            height=120,  # assigns the computed value to height
        )  # closes the multiline block
        self.pie_canvas.grid(row=0, column=3, sticky="e", padx=(0, 22), pady=(10, 2))  # places the widget in the grid

        self.reason_label = tk.Label(  # builds the label widget
            self.card,  # evaluates the self.card expression
            text="",  # sets the text text
            bg=PANEL,  # copies the PANEL value into bg
            fg=MUTED,  # copies the MUTED value into fg
            font=(UI_FONT, 9),  # assigns the computed value to font
            anchor="w",  # sets the anchor text
            justify="left",  # sets the justify text
            wraplength=900,  # assigns the computed value to wraplength
        )  # closes the multiline block
        self.reason_label.grid(  # places the widget in the grid
            row=1, column=0, columnspan=3, sticky="ew", padx=22, pady=(0, 4)  # assigns the computed value to row
        )  # closes the multiline block
        self.card.bind("<Configure>", self._resize_reason)  # wires the event handler

        # Confidence gauge: arc sweeping with the confidence score.
        tk.Label(  # runs the Label() call
            self.card,  # evaluates the self.card expression
            text="SCAN CONFIDENCE",  # the headline above the confidence strip
            bg=PANEL,  # copies the PANEL value into bg
            fg=config.BRAND_GREEN,  # the logo's green
            font=(UI_FONT, 10, "bold"),  # larger, brand-coloured label
        ).grid(  # closes the multiline block
            row=2, column=0, columnspan=4, sticky="w", padx=22, pady=(6, 0)  # above the strip
        )  # closes the placement
        self.gauge_canvas = tk.Canvas(  # creates the drawing canvas
            self.card, bg=PANEL, highlightthickness=0, width=400, height=72  # no wide request: the grid must stay free
        )  # closes the multiline block
        self.gauge_canvas.grid(row=3, column=0, columnspan=4, sticky="ew", padx=22, pady=(2, 12))  # places the widget in the grid
        self.gauge_canvas.bind(  # wires the event handler
            "<Configure>", self._on_gauge_resize  # debounces the canvas <Configure> storm
        )  # closes the multiline block

    def _resize_reason(self, event: tk.Event) -> None:
        """Debounces the card's wraplength re-fit so resizes stop thrashing."""
        self._reason_width = event.width  # remembers the newest row width for the timer
        self._after_debounced("_reason_after", self._reason_resize_done)  # one timer per resize burst

    def _reason_resize_done(self) -> None:
        """Apply the newest measured card width to the verdict reason label."""
        self._reason_after = None  # resets the pending handle
        width = getattr(self, "_reason_width", 0)  # the width the last <Configure> reported
        self.reason_label.configure(wraplength=max(width - 60, 300))  # updates the widget settings

    def _on_gauge_resize(self, event: tk.Event) -> None:
        """Schedules one debounced gauge repaint instead of one per pixel."""
        self._after_debounced("_gauge_redraw_after", self._gauge_redraw_done)  # one timer covers the pixel storm

    def _gauge_redraw_done(self) -> None:
        """Debounced gauge redraw; the always-on meter follows the scan."""
        self._gauge_redraw_after = None  # resets the pending handle
        if self._report:  # evaluates the branch condition
            self._render_gauge(self._report)  # keeps the confidence meter drawn

    def _after_debounced(self, attr: str, method) -> None:
        """Cancels any pending ``attr`` timer and re-queues ``method`` at the shared debounce."""
        pending = getattr(self, attr, None)  # fetches the pending timer handle
        if pending:  # evaluates the branch condition
            try:  # watches for errors in the block
                self.after_cancel(pending)  # cancels the queued redraw
            except Exception:  # handles the raised error
                pass  # keeps the block syntactically empty
        setattr(self, attr, self.after(RESIZE_DEBOUNCE_MS, method))  # queues one debounced pass

    # ------------------------------------------------------------------
    # Dashboard visuals (pie chart + confidence gauge)
    # ------------------------------------------------------------------
    def _render_pie(self, report: dict[str, Any]) -> None:  # defines the _render_pie() function
        canvas = self.pie_canvas  # copies the self.pie_canvas value into canvas
        canvas.delete("all")  # removes the matched item
        width = int(canvas["width"])  # runs the int() call
        height = int(canvas["height"])  # runs the int() call
        radius = 42  # assigns the computed value to radius
        cx: int = radius + 14  # evaluates the cx expression
        cy: int = height // 2  # evaluates the cy expression
        box = (cx - radius, cy - radius, cx + radius, cy + radius)  # assigns the computed value to box

        slices = scoring.severity_pie_slices(report["totals"])  # runs the severity_pie_slices() call
        angle = 90.0  # assigns the computed value to angle
        for key, count, colour, fraction in slices:  # loops over the collection
            extent = -360.0 * fraction  # assigns the computed value to extent
            # A truly full-circle sweep collapses to a sliver in Tk.
            if -extent >= 359.99:  # evaluates the branch condition
                extent = -359.99  # assigns the computed value to extent
            canvas.create_arc(  # runs the create_arc() call
                *box,  # spreads the collected values
                start=angle,  # copies the angle value into start
                extent=extent,  # copies the extent value into extent
                fill=colour,  # copies the colour value into fill
                outline=PANEL,  # copies the PANEL value into outline
                width=1,  # assigns the computed value to width
                style="pieslice",  # sets the style text
            )  # closes the multiline block
            angle += extent  # evaluates the angle expression
        # Donut hole with the total in the middle.
        hole = radius - 18  # copies the radius value into hole
        canvas.create_oval(  # runs the create_oval() call
            cx - hole, cy - hole, cx + hole, cy + hole, fill=PANEL, outline=PANEL  # evaluates the cx expression
        )  # closes the multiline block
        canvas.create_text(  # runs the create_text() call
            cx, cy - 6, text=str(report["totals"]["findings"]), fill=TEXT,  # runs the str() call
            font=(UI_FONT, 13, "bold"),  # assigns the computed value to font
        )  # closes the multiline block
        canvas.create_text(  # runs the create_text() call
            cx, cy + 9, text="findings", fill=MUTED, font=(UI_FONT, 6)  # evaluates the cx expression
        )  # closes the multiline block

        # Legend to the right of the pie.
        x0 = cx + radius + 16  # copies the cx value into x0
        y = cy - ((len(slices) - 1) * 19 + 8) / 2 + 8  # counts the items
        for key, count, colour, _fraction in slices:  # loops over the collection
            canvas.create_rectangle(x0, y - 5, x0 + 9, y + 4, fill=colour, outline="")  # runs the create_rectangle() call
            canvas.create_text(  # runs the create_text() call
                x0 + 15,  # evaluates the x0 expression
                y,  # evaluates the y expression
                anchor="w",  # sets the anchor text
                text=f"{key.capitalize()}  {count}",  # sets the text text
                fill=TEXT,  # copies the TEXT value into fill
                font=(UI_FONT, 9),  # assigns the computed value to font
            )  # closes the multiline block
            y += 19  # evaluates the y expression

    def _render_gauge(self, report: dict[str, Any]) -> None:  # defines the _render_gauge() function
        canvas = self.gauge_canvas  # copies the self.gauge_canvas value into canvas
        canvas.delete("all")  # removes the matched item
        confidence = report.get("confidence") or {}  # fetches the value
        if not confidence:  # evaluates the branch condition
            return  # evaluates the return expression

        score = int(confidence.get("score", 0))  # runs the int() call
        colour = config.BRAND_GREEN  # the confidence bar renders in the logo's green
        width = max(canvas.winfo_width(), 320)  # takes the largest value
        bar_right = width - 132  # copies the width value into bar_right
        # Track + fill for the 0-100 meter.
        canvas.create_rectangle(0, 6, bar_right, 26, fill=TRACK_COLOUR, outline="")  # runs the create_rectangle() call
        if score:  # evaluates the branch condition
            canvas.create_rectangle(0, 6, int(bar_right * score / 100), 26, fill=colour, outline="")  # runs the create_rectangle() call
        # Confidence band thresholds.
        for mark in CONFIDENCE_MARKS:  # loops over the collection
            x = int(bar_right * mark / 100)  # runs the int() call
            canvas.create_line(x, 4, x, 28, fill=BG, width=2)  # runs the create_line() call
        canvas.create_text(  # runs the create_text() call
            width - 100, 10, text=f"{score} / 100", fill=colour,  # evaluates the width expression
            font=(UI_FONT, 10, "bold"),  # assigns the computed value to font
        )  # closes the multiline block
        canvas.create_text(  # runs the create_text() call
            width - 100, 26, text=str(confidence.get("band", "")),  # runs the str() call
            fill=MUTED, font=(UI_FONT, 8),  # reads alongside the score
        )  # closes the multiline block
        factors = confidence.get("factors") or []  # fetches the value
        if factors:  # evaluates the branch condition
            text = "   ·   ".join(  # sets the text text
                f"{factor['label']} {factor['score']}%" for factor in factors  # evaluates the f expression
            )  # closes the multiline block
            canvas.create_text(  # runs the create_text() call
                0, 42, anchor="nw", text=text, fill=MUTED, font=(UI_FONT, 9)  # executes the statement
            )  # closes the multiline block
        notes = confidence.get("notes") or []  # fetches the value
        if notes:  # evaluates the branch condition
            joined = "  ·  ".join(notes[:2])  # sets the joined text
            canvas.create_text(  # runs the create_text() call
                0, 58, anchor="nw", text=joined, fill="#7b91b3", font=(UI_FONT, 8)  # executes the statement
            )  # closes the multiline block

    def _clear_dashboard(self) -> None:
        self.pie_canvas.delete("all")
        width = int(self.pie_canvas["width"])
        self.pie_canvas.create_text(
            width // 2,
            62,
            text="severity breakdown · pie chart after a scan",
            fill=DISABLED_GREY,  # sets the DISABLED_GREY value into fill
            font=(UI_FONT, 9),  # assigns the computed value to font
        )
        self.gauge_canvas.delete("all")

    # ------------------------------------------------------------------
    # Metric dashboard pane (tick boxes -> widgets -> canvas)
    # ------------------------------------------------------------------
    def _selected_metrics(self) -> list[str]:
        return [key for key in config.DASHBOARD_ALL if self.dash_vars[key].get()]

    def _select_all_metrics(self) -> None:
        """Tick every dashboard metric and redraw the widgets."""
        self._set_all_metrics(True)  # ticks everything

    def _clear_all_metrics(self) -> None:
        """Untick every dashboard metric so the dashboard renders empty."""
        self._set_all_metrics(False)  # clears everything

    def _set_all_metrics(self, state: bool) -> None:
        """Apply one tick state to all metric checkboxes and redraw once."""
        for var in self.dash_vars.values():  # loops over the variables
            var.set(state)  # programmatic writes do not fire widget commands
        self._render_metric_dashboard()  # one explicit redraw

    def _render_metric_dashboard(self) -> None:
        canvas = self.metric_canvas  # copies the self.metric_canvas value into canvas
        if not canvas.winfo_exists():  # evaluates the branch condition
            return  # evaluates the return expression
        width = canvas.winfo_width()  # reads the mapped width
        if width < 120:  # pane not mapped yet: draw at a provisional width
            width = max(860, getattr(self, "_last_dash_width", 0) or 860)  # picks the provisional width
        self._last_dash_width = width  # remembers the last usable width
        canvas.delete("all")
        selection = self._selected_metrics()
        report = self._report or {}

        if not selection:
            canvas.create_text(
                width // 2, 60, text="No metrics ticked: the dashboard is empty",
                fill=DISABLED_GREY, font=(UI_FONT, 10),
            )
            canvas.configure(scrollregion=(0, 0, width, 120))
            return

        payloads = dashboard.collect_metrics(report, selection)
        x_margin = 22
        y = 16
        track_right = width - 96

        for key, payload in payloads.items():
            kind = payload.get("kind")
            canvas.create_text(
                x_margin, y, anchor="nw",
                text=str(payload.get("label") or "").upper(),
                fill=config.BRAND_GREEN, font=(UI_FONT, 10, "bold"),
            )
            y += 20
            explainer = dashboard.METRIC_EXPLAINERS.get(key)  # what it is and why it matters
            if explainer:  # one wrapped line under every section title
                text_width = max(300, width - x_margin - 130)  # the wrap window the pane allows
                wrapped_lines = max(1, -(-(self._explain_font.measure(explainer)) // text_width))
                canvas.create_text(
                    x_margin, y, anchor="nw",
                    width=text_width, text=explainer,
                    fill="#a9bbd4", font=(UI_FONT, 8),
                )
                y += wrapped_lines * 13 + 5  # the measured wrap keeps blocks from colliding
            if not report:
                canvas.create_text(
                    x_margin + 4, y, anchor="nw",
                    text="(run a scan to fill this widget)",
                    fill=MUTED, font=(UI_FONT, 9),
                )
                y += 26
                continue

            if kind == "number":
                value = payload.get("value", 0)
                colour = payload.get("colour") or TEXT
                canvas.create_text(
                    x_margin + 6, y, anchor="nw", text=str(value),
                    fill=colour, font=(UI_FONT, 24, "bold"),
                )
                caption = payload.get("caption") or ""
                value_text = str(value)  # the measured figure, word or number alike
                caption_x = (  # the real pixel width, no more per-character guessing
                    x_margin + 6 + self._dash_value_font.measure(value_text) + 18  # one fixed gutter
                )  # closes the x computation
                canvas.create_text(
                    caption_x, y + 14, anchor="nw",
                    text=caption, fill=MUTED, font=(UI_FONT, 9),
                )
                y += 44
            elif kind == "bar":
                rows = payload.get("rows") or []
                top = float(payload.get("max") or 1)
                bar_left = x_margin + 190
                for bar_label, bar_value, bar_colour in rows:
                    canvas.create_text(
                        x_margin, y + 2, anchor="nw",
                        text=str(bar_label)[:26], fill=TEXT, font=(MONO_FONT, 9),
                    )
                    track = track_right - bar_left
                    fraction = min(1.0, float(bar_value) / top) if top else 0
                    canvas.create_rectangle(
                        bar_left, y + 3, bar_left + track, y + 13,
                        fill=TRACK_COLOUR, outline="",
                    )
                    canvas.create_rectangle(
                        bar_left, y + 3, bar_left + track * fraction, y + 13,
                        fill=bar_colour, outline="",
                    )
                    canvas.create_text(
                        track_right + 8, y + 2, anchor="nw",
                        text=str(bar_value), fill=TEXT, font=(MONO_FONT, 9),
                    )
                    y += 16
                note = payload.get("note") or ""
                if note:
                    canvas.create_text(
                        x_margin, y, anchor="nw", text=f"({note})",
                        fill=MUTED, font=(UI_FONT, 8),
                    )
                    y += 13
            elif kind == "donut":
                rows = payload.get("rows") or []
                shares = sum(float(v) for _l, v, _c in rows) or 1
                segment_x = x_margin
                for label_s, value_s, colour_s in rows:
                    seg_width = (track_right - x_margin) * (float(value_s) / shares)
                    canvas.create_rectangle(
                        segment_x, y, segment_x + max(seg_width - 2, 0), y + 14,
                        fill=colour_s, outline="",
                    )
                    segment_x += seg_width
                # The legend lays the labels out by their measured pixel width
                # (a fixed 9px step once crammed them into one unreadable blob)
                # and wraps to another line before reaching the right edge.
                x_margin = 22
                legend_x = x_margin  # the legend starts at the left margin
                legend_y = y + 20  # the first legend line under the bar
                for label_s, value_s, colour_s in rows:
                    text_s = f"{label_s} {round(100 * float(value_s) / shares)}%"
                    text_w = self._legend_font.measure(text_s)  # the pixel width of this entry
                    if legend_x + text_w > width - 30 and legend_x > x_margin:  # runs out of room
                        legend_x = x_margin  # wraps the legend to a fresh line
                        legend_y += 14  # one text line further down
                    canvas.create_text(
                        legend_x, legend_y, anchor="nw",
                        text=text_s, fill=TEXT, font=(UI_FONT, 9),
                    )
                    legend_x += text_w + 14  # a breathing gap before the next entry
                legend_extra = legend_y - (y + 20)  # how far the legend sank from wraps
                note = payload.get("note") or ""
                if note:
                    canvas.create_text(
                        x_margin, legend_y + 14, anchor="nw", text=f"({note})",
                        fill=MUTED, font=(UI_FONT, 8),
                    )
                y += 62 + legend_extra  # the single-line legend matches yesterday's 62px
            elif kind == "heat":
                sevs = payload.get("sevs") or []
                rows = list(payload.get("rows") or [])
                if not sevs or not rows:
                    canvas.create_text(
                        x_margin + 4, y, anchor="nw", text="(nothing to plot)",
                        fill=MUTED, font=(UI_FONT, 9),
                    )
                    y += 22
                else:
                    heat_left = x_margin + 300
                    cell_w = min(HEAT_CELL_MAX, (track_right - heat_left) / len(sevs))  # the widest cell the layout allows
                    max_count = max([c for _f, b in rows for c in b.values()] or [1])
                    for index, sev in enumerate(sevs):
                        canvas.create_text(
                            heat_left + index * cell_w + 12, y, anchor="nw",
                            text=sev[:1].upper(), fill=MUTED, font=(UI_FONT, 8),
                        )
                    y += 16
                    for file_id, buckets in rows:
                        canvas.create_text(
                            x_margin, y, anchor="nw",
                            text=str(file_id), fill=TEXT, font=(MONO_FONT, 9),
                        )
                        for index, sev in enumerate(sevs):
                            value = int(buckets.get(sev, 0) or 0)
                            if value:
                                intensity = 0.25 + 0.75 * min(1.0, value / max(max_count, 1))
                                hex_colour = self._heat_fill(sev, intensity)
                                canvas.create_rectangle(
                                    heat_left + index * cell_w, y,
                                    heat_left + (index + 1) * cell_w - 2, y + 13,
                                    fill=hex_colour,
                                    outline=BG,
                                )
                            canvas.create_text(
                                heat_left + index * cell_w + 12, y + 1, anchor="nw",
                                text=str(value) if value else "", fill=TEXT,
                                font=(UI_FONT, 8),
                            )
                        y += 16
            elif kind == "table":
                for row in payload.get("rows") or []:
                    canvas.create_text(
                        x_margin + 4, y, anchor="nw",
                        text="  ·  ".join(str(cell) for cell in row),
                        fill=TEXT, font=(MONO_FONT, 9),
                    )
                    y += 14
                note = payload.get("note") or ""
                if note:
                    canvas.create_text(
                        x_margin, y, anchor="nw", text=f"({note})",
                        fill=MUTED, font=(UI_FONT, 8),
                    )
                    y += 13
            elif kind == "na":
                canvas.create_text(
                    x_margin + 4, y, anchor="nw",
                    text=f"(not assessable here: {payload.get('note', '')})",
                    fill=SEVERITY_COLOURS["unknown"], font=(UI_FONT, 9),
                )
                y += 26
            y += 14  # gap between widgets

        canvas.configure(scrollregion=(0, 0, width, max(y + 20, 200)))

    def _hex_to_rgb(self, hex_value: str) -> tuple[int, ...]:
        text = str(hex_value or "").lstrip("#")  # strips the hash
        return tuple(int(text[index:index + 2], 16) for index in (0, 2, 4))  # parses the channels

    # Dark, brand-tuned fills for the heat map so white axis text stays readable.
    _HEAT_FILLS = {
        "critical": "#b91c1c",
        "high": "#c2410c",
        "medium": "#a16207",
        "low": "#4d7c0f",
        "unknown": "#44577a",
    }

    def _heat_fill(self, sev: str, intensity: float) -> str:
        """Blend the dark panel into the severity colour by ``intensity`` (memoised)."""
        amount = min(1.0, max(0.30, intensity))  # keeps faint cells visible
        key = (sev, round(amount * 100))  # one cache slot per quantised shade
        cached = self._heat_cache.get(key)  # skips the hex parsing on repeats
        if cached:  # evaluates the branch condition
            return cached  # returns the blended colour to the caller
        base = self._heat_base  # the dashboard panel colour, parsed once in __init__
        target = self._hex_to_rgb(self._HEAT_FILLS.get(sev, "#44577a"))  # picks the severity tone
        blended = tuple(  # interpolates the channels
            round(b * (1 - amount) + t * amount)
            for b, t in zip(base, target)
        )
        fill = f"#{blended[0]:02x}{blended[1]:02x}{blended[2]:02x}"  # packs the channels
        self._heat_cache[key] = fill  # remembers the shade for every other cell
        return fill  # returns the value to the caller

    def _on_metric_canvas_resize(self, event: tk.Event) -> None:
        """Schedules a debounced redraw when the dashboard pane resizes."""
        if event.width <= 120:  # pane is being mapped or torn down
            return  # returns nothing to the caller
        self._after_debounced("_metric_redraw_after", self._metric_redraw_done)  # queues one debounced redraw

    def _metric_redraw_done(self) -> None:  # defines the _metric_redraw_done() function
        """Debounced dashboard redraw; the card charts follow the scan state."""
        self._metric_redraw_after = None  # resets the pending handle
        self._render_metric_dashboard()  # runs the _render_metric_dashboard() call
        if self._report:  # evaluates the branch condition
            self._render_pie(self._report)  # keeps the real donut, never the hint
            self._render_gauge(self._report)  # keeps the confidence meter drawn
        else:  # covers the remaining branch
            self._clear_dashboard()  # no scan yet: show the placeholder hints

    def _tab_button(self, parent: tk.Frame, text: str, command) -> tk.Label:  # defines the _tab_button() function
        label = tk.Label(  # builds the label widget
            parent,  # evaluates the parent expression
            text=text,  # copies the text value into text
            bg=PANEL_ALT,  # copies the PANEL_ALT value into bg
            fg=MUTED,  # copies the MUTED value into fg
            font=(UI_FONT, 9, "bold"),  # assigns the computed value to font
            padx=14,  # assigns the computed value to padx
            pady=8,  # assigns the computed value to pady
            cursor="hand2",  # sets the cursor text
        )  # closes the multiline block
        label.pack(side="left")  # places the widget in the layout
        label.bind("<Button-1>", lambda _e: command())  # wires the event handler
        return label  # returns the label to the caller

    def _check(  # defines the _check() factory
        self,  # evaluates the self expression
        parent: tk.Widget,  # the row or pane the box lands in
        var: tk.BooleanVar,  # the tick state variable
        text: str,  # the visible caption
        command=None,  # optional change callback (var-traced boxes need none)
        *,  # spreads the collected values
        bg: str = BG,  # the row background behind the box
        font=(UI_FONT, 9),  # the caption tuple (dashboxes pass the smaller 8)
        selectcolor: str = PANEL_ALT,  # the tick-well colour
        padx: int = 2,  # the caption inset
        pady: int = 0,  # the vertical inset
        anchor: str = "center",  # the caption alignment
    ) -> tk.Checkbutton:  # closes the signature
        """One factory paints every dark-theme Checkbutton in the app."""
        extra = dict(bg=bg, font=font, selectcolor=selectcolor, padx=padx, pady=pady, anchor=anchor)  # the shared config, callers may nudge
        return tk.Checkbutton(  # builds the checkbox widget
            parent,  # evaluates the parent expression
            text=text,  # sets the text text
            variable=var,  # copies the var value into variable
            command=command,  # copies the command value into command
            fg=TEXT,  # copies the TEXT value into fg
            activebackground=bg,  # copies the bg value into activebackground
            activeforeground=TEXT,  # copies the TEXT value into activeforeground
            highlightthickness=0,  # assigns the computed value to highlightthickness
            bd=0,  # assigns the computed value to bd
            cursor="hand2",  # sets the cursor text
            **extra,  # spreads the collected values
        )  # closes the multiline block

    def _flat_button(self, parent: tk.Widget, text: str, command, *, bg: str = BG, padx: int = 4) -> tk.Button:
        """One factory paints every flat accent/ghost quick-button in the app."""
        return tk.Button(  # builds the button widget
            parent,  # evaluates the parent expression
            text=text,  # copies the text value into text
            command=command,  # copies the command value into command
            bg=bg,  # copies the bg value into bg
            fg=config.BRAND_GREEN,  # the brand accent
            activebackground=bg,  # copies the activebackground text
            activeforeground=TEXT,  # copies the TEXT value into activeforeground
            relief="flat",  # sets the relief text
            font=(UI_FONT, 9),  # assigns the computed value to font
            padx=padx,  # assigns the computed value to padx
            pady=0,  # assigns the computed value to pady
            cursor="hand2",  # sets the cursor text
            borderwidth=0,  # assigns the computed value to borderwidth
        )  # closes the multiline block

    def _footer_button(self, parent: tk.Frame, text: str, command) -> tk.Button:  # defines the _footer_button() function
        return tk.Button(  # returns the tk.Button to the caller
            parent,  # evaluates the parent expression
            text=text,  # copies the text value into text
            command=command,  # copies the command value into command
            bg=PANEL,  # copies the PANEL value into bg
            fg=TEXT,  # copies the TEXT value into fg
            activebackground=ACTIVE_ROW_BG,  # sets the activebackground text
            activeforeground=TEXT,  # copies the TEXT value into activeforeground
            relief="flat",  # sets the relief text
            font=(UI_FONT, 9),  # assigns the computed value to font
            padx=12,  # assigns the computed value to padx
            pady=5,  # assigns the computed value to pady
            cursor="hand2",  # sets the cursor text
            borderwidth=0,  # assigns the computed value to borderwidth
        )  # closes the multiline block

    def _configure_tags(self, area: tk.Text | None = None) -> None:  # defines the _configure_tags() function
        area = area or self.text_area  # defaults to the report panel
        area.tag_configure("title", font=(UI_FONT, 13, "bold"), foreground=TEXT, spacing3=4)  # runs the tag_configure() call
        area.tag_configure("subtitle", foreground=MUTED, spacing3=10)  # runs the tag_configure() call
        area.tag_configure(  # runs the tag_configure() call
            "h", font=(UI_FONT, 9, "bold"), foreground=ACCENT, spacing1=12, spacing3=4  # supplies the literal text
        )  # closes the multiline block
        area.tag_configure("body", foreground=TEXT)  # runs the tag_configure() call
        area.tag_configure("muted", foreground=MUTED)  # runs the tag_configure() call
        area.tag_configure("loc", foreground=MUTED)  # runs the tag_configure() call
        area.tag_configure("link", foreground=config.BRAND_GREEN)  # runs the tag_configure() call
        area.tag_configure("verdict_ok", foreground=OK, font=(UI_FONT, 9, "bold"))  # runs the tag_configure() call
        area.tag_configure("verdict_bad", foreground=DANGER, font=(UI_FONT, 9, "bold"))  # runs the tag_configure() call
        for severity, colour in SEVERITY_COLOURS.items():  # loops over the collection
            area.tag_configure(f"sev_{severity}", foreground=colour)  # runs the tag_configure() call
        area.tag_configure("mono_hint", foreground=MUTED)  # runs the tag_configure() call

    # ------------------------------------------------------------------
    # Tabs
    # ------------------------------------------------------------------
    def _show_pane(self, pane: str) -> None:  # defines the _show_pane() function
        self._pane = pane  # saves the result on _pane
        for name, label in (  # loops over the collection
            ("report", self.report_tab),  # executes the statement
            ("log", self.log_tab),  # executes the statement
            ("dashboard", self.dash_tab),  # executes the statement
            ("recommend", self.recommend_tab),  # executes the statement
            ("about", self.about_tab),  # executes the statement
        ):  # closes the multiline block
            label.configure(  # one configure paints the whole tab pill
                # The active tab picks up the logo green with near-black ink
                # (the same readable-on-green pairing the verdict badge uses);
                # inactive tabs stay flat on the panel navy.
                fg=BLACK_INK if name == pane else MUTED,  # the active tab reads black
                bg=config.BRAND_GREEN if name == pane else PANEL_ALT,  # the active tab gets the logo green
            )  # closes the multiline block

        # The report frame hosts the tab bar and both inner panes; the
        # dashboard is one of its children, so the frame always stays mapped.
        self.report_frame.grid()  # keeps the tab bar and panes visible
        # The score card sits in its own row of the main window, beside the
        # tab strip, so it stays visible on every tab (it carries the pie and
        # the verdict, not a duplicate). The tab-strip's "Hide score banner"
        # toggle is the only thing that collapses it, exactly as the user
        # asked for it: session-wide, not per-tab.
        if self._banner_hidden:  # evaluates the branch condition
            self.card.grid_remove()  # frees the card's vertical space when hidden
        else:  # covers the remaining branch
            self.card.grid()  # restores the score card
        if pane in {"dashboard", "recommend"}:  # both panes live outside the text cell
            self.text_area.grid_remove()  # hides the text report
            self.text_scroll.grid_remove()  # hides the report scrollbar
            self.dash_holder.grid_remove()  # first off: hide the dashboard
            self.recommend_holder.grid_remove()  # first off: hide the recommendations
        else:  # covers the remaining branch
            self.dash_holder.grid_remove()  # hides the dashboard pane
            self.recommend_holder.grid_remove()  # hides the recommendations pane
            self.text_area.grid()  # shows the text report
            self.text_scroll.grid()  # shows the report scrollbar

        if pane == "dashboard":  # evaluates the branch condition
            self.dash_holder.grid()  # shows the dashboard pane
            width = self.metric_canvas.winfo_width()  # the canvas width on this visit
            last = getattr(self, "_last_dash_width", 0)  # the width the last render used
            if self._pane_dirty.get("dashboard", False) or abs(width - last) > 2:  # state or size moved
                self._render_metric_dashboard()  # runs the _render_metric_dashboard() call
                self._pane_dirty["dashboard"] = False  # clears the pane's dirty flag
        elif pane == "recommend":  # evaluates the branch condition
            self.recommend_holder.grid()  # shows the recommendations pane
            if self._pane_dirty.get("recommend", False):  # only repaints when its state changed
                self._render_recommendations()  # runs the _render_recommendations() call
                self._pane_dirty["recommend"] = False  # clears the pane's dirty flag

        if pane == "report":  # evaluates the branch condition
            self._refresh_text_pane("report", self._render_report)  # the cache skips unchanged reports
        elif pane == "log":  # checks the alternate condition
            self._refresh_text_pane("log", self._render_log)  # the live appends keep it current
        elif pane == "dashboard":  # evaluates the branch condition
            pass  # dashboard drawn above
        else:  # covers the remaining branch
            self._refresh_text_pane("about", self._render_about)  # the static page is built once

    def _refresh_text_pane(self, pane: str, renderer) -> None:
        """Rewrites the shared text widget only when pane content moved on."""
        if self._text_area_pane == pane and not self._pane_dirty.get(pane, True):  # evaluates the branch condition
            area = self.text_area  # copies the self.text_area value into area
            area.yview_moveto(0)  # returns to the top without a repaint
            return  # the pane is already exactly as it should read
        renderer()  # runs the pane's own render into the shared text widget
        self._text_area_pane = pane  # the pane now owns the shared text widget
        self._pane_dirty[pane] = False  # clears the pane's dirty flag

    def _write(  # defines the _write() function
        self,  # evaluates the self expression
        segments: list[tuple[str, tuple[str, ...]]],  # evaluates the segments expression
        *,  # spreads the collected values
        images: list[tk.PhotoImage] | None = None,  # evaluates the images expression
        area: tk.Text | None = None,  # targets the report by default
    ) -> None:  # closes the multiline block
        area = area or self.text_area  # copies the self.text_area value into area
        area.configure(state="normal")  # updates the widget settings
        area.delete("1.0", "end")  # removes the matched item
        for image in images or []:  # loops over the collection
            area.image_create("end", image=image)  # runs the image_create() call
        # One insert per same-tag run instead of one per segment: identical
        # text, a fraction of the Tcl round-trips on a long report.
        for blob, tags in report_view.batch_segments(segments):  # loops over the coalesced runs
            if isinstance(tags, tk.Widget):  # embedded controls ride alongside text
                area.window_create("end", window=tags)  # embeds the control
                continue  # skips to the next loop iteration
            area.insert("end", blob, tags)  # inserts the run exactly as composed
        area.configure(state="disabled")  # updates the widget settings
        area.yview_moveto(0)  # runs the yview_moveto() call

    def _set_report_placeholder(self) -> None:  # defines the _set_report_placeholder() function
        self._write(  # runs the _write() call
            [  # executes the statement
                ("Nothing scanned yet\n", ("title",)),  # executes the statement
                (  # executes the statement
                    "Paste a GitHub repository URL above and press Scan. The app will:\n\n"  # maps the Paste a GitHub repositor dictionary entry
                    "  1. download the repository source (no Git required)\n"  # supplies the literal text
                    "  2. run the selected scanners: CodeQL, Trivy, Semgrep CE, Grype,\n"  # supplies the literal text
                    "     OSV-Scanner, GitLeaks, TruffleHog, Syft, Checkov and GuardDog,\n"  # supplies the literal text
                    "     plus Nuclei, Kubescape, Scorecard and OSS-Fuzz\n"  # adds the hardening row
                    "  3. merge duplicate findings across tools so a CVE found by three\n"  # supplies the literal text
                    "     dependency scanners is charged once but names all three\n"  # supplies the literal text
                    "  4. map your findings onto any compliance framework you ticked\n"  # supplies the literal text
                    "  5. subtract weighted penalties from 100 and show the verdict, the\n"  # supplies the literal text
                    "     dashboard pie chart, a confidence figure, the greatest risks,\n"  # supplies the literal text
                    "     and where every finding was identified\n\n"  # supplies the literal text
                    "Any other web address starts a website scan instead: the built-in\n"  # adds the web note
                    "web audit plus (when ticked) Nuclei check the live site directly.\n"  # finishes the web note
                ,  # keeps the tuple shape honest
                    ("body",),  # executes the statement
                ),  # closes the multiline block
                (  # executes the statement
                    "The first scan downloads the scanners into "  # supplies the literal text
                    f"{config.CACHE_DIR} (several hundred MB plus a Semgrep virtual "  # supplies the literal text
                    "environment). Later scans start immediately.\n",  # supplies the literal text
                    ("muted",),  # executes the statement
                ),  # closes the multiline block
            ]  # closes the multiline block
        )  # closes the multiline block

    def _render_report(self) -> None:  # defines the _render_report() function
        self._text_area_pane = "report"  # this pane owns the shared text widget now
        if not self._report:  # evaluates the branch condition
            self._set_report_placeholder()  # runs the _set_report_placeholder() call
            self._pane_dirty["report"] = False  # the placeholder is itself a finished render
            return  # evaluates the return expression

        key = self._report_cache_key()  # report identity, omissions and dashboard selection in one
        segments = self._segment_cache.get(key)  # the composed order for exactly this state
        if segments is None:  # only an actually-changed report rebuilds the layout
            self._destroy_risk_checkboxes()  # stale boxes die only when we rebuild
            segments = report_view.build_report_segments(  # runs the build_report_segments() call
                self._report,  # copies the self._report value into report
                tuple(sorted(self._omitted_groups)),  # a frozen view of the reviewer's exclusions
                self._risk_box_marker,  # the hook splicing replayable marker rows in
            )  # closes the multiline block
            self._segment_cache.clear()  # stale entries hold dead references
            self._segment_cache[key] = segments  # caches the composed order for cheap tab switches
        self._destroy_risk_checkboxes()  # a rebuild wipes the widgets; Tcl dead ones clean up quietly
        self._write(self._rehydrate_risk_boxes(segments))  # writes the live widget-bearing order
        self._pane_dirty["report"] = False  # the shared text widget now shows this report

    def _report_cache_key(self) -> tuple[Any, ...]:  # defines the _report_cache_key() function
        """The state tuple that decides whether a report render is reusable."""
        report = self._report or {}  # fetches the value
        return (  # returns the state tuple to the caller
            id(report),  # each scan builds a fresh report dictionary
            report.get("generated_at", ""),  # belt and braces against dictionary reuse
            tuple(sorted(self._omitted_groups)),  # the reviewer's exclusion set
            tuple(self._selected_metrics()),  # the dashboard selection hash
        )  # closes the state tuple

    def _destroy_risk_checkboxes(self) -> None:  # defines the _destroy_risk_checkboxes() function
        """Destroys every embedded omission checkbox from a previous render."""
        for entry in self._risk_checkboxes:  # finds the previous render's misses
            box, var, trace_id = entry  # unpacks the tuple into the parts
            try:  # watches for errors in the block
                var.trace_vdelete("write", trace_id)  # removes the var trace
            except Exception:  # handles the raised error
                pass  # keeps the block syntactically empty
            try:  # watches for errors in the block
                box.destroy()  # removes the stale checkbox
            except Exception:  # handles the raised error
                pass  # keeps the block syntactically empty
        self._risk_checkboxes.clear()  # starts the list over

    def _risk_box_marker(self, key: str, ticked: bool) -> list:  # defines the _risk_box_marker() function
        """The builder's hook: a replayable marker for one omission row.

        Live checkbox widgets cannot be cached (Tcl destroys embedded
        windows when the text pane is rewiped), so the cached layout
        stores a marker dictionary and the widgets are built fresh at
        every write."""
        return [({"risk_box": key, "ticked": ticked}, RISK_BOX_SLOT), ("\n", ())]  # the marker pair, then the newline

    def _rehydrate_risk_boxes(self, segments: list) -> list:  # defines the _rehydrate_risk_boxes() function
        """Replaces every risk marker with a freshly built live checkbox."""
        live: list = []  # the widget-bearing order the writer receives
        for text, tags in segments:  # walks the cached order
            if isinstance(text, dict) and "risk_box" in text:  # a boxed omission row
                key = text["risk_box"]  # the theme's stable key
                box = self._make_risk_checkbox(key, text["ticked"])  # the widget built now
                live.append((None, box))  # embeds the checkbox, alone on its own line
            else:  # a plain text (or image-free) segment
                live.append((text, tags))  # rides through untouched
        return live  # returns the live order to the writer

    def _make_risk_checkbox(self, key: str, ticked: bool) -> tk.Checkbutton:  # defines the _make_risk_checkbox() function
        """Builds one live "Omit from Report" checkbox and wires its trace."""
        box_var = tk.BooleanVar(value=ticked)  # reflects the live choice
        box = self._check(  # one factory paints every dark-theme checkbox
            self.text_area,  # evaluates the self.text_area expression
            box_var,  # wires the event
            "Omit from Report",  # names what the tick does, right on the box
            bg=PANEL_ALT, font=(UI_FONT, 9),  # a quiet label; the tick carries the story
            selectcolor=TRACK_COLOUR, padx=0, pady=0, anchor="w",  # the box glyph lines up with the finding numbers
        )  # closes the multiline block
        trace_id = box_var.trace_add(  # the variable state is the single source of truth
            "write",  # fires whenever the tick state changes
            lambda *_args, k=key, v=box_var: self._sync_omitted(k, v),  # rescores on each change
        )  # closes the trace pair
        self._risk_checkboxes.append((box, box_var, trace_id))  # saves the result for cleanup
        return box  # returns the widget to the caller

    def _mark_results_dirty(self) -> None:  # defines the _mark_results_dirty() function
        """Flags every results pane to repaint on its next visit."""
        for pane in ("report", "log", "dashboard", "recommend"):  # the About page never changes
            self._pane_dirty[pane] = True  # reassigns the flag


    def _render_log(self) -> None:  # defines the _render_log() function
        area = self.text_area  # copies the self.text_area value into area
        area.configure(state="normal")  # updates the widget settings
        area.delete("1.0", "end")  # removes the matched item
        area.insert("end", "\n".join(self._log_buffer), ("body",))  # inserts text or data
        self._log_lines = len(self._log_buffer)  # counters rebuilt from the buffer, never drifting
        area.configure(state="disabled")  # updates the widget settings
        area.see("end")  # runs the see() call

    def _render_about(self) -> None:  # defines the _render_about() function
        if self._about_segments is None:  # the static page composes exactly once
            images: list[tk.PhotoImage] = []  # evaluates the images expression
            try:  # watches for errors in the block
                logo = self._brand_image(config.BRANDING_LOGO, 12)  # the cached about variant
                if logo:  # evaluates the branch condition
                    images.append(logo)  # adds an item to the list
            except Exception:  # handles the raised error
                pass  # keeps the block syntactically empty
            self._about_segments = (self._about_page_segments(), images)  # text and art, built one time
        segments, images = self._about_segments  # unpacks the composed page
        self._write(  # runs the _write() call
            segments,  # the cached About page content
            images=images,  # copies the images value into images
        )  # closes the multiline block

    def _about_page_segments(self) -> list:  # defines the _about_page_segments() function
        """The About pane's segment list; static for the whole session."""
        return [  # returns the value to the caller
            (f"  {config.APP_NAME} {config.APP_VERSION}\n", ("title",)),  # executes the statement
                (  # executes the statement
                    f"\n{config.APP_TAGLINE}. A local security triage tool. It clones nothing "  # supplies the literal text
                    "(source arrives as a GitHub zip), runs fifteen open-source scanners, "  # supplies the literal text
                    "and converts their raw output into one score you can actually read. "  # supplies the literal text
                    "Every finding names the scanner that found it and the file and line "  # supplies the literal text
                    "where it lives.\n",  # supplies the literal text
                    ("body",),  # executes the statement
                ),  # closes the multiline block
                (  # executes the statement
                    "Paste a GitHub repository URL for the full source scan - or any other web "  # supplies the literal text
                    "address to check the live site instead: the built-in web audit reads the "  # supplies the literal text
                    "page's hardening headers and probes classic exposed files (.env, .git/config), "  # supplies the literal text
                    "and Nuclei runs its active DAST templates if ticked. Source-only scanners are "  # supplies the literal text
                    "marked not applicable for a website scan, and the verdict is scored from the "  # supplies the literal text
                    "web findings alone.\n",  # supplies the literal text
                    ("body",),  # executes the statement
                ),  # closes the multiline block
                ("\n\nSCANNERS\n", ("h",)),  # executes the statement
                (  # executes the statement
                    "  CodeQL        data-flow security queries per detected language\n"  # supplies the literal text
                    "  Trivy         dependency CVEs, committed secrets, IaC/container misconfig\n"  # supplies the literal text
                    "  Semgrep CE    pattern-based code security (community rules)\n"  # supplies the literal text
                    "  Grype         dependency CVEs from the Anchore database\n"  # supplies the literal text
                    "  OSV-Scanner   dependency CVEs from the OSV database\n"  # supplies the literal text
                    "  GitLeaks      committed secrets, with the value redacted\n"  # supplies the literal text
                    "  TruffleHog    committed secrets; verification is disabled so no\n"  # supplies the literal text
                    "                secret is ever sent to a third party\n"  # supplies the literal text
                    "  Syft          SBOM inventory; adds context, never removes points\n"  # supplies the literal text
                    "  Checkov       IaC and container misconfigurations (and secret checks)\n"  # supplies the literal text
                    "  GuardDog      malicious-package and supply-chain patterns\n"  # supplies the literal text
                    "  Nuclei        active DAST templates against the live web site\n"  # supplies the literal text
                    "  Kubescape     Kubernetes/IaC misconfigurations (NSA + MITRE)\n"  # supplies the literal text
                    "  Scorecard     OpenSSF posture checks from the public scorecard.dev\n"  # supplies the literal text
                    "                API, with no binary to install\n"  # supplies the literal text
                    "  OSS-Fuzz      continuous-fuzzing coverage signal from the\n"  # supplies the literal text
                    "                google/oss-fuzz project registry\n",  # supplies the literal text
                    ("body",),  # executes the statement
                ),  # closes the multiline block
                ("\n\nWHAT EACH SCANNER DOES\n", ("h",)),  # executes the statement
                *self._scanner_profile_segments(),  # one paragraph per scanner
                ("\n\nHOW THE SCORE WORKS\n", ("h",)),  # executes the statement
                (  # executes the statement
                    "Start at 100 and subtract a weighted penalty per finding. Category caps stop "  # supplies the literal text
                    "one scanner from dominating. Trivy, Grype and OSV findings about the same CVE "  # supplies the literal text
                    "are merged and charged once; the same applies to secrets found by more than "  # supplies the literal text
                    "one tool and to IaC checks found by both Trivy and Checkov. A merged finding "  # supplies the literal text
                    "still lists every detecting tool. Syft only inventories components, so it "  # supplies the literal text
                    "cannot change the score by itself. A repo only counts "  # supplies the literal text
                    "as SECURE at 85+ with zero critical findings; every other outcome is INSECURE, "  # supplies the literal text
                    "including runs where a required scanner (CodeQL or Trivy) failed. Failures of "  # supplies the literal text
                    "the optional scanners become warnings instead.\n",  # supplies the literal text
                    ("body",),  # executes the statement
                ),  # closes the multiline block
                ("\n\nCONFIDENCE & COMPLIANCE MAPPING\n", ("h",)),  # executes the statement
                (  # executes the statement
                    "The confidence figure (gauge next to the score) rates how trustworthy this "  # supplies the literal text
                    "report is: it weighs whether the selected scanners completed (partial "  # maps the report is: it weighs whe dictionary entry
                    "results count for half), whether "  # supplies the literal text
                    "independent tools corroborated each other's findings, whether severities "  # executes the statement
                    "were actually rated (vs unknown) and how many tools ran. Compliance "  # supplies the literal text
                    "framework checkboxes map your findings onto the controls of NIST RMF, NIST "  # supplies the literal text
                    "CSF, HIPAA, GDPR, CMMC, ISO 27001, PCI DSS or SOC 2 Type 2. Mapping is "  # supplies the literal text
                    "keyword-based and transparent, never changes the score, and a control with "  # supplies the literal text
                    "no findings is evidence of a clean check, not proof of compliance.\n",  # supplies the literal text
                    ("body",),  # executes the statement
                ),  # closes the multiline block
                ("\n\nCARE AND FEEDING\n", ("h",)),  # executes the statement
                (  # executes the statement
                    "Alongside the scanners, the app pulls maintenance statistics from the GitHub "  # supplies the literal text
                    "API: last commit and last release, commit and release cadence, the "  # maps the API: last commit and las dictionary entry
                    "development trend (accelerating / steady / slowing / dormant), open pull "  # supplies the literal text
                    "requests and the oldest one, the oldest open issue, how fast issues and PRs "  # supplies the literal text
                    "get their first resolution, contributor activity, and how much of the last "  # supplies the literal text
                    "12 months' commit activity is recent. Maintenance data never changes the "  # executes the statement
                    "score.\n",  # supplies the literal text
                    ("body",),  # executes the statement
                ),  # closes the multiline block
                ("\n\nTHE NERD BEHIND SCANITYCHECK\n", ("h",)),  # executes the statement
                (  # executes the statement
                    "Bill Spettmann is a cybersecurity strategist, security leader, educator, "  # supplies the literal text
                    "and technology enthusiast with almost 20 years of experience in cybersecurity, "  # supplies the literal text
                    "information assurance, risk management, and enterprise security architecture.\n\n",  # supplies the literal text
                    ("body",),  # executes the statement
                ),  # closes the multiline block
                (  # executes the statement
                    "For nearly 15 years, Bill has supported the Department of Defense and "  # supplies the literal text
                    "Defense Industrial Base (DIB), working across mission-critical environments, "  # supplies the literal text
                    "nuclear systems, cybersecurity operations, RMF, CMMC, FedRAMP, and enterprise "  # supplies the literal text
                    "security programs. He holds an MBA and an M.S. in Cybersecurity and IT "  # supplies the literal text
                    "Management, along with professional certifications including CISSP, CISM, PMP, "  # supplies the literal text
                    "CEH, CNDA, Security+, SecAI+ and CMMC CCP.\n\n",  # supplies the literal text
                    ("body",),  # executes the statement
                ),  # closes the multiline block
                (  # executes the statement
                    "Beyond industry, Bill teaches at the university level and has mentored more "  # supplies the literal text
                    "than 100 emerging cybersecurity professionals. He is the founder of Quantum "  # supplies the literal text
                    "Cyber Defense Systems, and is passionate about making cybersecurity "  # supplies the literal text
                    "practical, accessible, and actionable. ScanityCheck is an extension of that "  # supplies the literal text
                    "philosophy: bringing security visibility, vulnerability intelligence, and "  # supplies the literal text
                    "meaningful risk assessment together in one place.\n",  # supplies the literal text
                    ("body",),  # executes the statement
                ),  # closes the multiline block
                ("\n\nLIMITS\n", ("h",)),  # executes the statement
                (  # executes the statement
                    "  · A clean score is not a proof of security, only an absence of findings.\n"  # supplies the literal text
                    "  · Dependency scanning is best-effort: the scanners need a lockfile or manifest.\n"  # maps the   · Dependency scanning  dictionary entry
                    "  · Semgrep CE downloads its community ruleset, so it needs network access.\n"  # supplies the literal text
                    "  · Private repos need GITHUB_TOKEN set in the environment.\n"  # supplies the literal text
                    "  · C/C++/C#/Java/Go/Swift use build-less extraction, so build-specific\n"  # supplies the literal text
                    "    bugs may be missed.\n",  # supplies the literal text
                    ("muted",),  # executes the statement
                ),  # closes the multiline block
                ("\n\nFILES\n", ("h",)),  # executes the statement
                (f"  Cache    {config.CACHE_DIR}\n", ("muted",)),  # executes the statement
                (f"  Reports  {config.REPORTS_DIR}\n", ("muted",)),  # executes the statement
        ]  # closes the multiline block

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------
    def _scanner_profile_segments(self) -> list[tuple[str, tuple[str, ...]]]:
        """One bold title and one explanatory paragraph per scanner."""
        segments: list[tuple[str, tuple[str, ...]]] = []  # builds the segments
        for tool, label in config.TOOL_LABELS.items():  # registry order
            segments.append((f"{label}\n", ("h",)))  # the scanner's name
            segments.append((SCANNER_PROFILES.get(  # the paragraph, keyed like the registry
                tool, "No profile written for this scanner yet.") + "\n", ("body",)))  # falls back safely
        return segments  # returns the composed blocks

    def _show_tool_description(self, tool: str) -> None:  # defines the _show_tool_description() function
        description = config.TOOL_DESCRIPTIONS.get(tool, "")  # fetches the value
        required = "  ·  required" if tool in config.REQUIRED_TOOLS else ""  # sets the required text
        self.tools_hint.configure(text=f"{description}{required}")  # updates the widget settings

    def _restore_status_hint(self) -> None:  # defines the _restore_status_hint() function
        self.tools_hint.configure(text="")  # updates the widget settings

    def _select_tools(self, tools) -> None:  # defines the _select_tools() function
        chosen = set(tools)  # gathers the values into a set
        for tool, var in self.tool_vars.items():  # loops over the collection
            var.set(tool in chosen)  # updates the stored value

    def _selected_tools(self) -> list[str]:  # defines the _selected_tools() function
        return [tool for tool in config.ALL_TOOLS if self.tool_vars[tool].get()]  # returns the value to the caller

    def _selected_frameworks(self) -> list[str]:  # defines the _selected_frameworks() function
        if not hasattr(self, "framework_vars"):  # evaluates the branch condition
            return []  # returns the value to the caller
        return [key for key in compliance.ALL_FRAMEWORKS if self.framework_vars[key].get()]  # returns the value to the caller

    def _clear_frameworks(self) -> None:  # defines the _clear_frameworks() function
        for var in self.framework_vars.values():  # loops over the collection
            var.set(False)  # updates the stored value
        self._update_framework_count()  # runs the _update_framework_count() call

    def _restore_frameworks_hint(self) -> None:  # defines the _restore_frameworks_hint() function
        self._update_framework_count()  # runs the _update_framework_count() call

    def _update_framework_count(self) -> None:  # defines the _update_framework_count() function
        chosen = self._selected_frameworks()  # runs the _selected_frameworks() call
        if not chosen:  # evaluates the branch condition
            text, colour = "none selected  ·  mapping off", MUTED  # sets the text, colour text
        elif len(chosen) == len(compliance.ALL_FRAMEWORKS):  # checks the alternate condition
            text, colour = f"all {len(chosen)} frameworks selected", config.BRAND_GREEN  # counts the items
        else:  # covers the remaining branch
            text, colour = (  # assigns the computed value to text, colour
                f"{len(chosen)} framework"  # supplies the literal text
                f"{'s' if len(chosen) != 1 else ''} selected: "  # runs the len() call
                + ", ".join(compliance.FRAMEWORK_LABELS[key] for key in chosen),  # waits for the thread
                MUTED,  # evaluates the MUTED expression
            )  # closes the multiline block
        if hasattr(self, "frameworks_hint"):  # evaluates the branch condition
            self.frameworks_hint.configure(text=text, fg=colour)  # updates the widget settings

    def _set_tool_controls_state(self, state: str) -> None:  # defines the _set_tool_controls_state() function
        for check in self.tool_checks.values():  # loops over the collection
            check.configure(state=state, cursor="hand2" if state == "normal" else "arrow")  # updates the widget settings
        for check in getattr(self, "framework_checks", {}).values():  # loops over the collection
            check.configure(state=state, cursor="hand2" if state == "normal" else "arrow")  # updates the widget settings

    def start_scan(self) -> None:  # defines the start_scan() function
        if self._worker and self._worker.is_alive():  # evaluates the branch condition
            return  # evaluates the return expression

        url = self.url_var.get().strip()  # fetches the value
        if not url:  # evaluates the branch condition
            self.status_var.set("Enter a repository or website URL first.")  # updates the stored value
            self.url_entry.focus_set()  # runs the focus_set() call
            return  # evaluates the return expression

        selected = self._selected_tools()  # runs the _selected_tools() call
        if not selected:  # evaluates the branch condition
            messagebox.showerror(  # runs the showerror() call
                config.APP_NAME,  # evaluates the config.APP_NAME expression
                "Select at least one scanner. CodeQL and Trivy are required for a trusted verdict.",  # supplies the literal text
                parent=self,  # copies the self value into parent
            )  # closes the multiline block
            return  # evaluates the return expression

        try:  # watches for errors in the block
            kind, target = scanners.parse_target(url)  # classifies repo vs website
        except scanners.ScanError as exc:  # handles the raised error
            messagebox.showerror(config.APP_NAME, str(exc), parent=self)  # runs the showerror() call
            return  # evaluates the return expression
        display = target.full_name if kind == "repo" else url  # names the queued scan
        self._remember_url(url)  # the rolling history now leads with this target
        self._hide_url_history()  # the dropdown never survives a scan launch

        self._report = None  # toggles the _report flag
        self._omitted_groups.clear()  # a fresh scan restarts with no omissions
        self._log_buffer = []  # starts the list on _log_buffer
        self._log_lines = 0  # saves the result on _log_lines
        self._segment_cache.clear()  # the old report's composed layout is gone
        self._mark_results_dirty()  # a fresh scan repaints every results pane
        frameworks = self._selected_frameworks()  # runs the _selected_frameworks() call
        self._save_settings(url, selected, frameworks)  # runs the _save_settings() call
        self._show_pane("log")  # runs the _show_pane() call

        self._cancel.clear()  # runs the clear() call
        self.scan_button.configure(state="disabled", bg=SCAN_DISABLED_BG, text="Scanning…")  # updates the widget settings
        self.stop_button.configure(state="normal", fg=TEXT)  # updates the widget settings
        self.url_entry.configure(  # updates the widget settings
            state="disabled",  # entries the field while the scan runs
            disabledbackground=PANEL_ALT,  # the fill must not flip to the system grey
            disabledforeground=TEXT,  # the typed URL stays readable, not greyed out
        )  # closes the configure call
        self._set_tool_controls_state("disabled")  # runs the _set_tool_controls_state() call
        for button in self._report_buttons():  # loops over the collection
            button.configure(state="disabled", fg=DISABLED_GREY)  # updates the widget settings
        self.status_var.set(  # updates the stored value
            f"Queued {display}"  # names the queued target
            + ("  ·  website scan" if kind == "web" else "")  # marks the web mode
            + f"  ·  {len(selected)} scanner"  # supplies the literal text
            f"{'s' if len(selected) != 1 else ''} selected"  # runs the len() call
            + (f"  ·  {len(frameworks)} framework"  # runs the len() call
               f"{'s' if len(frameworks) != 1 else ''}" if frameworks else "") + "…"  # runs the len() call
        )  # closes the multiline block
        self.progress.configure(mode="indeterminate")  # updates the widget settings
        self.progress.start(12)  # begins the scan/thread
        self._start_clock()  # the header clock begins counting
        self._reset_card()  # runs the _reset_card() call

        self._worker = threading.Thread(  # saves the result on _worker
            target=self._scan_worker, args=(url, selected, frameworks), daemon=True  # copies the self._scan_worker value into target
        )  # closes the multiline block
        self._worker.start()  # begins the scan/thread

    def _scan_worker(self, url: str, tools: list[str], frameworks: list[str]) -> None:  # defines the _scan_worker() function
        try:  # watches for errors in the block
            report = scanners.scan_target(  # dispatches repo vs website
                url,  # evaluates the url expression
                log=lambda line: self._events.put(("log", line)),  # runs the put() call
                cancel=self._cancel,  # copies the self._cancel value into cancel
                tools=tools,  # copies the tools value into tools
                frameworks=frameworks,  # copies the frameworks value into frameworks
            )  # closes the multiline block
            self._events.put(("done", report))  # runs the put() call
        except scanners.ScanCancelled:  # handles the raised error
            self._events.put(("cancelled", None))  # runs the put() call
        except scanners.ScanError as exc:  # handles the raised error
            self._events.put(("error", str(exc)))  # runs the put() call
        except Exception as exc:  # noqa: BLE001  # handles the raised error
            self._events.put(("error", f"Unexpected error: {exc}"))  # runs the put() call

    def cancel_scan(self) -> None:  # defines the cancel_scan() function
        if self._worker and self._worker.is_alive():  # evaluates the branch condition
            self._cancel.set()  # updates the stored value
            self.status_var.set("Stopping…")  # updates the stored value
            self.stop_button.configure(state="disabled", fg=DISABLED_GREY)  # updates the widget settings

    def _start_clock(self) -> None:  # defines the _start_clock() function
        """Starts the header elapsed clock when a scan launches."""  # keeps the docstring text
        self._scan_started = time.monotonic()  # the monotonic stamp counts from now
        self.elapsed_label.configure(text=self._elapsed_text(0.0))  # the clock reads 00:00 at once
        self._elapsed_after = self.after(ELAPSED_TICK_MS, self._tick_clock)  # schedules the first tick

    def _tick_clock(self) -> None:  # defines the _tick_clock() function
        """One clock tick: repaint the header with the newest elapsed time."""  # keeps the docstring text
        if self._scan_started is None:  # evaluates the branch condition
            return  # no running scan, no tick
        self.elapsed_label.configure(text=self._elapsed_text(time.monotonic() - self._scan_started))  # repainting the clock
        self._elapsed_after = self.after(ELAPSED_TICK_MS, self._tick_clock)  # the next beat of the clock

    def _stop_clock(self) -> None:  # defines the _stop_clock() function
        """Stops the elapsed clock and freezes it at the final reading."""  # keeps the docstring text
        if self._elapsed_after is not None:  # evaluates the branch condition
            self.after_cancel(self._elapsed_after)  # cancels the pending tick
            self._elapsed_after = None  # saves the result on _elapsed_after
        if self._scan_started is not None:  # evaluates the branch condition
            self.elapsed_label.configure(text=self._elapsed_text(time.monotonic() - self._scan_started))  # the frozen reading

    @staticmethod  # marks the static body
    def _elapsed_text(seconds: float) -> str:  # defines the _elapsed_text() function
        """One formatted clock line: ELAPSED  MM:SS (or H:MM:SS past an hour)."""  # keeps the docstring text
        total = max(0, int(seconds))  # whole seconds, never negative
        mins, secs = divmod(total, 60)  # splits the seconds off
        hours, mins = divmod(mins, 60)  # splits the minutes off
        if hours:  # evaluates the branch condition
            return f"ELAPSED  {hours}:{mins:02d}:{secs:02d}"  # the long form past an hour
        return f"ELAPSED  {mins:02d}:{secs:02d}"  # the usual short form

    def _finish_scan_ui(self) -> None:  # defines the _finish_scan_ui() function
        self._stop_clock()  # freezes the clock the moment the scan ends
        self.progress.stop()  # runs the stop() call
        self.progress.configure(mode="determinate", value=0)  # updates the widget settings
        self.scan_button.configure(state="normal", bg=ACCENT, text="Scan repository")  # updates the widget settings
        self.stop_button.configure(state="disabled", fg=DISABLED_GREY)  # updates the widget settings
        self.url_entry.configure(  # updates the widget settings
            state="normal",  # releases the field after the scan
            bg=PANEL_ALT,  # the fill returns to the panel tint
            fg=TEXT,  # copies the fg value
        )  # closes the configure call
        self._set_tool_controls_state("normal")  # runs the _set_tool_controls_state() call

    def _handle_done(self, report: dict[str, Any]) -> None:  # defines the _handle_done() function
        self._report = report  # saves the result on _report
        self._segment_cache.clear()  # the new report composes afresh
        self._mark_results_dirty()  # every pane repaints for the new report
        self._finish_scan_ui()  # runs the _finish_scan_ui() call
        self._refresh_card(report)  # paints the score, verdict and card charts

        confidence = report.get("confidence") or {}  # fetches the value
        dedupe = report.get("dedupe") or {}  # fetches the value
        dedupe_text = (  # assigns the computed value to dedupe_text
            f"  ·  {dedupe.get('removed', 0)} duplicates removed" if dedupe.get("removed") else ""  # fetches the value
        )  # closes the multiline block
        confidence_text = (  # assigns the computed value to confidence_text
            f"  ·  confidence {confidence.get('score')}/100 ({confidence.get('band')})"  # fetches the value
            if confidence  # evaluates the branch condition
            else ""  # covers the remaining branch
        )  # closes the multiline block
        self.status_var.set(  # updates the stored value
            f"Scored {report['score']}/100 in {report['duration_seconds']:.0f}s  ·  "  # evaluates the f expression
            f"{report['totals']['findings']} findings{dedupe_text}"  # evaluates the f expression
            f"{confidence_text}  ·  verdict {report['verdict']}"  # evaluates the f expression
        )  # closes the multiline block
        skipped = [  # assigns the computed value to skipped
            config.TOOL_LABELS.get(name, name)  # fetches the value
            for name, status in (report.get("scanner_status") or {}).items()  # loops over the collection
            if status.get("status") == "skipped"  # evaluates the branch condition
        ]  # closes the multiline block
        hint = f"Artifacts saved to {report.get('artifacts_dir', config.WORK_DIR)}"  # sets the hint text
        if skipped:  # evaluates the branch condition
            hint += "  ·  not run: " + ", ".join(skipped)  # waits for the thread
        self.hint_label.configure(text=hint)  # updates the widget settings
        for button in self._report_buttons():  # loops over the collection
            button.configure(state="normal", fg=TEXT)  # updates the widget settings

        self._show_pane("report")  # runs the _show_pane() call

        # Persist a copy of every run so results are reviewable later.
        try:  # watches for errors in the block
            name = (report.get("repo") or {}).get("full_name", "repo").replace("/", "-")  # fetches the value
            stamp = time.strftime("%Y%m%d-%H%M%S")  # formats the timestamp
            scoring.write_report_json(report, config.REPORTS_DIR / f"{name}-{stamp}.json")  # runs the write_report_json() call
        except Exception:  # handles the raised error
            pass  # keeps the block syntactically empty

    def _refresh_card(self, report: dict[str, Any]) -> None:
        """Repaint every summary surface that reads off the report numbers."""
        score = report["score"]  # copies the report value into score
        colour = report["band_colour"]  # copies the report value into colour
        self.score_label.configure(text=str(score), fg=colour)  # updates the widget settings
        secure = report["verdict"] == "SECURE"  # the formal verdict of the scan
        if self._omitted_groups:  # a reviewer is arbitrating: the badge echoes the
            # risk-band classification instead of the binary verdict, so the
            # banner can never contradict the score it sits beside (a red
            # INSECURE would otherwise survive any score the reviewer creates).
            self.verdict_label.configure(  # updates the widget settings
                text=str(report.get("band") or "reviewed"),  # the band label as the badge
                bg=report.get("band_colour") or MUTED,  # the band's own colour
                fg=self._badge_foreground(str(report.get("band_colour") or MUTED)),  # readable text
            )  # closes the label update
        else:  # covers the remaining branch
            self.verdict_label.configure(  # updates the widget settings
                text=report["verdict"],  # copies the report value into text
                bg=OK if secure else DANGER,  # copies the OK value into bg
                fg="#08130c" if secure else "#ffffff",  # sets the fg text
            )  # closes the label update
        self.band_label.configure(text=f"{report['band']}", fg=colour)  # updates the widget settings
        self.reason_label.configure(text=report["verdict_reason"], fg=TEXT if not secure else MUTED)  # updates the widget settings
        self.count_labels["critical"].configure(text=str(report["totals"]["critical"]))  # updates the widget settings
        self.count_labels["high"].configure(text=str(report["totals"]["high"]))  # updates the widget settings
        self.count_labels["medium"].configure(text=str(report["totals"]["medium"]))  # updates the widget settings
        self.count_labels["low"].configure(text=str(report["totals"]["low"]))  # updates the widget settings
        self._render_pie(report)  # runs the _render_pie() call
        self._render_gauge(report)  # runs the _render_gauge() call
        try:  # watches for errors in the block
            self.metric_canvas.delete("all")  # clears the stale widgets
        except Exception:  # handles the raised error
            pass  # keeps the block syntactically empty
        if self._pane == "dashboard":  # evaluates the branch condition
            self._render_metric_dashboard()  # runs the _render_metric_dashboard() call
            self._pane_dirty["dashboard"] = False  # the visible pane is current again
        elif self._pane == "recommend":  # evaluates the branch condition
            self._render_recommendations()  # re-ranks for the rescoring set
            self._pane_dirty["recommend"] = False  # the visible pane is current again

    def _render_recommendations(self) -> None:
        """Write the ranked remediation list into the recommendations pane."""
        from recommendations import build_recommendations  # keeps the module pure

        area = self.recommend_area  # the recommendations text pane
        report = self._report  # copies the self._report value into report

        if not report:  # evaluates the branch condition
            self._write([  # builds the segments list
                ("Remediations\n", ("h",)),
                ("Run a scan first - this tab ranks the remediation work that "  # supplies the literal text
                 "the findings earned.\n", ("muted",)),
            ], area=area)  # writes the placeholder
            return  # returns the caller

        items = build_recommendations(report)  # ranks the themes
        segments: list[tuple[str, tuple[str, ...]]] = [  # builds the segments list
            ("Remediations\n", ("h",)),  # supplies the literal text
            ("Twenty-five highest-impact remediation steps from this scan's open findings. "  # supplies the literal text
             "\"impact\" states the points each fix returns from the current score, "  # supplies the literal text
             "bounded by the 100-point ceiling and the category caps; rows respect "  # binds the honesty
             "any findings you excluded on the Report tab.\n", ("muted",)),  # adds the intro text
        ]  # closes the segments list
        if not items:  # evaluates the branch condition
            segments.append(("No remediation work is suggested: the open scoring "  # supplies the literal text
                             "set is empty or already at its ceiling.\n", ("muted",)))  # adds the empty text
        for item in items:  # loops over the ranked rows
            if item.get("general"):  # evaluates the branch condition
                segments.append((f"{item['rank']}. {item['subject']}\n", ("h",)))  # prints the title
                segments.append(("   general best practice  ·  not tied to a specific finding\n", ("muted",)))  # labels it honestly
            else:  # covers the remaining branch
                segments.append((f"{item['rank']}. {item['subject']}\n", ("h",)))  # prints the action
                cap_note = "  ·  cap-bound: fixing these raises no more points" if item.get("capped") else ""  # the cap label
                segments.append((f"[+{item['impact']:.1f} pts]{cap_note}", ("verdict_ok",)))  # prints the impact
                segments.append(("  ·  "  # builds the meta line
                                 + f"{item['instances']} finding{'s' if item['instances'] != 1 else ''}"  # counts the instances
                                 + f"  ·  worst: {str(item['worst']).upper()}"  # adds the worst rating
                                 + (f"  ·  package: {item['package']}" if item["package"] else "")  # names the package
                                 + f"  ·  score projection: {item['score_projection']}/100"  # adds the projection
                                 + "\n", ("muted",)))  # closes the line build
                if item.get("locations"):  # evaluates the branch condition
                    segments.append((f"   touch: {', '.join(item['locations'])}\n", ("muted",)))  # sample spots
                if item.get("tools"):  # evaluates the branch condition
                    segments.append((f"   identified by: {', '.join(item['tools'])}\n", ("muted",)))  # attribution
            segments.append(("\n", ("body",)))  # spacer line

        self._write(segments, area=area)  # writes the composed segments
        area.configure(state="disabled")  # updates the widget settings
        area.yview_moveto(0)  # runs the yview_moveto() call

    def _sync_omitted(self, key: str, var: tk.BooleanVar) -> None:
        """Align the omission set with the checkbox state, then rescore."""
        if not key:  # evaluates the branch condition
            return  # nothing to identify this row
        state = bool(var.get())  # reads the tick the user just made
        if state:  # evaluates the branch condition
            self._omitted_groups.add(key)  # excludes the risk theme
        else:  # covers the remaining branch
            self._omitted_groups.discard(key)  # re-includes it
        # Rapid checkbox flicks coalesce into one rescore + repaint pass.
        pending = getattr(self, "_omit_after", None)  # fetches the pending rescore
        if pending:  # evaluates the branch condition
            try:  # watches for errors in the block
                self.after_cancel(pending)  # cancels the queued rescore
            except Exception:  # handles the raised error
                pass  # keeps the block syntactically empty
        self._omit_after = self.after(OMISSION_DEBOUNCE_MS, self._apply_omissions)  # queues one debounced rescore

    def _apply_omissions(self) -> None:
        """Rescore with the reviewer's set and repaint every surface."""
        self._omit_after = None  # resets the pending handle
        if not self._report:  # evaluates the branch condition
            return  # nothing to score without a report
        fraction = self.text_area.yview()[0]  # remembers the reading position
        scoring.rescore_report(self._report, self._omitted_groups)  # recomputes with the reviewer's set
        self._mark_results_dirty()  # every results pane sees the new numbers
        self._refresh_card(self._report)  # repaints the score, verdict and card charts
        self._render_report()  # re-renders the checkbox rows and omission markers
        self.text_area.yview_moveto(fraction)  # keeps the reading position

    def _badge_foreground(self, bg_hex: str) -> str:
        """Readable text colour on a band-coloured badge (dark ink or white)."""
        try:  # watches for errors in the block
            red, green, blue = self._hex_to_rgb(bg_hex)  # splits the channels
            luma = 0.299 * red + 0.587 * green + 0.114 * blue  # perceived brightness
            return BG if luma > LUMA_TEXT_THRESHOLD else "#ffffff"  # picks the readable ink
        except Exception:  # handles the raised error
            return "#ffffff"  # safe default on a bad colour string

    def _toggle_banner(self) -> None:
        """Show or hide the score card everywhere; the pane re-lays out."""
        self._banner_hidden = not self._banner_hidden  # flips the session choice
        self.banner_toggle.configure(  # updates the widget settings
            text="Show score banner" if self._banner_hidden else "Hide score banner",  # reflects the state
        )  # closes the multiline block
        self._show_pane(self._pane)  # re-runs the layout for the active pane

    def _reset_card(self) -> None:  # defines the _reset_card() function
        self.score_label.configure(text="--", fg=DISABLED_GREY)  # updates the widget settings
        self.verdict_label.configure(text="SCANNING", bg=VERDICT_SCANNING_BG, fg=TEXT)  # updates the widget settings
        self.band_label.configure(text="Working…", fg=MUTED)  # updates the widget settings
        self.reason_label.configure(text="", fg=MUTED)  # updates the widget settings
        for label in self.count_labels.values():  # loops over the collection
            label.configure(text="–")  # updates the widget settings
        self._clear_dashboard()  # runs the _clear_dashboard() call

    # ------------------------------------------------------------------
    # Event pump
    # ------------------------------------------------------------------
    def _log(self, line: str) -> None:  # defines the _log() function
        self._log_buffer.append(line)  # adds an item to the list
        if len(self._log_buffer) > LOG_BUFFER_MAX:  # evaluates the branch condition
            del self._log_buffer[:LOG_BUFFER_DROP]  # removes the variable or entry
        if getattr(self, "_pane", "report") != "log":  # evaluates the branch condition
            self._pane_dirty["log"] = True  # the pane repaints from the buffer on its next visit
            return  # returns nothing to the caller
        self._log_lines = len(self._log_buffer)  # the counter always mirrors the buffer
        area = self.text_area  # copies the self.text_area value into area
        area.configure(state="normal")  # updates the widget settings
        area.insert("end", line + "\n", ("body",))  # inserts text or data
        if self._log_lines > LOG_VIEW_MAX:  # evaluates the branch condition
            area.delete("1.0", f"{LOG_VIEW_TRIM}.0")  # removes the leading block of rows
            self._log_lines = LOG_VIEW_KEEP  # saves the result on _log_lines
        area.configure(state="disabled")  # updates the widget settings
        area.see("end")  # runs the see() call

    def _set_status(self, text: str) -> None:  # defines the _set_status() function
        """Writes the status bar only when the string actually changes."""
        if text == self._last_status:  # evaluates the branch condition
            return  # unchanged: skip the StringVar write entirely
        self._last_status = text  # remembers the newest string
        self.status_var.set(text)  # updates the stored value

    def _dispatch_event(self, kind: str, payload: Any) -> None:  # defines the _dispatch_event() function
        """Routes one queued worker event to its handler."""
        if kind == "log":  # evaluates the branch condition
            self._log(str(payload))  # runs the _log() call
            stripped = str(payload).strip()  # runs the str() call
            if stripped and not stripped.startswith(("$", "  ")):  # evaluates the branch condition
                self._set_status(stripped[:140])  # updates the stored value
        elif kind == "done":  # checks the alternate condition
            self._handle_done(payload)  # runs the _handle_done() call
        elif kind == "cancelled":  # checks the alternate condition
            self._finish_scan_ui()  # runs the _finish_scan_ui() call
            self._set_status("Scan cancelled.")  # updates the stored value
            self.hint_label.configure(text="")  # updates the widget settings
        elif kind == "error":  # checks the alternate condition
            self._finish_scan_ui()  # runs the _finish_scan_ui() call
            self._set_status("Scan failed.")  # updates the stored value
            self._log(f"FATAL: {payload}")  # runs the _log() call
            self._log("")  # runs the _log() call
            self._show_pane("log")  # runs the _show_pane() call
            messagebox.showerror(config.APP_NAME, str(payload), parent=self)  # runs the showerror() call

    def _drain_events(self) -> None:  # defines the _drain_events() function
        active = bool(self._worker and self._worker.is_alive())  # a running scan keeps the fast pace
        had_events = False  # remembers whether anything was queued this pass
        try:  # the reschedule below can never be skipped
            while True:  # loops while the condition holds
                try:  # drains until the queue is empty
                    kind, payload = self._events.get_nowait()  # runs the get_nowait() call
                except queue.Empty:  # handles the raised error
                    break  # closes the drain loop
                had_events = True  # marks the pass as productive
                try:  # one broken handler must not kill the polling chain
                    self._dispatch_event(kind, payload)  # runs the _dispatch_event() call
                except Exception as exc:  # noqa: BLE001  # handles the raised error
                    self._log(f"UI error: {kind} handling failed: {exc}")  # keeps the pump alive
        finally:  # always executes, handler errors included
            cadence = POLL_ACTIVE_MS if active or had_events else POLL_IDLE_MS  # adapts the poll pace
            self.after(cadence, self._drain_events)  # runs the after() call

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def copy_report(self) -> None:  # defines the copy_report() function
        if not self._report:  # evaluates the branch condition
            return  # evaluates the return expression
        text = self._build_plain_report()  # runs the _build_plain_report() call
        self.clipboard_clear()  # runs the clipboard_clear() call
        self.clipboard_append(text)  # runs the clipboard_append() call
        self.status_var.set("Report copied to clipboard.")  # updates the stored value

    def _build_plain_report(self) -> str:  # defines the _build_plain_report() function
        assert self._report is not None  # verifies the assumption
        text = scoring.render_report_text(self._report)  # runs the render_report_text() call
        tailored = (  # assigns the computed value to tailored
            f"{self._report['verdict']}  ·  {self._report['score']}/100  "  # evaluates the f expression
            f"({self._report['band']})\n" + ("-" * 60) + "\n"  # evaluates the f expression
        )  # closes the multiline block
        return tailored + text  # returns the tailored to the caller

    def _ask_export(self, title: str, suffix: str, filetypes, writer, *, failure: str, open_after: bool = False, preset_name: str | None = None) -> None:
        """The shared save-dialog + try/except + status/messagebox dance."""
        if not self._report:  # evaluates the branch condition
            return  # evaluates the return expression
        # A save dialog is a native window: any topmost popup (Summarize It,
        # Check GAD...) would sit in front of it, so those popups drop their
        # always-on-top flag for exactly the dialog's lifetime.
        topmost_popups: list[tk.Toplevel] = []  # the popups whose flag we flip
        for child in self.winfo_children():  # walks the app's toplevels
            if isinstance(child, tk.Toplevel) and child.winfo_viewable():  # the visible popups
                try:  # the attribute exists on Windows at least
                    if child.attributes("-topmost"):  # evaluates the branch condition
                        topmost_popups.append(child)  # remembers who to restore
                        child.attributes("-topmost", False)  # drops the flag
                except Exception:  # handles the destroyed case
                    pass  # keeps the block syntactically empty
        try:  # the dialog opens with the field clear of overlays
            path = filedialog.asksaveasfilename(  # runs the asksaveasfilename() call
                parent=self,  # copies the self value into parent
                title=title,  # copies the title value into title
                defaultextension=suffix,  # sets the defaultextension text
                initialdir=str(config.REPORTS_DIR),  # runs the str() call
                initialfile=preset_name or self._default_report_name(suffix),  # the suggested file name
                filetypes=filetypes,  # copies the filetypes value into filetypes
            )  # closes the multiline block
        finally:  # the popups regain their topmost flag either way
            for window in topmost_popups:  # loops over the flipped popups
                try:  # the widget may already be gone
                    window.attributes("-topmost", True)  # restores the always-on-top flag
                except Exception:  # handles the destroyed case
                    pass  # keeps the block syntactically empty
        if not path:  # evaluates the branch condition
            return  # evaluates the return expression
        try:  # watches for errors in the block
            self.status_var.set(writer(path))  # writes after the exporter's own status text
            if open_after:  # evaluates the branch condition
                self._open_saved_file(path)  # hands the file to the OS viewer
        except OSError as exc:  # handles the raised error
            messagebox.showerror(config.APP_NAME, f"{failure}: {exc}", parent=self)  # runs the showerror() call

    def _open_saved_file(self, path: str) -> None:
        """Open a saved artefact in the OS default viewer; a failure is a note."""
        try:  # os.startfile exists on Windows; other hosts fall back gracefully
            if hasattr(os, "startfile"):  # the Windows shell open
                os.startfile(os.path.abspath(path))  # runs the startfile() call
            else:  # covers the remaining branch
                subprocess.run(["open" if sys.platform == "darwin" else "xdg-open", path], check=False)  # mac / linux
            self._log(f"Opened {path} in the system viewer.")  # the activity-log trail
        except Exception as exc:  # noqa: BLE001 - a missing viewer must not fail the export
            self._log(f"Saved {path}, but the system viewer did not open it ({exc}).")  # the honest note

    def save_report(self) -> None:  # defines the save_report() function
        report = self._report  # the shared dialog helper has already guarded the None case

        def write(path: str) -> str:  # defines the small inline helper
            if path.lower().endswith(".txt"):  # evaluates the branch condition
                with open(path, "w", encoding="utf-8") as handle:  # opens the context for the block
                    handle.write(self._build_plain_report())  # runs the write() call
            else:  # covers the remaining branch
                scoring.write_report_json(report, path)  # runs the write_report_json() call
            return f"Report saved to {path}"  # the status line the user reads

        self._ask_export(  # runs the _ask_export() call
            "Save security report",  # sets the title text
            ".json",  # sets the defaultextension text
            [("JSON report", "*.json"), ("Text report", "*.txt")],  # assigns the computed value to filetypes
            write,  # copies the write value into writer
            failure="Could not save report",  # the message prefix on failure
        )  # closes the multiline block

    def _default_report_name(self, suffix: str) -> str:  # defines the _default_report_name() function
        assert self._report is not None  # verifies the assumption
        repo_name = (self._report.get("repo") or {}).get("full_name", "repo")  # fetches the value
        return f"{repo_name.replace('/', '-')}-security-report{suffix}"  # returns the f to the caller

    def export_csv(self) -> None:  # defines the export_csv() function
        def write(path: str) -> str:  # defines the small inline helper
            exports.write_report_csv(self._report, path)  # runs the write_report_csv() call
            return f"CSV exported to {path}"  # the status line the user reads

        self._ask_export(  # runs the _ask_export() call
            "Export findings to CSV",  # sets the title text
            ".csv",  # sets the defaultextension text
            [("CSV spreadsheet", "*.csv")],  # assigns the computed value to filetypes
            write,  # copies the write value into writer
            failure="Could not export CSV",  # the message prefix on failure
        )  # closes the multiline block

    def export_pdf(self) -> None:  # defines the export_pdf() function
        def write(path: str) -> str:  # defines the small inline helper
            exports.write_report_pdf(self._report, path)  # runs the write_report_pdf() call
            return f"PDF report saved to {path}"  # the status line the user reads

        self._ask_export(  # runs the _ask_export() call
            "Print security report to PDF",  # sets the title text
            ".pdf",  # sets the defaultextension text
            [("PDF document", "*.pdf")],  # assigns the computed value to filetypes
            write,  # copies the write value into writer
            failure="Could not write PDF",  # the message prefix on failure
            open_after=True,  # hands the saved PDF straight to the system viewer
        )  # closes the multiline block

    def _require_sbom(self) -> bool:  # defines the _require_sbom() function
        """Gate the SBOM buttons behind an SBOM scan (Syft or cdxgen)."""
        already = (self._report or {}).get("sbom") or {}  # the scanned payload
        if not already.get("all_components"):  # evaluates the branch condition
            messagebox.showerror(  # the honest gate the user asked for
                config.APP_NAME,  # evaluates the config.APP_NAME expression
                "No SBOM in this report. Run an SBOM scan first: tick Syft or "
                "cdxgen in the Scanners row, then scan a repository.",  # the instruction text
                parent=self,  # copies the self value into parent
            )  # closes the multiline block
            return False  # covers the remaining branch
        return True  # the payload is present

    def export_sbom(self) -> None:  # defines the export_sbom() function
        def write(path: str) -> str:  # the small inline write helper
            exports.write_report_sbom_csv(self._report, path)  # runs the write_report_sbom_csv() call
            return f"SBOM exported to {path}"  # the status line the user reads

        if not self._require_sbom():  # evaluates the branch condition
            return  # the gate refused without an SBOM scan
        self._ask_export(  # runs the _ask_export() call
            "Export SBOM to CSV",  # sets the title text
            ".csv",  # sets the defaultextension text
            [("CSV spreadsheet", "*.csv")],  # assigns the computed value to filetypes
            write,  # copies the write value into writer
            failure="Could not export the SBOM",  # the message prefix on failure
        )  # closes the multiline block

    def print_sbom(self) -> None:  # defines the print_sbom() function
        def write(path: str) -> str:  # the small inline write helper
            exports.write_report_sbom_pdf(self._report, path)  # runs the write_report_sbom_pdf() call
            return f"SBOM PDF saved to {path}"  # the status line the user reads

        if not self._require_sbom():  # evaluates the branch condition
            return  # the gate refused without an SBOM scan
        self._ask_export(  # runs the _ask_export() call
            "Print SBOM to PDF",  # sets the title text
            ".pdf",  # sets the defaultextension text
            [("PDF document", "*.pdf")],  # assigns the computed value to filetypes
            write,  # copies the write value into writer
            failure="Could not write the SBOM PDF",  # the message prefix on failure
            open_after=True,  # the saved SBOM opens like the report PDF does
        )  # closes the multiline block

    def summarize_report(self) -> None:  # defines the summarize_report() function
        """Compose the plain-language summary and open its themed popup."""
        bullets = summarizer.summary_bullets(self._report or {})  # runs the summary_bullets() call
        self._show_summary_popup(bullets)  # opens the themed popup

    def _show_summary_popup(self, bullets: list[str]) -> None:
        """Build the Acknowledgement-styled popup that reads the summary."""
        box = tk.Toplevel(self)  # the popup surface over the app
        box.title(f"{config.APP_NAME} - Scan Summary")  # the window title
        box.configure(bg=config.BRAND_NAVY)  # the app's own background
        box.attributes("-topmost", True)  # the popup sits over the report
        box.transient(self)  # groups with the app window
        box.app_icon = _set_window_icon(box)  # the AppIcon on the summary popup too

        def close_box() -> None:  # the shared close path
            if box.winfo_exists():  # the popup may already be gone
                box.destroy()  # closes the popup

        box.protocol("WM_DELETE_WINDOW", close_box)  # wires the cross button
        box.bind("<Escape>", lambda _e: close_box())  # escape closes too

        body = tk.Frame(box, bg=config.BRAND_NAVY)  # the full-bleed content column
        body.pack(fill="both", expand=True)  # owns the window
        body.columnconfigure(0, weight=1)  # runs the columnconfigure() call
        body.rowconfigure(4, weight=1)  # the bullet list takes the slack

        try:  # the branding graphic rides the top, exactly like the gate
            art = tk.PhotoImage(  # the full-resolution asset
                file=str(Path(__file__).resolve().parent / config.BRANDING_WORDMARK)
            )  # loads once at native size
            factor = max(2, -(-art.width() // 460))  # fits the narrower popup head
            art = art.subsample(factor, factor)  # scales the artwork down
            logo = tk.Label(body, image=art, bg=config.BRAND_NAVY)  # runs the Label() call
            logo.image = art  # anchors the image against garbage collection
            logo.grid(row=0, column=0, pady=(14, 2))  # runs the widget placement
        except Exception:  # a missing artwork never blocks a summary
            tk.Label(  # the text fallback header
                body, text=config.APP_NAME, bg=config.BRAND_NAVY,  # the name instead
                fg=config.BRAND_GREEN, font=(UI_FONT, 16, "bold"),  # the strong header
            ).grid(row=0, column=0, pady=(14, 2))  # runs the widget placement

        repo = self._report.get("repo") or {}  # the scanned target's identity block
        repo_name = str(repo.get("full_name") or repo.get("input_url") or "repository")  # the display title
        web_url = repo.get("web_url") or (  # the GitHub path when one is known
            f"https://github.com/{repo.get('full_name')}" if repo.get("full_name")  # the canonical URL
            else str(repo.get("input_url") or "")  # website scans keep their address
        )  # closes the url build
        tk.Label(  # the repository title, right under the artwork
            body,  # evaluates the body expression
            text=repo_name,  # the scanned repo's name
            bg=config.BRAND_NAVY,  # copies the BRAND_NAVY value into bg
            fg=TEXT,  # full-bright: the page is about this repository
            font=(UI_FONT, 12, "bold"),  # the title weight
        ).grid(row=1, column=0)  # runs the widget placement
        if web_url:  # evaluates the branch condition
            tk.Label(  # the GitHub path lives directly under the name
                body,  # evaluates the body expression
                text=web_url,  # the repository path
                bg=config.BRAND_NAVY,  # copies the BRAND_NAVY value into bg
                fg=MUTED,  # the path reads quieter than the name
                font=(UI_FONT, 9),  # the sub-line height
            ).grid(row=2, column=0, pady=(0, 6))  # runs the widget placement

        tk.Label(  # the section header under the artwork
            body,  # evaluates the body expression
            text=f"Scan Summary  ·  {len(bullets)} key point{'s' if len(bullets) != 1 else ''}",  # the header text
            bg=config.BRAND_NAVY,  # copies the BRAND_NAVY value into bg
            fg=config.BRAND_GREEN,  # the logo green
            font=(UI_FONT, 12, "bold"),  # the strong header weight
        ).grid(row=3, column=0, pady=(2, 6))  # runs the widget placement

        list_holder = tk.Frame(body, bg=config.BRAND_NAVY)  # hosts the scrolling bullets
        list_holder.grid(row=4, column=0, sticky="nsew", padx=18)  # runs the widget placement
        list_holder.columnconfigure(0, weight=1)  # runs the columnconfigure() call
        list_holder.rowconfigure(0, weight=1)  # runs the rowconfigure() call

        bullets_area = tk.Text(  # the read-only bullet list
            list_holder,  # evaluates the list_holder expression
            bg=PANEL,  # the panel tint like the report pane
            fg=TEXT,  # copies the TEXT value into fg
            insertbackground=TEXT,  # copies the TEXT value into insertbackground
            relief="flat",  # flat body
            font=(UI_FONT, 10),  # the readable summary size
            wrap="word",  # wraps at the box edge
            padx=14,  # assigns the computed value to padx
            pady=10,  # assigns the computed value to pady
            spacing1=4,  # a gap above each bullet
        )  # closes the multiline block
        bullets_area.tag_configure("dot", foreground=config.BRAND_GREEN, font=(UI_FONT, 10, "bold"))  # the marker tag
        for bullet in bullets:  # walks the composed points
            bullets_area.insert("end", "●  ", "dot")  # the brand-green marker
            bullets_area.insert("end", bullet + "\n\n")  # the sentence itself
        bullets_area.configure(state="disabled")  # read-only by definition
        bullets_area.grid(row=0, column=0, sticky="nsew")  # runs the widget placement

        bullet_scroll = tk.Scrollbar(list_holder, command=bullets_area.yview, bg=PANEL, troughcolor=PANEL, width=14)  # the bar
        bullet_scroll.grid(row=0, column=1, sticky="ns")  # runs the widget placement
        bullets_area.configure(yscrollcommand=bullet_scroll.set)  # updates the widget settings
        bullets_area.bind("<MouseWheel>", lambda event: bullets_area.yview_scroll(int(-event.delta / 120), "units"))  # wheel

        button_row = tk.Frame(body, bg=config.BRAND_NAVY)  # hosts Print and Close side by side
        button_row.grid(row=6, column=0, pady=(8, 16))  # runs the widget placement

        print_summary = tk.Button(  # prints the summary bullets to a themed PDF
            button_row,  # evaluates the button_row expression
            text="Print",  # the summary print action
            command=lambda: self._print_summary_pdf(bullets),  # prints via the shared dialog
            bg=ACCENT,  # the brand-green style all primary actions wear
            fg=BG,  # the near-black ink straight off the brand background
            activebackground=ACCENT_HOVER,  # the pressed state
            activeforeground=BG,  # the near-black ink straight off the brand background
            relief="flat",  # sets the relief text
            font=(UI_FONT, 10, "bold"),  # the primary action weight
            padx=20,  # assigns the computed value to padx
            pady=6,  # assigns the computed value to pady
            cursor="hand2",  # sets the cursor text
            borderwidth=0,  # assigns the computed value to borderwidth
        )  # closes the multiline block
        print_summary.grid(row=0, column=0, padx=(0, 10))  # runs the widget placement

        close = tk.Button(  # the way back to the report
            button_row,  # evaluates the button_row expression
            text="Close",  # the single action
            command=close_box,  # copies the close value into command
            bg=ACCENT,  # the brand-green style all primary actions wear
            fg=BG,  # the near-black ink straight off the brand background
            activebackground=ACCENT_HOVER,  # the pressed state
            activeforeground=BG,  # the near-black ink straight off the brand background
            relief="flat",  # sets the relief text
            font=(UI_FONT, 10, "bold"),  # the primary action weight
            padx=28,  # assigns the computed value to padx
            pady=6,  # assigns the computed value to pady
            cursor="hand2",  # sets the cursor text
            borderwidth=0,  # assigns the computed value to borderwidth
        )  # closes the multiline block
        close.grid(row=0, column=1)  # runs the widget placement

        box.update_idletasks()  # flushes the geometry before centreing
        x = max((box.winfo_screenwidth() - box.winfo_reqwidth()) // 2, 0)  # clampx
        y = max((box.winfo_screenheight() - box.winfo_reqheight()) // 2 - 30, 0)  # clampy
        box.geometry(f"+{x}+{y}")  # centres the popup on screen

    def _print_summary_pdf(self, bullets: list[str]) -> None:  # defines the _print_summary_pdf() function
        """Print the summary bullets through the shared themed PDF writer."""
        def write(path: str) -> str:  # the small inline write helper
            exports.write_summary_pdf(self._report, bullets, path)  # runs the write_summary_pdf() call
            return f"Summary PDF saved to {path}"  # the status line the user reads

        repo_name = (self._report.get("repo") or {}).get("full_name", "repo").replace("/", "-")  # the asset name
        self._ask_export(  # runs the _ask_export() call
            "Print summary to PDF",  # sets the title text
            ".pdf",  # sets the defaultextension text
            [("PDF document", "*.pdf")],  # assigns the computed value to filetypes
            write,  # copies the write value into writer
            failure="Could not write the summary PDF",  # the message prefix on failure
            open_after=True,  # opens the saved summary like the other PDF exports
            preset_name=f"{repo_name}-scan-summary.pdf",  # the suggested file name
        )  # closes the multiline block

    def check_gad(self) -> None:  # defines the check_gad() function
        """Run the GitHub Advisory Database sweep in a thread, then pop results."""
        if getattr(self, "_gad_checking", False):  # evaluates the branch condition
            return  # one sweep at a time
        targets = gad.gad_targets(self._report or {})  # the three-tier lookups, SBOM-independent
        if not (targets["components"] or targets["cves"] or targets["packages"]):  # evaluates
            messagebox.showerror(  # the honest gate
                config.APP_NAME,  # evaluates the config.APP_NAME expression
                "Nothing to look up: this report has no pinned components and no "
                "CVE identifiers. Run a scan with at least one SCA or SBOM scanner "
                "(Trivy, Grype, OSV, Syft or cdxgen), then use Check GAD.",  # the instruction text
                parent=self,  # copies the self value into parent
            )  # closes the multiline block
            return  # evaluates the return expression
        self._gad_checking = True  # the sweep guard
        self._gad_done = 0  # the progress counter the poll reads
        self._gad_total = len(targets["components"]) + len(targets["cves"]) + len(targets["packages"])  # the total
        self.progress.configure(mode="determinate", maximum=max(1, self._gad_total), value=0)  # the live bar
        self.gad_button.configure(state="disabled", text="Checking GAD…")  # the wait state
        self._set_status(  # the busy status line
            f"Checking the GitHub Advisory Database… 0/{self._gad_total}"
        )  # closes the status call

        def on_progress(done: int, total: int) -> None:  # the worker-side progress callback
            self._gad_done = done  # the counter the poll paints (int swaps are thread-safe)

        def worker() -> None:  # runs the network sweep off the UI thread
            result = gad.check_gad(  # runs the check_gad() call
                self._report or {},  # copies the report value into report
                progress=on_progress,  # the per-lookup progress callback
            )  # closes the sweep call
            self._gad_result = result  # publishes through the poll below
        thread = threading.Thread(target=worker, daemon=True)  # the worker thread
        thread.start()

        def poll() -> None:  # the main-thread poll that never touches Tk from the worker
            if thread.is_alive():  # evaluates the branch condition
                done = getattr(self, "_gad_done", 0)  # fetches the finished count
                total = getattr(self, "_gad_total", 1) or 1  # copies the total value into total
                self.progress.configure(value=done)  # paints the live bar
                self._set_status(f"Checking the GitHub Advisory Database… {done}/{total}")  # the live status
                self.after(200, poll)  # waits one more beat
                return  # covers the remaining branch
            self._gad_checking = False  # clears the sweep guard
            self.progress.configure(value=0)  # resets the bar to its resting state
            self.gad_button.configure(state="normal", text="Check GAD")  # restores the button
            self._set_status("GitHub Advisory Database check complete.")  # the finished status
            result = getattr(self, "_gad_result", None) or {}  # fetches the finished payload
            self._show_gad_popup(result)  # opens the themed results popup
        self.after(200, poll)  # starts the polling

    def _show_gad_popup(self, results: dict[str, Any]) -> None:
        """Build the Acknowledgement-styled popup reading the advisory sweep."""
        box = tk.Toplevel(self)  # the popup surface over the app
        box.title(f"{config.APP_NAME} - GitHub Advisory Check")  # the window title
        box.configure(bg=config.BRAND_NAVY)  # the app's own background
        box.attributes("-topmost", True)  # the popup sits over the report
        box.transient(self)  # groups with the app window
        box.app_icon = _set_window_icon(box)  # the AppIcon on this popup too

        def close_box() -> None:  # the shared close path
            if box.winfo_exists():  # the popup may already be gone
                box.destroy()  # closes the popup

        box.protocol("WM_DELETE_WINDOW", close_box)  # wires the cross button
        box.bind("<Escape>", lambda _e: close_box())  # escape closes too

        body = tk.Frame(box, bg=config.BRAND_NAVY)  # the full-bleed content column
        body.pack(fill="both", expand=True)  # owns the window
        body.columnconfigure(0, weight=1)  # runs the columnconfigure() call
        body.rowconfigure(4, weight=1)  # the hit list takes the slack

        try:  # the branding graphic rides the top, like every popup
            art = tk.PhotoImage(  # the full-resolution asset
                file=str(Path(__file__).resolve().parent / config.BRANDING_WORDMARK)
            )  # loads once at native size
            factor = max(2, -(-art.width() // 460))  # fits the narrower popup head
            art = art.subsample(factor, factor)  # scales the artwork down
            logo = tk.Label(body, image=art, bg=config.BRAND_NAVY)  # runs the Label() call
            logo.image = art  # anchors the image against garbage collection
            logo.grid(row=0, column=0, pady=(14, 2))  # runs the widget placement
        except Exception:  # a missing artwork never blocks a result set
            tk.Label(  # the text fallback header
                body, text=config.APP_NAME, bg=config.BRAND_NAVY,  # the name instead
                fg=config.BRAND_GREEN, font=(UI_FONT, 16, "bold"),  # the strong header
            ).grid(row=0, column=0, pady=(14, 2))  # runs the widget placement

        repo = self._report.get("repo") or {}  # the scanned target's identity block
        repo_name = str(repo.get("full_name") or repo.get("input_url") or "repository")  # the display title
        web_url = repo.get("web_url") or (  # the GitHub path when one is known
            f"https://github.com/{repo.get('full_name')}"  # the canonical URL
            if repo.get("full_name") else str(repo.get("input_url") or "")  # websites keep the address
        )  # closes the url build
        tk.Label(  # the repository title under the artwork
            body,  # evaluates the body expression
            text=repo_name,  # the scanned repo's name
            bg=config.BRAND_NAVY,  # copies the BRAND_NAVY value into bg
            fg=TEXT,  # full-bright: the page is about this repository
            font=(UI_FONT, 12, "bold"),  # the title weight
        ).grid(row=1, column=0)  # runs the widget placement
        if web_url:  # evaluates the branch condition
            tk.Label(  # the GitHub path line under the name
                body,  # evaluates the body expression
                text=web_url,  # the repository path
                bg=config.BRAND_NAVY,  # copies the BRAND_NAVY value into bg
                fg=MUTED,  # the path reads quieter than the name
                font=(UI_FONT, 9),  # the sub-line height
            ).grid(row=2, column=0, pady=(0, 6))  # runs the widget placement

        hits = list(results.get("hits") or [])  # the advisory hits, worst first
        header_text = (  # the one-line sweep summary
            f"GitHub Advisory Database  ·  {len(hits)} match{'es' if len(hits) != 1 else ''}  ·  "
            f"checked {results.get('checked', 0)} of {results.get('considered', 0)} pinned components"
        )  # closes the header build
        tk.Label(  # the section header under the identity block
            body,  # evaluates the body expression
            text=header_text,  # the header text
            bg=config.BRAND_NAVY,  # copies the BRAND_NAVY value into bg
            fg=config.BRAND_GREEN,  # the logo green
            font=(UI_FONT, 12, "bold"),  # the strong header weight
        ).grid(row=3, column=0, pady=(2, 6))  # runs the widget placement

        list_holder = tk.Frame(body, bg=config.BRAND_NAVY)  # hosts the scrolling hit list
        list_holder.grid(row=4, column=0, sticky="nsew", padx=18)  # runs the widget placement
        list_holder.columnconfigure(0, weight=1)  # runs the columnconfigure() call
        list_holder.rowconfigure(0, weight=1)  # runs the rowconfigure() call

        area = tk.Text(  # the read-only advisory list
            list_holder,  # evaluates the list_holder expression
            bg=PANEL,  # the panel tint like the report pane
            fg=TEXT,  # copies the TEXT value into fg
            insertbackground=TEXT,  # copies the TEXT value into insertbackground
            relief="flat",  # flat body
            font=(UI_FONT, 10),  # the readable summary size
            wrap="word",  # wraps at the box edge
            padx=14,  # assigns the computed value to padx
            pady=10,  # assigns the computed value to pady
            spacing1=4,  # a gap above each hit
        )  # closes the multiline block
        area.tag_configure("dot", foreground=config.BRAND_GREEN, font=(UI_FONT, 10, "bold"))  # the marker tag
        area.tag_configure("sev", font=(UI_FONT, 10, "bold"))  # the severity tag
        for hit in hits:  # walks the sorted advisory rows
            index = hits.index(hit)  # the row's ordinal, used for the per-hit colour tag
            severity = str(hit.get("severity") or "unknown")  # the severity word
            sev_colour = SEVERITY_COLOURS.get(  # the palette colour for the band
                "critical" if severity == "critical" else
                "high" if severity == "high" else
                "medium" if severity in {"moderate", "unknown"} else "low"  # the GHSA bands
            )  # closes the colour build
            area.tag_configure(f"sev{index}", foreground=sev_colour, font=(UI_FONT, 10, "bold"))  # the per-hit band tag
            area.insert("end", "●  ", "dot")  # the brand-green marker
            area.insert("end", f"[{severity.upper()}] ", f"sev{index}")  # the band, worst-severity coloured
            area.insert("end", f"{hit.get('ghsa') or 'GHSA'} · {hit.get('package', '')}\n", f"sev{index}")  # ids + package
            area.insert("end", f"{hit.get('summary') or ''}\n")  # the summary sentence
            area.insert("end", f"{hit.get('url') or ''}\n\n")  # the advisory link
        area.configure(state="disabled")  # read-only by definition
        area.grid(row=0, column=0, sticky="nsew")  # runs the widget placement

        area_scroll = tk.Scrollbar(list_holder, command=area.yview, bg=PANEL, troughcolor=PANEL, width=14)  # the bar
        area_scroll.grid(row=0, column=1, sticky="ns")  # runs the widget placement
        area.configure(yscrollcommand=area_scroll.set)  # updates the widget settings
        area.bind("<MouseWheel>", lambda event: area.yview_scroll(int(-event.delta / 120), "units"))  # wheel scroll

        if results.get("rate_limited") or results.get("errors"):  # evaluates the branch condition
            notes = list(results.get("errors") or [])[:3]  # the top notes
            note_text = ("Rate limited by GitHub (set GITHUB_TOKEN); " if results.get("rate_limited") else "")
            tk.Label(  # the muted notes row above the buttons
                body,  # evaluates the body expression
                text=(note_text + "; ".join(n for n in notes if "Rate limited" not in n))[:150],  # the note text
                bg=config.BRAND_NAVY,  # copies the BRAND_NAVY value into bg
                fg=DISABLED_GREY,  # sets the fg text
                font=(UI_FONT, 8),  # the footnote height
                wraplength=820,  # wraps inside the popup body
                justify="left",  # reads left to right
            ).grid(row=5, column=0, sticky="w", padx=18)  # runs the widget placement

        button_row = tk.Frame(body, bg=config.BRAND_NAVY)  # hosts Print and Close side by side
        button_row.grid(row=6, column=0, pady=(8, 16))  # runs the widget placement

        print_check = tk.Button(  # prints the advisory sweep to a themed PDF
            button_row,  # evaluates the button_row expression
            text="Print",  # the print action
            command=lambda: self._print_gad_pdf(results),  # the shared dialog writer
            bg=ACCENT,  # the brand-green style primary actions wear
            fg=BG,  # the near-black ink straight off the brand background
            activebackground=ACCENT_HOVER,  # the pressed state
            activeforeground=BG,  # the near-black ink straight off the brand background
            relief="flat",  # sets the relief text
            font=(UI_FONT, 10, "bold"),  # the primary action weight
            padx=20,  # assigns the computed value to padx
            pady=6,  # assigns the computed value to pady
            cursor="hand2",  # sets the cursor text
            borderwidth=0,  # assigns the computed value to borderwidth
        )  # closes the multiline block
        print_check.grid(row=0, column=0, padx=(0, 10))  # runs the widget placement

        close = tk.Button(  # the way back to the report
            button_row,  # evaluates the button_row expression
            text="Close",  # the single close action
            command=close_box,  # copies the close value into command
            bg=ACCENT,  # the brand-green style primary actions wear
            fg=BG,  # the near-black ink straight off the brand background
            activebackground=ACCENT_HOVER,  # the pressed state
            activeforeground=BG,  # the near-black ink straight off the brand background
            relief="flat",  # sets the relief text
            font=(UI_FONT, 10, "bold"),  # the primary action weight
            padx=28,  # assigns the computed value to padx
            pady=6,  # assigns the computed value to pady
            cursor="hand2",  # sets the cursor text
            borderwidth=0,  # assigns the computed value to borderwidth
        )  # closes the multiline block
        close.grid(row=0, column=1)  # runs the widget placement

        box.update_idletasks()  # flushes the geometry before centreing
        x = max((box.winfo_screenwidth() - box.winfo_reqwidth()) // 2, 0)  # clampx
        y = max((box.winfo_screenheight() - box.winfo_reqheight()) // 2 - 30, 0)  # clampy
        box.geometry(f"+{x}+{y}")  # centres the popup on screen

    def _print_gad_pdf(self, results: dict[str, Any]) -> None:  # defines the _print_gad_pdf() function
        """Print the advisory sweep through the shared themed PDF writer."""
        def write(path: str) -> str:  # the small inline write helper
            exports.write_gad_pdf(self._report, results, path)  # runs the write_gad_pdf() call
            return f"GitHub Advisory check PDF saved to {path}"  # the status line the user reads

        repo_name = (self._report.get("repo") or {}).get("full_name", "repo").replace("/", "-")  # the asset name
        self._ask_export(  # runs the _ask_export() call
            "Print GAD check to PDF",  # sets the title text
            ".pdf",  # sets the defaultextension text
            [("PDF document", "*.pdf")],  # assigns the computed value to filetypes
            write,  # copies the write value into writer
            failure="Could not write the advisory-check PDF",  # the message prefix on failure
            open_after=True,  # opens the saved check like the other PDF exports
            preset_name=f"{repo_name}-github-advisory-check.pdf",  # the suggested file name
        )  # closes the multiline block

    def _remember_url(self, url: str) -> None:  # defines the instance wrapper
        """Promote the just-scanned target to the front of the URL history."""
        self._url_history = _remember_url(url)  # the shared module helper, instance-cached

    def _drop_global_click(self, event) -> None:  # defines the _drop_global_click() function
        """Close the open dropdown on any click outside it and the URL field."""
        drop = getattr(self, "_url_drop", None)  # the open dropdown, when there is one
        if drop is None:  # evaluates the branch condition
            return  # nothing to dismiss
        widget = event.widget  # the clicked widget
        while widget is not None:  # walks up to find the ancestry
            if widget is drop or widget is self.url_entry:  # the click belonged to the field or the list
                return  # their own bindings handle it
            widget = widget.master  # climbs one level
        self._hide_url_history()  # the click was elsewhere in the app: close now

    def _show_url_history(self) -> None:  # defines the _show_url_history() function
        """Drop a selection list under the URL field when it gains focus."""
        if getattr(self, "_url_drop", None) is not None:  # already open; nothing to do
            return  # covers the remaining branch
        entries = self._url_history  # the instance-cached history list
        if not entries:  # evaluates the branch condition
            return  # an empty history drops nothing
        drop = tk.Toplevel(self)  # creates the dropdown surface
        drop.overrideredirect(True)  # a borderless dropdown, not a dialog
        drop.transient(self)  # stays above the app window
        drop.attributes("-topmost", True)  # the pick list may never sit behind the panel
        entry_x = self.url_entry.winfo_rootx()  # the entry's screen position
        entry_y = self.url_entry.winfo_rooty() + self.url_entry.winfo_height() + 2  # just under the field
        drop.geometry(f"+{entry_x}+{entry_y}")  # runs the geometry() call

        listbox = tk.Listbox(  # the pick list
            drop,  # evaluates the drop expression
            height=min(len(entries), config.URL_HISTORY_LIMIT),  # one row per entry
            width=max(48, self.url_entry.winfo_width() // 9),  # entry-width rows
            bg=PANEL_ALT,  # the dark panel fill
            fg=TEXT,  # copies the TEXT value into fg
            highlightthickness=1,  # a thin edge
            highlightbackground=BORDER,  # sets the highlightbackground text
            activestyle="dotbox",  # marks the row the cursor is on
            relief="flat",  # sets the relief text
            font=(UI_FONT, 10),  # a comfortable pick size
        )  # closes the multiline block
        for entry in entries:  # builds the list content
            listbox.insert("end", entry)  # inserts an item to the listbox
        listbox.grid(row=0, column=0, sticky="nsew")  # runs the widget placement
        listbox.bind("<ButtonPress-1>", lambda _e: self._drop_pending_cancel())  # a press inside the list cancels the close timer
        listbox.bind("<ButtonRelease-1>", lambda _e: self._pick_url_history(listbox))  # click-to-pick
        listbox.bind("<Return>", lambda _e: self._pick_url_history(listbox))  # keyboard pick
        listbox.bind("<Escape>", lambda _e: self._hide_url_history())  # escape closes
        drop.listbox = listbox  # keeps a reference for the pick handler
        self._url_drop = drop  # the app remembers its open dropdown
        self.url_entry.bind("<Escape>", lambda _e: self._hide_url_history(), add="+")  # escape in the field closes
        self.url_entry.bind("<FocusOut>", lambda _e: self._drop_pending_hide(), add="+")  # leaving the field schedules the close
        drop.deiconify()  # forces the mapping overrideredirect needs
        drop.lift()  # raises the dropdown above the app surface
        drop.update_idletasks()  # flushes the mapping now, not later
        pending = getattr(self, "_drop_hide_id", None)  # a re-focus cancels the pending hide
        if pending:  # evaluates the branch condition
            self.after_cancel(pending)  # keeps the list alive while the field re-focused
            self._drop_hide_id = None  # clears the pending handle

    def _drop_pending_cancel(self) -> None:  # defines the _drop_pending_cancel() function
        """Cancel only the scheduled close (a list click is arriving)."""
        pending = getattr(self, "_drop_hide_id", None)  # the pending timer
        if pending:  # evaluates the branch condition
            try:  # the timer may already be gone
                self.after_cancel(pending)  # cancels the scheduled close
            except Exception:  # handles the destroyed case
                pass  # keeps the block syntactically empty
        self._drop_hide_id = None  # clears the pending handle

    def _drop_pending_hide(self) -> None:  # defines the _drop_pending_hide() function
        """Schedule the dropdown close; a click into the list can cancel it."""
        pending = getattr(self, "_drop_hide_id", None)  # avoids stacking timers
        if pending:  # evaluates the branch condition
            self.after_cancel(pending)  # cancels the pending timer
        self._drop_hide_id = self.after(280, self._hide_url_history)  # generous enough for list clicks

    def _hide_url_history(self) -> None:  # defines the _hide_url_history() function
        """Close the history dropdown if it is open."""
        pending = getattr(self, "_drop_hide_id", None)  # the scheduled close
        if pending:  # evaluates the branch condition
            try:  # the timer may already be gone
                self.after_cancel(pending)  # cancels the scheduled close
            except Exception:  # handles the destroyed case
                pass  # keeps the block syntactically empty
        self._drop_hide_id = None  # clears the pending handle
        drop = getattr(self, "_url_drop", None)  # fetches the open dropdown
        if drop is not None:  # evaluates the branch condition
            try:  # the widget may already be gone
                drop.destroy()  # closes the dropdown
            except Exception:  # handles the destroyed case
                pass  # keeps the block syntactically empty
        self._url_drop = None  # clears the reference

    def _pick_url_history(self, listbox: tk.Listbox) -> None:  # defines the _pick_url_history() function
        """Load the selected history row into the URL field and close the list."""
        selection = listbox.curselection()  # fetches the picked row
        if selection:  # evaluates the branch condition
            self.url_var.set(listbox.get(selection[0]))  # copies the picked value into url_var
        self._hide_url_history()  # runs the _hide_url_history() call
        self.url_entry.focus_set()  # returns the cursor to the field

    def open_folder(self) -> None:  # defines the open_folder() function
        target = (self._report or {}).get("artifacts_dir") or str(config.CACHE_DIR)  # fetches the value
        try:  # watches for errors in the block
            if os.name == "nt":  # evaluates the branch condition
                os.startfile(target)  # type: ignore[attr-defined]  # opens the item in Explorer
            elif sys.platform == "darwin":  # checks the alternate condition
                subprocess.Popen(["open", target])  # runs the Popen() call
            else:  # covers the remaining branch
                subprocess.Popen(["xdg-open", target])  # runs the Popen() call
        except Exception as exc:  # handles the raised error
            messagebox.showerror(config.APP_NAME, f"Could not open {target}: {exc}", parent=self)  # runs the showerror() call

    # ------------------------------------------------------------------
    # Settings / lifecycle
    # ------------------------------------------------------------------
    def _restore_settings(self) -> None:  # defines the _restore_settings() function
        try:  # watches for errors in the block
            data = json.loads(config.SETTINGS_FILE.read_text(encoding="utf-8"))  # parses the text into JSON data
            last = data.get("last_url", "")  # fetches the value
            if last:  # evaluates the branch condition
                self.url_var.set(last)  # updates the stored value
                self.url_entry.select_range(0, "end")  # runs the select_range() call
            saved_tools = data.get("tools")  # fetches the value
            if isinstance(saved_tools, list) and saved_tools:  # evaluates the branch condition
                chosen = {str(tool) for tool in saved_tools}  # runs the str() call
                # A settings file from before the newer scanners existed cannot
                # express an opinion about them, so enable them by default rather
                # than silently dropping their coverage from every scan.
                if data.get("settings_version", 1) < config.SETTINGS_VERSION:  # evaluates the branch condition
                    chosen |= set(config.DEFAULT_TOOLS)  # updates the stored value in place
                for tool, var in self.tool_vars.items():  # loops over the collection
                    var.set(tool in chosen)  # updates the stored value
            saved_frameworks = data.get("frameworks")  # fetches the value
            if isinstance(saved_frameworks, list):  # evaluates the branch condition
                chosen = compliance.normalize_frameworks(saved_frameworks)  # runs the normalize_frameworks() call
                # Framework choices are organisation-specific, so an old file's
                # empty selection is simply kept rather than force-enabled.
                for key, var in self.framework_vars.items():  # loops over the collection
                    var.set(key in chosen)  # updates the stored value
                self._update_framework_count()  # runs the _update_framework_count() call
            # Dashboard metrics are NOT restored: every launch starts with the
            # whole set ticked, and per-session unticks live only until close.
        except Exception:  # handles the raised error
            pass  # keeps the block syntactically empty

    def _save_settings(  # defines the _save_settings() function
        self, url: str, tools: list[str] | None = None, frameworks: list[str] | None = None  # evaluates the self expression
    ) -> None:  # closes the multiline block
        try:  # watches for errors in the block
            config.CACHE_DIR.mkdir(parents=True, exist_ok=True)  # creates the folder
            payload = {  # assigns the computed value to payload
                "settings_version": config.SETTINGS_VERSION,  # maps the settings_version dictionary entry
                "last_url": url,  # maps the last_url dictionary entry
                "tools": list(tools if tools is not None else self._selected_tools()),  # maps the tools dictionary entry
                "frameworks": list(  # maps the frameworks dictionary entry
                    frameworks if frameworks is not None else self._selected_frameworks()  # runs the _selected_frameworks() call
                ),  # closes the multiline block
                # dashboard metrics are intentionally not persisted: the metric
                # selection restarts fully ticked on every launch.
            }  # closes the multiline block
            config.SETTINGS_FILE.write_text(  # writes the text file
                json.dumps(payload, indent=2), encoding="utf-8"  # runs the dumps() call
            )  # closes the multiline block
        except Exception:  # handles the raised error
            pass  # keeps the block syntactically empty

    def _on_close(self) -> None:  # defines the _on_close() function
        """Confirms any live scan, then tears the window down.

        The scan worker itself is a daemon thread: it dies with the
        process at interpreter exit, so an unfinished scan never blocks
        shutdown - the cancel flag merely asks it politely to abandon its
        work while the user is still looking at the dialog."""
        if self._worker and self._worker.is_alive():  # evaluates the branch condition
            if not messagebox.askyesno(  # evaluates the branch condition
                config.APP_NAME, "A scan is running. Stop it and quit?", parent=self  # evaluates the config.APP_NAME expression
            ):  # closes the multiline block
                return  # evaluates the return expression
            self._cancel.set()  # updates the stored value
        self.destroy()  # runs the destroy() call

    def _report_callback_exception(self, exc, value, tb) -> None:  # noqa: ANN001  # defines the _report_callback_exception() function
        """Keep unexpected UI errors visible even when launched with pythonw."""  # keeps the docstring text
        import traceback  # imports the traceback module

        detail = "".join(traceback.format_exception(exc, value, tb))  # sets the detail text
        try:  # watches for errors in the block
            (config.CACHE_DIR / "ui-errors.log").write_text(detail, encoding="utf-8")  # writes the text file
        except Exception:  # handles the raised error
            pass  # keeps the block syntactically empty
        self._log(f"UI error: {value}")  # runs the _log() call
        try:  # watches for errors in the block
            messagebox.showerror(  # runs the showerror() call
                config.APP_NAME,  # evaluates the config.APP_NAME expression
                f"Something went wrong in the interface:\n\n{value}\n\nDetails written to "  # maps the Something went wrong in  dictionary entry
                f"{config.CACHE_DIR / 'ui-errors.log'}",  # evaluates the f expression
                parent=self,  # copies the self value into parent
            )  # closes the multiline block
        except Exception:  # handles the raised error
            pass  # keeps the block syntactically empty


def _record_disclaimer_acceptance(version: int) -> None:
    """Stamp the live settings file with the accepted disclaimer version."""
    payload: dict[str, Any] = {}  # reads the existing settings without clobbering them
    try:  # watches for a missing or unreadable file
        payload = json.loads(config.SETTINGS_FILE.read_text(encoding="utf-8"))  # reads prior choices
    except Exception:  # handles the read error
        payload = {}  # keeps the block syntactically empty
    payload["disclaimer_accepted_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")  # the audit trail
    payload["disclaimer_version"] = version  # which wording was accepted
    try:  # watches for write failures
        config.SETTINGS_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")  # writes the stamp
    except Exception:  # handles the write error
        pass  # the gate decision stands even if the audit stamp cannot be written


def _build_disclaimer_screen(gate: tk.Tk, on_accept) -> None:
    """Assemble the brand-styled pre-launch gate onto a bare Tk root.

    ``on_accept(True)`` fires when "I Understand & Agree" is pressed;
    ``on_accept(False)`` when the window is closed without agreeing. Building
    the widgets is separate from the mainloop so tests can drive the buttons
    offline.
    """
    gate.title(f"{config.APP_NAME} - Legal Disclaimer")  # a proper window title
    gate.configure(bg=config.BRAND_NAVY)  # the app's own background
    gate.attributes("-topmost", True)  # the gate is modal: it must not hide behind other windows
    gate.app_icon = _set_window_icon(gate)  # the gate carries the AppIcon too

    def on_closed() -> None:  # the window cross button is a refusal
        on_accept(False)  # refuses without recording an acceptance

    gate.protocol("WM_DELETE_WINDOW", on_closed)  # wires the cross button

    def _centre_gate(root: tk.Tk) -> None:  # defines the _centre_gate() function
        """Centre the gate on the primary screen before it paints."""
        root.update_idletasks()  # flushes the pending geometry
        width = root.winfo_reqwidth()  # reads the requested width
        height = root.winfo_reqheight()  # reads the requested height
        x = max((root.winfo_screenwidth() - width) // 2, 0)  # clamps the origin
        y = max((root.winfo_screenheight() - height) // 2 - 30, 0)  # clamps the origin
        root.geometry(f"+{x}+{y}")  # runs the geometry() call

    body = tk.Frame(gate, bg=config.BRAND_NAVY)  # the full-bleed content column
    body.pack(fill="both", expand=True)  # owns the window
    body.columnconfigure(0, weight=1)  # runs the columnconfigure() call
    body.rowconfigure(3, weight=1)  # the disclaimer text takes the slack

    try:  # the branding graphic rides the top of the gate
        art = tk.PhotoImage(  # the full-resolution "Branding" asset
            file=str(Path(__file__).resolve().parent / config.BRANDING_WORDMARK)
        )  # loads once at native size
        factor = max(2, -(-art.width() // 520))  # the smallest factor that fits 520 px
        art = art.subsample(factor, factor)  # fits the gate width exactly
        logo = tk.Label(  # runs the Label() call
            body,  # evaluates the body expression
            image=art,  # the ScanityCheck artwork
            bg=config.BRAND_NAVY,  # blends into the header
        )  # closes the multiline block
        logo.image = art  # anchors the scaled copy against garbage collection
        logo.grid(row=0, column=0, pady=(18, 4))  # runs the widget placement
    except Exception:  # a missing artwork never blocks a legal notice
        tk.Label(  # renders the wordmark in text instead
            body,  # evaluates the body expression
            text=config.APP_NAME,  # the plain-text fallback
            bg=config.BRAND_NAVY,  # copies the BRAND_NAVY value into bg
            fg=config.BRAND_GREEN,  # the logo green
            font=(UI_FONT, 16, "bold"),  # a strong header
        ).grid(row=0, column=0, pady=(18, 4))  # runs the widget placement

    tk.Label(  # the badge strip, matching the app header's family
        body,  # evaluates the body expression
        text="LOCAL  ·  NO CODE LEAVES THIS MACHINE",  # the badge text
        bg=config.BRAND_NAVY,  # copies the BRAND_NAVY value into bg
        fg=MUTED,  # copies the MUTED value into fg
        font=(UI_FONT, 8),  # the badge foot height
    ).grid(row=1, column=0, pady=(0, 10))  # runs the widget placement

    tk.Label(  # the section header the user reads first
        body,  # evaluates the body expression
        text="Legal Disclaimer & Authorized Use",  # the section header
        bg=config.BRAND_NAVY,  # copies the BRAND_NAVY value into bg
        fg=config.BRAND_GREEN,  # the logo green
        font=(UI_FONT, 12, "bold"),  # a strong header weight
    ).grid(row=2, column=0, pady=(0, 8), padx=18, sticky="w")  # runs the widget placement

    text_holder = tk.Frame(body, bg=config.BRAND_NAVY)  # hosts the scrolling text
    text_holder.grid(row=3, column=0, sticky="nsew", padx=18)  # runs the widget placement
    text_holder.columnconfigure(0, weight=1)  # runs the columnconfigure() call
    text_holder.rowconfigure(0, weight=1)  # runs the rowconfigure() call

    disclaimer = tk.Text(  # the read-only disclaimer body
        text_holder,  # evaluates the text_holder expression
        bg=PANEL,  # the panel tint like the report pane
        fg=TEXT,  # copies the TEXT value into fg
        insertbackground=TEXT,  # copies the TEXT value into insertbackground
        relief="flat",  # flat body
        font=(MONO_FONT, 9),  # the report-pane mono pairing
        wrap="word",  # wraps at the box edge
        padx=14,  # assigns the computed value to padx
        pady=10,  # assigns the computed value to pady
        spacing2=3,  # a small paragraph gap
    )  # closes the multiline block
    disclaimer.insert("1.0", config.LEGAL_DISCLAIMER)  # the full legal text
    disclaimer.configure(state="disabled")  # read-only by definition
    disclaimer.grid(row=0, column=0, sticky="nsew")  # runs the widget placement

    scroll = tk.Scrollbar(text_holder, command=disclaimer.yview, bg=PANEL, troughcolor=PANEL, width=14)  # the drag bar
    scroll.grid(row=0, column=1, sticky="ns")  # runs the widget placement
    disclaimer.configure(yscrollcommand=scroll.set)  # updates the widget settings
    disclaimer.bind("<MouseWheel>", lambda event: disclaimer.yview_scroll(int(-event.delta / 120), "units"))  # wheel

    tk.Label(  # the honest footer line above the button
        body,  # evaluates the body expression
        text="The application opens only after you accept these terms.",  # the gate rule
        bg=config.BRAND_NAVY,  # copies the BRAND_NAVY value into bg
        fg=MUTED,  # copies the MUTED value into fg
        font=(UI_FONT, 8),  # the small footer height
    ).grid(row=4, column=0, pady=(10, 2))  # runs the widget placement

    agree = tk.Button(  # the single accepting action
        body,  # evaluates the body expression
        text="I Understand & Agree",  # the exact consent phrase
        command=lambda: on_accept(True),  # accepts loudly
        bg=ACCENT,  # the brand-green style the Scan button wears
        fg=BG,  # the near-black ink straight off the brand background
        activebackground=ACCENT_HOVER,  # the pressed state
        activeforeground=BG,  # the near-black ink straight off the brand background
        relief="flat",  # sets the relief text
        font=(UI_FONT, 10, "bold"),  # the primary action weight
        padx=24,  # assigns the computed value to padx
        pady=8,  # assigns the computed value to pady
        cursor="hand2",  # sets the cursor text
        borderwidth=0,  # assigns the computed value to borderwidth
    )  # closes the multiline block
    agree.grid(row=5, column=0, pady=(2, 20), ipadx=4)  # runs the widget placement

    tk.Label(  # the decline guidance under the button
        body,  # evaluates the body expression
        text="To decline, simply close this window - the application will not open.",  # the refusal path
        bg=config.BRAND_NAVY,  # copies the BRAND_NAVY value into bg
        fg=DISABLED_GREY,  # sets the fg text
        font=(UI_FONT, 8),  # assigns the computed value to font
    ).grid(row=6, column=0, pady=(0, 14))  # runs the widget placement

    _centre_gate(gate)  # centres the gate before it paints


def _show_disclaimer_gate() -> bool:
    """Show the pre-launch disclaimer; return True only on explicit consent."""
    accepted: list[bool] = [False]  # a slot the handlers write through

    gate = tk.Tk()  # the gate is its own root: nothing of the app exists yet

    def on_accept(agreed: bool) -> None:  # the screen reports through here
        accepted[0] = agreed  # records the decision
        gate.destroy()  # ends the gate's mainloop either way

    _build_disclaimer_screen(gate, on_accept)  # the styled screen
    gate.mainloop()  # blocks until the gate is answered or closed

    agreed = accepted[0]  # reads the decision the buttons recorded
    if agreed:  # evaluates the branch condition
        _record_disclaimer_acceptance(config.LEGAL_DISCLAIMER_VERSION)  # the audit stamp
    return agreed  # True only after an explicit agreement


def _load_url_history() -> list[str]:  # defines the _load_url_history() function
    """The most recent scanned targets, newest first, capped and cleaned."""
    try:  # watches for a missing or corrupted file
        data = json.loads(config.URL_HISTORY_FILE.read_text(encoding="utf-8"))  # reads the list
    except Exception:  # handles the read error
        return []  # an unreadable history is simply an empty one
    entries: list[str] = []  # deduplicated, in stored order
    for raw in data if isinstance(data, list) else []:  # loops over the stored rows
        url = str(raw).strip()  # cleans the entry
        if url and url not in entries:  # evaluates the branch condition
            entries.append(url)  # keeps the newest-first order
    return entries[: config.URL_HISTORY_LIMIT]  # the capped list of recent targets


def _save_url_history(entries: list[str]) -> None:  # defines the _save_url_history() function
    """Persist the rolling history; a failed write never fails a scan launch."""
    try:  # watches for write failures
        config.CACHE_DIR.mkdir(parents=True, exist_ok=True)  # creates the folder
        config.URL_HISTORY_FILE.write_text(  # writes the list as plain JSON
            json.dumps(entries[: config.URL_HISTORY_LIMIT], indent=2), encoding="utf-8"
        )  # closes the write
    except Exception:  # handles the read error
        pass  # the session still remembers its own entries in memory


def _remember_url(url: str) -> list[str]:  # defines the _remember_url() function
    """Insert-or-promote one target to the front of the rolling history."""
    entries = [entry for entry in _load_url_history() if entry != url.strip()]  # the prior list without it
    url = url.strip()  # cleans the entered value
    if url:  # evaluates the branch condition
        entries.insert(0, url)  # promotes the newest target to the front
    entries = entries[: config.URL_HISTORY_LIMIT]  # keeps the dropdown bounded
    _save_url_history(entries)  # persists the rotation
    return entries  # returns the list for the dropdown's use


def main() -> None:  # defines the main() function
    _enable_dpi_awareness()  # runs the _enable_dpi_awareness() call
    config.CACHE_DIR.mkdir(parents=True, exist_ok=True)  # creates the folder
    if not _show_disclaimer_gate():  # the legal gate: no agreement, no app
        return  # the application never opens without consent
    app = App()  # runs the App() call
    app.mainloop()  # runs the mainloop() call


if __name__ == "__main__":  # runs the module entry point
    main()  # runs the main() call
