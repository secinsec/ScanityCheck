"""CSV and PDF export of a finished scan report.

Both writers use only the Python standard library: CSV through :mod:`csv` and
PDF through a tiny built-in writer that emits base-14 fonts (Helvetica and
Courier), so exporting never needs an extra package, a browser, or a word
processor.
"""

from __future__ import annotations  # imports annotations from the __future__ module

import care  # imports the care module
import csv  # imports the csv module
import hashlib  # the SHA-256 fingerprint the integrity page stamps
import re as regex  # imports re as regex from the re module
import struct  # imports the struct module
import textwrap  # imports the textwrap module
import unicodedata  # imports the unicodedata module
import zlib  # imports the zlib module
from pathlib import Path  # imports Path from the pathlib module
from typing import Any, Iterable  # imports Any, Iterable from the typing module

import config  # imports the config module
import reportkeys  # imports the shared category registry
import scoring  # imports the scoring module
import textutil  # imports the shared clip/clean helpers

# --------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------

CSV_COLUMNS = (  # assigns the computed value to CSV_COLUMNS
    "Severity",  # supplies the literal text
    "Category",  # supplies the literal text
    "Title",  # supplies the literal text
    "Tools",  # supplies the literal text
    "Tool Keys",  # supplies the literal text
    "File",  # supplies the literal text
    "Line",  # supplies the literal text
    "Location",  # supplies the literal text
    "Rule ID",  # supplies the literal text
    "Package",  # supplies the literal text
    "CWE",  # supplies the literal text
    "Penalty",  # supplies the literal text
    "Detail",  # supplies the literal text
    "Reference",  # supplies the literal text
    "Compliance Frameworks",  # supplies the literal text
    "Affected Controls",  # supplies the literal text
)  # closes the multiline block


def _framework_text_for(  # defines the _framework_text_for() function
    item: dict[str, Any], framework_by_finding: dict[str, Any]  # evaluates the item expression
) -> tuple[str, str]:  # closes the multiline block
    """Mapping text for one CSV row: (framework labels, control ids)."""
    key = reportkeys.location_key(item)  # the shared row identity
    entry = framework_by_finding.get(key)  # fetches the value
    if not entry:  # evaluates the branch condition
        return "", ""  # returns the value to the caller
    labels = list(entry)  # builds the list collection
    controls_text = "; ".join(  # sets the controls_text text
        f"{label}: {', '.join(ids)}" for label, ids in entry.items()  # waits for the thread
    )  # closes the multiline block
    return "; ".join(labels), controls_text  # returns the value to the caller


def _sorted_findings(report: dict[str, Any]) -> list[dict[str, Any]]:  # defines the _sorted_findings() function
    findings = list(report.get("findings") or [])  # builds the list collection
    return sorted(  # returns the sorted to the caller
        findings,  # evaluates the findings expression
        key=lambda item: (  # copies the lambda value into key
            scoring.severity_rank(str(item.get("severity") or "unknown")),  # runs the severity_rank() call
            str(item.get("category") or ""),  # runs the str() call
            str(item.get("location") or ""),  # runs the str() call
            str(item.get("title") or ""),  # runs the str() call
        ),  # closes the multiline block
    )  # closes the multiline block


def write_report_csv(report: dict[str, Any], path: str | Path) -> Path:  # defines the write_report_csv() function
    """Write one row per de-duplicated finding.

    The file starts with a UTF-8 BOM so Excel opens it with the right encoding,
    and ``csv`` handles quoting for titles/details that contain commas.
    """
    path = Path(path)  # creates the path object
    path.parent.mkdir(parents=True, exist_ok=True)  # creates the folder
    labels = scoring.CATEGORY_LABELS  # the public registry, not a report copy
    framework_by_finding = report.get("framework_by_finding") or {}  # fetches the value

    with path.open("w", encoding="utf-8-sig", newline="") as handle:  # opens the context for the block
        writer = csv.writer(handle)  # runs the writer() call
        writer.writerow(CSV_COLUMNS)  # runs the writerow() call
        for item in _sorted_findings(report):  # loops over the collection
            frameworks_text, controls_text = _framework_text_for(  # runs the _framework_text_for() call
                item, framework_by_finding  # evaluates the item expression
            )  # closes the multiline block
            writer.writerow(  # runs the writerow() call
                [  # executes the statement
                    str(item.get("severity") or "unknown").upper(),  # runs the str() call
                    labels.get(item.get("category"), item.get("category") or ""),  # fetches the value
                    item.get("title") or "",  # fetches the value
                    "; ".join(item.get("tool_labels") or []),  # supplies the literal text
                    "; ".join(item.get("tools") or []),  # supplies the literal text
                    item.get("file") or "",  # fetches the value
                    item.get("line") or "",  # fetches the value
                    item.get("location") or "",  # fetches the value
                    item.get("rule_id") or "",  # fetches the value
                    item.get("package") or "",  # fetches the value
                    item.get("cwe") or "",  # fetches the value
                    item.get("weight", ""),  # fetches the value
                    item.get("detail") or "",  # fetches the value
                    item.get("reference") or "",  # fetches the value
                    frameworks_text,  # evaluates the frameworks_text expression
                    controls_text,  # evaluates the controls_text expression
                ]  # closes the multiline block
            )  # closes the multiline block
    return path  # returns the path to the caller


# --------------------------------------------------------------------------
# PDF
# --------------------------------------------------------------------------

PAGE_WIDTH = 595.28  # A4 portrait, in PostScript points  # assigns the computed value to PAGE_WIDTH
PAGE_HEIGHT = 841.89  # assigns the computed value to PAGE_HEIGHT
MARGIN = 42.0  # assigns the computed value to MARGIN
BOTTOM = 52.0  # assigns the computed value to BOTTOM

FONT_REGULAR = "F1"  # Helvetica  # sets the FONT_REGULAR text
FONT_BOLD = "F2"  # Helvetica-Bold  # sets the FONT_BOLD text
FONT_MONO = "F3"  # Courier  # sets the FONT_MONO text
FONT_MONO_BOLD = "F4"  # Courier-Bold  # sets the FONT_MONO_BOLD text

INK = (0.12, 0.16, 0.22)  # assigns the computed value to INK
MUTED = (0.36, 0.42, 0.50)  # assigns the computed value to MUTED
ACCENT = (0.20, 0.45, 0.75)  # assigns the computed value to ACCENT
RULE = (0.78, 0.82, 0.87)  # assigns the computed value to RULE
DANGER = (0.78, 0.20, 0.24)  # assigns the computed value to DANGER
OK = (0.13, 0.55, 0.32)  # assigns the computed value to OK
TRACK_GREY = (0.90, 0.92, 0.94)  # bar-chart track colour

DIGEST_PLACEHOLDER = "0" * 64  # the reserved slot the fingerprint is hashed into

# Severity fills for the dashboard heat grid (brand-tuned dark tones so the
# white counts inside the cells stay readable on print).
_SEV_FILL = {
    "critical": "#b91c1c",
    "high": "#c2410c",
    "medium": "#a16207",
    "low": "#4d7c0f",
    "unknown": "#44577a",
}


def _pdf_colour(hex_value: str) -> tuple[float, float, float]:
    """Convert a #rrggbb string into a 0-1 RGB tuple."""
    text = str(hex_value or "").lstrip("#")  # strips the leading hash
    if len(text) != 6:  # evaluates the branch condition
        return (0.55, 0.64, 0.76)  # falls back to a neutral grey
    return (  # returns the channels
        int(text[0:2], 16) / 255.0,
        int(text[2:4], 16) / 255.0,
        int(text[4:6], 16) / 255.0,
    )


def _mix_white(colour, amount):  # defines the _mix_white() function
    """Blend a colour toward white by ``amount`` (0-1)."""
    amount = min(1.0, max(0.0, amount))  # clamps the blend
    r, g, b = colour  # unpacks the channels
    return (  # returns the blended channels
        r * (1 - amount) + amount,
        g * (1 - amount) + amount,
        b * (1 - amount) + amount,
    )

_TRANSLITERATE = str.maketrans(  # runs the maketrans() call
    {  # executes the statement
        "\u2018": "'",  # maps the \u2018 dictionary entry
        "\u2019": "'",  # maps the \u2019 dictionary entry
        "\u201c": '"',  # maps the \u201c dictionary entry
        "\u201d": '"',  # maps the \u201d dictionary entry
        "\u2013": "-",  # maps the \u2013 dictionary entry
        "\u2014": "-",  # maps the \u2014 dictionary entry
        "\u2026": "...",  # maps the \u2026 dictionary entry
        "\u2192": "->",  # maps the \u2192 dictionary entry
        "\u00b7": "-",  # maps the \u00b7 dictionary entry
        "\u2022": "*",  # maps the \u2022 dictionary entry
        "\u00a0": " ",  # maps the \u00a0 dictionary entry
        "\u2265": ">=",  # maps the \u2265 dictionary entry
        "\u2264": "<=",  # maps the \u2264 dictionary entry
    }  # closes the multiline block
)  # closes the multiline block


def _pdf_text(value: Any) -> str:  # defines the _pdf_text() function
    """Make text safe for a base-14 PDF font and a literal string object."""  # keeps the docstring text
    text = str(value or "").translate(_TRANSLITERATE)  # runs the str() call
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")  # runs the normalize() call
    text = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")  # swaps the text
    return "".join(ch if 32 <= ord(ch) < 127 else " " for ch in text)  # returns the value to the caller


def _wrap_chars(value: Any, width: int) -> list[str]:  # defines the _wrap_chars() function
    """Word-aware wrap to a character-count width; long tokens hard-break.

    Returns every line of the cell content, so nothing a fixed-width column
    cannot fit is silently dropped on the floor by ``_fit``.
    """
    text = str(value or "").replace("\t", " ").strip()  # normalises the cell text
    if not text:  # evaluates the branch condition
        return [""]  # an empty cell still occupies one drawn line
    if width <= 0:  # evaluates the branch condition
        return [text]  # a zero-width column degenerates to one line
    lines: list[str] = []  # the wrapped output
    for paragraph in text.splitlines() or [text]:  # honours embedded newlines
        words = paragraph.split(" ")  # splits the words apart
        current = ""  # the line being assembled
        for word in words:  # packs the words into the lines
            while len(word) > width:  # a token longer than the column hard-breaks
                piece = word[:width]  # the fitting piece
                if current:  # finishes the line first
                    lines.append(current)  # adds the assembled line
                lines.append(piece)  # adds the hard-cut piece
                word = word[width:]  # continues with the rest
                current = ""  # the remainder starts a new line
            candidate = f"{current} {word}".strip() if current else word  # the widened candidate
            if len(candidate) <= width:  # evaluates the branch condition
                current = candidate  # the word fits on this line
            else:  # covers the remaining branch
                lines.append(current)  # flushes the assembled line
                current = word  # the word opens the next line
        if current:  # evaluates the branch condition
            lines.append(current)  # flushes the tail line
    return lines or [""]  # returns the wrapped lines



def _fit(value: Any, limit: int) -> str:  # defines the _fit() function
    """Shared fixed-limit clip with the ASCII "..." marker (see :mod:`textutil`)."""  # keeps the docstring text
    return textutil.clip_raw(value, limit, "...")  # returns the clipped value


def _paeth(a: int, b: int, c: int) -> int:  # defines the _paeth() function
    p = a + b - c  # copies the a value into p
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)  # runs the abs() call
    if pa <= pb and pa <= pc:  # evaluates the branch condition
        return a  # returns the a to the caller
    if pb <= pc:  # evaluates the branch condition
        return b  # returns the b to the caller
    return c  # returns the c to the caller


def _unfilter_png(raw: bytes, width: int, height: int, bpp: int) -> bytes:  # defines the _unfilter_png() function
    """Reverse PNG's per-scanline filters for one non-interlaced image."""  # keeps the docstring text
    stride = width * bpp  # copies the width value into stride
    stride_with_filter = stride + 1  # copies the stride value into stride_with_filter
    if len(raw) != stride_with_filter * height:  # evaluates the branch condition
        raise ValueError("unexpected PNG raw-data size")  # raises the ValueError error
    out = bytearray(stride * height)  # runs the bytearray() call
    prev_start = -1  # assigns the computed value to prev_start
    for y in range(height):  # loops over the collection
        src = y * stride_with_filter  # copies the y value into src
        filter_byte = raw[src]  # copies the raw value into filter_byte
        line = bytearray(raw[src + 1:src + 1 + stride])  # runs the bytearray() call
        if filter_byte == 1:  # sub  # evaluates the branch condition
            for i in range(bpp, stride):  # loops over the collection
                line[i] = (line[i] + line[i - bpp]) & 0xFF  # assigns the computed value to line[i]
        elif filter_byte == 2:  # up  # checks the alternate condition
            if prev_start >= 0:  # evaluates the branch condition
                for i in range(stride):  # loops over the collection
                    line[i] = (line[i] + out[prev_start + i]) & 0xFF  # assigns the computed value to line[i]
        elif filter_byte == 3:  # average  # checks the alternate condition
            for i in range(stride):  # loops over the collection
                left = line[i - bpp] if i >= bpp else 0  # copies the line value into left
                above = out[prev_start + i] if prev_start >= 0 else 0  # copies the out value into above
                line[i] = (line[i] + (left + above) // 2) & 0xFF  # assigns the computed value to line[i]
        elif filter_byte == 4:  # paeth  # checks the alternate condition
            for i in range(stride):  # loops over the collection
                left = line[i - bpp] if i >= bpp else 0  # copies the line value into left
                above = out[prev_start + i] if prev_start >= 0 else 0  # copies the out value into above
                upper_left = out[prev_start + i - bpp] if (prev_start >= 0 and i >= bpp) else 0  # copies the out value into upper_left
                line[i] = (line[i] + _paeth(left, above, upper_left)) & 0xFF  # runs the _paeth() call
        elif filter_byte != 0:  # checks the alternate condition
            raise ValueError(f"unknown PNG filter {filter_byte}")  # raises the ValueError error
        out[y * stride:(y + 1) * stride] = line  # evaluates the out expression
        prev_start = y * stride  # copies the y value into prev_start
    return bytes(out)  # returns the bytes to the caller


def _load_png_rgb(path: Path, downsample: int = 1) -> tuple[int, int, bytes] | None:  # defines the _load_png_rgb() function
    """Decode a truecolour PNG into RGB pixels, shrinking each axis.

    Returns ``(width, height, rgb bytes)`` or ``None`` for unsupported/missing
    files so callers can fall back gracefully. Supports bit depth 8, colour
    types 2 (RGB) and 6 (RGBA flattened onto white), no interlace - which covers
    the shipped branding graphics.
    """
    try:  # watches for errors in the block
        data = Path(path).read_bytes()  # creates the path object
    except OSError:  # handles the raised error
        return None  # returns nothing to the caller
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):  # evaluates the branch condition
        return None  # returns nothing to the caller

    width = height = depth = colour_type = interlace = 0  # copies the height value into width
    idat = bytearray()  # runs the bytearray() call
    pos = 8  # assigns the computed value to pos
    while pos + 8 <= len(data):  # loops while the condition holds
        length, ctype = struct.unpack(">I4s", data[pos:pos + 8])  # runs the unpack() call
        chunk = data[pos + 8:pos + 8 + length]  # copies the data value into chunk
        if ctype == b"IHDR":  # evaluates the branch condition
            width, height, depth, colour_type, _comp, _filt, interlace = struct.unpack(  # runs the unpack() call
                ">IIBBBBB", chunk[:13]  # maps the >IIBBBBB dictionary entry
            )  # closes the multiline block
        elif ctype == b"IDAT":  # checks the alternate condition
            idat.extend(chunk)  # adds several items to the list
        elif ctype == b"IEND":  # checks the alternate condition
            break  # exits the loop early
        pos += 12 + length  # evaluates the pos expression

    if not width or not height or depth != 8 or interlace:  # evaluates the branch condition
        return None  # returns nothing to the caller
    if colour_type == 2:  # evaluates the branch condition
        channels, has_alpha = 3, False  # assigns the computed value to channels, has_alpha
    elif colour_type == 6:  # checks the alternate condition
        channels, has_alpha = 4, True  # assigns the computed value to channels, has_alpha
    else:  # covers the remaining branch
        return None  # returns nothing to the caller

    try:  # watches for errors in the block
        raw = zlib.decompress(bytes(idat))  # runs the decompress() call
        pixels = _unfilter_png(raw, width, height, channels)  # runs the _unfilter_png() call
    except (ValueError, zlib.error):  # handles the raised error
        return None  # returns nothing to the caller

    step = max(1, int(downsample))  # takes the largest value
    out_width = max(1, width // step)  # takes the largest value
    out_height = max(1, height // step)  # takes the largest value
    rows: list[bytes] = []  # evaluates the rows expression
    for out_y in range(out_height):  # loops over the collection
        start_row = out_y * step  # copies the out_y value into start_row
        row = bytearray(out_width * 3)  # runs the bytearray() call
        for out_x in range(out_width):  # loops over the collection
            # Average a step x step block of source pixels.
            total = [0, 0, 0]  # assigns the computed value to total
            used = 0  # assigns the computed value to used
            for dy in range(step):  # loops over the collection
                src_y = start_row + dy  # copies the start_row value into src_y
                if src_y >= height:  # evaluates the branch condition
                    break  # exits the loop early
                for dx in range(step):  # loops over the collection
                    src_x = out_x * step + dx  # copies the out_x value into src_x
                    if src_x >= width:  # evaluates the branch condition
                        break  # exits the loop early
                    offset = (src_y * width + src_x) * channels  # assigns the computed value to offset
                    r, g, b, a = pixels[offset], pixels[offset + 1], pixels[offset + 2], (  # copies the pixels value into r, g, b, a
                        pixels[offset + 3] if has_alpha else 255  # evaluates the pixels expression
                    )  # closes the multiline block
                    if has_alpha and a < 255:  # evaluates the branch condition
                        # Flatten onto the (white) PDF page.
                        alpha = a / 255.0  # copies the a value into alpha
                        r = int(r * alpha + 255 * (1 - alpha))  # runs the int() call
                        g = int(g * alpha + 255 * (1 - alpha))  # runs the int() call
                        b = int(b * alpha + 255 * (1 - alpha))  # runs the int() call
                    total[0] += r  # evaluates the total expression
                    total[1] += g  # evaluates the total expression
                    total[2] += b  # evaluates the total expression
                    used += 1  # evaluates the used expression
            if used:  # evaluates the branch condition
                base = out_x * 3  # copies the out_x value into base
                row[base] = total[0] // used  # copies the total value into row[base]
                row[base + 1] = total[1] // used  # evaluates the row expression
                row[base + 2] = total[2] // used  # evaluates the row expression
        rows.append(bytes(row))  # adds an item to the list
    return out_width, out_height, b"".join(rows)  # returns the out_width to the caller


_BRANDING_CACHE: dict[tuple[str, int], tuple[int, int, bytes] | None] = {}  # the static-asset cache (path, downsample)


def _load_branding(path: Path, downsample: int = 1) -> tuple[int, int, bytes] | None:  # defines the _load_branding() function
    """Decode-and-downsample the branding PNG, cached per (path, scale).

    The wordmark is a shipped static asset, so its decoded pixels never
    change between exports; the first PDF gets the full decode, later ones
    reuse the cached tuple (including a cached ``None`` for a missing or
    unsupported file, so the text fallback stays equally cheap).
    """
    key = (str(path), int(downsample))  # the cache identity
    if key not in _BRANDING_CACHE:  # evaluates the branch condition
        _BRANDING_CACHE[key] = _load_png_rgb(path, downsample)  # decodes once
    return _BRANDING_CACHE[key]  # returns the cached pixel tuple


class _PdfBuilder:  # defines the _PdfBuilder class
    """Accumulate page content, then serialise a small valid PDF."""  # keeps the docstring text

    def __init__(self, title: str) -> None:  # defines the __init__() function
        self.title = title  # saves the result on title
        self.pages: list[list[str]] = []  # evaluates the self.pages expression
        self.images: list[tuple[int, int, bytes]] = []  # evaluates the self.images expression
        self.y = 0.0  # saves the result on y
        self._new_page(first=True)  # runs the _new_page() call

    # -- layout ---------------------------------------------------------
    def _new_page(self, *, first: bool = False) -> None:  # defines the _new_page() function
        self.pages.append([])  # adds an item to the list
        self.y = PAGE_HEIGHT - MARGIN  # saves the result on y
        if not first:  # evaluates the branch condition
            self._raw_text(  # runs the _raw_text() call
                MARGIN,  # evaluates the MARGIN expression
                PAGE_HEIGHT - MARGIN + 10,  # evaluates the PAGE_HEIGHT expression
                f"{_fit(self.title, 82)}  (continued)",  # supplies the literal text
                FONT_REGULAR,  # evaluates the FONT_REGULAR expression
                7.5,  # executes the statement
                MUTED,  # evaluates the MUTED expression
            )  # closes the multiline block
            self.y -= 8  # updates the stored value in place

    def _space(self, height: float) -> None:  # defines the _space() function
        if self.y - height < BOTTOM:  # evaluates the branch condition
            self._new_page()  # runs the _new_page() call

    def _raw_text(  # defines the _raw_text() function
        self,  # evaluates the self expression
        x: float,  # evaluates the x expression
        y: float,  # evaluates the y expression
        text: str,  # evaluates the text expression
        font: str,  # evaluates the font expression
        size: float,  # evaluates the size expression
        colour: tuple[float, float, float],  # evaluates the colour expression
    ) -> None:  # closes the multiline block
        r, g, b = colour  # copies the colour value into r, g, b
        self.pages[-1].append(  # adds an item to the list
            f"BT {r:.3f} {g:.3f} {b:.3f} rg /{font} {size:.2f} Tf "  # maps the BT {r:.3f} {g:.3f} {b:.3 dictionary entry
            f"1 0 0 1 {x:.2f} {y:.2f} Tm ({_pdf_text(text)}) Tj ET"  # maps the 1 0 0 1 {x:.2f} {y:.2f}  dictionary entry
        )  # closes the multiline block

    def text(  # defines the text() function
        self,  # evaluates the self expression
        value: Any,  # evaluates the value expression
        *,  # spreads the collected values
        font: str = FONT_REGULAR,  # evaluates the font expression
        size: float = 9.0,  # evaluates the size expression
        indent: float = 0.0,  # evaluates the indent expression
        leading: float | None = None,  # evaluates the leading expression
        colour: tuple[float, float, float] = INK,  # evaluates the colour expression
        width: int | None = None,  # evaluates the width expression
        gap: float = 0.0,  # evaluates the gap expression
    ) -> None:  # closes the multiline block
        text = str(value or "")  # runs the str() call
        lines = textwrap.wrap(text, width=width) if width else text.splitlines()  # runs the wrap() call
        if not lines:  # evaluates the branch condition
            lines = [""]  # assigns the computed value to lines
        leading = leading or size * 1.32  # copies the leading value into leading
        if gap:  # evaluates the branch condition
            self.y -= gap  # updates the stored value in place
        for line in lines:  # loops over the collection
            self._space(leading)  # runs the _space() call
            self.y -= leading  # updates the stored value in place
            self._raw_text(MARGIN + indent, self.y, line, font, size, colour)  # runs the _raw_text() call
        self._space(leading)  # runs the _space() call

    def section(self, title: str) -> None:  # defines the section() function
        self.y -= 10  # updates the stored value in place
        self._space(24)  # runs the _space() call
        self.y -= 14  # updates the stored value in place
        self._raw_text(MARGIN, self.y, title, FONT_BOLD, 11.5, ACCENT)  # runs the _raw_text() call
        self.pages[-1].append(  # adds an item to the list
            f"0.60 w {RULE[0]:.3f} {RULE[1]:.3f} {RULE[2]:.3f} RG "  # maps the 0.60 w {RULE[0]:.3f} {RU dictionary entry
            f"{MARGIN:.2f} {self.y - 4:.2f} m {PAGE_WIDTH - MARGIN:.2f} {self.y - 4:.2f} l S"  # maps the {MARGIN:.2f} {self.y - 4 dictionary entry
        )  # closes the multiline block
        self.y -= 10  # updates the stored value in place

    def _row_dividers(  # defines the _row_dividers() function
        self,  # evaluates the self expression
        xs: list[float],  # the one x per column gap
        leading: float,  # the row height the segments tile against
    ) -> None:  # closes the multiline block
        """One light vertical rule per column gap, tiling row to row.

        Each segment covers half a row above and half a row below the
        baseline, so boxes drawn for consecutive rows join into a
        continuous column line the reader can trace down the table.
        """  # keeps the docstring text
        if not xs:  # evaluates the branch condition
            return  # returns nothing to the caller
        top = self.y + leading / 2  # a half row up meets the line above
        bottom = self.y - leading / 2  # a half row down meets the line below
        for x in xs:  # loops over the collection
            self.pages[-1].append(  # adds an item to the list
                f"0.50 w {RULE[0]:.3f} {RULE[1]:.3f} {RULE[2]:.3f} RG "  # maps the 0.50 w {RULE[0]:.3 dictionary entry
                f"{x:.2f} {bottom:.2f} m {x:.2f} {top:.2f} l S"  # strokes one vertical rule
            )  # closes the multiline block

    def verification_page(self, digest_text: str) -> None:  # defines the verification_page() function
        """Appends the tamper-evidence page: the digest of the whole document.

        The 64 digest digits printed here read as zeros during hashing, so a
        receiver can re-stamp the zeros and re-compute the fingerprint to
        prove nothing between page one and this one was altered.
        """  # keeps the docstring text
        self._new_page()  # a fresh sheet carries the fingerprint
        self.section("INTEGRITY VERIFICATION")  # the section banner
        self.text(  # runs the text() call
            f"SHA-256: {digest_text}",  # the fingerprint, reserved or stamped
            font=FONT_MONO,  # digits draw in a fixed-width face
            size=9.0,  # the digest line reads clearly
            leading=13,  # assigns the computed value to leading
        )  # closes the multiline block
        self.y -= 4  # a breath before the explanatory copy
        self.text(  # runs the text() call
            "This fingerprint covers every byte of this document: each page, "
            "table, chart and image. If a single byte changes after printing, "
            "re-computing the fingerprint yields a different value.",
            size=8.4,  # the plain-language explanation
            width=104,  # the wrap window the page allows
            leading=11,  # assigns the computed value to leading
        )  # closes the multiline block
        self.text(  # runs the text() call
            "To re-check it: replace the 64 hex digits above with zeros, "
            "hash the whole file with SHA-256, and the result must equal the "
            "digits printed on this line.",
            size=8.4,  # the receiver's recipe
            colour=INK,  # the instruction reads at full ink
            width=104,  # the wrap window the page allows
            leading=11,  # assigns the computed value to leading
        )  # closes the multiline block
        self.text(  # runs the text() call
            f"Stamped by {config.APP_NAME} {config.APP_VERSION} at print time. "
            "A digest proves the file is unchanged, but not by itself who "
            "printed it: file the digest somewhere independent (ticket, e-mail) "
            "to bind the printout to its printer.",
            size=7.6,  # the honest small print
            colour=MUTED,  # the muted provenance note
            width=104,  # the wrap window the page allows
            leading=10,  # assigns the computed value to leading
        )  # closes the multiline block

    def rule(self) -> None:  # defines the rule() function
        self._space(8)  # runs the _space() call
        self.pages[-1].append(  # adds an item to the list
            f"0.50 w {RULE[0]:.3f} {RULE[1]:.3f} {RULE[2]:.3f} RG "  # maps the 0.50 w {RULE[0]:.3f} {RU dictionary entry
            f"{MARGIN:.2f} {self.y - 2:.2f} m {PAGE_WIDTH - MARGIN:.2f} {self.y - 2:.2f} l S"  # maps the {MARGIN:.2f} {self.y - 2 dictionary entry
        )  # closes the multiline block
        self.y -= 8  # updates the stored value in place

    def columns(  # defines the columns() function
        self,  # evaluates the self expression
        values: Iterable[Any],  # evaluates the values expression
        widths: Iterable[int],  # evaluates the widths expression
        *,  # spreads the collected values
        font: str = FONT_MONO,  # evaluates the font expression
        size: float = 8.2,  # evaluates the size expression
        colour: tuple[float, float, float] = INK,  # evaluates the colour expression
    ) -> None:  # closes the multiline block
        """Draw fixed-width columns; widths are character counts for Courier."""  # keeps the docstring text
        char_width = size * 0.60  # copies the size value into char_width
        leading = size * 1.4  # copies the size value into leading
        self._space(leading)  # runs the _space() call
        self.y -= leading  # updates the stored value in place
        values = list(values)  # the divider pass needs a second sweep
        widths = list(widths)  # the divider pass needs a second sweep
        x = MARGIN  # copies the MARGIN value into x
        dividers: list[float] = []  # the row rail builds row by row
        for value, width in zip(values, widths):  # loops over the collection
            self._raw_text(x, self.y, _fit(value, width), font, size, colour)  # runs the _raw_text() call
            dividers.append(x + width * char_width + 2.5)  # half-way through the 5pt gap
            x += width * char_width + 5  # evaluates the x expression
        self._row_dividers(dividers[:-1], leading)  # lines between columns, none after the last
        self._space(leading)  # runs the _space() call

    def mono_row(  # defines the mono_row() function
        self,  # evaluates the self expression
        label: str,  # evaluates the label expression
        value: str,  # evaluates the value expression
        *,  # spreads the collected values
        label_chars: int = 22,  # evaluates the label_chars expression
        value_chars: int = 84,  # evaluates the value_chars expression
        size: float = 7.9,  # evaluates the size expression
        leading: float = 10.5,  # evaluates the leading expression
    ) -> None:  # closes the multiline block
        """Fixed-width row: label in column one, wrapped value text after it.

        Continuation lines stay aligned under the value column, so a long
        "Care and Feeding" line can never run off the right edge of the page.
        """
        chunks = textwrap.wrap(str(value), width=value_chars) or [""]  # runs the wrap() call
        indent_points = label_chars * size * 0.60  # copies the label_chars value into indent_points
        for index, chunk in enumerate(chunks):  # loops over the collection
            self._space(leading)  # runs the _space() call
            self.y -= leading  # updates the stored value in place
            self._row_dividers([MARGIN + indent_points - 2.5], leading)  # the label/value rail
            if index == 0:  # evaluates the branch condition
                self._raw_text(MARGIN, self.y, _fit(label, label_chars), FONT_MONO, size, MUTED)  # runs the _raw_text() call
            self._raw_text(MARGIN + indent_points, self.y, chunk, FONT_MONO, size, INK)  # runs the _raw_text() call
        self._space(leading)  # runs the _space() call

    def rect(self, x: float, y: float, w: float, h: float, colour: tuple[float, float, float]) -> None:
        """Fill a rectangle (used for the dashboard bars and heat grid)."""
        self._space(h + 4)
        r, g, b = colour
        self.pages[-1].append(
            f"{r:.3f} {g:.3f} {b:.3f} rg {x:.2f} {y:.2f} {w:.2f} {h:.2f} re f"
        )

    def rect_at(self, x: float, y: float, w: float, h: float, colour: tuple[float, float, float]) -> None:
        """Fill a rectangle without touching the text cursor."""  # keeps the docstring text
        if w <= 0 or h <= 0:  # evaluates the branch condition
            return  # returns nothing to the caller
        r, g, b = colour  # supplies the colour channels
        self.pages[-1].append(  # adds an item to the list
            f"{r:.3f} {g:.3f} {b:.3f} rg {x:.2f} {y:.2f} {w:.2f} {h:.2f} re f"  # fills the rectangle
        )  # closes the multiline block

    def number_card(self, value: Any, caption: str, colour: tuple[float, float, float], *, size: float = 22.0) -> None:
        """Big dashboard figure with its caption underneath."""  # keeps the docstring text
        self._space(size + 16)  # runs the _space() call
        self.y -= size  # moves the cursor down
        self._raw_text(MARGIN, self.y, str(value), FONT_BOLD, size, colour)  # draws the big figure
        self.y -= 11  # moves the cursor down
        if caption:  # evaluates the branch condition
            self._raw_text(MARGIN + 2, self.y + 4, _pdf_text(caption), FONT_REGULAR, 8.2, MUTED)  # draws the caption
        self.y -= 6  # moves the cursor down

    def hbar(self, label: str, value: float, max_value: float, colour: tuple[float, float, float], *, size: float = 7.9, label_chars: int = 30) -> None:
        """One labelled horizontal bar of the PDF bar charts."""  # keeps the docstring text
        leading = size * 1.5  # computes the bar spacing
        self._space(leading + 4)  # runs the _space() call
        self.y -= leading  # moves the cursor down
        self._raw_text(MARGIN, self.y, _fit(label, label_chars), FONT_MONO, size, INK)  # draws the bar label
        track_x = MARGIN + label_chars * size * 0.60 + 6  # computes the track start
        track_w = PAGE_WIDTH - MARGIN - track_x - 30  # computes the track width
        fraction = max(0.0, min(1.0, (float(value) / max_value) if max_value else 0.0))  # computes the fraction
        baseline = self.y - size + 1.5  # computes the bar baseline
        self.rect_at(track_x, baseline, track_w, size - 1, TRACK_GREY)  # shades the empty track
        self.rect_at(track_x, baseline, track_w * fraction, size - 1, colour)  # fills the bar
        self._raw_text(PAGE_WIDTH - MARGIN - 26, self.y, str(value), FONT_MONO, size, INK)  # draws the value
        self._space(2)  # runs the _space() call

    def donut_track(self, rows, *, size: float = 12.0, legend: str = "") -> None:
        """One segmented share bar with a small legend underneath."""  # keeps the docstring text
        total = sum(float(value) for _l, value, _c in rows or []) or 1  # adds up the shares
        self._space(size + 16)  # runs the _space() call
        self.y -= size  # moves the cursor down
        baseline = self.y - size + 2  # computes the bar baseline
        track_w = PAGE_WIDTH - 2 * MARGIN  # computes the track width
        # The background is painted first and the slices once on top: the old
        # paint/overpaint/repaint order drew everything three times for the
        # same pixels.
        self.rect_at(MARGIN, baseline, track_w, size, (0.97, 0.97, 0.97))  # shades the background
        x = MARGIN  # starts at the left margin
        for label, value, colour in rows or []:  # loops over the collection
            width = track_w * (float(value) / total)  # computes the slice width
            self.rect_at(x, baseline, width - 1.5, size, _pdf_colour(colour))  # fills the slice
            x += width  # advances the cursor
        self.y -= 10  # moves the cursor down
        if legend:  # evaluates the branch condition
            self._raw_text(MARGIN, self.y, _pdf_text(legend), FONT_REGULAR, 7.6, MUTED)  # draws the legend
        self._space(4)  # runs the _space() call

    def heat_grid(self, rows, sevs, max_count: int, *, size: float = 7.4) -> None:
        """File x severity heat map: shaded cells with the counts inside."""  # keeps the docstring text
        label_width = 240.0  # sets the label column width
        leading = size * 1.6  # computes the row spacing
        cell_w = min(46.0, (PAGE_WIDTH - 2 * MARGIN - label_width) / max(1, len(sevs)))  # computes the cell width
        self._space(leading * (len(rows) + 2) + 8)  # reserves the grid space
        self.y -= leading  # moves the cursor down
        x0 = MARGIN + label_width  # computes the grid start
        for index, sev in enumerate(sevs):  # loops over the collection
            self._raw_text(x0 + index * cell_w, self.y, sev[:1].upper(), FONT_MONO, size, MUTED)  # draws the column letter
        for file_id, buckets in rows or []:  # loops over the collection
            self._space(leading)  # runs the _space() call
            self.y -= leading  # moves the cursor down
            self._raw_text(MARGIN, self.y, _fit(file_id, 38), FONT_MONO, size, INK)  # draws the file name
            baseline = self.y - size + 1  # computes the row baseline
            for index, sev in enumerate(sevs):  # loops over the collection
                count = int(buckets.get(sev, 0) or 0)  # fetches the value
                if count:  # evaluates the branch condition
                    intensity = 0.35 + 0.65 * min(1.0, count / max(max_count, 1))  # computes the shading
                    self.rect_at(  # shades the cell
                        x0 + index * cell_w, baseline, cell_w - 2, leading - 3,
                        _mix_white(_pdf_colour(_SEV_FILL[sev]), 1 - intensity),
                    )  # shades the cell
                    count_colour = (1.0, 1.0, 1.0)  # sets the count text to white
                else:  # covers the remaining branch
                    count_colour = MUTED  # keeps the empty cells muted
                self._raw_text(x0 + index * cell_w + cell_w / 2 - 2, self.y, str(count) if count else "", FONT_MONO, size, count_colour)  # draws the count
        self._space(4)  # runs the _space() call

    def score_box(self, score: int, verdict: str, band: str) -> None:  # defines the score_box() function
        height = 58.0  # assigns the computed value to height
        self._space(height + 12)  # runs the _space() call
        colour = OK if verdict == "SECURE" else DANGER  # copies the OK value into colour
        x, y = MARGIN, self.y - height  # copies the MARGIN value into x, y
        self.pages[-1].append(  # adds an item to the list
            f"{colour[0]:.3f} {colour[1]:.3f} {colour[2]:.3f} rg "  # maps the {colour[0]:.3f} {colour[ dictionary entry
            f"{x:.2f} {y:.2f} {PAGE_WIDTH - 2 * MARGIN:.2f} {height:.2f} re f"  # maps the {x:.2f} {y:.2f} {PAGE_WI dictionary entry
        )  # closes the multiline block
        self._raw_text(x + 14, y + 20, f"{score} / 100", FONT_BOLD, 22, (1, 1, 1))  # runs the _raw_text() call
        self._raw_text(x + 170, y + 25, f"{verdict}  -  {band}", FONT_BOLD, 12, (1, 1, 1))  # runs the _raw_text() call
        self._raw_text(  # runs the _raw_text() call
            x + 170,  # evaluates the x expression
            y + 10,  # evaluates the y expression
            f"Pass mark {config.SECURE_MIN_SCORE}/100 with zero critical findings",  # supplies the literal text
            FONT_REGULAR,  # evaluates the FONT_REGULAR expression
            8,  # executes the statement
            (1, 1, 1),  # executes the statement
        )  # closes the multiline block
        self.y = y - 14  # saves the result on y

    # -- images ----------------------------------------------------------
    def register_image(self, pixel_data: tuple[int, int, bytes]) -> str:  # defines the register_image() function
        """Queue an (width, height, RGB) image; returns its resource name."""  # keeps the docstring text
        name = f"Im{len(self.images) + 1}"  # counts the items
        self.images.append(pixel_data)  # adds an item to the list
        return name  # returns the name to the caller

    def draw_image(self, name: str, width: float, height: float) -> None:  # defines the draw_image() function
        """Draw a registered image at the left margin, advancing the cursor."""  # keeps the docstring text
        self._space(height)  # runs the _space() call
        y = self.y - height  # copies the self.y value into y
        self.pages[-1].append(  # adds an item to the list
            f"q {width:.2f} 0 0 {height:.2f} {MARGIN:.2f} {y:.2f} cm /{name} Do Q"  # maps the q {width:.2f} 0 0 {heigh dictionary entry
        )  # closes the multiline block
        self.y = y  # saves the result on y

    # -- serialisation --------------------------------------------------
    def _footer_ops(self, page: int, total: int) -> list[str]:  # defines the _footer_ops() function
        label = f"{config.APP_NAME}  -  page {page} of {total}"  # sets the label text
        x = PAGE_WIDTH - MARGIN - len(label) * 4.2  # counts the items
        return [  # returns the value to the caller
            f"0.50 w {RULE[0]:.3f} {RULE[1]:.3f} {RULE[2]:.3f} RG "  # maps the 0.50 w {RULE[0]:.3f} {RU dictionary entry
            f"{MARGIN:.2f} {BOTTOM - 12:.2f} m {PAGE_WIDTH - MARGIN:.2f} {BOTTOM - 12:.2f} l S",  # maps the {MARGIN:.2f} {BOTTOM - 1 dictionary entry
            f"BT {MUTED[0]:.3f} {MUTED[1]:.3f} {MUTED[2]:.3f} rg /{FONT_REGULAR} 7 Tf "  # maps the BT {MUTED[0]:.3f} {MUTED dictionary entry
            f"1 0 0 1 {x:.2f} 30 Tm ({_pdf_text(label)}) Tj ET",  # maps the 1 0 0 1 {x:.2f} 30 Tm ({ dictionary entry
        ]  # closes the multiline block

    def wrapped_columns(  # defines the wrapped_columns() function
        self,  # evaluates the self expression
        values: Iterable[Any],  # evaluates the values expression
        widths: Iterable[int],  # evaluates the widths expression
        *,  # spreads the collected values
        font: str = FONT_MONO,  # evaluates the font expression
        size: float = 8.2,  # evaluates the size expression
        colour: tuple[float, float, float] = INK,  # evaluates the colour expression
    ) -> None:
        """Draw fixed-width columns where every cell wraps instead of cutting.

        Each cell is word-wrapped to its column width, then the resulting
        line matrix is emitted one physical line at a time (page breaks
        handled by the usual ``_space`` inside :meth:`columns`), so long
        component names and PURLs stay fully readable.
        """
        widths = list(widths)  # materialises the widths
        cells = [  # wraps every cell to its width
            _wrap_chars(value, width)  # runs the _wrap_chars() call
            for value, width in zip(values, widths)  # pairs the cells
        ]  # closes the cells build
        height = max(len(cell) for cell in cells)  # the tallest column decides the rows
        for line_index in range(height):  # emits one matrix line per wrapped row
            line_values = [  # the slice each column shows on this line
                cell[line_index] if line_index < len(cell) else ""  # shorter columns pad blank
                for cell in cells  # loops over the cells
            ]  # closes the line build
            self.columns(line_values, widths, font=font, size=size, colour=colour)  # draws the line

    def build(self) -> bytes:  # defines the build() function
        total = len(self.pages)  # counts the items
        objects: list[bytes] = []  # evaluates the objects expression

        def add(payload: bytes) -> int:  # defines the add() function
            objects.append(payload)  # adds an item to the list
            return len(objects)  # returns the len to the caller

        catalog_id = add(b"")  # filled in below  # adds an item to the set
        pages_id = add(b"")  # adds an item to the set
        font_ids = {  # assigns the computed value to font_ids
            FONT_REGULAR: add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"),  # adds an item to the set
            FONT_BOLD: add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"),  # adds an item to the set
            FONT_MONO: add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>"),  # adds an item to the set
            FONT_MONO_BOLD: add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold >>"),  # adds an item to the set
        }  # closes the multiline block
        font_map = " ".join(f"/{name} {fid} 0 R" for name, fid in font_ids.items())  # sets the font_map text

        # Flate-encoded RGB image XObjects (e.g. the branding wordmark).
        xobject_map = ""  # sets the xobject_map text
        image_ids: dict[str, int] = {}  # evaluates the image_ids expression
        for index, (width, height, pixels) in enumerate(self.images, 1):  # loops over the collection
            name = f"Im{index}"  # sets the name text
            stream = zlib.compress(pixels, 6)  # runs the compress() call
            image_ids[name] = add(  # adds an item to the set
                (  # executes the statement
                    f"<< /Type /XObject /Subtype /Image /Width {width} /Height {height} "  # supplies the literal text
                    f"/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode "  # supplies the literal text
                    f"/Length {len(stream)} >>\nstream\n"  # supplies the literal text
                ).encode("ascii")  # closes the multiline block
                + stream  # executes the statement
                + b"\nendstream"  # executes the statement
            )  # closes the multiline block
        if image_ids:  # evaluates the branch condition
            refs = " ".join(f"/{name} {fid} 0 R" for name, fid in image_ids.items())  # sets the refs text
            xobject_map = f"/XObject << {refs} >>"  # sets the xobject_map text

        page_ids: list[int] = []  # evaluates the page_ids expression
        for index, ops in enumerate(self.pages, 1):  # loops over the collection
            stream = "\n".join([*ops, *self._footer_ops(index, total)]).encode("ascii")  # sets the stream text
            content_id = add(  # adds an item to the set
                f"<< /Length {len(stream)} >>\nstream\n".encode("ascii")  # supplies the literal text
                + stream  # executes the statement
                + b"\nendstream"  # executes the statement
            )  # closes the multiline block
            page_id = add(  # adds an item to the set
                (  # executes the statement
                    f"<< /Type /Page /Parent {pages_id} 0 R "  # supplies the literal text
                    f"/MediaBox [0 0 {PAGE_WIDTH:.2f} {PAGE_HEIGHT:.2f}] "  # maps the /MediaBox [0 0 {PAGE_WID dictionary entry
                    f"/Resources << /Font << {font_map} >> {xobject_map} >> "  # supplies the literal text
                    f"/Contents {content_id} 0 R >>"  # supplies the literal text
                ).encode("ascii")  # closes the multiline block
            )  # closes the multiline block
            page_ids.append(page_id)  # adds an item to the list

        objects[catalog_id - 1] = (  # evaluates the objects expression
            f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("ascii")  # supplies the literal text
        )  # closes the multiline block
        kids = " ".join(f"{pid} 0 R" for pid in page_ids)  # sets the kids text
        objects[pages_id - 1] = (  # evaluates the objects expression
            f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("ascii")  # supplies the literal text
        )  # closes the multiline block

        buffer = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")  # runs the bytearray() call
        offsets = [0]  # assigns the computed value to offsets
        for number, payload in enumerate(objects, 1):  # loops over the collection
            offsets.append(len(buffer))  # adds an item to the list
            buffer += f"{number} 0 obj\n".encode("ascii")  # runs the encode() call
            buffer += payload  # evaluates the buffer expression
            buffer += b"\nendobj\n"  # evaluates the buffer expression

        xref_at = len(buffer)  # counts the items
        buffer += f"xref\n0 {len(objects) + 1}\n".encode("ascii")  # runs the len() call
        buffer += b"0000000000 65535 f \n"  # evaluates the buffer expression
        for offset in offsets[1:]:  # loops over the collection
            buffer += f"{offset:010d} 00000 n \n".encode("ascii")  # runs the encode() call
        buffer += (  # evaluates the buffer expression
            f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R "  # supplies the literal text
            f"/Info << /Title ({_pdf_text(self.title)}) /Producer ({_pdf_text(config.APP_NAME)} {config.APP_VERSION}) >> >>\n"  # supplies the literal text
            f"startxref\n{xref_at}\n%%EOF\n"  # supplies the literal text
        ).encode("ascii")  # closes the multiline block
        return bytes(buffer)  # returns the bytes to the caller


def _repo_name(report: dict[str, Any]) -> str:  # defines the _repo_name() function
    repo = report.get("repo") or {}  # fetches the value
    return repo.get("full_name") or repo.get("input_url") or "repository"  # returns the repo.get to the caller


def _stamp_digest(pdf: _PdfBuilder) -> bytes:  # defines the _stamp_digest() function
    """Serialise the document, fingerprint it, then write the fingerprint in.

    The digest is computed over the exact bytes being handed to the reader,
    with the 64 digits of its own verification line still all zeros - so
    zeroing the printed digits reproduces exactly the hashed bytes.
    """  # keeps the docstring text
    pdf.verification_page(DIGEST_PLACEHOLDER)  # the slot is reserved first
    raw = pdf.build()  # the document bytes with zeros in the slot
    if raw.count(DIGEST_PLACEHOLDER.encode("ascii")) != 1:  # evaluates the branch condition
        raise ValueError("digest slot is not unique - refusing to stamp the PDF")  # the honest guard
    digest = hashlib.sha256(raw).hexdigest()  # the fingerprint of the zeroed document
    return raw.replace(  # the same length swap keeps every byte offset intact
        DIGEST_PLACEHOLDER.encode("ascii"), digest.encode("ascii"), 1  # one slot, one stamp
    )  # returns the stamped bytes


def verify_pdf(path: str | Path) -> tuple[bool, str]:  # defines the verify_pdf() function
    """Re-check a stamped PDF: zero every 64-hex run, re-hash, compare.

    Returns ``(True, digest)`` when the file matches its printed fingerprint
    and ``(False, reason)`` otherwise - never an exception for a bad file.
    """  # keeps the docstring text
    try:  # watches for a missing or unreadable file
        data = Path(path).read_bytes()  # the exact printed bytes
    except OSError as exc:  # handles the raised error
        return False, f"cannot read {path}: {exc}"  # the honest gap
    runs = regex.findall(  # assigns the computed value to runs
        rb"(?<![0-9a-fA-F])([0-9a-f]{64})(?![0-9a-fA-F])", data  # every printed 64-hex run
    )  # closes the findall call
    if not runs:  # evaluates the branch condition
        return False, "no digest line found - this PDF was not stamped"  # the unlackey case
    for candidate in runs:  # loops over the collection
        digit = candidate.decode("ascii")  # the printed fingerprint
        if digit == DIGEST_PLACEHOLDER:  # evaluates the branch condition
            continue  # a zeroed slot means the stamp never ran
        zeroed = data.replace(candidate, b"0" * 64, 1)  # the slot back to its hashing form
        if hashlib.sha256(zeroed).hexdigest() == digit:  # compares the hashes
            return True, digit  # the file is exactly as printed
    return False, "fingerprint does not match - this PDF has been modified"  # tampered or rebuilt


def write_report_pdf(report: dict[str, Any], path: str | Path) -> Path:  # defines the write_report_pdf() function
    """Render the human-readable report as a paginated A4 PDF."""  # keeps the docstring text
    path = Path(path)  # creates the path object
    path.parent.mkdir(parents=True, exist_ok=True)  # creates the folder
    name = _repo_name(report)  # runs the _repo_name() call
    pdf = _PdfBuilder(f"{name} - {config.APP_NAME}")  # runs the _PdfBuilder() call

    # ScanityCheck wordmark (white-background artwork, correct for a printed page).
    wordmark = _load_branding(  # the cached decode (static asset)
        Path(__file__).resolve().parent / config.BRANDING_WHITE, downsample=3  # runs the Path() call
    )  # closes the multiline block
    if wordmark:  # evaluates the branch condition
        pw, ph, pixels = wordmark  # copies the wordmark value into pw, ph, pixels
        pdf.register_image((pw, ph, pixels))  # runs the register_image() call
        draw_width = 150.0  # assigns the computed value to draw_width
        pdf.draw_image(f"Im{len(pdf.images)}", draw_width, draw_width * ph / pw)  # runs the draw_image() call
        pdf.y -= 10  # updates the stored value in place
    else:  # covers the remaining branch
        pdf.text(config.APP_NAME, font=FONT_BOLD, size=19, leading=24, colour=INK)  # runs the text() call
    pdf.text(config.APP_TAGLINE, size=8.5, colour=MUTED, leading=11)  # runs the text() call
    pdf.text(name, font=FONT_BOLD, size=13, leading=17, colour=ACCENT)  # runs the text() call
    repo = report.get("repo") or {}  # fetches the value
    if repo.get("description"):  # evaluates the branch condition
        pdf.text(repo["description"], size=8.5, width=96, colour=MUTED, leading=11)  # runs the text() call
    generated = str(report.get("generated_at") or "").replace("T", " ")  # runs the str() call
    pdf.text(  # runs the text() call
        f"Generated {generated}  -  app {report.get('app_version', config.APP_VERSION)}"  # fetches the value
        f"  -  scan took {report.get('duration_seconds', 0):.1f}s",  # fetches the value
        size=8,  # assigns the computed value to size
        colour=MUTED,  # copies the MUTED value into colour
        leading=10,  # assigns the computed value to leading
    )  # closes the multiline block
    pdf.y -= 6  # updates the stored value in place

    pdf.score_box(int(report.get("score") or 0), str(report.get("verdict") or ""), str(report.get("band") or ""))  # runs the score_box() call
    pdf.text(report.get("verdict_reason") or "", size=9, width=96, leading=12)  # runs the text() call

    confidence = report.get("confidence") or {}  # fetches the value
    if confidence:  # evaluates the branch condition
        pdf.section("CONFIDENCE IN THIS REPORT")  # runs the section() call
        pdf.text(  # runs the text() call
            f"{int(confidence.get('score', 0))}/100  -  {confidence.get('band', '')}",  # runs the int() call
            font=FONT_BOLD,  # copies the FONT_BOLD value into font
            size=10.5,  # assigns the computed value to size
            leading=13,  # assigns the computed value to leading
        )  # closes the multiline block
        pdf.columns(  # runs the columns() call
            ("Signal", "Weight", "Score", "Points"),  # executes the statement
            (34, 9, 8, 5),  # executes the statement
            font=FONT_MONO_BOLD,  # copies the FONT_MONO_BOLD value into font
            size=8.2,  # assigns the computed value to size
            colour=MUTED,  # copies the MUTED value into colour
        )  # closes the multiline block
        for factor in confidence.get("factors") or []:  # loops over the collection
            pdf.columns(  # runs the columns() call
                (  # executes the statement
                    factor.get("label", ""),  # fetches the value
                    factor.get("weight", 0),  # fetches the value
                    f"{factor.get('score', 0)}%",  # fetches the value
                    f"+{factor.get('contribution', 0):.1f}",  # fetches the value
                ),  # closes the multiline block
                (34, 9, 8, 5),  # executes the statement
                size=8.2,  # assigns the computed value to size
            )  # closes the multiline block
        for note in confidence.get("notes") or []:  # loops over the collection
            pdf.text(f"- {note}", size=8, colour=MUTED, leading=10, width=104)  # runs the text() call

    pdf.section("WHAT THE SCORE MEANS")  # runs the section() call
    pdf.text(report.get("explanation") or "", size=8.6, width=100, leading=11)  # runs the text() call

    pdf.section("WHERE THE POINTS WENT")  # runs the section() call
    pdf.columns(  # runs the columns() call
        ("Category", "Findings", "Penalty", "Cap"),  # executes the statement
        (34, 9, 8, 5),  # executes the statement
        font=FONT_MONO_BOLD,  # copies the FONT_MONO_BOLD value into font
        size=8.2,  # assigns the computed value to size
        colour=MUTED,  # copies the MUTED value into colour
    )  # closes the multiline block
    labels = scoring.CATEGORY_LABELS  # the public registry, not a report copy
    counts = report.get("counts") or {}  # fetches the value
    penalties = report.get("penalties") or {}  # fetches the value
    caps = report.get("caps") or {}  # fetches the value
    by_category = (report.get("totals") or {}).get("by_category") or {}  # the precomputed per-category counts
    for category in reportkeys.SCORING_CATEGORIES:  # loops over the collection
        count = by_category.get(category)  # reads the precomputed count
        if count is None:  # evaluates the branch condition
            count = sum((counts.get(category) or {}).values())  # the legacy re-sum fallback
        if category == "code-quality" and count == 0:  # evaluates the branch condition
            continue  # skips to the next loop iteration
        pdf.columns(  # runs the columns() call
            (labels.get(category, category), count, f"{penalties.get(category, 0):.1f}", f"{caps.get(category, 0):.0f}"),  # fetches the value
            (34, 9, 8, 5),  # executes the statement
            size=8.2,  # assigns the computed value to size
        )  # closes the multiline block
    totals = report.get("totals") or {}  # fetches the value
    pdf.rule()  # runs the rule() call
    pdf.columns(  # runs the columns() call
        ("TOTAL", totals.get("findings", 0), f"{sum(penalties.values()):.1f}", ""),  # fetches the value
        (34, 9, 8, 5),  # executes the statement
        font=FONT_MONO_BOLD,  # copies the FONT_MONO_BOLD value into font
        size=8.2,  # assigns the computed value to size
    )  # closes the multiline block

    dedupe = report.get("dedupe") or {}  # fetches the value
    if dedupe.get("raw", 0) > 0:  # evaluates the branch condition
        pdf.text(  # runs the text() call
            f"De-duplication: {dedupe.get('raw', 0)} raw findings from all tools collapsed into "  # fetches the value
            f"{dedupe.get('merged', 0)} unique issues ({dedupe.get('removed', 0)} duplicates "  # fetches the value
            f"removed; {dedupe.get('corroborated', 0)} corroborated by 2+ tools).",  # fetches the value
            size=8.4,  # assigns the computed value to size
            width=104,  # assigns the computed value to width
            leading=10.5,  # assigns the computed value to leading
        )  # closes the multiline block

    inventory = report.get("inventory")  # fetches the value
    if inventory:  # evaluates the branch condition
        pdf.section("SBOM INVENTORY (SYFT)")  # runs the section() call
        ecosystems = inventory.get("ecosystems") or {}  # fetches the value
        eco_text = ", ".join(f"{key} {value}" for key, value in ecosystems.items()) or "none"  # sets the eco_text text
        pdf.text(  # runs the text() call
            f"{inventory.get('components', 0)} components catalogued ({eco_text}). "  # fetches the value
            f"{inventory.get('unversioned', 0)} without a resolved version.",  # fetches the value
            size=8.6,  # assigns the computed value to size
            width=100,  # assigns the computed value to width
            leading=11,  # assigns the computed value to leading
        )  # closes the multiline block
        for component in (inventory.get("top_packages") or [])[:10]:  # loops over the collection
            version = component.get("version") or "?"  # fetches the value
            pdf.text(  # runs the text() call
                f"  {component.get('name') or '?'} {version}  ({component.get('type') or 'package'})",  # fetches the value
                font=FONT_MONO,  # copies the FONT_MONO value into font
                size=8,  # assigns the computed value to size
                leading=10,  # assigns the computed value to leading
            )  # closes the multiline block

    care_pairs = care.render_pairs(report.get("care") or {})  # the structured rows (no line re-parsing)
    if care_pairs:  # evaluates the branch condition
        pdf.section("CARE AND FEEDING (repository maintenance)")  # runs the section() call
        for label, value in care_pairs:  # loops over the collection
            if not label:  # evaluates the branch condition
                # Full-width rows (disclaimer, API error notes) render as
                # their own text run, exactly like the legacy line strings.
                pdf.text(value, font=FONT_MONO, size=7.9, leading=10.5, width=106)  # runs the text() call
                continue  # skips to the next loop iteration
            clauses = [  # splits the clauses
                part.strip() for part in regex.split(r"\s{2}[·-]\s{2}", value)
            ]
            if len(clauses) > 1:  # evaluates the branch condition
                # Dash-separated clauses get their own aligned sub-rows
                # instead of an arbitrary mid-phrase word wrap.
                pdf.mono_row(label, clauses[0])  # runs the mono_row() call
                for clause in clauses[1:]:  # loops over the collection
                    pdf.mono_row("", clause)  # runs the mono_row() call
            else:  # covers the remaining branch
                # Label-column rows wrap inside the value column so no text
                # runs past the right margin (long release notes, titles...).
                pdf.mono_row(label, value)  # runs the mono_row() call

    dashboard_payloads = report.get("dashboard") or {}  # fetches the value
    if dashboard_payloads:  # evaluates the branch condition
        pdf.section("DASHBOARD (selected metrics)")  # runs the section() call
        for payload in dashboard_payloads.values():  # loops over the collection
            kind = payload.get("kind")  # fetches the value
            pdf.text(str(payload.get("label") or "").upper(), font=FONT_BOLD, size=9.4, leading=13)  # draws the widget title
            if kind == "number":  # evaluates the branch condition
                card_colour = _pdf_colour(payload.get("colour") or "")  # runs the _pdf_colour() call
                pdf.number_card(payload.get("value", 0), payload.get("caption") or "", card_colour)  # draws the figure card
            elif kind == "bar":  # evaluates the branch condition
                for bar_label, bar_value, bar_colour in payload.get("rows") or []:  # loops over the collection
                    pdf.hbar(str(bar_label), bar_value, float(payload.get("max") or 1), _pdf_colour(bar_colour))  # draws the bar
                note = payload.get("note") or ""  # fetches the value
                if note:  # evaluates the branch condition
                    pdf.text(f"({note})", size=7.8, colour=MUTED, width=104, leading=10)  # draws the note
            elif kind == "donut":  # evaluates the branch condition
                data_rows = payload.get("rows") or []  # fetches the value
                shares = sum(float(count) for _l, count, _c in data_rows) or 1  # adds up the shares
                legend = "  ·  ".join(  # builds the legend text
                    f"{_fit(label, 18)} {round(100 * float(count) / shares)}%"
                    for label, count, _c in data_rows
                )  # closes the multiline block
                pdf.donut_track(data_rows, legend=legend)  # draws the segmented bar
                note = payload.get("note") or ""  # fetches the value
                if note:  # evaluates the branch condition
                    pdf.text(f"({note})", size=7.8, colour=MUTED, width=104, leading=10)  # draws the note
            elif kind == "heat":  # evaluates the branch condition
                pdf.heat_grid(  # draws the heat grid
                    payload.get("rows") or [],  # passes the grid rows
                    payload.get("sevs") or [],  # passes the severity columns
                    max((  # computes the cell maximum
                        count
                        for _file, buckets in payload.get("rows") or []
                        for count in buckets.values()
                    ), default=1),  # covers the empty-grid case
                )  # closes the multiline block
            elif kind == "table":  # evaluates the branch condition
                for row in payload.get("rows") or []:  # loops over the collection
                    pdf.text(  # runs the text() call
                        "  -  ".join(str(cell) for cell in row), font=FONT_MONO, size=7.9, leading=10.5, width=106
                    )  # closes the multiline block
                note = payload.get("note") or ""  # fetches the value
                if note:  # evaluates the branch condition
                    pdf.text(f"({note})", size=7.8, colour=MUTED, width=104, leading=10)  # draws the note
            elif kind == "na":  # evaluates the branch condition
                pdf.text(  # runs the text() call
                    f"(not assessable here: {payload.get('note', '')})", size=8, colour=MUTED, width=104, leading=10
                )  # closes the multiline block

    pdf.section("GREATEST RISKS")  # runs the section() call
    risks = report.get("greatest_risks") or []  # fetches the value
    if not risks:  # evaluates the branch condition
        pdf.text("None. No selected scanner produced a security finding.", size=9)  # runs the text() call
    for index, risk in enumerate(risks, 1):  # loops over the collection
        suffix = f"  (x{risk.get('count', 1)})" if risk.get("count", 1) > 1 else ""  # sets the suffix text
        if risk.get("omitted"):  # evaluates the branch condition
            suffix += "   [excluded from scoring]"  # keeps omissions visible in print  # flags the omission
        pdf.text(  # runs the text() call
            f"{index}. [{str(risk.get('severity', 'unknown')).upper()}] "  # runs the str() call
            f"{risk.get('title', '')}{suffix}   -{risk.get('penalty', 0):.1f} pts",  # fetches the value
            font=FONT_BOLD,  # copies the FONT_BOLD value into font
            size=9.2,  # assigns the computed value to size
            width=92,  # assigns the computed value to width
            leading=12,  # assigns the computed value to leading
            colour=INK,  # copies the INK value into colour
        )  # closes the multiline block
        pdf.text(  # runs the text() call
            f"{labels.get(risk.get('category'), risk.get('category', ''))} - {risk.get('rule_id', '')}",  # fetches the value
            size=8,  # assigns the computed value to size
            indent=8,  # assigns the computed value to indent
            colour=MUTED,  # copies the MUTED value into colour
            leading=10,  # assigns the computed value to leading
            width=96,  # assigns the computed value to width
        )  # closes the multiline block
        if risk.get("tool_labels"):  # evaluates the branch condition
            pdf.text(  # runs the text() call
                "Identified by: " + ", ".join(risk["tool_labels"]),  # maps the Identified by:  dictionary entry
                size=8,  # assigns the computed value to size
                indent=8,  # assigns the computed value to indent
                leading=10,  # assigns the computed value to leading
                width=96,  # assigns the computed value to width
            )  # closes the multiline block
        if risk.get("detail"):  # evaluates the branch condition
            pdf.text(risk["detail"], size=8.2, indent=8, colour=MUTED, leading=10, width=98)  # runs the text() call
        for location in (risk.get("locations") or [])[:3]:  # loops over the collection
            pdf.text(f"-> {location}", font=FONT_MONO, size=7.8, indent=8, leading=9.5, width=104)  # runs the text() call
        pdf.y -= 4  # updates the stored value in place

    totals = report.get("totals") or {}  # fetches the value
    pdf.section("FINDINGS BY SEVERITY")  # runs the section() call
    pdf.text(  # runs the text() call
        f"Critical {totals.get('critical', 0)}   High {totals.get('high', 0)}   "  # fetches the value
        f"Medium {totals.get('medium', 0)}   Low {totals.get('low', 0)}   "  # fetches the value
        f"Unknown {totals.get('unknown', 0)}",  # fetches the value
        font=FONT_MONO,  # copies the FONT_MONO value into font
        size=9,  # assigns the computed value to size
    )  # closes the multiline block

    pdf.section("FINDINGS BY TOOL")  # runs the section() call
    pdf.columns(  # runs the columns() call
        ("Tool", "Crit", "High", "Med", "Low", "Unk", "Total"),  # executes the statement
        (22, 5, 5, 4, 4, 4, 6),  # executes the statement
        font=FONT_MONO_BOLD,  # copies the FONT_MONO_BOLD value into font
        size=8.2,  # assigns the computed value to size
        colour=MUTED,  # copies the MUTED value into colour
    )  # closes the multiline block
    tool_labels = report.get("tool_labels") or {}  # fetches the value
    for key, stats in (report.get("by_tool") or {}).items():  # loops over the collection
        pdf.columns(  # runs the columns() call
            (  # executes the statement
                tool_labels.get(key, key.title()),  # fetches the value
                stats.get("critical", 0),  # fetches the value
                stats.get("high", 0),  # fetches the value
                stats.get("medium", 0),  # fetches the value
                stats.get("low", 0),  # fetches the value
                stats.get("unknown", 0),  # fetches the value
                stats.get("total", 0),  # fetches the value
            ),  # closes the multiline block
            (22, 5, 5, 4, 4, 4, 6),  # executes the statement
            size=8.2,  # assigns the computed value to size
        )  # closes the multiline block

    frameworks = report.get("frameworks") or {}  # fetches the value
    if frameworks:  # evaluates the branch condition
        pdf.section("COMPLIANCE FRAMEWORK MAPPING")  # runs the section() call
        pdf.text(  # runs the text() call
            "Affected = the findings touch this control this run. Clear = the area was "  # supplies the literal text
            "scanned and produced no finding, which is not proof of compliance.",  # supplies the literal text
            size=8,  # assigns the computed value to size
            colour=MUTED,  # copies the MUTED value into colour
            width=104,  # assigns the computed value to width
            leading=10,  # assigns the computed value to leading
        )  # closes the multiline block
        for entry in frameworks.values():  # loops over the collection
            pdf.text(  # runs the text() call
                f"{entry.get('label', '')}  -  "  # fetches the value
                f"{entry.get('affected_controls', 0)} of {entry.get('total_controls', 0)} "  # fetches the value
                "controls touched"  # supplies the literal text
                + (  # executes the statement
                    f"  -  {entry.get('unmapped', 0)} finding(s) outside the map"  # fetches the value
                    if entry.get("unmapped")  # evaluates the branch condition
                    else ""  # covers the remaining branch
                ),  # closes the multiline block
                font=FONT_BOLD,  # copies the FONT_BOLD value into font
                size=9.4,  # assigns the computed value to size
                leading=12,  # assigns the computed value to leading
            )  # closes the multiline block
            pdf.columns(  # runs the columns() call
                ("Control", "Title", "Findings", "Worst"),  # executes the statement
                (16, 46, 9, 9),  # executes the statement
                font=FONT_MONO_BOLD,  # copies the FONT_MONO_BOLD value into font
                size=8.2,  # assigns the computed value to size
                colour=MUTED,  # copies the MUTED value into colour
            )  # closes the multiline block
            affected = [  # assigns the computed value to affected
                control for control in entry.get("controls") or []  # fetches the value
                if control.get("status") == "affected"  # evaluates the branch condition
            ]  # closes the multiline block
            for control in affected:  # loops over the collection
                pdf.columns(  # runs the columns() call
                    (  # executes the statement
                        _fit(control.get("id", ""), 16),  # runs the _fit() call
                        _fit(control.get("title", ""), 66),  # runs the _fit() call
                        control.get("affected", 0),  # fetches the value
                        str(control.get("worst") or "-"),  # runs the str() call
                    ),  # closes the multiline block
                    (16, 46, 9, 9),  # executes the statement
                    size=8.2,  # assigns the computed value to size
                )  # closes the multiline block
            for control in affected:  # loops over the collection
                for example in (control.get("examples") or [])[:2]:  # loops over the collection
                    pdf.text(  # runs the text() call
                        f"{control.get('id', '')}: {example}",  # fetches the value
                        size=7.6,  # assigns the computed value to size
                        indent=16,  # assigns the computed value to indent
                        colour=MUTED,  # copies the MUTED value into colour
                        leading=9,  # assigns the computed value to leading
                        width=100,  # assigns the computed value to width
                    )  # closes the multiline block
            cleared = [  # assigns the computed value to cleared
                control.get("id")  # fetches the value
                for control in entry.get("controls") or []  # loops over the collection
                if control.get("status") == "clear"  # evaluates the branch condition
            ]  # closes the multiline block
            if cleared:  # evaluates the branch condition
                pdf.text(  # runs the text() call
                    "Clear in this run: " + ", ".join(cleared),  # maps the Clear in this run:  dictionary entry
                    size=7.8,  # assigns the computed value to size
                    colour=MUTED,  # copies the MUTED value into colour
                    width=104,  # assigns the computed value to width
                )  # closes the multiline block

    findings = _sorted_findings(report)  # runs the _sorted_findings() call
    if findings:  # evaluates the branch condition
        shown = findings[: config.MAX_LISTED_FINDINGS]  # copies the findings value into shown
        pdf.section(f"ALL FINDINGS (showing {len(shown)} of {len(findings)})")  # runs the section() call
        for item in shown:  # loops over the collection
            severity = str(item.get("severity") or "unknown").upper()  # runs the str() call
            title = item.get("title") or item.get("rule_id") or "finding"  # fetches the value
            pdf.text(  # runs the text() call
                f"[{severity}] {_fit(title, 78)}",  # supplies the literal text
                font=FONT_MONO,  # copies the FONT_MONO value into font
                size=7.9,  # assigns the computed value to size
                leading=9.6,  # assigns the computed value to leading
                width=107,  # assigns the computed value to width
            )  # closes the multiline block
            tools = ", ".join(item.get("tool_labels") or [])  # sets the tools text
            location = item.get("location") or "location not reported"  # fetches the value
            pdf.text(  # runs the text() call
                f"    {_fit(tools, 32)} - {_fit(location, 62)}",  # supplies the literal text
                font=FONT_MONO,  # copies the FONT_MONO value into font
                size=7.4,  # assigns the computed value to size
                colour=MUTED,  # copies the MUTED value into colour
                leading=9.2,  # assigns the computed value to leading
                width=110,  # assigns the computed value to width
            )  # closes the multiline block
        if len(findings) > len(shown):  # evaluates the branch condition
            pdf.text(  # runs the text() call
                f"... {len(findings) - len(shown)} more findings are available in the JSON/CSV export.",  # supplies the literal text
                size=8,  # assigns the computed value to size
                colour=MUTED,  # copies the MUTED value into colour
            )  # closes the multiline block

    pdf.section("SCANNERS")  # runs the section() call
    for key, status in (report.get("scanner_status") or {}).items():  # loops over the collection
        state = str(status.get("status") or "unknown")  # runs the str() call
        elapsed = status.get("duration_seconds")  # fetches the value
        elapsed_text = f"{elapsed:.1f}s" if isinstance(elapsed, (int, float)) else "n/a"  # sets the elapsed_text text
        label = tool_labels.get(key, config.TOOL_LABELS.get(key, key.title()))  # fetches the value
        pdf.columns((label, state, elapsed_text), (14, 9, 7), size=8.2)  # runs the columns() call
        for detail in status.get("details") or []:  # loops over the collection
            pdf.text(f"- {detail}", size=7.8, indent=14, colour=MUTED, leading=9.5, width=104)  # runs the text() call

    warnings = report.get("warnings") or []  # fetches the value
    if warnings:  # evaluates the branch condition
        pdf.section("WARNINGS")  # runs the section() call
        for warning in warnings:  # loops over the collection
            pdf.text(f"- {warning}", size=8, width=104, leading=10, colour=MUTED)  # runs the text() call

    path.write_bytes(_stamp_digest(pdf))  # writes the stamped, self-verifying document
    return path  # returns the path to the caller


def _report_sbom(report: dict[str, Any]) -> list[dict[str, str]]:  # defines the _report_sbom() function
    """The SBOM component rows of the report, or an error when none ran."""
    sbom = report.get("sbom") or {}  # the merged payload from the scan
    rows = list(sbom.get("all_components") or [])  # the component rows
    if not rows:  # evaluates the branch condition
        raise ValueError(  # raises the honest gap
            "No SBOM payload is in this report: run a scan with Syft or "
            "cdxgen selected, then print or export again."
        )  # closes the message
    return rows  # returns the rows to the caller


def write_report_sbom_csv(report: dict[str, Any], path: str | Path) -> Path:  # defines the writer
    """Export the scan's SBOM components as a UTF-8 CSV.

    One row per unique component (name, version, type, PURL and, for Syft,
    the file it was catalogued in), with a UTF-8 BOM so Excel opens it
    cleanly.
    """
    path = Path(path)  # creates the path object
    path.parent.mkdir(parents=True, exist_ok=True)  # creates the folder
    rows = _report_sbom(report)  # runs the _report_sbom() call
    with path.open("w", encoding="utf-8-sig", newline="") as handle:  # opens the context for the block
        writer = csv.writer(handle)  # runs the writer() call
        writer.writerow(("Component", "Version", "Type", "PURL", "File"))  # the header row
        for component in rows:  # loops over the components
            writer.writerow([  # runs the writerow() call
                component.get("name") or "",  # maps the name dictionary entry
                component.get("version") or "",  # maps the version dictionary entry
                component.get("type") or "",  # maps the type dictionary entry
                component.get("purl") or "",  # maps the purl dictionary entry
                component.get("file") or "",  # maps the file dictionary entry
            ])  # closes the row build
    return path  # returns the path to the caller


def write_report_sbom_pdf(report: dict[str, Any], path: str | Path) -> Path:  # defines the writer
    """Render the scan's SBOM as a paginated A4 PDF (same styling as Print Report)."""
    sbom = report.get("sbom") or {}  # the merged payload from the scan
    rows = list(sbom.get("all_components") or [])  # the component rows
    if not rows:  # evaluates the branch condition
        raise ValueError(  # raises the honest gap
            "No SBOM payload is in this report: run a scan with Syft or "
            "cdxgen selected, then print again."
        )  # closes the message
    path = Path(path)  # creates the path object
    path.parent.mkdir(parents=True, exist_ok=True)  # creates the folder
    name = _repo_name(report)  # runs the _repo_name() call
    pdf = _PdfBuilder(f"{name} - Software Bill of Materials")  # runs the _PdfBuilder() call

    wordmark = _load_branding(  # the cached decode (static asset)
        Path(__file__).resolve().parent / config.BRANDING_WHITE, downsample=3  # runs the Path() call
    )  # closes the multiline block
    if wordmark:  # evaluates the branch condition
        pw, ph, pixels = wordmark  # copies the wordmark value into pw, ph, pixels
        pdf.register_image((pw, ph, pixels))  # runs the register_image() call
        draw_width = 150.0  # assigns the computed value to draw_width
        pdf.draw_image(f"Im{len(pdf.images)}", draw_width, draw_width * ph / pw)  # runs the draw_image() call
        pdf.y -= 10  # updates the stored value in place
    else:  # covers the remaining branch
        pdf.text(config.APP_NAME, font=FONT_BOLD, size=19, leading=24, colour=INK)  # runs the text() call
    pdf.text(config.APP_TAGLINE, size=8.5, colour=MUTED, leading=11)  # runs the text() call
    pdf.text(f"{name} - Software Bill of Materials", font=FONT_BOLD, size=13, leading=17, colour=ACCENT)  # the title
    generated = str(report.get("generated_at") or "").replace("T", " ")  # runs the str() call
    pdf.text(  # runs the text() call
        f"Generated {generated}  -  app {report.get('app_version', config.APP_VERSION)}",  # supplies the literal text
        size=8,  # assigns the computed value to size
        colour=MUTED,  # copies the MUTED value into colour
        leading=10,  # assigns the computed value to leading
    )  # closes the multiline block
    pdf.y -= 6  # updates the stored value in place

    pdf.section("SBOM (SOFTWARE BILL OF MATERIALS)")  # the section banner
    pdf.mono_row("Catalogued by", str(sbom.get("tools") or "sbom"))  # who produced it
    if sbom.get("spec_version"):  # evaluates the branch condition
        pdf.mono_row("CycloneDX spec", str(sbom.get("spec_version")))  # the spec claim
    pdf.mono_row("Components", f"{sbom.get('components', len(rows))} unique")  # the row count
    pdf.mono_row(  # runs the mono_row() call
        "Unversioned",  # the label text
        f"{sbom.get('unversioned', 0)} rows without a version",  # the honest gap line
    )  # closes the mono_row call
    if sbom.get("ecosystems"):  # evaluates the branch condition
        family_bits = ", ".join(f"{key} ({count})" for key, count in sbom["ecosystems"].items())  # the families
        pdf.mono_row("Families", family_bits[:84])  # the family counts
    pdf.rule()  # runs the rule() call

    pdf.columns(("Component", "Version", "Type", "PURL"), (32, 14, 10, 34))  # the header row
    for component in rows:  # loops over the components
        pdf.wrapped_columns((  # wraps instead of cutting - nothing is hidden
            component.get("name") or "",  # maps the name dictionary entry
            component.get("version") or "-",  # maps the version dictionary entry
            component.get("type") or "",  # maps the type dictionary entry
            component.get("purl") or "-",  # maps the purl dictionary entry
        ), (34, 14, 10, 38))  # closes the row call

    path.write_bytes(_stamp_digest(pdf))  # writes the stamped, self-verifying document
    return path  # returns the path to the caller


def write_summary_pdf(report: dict[str, Any], bullets: list[str], path: str | Path) -> Path:  # defines the writer
    """Render the Summarize It bullets as a paginated A4 PDF.

    Same template family as the other PDF exports - wordmark, tagline, the
    repository heading, a SCAN SUMMARY section and one wrapped line per
    bullet with the brand-green dots.
    """
    path = Path(path)  # creates the path object
    path.parent.mkdir(parents=True, exist_ok=True)  # creates the folder
    name = _repo_name(report)  # runs the _repo_name() call
    pdf = _PdfBuilder(f"{name} - Summary")  # runs the _PdfBuilder() call

    wordmark = _load_branding(  # the cached decode (static asset)
        Path(__file__).resolve().parent / config.BRANDING_WHITE, downsample=3  # runs the Path() call
    )  # closes the multiline block
    if wordmark:  # evaluates the branch condition
        pw, ph, pixels = wordmark  # copies the wordmark value into pw, ph, pixels
        pdf.register_image((pw, ph, pixels))  # runs the register_image() call
        draw_width = 150.0  # assigns the computed value to draw_width
        pdf.draw_image(f"Im{len(pdf.images)}", draw_width, draw_width * ph / pw)  # runs the draw_image() call
        pdf.y -= 10  # updates the stored value in place
    else:  # covers the remaining branch
        pdf.text(config.APP_NAME, font=FONT_BOLD, size=19, leading=24, colour=INK)  # runs the text() call
    pdf.text(config.APP_TAGLINE, size=8.5, colour=MUTED, leading=11)  # runs the text() call
    pdf.text(f"{name} - Summary", font=FONT_BOLD, size=13, leading=17, colour=ACCENT)  # the title line
    repo = report.get("repo") or {}  # the repository block
    repo_url = repo.get("web_url") or (  # the GitHub path when one is known
        f"https://github.com/{repo.get('full_name')}"  # the canonical URL
        if repo.get("full_name") else str(repo.get("input_url") or "")  # website scans keep the address
    )  # closes the url build
    if repo_url:  # evaluates the branch condition
        pdf.text(repo_url, size=8, colour=MUTED, leading=10)  # draws the repository path
    generated = str(report.get("generated_at") or "").replace("T", " ")  # runs the str() call
    pdf.text(  # runs the text() call
        f"Generated {generated}  -  app {report.get('app_version', config.APP_VERSION)}",  # supplies the literal text
        size=8,  # assigns the computed value to size
        colour=MUTED,  # copies the MUTED value into colour
        leading=10,  # assigns the computed value to leading
    )  # closes the multiline block
    pdf.y -= 6  # updates the stored value in place

    pdf.section("SCAN SUMMARY")  # the section banner
    for bullet in bullets:  # loops over the composed sentences
        pdf.text("-  " + bullet, size=9.2, leading=13, width=96, colour=INK)  # a wrapped dotted line
        pdf._space(3)  # a small gap between bullets
    path.write_bytes(pdf.build())  # writes the document
    return path  # returns the path to the caller


def write_gad_pdf(report: dict[str, Any], results: dict[str, Any], path: str | Path) -> Path:  # defines the writer
    """Render the GitHub Advisory Database quick-check results as a themed PDF.

    Same template family as the other exports - wordmark, tagline, repository
    heading, a GITHUB ADVISORY DATABASE section with the sweep summary and
    one wrapped row per advisory hit, worst severity first.
    """
    path = Path(path)  # creates the path object
    path.parent.mkdir(parents=True, exist_ok=True)  # creates the folder
    name = _repo_name(report)  # runs the _repo_name() call
    pdf = _PdfBuilder(f"{name} - GitHub Advisory Check")  # runs the _PdfBuilder() call

    wordmark = _load_branding(  # the cached decode (static asset)
        Path(__file__).resolve().parent / config.BRANDING_WHITE, downsample=3  # runs the Path() call
    )  # closes the multiline block
    if wordmark:  # evaluates the branch condition
        pw, ph, pixels = wordmark  # copies the wordmark value into pw, ph, pixels
        pdf.register_image((pw, ph, pixels))  # runs the register_image() call
        draw_width = 150.0  # assigns the computed value to draw_width
        pdf.draw_image(f"Im{len(pdf.images)}", draw_width, draw_width * ph / pw)  # runs the draw_image() call
        pdf.y -= 10  # updates the stored value in place
    else:  # covers the remaining branch
        pdf.text(config.APP_NAME, font=FONT_BOLD, size=19, leading=24, colour=INK)  # runs the text() call
    pdf.text(config.APP_TAGLINE, size=8.5, colour=MUTED, leading=11)  # runs the text() call
    pdf.text(f"{name} - GitHub Advisory Database check", font=FONT_BOLD, size=13, leading=17, colour=ACCENT)  # the title
    generated = str(report.get("generated_at") or "").replace("T", " ")  # runs the str() call
    pdf.text(  # runs the text() call
        f"Generated {generated}  -  app {report.get('app_version', config.APP_VERSION)}",  # supplies the literal text
        size=8,  # assigns the computed value to size
        colour=MUTED,  # copies the MUTED value into colour
        leading=10,  # assigns the computed value to leading
    )  # closes the multiline block
    pdf.y -= 6  # updates the stored value in place

    hits = list(results.get("hits") or [])  # the advisory rows, worst first
    pdf.section("GITHUB ADVISORY DATABASE (QUICK SEARCH)")  # the section banner
    pdf.mono_row("Checked", f"{results.get('checked', 0)} of {results.get('considered', 0)} "
                            f"pinned components")  # the sweep coverage
    pdf.mono_row("Advisory hits", f"{len(hits)} published match{'es' if len(hits) != 1 else ''}")  # the hit count
    if results.get("rate_limited"):  # evaluates the branch condition
        pdf.mono_row("Note", "the sweep stopped early on a GitHub rate limit; "
                             "a GITHUB_TOKEN raises the budget")  # the honest note
    for note in (results.get("errors") or [])[:6]:  # loops over the per-component notes
        pdf.mono_row("- note", note[:84])  # the muted rows
    pdf.rule()  # runs the rule() call

    if hits:  # evaluates the branch condition
        for hit in hits:  # loops over the sorted hits
            marker = str(hit.get("severity") or "unknown").upper()  # the severity label
            pdf.columns((marker, str(hit.get("ghsa") or "-")), (10, 20))  # the id line
            pdf.text(  # runs the text() call
                f"  {hit.get('package', '')}  -  {hit.get('published', '')}",  # the package line
                size=7.9, leading=10, width=100, colour=MUTED,  # the muted context
            )  # closes the call
            if hit.get("summary"):  # evaluates the branch condition
                pdf.text(f"  {hit.get('summary')}", size=8.6, leading=11.5, width=100)  # the wrapped summary
            if hit.get("url"):  # evaluates the branch condition
                pdf.text(f"  {hit.get('url')}", size=7.6, leading=10, width=100, colour=MUTED)  # the link
            pdf._space(4)  # a gap before the next hit
    else:  # covers the remaining branch
        pdf.mono_row("Result", "no published advisories matched the catalogued components.")  # the good news
    path.write_bytes(pdf.build())  # writes the document
    return path  # returns the path to the caller


def _verify_cli(argv: list[str] | None = None) -> int:  # defines the _verify_cli() function
    """One-stamp verifier: ``python exports.py --verify report.pdf [more.pdf]``.

    Exit code: 0 = every file intact, 1 = at least one failed or unstamped.
    """  # keeps the docstring text
    paths = argv if argv is not None else sys.argv[1:]  # the files named on the command line
    paths = [path for path in paths if path != "--verify"]  # the flag itself names no file
    if not paths:  # evaluates the branch condition
        print("usage: python exports.py --verify <pdf> [more.pdf ...]", file=sys.stderr)  # the honest usage
        return 1  # closes the verifier
    print(f"{config.APP_NAME} {config.APP_VERSION} - PDF integrity verifier", flush=True)  # the banner
    ok = True  # the verdict so far, one failure is enough
    for path in paths:  # loops over the collection
        good, note = verify_pdf(path)  # runs the verify_pdf() call
        state = "intact" if good else "FAILED"  # the one-word verdict
        print(f"  {state:>7}  {path}  {note}", flush=True)  # the reader
        ok = ok and good  # saves the result on ok
    return 0 if ok else 1  # the exit code mirrors the verdicts


if __name__ == "__main__":  # evaluates the branch condition
    import sys  # the argv reader, imported only when verifying
    raise SystemExit(_verify_cli())  # runs the verifier
