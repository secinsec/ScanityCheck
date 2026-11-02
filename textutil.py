"""Shared small text helpers used across modules.

Several modules had grown private near-identical clipping helpers
(``scoring._clean/_ellipsis``, ``dashboard._clip``, ``care._trim``,
``exports._fit``). This module is the single source for that behaviour so the
ellipsis and limits cannot silently diverge between report formats.

Two clipping contracts exist:

* :func:`clip` first collapses runs of whitespace (the ``scoring._clean``
  flavour used on prose) and
* :func:`clip_raw` keeps the text exactly as given (the flavour the
  dashboard, care, exports and the findings list use on paths, titles and
  rule ids where collapsing would corrupt the string).
"""

from __future__ import annotations

import re as _regex_module
from typing import Any

_ELLIPSIS = "…"  # the one-character continuation marker used everywhere
_WHITESPACE = _regex_module.compile(r"\s+")


def clean(text: Any) -> str:
    """Collapse runs of whitespace and strip the edges."""
    return _WHITESPACE.sub(" ", str(text or "")).strip()


def clip(text: Any, limit: int, ellipsis: str = _ELLIPSIS) -> str:  # defines the clip() function
    """Collapse whitespace, then trim to ``limit`` characters with ``ellipsis``."""
    return clip_raw(clean(text), limit, ellipsis)  # trims the sanitised text


def clip_raw(text: Any, limit: int, ellipsis: str = _ELLIPSIS) -> str:  # defines the clip_raw() function
    """Trim verbatim text to ``limit`` characters, replacing the cut with ``ellipsis``.

    No whitespace touching: the result is ``len(text)`` characters at most and
    the cut keeps at least one room for the ellipsis marker so the string is
    never longer than ``limit``.
    """
    value = str(text or "")  # makes the string form
    if len(value) <= limit:  # evaluates the branch condition
        return value  # already short enough
    if limit <= len(ellipsis):  # evaluates the branch condition
        return ellipsis[:limit]  # degenerate limits still keep the marker shape
    return value[: limit - len(ellipsis)] + ellipsis  # trims and marks the cut
