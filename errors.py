"""Exceptions shared by the scanner runners, bootstrap and UI."""  # keeps the docstring text

from __future__ import annotations  # imports annotations from the __future__ module


class ScanError(RuntimeError):  # defines the ScanError class
    """Fatal problem that stops the whole scan."""  # keeps the docstring text


class ScanCancelled(ScanError):  # defines the ScanCancelled class
    """Raised when the user presses Stop."""  # keeps the docstring text


class ToolError(ScanError):  # defines the ToolError class
    """A scanner could not be downloaded, installed or started."""  # keeps the docstring text
