"""JSON parsing for the service-principal modules, as a value rather than an exception."""

from __future__ import annotations

import json
from typing import Final

INVALID: Final = object()
"""What `parse_json` returns for text that is not JSON."""


def parse_json(text: str) -> object:
    """The parsed JSON, or `INVALID`.

    It returns rather than raises, so the caller raises its own error with no exception in flight: `JSONDecodeError.doc`
    is the text, which can hold a key. `NaN` and `Infinity`, which Python's `json` takes by default, are not JSON.
    """

    def refuse(_constant: str) -> object:
        raise ValueError("NaN and Infinity are not JSON")

    try:
        return json.loads(text, parse_constant=refuse)
    except (ValueError, RecursionError):
        return INVALID
