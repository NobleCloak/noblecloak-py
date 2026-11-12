"""Strict base64url, as RFC 7515 writes it: unpadded, canonical and in the URL-safe alphabet."""

from __future__ import annotations

import base64
import re
from typing import Final

__all__ = ["b64url_decode"]

_BASE64URL: Final = re.compile(r"[A-Za-z0-9_-]*", re.ASCII)


def b64url_decode(text: str) -> bytes | None:
    """The bytes of unpadded, canonical base64url `text`, or None when it is anything else."""
    if not _BASE64URL.fullmatch(text) or len(text) % 4 == 1:
        return None
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    return raw if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == text else None
