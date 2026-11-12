"""The host of a URL, in the one form this package accepts: what a URL parser that follows the WHATWG URL Standard
(`new URL()`, which the TypeScript original uses) would say, for the hosts that a plain name or an address can be.

`normal_host` returns the host in lower-case ASCII, or None for a host this package refuses. A refused host is one
whose reading differs between parsers, or that no resolver would take:

- an internationalised name is converted with UTS #46, non-transitional (`straße.example` is `xn--strae-oqa.example`;
  Python's `str.encode("idna")` is IDNA 2003 and says `strasse.example`);
- a name with a label that is empty (but for the one after a trailing dot), longer than 63 characters or outside
  letters, digits, `-` and `_`, a name longer than 253 characters, and an `xn--` label that is not valid punycode, are
  refused;
- a percent-encoded host (`ex%61mple.com`) is refused rather than decoded;
- a host whose last label is a number (`0x7f.1`, `1.2.3.04`, `2130706433`), which a WHATWG parser reads as an IPv4
  address in a dozen spellings, is refused unless it is a dotted quad with no leading zero;
- an IPv6 address is returned in its compressed form.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Final

import idna

__all__ = ["normal_host"]

_LABEL: Final = re.compile(r"[a-z0-9_-]{1,63}", re.ASCII)
_NUMBER: Final = re.compile(r"[0-9]+|0[xX][0-9a-fA-F]*", re.ASCII)
_MAX_HOST: Final = 253


def normal_host(host: str) -> str | None:
    """The host as lower-case ASCII (an IPv6 address compressed, without brackets), or None when it is refused."""
    if host == "" or "%" in host:
        return None
    if ":" in host:
        try:
            return ipaddress.IPv6Address(host).compressed
        except ValueError:
            return None
    name = host
    if not name.isascii():
        try:
            name = idna.encode(name, uts46=True, transitional=False).decode("ascii")
        except (idna.IDNAError, UnicodeError):
            return None
    name = name.lower()
    labels = name.removesuffix(".").split(".")
    if _NUMBER.fullmatch(labels[-1]):
        try:
            return str(ipaddress.IPv4Address(name))
        except ValueError:
            return None
    if len(name.removesuffix(".")) > _MAX_HOST or not all(_LABEL.fullmatch(label) for label in labels):
        return None
    for label in labels:
        if label.startswith("xn--"):
            try:
                idna.decode(label)
            except (idna.IDNAError, UnicodeError):
                return None
    return name
