"""Argument digests: `sha256(RFC 8785 JCS(arguments as sent))`, lowercase hex.

Python port of `digest.ts` in `@noblecloak/client` 0.13.0. Canonicalisation is the `rfc8785` package's
(Apache-2.0), an implementation of RFC 8785; it is locked at 0.1.4 for CI, and consumers get `>=0.1.4,<0.2`.
"Arguments as sent" means before any schema default is applied.

The server digests what it received, so a digest it would compute differently never matches. `jcs` therefore
refuses, before canonicalising, everything that has no single JSON reading:

- a value whose type is not exactly `None`, `bool`, `int`, `float`, `str`, `list` or `dict` (subclasses, enums,
  tuples, bytes, sets and decimals are refused), and a `dict` key that is not exactly a `str`;
- a number that is not finite, and an integral number, `int` or `float`, outside ±(2^53 - 1), the range in which
  every integer is one IEEE 754 double (`1e300` and `2**53` are refused);
- a string or key holding a surrogate code point (a Python `str` holds a valid astral character as one code point,
  so every surrogate is unpaired);
- a cyclic value, and nesting deeper than `MAX_NESTING_DEPTH`, the top-level container being depth 1.

A container reachable by several paths is validated once per depth it is reached at (at most `MAX_NESTING_DEPTH`
times), so validation of a value built from shared references does not blow up. Canonicalisation does: `rfc8785`
writes every path, so `jcs` and `arg_digest` take time and memory proportional to the expanded tree, exponential
for a value that shares references on purpose (the TypeScript original has the same cost). JSON decoded off the
wire holds no shared references.

When one value holds several faults, this module and the original both refuse it, but which `DigestError.code`
is raised first follows the iteration order of the object (insertion order of a dict here; `Object.entries` in the
original lists integer-like keys first), so only the refusal, not the code, is guaranteed to match the original.

`bool` is its own case, so `True` canonicalises as `true`, never as `1`. `1` and `1.0` canonicalise alike.

This module does not read tool schemas. A tool whose schema declares a `contentEncoding: base64` or
`x-noblecloak-streaming: true` argument contributes the SHA-256 of the decoded bytes, or of the stream, in place of
the value: the caller computes that with `sha256_hex` and puts the result in the argument before canonicalising.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Final, Literal, cast

import rfc8785

__all__ = ["MAX_NESTING_DEPTH", "DigestError", "DigestErrorCode", "arg_digest", "jcs", "sha256_hex"]

MAX_NESTING_DEPTH: Final = 64
"""Maximum nesting of lists and dicts, the arguments object itself being depth 1."""

_MAX_SAFE_INTEGER: Final = 2**53 - 1
_SURROGATE: Final = re.compile(r"[\ud800-\udfff]")

DigestErrorCode = Literal[
    "unsupported_type",
    "non_finite_number",
    "integer_out_of_range",
    "invalid_string",
    "nesting_too_deep",
]


class DigestError(TypeError):
    """Why a value cannot be canonicalised. A `TypeError`, so a caller that catches `TypeError` still does.

    The message names the class of problem. It never contains a key or the text of a string or integer, because
    arguments can be sensitive; it may name a Python type, or say NaN or infinity.
    """

    code: DigestErrorCode

    def __init__(self, code: DigestErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code

    def __reduce__(self) -> tuple[type[DigestError], tuple[DigestErrorCode, str]]:
        # `args` is `(message,)`, so the default reconstruction `cls(message)` fails; pickle and copy use this instead.
        return (type(self), (self.code, str(self)))


def _check_string(text: str, what: str) -> None:
    if _SURROGATE.search(text) is not None:
        raise DigestError("invalid_string", f"{what} contains a lone surrogate")


def _check_float(value: float) -> None:
    if not math.isfinite(value):
        raise DigestError("non_finite_number", f"{value!r} is not representable in JSON")
    if value.is_integer() and abs(value) > _MAX_SAFE_INTEGER:
        raise DigestError("integer_out_of_range", "an integral number is outside ±(2^53 - 1)")


def _check_container(
    value: list[object] | dict[object, object], depth: int, ancestors: list[int], validated: dict[int, int]
) -> None:
    if id(value) in ancestors:
        raise DigestError("unsupported_type", "cyclic value")
    if depth + 1 > MAX_NESTING_DEPTH:
        raise DigestError("nesting_too_deep", f"nesting exceeds the maximum depth of {MAX_NESTING_DEPTH}")
    # A container already validated at this depth or deeper fits here too; one first seen shallower is walked again.
    if validated.get(id(value), -1) >= depth:
        return
    ancestors.append(id(value))
    if isinstance(value, list):
        for item in value:
            _check(item, depth + 1, ancestors, validated)
    else:
        for key, child in value.items():
            if type(key) is not str:
                raise DigestError("unsupported_type", f"an object key of type {type(key).__name__} is not a string")
            _check_string(key, "a key")
            _check(child, depth + 1, ancestors, validated)
    ancestors.pop()
    validated[id(value)] = depth


def _check(value: object, depth: int, ancestors: list[int], validated: dict[int, int]) -> None:
    kind = type(value)
    # Exact types only. `bool` is its own case so that it is never read as the integer it subclasses.
    if value is None or kind is bool:
        return
    if kind is int:
        if not -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER:  # pyright: ignore[reportOperatorIssue]
            raise DigestError("integer_out_of_range", "an integer is outside ±(2^53 - 1)")
    elif kind is float:
        _check_float(value)  # pyright: ignore[reportArgumentType]
    elif kind is str:
        _check_string(value, "a string")  # pyright: ignore[reportArgumentType]
    elif kind is list or kind is dict:
        _check_container(cast("list[object] | dict[object, object]", value), depth, ancestors, validated)
    else:
        raise DigestError("unsupported_type", f"{kind.__name__} is not a JSON value")


def jcs(value: object) -> str:
    """The RFC 8785 canonical form of `value`. Raises `DigestError` for a value that is not JSON."""
    _check(value, 0, [], {})
    return rfc8785.dumps(value).decode("utf-8")  # pyright: ignore[reportArgumentType]


def sha256_hex(data: str | bytes | bytearray | memoryview) -> str:
    """Lowercase hex SHA-256 of a `str` (as UTF-8) or of `bytes`, `bytearray` or `memoryview`.

    The types are exact, as in `jcs`: a subclass could override `encode` and hash other bytes than the ones it shows.
    Raises `DigestError` for any other type and for a string holding a surrogate code point: UTF-8 has no encoding
    for it, and substituting U+FFFD would hash text the caller did not send.
    """
    kind = type(data)
    if kind is str:
        text = cast("str", data)
        _check_string(text, "a string")
        return hashlib.sha256(text.encode("utf-8")).hexdigest()
    if kind is bytes or kind is bytearray or kind is memoryview:
        return hashlib.sha256(cast("bytes", data)).hexdigest()
    raise DigestError("unsupported_type", f"{kind.__name__} is neither text nor bytes")


def arg_digest(args: object) -> str:
    """The argument digest of `args`: lowercase hex SHA-256 of their canonical form."""
    return sha256_hex(jcs(args))
