"""Verification of a Resumption, and the replay guards that go with it.

Python port of `resumption.ts` in `@noblecloak/client` 0.13.0 (public `NobleCloak/noblecloak-ts` at `bb1be4c`) and of
`ForgettingReplayGuard` in `replay.ts` of `@noblecloak/langgraph`.

A Resumption's `signature` is a JWS compact serialization (ES256, `kid` in the protected header) whose payload is the
JSON object without `signature`. A runtime verifies it against the key set served at `/.well-known/jwks.json` and
checks that what it is about to run is what was approved: the `tool_ref` and the `action_digest` (a digest binds the
arguments, not the tool). The signature is checked with `cryptography` directly, so every check and error code is
ours.

`verify_resumption` runs these checks in this order, and the first to fail raises its `ResumptionError`:

1. structure (three non-empty base64url parts, strict and canonical) and a protected header that is a JSON object;
2. `alg` is `ES256`; the header has no `crit`; it has a `kid`;
3. `kid` names a key in the key set (a `jwks` that is not a mapping with a `keys` list of mappings is a
   `TypeError`, not a verdict on the Resumption); the key is EC P-256 with `x` and `y`;
4. the signature (64 bytes, r || s) verifies over the text of the first two parts;
5. `expires_at` is a strict RFC 3339 time and `expires_at + clock_skew_seconds` is after now;
6. `resolution` is one of `accept_resolutions` (default `("approved",)`);
7. `tool_ref` equals the expected one; `action_digest` equals the expected digest;
8. the replay guard, if there is one, has not seen this `approval_id`. This is last, so a Resumption that fails any
   earlier check never uses up its key.

Where this port is stricter than the TypeScript original, on purpose: a header with a `crit` member is refused (the
original has no check); `expires_at` must be RFC 3339 with an offset (the original reads it with `Date.parse`, which
takes many other spellings); a JSON segment with a repeated object member, bytes that are not UTF-8 or a leading
byte-order mark is `malformed` (the original's `JSON.parse` keeps the last repeated member and its `TextDecoder`
replaces bad bytes and drops a byte-order mark); a replay guard must be given (`None` opts out); and a guard that
does not answer with a `bool` is refused rather than read as truthy; `InMemoryReplayGuard` raises `expired` for a key
whose expiry its own clock has passed, where the original records it and forgets it on the next call; an entry in
the key set's `keys` list that is not a mapping is a `TypeError` (the original skips it); a negative
`clock_skew_seconds` is a `ValueError`; a `jws` that is not a `str` is `malformed`; and `accept_resolutions` given as a
bare string is a `TypeError`. `NaN` and
`Infinity` are refused here as there: Python's `json` accepts them unless told not to.

A failure of the environment (`cryptography` without P-256, a bug) is never reported as `bad_signature`: it propagates
as itself. So does anything a replay guard raises, and a key set of the wrong shape (`TypeError`, as the original's
`jwks.keys.find` throws). A key set that cannot be fetched is the caller's `fetch`
failing before this module is reached; this module takes the key set as a value.
"""

from __future__ import annotations

import base64
import inspect
import json
import math
import re
import threading
from collections.abc import Awaitable, Callable, Collection, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from typing import Any, Final, Literal, Protocol, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from noblecloak import digest as _digest

__all__ = [
    "AsyncReplayGuard",
    "ExpectedAction",
    "ForgettingReplayGuard",
    "InMemoryReplayGuard",
    "ReplayGuard",
    "ResumptionError",
    "ResumptionErrorCode",
    "ResumptionPayload",
    "averify_resumption",
    "verify_resumption",
]

ResumptionErrorCode = Literal[
    "malformed",
    "unsupported_alg",
    "unknown_kid",
    "bad_signature",
    "expired",
    "not_approved",
    "tool_mismatch",
    "digest_mismatch",
    "replayed",
]

ResumptionPayload = dict[str, Any]
"""The signed payload of a Resumption: the JSON object without its `signature`. Members are as the server sent them."""


class ResumptionError(Exception):
    """Why a Resumption was rejected. Not a `ValueError` or `TypeError`: those are for a caller's own mistakes."""

    code: ResumptionErrorCode

    def __init__(self, code: ResumptionErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code

    def __reduce__(self) -> tuple[type[ResumptionError], tuple[ResumptionErrorCode, str]]:
        # `args` is `(message,)`, so the default reconstruction `cls(message)` fails; pickle and copy use this instead.
        return (type(self), (self.code, str(self)))


class ReplayGuard(Protocol):
    """Remembers which Resumptions a runtime has already acted on."""

    def first_use(self, key: str, expires_at: datetime) -> bool:
        """Record `key` and return True the first time it is seen, False for a key already recorded.

        `expires_at` is a timezone-aware time after which an implementation may forget the key.
        """
        ...


# --- replay guards --------------------------------------------------------------------------------
#
# A Resumption is a statement, not a single-use credential: single use is the server's `/consume`. A runtime that
# must not act on the same Resumption twice (a retry after a crash, a duplicate push) keeps a guard. The two guards
# here keep keys in memory, for one process; they are not shared between processes.


class AsyncReplayGuard(Protocol):
    """A `ReplayGuard` whose `first_use` is a coroutine function, for a shared store behind I/O."""

    async def first_use(self, key: str, expires_at: datetime) -> bool:
        """As `ReplayGuard.first_use`."""
        ...


def _utc_now() -> datetime:
    return datetime.now(UTC)


class InMemoryReplayGuard:
    """A guard that keeps keys in memory until they expire. Safe to share between threads.

    A key is forgotten once `expires_at <= now`, where `now` comes from the clock given at construction. That clock
    and the `now` given to `verify_resumption` must agree. `first_use` raises `ResumptionError("expired")` for a key
    whose `expires_at` is not after the guard's own clock, instead of recording a key it would forget on the next call:
    a guard whose clock is ahead of the verifier's therefore fails loudly and never silently stops guarding.
    """

    def __init__(self, now: Callable[[], datetime] = _utc_now) -> None:
        self._now = now
        self._seen: dict[str, datetime] = {}
        # The TypeScript guard relies on a single thread; here the sweep, the lookup and the insert are one step.
        self._lock = threading.Lock()

    def first_use(self, key: str, expires_at: datetime) -> bool:
        if not isinstance(key, str):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError("a replay key is a str")
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise ValueError("expires_at must carry a timezone")
        with self._lock:
            now = self._now()
            for seen in [k for k, until in self._seen.items() if until <= now]:
                del self._seen[seen]
            if expires_at <= now:
                raise ResumptionError("expired", "the key has expired by this guard's clock; it is not recorded")
            if key in self._seen:
                return False
            self._seen[key] = expires_at
            return True


class ForgettingReplayGuard(InMemoryReplayGuard):
    """An `InMemoryReplayGuard` that can also forget a key, so a resume that failed before it did anything can be
    tried again in this process. Across processes `/consume` is the atomic single use."""

    def forget(self, key: str) -> None:
        with self._lock:
            self._seen.pop(key, None)


# --- verification ---------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExpectedAction:
    """What the runtime is about to run: the tool and the digest of the arguments as it will send them."""

    tool_ref: str
    arg_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.tool_ref, str) or not isinstance(self.arg_digest, str):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError("tool_ref and arg_digest are both str")

    @classmethod
    def for_call(cls, tool_ref: str, arguments: object) -> ExpectedAction:
        """The expected action for a call of `tool_ref` with `arguments`, digested by `noblecloak.digest.arg_digest`.

        Raises `noblecloak.digest.DigestError` for arguments that have no digest.
        """
        return cls(tool_ref=tool_ref, arg_digest=_digest.arg_digest(arguments))


_BASE64URL: Final = re.compile(r"[A-Za-z0-9_-]*")
_RFC3339: Final = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?([Zz]|[+-][0-9]{2}:[0-9]{2})"
)
_MAX_DATETIME: Final = datetime.max.replace(tzinfo=UTC)


def _show(value: object) -> str:
    """A value as it appears in a message: JSON, ASCII only, and cut short, because it came off the wire."""
    text = json.dumps(value, ensure_ascii=True, default=repr)
    return text if len(text) <= 80 else text[:77] + "..."


def _b64url_decode(text: str) -> bytes:
    """Strict, canonical base64url. A signature has exactly one text: padding, other alphabets and unused trailing
    bits (`AB` and `AC` decode alike) are all refused."""
    if _BASE64URL.fullmatch(text) is None:
        raise ResumptionError("malformed", "not base64url")
    if len(text) % 4 == 1:
        raise ResumptionError("malformed", "not valid base64url: the length is impossible")
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii") != text:
        raise ResumptionError("malformed", "not canonical base64url: unused trailing bits are set")
    return data


def _refuse_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("a repeated object member")
        result[key] = value
    return result


def _refuse_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _parse_json_segment(segment: str, what: str) -> dict[str, Any]:
    data = _b64url_decode(segment)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ResumptionError("malformed", f"{what} is not UTF-8") from error
    try:
        value = json.loads(text, object_pairs_hook=_refuse_duplicates, parse_constant=_refuse_constant)
    except (ValueError, RecursionError) as error:
        raise ResumptionError("malformed", f"{what} is not JSON") from error
    if not isinstance(value, dict):
        raise ResumptionError("malformed", f"{what} is not an object")
    return cast("dict[str, Any]", value)


def _parse_rfc3339(text: object) -> datetime | None:
    """An aware `datetime` for an RFC 3339 `date-time` (an offset is required), or None for anything else."""
    if not isinstance(text, str):
        return None
    match = _RFC3339.fullmatch(text)
    if match is None:
        return None
    year, month, day, hour, minute, second, fraction, offset = match.groups()
    try:
        if offset in ("Z", "z"):
            zone = UTC
        else:
            offset_minutes = int(offset[1:3]) * 60 + int(offset[4:6])
            if int(offset[4:6]) > 59:
                return None
            zone = timezone(timedelta(minutes=-offset_minutes if offset[0] == "-" else offset_minutes))
        microseconds = int((fraction or "0")[:6].ljust(6, "0"))
        return datetime(int(year), int(month), int(day), int(hour), int(minute), int(second), microseconds, tzinfo=zone)
    except ValueError:
        return None


def _load_p256_key(x: str, y: str) -> ec.EllipticCurvePublicKey:
    """The public key for JWK coordinates. Raises `ValueError` when they are not a P-256 key: not canonical base64url,
    not 32 bytes each, or not a point on the curve."""
    try:
        x_bytes, y_bytes = _b64url_decode(x), _b64url_decode(y)
    except ResumptionError as error:
        raise ValueError("a coordinate is not canonical base64url") from error
    if len(x_bytes) != 32 or len(y_bytes) != 32:
        raise ValueError("a P-256 coordinate is 32 bytes")
    numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x_bytes, "big"), int.from_bytes(y_bytes, "big"), ec.SECP256R1()
    )
    return numbers.public_key()


def _ecdsa_verify(key: ec.EllipticCurvePublicKey, signature: bytes, signing_input: bytes) -> None:
    """Returns when the 64-byte r || s `signature` is valid; raises `InvalidSignature` when it is not."""
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))


def _skew(seconds: object) -> timedelta:
    try:
        if (
            isinstance(seconds, bool)
            or not isinstance(seconds, int | float)
            or not math.isfinite(seconds)
            or seconds < 0
        ):
            raise ValueError
        return timedelta(seconds=seconds)
    except (ValueError, OverflowError):
        raise ValueError("clock_skew_seconds must be a finite number of seconds, zero or more") from None


def _accepted(resolutions: object) -> frozenset[str]:
    if isinstance(resolutions, str | bytes) or not isinstance(resolutions, Collection):
        # A bare string would make `in` a substring test: "app" in "approved".
        raise TypeError("accept_resolutions must be a collection of str, not a single string")
    items = cast("Collection[object]", resolutions)
    if not all(isinstance(item, str) for item in items):
        raise TypeError("accept_resolutions must hold only str")
    return frozenset(cast("Collection[str]", items))


@dataclass(frozen=True, slots=True)
class _Verified:
    payload: ResumptionPayload
    keep_until: datetime
    """How long a replay guard must remember this Resumption: while it can still pass the expiry check."""


def _find_key(header: Mapping[str, Any], jwks: Mapping[str, Any]) -> ec.EllipticCurvePublicKey:
    """The P-256 key the protected header's `kid` names in `jwks`."""
    kid = header.get("kid")
    if not isinstance(kid, str) or kid == "":
        raise ResumptionError("malformed", "no kid in the header")
    if not isinstance(jwks, Mapping):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise TypeError("jwks must be a mapping with a `keys` list")
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        # The caller handed over something that is not a key set; that is not a verdict on the Resumption, and a
        # caller that refetches the key set on `unknown_kid` must not read it as key rotation.
        raise TypeError("jwks must be a mapping with a `keys` list")
    jwk: Mapping[str, Any] | None = None
    for candidate in cast("list[object]", keys):
        if not isinstance(candidate, Mapping):
            # Same reasoning as above: a model object or other non-JSON entry is a caller mistake, and skipping it
            # would end in `unknown_kid`, which a refetching caller reads as key rotation.
            raise TypeError("each entry in the key set's `keys` list must be a mapping (a JWK as plain JSON)")
        if candidate.get("kid") == kid:  # pyright: ignore[reportUnknownMemberType]
            jwk = cast("Mapping[str, Any]", candidate)
            break
    if jwk is None:
        raise ResumptionError("unknown_kid", f"no key {_show(kid)} in the key set")
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ResumptionError("unknown_kid", f"key {_show(kid)} is not an EC P-256 key")
    x, y = jwk.get("x"), jwk.get("y")
    if not isinstance(x, str) or not isinstance(y, str):
        raise ResumptionError("malformed", f"key {_show(kid)} has no x and y coordinates")
    try:
        return _load_p256_key(x, y)
    except ValueError as error:
        # Only "these coordinates are not a P-256 point" is a bad signature. Anything else (`UnsupportedAlgorithm`
        # when the backend lacks P-256, a bug) is the environment and propagates as itself.
        raise ResumptionError("bad_signature", "the key could not be imported") from error


def _signed_payload(jws: object, jwks: Mapping[str, Any]) -> dict[str, Any]:
    """The payload of `jws`, once its structure, algorithm, key and signature have checked out (checks 1 to 4)."""
    parts = jws.split(".") if isinstance(jws, str) else []
    if len(parts) != 3 or any(part == "" for part in parts):
        raise ResumptionError("malformed", "a JWS compact serialization has three non-empty parts")
    encoded_header, encoded_payload, encoded_signature = parts
    header = _parse_json_segment(encoded_header, "the protected header")
    if header.get("alg") != "ES256":
        raise ResumptionError("unsupported_alg", f"alg {_show(header.get('alg'))} is not ES256")
    if "crit" in header:
        # RFC 7515 4.1.11: a JWS with a critical extension the verifier does not understand must be rejected, and
        # this verifier understands none. The TypeScript original does not look at `crit`.
        raise ResumptionError("malformed", "the header has a crit member; no critical extension is understood")
    # The key is imported before the signature text is decoded, as in the original: a key that cannot be imported is
    # a `bad_signature` even when the signature text is also malformed.
    key = _find_key(header, jwks)
    signature = _b64url_decode(encoded_signature)
    if len(signature) != 64:
        raise ResumptionError("bad_signature", "the signature is not 64 bytes")
    try:
        _ecdsa_verify(key, signature, f"{encoded_header}.{encoded_payload}".encode())
    except InvalidSignature as error:
        raise ResumptionError("bad_signature", "the signature does not match the payload") from error
    return _parse_json_segment(encoded_payload, "the payload")


def _check_claims(
    raw: Mapping[str, Any], expected: ExpectedAction, now: datetime, skew: timedelta, accepted: frozenset[str]
) -> datetime:
    """Checks 5 to 7. Returns `expires_at`."""
    expires_at = _parse_rfc3339(raw.get("expires_at"))
    if expires_at is None:
        raise ResumptionError("malformed", "the payload has no expires_at in RFC 3339 form")
    if now - expires_at >= skew:  # expires_at + skew <= now, without overflowing near the end of time
        raise ResumptionError("expired", f"the Resumption expired at {_show(raw['expires_at'])}")
    resolution = raw.get("resolution")
    if not isinstance(resolution, str) or resolution not in accepted:
        raise ResumptionError(
            "not_approved", f"the resolution is {_show(resolution)}, not one of {_show(sorted(accepted))}"
        )
    if raw.get("tool_ref") != expected.tool_ref:
        raise ResumptionError(
            "tool_mismatch", f"approved for {_show(raw.get('tool_ref'))}, about to run {_show(expected.tool_ref)}"
        )
    if raw.get("action_digest") != expected.arg_digest:
        raise ResumptionError("digest_mismatch", "the arguments are not the ones that were approved")
    return expires_at


def _verify_before_guard(
    jws: object,
    jwks: Mapping[str, Any],
    expected: ExpectedAction,
    *,
    now: datetime | None,
    clock_skew_seconds: float,
    accept_resolutions: Collection[str],
) -> _Verified:
    skew = _skew(clock_skew_seconds)
    accepted = _accepted(accept_resolutions)
    now = datetime.now(UTC) if now is None else now
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must carry a timezone")
    raw = _signed_payload(jws, jwks)
    expires_at = _check_claims(raw, expected, now, skew, accepted)
    try:
        keep_until = expires_at + skew
    except OverflowError:
        keep_until = _MAX_DATETIME
    return _Verified(raw, keep_until)


def _replay_key(payload: ResumptionPayload) -> str:
    # One Resumption exists per approval, so the approval is the key. The signature is not: ECDSA admits a second
    # valid signature for the same payload (s -> n - s), and the signature text admits other spellings unless it is
    # held canonical.
    approval_id = payload.get("approval_id")
    if not isinstance(approval_id, str) or approval_id == "":
        raise ResumptionError("malformed", "the payload has no approval_id")
    return approval_id


def _require_fresh(answer: object) -> None:
    if not isinstance(answer, bool):
        raise TypeError("a replay guard's first_use must answer with a bool")
    if not answer:
        raise ResumptionError("replayed", "this Resumption was already acted on")


def verify_resumption(
    jws: str,
    jwks: Mapping[str, Any],
    expected: ExpectedAction,
    *,
    replay_guard: ReplayGuard | None,
    now: datetime | None = None,
    clock_skew_seconds: float = 0,
    accept_resolutions: Collection[str] = ("approved",),
) -> ResumptionPayload:
    """Verify a Resumption's JWS against a key set and the action the runtime is about to run.

    Returns the payload when every check holds and raises `ResumptionError` otherwise (checks and order in the module
    docstring). A fault in the environment, or one raised by `replay_guard`, propagates as itself.

    `replay_guard` has no default: a runtime that must not act twice passes its guard, and one that does not passes
    `None` on purpose. Use `averify_resumption` for a guard whose `first_use` is a coroutine function.

    `now` is an aware `datetime` (default: the current time). It is not passed to `replay_guard`: a guard keeps its own
    clock, and `InMemoryReplayGuard` raises `expired` for a key that its clock says has expired, so when `now` is
    injected give the guard the same clock (`InMemoryReplayGuard(lambda: now)`). `clock_skew_seconds` is the tolerance
    on expiry, zero or more. `accept_resolutions` is the collection of resolutions to act on, default `("approved",)`:
    a validly signed `rejected` is `not_approved`, because the signature proves who said it, not that the answer
    was yes.
    """
    verified = _verify_before_guard(
        jws, jwks, expected, now=now, clock_skew_seconds=clock_skew_seconds, accept_resolutions=accept_resolutions
    )
    if replay_guard is not None:
        answer = replay_guard.first_use(_replay_key(verified.payload), verified.keep_until)
        if inspect.isawaitable(answer):
            if inspect.iscoroutine(answer):
                answer.close()
            raise TypeError("this guard's first_use is a coroutine function; use averify_resumption")
        _require_fresh(answer)
    return verified.payload


async def averify_resumption(
    jws: str,
    jwks: Mapping[str, Any],
    expected: ExpectedAction,
    *,
    replay_guard: ReplayGuard | AsyncReplayGuard | None,
    now: datetime | None = None,
    clock_skew_seconds: float = 0,
    accept_resolutions: Collection[str] = ("approved",),
) -> ResumptionPayload:
    """`verify_resumption` for a guard that is a coroutine function (or a plain one). The checks are the same.

    The checks are synchronous and run before the guard is consulted; only the guard's `first_use` is awaited, which
    is why this entry point exists: a sync `verify_resumption` cannot await a guard that talks to a shared store.
    """
    verified = _verify_before_guard(
        jws, jwks, expected, now=now, clock_skew_seconds=clock_skew_seconds, accept_resolutions=accept_resolutions
    )
    if replay_guard is not None:
        answer: object = replay_guard.first_use(_replay_key(verified.payload), verified.keep_until)
        if inspect.isawaitable(answer):
            answer = await cast("Awaitable[object]", answer)
        _require_fresh(answer)
    return verified.payload
