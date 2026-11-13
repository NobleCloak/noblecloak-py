"""What `TokenSource` and `AsyncTokenSource` share: the cache, the one request shared by concurrent callers, the
request's form and signature, and the reading of the answer. The two sources themselves are in `_async/token.py`
(written by hand) and `_sync/token.py` (generated from it; see `scripts/generate_sync.py`).

Python port of `service-principal-token.ts` and `service-principal-error.ts` in `@noblecloak/client` 0.13.0 (public
`NobleCloak/noblecloak-ts` at `bb1be4c`). The seven error codes, the 120 s assertion (`iss` = `sub` = `client_id`,
`aud` = the credential's `assertion_audience`, a fresh `jti`), the RFC 7638 thumbprint as the key id when the JWK has
none, the cache until `life - min(skew, life / 2)`, the one request shared by concurrent callers, the generation
counter that `invalidate()` bumps and the rule that a failure is not cached are the original's.

`TokenSource` is synchronous and `AsyncTokenSource` is its `asyncio` twin, generated from it; both take the same
arguments and have the same behavior. `get_token` is what the client's token seam takes. Time is in seconds, as a
float.

What differs from the original, because Python is not JavaScript:

- Locks. JavaScript runs on one thread, so the original shares one in-flight request without a lock; here the state is
  guarded by a `threading.Lock` held only for short sections and never across an `await`. Callers of one
  `AsyncTokenSource` may be on different event loops (or threads): the caller that starts the request is the leader,
  and the others wait for its answer on their own loop. A leader that is cancelled (or interrupted) does not fail the
  others: each of them starts again, and one becomes the leader.
- The timeout covers the whole request, body read included. `httpx`'s own timeouts apply to each connect, write and
  read separately, so a server that trickles its answer would never trip them. `AsyncTokenSource` wraps the exchange
  in `asyncio.timeout`, which ends it at `timeout_seconds` wherever it is awaiting (not when the event loop itself is
  blocked). `TokenSource` starts no thread and cannot cancel a call that is blocked in the caller's thread, so it
  bounds the request with `httpx` per-operation timeouts, each set to the budget left when the request is issued, and a
  deadline check as soon as the headers are in and after every chunk of the body; it does not bound name resolution
  (`socket.getaddrinfo` cannot be interrupted). See the class docstring for the bound that gives.
- A caller that joins a request another caller started waits for it at most its own `timeout_seconds` plus a margin,
  and then gets `network_error` (`TimeoutError`): a leader that is stuck, on another thread or another event loop that
  is blocked, does not hold the followers.
- The request is built by `build_request` with only its own headers and sent with `Client.send`: a client that was
  passed in may carry default headers, cookies, auth or a base URL for another service, none of which is sent to the
  token endpoint. (`Client.stream` and `Client.post` would merge them in.)
- Anything that stops a request (an `httpx` error, an `OSError` from a transport, a closed client, a response that was
  read already) is `network_error`, as any rejection of `fetch` is in the original. A response that was read already
  (a response hook that reads it, or `httpx.MockTransport` with `json=`) is taken from `response.content` under the same
  1 MiB cap and `Content-Encoding` refusal.
- The message of an error for a token endpoint's refusal carries only the OAuth `error` code, once it is shown to be
  one (the original puts `error_description` in the message): the prose is `oauth_error_description`, capped, cleaned
  and redacted of the assertion, out of `str()` and `repr()`. An answer with a status that is not 2xx and no usable
  OAuth error says what it was (content type, size, whether JSON) in `cause`, never what it said.
- A redirect is `network_error` and is never followed: `follow_redirects=False` is passed to `Client.send`, which wins
  over a client that was built with `follow_redirects=True`, and a 3xx answer is refused before its body is read
  (`cause` `redirect_not_followed`, or `unexpected_3xx` for a 304, which is not a redirect).
- An answer larger than 1 MiB is `invalid_response` (the original reads without a limit). The limit applies to the
  bytes on the wire, not to what `httpx` would decode from them: the request sends `accept-encoding: identity`, an
  answer with any other `Content-Encoding` is `invalid_response` before its body is read, and the body is read raw.
  Otherwise a few kilobytes of gzip could inflate far past the limit before it was checked.
- The transport is `httpx`. Without an `http_client`, each request uses a client of its own, closed afterwards: a
  token is minted about once per token lifetime, so the pool would be idle, and the pooled connections of an
  `httpx.AsyncClient` belong to the event loop they were opened on. A client you pass is used as is and never
  closed; it must be an `httpx.Client` for `TokenSource` and an `httpx.AsyncClient` for `AsyncTokenSource`.
- A `ServicePrincipalError` from a failed token request has a `__cause__` (`raise ... from`), a `TransportFailure` that
  names the class of the exception underneath (`httpx.ConnectError`, `httpx.ReadTimeout`, `TimeoutError`) and nothing
  more: no message, no `request`, no `response`, no traceback. The original is not kept, because it holds its request
  and the request holds the signed assertion, and an error tracker that walks `__cause__` and captures frames with
  their locals would send them out. So a failure is debuggable by its class (and by the `cause` string, which names a
  timeout `TimeoutError` whatever its class), not by the transport's own message or traceback; the cost is that a
  detail such as `[Errno 61]` is lost. No frame of the error's own traceback holds the form, the key or the answer
  either. A failure with no exception underneath (a redirect, an answer that is not a token response) has no
  `__cause__`. Loading a credential keeps no chain at all, because `OSError.filename` and `JSONDecodeError.doc` would
  carry a path or the credential's text; see `credential.py`. Neither does the import failure of the private key,
  which is reported at the first request.
- Keys are imported with `cryptography`: ES256 for an EC P-256 key (the signature is the raw 64-byte `r || s` of
  RFC 7518 §3.4) and RS256 for an RSA key. An EC key whose `x` and `y` do not belong to `d`, and an RSA key without its
  CRT members (`p`, `q`, `dp`, `dq`, `qi`, which the WebCrypto of Node 26.7.0 and Bun also refuse to import a
  private key without, checked on 2026-11-10), are `invalid_credential` at the first request.
- Arguments that are a caller's mistake are `TypeError` or `ValueError`: `scopes` given as one string, an empty
  `scopes`, a scope that is not an OAuth scope token, a `refresh_skew_seconds` that is not a finite number of
  seconds from zero up, a `timeout_seconds` that is not a finite number above zero. An `audience` that is not an
  origin, and a credential that does not validate, are `ServicePrincipalError` (`invalid_credential`), as in the
  original. The original takes any URL scheme for the audience; here it is `http` or `https`, and a user part is
  refused.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import math
import re
import threading
import time
import unicodedata
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Literal, NoReturn, TypeVar
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from noblecloak.service_principal._b64 import b64url_decode
from noblecloak.service_principal._host import normal_host
from noblecloak.service_principal._json import INVALID, parse_json
from noblecloak.service_principal.credential import ServicePrincipalCredential
from noblecloak.service_principal.error import ServicePrincipalError

_ASSERTION_TYPE: Final = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
# Core accepts an assertion lifetime of at most 300 s.
_ASSERTION_LIFETIME_SECONDS: Final = 120
DEFAULT_REFRESH_SKEW_SECONDS: Final = 30.0
DEFAULT_TIMEOUT_SECONDS: Final = 10.0
_MIN_WAIT_MARGIN_SECONDS: Final = 0.05
_WAIT_MARGIN_FRACTION: Final = 0.1
MAX_RESPONSE_BYTES: Final = 1024 * 1024
_FORBIDDEN_IN_URL: Final = re.compile(r"[\x00-\x20\x7f\\]")
# RFC 6749 §3.3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
_SCOPE_TOKEN: Final = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]+", re.ASCII)
_NO_ANSWER: Final = "The token request did not get an answer."


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _json_segment(value: Mapping[str, object]) -> str:
    return _b64url(json.dumps(value, separators=(",", ":")).encode("utf-8"))


# --- keys -----------------------------------------------------------------------------------------


class _KeyRejected(ValueError):
    """A key member is missing or malformed. The message is fixed text: it never holds a member."""


@dataclass(frozen=True, slots=True)
class _Signer:
    alg: Literal["ES256", "RS256"]
    kid: str
    sign: Callable[[bytes], bytes]


def _member(jwk: Mapping[str, Any], name: str, *, length: int | None = None) -> bytes:
    value = jwk.get(name)
    raw = b64url_decode(value) if isinstance(value, str) else None
    if raw is None or raw == b"" or (length is not None and len(raw) != length):
        raise _KeyRejected(f"{name} is missing or malformed")
    return raw


def _thumbprint(jwk: Mapping[str, Any]) -> str:
    """The RFC 7638 thumbprint, which is the key id when the JWK has none. The members are base64url text that
    `_member` has checked, so they need no JSON escaping."""
    if jwk["kty"] == "EC":
        members = f'{{"crv":"P-256","kty":"EC","x":"{jwk["x"]}","y":"{jwk["y"]}"}}'
    else:
        members = f'{{"e":"{jwk["e"]}","kty":"RSA","n":"{jwk["n"]}"}}'
    return _b64url(hashlib.sha256(members.encode("ascii")).digest())


def _ec_signer(jwk: Mapping[str, Any]) -> tuple[Literal["ES256"], Callable[[bytes], bytes]]:
    x, y = _member(jwk, "x", length=32), _member(jwk, "y", length=32)
    key = ec.derive_private_key(int.from_bytes(_member(jwk, "d", length=32), "big"), ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    if numbers.x != int.from_bytes(x, "big") or numbers.y != int.from_bytes(y, "big"):
        raise _KeyRejected("x and y do not belong to d")

    def sign(data: bytes) -> bytes:
        # JWS wants the raw r || s (RFC 7518 §3.4); `cryptography` gives DER.
        r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    return "ES256", sign


def _rsa_signer(jwk: Mapping[str, Any]) -> tuple[Literal["RS256"], Callable[[bytes], bytes]]:
    def number(name: str) -> int:
        return int.from_bytes(_member(jwk, name), "big")

    numbers = rsa.RSAPrivateNumbers(
        p=number("p"),
        q=number("q"),
        d=number("d"),
        dmp1=number("dp"),
        dmq1=number("dq"),
        iqmp=number("qi"),
        public_numbers=rsa.RSAPublicNumbers(e=number("e"), n=number("n")),
    )
    key = numbers.private_key()  # checks that the members belong together; ValueError if not

    def sign(data: bytes) -> bytes:
        return key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    return "RS256", sign


def _create_signer(jwk: Mapping[str, Any]) -> _Signer:
    """Raises `ValueError` (a `_KeyRejected`, or one from `cryptography`) for a key that cannot be imported."""
    alg, sign = _ec_signer(jwk) if jwk.get("kty") == "EC" else _rsa_signer(jwk)
    kid = jwk.get("kid")
    return _Signer(alg, kid if isinstance(kid, str) and kid != "" else _thumbprint(jwk), sign)


# --- audience and scopes --------------------------------------------------------------------------


def _check_audience(audience: str) -> str:
    """The origin of `audience` in its normal form (lower-case host, no default port, no trailing slash)."""
    not_an_origin = ServicePrincipalError(
        "invalid_credential",
        "audience must be an origin (scheme, host and optional port; no path), such as https://govern.example.com.",
    )
    not_a_url = ServicePrincipalError(
        "invalid_credential", "audience must be the API origin, such as https://govern.example.com."
    )
    if _FORBIDDEN_IN_URL.search(audience):
        raise not_a_url
    try:
        parts = urlsplit(audience)
        host = parts.hostname
        port = parts.port
    except ValueError:
        raise not_a_url from None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not host:
        raise not_a_url
    if "@" in parts.netloc or parts.path not in ("", "/") or parts.query or parts.fragment:
        raise not_an_origin
    normal = normal_host(host)
    if normal is None:
        raise not_a_url
    shown = f"[{normal}]" if ":" in normal else normal
    default_port = 443 if scheme == "https" else 80
    return f"{scheme}://{shown}" if port in (None, default_port) else f"{scheme}://{shown}:{port}"


def _join_scopes(scopes: Sequence[str] | None) -> str | None:
    if scopes is None:
        return None
    if isinstance(scopes, str):
        raise TypeError("scopes must be a sequence of scope names, not one string")
    names = list(scopes)
    if not names:
        raise ValueError("scopes must not be empty; leave it out to get the principal's stored scopes")
    if not all(isinstance(name, str) and _SCOPE_TOKEN.fullmatch(name) for name in names):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise ValueError("each scope must be an OAuth scope token: no space, quote or backslash")
    return " ".join(names)


def _positive(value: float, name: str, *, allow_zero: bool) -> float:
    if isinstance(value, bool) or not math.isfinite(value) or value < 0 or (value == 0 and not allow_zero):
        raise ValueError(f"{name} must be a finite number of seconds, {'not negative' if allow_zero else 'positive'}")
    return float(value)


# --- one flight, and what comes of it -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Outcome:
    token: str | None = field(default=None, repr=False)
    error: Exception | None = None
    # With neither set: the leader was interrupted (cancelled), and the callers that waited on it start again.


class Flight:
    """One request to the token endpoint, and the callers waiting for its answer."""

    __slots__ = ("event", "expires", "followers", "generation", "outcome", "waiters")

    def __init__(self, generation: int, expires: float) -> None:
        self.generation = generation
        # After this (monotonic) time its leader has outlived any bound it was given: a caller that finds the flight
        # then does not join it but starts a request of its own.
        self.expires = expires
        self.followers = 0  # how many callers have joined it; only ever goes up
        self.event = threading.Event()  # what a `TokenSource` caller waits on
        self.outcome: Outcome | None = None
        # What an `AsyncTokenSource` caller waits on: its own loop's future.
        self.waiters: list[tuple[asyncio.AbstractEventLoop, asyncio.Future[Outcome]]] = []


def _deliver(future: asyncio.Future[Outcome], outcome: Outcome) -> None:
    if not future.done():
        future.set_result(outcome)


def unwrap(outcome: Outcome) -> str | None:
    """The token, or None when the caller must start again. Raises the leader's error. A `ServicePrincipalError` is
    raised as a copy, since one exception object raised in several callers would collect all their tracebacks."""
    if outcome.token is not None:
        return outcome.token
    error = outcome.error
    if error is None:
        return None
    if isinstance(error, ServicePrincipalError):
        raise ServicePrincipalError(
            error.code,
            str(error),
            status=error.status,
            oauth_error=error.oauth_error,
            oauth_error_description=error.oauth_error_description,
            cause=error.cause,
        ) from error.__cause__
    raise error


Phase = Literal["request", "body"]


class TransportFailure(Exception):
    """Stands in for the exception that stopped a token request, as the `__cause__` of the `ServicePrincipalError`.

    It names the class of the original (`httpx.ReadTimeout`) and nothing else: no message, no `request`, no `response`,
    no traceback, no `__context__`. The original holds the request, and so the signed assertion, and its traceback holds
    the frames that built it; an error tracker that walks `__cause__` and captures frames with their locals would
    send them out. A message is left out too, because a transport that was passed in may put anything in one.
    """


@dataclass(frozen=True, slots=True)
class Failure:
    """A request that got no usable answer: where it stopped (`request` or `body`), the name of what stopped it (see
    `describe`) and a `TransportFailure` standing in for the exception. The exception itself is not kept."""

    phase: Phase
    cause: str
    error: TransportFailure


def failure_of(phase: Phase, error: BaseException) -> Failure:
    """The `Failure` for `error`, which is let go once the caller leaves its `except` block."""
    surrogate = TransportFailure(f"{type(error).__module__}.{type(error).__qualname__}")
    surrogate.__traceback__ = None
    surrogate.__cause__ = None
    surrogate.__context__ = None
    return Failure(phase, describe(error), surrogate)


@dataclass(frozen=True, slots=True)
class Reply:
    """What came back from one exchange, before it is read as a token response."""

    status: int = 0
    # The answer read as a token response (or as the error to raise), made where the body is known, so that no frame
    # of the error that is raised later holds the body or the assertion. It may hold an access token.
    result: tuple[str, float] | ServicePrincipalError | None = field(default=None, repr=False)
    redirect: str | None = None  # a 3xx answer, refused before its body is read: the `cause` for it
    too_large: bool = False
    encoded: bool = False  # a `Content-Encoding` other than identity: refused before the body is read
    failure: Failure | None = None


class Deadline(TimeoutError):
    """The exchange ran past its deadline."""


def describe(error: BaseException) -> str:
    """A short, safe name for what went wrong: the class name, and `TimeoutError` for any kind of timeout, so that
    the same failure has the same name in the sync and the async source."""
    if isinstance(error, TimeoutError | httpx.TimeoutException):
        return "TimeoutError"
    return type(error).__name__


# --- what differs between the sync and the async source -------------------------------------------
#
# `_async/token.py` is the source of the two. `scripts/generate_sync.py` turns it into `_sync/token.py` with
# `unasync`, which drops `async` and `await` and renames names; the pairs below are what a renamed name stands for.
# Each `async_x` is the async source's `x`, and each `sync_x` the sync source's, and the generator renames the one to
# the other.

_Waiter = TypeVar("_Waiter")


def deadline_after(seconds: float) -> float:
    return time.monotonic() + seconds


def async_scope(seconds: float) -> asyncio.Timeout:
    """What bounds the whole exchange: `asyncio.timeout`, which cancels it at the deadline."""
    return asyncio.timeout(seconds)


def sync_scope(seconds: float) -> contextlib.nullcontext[None]:
    """The sync source cannot cancel a blocked call: it has no scope, only per-operation timeouts and a deadline."""
    del seconds
    return contextlib.nullcontext()


def async_timeout(deadline: float) -> httpx.Timeout:
    """The `httpx` timeouts of the request. The async source has none: `asyncio.timeout` bounds all of it, and two
    clocks that expire together would make the error depend on which one won."""
    del deadline
    return httpx.Timeout(None)


def sync_timeout(deadline: float) -> httpx.Timeout:
    """The `httpx` timeouts of the request: connect, write, read and pool each get the budget that is left."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise Deadline
    return httpx.Timeout(remaining)


def async_tick(deadline: float) -> None:
    """Called after each chunk of the body. The async source needs no check: `asyncio.timeout` cancels it."""
    del deadline


def sync_tick(deadline: float) -> None:
    """Called after each chunk of the body, and at its end: raises `Deadline` once the deadline has passed."""
    if time.monotonic() > deadline:
        raise Deadline


def async_check_client(client: object) -> None:
    """The client that was passed, if any, must be the async source's kind."""
    if client is not None and not isinstance(client, httpx.AsyncClient):
        raise TypeError("AsyncTokenSource needs an httpx.AsyncClient")


def sync_check_client(client: object) -> None:
    """The client that was passed, if any, must be the sync source's kind."""
    if client is not None and not isinstance(client, httpx.Client):
        raise TypeError("TokenSource needs an httpx.Client")


def async_enlist(flight: Flight) -> asyncio.Future[Outcome]:
    """Joins `flight` from the running event loop; the leader delivers the outcome to that loop's future."""
    loop = asyncio.get_running_loop()
    future: asyncio.Future[Outcome] = loop.create_future()
    flight.waiters.append((loop, future))
    return future


def wait_expired() -> Outcome:
    """What a follower is told when the request it joined has not answered in time: the same `network_error` as for a
    request of its own that timed out."""
    error = ServicePrincipalError(
        "network_error", "Timed out waiting for the token request that another caller started.", cause="TimeoutError"
    )
    error.__cause__ = failure_of("request", TimeoutError()).error
    return Outcome(error=error)


async def async_wait(waiter: asyncio.Future[Outcome], seconds: float) -> Outcome:
    """The leader's outcome, or `wait_expired()` after `seconds`. The wait is on this caller's own loop, so it ends on
    time even when the leader's loop is blocked."""
    try:
        return await asyncio.wait_for(waiter, seconds)
    except TimeoutError:
        return wait_expired()


def sync_enlist(flight: Flight) -> Flight:
    """Joins `flight` from a thread: it waits on the flight's event."""
    return flight


def sync_wait(flight: Flight, seconds: float) -> Outcome:
    """The leader's outcome, or `wait_expired()` after `seconds`."""
    if not flight.event.wait(seconds):
        return wait_expired()
    assert flight.outcome is not None
    return flight.outcome


# --- the shared core ------------------------------------------------------------------------------


class Core:
    """What the two sources share: the validated arguments, the cache, the flight and the request's form."""

    def __init__(
        self,
        credential: ServicePrincipalCredential,
        *,
        audience: str,
        scopes: Sequence[str] | None,
        clock: Callable[[], float],
        refresh_skew_seconds: float,
        timeout_seconds: float,
    ) -> None:
        self._credential = credential
        self._resource = _check_audience(audience)
        self._scope = _join_scopes(scopes)
        self._clock = clock
        self._skew = _positive(refresh_skew_seconds, "refresh_skew_seconds", allow_zero=True)
        self._timeout = _positive(timeout_seconds, "timeout_seconds", allow_zero=False)
        margin = max(_MIN_WAIT_MARGIN_SECONDS, self._timeout * _WAIT_MARGIN_FRACTION)
        # How long a caller that joins another's request waits for it: its own `timeout_seconds`, and a margin.
        self._wait_bound = self._timeout + margin
        # How long a request may be joined. Past this, a later caller starts its own request rather than joining one
        # whose leader may be stuck before its headers (a sync leader is not deadline-bound there).
        self._flight_life = 2 * self._timeout + margin
        # `_lock` guards `_cached`, `_inflight` and `_generation`; `_signer_lock` guards `_signer`. `_lock` is never
        # held while waiting, signing or talking to the network; `_signer_lock` is held while a key is imported.
        self._lock = threading.Lock()
        self._cached: tuple[str, float] | None = None  # the token, and the time until which it is served
        self._inflight: Flight | None = None
        # Bumped by `invalidate()`: a request that started under an older generation does not write the cache.
        self._generation = 0
        self._signer: _Signer | None = None
        self._signer_lock = threading.Lock()

    def __reduce_ex__(self, protocol: object) -> NoReturn:
        # A source holds the credential, and so a private key: pickle, `copy.copy` and `copy.deepcopy` (which fall back
        # to this) refuse it, and it is not sent to another process by accident.
        raise TypeError(f"{type(self).__name__} holds a private key and is not serialisable")

    def invalidate(self) -> None:
        """Drops the cached token, so the next `get_token` mints a new one. A request already under way still
        answers the callers that were waiting for it, but its token is not cached."""
        with self._lock:
            self._generation += 1
            self._cached = None
            self._inflight = None

    # -- the cache and the flight, under `_lock` --

    def _fresh_token(self) -> str | None:
        cached = self._cached
        return cached[0] if cached is not None and self._clock() < cached[1] else None

    def _claim(
        self, enlist: Callable[[Flight], _Waiter], led: list[Flight]
    ) -> tuple[str | None, Flight | None, _Waiter | None]:
        """What a `get_token` caller does next, decided under the lock: use the cached token `(token, None, None)`;
        start the request `(None, flight, None)`, as its leader; or wait for the leader's `(None, flight, waiter)`.
        A flight that is past its life (its leader is stuck) is not joined. A flight this caller starts is put in `led`
        before it is installed, so that the caller can complete it on any exception from there on."""
        with self._lock:
            token = self._fresh_token()
            if token is not None:
                return token, None, None
            flight = self._inflight
            if flight is None or time.monotonic() > flight.expires:
                return None, self._begin(led), None
            flight.followers += 1
            return None, flight, enlist(flight)

    def _begin(self, led: list[Flight]) -> Flight:
        flight = Flight(self._generation, deadline_after(self._flight_life))
        led.append(flight)
        self._inflight = flight
        return flight

    def _abandon(self, led: list[Flight]) -> None:
        """Completes the flights a caller started and did not complete, because it was interrupted: its followers start
        again. Called for any `BaseException` that leaves `get_token`, so that no flight outlives its leader."""
        for flight in led:
            self._complete(flight, Outcome())

    def _complete(self, flight: Flight, outcome: Outcome) -> None:
        """Completes `flight` once (the first outcome stands) and gives the outcome to everyone waiting. It may be
        called again for the same flight (by `_abandon`): then it only gives the outcome to whoever is left."""
        with self._lock:
            if flight.outcome is None:
                flight.outcome = outcome
            # An invalidate() may have replaced `_inflight` already; clear only our own.
            if self._inflight is flight:
                self._inflight = None
            waiters, flight.waiters = flight.waiters, []
            outcome = flight.outcome
        flight.event.set()
        for loop, future in waiters:
            with contextlib.suppress(RuntimeError):  # that loop is closed: its caller is gone
                loop.call_soon_threadsafe(_deliver, future, outcome)

    # -- the request --

    def _get_signer(self) -> _Signer:
        """The signer, made once. A key that cannot be imported is retried at the next request."""
        with self._signer_lock:
            if self._signer is None:
                rejected: str | None = None
                try:
                    self._signer = _create_signer(self._credential.private_jwk)
                except ValueError as exc:
                    rejected = str(exc) if isinstance(exc, _KeyRejected) else describe(exc)
                if self._signer is None:
                    raise ServicePrincipalError(
                        "invalid_credential", "The private key could not be imported for signing.", cause=rejected
                    )
            return self._signer

    def _assertion(self) -> str:
        signer = self._get_signer()
        issued_at = math.floor(self._clock())
        credential = self._credential
        header = {"alg": signer.alg, "typ": "JWT", "kid": signer.kid}
        claims = {
            "iss": credential.client_id,
            "sub": credential.client_id,
            "aud": credential.assertion_audience,
            "iat": issued_at,
            "exp": issued_at + _ASSERTION_LIFETIME_SECONDS,
            "jti": str(uuid.uuid4()),
        }
        signing_input = f"{_json_segment(header)}.{_json_segment(claims)}"
        return f"{signing_input}.{_b64url(signer.sign(signing_input.encode('ascii')))}"

    def _form(self) -> dict[str, str]:
        form = {
            "grant_type": "client_credentials",
            "client_id": self._credential.client_id,
            "client_assertion_type": _ASSERTION_TYPE,
            "client_assertion": self._assertion(),
            "resource": self._resource,
        }
        if self._scope is not None:
            form["scope"] = self._scope
        return form

    def _read(self, reply: Reply) -> tuple[str, float]:
        """The token and its life in seconds; raises the typed error for anything but a bearer token."""
        if reply.failure is not None:
            failure = reply.failure
            message = "The token response could not be read to the end." if failure.phase == "body" else _NO_ANSWER
            raise ServicePrincipalError("network_error", message, cause=failure.cause) from failure.error
        if reply.redirect is not None:
            # A redirect would re-send the signed assertion to the Location; fail closed instead.
            raise ServicePrincipalError("network_error", _NO_ANSWER, status=reply.status, cause=reply.redirect)
        if reply.encoded:
            raise ServicePrincipalError(
                "invalid_response",
                "The token endpoint's answer has a Content-Encoding; the request asked for none.",
                status=reply.status,
            )
        if reply.too_large:
            raise ServicePrincipalError(
                "invalid_response", "The token endpoint's answer is larger than 1 MiB.", status=reply.status
            )
        result = reply.result
        assert result is not None  # a reply with none of the flags above has a result
        if isinstance(result, ServicePrincipalError):
            # Raised here and not where it was made: the frame that made it holds the answer and the assertion.
            raise result
        return result

    def _secrets(self, assertion: str) -> list[str]:
        """What a token endpoint must not be able to make an error repeat: the assertion that was sent, its parts and
        the private members of the key."""
        members = [self._credential.private_jwk.get(name) for name in _PRIVATE_MEMBERS]
        found = [assertion, *assertion.split("."), *(m for m in members if isinstance(m, str))]
        return [secret for secret in found if len(secret) >= _MIN_SECRET]

    def _answer(self, status: int, body: bytes, content_type: str | None, form: Mapping[str, str]) -> Reply:
        """The `Reply` for a whole answer: too large, or read as a token response (or as the error for it)."""
        if len(body) > MAX_RESPONSE_BYTES:
            return Reply(status=status, too_large=True)
        return Reply(status=status, result=self._parse(status, body, content_type, form["client_assertion"]))

    def _parse(
        self, status: int, body: bytes, content_type: str | None, assertion: str
    ) -> tuple[str, float] | ServicePrincipalError:
        """The token and its life, or the error to raise for an answer that is not a bearer token. The error is returned
        and not raised, so that its traceback holds no frame with the body in it."""
        try:
            text: str | None = body.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        parsed = INVALID if text is None else parse_json(text)
        record: dict[str, Any] = parsed if isinstance(parsed, dict) else {}  # pyright: ignore[reportUnknownVariableType]
        if not 200 <= status < 300:
            return self._rejection(
                status, record, self._secrets(assertion), _answer_facts(content_type, body, parsed is not INVALID)
            )
        token, token_type = record.get("access_token"), record.get("token_type")
        life = _lifetime(record.get("expires_in"))
        if (
            not isinstance(token, str)
            or token == ""
            or not isinstance(token_type, str)
            or token_type.lower() != "bearer"
            or life is None
        ):
            return ServicePrincipalError(
                "invalid_response",
                "The token endpoint answered 200 without a bearer access_token and a positive expires_in.",
                status=status,
            )
        return token, life

    @staticmethod
    def _rejection(status: int, record: Mapping[str, Any], secrets: Sequence[str], facts: str) -> ServicePrincipalError:
        """The error for a non-2xx answer. Only the OAuth `error`, once it is shown to be an error code, goes in the
        message; the server's prose goes in `oauth_error_description`."""
        oauth_error = record.get("error")
        if not isinstance(oauth_error, str) or not _OAUTH_ERROR.fullmatch(oauth_error) or _echoes(oauth_error, secrets):
            return ServicePrincipalError(
                "invalid_response",
                f"The token endpoint answered {status} without a usable OAuth error.",
                status=status,
                cause=facts,
            )
        description = record.get("error_description")
        shown = _clean_description(description, secrets) if isinstance(description, str) else None
        if oauth_error == "invalid_client":
            return ServicePrincipalError(
                "invalid_client",
                "The token endpoint rejected the service principal (invalid_client): it is revoked or expired, "
                "or its key is not registered, or this machine's clock is more than 60 seconds off. "
                "Check the clock; otherwise rotate its key or create a new service principal.",
                status=status,
                oauth_error=oauth_error,
                oauth_error_description=shown,
            )
        return ServicePrincipalError(
            "token_request_rejected",
            f"The token endpoint refused the request ({oauth_error}).",
            status=status,
            oauth_error=oauth_error,
            oauth_error_description=shown,
        )

    def _store(self, generation: int, token: str, life: float) -> None:
        """Caches the token until shortly before it expires, unless an invalidate() came after the request began."""
        refresh_at = min(self._skew, life / 2)
        with self._lock:
            if generation == self._generation:
                self._cached = (token, self._clock() + life - refresh_at)


def _lifetime(expires_in: object) -> float | None:
    """`expires_in` as seconds, or None unless it is a finite number above zero (a JSON number, not a `bool`)."""
    if isinstance(expires_in, bool) or not isinstance(expires_in, int | float):
        return None
    try:
        life = float(expires_in)
    except OverflowError:
        return None
    return life if math.isfinite(life) and life > 0 else None


def has_content_encoding(headers: httpx.Headers) -> bool:
    """Whether the answer says it is encoded. Only an absent `Content-Encoding` or `identity` is not."""
    value = headers.get("content-encoding")
    return value is not None and value.strip().lower() != "identity"


def redirect_cause(status: int) -> str:
    """Why a 3xx answer is refused: `redirect_not_followed` (it would send the signed assertion on to the `Location`),
    or `unexpected_3xx` for 304, which is not a redirect and which a request with no validators cannot get."""
    return "unexpected_3xx" if status == 304 else "redirect_not_followed"


def build_request(url: str, form: Mapping[str, str], timeout: httpx.Timeout) -> httpx.Request:
    """The token request, with only its own headers. It is built here and sent with `Client.send`, which merges
    nothing: `Client.build_request` would add the client's default headers, cookies and base URL, and a caller's client
    may carry an `Authorization` or an API key for another service. `identity`: no compression, so that the size limit
    counts what is on the wire and a small answer cannot inflate. The timeout travels as the request's extension, which
    is where `httpx` puts it."""
    return httpx.Request(
        "POST",
        url,
        headers={"accept": "application/json", "accept-encoding": "identity"},
        data=form,
        extensions={"timeout": timeout.as_dict()},
    )


_TCHAR: Final = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_MEDIA_TYPE: Final = re.compile(f"{_TCHAR}/{_TCHAR}", re.ASCII)
# RFC 6749 §5.2: error = 1*( %x20-21 / %x23-5B / %x5D-7E ); and an error code is short.
_OAUTH_ERROR: Final = re.compile(r"[\x20\x21\x23-\x5b\x5d-\x7e]{1,64}", re.ASCII)
_MAX_DESCRIPTION: Final = 200
_REDACTED: Final = "[redacted]"
_MIN_SECRET: Final = 8
_PRIVATE_MEMBERS: Final = ("d", "p", "q", "dp", "dq", "qi")


def _answer_facts(content_type: str | None, body: bytes, was_json: bool) -> str:
    """What may be said about an answer that is not a token response and has no usable OAuth error: its media type (only
    when it is `type/subtype` of RFC 7230 token characters, which holds no text of the server's), its size and whether
    it was JSON. Never the body."""
    facts: list[str] = []
    media = None if content_type is None else content_type.split(";", 1)[0].strip().lower()
    if media is not None and len(media) <= 100 and _MEDIA_TYPE.fullmatch(media):
        facts.append(f"content_type={media}")
    facts.append(f"body_bytes={len(body)}")
    facts.append(f"json={'true' if was_json else 'false'}")
    return "; ".join(facts)


def _clean_description(text: str, secrets: Sequence[str]) -> str:
    """Server text for a person to read: control characters removed, each secret replaced, at most 200 characters.
    The secrets are replaced after the control characters are gone (so one cannot be split by them) and before the text
    is cut (so a cut cannot leave half of one)."""
    plain = "".join(char for char in text if not unicodedata.category(char).startswith("C"))
    for secret in sorted(secrets, key=len, reverse=True):
        plain = plain.replace(secret, _REDACTED)
    return plain[:_MAX_DESCRIPTION]


def _echoes(text: str, secrets: Sequence[str]) -> bool:
    """Whether `text` is, holds or is a long part of one of the secrets."""
    return any(secret in text or (len(text) >= 16 and text in secret) for secret in secrets)
