"""What the sync and the async client share: validation of the arguments, the request and its authorization, the
reading of an answer. Nothing here sends a request.

`_async/client.py` is the source of the two clients. `scripts/generate_sync.py` turns it into `_sync/client.py` with
`unasync`, which drops `async` and `await` and renames names; the pairs below are what a renamed name stands for. Each
`async_x` is the async client's `x` and each `sync_x` the sync client's, and the generator renames the one to the other.
"""

from __future__ import annotations

import inspect
import json
import math
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any, Final, Literal, cast
from urllib.parse import quote, urlsplit

import httpx
from pydantic import BaseModel, ValidationError

from noblecloak.client.types import (
    Answer,
    ApprovalsPage,
    DpopRequest,
    ModuleApiError,
    Ok,
    Problem,
)
from noblecloak.models import Approval
from noblecloak.service_principal._host import normal_host  # pyright: ignore[reportPrivateUsage]

DEFAULT_TIMEOUT_SECONDS: Final = 30.0
WAIT_MARGIN_SECONDS: Final = 10.0
"""How long `wait_approval` reads for the answer beyond the seconds it asked the server to wait."""

_FORBIDDEN_IN_URL: Final = re.compile(r"[\x00-\x20\x7f\\]")
_CREDENTIAL_TEXT: Final = re.compile(r"[\x21-\x7e]+", re.ASCII)
_LOOPBACK: Final = frozenset({"localhost", "127.0.0.1", "::1"})
_MAX_LOCATIONS: Final = 5
_MAX_DETAIL: Final = 200

type Unwrap[T] = Callable[[object, Mapping[str, Any]], T]
"""Turns an envelope's `data` (and the envelope, for `meta`) into the operation's result, or raises `ModuleApiError`."""

AsyncTokenGetter = Callable[[], str | Awaitable[str]]
TokenGetter = Callable[[], str]
AsyncProofHook = Callable[[DpopRequest], str | Awaitable[str]]
ProofHook = Callable[[DpopRequest], str]


class NoBody:
    """Marks a request without a body (`None` is a JSON value, `null`, that a caller may mean)."""


NO_BODY: Final = NoBody()


class Misuse(TypeError):
    """A caller's mistake that is found while a request is being made (`get_token` or `dpop_proof` returned something
    that is not a token or a proof). It is never turned into `unreachable`: that would have a retry loop run a bug
    again and again."""


# --- arguments --------------------------------------------------------------------------------------


def check_base_url(base_url: str) -> str:
    """`base_url` in its normal form (lower-case host, no default port, no trailing slash). `https`, or `http` for
    `localhost`, `127.0.0.1` and `[::1]` only: a token is sent with every request. A path prefix is kept. The error
    never echoes the value."""
    if not isinstance(base_url, str):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise TypeError("base_url must be a string")
    refused = ValueError("base_url must be an https URL (http only for localhost), such as https://govern.example.com")
    if _FORBIDDEN_IN_URL.search(base_url):
        raise refused
    try:
        parts = urlsplit(base_url)
        host = parts.hostname
        port = parts.port
    except ValueError:
        raise refused from None
    scheme = parts.scheme.lower()
    if not host or port == 0 or "@" in parts.netloc or "?" in base_url or "#" in base_url:
        raise refused
    normal = normal_host(host)
    if normal is None or (scheme != "https" and not (scheme == "http" and normal in _LOOPBACK)):
        raise refused
    shown = f"[{normal}]" if ":" in normal else normal
    default_port = 443 if scheme == "https" else 80
    origin = f"{scheme}://{shown}" if port in (None, default_port) else f"{scheme}://{shown}:{port}"
    return origin + parts.path.rstrip("/")


def positive(value: float, name: str) -> float:
    if isinstance(value, bool) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a finite number of seconds above zero")
    return float(value)


def check_path(path: str) -> str:
    """A path for `request`: it starts with one `/` and carries no query or fragment (those are `params`)."""
    if not isinstance(path, str):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise TypeError("path must be a string")
    if (
        not path.startswith("/")
        or path.startswith("//")
        or _FORBIDDEN_IN_URL.search(path)
        or "?" in path
        or "#" in path
    ):
        raise ValueError("path must start with one '/', and carry no query, fragment, space or backslash")
    return path


def segment(value: str, name: str) -> str:
    """One path segment, percent-encoded as `encodeURIComponent` does, so that an id cannot add a segment or a query.
    `.` and `..` are refused: percent-encoding leaves them as they are and `httpx` resolves them as dot segments, which
    would send the request to another route."""
    if not isinstance(value, str):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise TypeError(f"{name} must be a string")
    if value == "":
        raise ValueError(f"{name} must not be empty")
    if value in (".", ".."):
        raise ValueError(f"{name} must not be '.' or '..'")
    return quote(value, safe="")


IDEMPOTENCY_KEY_MAX: Final = 255


def key_header(value: str, name: str) -> str:
    """An `Idempotency-Key`: 1 to 255 characters of printable ASCII, without a space (the spec's `minLength` and
    `maxLength`)."""
    if not isinstance(value, str):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise TypeError(f"{name} must be a string")
    if _CREDENTIAL_TEXT.fullmatch(value) is None or len(value) > IDEMPOTENCY_KEY_MAX:
        raise ValueError(f"{name} must be 1 to {IDEMPOTENCY_KEY_MAX} characters of printable ASCII without spaces")
    return value


def wait_seconds(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise TypeError("timeout_seconds must be an integer number of seconds")
    if value < 0:
        raise ValueError("timeout_seconds must not be negative")
    return value


def check_credential_text(value: object, what: str) -> str:
    """A token or a DPoP proof as it goes into a header: a non-empty string of printable ASCII without a space. Never
    echoed."""
    if not isinstance(value, str) or _CREDENTIAL_TEXT.fullmatch(value) is None:
        raise Misuse(f"{what} must return a non-empty string of printable ASCII without spaces")
    return value


def _plain(value: object, strip_none: bool) -> object:
    """`value` with every model in it dumped as what was set on it, and every `Mapping` and list rebuilt as a `dict`
    and a `list`, which is what `json` takes. With `strip_none`, a model field that is `None` is left out (a `None`
    inside a dict or a list is a value and stays)."""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_unset=True, exclude_none=strip_none)
    if isinstance(value, Mapping):
        return {key: _plain(item, strip_none) for key, item in cast("Mapping[Any, object]", value).items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item, strip_none) for item in cast("Sequence[object]", value)]
    return value


def encode_body(body: object, *, strip_none: bool = False) -> bytes | None:
    """The JSON of a request body. A model is dumped as what was set on it, also when it is inside a `Mapping` or a
    list. `strip_none` leaves out a model field that was set to `None`: the typed operations send it, because no
    request schema they use has a nullable member, and the server answers 400 to a `null` where it expects an object;
    `request` does not, so a `null` that means something to a route is still sent. NaN and infinities are refused
    (`ValueError`) whichever `httpx` version is installed, and so is a body that contains itself or is nested too
    deeply; nothing is sent."""
    if isinstance(body, NoBody):
        return None
    try:
        text = json.dumps(_plain(body, strip_none), allow_nan=False, ensure_ascii=False, separators=(",", ":"))
    except RecursionError:
        raise ValueError("a request body must not contain itself or be nested too deeply") from None
    return text.encode("utf-8")


def message_of(error: BaseException) -> str:
    """The message of any raised value; the class name when it has none (`httpx.ReadTimeout` often has none)."""
    return str(error) or type(error).__name__


# --- what differs between the sync and the async client ---------------------------------------------


async def async_token(get_token: AsyncTokenGetter) -> str:
    """The access token for one request: `get_token()`, awaited when it returns an awaitable."""
    token = get_token()
    if inspect.isawaitable(token):
        token = await token
    return check_credential_text(token, "get_token")


def sync_token(get_token: TokenGetter) -> str:
    """The access token for one request. A coroutine function is a mistake the sync client names, not one it sends."""
    token: object = get_token()
    if inspect.isawaitable(token):
        if inspect.iscoroutine(token):
            token.close()
        raise Misuse("get_token returned an awaitable; use AsyncModuleClient for an async token source")
    return check_credential_text(token, "get_token")


async def async_proof(dpop_proof: AsyncProofHook, request: DpopRequest) -> str:
    proof = dpop_proof(request)
    if inspect.isawaitable(proof):
        proof = await proof
    return check_credential_text(proof, "dpop_proof")


def sync_proof(dpop_proof: ProofHook, request: DpopRequest) -> str:
    proof: object = dpop_proof(request)
    if inspect.isawaitable(proof):
        if inspect.iscoroutine(proof):
            proof.close()
        raise Misuse("dpop_proof returned an awaitable; use AsyncModuleClient for an async proof hook")
    return check_credential_text(proof, "dpop_proof")


def async_check_client(client: object, transport: object) -> None:
    """What was passed in must be the async client's kind, and a client and a transport are not both given."""
    if client is not None and transport is not None:
        raise ValueError("pass http_client or transport, not both")
    if client is not None and not isinstance(client, httpx.AsyncClient):
        raise TypeError("AsyncModuleClient needs an httpx.AsyncClient")
    if transport is not None and not isinstance(transport, httpx.AsyncBaseTransport):
        raise TypeError("AsyncModuleClient needs an httpx.AsyncBaseTransport")


def sync_check_client(client: object, transport: object) -> None:
    """What was passed in must be the sync client's kind, and a client and a transport are not both given."""
    if client is not None and transport is not None:
        raise ValueError("pass http_client or transport, not both")
    if client is not None and not isinstance(client, httpx.Client):
        raise TypeError("ModuleClient needs an httpx.Client")
    if transport is not None and not isinstance(transport, httpx.BaseTransport):
        raise TypeError("ModuleClient needs an httpx.BaseTransport")


# --- reading an answer ------------------------------------------------------------------------------

_UNREADABLE: Final = object()


def _body(response: httpx.Response) -> object:
    """The JSON of the body; None for an empty body, `_UNREADABLE` for a body that is not JSON or is nested so deeply
    that it cannot be parsed."""
    if not response.content:
        return None
    try:
        return cast("object", response.json())
    except (ValueError, RecursionError):
        return _UNREADABLE


def json_of(response: httpx.Response) -> object:
    """The JSON of a body that has to be JSON: a `ValueError` when it is empty or is not."""
    return cast("object", response.json())


def problem_of(status: int, error: object) -> Problem:
    """The code is the last segment of the problem's `type`, `detail` is kept only when it is a string."""
    type_ = ""
    detail: str | None = None
    if isinstance(error, dict):
        body = cast("dict[str, object]", error)
        raw_type, raw_detail = body.get("type"), body.get("detail")
        type_ = raw_type if isinstance(raw_type, str) else ""
        detail = raw_detail if isinstance(raw_detail, str) else None
    return Problem(status=status, code=type_[type_.rfind("/") + 1 :], detail=detail)


# C0 and C1 controls, the Unicode line and paragraph separators, and the bidi embeddings, overrides and isolates.
_CONTROL: Final = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def _shown(text: str) -> str:
    """Server text as it goes into a message: control characters (a line break, an escape, a bidi override) become
    spaces and it is cut at `_MAX_DETAIL`."""
    return _CONTROL.sub(" ", text)[:_MAX_DETAIL]


def _server_failure(status: int, body: object) -> ModuleApiError:
    """`unreachable` for a 5xx. What the body says goes on the error: `problem` (status, code, detail) and
    `request_id`. The message names only the code and the request id, each cut at `_MAX_DETAIL`: the server's free
    `detail` stays on `problem` and out of `str()` and `repr()`, which is what lands in logs. A body that is empty,
    not JSON or not a problem leaves the message at `/v1 answered <status>`."""
    problem = problem_of(status, body)
    raw_id = cast("dict[str, object]", body).get("request_id") if isinstance(body, dict) else None
    request_id = raw_id if isinstance(raw_id, str) and raw_id else None
    named = [
        part
        for part in (problem.code and _shown(problem.code), request_id and f"request_id {_shown(request_id)}")
        if part
    ]
    message = f"/v1 answered {status}" + (f" ({', '.join(named)})" if named else "")
    return ModuleApiError("unreachable", message, problem=problem, request_id=request_id)


def answer_of[T](response: httpx.Response, unwrap: Unwrap[T]) -> Answer[T]:
    """A 5xx is `unreachable`, with what its body says (`_server_failure`); another status that is not 2xx (a 4xx, and a
    redirect, which is never followed) is a `Problem`; a 2xx has to be an envelope with a `data` member."""
    status = response.status_code
    body = _body(response)
    if status >= 500:
        raise _server_failure(status, body)
    if not response.is_success:
        return problem_of(status, body)
    if body is _UNREADABLE:
        raise ModuleApiError("unreachable", f"/v1 answered {status} with a body that is not JSON")
    if not isinstance(body, dict) or "data" not in body:
        raise ModuleApiError("unreachable", f"/v1 answered {status} without a data member")
    envelope = cast("dict[str, Any]", body)
    return Ok(unwrap(envelope["data"], envelope))


def _not_a(name: str, error: ValidationError) -> ModuleApiError:
    """`unreachable` for data that is not a `name`. The message says where (the locations of the first few faults),
    never what was there: a Resumption's `resume_token` must not end up in a log through a validation message."""
    locations = [
        ".".join(str(part) for part in fault["loc"])
        for fault in error.errors(include_url=False, include_context=False, include_input=False)[:_MAX_LOCATIONS]
    ]
    where = ", ".join(location or "(root)" for location in locations)[:_MAX_DETAIL]
    return ModuleApiError("unreachable", f"/v1 answered data that is not a {name} (at: {where})")


def model_of[M: BaseModel](model: type[M]) -> Unwrap[M]:
    """Validates `data` as `model`; what does not validate is `unreachable`, not a `Problem` and not a guess."""

    def unwrap(data: object, envelope: Mapping[str, Any]) -> M:
        del envelope
        try:
            return model.model_validate(data)
        except ValidationError as error:
            refusal = _not_a(model.__name__, error)
        raise refusal  # outside the `except`, so that the ValidationError, which holds the input, is not `__context__`

    return unwrap


def page_of(data: object, envelope: Mapping[str, Any]) -> ApprovalsPage:
    """A page that is not a list, or a cursor that is neither a string nor null, is an unreadable answer, not an empty
    one: reading it as "no approvals" would leave answered approvals alone."""
    if not isinstance(data, list):
        raise ModuleApiError("unreachable", "/v1 answered an approvals page whose data is not an array")
    meta: object = envelope.get("meta")
    cursor = cast("dict[str, object]", meta).get("next") if isinstance(meta, dict) else None
    if cursor is not None and not isinstance(cursor, str):
        raise ModuleApiError("unreachable", "/v1 answered an approvals page whose meta.next is not a string or null")
    check = model_of(Approval)
    return ApprovalsPage(rows=[check(row, envelope) for row in cast("list[object]", data)], next=cursor)


# --- the shared core --------------------------------------------------------------------------------


def _never(error: Exception) -> bool:
    del error
    return False


class Core:
    """The configuration and the non-I/O steps of a client; `_async/client.py` adds the I/O."""

    def __init__(
        self, base_url: str, *, timeout_seconds: float, is_pass_through: Callable[[Exception], bool] | None
    ) -> None:
        self._base = check_base_url(base_url)
        self._timeout = positive(timeout_seconds, "timeout_seconds")
        self._is_pass_through = _never if is_pass_through is None else is_pass_through

    @property
    def base_url(self) -> str:
        """The base URL in its normal form: lower-case host, no default port, no trailing slash."""
        return self._base

    def _passes(self, error: Exception) -> bool:
        """Whether `error` is raised as itself and not as `unreachable`: a caller's mistake, or what the caller's
        `is_pass_through` accepts (what its `get_token` raises and it needs to see as itself)."""
        return isinstance(error, Misuse) or self._is_pass_through(error)

    def _timeouts(self, kind: Literal["default", "wait", "stream"], waits: int = 0) -> httpx.Timeout:
        """`timeout_seconds` for connect, write, read and pool. A wait reads for the `waits` seconds it asked the server
        to wait plus `WAIT_MARGIN_SECONDS`, and never for less than `timeout_seconds`; a stream reads for ever (it is
        quiet between events)."""
        if kind == "wait":
            return httpx.Timeout(self._timeout, read=max(self._timeout, waits + WAIT_MARGIN_SECONDS))
        if kind == "stream":
            return httpx.Timeout(self._timeout, read=None)
        return httpx.Timeout(self._timeout)

    def _build(
        self,
        http: httpx.Client | httpx.AsyncClient,
        method: str,
        path: str,
        *,
        params: Mapping[str, str] | None,
        content: bytes | None,
        headers: Mapping[str, str] | None,
        timeout: httpx.Timeout,
    ) -> httpx.Request:
        """The request without its authorization. The caller's `Authorization` and `DPoP` headers are dropped: the
        credential is the one `get_token` gave. With a body, the caller's `Content-Type` is dropped too: it is JSON."""
        dropped = ("authorization", "dpop") if content is None else ("authorization", "dpop", "content-type")
        kept = {name: value for name, value in (headers or {}).items() if name.lower() not in dropped}
        if content is not None:
            kept["content-type"] = "application/json"
        return http.build_request(
            method, self._base + check_path(path), params=params, content=content, headers=kept, timeout=timeout
        )

    @staticmethod
    def _bearer(request: httpx.Request, token: str) -> None:
        """A bearer credential carries no proof: a `DPoP` header from the caller's `httpx` client is removed."""
        request.headers["Authorization"] = f"Bearer {token}"
        request.headers.pop("DPoP", None)

    @staticmethod
    def _proof_request(request: httpx.Request, token: str) -> DpopRequest:
        """What the DPoP hook is asked for: the URL without query or fragment, as RFC 9449 §4.2 requires for `htu`."""
        url = request.url.copy_with(query=None, fragment=None)
        return DpopRequest(method=request.method, url=str(url), access_token=token)

    @staticmethod
    def _dpop(request: httpx.Request, token: str, proof: str) -> None:
        request.headers["Authorization"] = f"DPoP {token}"
        request.headers["DPoP"] = proof
