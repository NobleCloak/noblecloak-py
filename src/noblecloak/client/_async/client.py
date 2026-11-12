"""The module API client. `_async/client.py` is written by hand; `_sync/client.py` is generated from it by
`scripts/generate_sync.py` (`unasync`), so edit this one and run the script. It is written so that the renames and the
removal of `async` and `await` make a correct synchronous client: what differs between the two is in `_core.py`, in
pairs of functions named `async_x` and `sync_x`.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from types import TracebackType
from typing import Any, cast

import httpx

from noblecloak.client._core import (
    DEFAULT_TIMEOUT_SECONDS,
    NO_BODY,
    AsyncProofHook,
    AsyncTokenGetter,
    Core,
    Unwrap,
    answer_of,
    async_check_client,
    async_proof,
    async_token,
    encode_body,
    json_of,
    key_header,
    message_of,
    model_of,
    page_of,
    segment,
    wait_seconds,
)
from noblecloak.client.types import Answer, ApprovalsPage, ModuleApiError
from noblecloak.models import (
    Approval,
    ApprovalState,
    Capabilities,
    ConsumeResult,
    Decision,
    DecisionRequest,
    Record,
    RecordCreate,
    Resumption,
    Run,
)

__all__ = ["AsyncModuleClient"]


class AsyncModuleClient(Core):
    """Everything a governed runtime asks of the module API's `/v1`: one method per operation, each resolving to an
    `Ok` with the validated `data` or to a `Problem`. A network failure, a 5xx or a body that is not an answer raises
    `ModuleApiError("unreachable")`; the caller decides what a 4xx means. (`AsyncModuleClient` is written by hand and
    `ModuleClient` is generated from it, so they share this docstring; the sync one takes an `httpx.Client`, an
    `httpx.BaseTransport` and a `get_token` that returns a string, and has `close` where this has `aclose`.)

    `base_url` is the API's URL, `https`, or `http` for `localhost` and the loopback addresses; a path prefix is kept.
    `get_token` is called before every request and returns the access token, so it may refresh. The async client takes
    a plain function or a coroutine function (`AsyncTokenSource.get_token`); the sync client takes a plain function
    (`TokenSource.get_token`) and refuses an awaitable with a `TypeError`. `dpop_proof` is the optional DPoP hook
    (RFC 9449), of the same two kinds: with it, the request carries the token under the `DPoP` scheme and the proof in a
    `DPoP` header, and the hook is asked for it with the URL as RFC 9449 §4.2 wants `htu` (no query, no fragment). A
    caller's own `Authorization` and `DPoP` headers are dropped.

    `http_client` is an `httpx.AsyncClient` to use (it is not closed); its own `auth` is not used, because the
    credential is the one `get_token` gave, but its cookies and default headers still go with every request. Or
    `transport` is an `httpx.AsyncBaseTransport` for the client this one builds (a test's fault injection); not both.
    Redirects are never followed: the credential would go with them. `timeout_seconds` is the `httpx` timeout of
    connecting, writing, reading and the connection pool, each on its own, not a bound on the whole request; a long poll
    reads for its wait and a margin, and an event stream reads for ever. `is_pass_through` takes an exception raised
    while a request is made and returns true for the ones that are raised as themselves and not as `unreachable`: what
    the caller's `get_token` raises and it needs to see.

    The async client is used from one event loop at a time, as `httpx.AsyncClient` is. Close the client with `aclose()`
    (`close()` for the sync one) or use it as a context manager (`async with`, `with`); that closes the `httpx` client
    this one built and leaves one that was passed in.
    """

    def __init__(
        self,
        base_url: str,
        *,
        get_token: AsyncTokenGetter,
        dpop_proof: AsyncProofHook | None = None,
        http_client: httpx.AsyncClient | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        is_pass_through: Callable[[Exception], bool] | None = None,
    ) -> None:
        async_check_client(http_client, transport)
        super().__init__(base_url, timeout_seconds=timeout_seconds, is_pass_through=is_pass_through)
        if not callable(get_token):  # pyright: ignore[reportUnnecessaryCallable]
            raise TypeError("get_token must be callable")
        if dpop_proof is not None and not callable(dpop_proof):  # pyright: ignore[reportUnnecessaryCallable]
            raise TypeError("dpop_proof must be callable")
        self._get_token = get_token
        self._dpop_proof = dpop_proof
        self._owns_client = http_client is None
        self._http = (
            httpx.AsyncClient(transport=transport, follow_redirects=False) if http_client is None else http_client
        )

    async def aclose(self) -> None:
        """Closes the `httpx` client this one built; one that was passed in is left open."""
        if self._owns_client:
            await self._http.aclose()

    async def __aenter__(self) -> AsyncModuleClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    # --- the raw request, and what the typed operations are made of ---------------------------------

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        json: object = NO_BODY,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        """One authenticated request, and its response, read in full: no envelope, no `Problem`, no wrapping. What
        `get_token`, `dpop_proof` and `httpx` raise propagates as itself; `unreachable` and `is_pass_through` belong to
        the typed operations. `path` starts with `/`. `json` is the body, when there is one (`None` is the JSON
        `null`)."""
        return await self._send(
            method, path, params=params, content=encode_body(json), headers=headers, timeout=self._timeouts("default")
        )

    async def _send(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str] | None,
        content: bytes | None,
        headers: Mapping[str, str] | None,
        timeout: httpx.Timeout,
        stream: bool = False,
    ) -> httpx.Response:
        token = await async_token(self._get_token)
        request = self._build(
            self._http, method, path, params=params, content=content, headers=headers, timeout=timeout
        )
        if self._dpop_proof is None:
            self._bearer(request, token)
        else:
            self._dpop(request, token, await async_proof(self._dpop_proof, self._proof_request(request, token)))
        return await self._http.send(request, stream=stream, auth=None, follow_redirects=False)

    async def _call[T](
        self,
        method: str,
        path: str,
        unwrap: Unwrap[T],
        *,
        params: Mapping[str, str] | None = None,
        body: object = NO_BODY,
        headers: Mapping[str, str] | None = None,
        timeout: httpx.Timeout | None = None,
    ) -> Answer[T]:
        # a body that cannot be encoded is the caller's mistake: nothing is sent
        content = encode_body(body, strip_none=True)
        try:
            response = await self._send(
                method,
                path,
                params=params,
                content=content,
                headers=headers,
                timeout=timeout or self._timeouts("default"),
            )
        except Exception as error:
            if self._passes(error):
                raise
            raise ModuleApiError("unreachable", f"/v1 could not be reached: {message_of(error)}") from error
        return answer_of(response, unwrap)

    # --- the operations -----------------------------------------------------------------------------

    async def capabilities(self) -> Answer[Capabilities]:
        """`GET /v1/capabilities`."""
        return await self._call("GET", "/v1/capabilities", model_of(Capabilities))

    async def jwks(self) -> dict[str, Any]:
        """`GET /.well-known/jwks.json`: the key set, as the dict `verify_resumption` takes. Raises `unreachable` on a
        network failure, a body that is not JSON, a status that is not 2xx (a 4xx included) and a body without a
        `keys` list."""
        try:
            response = await self._send(
                "GET",
                "/.well-known/jwks.json",
                params=None,
                content=None,
                headers=None,
                timeout=self._timeouts("default"),
            )
            if response.is_success:
                keys = json_of(response)
                if isinstance(keys, dict) and isinstance(cast("dict[str, Any]", keys).get("keys"), list):
                    return cast("dict[str, Any]", keys)
        except Exception as error:
            if self._passes(error):
                raise
            raise ModuleApiError("unreachable", f"the key set could not be read: {message_of(error)}") from error
        raise ModuleApiError("unreachable", f"the key set answered {response.status_code}")

    async def create_run(self, idempotency_key: str) -> Answer[Run]:
        """`POST /v1/runs` for an external run."""
        return await self._call(
            "POST",
            "/v1/runs",
            model_of(Run),
            body={"kind": "external"},
            headers={"Idempotency-Key": key_header(idempotency_key, "idempotency_key")},
        )

    async def decide(self, body: DecisionRequest | Mapping[str, Any]) -> Answer[Decision]:
        """`POST /v1/decisions`."""
        return await self._call("POST", "/v1/decisions", model_of(Decision), body=body)

    async def get_approval(self, approval_id: str) -> Answer[Approval]:
        """`GET /v1/approvals/{id}`."""
        return await self._call("GET", f"/v1/approvals/{segment(approval_id, 'approval_id')}", model_of(Approval))

    async def wait_approval(self, approval_id: str, timeout_seconds: int) -> Answer[Approval]:
        """`GET /v1/approvals/{id}/wait`: returns when the state changes or `timeout_seconds` pass (the server allows
        at most 55). With the async client, cancelling the task that awaits it cancels the request."""
        waits = wait_seconds(timeout_seconds)
        return await self._call(
            "GET",
            f"/v1/approvals/{segment(approval_id, 'approval_id')}/wait",
            model_of(Approval),
            params={"timeout": str(waits)},
            timeout=self._timeouts("wait", waits),
        )

    async def get_resumption(self, approval_id: str) -> Answer[Resumption]:
        """`GET /v1/approvals/{id}/resumption`."""
        return await self._call(
            "GET", f"/v1/approvals/{segment(approval_id, 'approval_id')}/resumption", model_of(Resumption)
        )

    async def consume(
        self, approval_id: str, resume_token: str, tool_ref: str, arguments: Mapping[str, Any]
    ) -> Answer[ConsumeResult]:
        """`POST /v1/approvals/{id}/consume`: spends the approval for the action `tool_ref` with `arguments`."""
        return await self._call(
            "POST",
            f"/v1/approvals/{segment(approval_id, 'approval_id')}/consume",
            model_of(ConsumeResult),
            body={"resume_token": resume_token, "action": {"tool_ref": tool_ref, "arguments": arguments}},
        )

    async def withdraw(self, approval_id: str) -> Answer[Approval]:
        """`POST /v1/approvals/{id}/withdraw`."""
        return await self._call(
            "POST", f"/v1/approvals/{segment(approval_id, 'approval_id')}/withdraw", model_of(Approval)
        )

    async def append_record(self, body: RecordCreate | Mapping[str, Any], idempotency_key: str) -> Answer[Record]:
        """`POST /v1/records`."""
        return await self._call(
            "POST",
            "/v1/records",
            model_of(Record),
            body=body,
            headers={"Idempotency-Key": key_header(idempotency_key, "idempotency_key")},
        )

    async def list_approvals(self, state: ApprovalState | str, cursor: str | None = None) -> Answer[ApprovalsPage]:
        """One page of the approvals in `state` that this principal created, newest first. It always asks for
        `created_by=me`: a worker may run under a user token, which sees its organisation's approvals."""
        params = {"state": ApprovalState(state).value, "created_by": "me"}
        if cursor is not None:
            params["cursor"] = cursor
        return await self._call("GET", "/v1/approvals", page_of, params=params)

    @asynccontextmanager
    async def stream_approvals(self) -> AsyncGenerator[AsyncIterator[bytes]]:
        """`GET /v1/approvals/stream` for the `approval.updated` events of the approvals this principal created
        (`created_by=me`) as a context manager (`async with` for the async client, `with` for the sync one) that
        yields the raw body as chunks of bytes (the server-sent events are not parsed here) and closes the response on
        leaving the block. Raises
        `unreachable` when the stream cannot be opened or answers a status that is not 2xx, a 4xx included. A failure
        while reading the body is raised by `httpx`, as itself."""
        try:
            response = await self._send(
                "GET",
                "/v1/approvals/stream",
                params={"created_by": "me"},
                content=None,
                headers=None,
                timeout=self._timeouts("stream"),
                stream=True,
            )
        except Exception as error:
            if self._passes(error):
                raise
            raise ModuleApiError(
                "unreachable", f"the approval stream could not be opened: {message_of(error)}"
            ) from error
        if not response.is_success:
            await response.aclose()
            raise ModuleApiError("unreachable", f"the approval stream answered {response.status_code}")
        try:
            yield response.aiter_bytes()
        finally:
            await response.aclose()
