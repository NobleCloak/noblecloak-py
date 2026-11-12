"""Service-principal token source. `_async/token.py` is written by hand; `_sync/token.py` is generated from it by
`scripts/generate_sync.py` (`unasync`), so edit this one and run the script. It is written so that the renames and the
removal of `async` and `await` make a correct synchronous source: what differs between the two is in `_core.py`, in
pairs of functions named `async_x` and `sync_x`, which is also where this port's differences from the original are.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any

import httpx

from noblecloak.service_principal._core import (
    DEFAULT_REFRESH_SKEW_SECONDS,
    DEFAULT_TIMEOUT_SECONDS,
    MAX_RESPONSE_BYTES,
    Core,
    Flight,
    Outcome,
    Phase,
    Reply,
    async_check_client,
    async_enlist,
    async_scope,
    async_tick,
    async_timeout,
    async_wait,
    build_request,
    deadline_after,
    failure_of,
    has_content_encoding,
    redirect_cause,
    unwrap,
)
from noblecloak.service_principal.credential import ServicePrincipalCredential, check_credential
from noblecloak.service_principal.error import ServicePrincipalError

__all__ = ["AsyncTokenSource"]


class AsyncTokenSource(Core):
    """Access tokens for a service principal, for one audience. Thread-safe, and one source may be used from several
    event loops and threads at once. (`AsyncTokenSource` is written by hand and `TokenSource` is generated from it, so
    they share this docstring.)

    `credential` is a `ServicePrincipalCredential` (or a mapping that validates as one). `audience` is the origin of
    the API the token is for and becomes the token request's `resource`. `scopes` are asked for; left out, the token
    carries the principal's stored scopes. `refresh_skew_seconds` is how long before expiry a cached token is
    replaced, capped at half the token's life. `clock` returns seconds since the epoch and is read for `iat`, `exp`
    and the cache. `http_client` is an `httpx.AsyncClient` for the async source and an `httpx.Client` for the sync one,
    to use instead of a fresh one per request; it is not closed.

    `timeout_seconds` bounds the whole request, body read included:

    - The async source ends it at `timeout_seconds` wherever it is awaiting (connecting, sending, waiting for the
      headers, reading the body), with `asyncio.timeout`. It cannot interrupt code that blocks the event loop itself
      (a transport that blocks, a CPU-bound hook), because the timeout runs on that loop. A name lookup runs in a worker
      thread, which carries on after the wait for it has been cancelled.
    - The sync source starts no thread and cannot interrupt a blocked call, so it bounds the request with `httpx`
      timeouts and a deadline. Until the headers are in, connect, write and read are each bounded by `timeout_seconds`
      on its own (the timeouts are set once, when the request is issued), not by the deadline: a server that dribbles
      the response headers, one read at a time, is bounded only by `httpx`'s limit on the size of the headers. **It does
      not bound name resolution at all**: `socket.getaddrinfo` can be neither timed nor interrupted, so a resolver that
      hangs holds the caller until the operating system gives up. Once the headers are in, the deadline
      (`timeout_seconds` after the request was issued) is checked at once and after every chunk of the body: a request
      whose headers came after the deadline ends at that moment, and one whose headers came before it ends at the first
      chunk after the deadline or, at the latest, one read timeout after the last chunk before it: under twice
      `timeout_seconds` from the request, in the worst case. A server that sends nothing at all, or the body in chunks,
      is cut off in about `timeout_seconds`.
    - A caller that joins a request another caller started waits for it at most `timeout_seconds` plus a small margin
      (a tenth of it, at least 50 ms), on its own event loop or thread, and then gets `network_error` with `cause`
      `TimeoutError`; the request it gave up on is not affected. A request is not joined once its leader has had
      `2 * timeout_seconds` plus the margin: the next caller starts one of its own.

    The answer is read raw, with `accept-encoding: identity` sent and any `Content-Encoding` refused
    (`invalid_response`), and at most 1 MiB of it. That is stricter than the original, which asks for what `fetch` asks
    for and reads without a limit.
    """

    def __init__(
        self,
        credential: ServicePrincipalCredential | Mapping[str, Any],
        *,
        audience: str,
        scopes: Sequence[str] | None = None,
        http_client: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.time,
        refresh_skew_seconds: float = DEFAULT_REFRESH_SKEW_SECONDS,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        async_check_client(http_client)
        # The credential is checked here, and the argument deleted before the error is raised, so that no frame of
        # the error's traceback holds the key.
        checked = check_credential(credential)
        del credential
        if isinstance(checked, ServicePrincipalError):
            raise checked
        super().__init__(
            checked,
            audience=audience,
            scopes=scopes,
            clock=clock,
            refresh_skew_seconds=refresh_skew_seconds,
            timeout_seconds=timeout_seconds,
        )
        self._http_client = http_client

    async def get_token(self) -> str:
        """An access token for the audience: cached, refreshed shortly before it expires, and one request for
        concurrent callers (on any event loop, for the async source). Raises `ServicePrincipalError`. A caller that
        joins another's request waits for it at most `timeout_seconds` plus a small margin, then gets a
        `network_error` (`cause` is `TimeoutError`)."""
        led: list[Flight] = []
        try:
            while True:
                token, flight, waiter = self._claim(async_enlist, led)
                if token is not None:
                    return token
                assert flight is not None
                if waiter is None:
                    return await self._lead(flight)
                token = unwrap(await async_wait(waiter, self._wait_bound))
                if token is not None:
                    return token
        except BaseException:
            # Whatever leaves here (a cancellation, a `KeyboardInterrupt`, an error) leaves no flight of ours that
            # nobody will complete.
            self._abandon(led)
            raise

    async def _lead(self, flight: Flight) -> str:
        try:
            token, life = self._read(await self._exchange(self._form()))
            self._store(flight.generation, token, life)
        except BaseException as exc:
            # An interruption (a cancellation) is not an answer: the callers that waited start again.
            self._complete(flight, Outcome(error=exc if isinstance(exc, Exception) else None))
            raise
        self._complete(flight, Outcome(token=token))
        return token

    async def _exchange(self, form: dict[str, str]) -> Reply:
        deadline = deadline_after(self._timeout)
        phase: list[Phase] = ["request"]
        try:
            async with async_scope(self._timeout):
                return await self._attempt(form, deadline, phase)
        except TimeoutError as exc:
            return Reply(failure=failure_of(phase[0], exc))

    async def _attempt(self, form: dict[str, str], deadline: float, phase: list[Phase]) -> Reply:
        url = self._credential.token_endpoint
        try:
            if self._http_client is not None:
                return await self._post(self._http_client, url, form, deadline, phase)
            async with httpx.AsyncClient() as client:
                return await self._post(client, url, form, deadline, phase)
        except Exception as exc:
            # Whatever stops the request is a request that got no answer: an `httpx` error, but also an `OSError` from
            # a transport, a client that was closed, a bad proxy variable or a response that was read already. In the
            # original any rejection of `fetch` is `network_error`. (`BaseException`s, a cancellation among them, pass.)
            return Reply(failure=failure_of(phase[0], exc))

    async def _post(
        self, client: httpx.AsyncClient, url: str, form: dict[str, str], deadline: float, phase: list[Phase]
    ) -> Reply:
        request = build_request(url, form, async_timeout(deadline))
        response = await client.send(request, stream=True, auth=None, follow_redirects=False)
        try:
            phase[0] = "body"
            async_tick(deadline)  # headers that came late are cut off now
            status = response.status_code
            if 300 <= status < 400:
                return Reply(status=status, redirect=redirect_cause(status))
            if has_content_encoding(response.headers):
                return Reply(status=status, encoded=True)
            if response.is_stream_consumed:
                # Something read it already (a response hook, or a transport that answers with a complete body, as
                # `httpx.MockTransport` does with `json=`): there is no stream left, but the bytes are known.
                return self._answer(status, response.content, response.headers.get("content-type"), form)
            body = bytearray()
            async for chunk in response.aiter_raw():
                async_tick(deadline)
                body += chunk
                if len(body) > MAX_RESPONSE_BYTES:
                    return Reply(status=status, too_large=True)
            async_tick(deadline)
            return self._answer(status, bytes(body), response.headers.get("content-type"), form)
        finally:
            await response.aclose()
