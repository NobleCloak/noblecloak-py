"""Support for the client tests: a rig that runs one case against the sync client and the async one, and the answers
a module API gives. Nothing here is a credential: tokens are fixed strings."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

from noblecloak.client import AsyncModuleClient, DpopRequest, ModuleClient

BASE = "https://govern.test"
META: dict[str, Any] = {"request_id": "r1", "deployment": "hosted"}
DIGEST = "a" * 64
TIME = "2026-11-10T12:00:00Z"
PRINCIPAL = {"kind": "user", "id": "u1"}

# One valid body for each model an operation returns (the required members, nothing more).
CAPABILITIES: dict[str, Any] = {
    "deployment": "hosted",
    "entitlements": [],
    "jwks_uri": f"{BASE}/.well-known/jwks.json",
    "kids": [],
    "resolutions": ["approved"],
    "features": [],
    "authzen_configuration": f"{BASE}/.well-known/authzen-configuration",
}
RUN: dict[str, Any] = {"id": "r1", "kind": "external", "scope_id": "s1", "created_at": TIME}
DECISION: dict[str, Any] = {"decision": "allow", "action_digest": DIGEST, "enforced": True}
APPROVAL: dict[str, Any] = {
    "id": "a1",
    "state": "pending",
    "tool_ref": "tool:x",
    "obligation_kind": "tool_invocation",
    "action_digest": DIGEST,
    "scope_id": "s1",
    "side_effect_level": "write",
    "created_at": TIME,
}
CONSUMED: dict[str, Any] = {
    "approval_id": "a1",
    "state": "consumed",
    "consumed_at": TIME,
    "tool_ref": "tool:x",
    "action_digest": DIGEST,
}
RECORD: dict[str, Any] = {
    "id": "rec1",
    "ts": TIME,
    "actor": PRINCIPAL,
    "tool_ref": "tool:x",
    "decision": "allow",
    "attestation": "observed",
}
RESUMPTION: dict[str, Any] = {
    "approval_id": "a1",
    "action_id": "act1",
    "tool_ref": "tool:x",
    "obligation_kind": "tool_invocation",
    "resolution": "approved",
    "action_digest": DIGEST,
    "approver": PRINCIPAL,
    "resolved_at": TIME,
    "expires_at": TIME,
    "continuation": {"kind": "webhook", "delivery": "push"},
    "signature": "header.payload.signature",
}


def ok(data: object, **meta: object) -> httpx.Response:
    return httpx.Response(200, json={"data": data, "meta": {**META, **meta}})


def status(code: int, body: object = None) -> httpx.Response:
    return httpx.Response(code, json={} if body is None else body)


def problem(code: int, type_: str, detail: str | None = None) -> httpx.Response:
    body: dict[str, Any] = {"type": f"{BASE}/problems/{type_}", "title": type_, "status": code}
    if detail is not None:
        body["detail"] = detail
    return httpx.Response(code, json=body, headers={"content-type": "application/problem+json"})


@dataclass(frozen=True)
class Seen:
    method: str
    url: httpx.URL
    headers: httpx.Headers
    body: bytes
    extensions: dict[str, Any]


Reply = Callable[[httpx.Request], httpx.Response]


class Rig:
    """A client of one kind over a mock transport, and what that transport saw. `call` runs an operation to its end:
    a sync call directly, an async one in its own event loop."""

    def __init__(
        self,
        kind: str,
        reply: Reply | None = None,
        *,
        get_token: Callable[[], Any] = lambda: "tok",
        dpop_proof: Callable[[DpopRequest], Any] | None = None,
        is_pass_through: Callable[[Exception], bool] | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        self.kind = kind
        self.seen: list[Seen] = []
        self._reply: Reply = reply or (lambda _request: ok({}))
        self.transport = httpx.MockTransport(self._handle)
        options: dict[str, Any] = {
            "get_token": get_token,
            "dpop_proof": dpop_proof,
            "is_pass_through": is_pass_through,
            "timeout_seconds": timeout_seconds,
        }
        if kind == "sync":
            self.client: ModuleClient | AsyncModuleClient = ModuleClient(BASE, transport=self.transport, **options)
        else:
            self.client = AsyncModuleClient(BASE, transport=self.transport, **options)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        extensions: dict[str, Any] = dict(request.extensions)  # pyright: ignore[reportUnknownMemberType, reportUnknownArgumentType]
        self.seen.append(Seen(request.method, request.url, request.headers, request.content, extensions))
        return self._reply(request)

    def call(self, name: str, *args: Any, **kwargs: Any) -> Any:
        result = getattr(self.client, name)(*args, **kwargs)
        return asyncio.run(_await(result)) if self.kind == "async" else result

    def stream(self, *, first_only: bool = False) -> list[bytes]:
        """Opens `stream_approvals`, reads the body (only its first chunk with `first_only`, leaving the block with the
        rest unread) and closes it; the chunks."""
        if self.kind == "sync":
            assert isinstance(self.client, ModuleClient)
            with self.client.stream_approvals() as body:
                return [next(iter(body))] if first_only else list(body)

        async def read() -> list[bytes]:
            assert isinstance(self.client, AsyncModuleClient)
            async with self.client.stream_approvals() as body:
                if first_only:
                    return [await anext(body)]
                return [chunk async for chunk in body]

        return asyncio.run(read())


async def _await(awaitable: Any) -> Any:
    return await awaitable
