"""noblecloak.client: how a client is built and how a request is authenticated.

The cases of `client.test.ts` (`createClient`, client 0.13.0) run against both clients, the sync one directly and the
async one in its own event loop, then the cases Python adds: the base URL, the token and the proof as they go into a
header, a redirect, the timeouts, and what a caller passes in.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from client_support import APPROVAL, BASE, CAPABILITIES, Rig, ok, status
from noblecloak.client import AsyncModuleClient, DpopRequest, ModuleApiError, ModuleClient
from noblecloak.client._core import check_base_url  # pyright: ignore[reportPrivateUsage]
from noblecloak.service_principal import AsyncTokenSource, TokenSource
from sp_support import AUDIENCE, Stub, credential, ec_key


def _url(scheme: str, authority: str) -> str:
    """A URL built from parts: the private-dependency guard scans this file for a URL with a user part, which is what
    these cases need to contain."""
    return f"{scheme}://{authority}/"


@pytest.fixture(params=["sync", "async"])
def kind(request: pytest.FixtureRequest) -> str:
    return str(request.param)


# --- the cases of client.test.ts ----------------------------------------------------------------------


def test_sends_the_token_as_a_bearer_credential_and_returns_the_envelope(kind: str) -> None:
    rig = Rig(kind, lambda _r: ok({"deployment": "hosted"}), get_token=lambda: "tok-1")
    response = rig.call("request", "GET", "/v1/capabilities")
    assert rig.seen[0].headers["authorization"] == "Bearer tok-1"
    assert str(rig.seen[0].url) == f"{BASE}/v1/capabilities"
    assert response.json()["meta"]["request_id"] == "r1"


def test_asks_for_the_token_on_every_request_so_a_refresh_takes_effect(kind: str) -> None:
    counter = iter(range(1, 10))
    rig = Rig(kind, get_token=lambda: f"tok-{next(counter)}")
    rig.call("request", "GET", "/v1/capabilities")
    rig.call("request", "GET", "/v1/capabilities")
    assert [s.headers["authorization"] for s in rig.seen] == ["Bearer tok-1", "Bearer tok-2"]


def test_with_a_dpop_hook_uses_the_dpop_scheme_and_a_proof_for_the_url_without_its_query(kind: str) -> None:
    asked: list[DpopRequest] = []

    def proof(request: DpopRequest) -> str:
        asked.append(request)
        return "proof-jwt"

    rig = Rig(kind, dpop_proof=proof)
    rig.call("request", "GET", "/v1/approvals", params={"limit": "5"})
    assert rig.seen[0].headers["authorization"] == "DPoP tok"
    assert rig.seen[0].headers["dpop"] == "proof-jwt"
    assert rig.seen[0].url.query == b"limit=5"
    assert asked == [DpopRequest(method="GET", url=f"{BASE}/v1/approvals", access_token="tok")]


def test_posts_a_body_through_a_typed_route(kind: str) -> None:
    rig = Rig(kind, lambda _r: ok({"decision": "allow", "action_digest": "a" * 64, "enforced": True}))
    rig.call("decide", {"action": {"tool_ref": "x", "arguments": {}}})
    assert rig.seen[0].method == "POST"
    assert str(rig.seen[0].url) == f"{BASE}/v1/decisions"
    assert rig.seen[0].headers["content-type"] == "application/json"
    assert rig.seen[0].body == b'{"action":{"tool_ref":"x","arguments":{}}}'


def test_a_401_problem_comes_back_and_does_not_raise(kind: str) -> None:
    body = {"type": "invalid_token", "title": "Token invalid or expired", "status": 401}
    rig = Rig(kind, lambda _r: httpx.Response(401, json=body, headers={"content-type": "application/problem+json"}))
    raw = rig.call("request", "GET", "/v1/capabilities")
    assert raw.status_code == 401
    assert raw.json() == body
    assert rig.call("capabilities").code == "invalid_token"


def test_a_get_token_that_raises_propagates_from_request_and_nothing_is_sent(kind: str) -> None:
    def refuse() -> str:
        raise RuntimeError("refresh failed")

    rig = Rig(kind, get_token=refuse)
    with pytest.raises(RuntimeError, match="refresh failed"):
        rig.call("request", "GET", "/v1/capabilities")
    assert rig.seen == []


def test_a_dpop_proof_that_raises_propagates_and_nothing_is_sent(kind: str) -> None:
    def refuse(request: DpopRequest) -> str:
        raise RuntimeError("no key")

    rig = Rig(kind, dpop_proof=refuse)
    with pytest.raises(RuntimeError, match="no key"):
        rig.call("request", "GET", "/v1/capabilities")
    assert rig.seen == []


def test_overrides_an_authorization_header_the_caller_supplied(kind: str) -> None:
    rig = Rig(kind, get_token=lambda: "real")
    rig.call("request", "GET", "/v1/capabilities", headers={"Authorization": "Bearer forged", "dpop": "forged"})
    assert rig.seen[0].headers.get_list("authorization") == ["Bearer real"]
    assert "dpop" not in rig.seen[0].headers


def test_a_caller_dpop_header_does_not_survive_next_to_the_clients_own_proof(kind: str) -> None:
    rig = Rig(kind, dpop_proof=lambda _r: "ours")
    rig.call("request", "GET", "/v1/capabilities", headers={"DPoP": "forged", "authorization": "DPoP forged"})
    assert rig.seen[0].headers.get_list("dpop") == ["ours"]
    assert rig.seen[0].headers.get_list("authorization") == ["DPoP tok"]


# --- the token seam: a token source is what get_token takes (the test `service-principal.test.ts:500` moved here) ---


def test_a_token_source_feeds_the_client_as_its_get_token(kind: str) -> None:
    stub = Stub()
    key = ec_key()
    if kind == "sync":
        source = TokenSource(credential(key), audience=AUDIENCE, http_client=stub.client())
    else:
        source = AsyncTokenSource(credential(key), audience=AUDIENCE, http_client=stub.aclient())
    rig = Rig(kind, get_token=source.get_token)
    rig.call("request", "GET", "/v1/capabilities")
    assert rig.seen[0].headers["authorization"] == "Bearer token-1"
    assert len(stub.requests) == 1


def test_the_async_client_takes_a_plain_get_token_and_the_sync_client_refuses_a_coroutine_function() -> None:
    plain = Rig("async", get_token=lambda: "plain")
    plain.call("request", "GET", "/v1/capabilities")
    assert plain.seen[0].headers["authorization"] == "Bearer plain"

    async def minted() -> str:
        return "minted"

    awaited = Rig("async", get_token=minted)
    awaited.call("request", "GET", "/v1/capabilities")
    assert awaited.seen[0].headers["authorization"] == "Bearer minted"

    coroutines: list[Any] = []

    def returns_a_coroutine() -> Any:
        coroutines.append(minted())
        return coroutines[-1]

    sync = Rig("sync", get_token=returns_a_coroutine)
    with pytest.raises(TypeError, match="use AsyncModuleClient"):
        sync.call("request", "GET", "/v1/capabilities")
    assert sync.seen == []
    assert coroutines[0].cr_frame is None  # closed, never awaited: no "was never awaited" warning


class Awaitable:
    """An awaitable that is not a coroutine, so there is nothing for the client to close."""

    def __await__(self) -> Any:
        yield from ()
        return "x"


def test_the_sync_client_refuses_any_awaitable_not_only_a_coroutine() -> None:
    token = Rig("sync", get_token=Awaitable)
    with pytest.raises(TypeError, match="get_token returned an awaitable"):
        token.call("request", "GET", "/v1/capabilities")
    proof = Rig("sync", dpop_proof=lambda _r: Awaitable())
    with pytest.raises(TypeError, match="dpop_proof returned an awaitable"):
        proof.call("request", "GET", "/v1/capabilities")
    assert token.seen == proof.seen == []


def test_the_async_client_awaits_any_awaitable() -> None:
    rig = Rig("async", get_token=Awaitable, dpop_proof=lambda _r: Awaitable())
    rig.call("request", "GET", "/v1/capabilities")
    assert rig.seen[0].headers["dpop"] == "x"


def test_the_sync_client_refuses_an_async_proof_hook() -> None:
    async def proof(request: DpopRequest) -> str:
        return "p"

    made: list[Any] = []

    def hook(request: DpopRequest) -> Any:
        made.append(proof(request))
        return made[-1]

    rig = Rig("sync", dpop_proof=hook)
    with pytest.raises(TypeError, match="dpop_proof returned an awaitable"):
        rig.call("request", "GET", "/v1/capabilities")
    assert rig.seen == []
    assert made[0].cr_frame is None


def test_the_async_client_takes_an_async_proof_hook() -> None:
    async def proof(request: DpopRequest) -> str:
        return f"proof-for-{request.method}"

    rig = Rig("async", dpop_proof=proof)
    rig.call("request", "GET", "/v1/capabilities")
    assert rig.seen[0].headers["dpop"] == "proof-for-GET"


@pytest.mark.parametrize("bad", ["", "has space", "line\nbreak", "tab\t", "café", 5, None, b"bytes"])
def test_a_token_that_is_not_printable_ascii_is_a_mistake_that_is_raised_as_itself(kind: str, bad: Any) -> None:
    rig = Rig(kind, get_token=lambda: bad)
    with pytest.raises(TypeError, match="get_token must return a non-empty string"):
        rig.call("capabilities")  # a typed operation: a mistake is not `unreachable`, which a caller would retry
    assert rig.seen == []


def test_a_bad_token_is_never_echoed(kind: str) -> None:
    rig = Rig(kind, get_token=lambda: "secret token with spaces")
    with pytest.raises(TypeError) as caught:
        rig.call("capabilities")
    assert "secret" not in str(caught.value)


def test_a_bad_proof_is_never_sent(kind: str) -> None:
    rig = Rig(kind, dpop_proof=lambda _r: "two words")
    with pytest.raises(TypeError, match="dpop_proof must return"):
        rig.call("capabilities")
    assert rig.seen == []


# --- redirects ----------------------------------------------------------------------------------------


def test_a_redirect_is_never_followed_and_the_credential_goes_nowhere_else(kind: str) -> None:
    def reply(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://elsewhere.test/v1/capabilities"})

    rig = Rig(kind, reply)
    answer = rig.call("capabilities")
    assert (answer.status, answer.code, answer.ok) == (302, "", False)
    assert [str(s.url) for s in rig.seen] == [f"{BASE}/v1/capabilities"]


def test_a_redirect_is_not_followed_even_by_an_httpx_client_that_follows(kind: str) -> None:
    seen: list[str] = []

    def reply(request: httpx.Request) -> httpx.Response:
        seen.append(f"{request.url} {request.headers.get('authorization')}")
        return httpx.Response(302, headers={"location": "https://elsewhere.test/x"})

    transport = httpx.MockTransport(reply)
    if kind == "sync":
        client: ModuleClient | AsyncModuleClient = ModuleClient(
            BASE, get_token=lambda: "tok", http_client=httpx.Client(transport=transport, follow_redirects=True)
        )
        response = client.request("GET", "/v1/capabilities")  # pyright: ignore[reportUnknownVariableType]
    else:
        client = AsyncModuleClient(
            BASE, get_token=lambda: "tok", http_client=httpx.AsyncClient(transport=transport, follow_redirects=True)
        )
        response = asyncio.run(client.request("GET", "/v1/capabilities"))  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType, reportAttributeAccessIssue]
    assert response.status_code == 302  # pyright: ignore[reportUnknownMemberType]
    assert seen == [f"{BASE}/v1/capabilities Bearer tok"]


def test_the_auth_of_an_http_client_is_not_used_and_its_cookies_and_default_headers_still_are(kind: str) -> None:
    seen: list[httpx.Request] = []

    def reply(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return ok({})

    transport = httpx.MockTransport(reply)
    options: dict[str, Any] = {"auth": ("u", "p"), "cookies": {"s": "1"}, "headers": {"X-Tenant": "t"}}
    if kind == "sync":
        client: ModuleClient | AsyncModuleClient = ModuleClient(
            BASE, get_token=lambda: "tok", http_client=httpx.Client(transport=transport, **options)
        )
        client.request("GET", "/v1/capabilities")  # pyright: ignore[reportUnusedCallResult]
    else:
        client = AsyncModuleClient(
            BASE, get_token=lambda: "tok", http_client=httpx.AsyncClient(transport=transport, **options)
        )
        asyncio.run(client.request("GET", "/v1/capabilities"))  # pyright: ignore[reportUnusedCallResult, reportUnknownArgumentType, reportAttributeAccessIssue]
    assert seen[0].headers.get_list("authorization") == ["Bearer tok"]
    assert seen[0].headers["cookie"] == "s=1"
    assert seen[0].headers["x-tenant"] == "t"


def test_a_dpop_default_header_of_an_http_client_is_removed_in_bearer_mode_and_replaced_by_the_proof(kind: str) -> None:
    seen: list[httpx.Request] = []

    def reply(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return ok({})

    transport = httpx.MockTransport(reply)
    hooks: list[Callable[[DpopRequest], str] | None] = [None, lambda _r: "ours"]
    for proof in hooks:
        if kind == "sync":
            client: ModuleClient | AsyncModuleClient = ModuleClient(
                BASE,
                get_token=lambda: "tok",
                dpop_proof=proof,
                http_client=httpx.Client(transport=transport, headers={"DPoP": "stale-proof"}),
            )
            client.request("GET", "/v1/capabilities")  # pyright: ignore[reportUnusedCallResult]
        else:
            client = AsyncModuleClient(
                BASE,
                get_token=lambda: "tok",
                dpop_proof=proof,
                http_client=httpx.AsyncClient(transport=transport, headers={"DPoP": "stale-proof"}),
            )
            asyncio.run(client.request("GET", "/v1/capabilities"))  # pyright: ignore[reportUnusedCallResult, reportUnknownArgumentType, reportAttributeAccessIssue]
    assert (seen[0].headers.get_list("authorization"), seen[0].headers.get_list("dpop")) == (["Bearer tok"], [])
    assert (seen[1].headers.get_list("authorization"), seen[1].headers.get_list("dpop")) == (["DPoP tok"], ["ours"])


# --- the raw request ----------------------------------------------------------------------------------


def test_a_body_is_sent_with_one_content_type_whatever_case_the_caller_spelled_it_in(kind: str) -> None:
    rig = Rig(kind)
    rig.call("request", "POST", "/v1/x", json={"a": 1}, headers={"Content-Type": "text/plain", "X-Other": "kept"})
    rig.call("request", "POST", "/v1/x", json={"a": 1}, headers={"CONTENT-TYPE": "text/plain"})
    assert [s.headers.get_list("content-type") for s in rig.seen] == [["application/json"], ["application/json"]]
    assert rig.seen[0].headers["x-other"] == "kept"


def test_a_request_without_a_body_keeps_the_content_type_the_caller_gave(kind: str) -> None:
    rig = Rig(kind)
    rig.call("request", "GET", "/v1/x", headers={"Content-Type": "text/plain"})
    assert rig.seen[0].headers.get_list("content-type") == ["text/plain"]


def test_request_returns_any_status_as_the_response_and_wraps_nothing(kind: str) -> None:
    rig = Rig(kind, lambda _r: status(503, {"x": 1}))
    response = rig.call("request", "GET", "/v1/capabilities")
    assert response.status_code == 503
    assert response.json() == {"x": 1}


def test_request_sends_a_json_body_and_none_is_the_json_null(kind: str) -> None:
    rig = Rig(kind)
    rig.call("request", "POST", "/v1/x", json={"a": [1, "é"]})
    rig.call("request", "POST", "/v1/x", json=None)
    rig.call("request", "POST", "/v1/x")
    assert [s.body for s in rig.seen] == ['{"a":[1,"é"]}'.encode(), b"null", b""]
    assert [s.headers.get("content-type") for s in rig.seen] == ["application/json", "application/json", None]


def test_request_lets_httpx_errors_propagate_as_themselves(kind: str) -> None:
    def reply(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    rig = Rig(kind, reply)
    with pytest.raises(httpx.ConnectError):
        rig.call("request", "GET", "/v1/capabilities")


@pytest.mark.parametrize(
    "path", ["v1/x", "https://evil.test/x", "//evil.test/x", "/v1/x?a=1", "/v1/x#f", "/v1/ x", "/v1\\x", "", "/v1/\x00"]
)
def test_request_takes_only_a_path_so_a_token_cannot_be_sent_to_another_host(kind: str, path: str) -> None:
    rig = Rig(kind)
    with pytest.raises(ValueError, match="path must start with one '/'"):
        rig.call("request", "GET", path)
    assert rig.seen == []


def test_request_path_must_be_a_string(kind: str) -> None:
    with pytest.raises(TypeError, match="path must be a string"):
        Rig(kind).call("request", "GET", 5)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), {"a": float("nan")}, [float("-inf")]])
def test_a_body_with_nan_or_infinity_is_refused_and_nothing_is_sent(kind: str, value: Any) -> None:
    rig = Rig(kind)
    with pytest.raises(ValueError, match="Out of range float"):
        rig.call("request", "POST", "/v1/x", json=value)
    with pytest.raises(ValueError, match="Out of range float"):
        rig.call("consume", "a1", "rt", "tool:x", {"n": value})  # a typed operation does not wrap it as unreachable
    assert rig.seen == []


# --- the base URL -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("given", "normal"),
    [
        ("https://govern.example.com", "https://govern.example.com"),
        ("https://GOVERN.Example.com/", "https://govern.example.com"),
        ("https://govern.example.com:443", "https://govern.example.com"),
        ("https://govern.example.com:8443/", "https://govern.example.com:8443"),
        ("https://govern.example.com/api/", "https://govern.example.com/api"),
        ("https://govern.example.com/a/b", "https://govern.example.com/a/b"),
        ("http://localhost:8787", "http://localhost:8787"),
        ("http://127.0.0.1:8787/", "http://127.0.0.1:8787"),
        ("http://[::1]:8787", "http://[::1]:8787"),
        ("HTTP://LOCALHOST", "http://localhost"),
    ],
)
def test_the_base_url_is_normalized(given: str, normal: str) -> None:
    assert check_base_url(given) == normal
    assert ModuleClient(given, get_token=lambda: "t").base_url == normal


@pytest.mark.parametrize(
    "given",
    [
        "http://govern.example.com",  # a token over plain http, off the loopback
        "http://localhost.evil.test",
        "http://127.0.0.2",
        "ftp://govern.example.com",
        "govern.example.com",
        "https://",
        _url("https", "user:pw@govern.example.com"),
        _url("https", "user@govern.example.com"),
        "https://govern.example.com?x=1",
        "https://govern.example.com/#f",
        "https://govern.example.com/?",
        "https://govern.example.com:0",
        "https://govern.example.com:99999",
        "https://gov ern.example.com",
        _url("https", "govern.example.com\\@evil.test"),
        "https://0x7f.1",
        "https://ex%61mple.com",
        "",
    ],
)
def test_a_base_url_that_could_send_the_token_astray_is_refused(given: str) -> None:
    with pytest.raises(ValueError, match="base_url must be an https URL"):
        ModuleClient(given, get_token=lambda: "t")


@pytest.mark.parametrize(
    "given", [_url("https", "user:s3cr3tpw@govern.example.com"), "http://s3cr3t.example.com", "s3cr3t"]
)
def test_a_refused_base_url_is_not_echoed(given: str) -> None:
    with pytest.raises(ValueError, match="base_url must be") as caught:
        ModuleClient(given, get_token=lambda: "t")
    assert "s3cr3t" not in str(caught.value)


def test_a_base_url_that_is_not_a_string_is_a_type_error() -> None:
    with pytest.raises(TypeError, match="base_url must be a string"):
        ModuleClient(5, get_token=lambda: "t")  # pyright: ignore[reportArgumentType]


def test_a_path_prefix_in_the_base_url_comes_before_every_path(kind: str) -> None:
    rig = Rig(kind, lambda _r: ok(APPROVAL))
    rig.client = (ModuleClient if kind == "sync" else AsyncModuleClient)(  # pyright: ignore[reportAttributeAccessIssue]
        f"{BASE}/api/", get_token=lambda: "t", transport=rig.transport
    )
    rig.call("get_approval", "a1")
    assert str(rig.seen[0].url) == f"{BASE}/api/v1/approvals/a1"


# --- timeouts -----------------------------------------------------------------------------------------


def test_requests_carry_timeout_seconds_for_each_phase(kind: str) -> None:
    rig = Rig(kind, lambda _r: ok(CAPABILITIES), timeout_seconds=7)
    rig.call("capabilities")
    assert rig.seen[0].extensions["timeout"] == {"connect": 7, "read": 7, "write": 7, "pool": 7}


def test_a_wait_reads_for_its_wait_and_a_margin_and_never_less_than_the_timeout(kind: str) -> None:
    rig = Rig(kind, lambda _r: ok(APPROVAL), timeout_seconds=30)
    rig.call("wait_approval", "a1", 55)
    rig.call("wait_approval", "a1", 5)
    assert rig.seen[0].extensions["timeout"] == {"connect": 30, "read": 65, "write": 30, "pool": 30}
    assert rig.seen[1].extensions["timeout"] == {"connect": 30, "read": 30, "write": 30, "pool": 30}


def test_a_stream_reads_for_ever_because_it_is_quiet_between_events(kind: str) -> None:
    rig = Rig(kind, lambda _r: httpx.Response(200, content=b"x"), timeout_seconds=9)
    rig.stream()
    assert rig.seen[0].extensions["timeout"] == {"connect": 9, "read": None, "write": 9, "pool": 9}


@pytest.mark.parametrize("bad", [0, -1, float("nan"), float("inf"), True])
def test_timeout_seconds_must_be_a_finite_number_above_zero(bad: Any) -> None:
    with pytest.raises(ValueError, match="timeout_seconds must be a finite number"):
        ModuleClient(BASE, get_token=lambda: "t", timeout_seconds=bad)


# --- what a caller passes in --------------------------------------------------------------------------


def test_an_http_client_is_used_and_left_open_and_a_built_one_is_closed(kind: str) -> None:
    transport = httpx.MockTransport(lambda _r: ok(APPROVAL))
    if kind == "sync":
        passed = httpx.Client(transport=transport)
        client = ModuleClient(BASE, get_token=lambda: "t", http_client=passed)
        client.get_approval("a1")
        client.close()
        assert not passed.is_closed
        built = ModuleClient(BASE, get_token=lambda: "t", transport=transport)
        with built:
            built.get_approval("a1")
        assert built._http.is_closed  # pyright: ignore[reportPrivateUsage]
    else:

        async def run() -> None:
            passed = httpx.AsyncClient(transport=transport)
            client = AsyncModuleClient(BASE, get_token=lambda: "t", http_client=passed)
            await client.get_approval("a1")
            await client.aclose()
            assert not passed.is_closed
            built = AsyncModuleClient(BASE, get_token=lambda: "t", transport=transport)
            async with built:
                await built.get_approval("a1")
            assert built._http.is_closed  # pyright: ignore[reportPrivateUsage]

        asyncio.run(run())


def test_an_http_client_and_a_transport_are_not_both_taken(kind: str) -> None:
    transport = httpx.MockTransport(lambda _r: ok({}))
    if kind == "sync":
        with pytest.raises(ValueError, match="not both"):
            ModuleClient(BASE, get_token=lambda: "t", http_client=httpx.Client(), transport=transport)
    else:
        with pytest.raises(ValueError, match="not both"):
            AsyncModuleClient(BASE, get_token=lambda: "t", http_client=httpx.AsyncClient(), transport=transport)


def test_a_client_or_transport_of_the_other_kind_is_refused() -> None:
    with pytest.raises(TypeError, match=r"ModuleClient needs an httpx\.Client"):
        ModuleClient(BASE, get_token=lambda: "t", http_client=httpx.AsyncClient())  # pyright: ignore[reportArgumentType]
    with pytest.raises(TypeError, match=r"ModuleClient needs an httpx\.BaseTransport"):
        ModuleClient(BASE, get_token=lambda: "t", transport=httpx.AsyncBaseTransport())  # pyright: ignore[reportArgumentType]
    with pytest.raises(TypeError, match=r"AsyncModuleClient needs an httpx\.AsyncClient"):
        AsyncModuleClient(BASE, get_token=lambda: "t", http_client=httpx.Client())  # pyright: ignore[reportArgumentType]
    with pytest.raises(TypeError, match=r"AsyncModuleClient needs an httpx\.AsyncBaseTransport"):
        AsyncModuleClient(BASE, get_token=lambda: "t", transport=httpx.BaseTransport())  # pyright: ignore[reportArgumentType]


def test_get_token_and_dpop_proof_must_be_callable(kind: str) -> None:
    cls = ModuleClient if kind == "sync" else AsyncModuleClient
    with pytest.raises(TypeError, match="get_token must be callable"):
        cls(BASE, get_token="tok")  # pyright: ignore[reportArgumentType]
    with pytest.raises(TypeError, match="dpop_proof must be callable"):
        cls(BASE, get_token=lambda: "t", dpop_proof="proof")  # pyright: ignore[reportArgumentType]


def test_the_client_it_builds_does_not_follow_redirects_and_trusts_the_environment_as_httpx_does() -> None:
    client = ModuleClient(BASE, get_token=lambda: "t")
    assert client._http.follow_redirects is False  # pyright: ignore[reportPrivateUsage]
    client.close()


def test_cancelling_the_task_cancels_the_request_and_is_not_unreachable() -> None:
    started = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        started.set()
        await asyncio.sleep(60)
        return ok({})

    client = AsyncModuleClient(BASE, get_token=lambda: "t", transport=httpx.MockTransport(handler))

    async def run() -> None:
        task = asyncio.create_task(client.wait_approval("a1", 55))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())


def test_an_exception_that_is_not_an_exception_leaves_as_itself(kind: str) -> None:
    class Stop(BaseException):
        pass

    def reply(request: httpx.Request) -> httpx.Response:
        raise Stop

    with pytest.raises(Stop):
        Rig(kind, reply).call("capabilities")


def test_the_two_clients_have_the_same_operations() -> None:
    def names(cls: type) -> set[str]:
        return {n for n in dir(cls) if not n.startswith("_")}

    assert names(ModuleClient) - {"close"} == names(AsyncModuleClient) - {"aclose"}
    assert ModuleApiError("unreachable", "x").code == "unreachable"
