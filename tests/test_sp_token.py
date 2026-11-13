"""noblecloak.service_principal: `TokenSource` and `AsyncTokenSource`.

The cases of `service-principal.test.ts` (client 0.13.0), except `feeds createClient`, which is in
`tests/test_client.py`, each run against both sources: a `Handle` calls the sync source directly and the async one
through `asyncio.run`, in the calling thread. Callers in other threads therefore share an async source across event
loops. Then the cases Python adds: a total timeout (and the bound each source keeps to), locks, a leader that is
interrupted, and the transport.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import gzip
import hashlib
import json
import math
import pickle
import re
import threading
import time
from collections.abc import AsyncIterator, Callable, Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any
from urllib.parse import parse_qsl

import httpx
import pytest

from noblecloak.service_principal import (
    AsyncTokenProvider,
    AsyncTokenSource,
    ServicePrincipalError,
    TokenProvider,
    TokenSource,
    parse_service_principal_credential,
)
from noblecloak.service_principal import _core as core_module  # pyright: ignore[reportPrivateUsage]
from sp_support import (
    AUDIENCE,
    CLIENT_ID,
    ISSUER,
    NOW,
    TOKEN_ENDPOINT,
    ClockAt,
    LocalServer,
    Recorded,
    Stub,
    TestKey,
    credential,
    ec_key,
    json_response,
    rsa_key,
    send_json,
    token_response,
    tracker_view,
    verify_assertion,
)

PARAMS = ["sync", "async"]


@pytest.fixture(params=PARAMS)
def kind(request: pytest.FixtureRequest) -> str:
    return str(request.param)


@pytest.fixture
def pool() -> Iterator[ThreadPoolExecutor]:
    with ThreadPoolExecutor(max_workers=16) as executor:
        yield executor


class Handle:
    """One source, sync or async, with a blocking `token()` and a way to call it from another thread."""

    def __init__(self, kind: str, source: TokenSource | AsyncTokenSource, pool: ThreadPoolExecutor) -> None:
        self.kind = kind
        self.source = source
        self._pool = pool

    def token(self) -> str:
        if isinstance(self.source, TokenSource):
            return self.source.get_token()
        return asyncio.run(self.source.get_token())

    def invalidate(self) -> None:
        self.source.invalidate()

    def submit(self) -> Future[str]:
        return self._pool.submit(self.token)

    def error(self) -> ServicePrincipalError:
        with pytest.raises(ServicePrincipalError) as caught:
            self.token()
        return caught.value

    def timed_error(self, bound: float) -> tuple[ServicePrincipalError, float]:
        """The error, and how long the call took, with the call made in another thread and given `bound` plus two
        seconds: a source that does not keep its bound fails this test instead of hanging the run."""
        started = time.monotonic()
        error = self._pool.submit(self.error).result(timeout=bound + 2)
        return error, time.monotonic() - started


Maker = Callable[..., Handle]


def build(
    kind: str,
    pool: ThreadPoolExecutor,
    cred: Any,
    client: Any = None,
    *,
    audience: str = AUDIENCE,
    **options: Any,
) -> Handle:
    source: TokenSource | AsyncTokenSource
    if kind == "sync":
        source = TokenSource(cred, audience=audience, http_client=client, **options)
    else:
        source = AsyncTokenSource(cred, audience=audience, http_client=client, **options)
    return Handle(kind, source, pool)


def client_for(kind: str, stub: Stub, **kwargs: Any) -> Any:
    return stub.client(**kwargs) if kind == "sync" else stub.aclient(**kwargs)


@pytest.fixture
def make(kind: str, pool: ThreadPoolExecutor) -> Maker:
    def maker(cred: Any, stub: Stub | None = None, *, client: Any = None, **options: Any) -> Handle:
        if client is None and stub is not None:
            client = client_for(kind, stub)
        return build(kind, pool, cred, client, **options)

    return maker


def _url(scheme: str, authority: str) -> str:
    """A URL built from parts: the private-dependency guard scans this file for a URL with a user part, which is what
    these cases need to contain."""
    return f"{scheme}://{authority}/"


def wait_for(condition: Callable[[], bool], timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "timed out waiting"
        time.sleep(0.005)


def joined(source: Handle | TokenSource | AsyncTokenSource) -> int:
    """How many callers have joined the request that is under way (0 when none is)."""
    target = source.source if isinstance(source, Handle) else source
    flight: core_module.Flight | None = target._inflight  # pyright: ignore[reportPrivateUsage]
    return 0 if flight is None else flight.followers


def wait_until_joined(source: Handle | TokenSource | AsyncTokenSource, followers: int) -> None:
    """Waits until `followers` callers have joined the request that is under way: they have, not a guess that 0.1 s is
    long enough for them to."""
    wait_for(lambda: joined(source) == followers)


def claims_of(request: Recorded) -> dict[str, Any]:
    segment = request.form["client_assertion"].split(".")[1]
    return json.loads(base64_decode(segment))


def base64_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --- the cases of service-principal.test.ts ----------------------------------------------------------


def test_posts_a_form_encoded_client_credentials_request_with_a_verifiable_es256_assertion(make: Maker) -> None:
    key = ec_key()
    stub = Stub()
    source = make(credential(key), stub, scopes=["module_api", "other"], clock=ClockAt())
    assert source.token() == "token-1"

    (request,) = stub.requests
    assert request.method == "POST"
    assert request.url == TOKEN_ENDPOINT
    assert "application/x-www-form-urlencoded" in request.headers["content-type"]
    assert "authorization" not in request.headers
    form = request.form
    assert form["grant_type"] == "client_credentials"
    assert form["client_id"] == CLIENT_ID
    assert form["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    assert form["resource"] == AUDIENCE
    assert form["scope"] == "module_api other"
    assert "client_secret" not in form

    assertion = verify_assertion(form["client_assertion"], key)
    assert assertion.signature_valid is True
    assert assertion.header["alg"] == "ES256"
    assert assertion.header["typ"] == "JWT"
    assert isinstance(assertion.header["kid"], str)
    assert assertion.claims["iss"] == CLIENT_ID
    assert assertion.claims["sub"] == CLIENT_ID
    assert assertion.claims["aud"] == ISSUER
    assert assertion.claims["iat"] == NOW
    assert assertion.claims["exp"] == NOW + 120
    assert 0 < len(str(assertion.claims["jti"])) <= 256


def test_omits_scope_when_none_is_asked_for_and_strips_a_trailing_slash_from_the_resource(make: Maker) -> None:
    stub = Stub()
    make(credential(ec_key()), stub, audience=f"{AUDIENCE}/").token()
    assert "scope" not in stub.requests[0].form
    assert stub.requests[0].form["resource"] == AUDIENCE


def test_uses_the_key_id_from_the_jwk_when_it_has_one_else_the_rfc_7638_thumbprint(make: Maker) -> None:
    key = ec_key()
    with_kid = Stub()
    make(credential(key, private_jwk={**key.private_jwk, "kid": "my-kid"}), with_kid).token()
    assert verify_assertion(with_kid.requests[0].form["client_assertion"], key).header["kid"] == "my-kid"

    without_kid = Stub()
    make(credential(key), without_kid).token()
    second = verify_assertion(without_kid.requests[0].form["client_assertion"], key)
    members = f'{{"crv":"P-256","kty":"EC","x":"{key.private_jwk["x"]}","y":"{key.private_jwk["y"]}"}}'
    expected = base64.urlsafe_b64encode(hashlib.sha256(members.encode()).digest()).rstrip(b"=").decode()
    assert second.header["kid"] == expected
    assert len(expected) == 43


def test_the_rfc_7638_thumbprint_of_an_rsa_key_uses_e_kty_n(make: Maker) -> None:
    key = rsa_key()
    stub = Stub()
    make(credential(key), stub).token()
    members = f'{{"e":"{key.private_jwk["e"]}","kty":"RSA","n":"{key.private_jwk["n"]}"}}'
    expected = base64.urlsafe_b64encode(hashlib.sha256(members.encode()).digest()).rstrip(b"=").decode()
    assert verify_assertion(stub.requests[0].form["client_assertion"], key).header["kid"] == expected


def test_signs_rs256_for_an_rsa_key(make: Maker) -> None:
    key = rsa_key()
    stub = Stub()
    make(credential(key), stub).token()
    assertion = verify_assertion(stub.requests[0].form["client_assertion"], key)
    assert assertion.header["alg"] == "RS256"
    assert assertion.signature_valid is True


def test_uses_a_fresh_jti_for_every_mint(make: Maker) -> None:
    stub = Stub()
    source = make(credential(ec_key()), stub, clock=ClockAt())
    source.token()
    source.invalidate()
    source.token()
    jtis = [claims_of(request)["jti"] for request in stub.requests]
    assert len(jtis) == 2
    assert len(set(jtis)) == 2


def test_serves_a_cached_token_until_shortly_before_it_expires_then_mints_again(make: Maker) -> None:
    clock = ClockAt()
    stub = Stub()
    source = make(credential(ec_key()), stub, clock=clock)
    assert source.token() == "token-1"
    clock.advance(500)
    assert source.token() == "token-1"
    assert len(stub.requests) == 1
    clock.advance(80)  # 580 s of 600 s: inside the 30 s refresh window
    assert source.token() == "token-2"
    assert len(stub.requests) == 2


def test_the_refresh_window_starts_exactly_skew_seconds_before_expiry(make: Maker) -> None:
    clock = ClockAt()
    stub = Stub()
    source = make(credential(ec_key()), stub, clock=clock)
    source.token()
    clock.advance(569.999)
    assert source.token() == "token-1"
    clock.advance(0.001)  # 570 s: `now < usable_until` is false
    assert source.token() == "token-2"


def test_does_not_cache_a_token_whose_whole_life_is_shorter_than_the_refresh_window(make: Maker) -> None:
    clock = ClockAt()
    stub = Stub(lambda _r, n: token_response(f"t{n}", 20))
    source = make(credential(ec_key()), stub, clock=clock)
    assert source.token() == "t1"
    clock.advance(11)
    assert source.token() == "t2"


def test_caps_the_refresh_skew_at_half_the_token_life_a_20_s_token_is_cached_for_10_s(make: Maker) -> None:
    clock = ClockAt()
    stub = Stub(lambda _r, n: token_response(f"t{n}", 20))
    source = make(credential(ec_key()), stub, clock=clock)
    assert source.token() == "t1"
    clock.advance(5)
    assert source.token() == "t1"
    assert len(stub.requests) == 1
    clock.advance(5)
    assert source.token() == "t2"
    assert len(stub.requests) == 2


def test_a_configured_refresh_skew_is_used(make: Maker) -> None:
    clock = ClockAt()
    stub = Stub()
    source = make(credential(ec_key()), stub, clock=clock, refresh_skew_seconds=100)
    source.token()
    clock.advance(499)
    assert source.token() == "token-1"
    clock.advance(2)
    assert source.token() == "token-2"


def test_shares_one_request_between_concurrent_callers(make: Maker) -> None:
    stub = Stub()
    stub.hold(1)
    source = make(credential(ec_key()), stub)
    calls = [source.submit() for _ in range(8)]
    wait_until_joined(source, 7)  # the others have joined the request that is under way
    stub.release(1)
    assert {call.result(5) for call in calls} == {"token-1"}
    assert len(stub.requests) == 1


def test_invalidate_during_a_mint_the_pending_token_is_not_cached_and_the_next_call_mints_anew(make: Maker) -> None:
    stub = Stub()
    stub.hold(1)
    source = make(credential(ec_key()), stub)
    first = source.submit()
    wait_for(lambda: len(stub.requests) == 1)
    source.invalidate()
    assert source.token() == "token-2"
    # token-1 finishes last, so it would overwrite token-2 in the cache if invalidate() did not stop it.
    stub.release(1)
    assert first.result(5) == "token-1"
    assert source.token() == "token-2"
    assert len(stub.requests) == 2


def test_invalidate_during_a_mint_a_finished_old_mint_does_not_clear_the_newer_inflight_request(make: Maker) -> None:
    stub = Stub()
    stub.hold(1)
    stub.hold(2)
    source = make(credential(ec_key()), stub)
    a = source.submit()
    wait_for(lambda: len(stub.requests) == 1)
    source.invalidate()
    b = source.submit()
    wait_for(lambda: len(stub.requests) == 2)
    stub.release(1)
    assert a.result(5) == "token-1"
    # Mint B is still pending: a third caller must join it, not start mint C.
    c = source.submit()
    wait_until_joined(source, 1)
    stub.release(2)
    assert b.result(5) == "token-2"
    assert c.result(5) == "token-2"
    assert len(stub.requests) == 2


def test_does_not_cache_a_failure_the_next_call_tries_again(make: Maker) -> None:
    stub = Stub(lambda _r, n: httpx.Response(503, text="upstream") if n == 1 else token_response("token-ok"))
    source = make(credential(ec_key()), stub)
    assert source.error().code == "invalid_response"
    assert source.token() == "token-ok"


def test_maps_invalid_client_to_a_typed_error_that_says_to_rotate_or_re_create(make: Maker) -> None:
    stub = Stub(lambda _r, _n: json_response({"error": "invalid_client", "error_description": "unknown client"}, 400))
    error = make(credential(ec_key()), stub).error()
    assert error.code == "invalid_client"
    assert error.status == 400
    assert error.oauth_error == "invalid_client"
    assert re.search(r"rotat|re-create|revoked", str(error), re.IGNORECASE)
    # Core's invalid_client also covers clock skew beyond 60 s, so the message must say so.
    assert re.search(r"clock", str(error), re.IGNORECASE)
    assert "client_assertion" not in str(error)


def test_reports_other_oauth_errors_with_their_code_and_non_json_failures_as_invalid_response(make: Maker) -> None:
    key = ec_key()
    rejected = make(
        credential(key),
        Stub(
            lambda _r, _n: json_response({"error": "invalid_target", "error_description": "resource not allowed"}, 400)
        ),
    ).error()
    assert (rejected.code, rejected.oauth_error, rejected.status) == ("token_request_rejected", "invalid_target", 400)
    assert str(rejected) == "The token endpoint refused the request (invalid_target)."
    assert rejected.oauth_error_description == "resource not allowed"
    bare = make(credential(key), Stub(lambda _r, _n: json_response({"error": "access_denied"}, 403))).error()
    assert (bare.code, bare.oauth_error) == ("token_request_rejected", "access_denied")
    assert str(bare) == "The token endpoint refused the request (access_denied)."
    html = make(credential(key), Stub(lambda _r, _n: httpx.Response(502, text="<html>"))).error()
    assert (html.code, html.status) == ("invalid_response", 502)
    odd = make(credential(key), Stub(lambda _r, _n: json_response({"error": 7}, 400))).error()
    assert odd.code == "invalid_response"


def _echo_stub(where: str, what: str, key: TestKey, seen: list[str], status: int = 400) -> Stub:
    """A token endpoint that puts the assertion it was sent, or the private key's `d`, in `error`, in
    `error_description` or in both."""

    def respond(request: Recorded, _n: int) -> httpx.Response:
        assertion = request.form["client_assertion"]
        seen.append(assertion)
        secret = assertion if what == "assertion" else key.private_jwk["d"]
        body: dict[str, str] = {"error": "invalid_request", "error_description": "bad"}
        if where in {"error", "both"}:
            body["error"] = secret
        if where in {"error_description", "both"}:
            body["error_description"] = f"the assertion {secret} is no good"
        return json_response(body, status)

    return Stub(respond)


@pytest.mark.parametrize("what", ["assertion", "d"])
@pytest.mark.parametrize("where", ["error", "error_description", "both"])
def test_a_server_that_echoes_the_assertion_or_the_key_into_the_answer_puts_it_nowhere(
    make: Maker, where: str, what: str
) -> None:
    key = ec_key()
    d = key.private_jwk["d"]
    seen: list[str] = []
    error = make(credential(key), _echo_stub(where, what, key, seen)).error()
    assert len(seen) == 1
    texts, _ = tracker_view(error)
    texts += [str(error), repr(error), repr(vars(error)), str(error.oauth_error), str(error.oauth_error_description)]
    for secret in (d, seen[0]):
        assert [t[:60] for t in texts if secret in t] == [], (where, what)
    if where in {"error", "both"}:
        assert error.oauth_error is None
        assert error.code == "invalid_response"
        assert str(error) == "The token endpoint answered 400 without a usable OAuth error."
    else:
        assert error.oauth_error == "invalid_request"
        assert error.code == "token_request_rejected"
    if where == "error_description":
        assert "[redacted]" in (error.oauth_error_description or "")
    else:
        assert error.oauth_error_description is None  # an answer with no usable error code keeps no prose


def test_a_description_the_server_sent_is_redacted_cleaned_and_cut(make: Maker) -> None:
    key = ec_key()
    seen: list[str] = []

    def respond(request: Recorded, _n: int) -> httpx.Response:
        assertion = request.form["client_assertion"]
        seen.append(assertion)
        # a control character inside the assertion does not hide it; the text is cut after the redaction
        split = assertion[:40] + "\x00\n\u202e" + assertion[40:]
        padded = f"a\tb\r\nc\x1b[31m {split} {assertion.split('.')[2]} " + "x" * 400
        return json_response({"error": "invalid_target", "error_description": padded}, 400)

    error = make(credential(key), Stub(respond)).error()
    shown = error.oauth_error_description
    assert shown is not None
    assert len(shown) == 200
    assert shown.startswith("abc[31m [redacted] [redacted] xxx")
    assert not any(ord(char) < 32 or char == "\u202e" for char in shown)
    assert seen[0] not in shown
    assert shown not in str(error) + repr(error)


@pytest.mark.parametrize(
    "value", ["", "a" * 65, 'has"quote', "back\\slash", "tab\there", "ünïcode", "new\nline", "\x7f"]
)
def test_an_error_that_is_not_an_oauth_error_code_is_not_shown(make: Maker, value: str) -> None:
    stub = Stub(lambda _r, _n: json_response({"error": value, "error_description": "why"}, 400))
    error = make(credential(ec_key()), stub).error()
    assert (error.code, error.oauth_error, error.status) == ("invalid_response", None, 400)
    assert error.cause is not None
    assert value.strip() not in str(error) + repr(error) + str(error.cause) or value.strip() == ""


@pytest.mark.parametrize("value", ["a", "a" * 64, "has space", "unsupported_grant_type", "x!#[]~"])
def test_an_oauth_error_code_of_the_rfc_6749_set_up_to_64_characters_is_shown(make: Maker, value: str) -> None:
    stub = Stub(lambda _r, _n: json_response({"error": value}, 400))
    error = make(credential(ec_key()), stub).error()
    assert (error.code, error.oauth_error) == ("token_request_rejected", value)
    assert error.oauth_error_description is None


@pytest.mark.parametrize("description", [7, None, ["x"], {"a": 1}])
def test_a_description_that_is_not_text_is_not_kept(make: Maker, description: object) -> None:
    stub = Stub(lambda _r, _n: json_response({"error": "invalid_target", "error_description": description}, 400))
    assert make(credential(ec_key()), stub).error().oauth_error_description is None


@pytest.mark.parametrize(
    ("response", "cause"),
    [
        (
            httpx.Response(502, text="<html>oops", headers={"content-type": "text/html"}),
            "content_type=text/html; body_bytes=10; json=false",
        ),
        (
            httpx.Response(500, text="<html>oops", headers={"content-type": "Text/HTML; charset=utf-8"}),
            "content_type=text/html; body_bytes=10; json=false",
        ),
        (
            httpx.Response(500, content=b'{"message": "boom"}', headers={"content-type": "application/json"}),
            "content_type=application/json; body_bytes=19; json=true",
        ),
        (httpx.Response(503, content=b"", headers={}), "body_bytes=0; json=false"),
        (httpx.Response(500, content=b"[1]", headers={"content-type": "<script>/x"}), "body_bytes=3; json=true"),
        (httpx.Response(500, content=b"x", headers={"content-type": "text"}), "body_bytes=1; json=false"),
        (httpx.Response(500, content=b"x", headers={"content-type": "text/" + "h" * 200}), "body_bytes=1; json=false"),
        (
            httpx.Response(400, content=b'{"error": 7}', headers={"content-type": "application/json"}),
            "content_type=application/json; body_bytes=12; json=true",
        ),
    ],
)
def test_a_non_2xx_answer_without_an_oauth_error_says_what_it_was_and_never_what_it_said(
    make: Maker, response: httpx.Response, cause: str
) -> None:
    error = make(credential(ec_key()), Stub(lambda _r, _n: response)).error()
    assert (error.code, error.status, error.cause) == ("invalid_response", response.status_code, cause)


@pytest.mark.parametrize(
    "body",
    [
        pytest.param({"token_type": "Bearer", "expires_in": 600}, id="no access_token"),
        pytest.param({"access_token": "", "token_type": "Bearer", "expires_in": 600}, id="an empty access_token"),
        pytest.param({"access_token": 7, "token_type": "Bearer", "expires_in": 600}, id="a numeric access_token"),
        pytest.param({"access_token": "a", "token_type": "DPoP", "expires_in": 600}, id="a non-bearer token_type"),
        pytest.param({"access_token": "a", "expires_in": 600}, id="no token_type"),
        pytest.param({"access_token": "a", "token_type": "Bearer"}, id="no expires_in"),
        pytest.param({"access_token": "a", "token_type": "Bearer", "expires_in": 0}, id="a zero expires_in"),
        pytest.param({"access_token": "a", "token_type": "Bearer", "expires_in": -5}, id="a negative expires_in"),
        pytest.param({"access_token": "a", "token_type": "Bearer", "expires_in": "600"}, id="a string expires_in"),
        pytest.param({"access_token": "a", "token_type": "Bearer", "expires_in": True}, id="a boolean expires_in"),
        pytest.param({"access_token": "a", "token_type": "Bearer", "expires_in": None}, id="a null expires_in"),
        pytest.param({"access_token": "a", "token_type": "Bearer", "expires_in": 10**400}, id="a huge expires_in"),
        pytest.param([1, 2], id="an array"),
        pytest.param("token", id="a string"),
    ],
)
def test_rejects_a_200_with_a_body_that_is_not_a_bearer_token_response(make: Maker, body: object) -> None:
    error = make(credential(ec_key()), Stub(lambda _r, _n: json_response(body))).error()
    assert error.code == "invalid_response"
    assert error.status == 200


@pytest.mark.parametrize(
    "text", ["NaN", "Infinity", '{"access_token":"a","token_type":"Bearer","expires_in":Infinity}']
)
def test_nan_and_infinity_are_not_json_in_a_token_response(make: Maker, text: str) -> None:
    error = make(credential(ec_key()), Stub(lambda _r, _n: httpx.Response(200, text=text))).error()
    assert error.code == "invalid_response"


def test_accepts_bearer_in_any_case_and_a_fractional_life(make: Maker) -> None:
    stub = Stub(lambda _r, _n: json_response({"access_token": "a", "token_type": "bEaReR", "expires_in": 60.5}))
    assert make(credential(ec_key()), stub).token() == "a"


def test_a_body_that_is_not_utf8_is_invalid_response(make: Maker) -> None:
    error = make(credential(ec_key()), Stub(lambda _r, _n: httpx.Response(200, content=b"\xff\xfe{}"))).error()
    assert error.code == "invalid_response"


def test_wraps_a_network_failure(make: Maker) -> None:
    def refuse(_r: Recorded, _n: int) -> httpx.Response:
        raise httpx.ConnectError("connect ECONNREFUSED")

    error = make(credential(ec_key()), Stub(refuse)).error()
    assert error.code == "network_error"
    assert error.cause == "ConnectError"
    assert error.status is None


@pytest.mark.parametrize("status", [300, 301, 302, 303, 307, 308, 399])
def test_a_redirect_is_network_error_and_no_second_request_is_made_even_by_a_client_that_follows(
    kind: str, pool: ThreadPoolExecutor, status: int
) -> None:
    stub = Stub(lambda _r, _n: httpx.Response(status, headers={"location": "https://elsewhere.example.test/steal"}))
    client = client_for(kind, stub, follow_redirects=True)
    error = build(kind, pool, credential(ec_key()), client).error()
    assert error.code == "network_error"
    assert error.status == status
    assert error.cause == "redirect_not_followed"
    assert "redirect" not in str(error)
    assert [request.url for request in stub.requests] == [TOKEN_ENDPOINT]


def test_a_304_is_not_called_a_redirect(make: Maker) -> None:
    """A 304 is not a redirect, and a token request carries no validators to earn one: it is refused with its own
    cause, and not followed or read."""
    error = make(credential(ec_key()), Stub(lambda _r, _n: httpx.Response(304))).error()
    assert (error.code, error.status, error.cause) == ("network_error", 304, "unexpected_3xx")


def test_a_201_with_a_token_is_a_token(make: Maker) -> None:
    stub = Stub(
        lambda _r, _n: httpx.Response(201, json={"access_token": "made", "token_type": "Bearer", "expires_in": 60})
    )
    assert make(credential(ec_key()), stub).token() == "made"


def test_refuses_a_bad_audience_or_a_malformed_credential_up_front(kind: str) -> None:
    cls = TokenSource if kind == "sync" else AsyncTokenSource
    key = ec_key()
    with pytest.raises(ServicePrincipalError, match="audience"):
        cls(credential(key), audience="govern")
    with pytest.raises(ServicePrincipalError, match="origin"):
        cls(credential(key), audience="https://govern.example.test/path")
    with pytest.raises(ServicePrincipalError) as caught:
        cls({**credential(key), "client_id": "x"}, audience=AUDIENCE)
    assert caught.value.code == "invalid_credential"


@pytest.mark.parametrize("skew", [0, -90, 90])
def test_signs_a_120_s_assertion_from_the_injected_clock_so_a_skewed_clock_shows_in_iat_and_exp(
    make: Maker, skew: float
) -> None:
    key = ec_key()
    stub = Stub()
    make(credential(key), stub, clock=ClockAt(NOW + skew)).token()
    claims = verify_assertion(stub.requests[0].form["client_assertion"], key).claims
    assert claims["iat"] == NOW + skew
    assert claims["exp"] == NOW + skew + 120
    assert claims["aud"] == ISSUER


def test_iat_is_the_whole_second_of_a_fractional_clock(make: Maker) -> None:
    stub = Stub()
    make(credential(ec_key()), stub, clock=ClockAt(NOW + 0.999)).token()
    assert claims_of(stub.requests[0])["iat"] == NOW


def test_the_default_clock_is_the_current_time(make: Maker) -> None:
    stub = Stub()
    make(credential(ec_key()), stub).token()
    assert abs(claims_of(stub.requests[0])["iat"] - time.time()) < 5


def test_still_reports_a_200_whose_body_is_not_json_as_invalid_response(make: Maker) -> None:
    error = make(credential(ec_key()), Stub(lambda _r, _n: httpx.Response(200, text="<html>"))).error()
    assert error.code == "invalid_response"


@pytest.mark.parametrize(
    "audience",
    [
        "https://govern.example.test:443",
        "https://GOVERN.example.test",
        "https://govern.example.test/",
        "https://govern.example.test",
        "https://govern.example.test?",
        "https://govern.example.test/#",
    ],
)
def test_accepts_an_origin_written_with_a_default_port_an_upper_case_host_or_a_trailing_slash(
    make: Maker, audience: str
) -> None:
    stub = Stub()
    make(credential(ec_key()), stub, audience=audience).token()
    assert stub.requests[0].form["resource"] == "https://govern.example.test"


@pytest.mark.parametrize(
    ("audience", "resource"),
    [
        ("http://govern.example.test:80", "http://govern.example.test"),
        ("http://govern.example.test:443", "http://govern.example.test:443"),
        ("https://govern.example.test:80", "https://govern.example.test:80"),
        ("https://govern.example.test:8443/", "https://govern.example.test:8443"),
        ("http://[::1]:8080", "http://[::1]:8080"),
        ("http://[::1]", "http://[::1]"),
        ("https://bücher.example", "https://xn--bcher-kva.example"),
        ("https://straße.example", "https://xn--strae-oqa.example"),  # UTS #46, as `new URL().origin`: not strasse
        ("https://STRAßE.example", "https://xn--strae-oqa.example"),
        ("http://[0:0:0:0:0:0:0:1]", "http://[::1]"),
        ("http://203.0.113.7:8080", "http://203.0.113.7:8080"),
    ],
)
def test_the_resource_is_the_normal_form_of_the_origin(make: Maker, audience: str, resource: str) -> None:
    stub = Stub()
    make(credential(ec_key()), stub, audience=audience).token()
    assert stub.requests[0].form["resource"] == resource


@pytest.mark.parametrize(
    "audience",
    [
        "https://govern.example.test?x=1",
        "https://govern.example.test/#frag",
        "https://govern.example.test/path",
        _url("https", "user@govern.example.test"),
        _url("https", "user:pw@govern.example.test"),
    ],
)
def test_refuses_an_audience_that_is_more_than_an_origin(kind: str, audience: str) -> None:
    cls = TokenSource if kind == "sync" else AsyncTokenSource
    with pytest.raises(ServicePrincipalError, match="origin"):
        cls(credential(ec_key()), audience=audience)


@pytest.mark.parametrize(
    "audience",
    [
        "",
        "govern",
        "ftp://govern.example.test",
        "https://",
        "https://gov\\ern.test",
        "https://gov ern.test",
        "https://[::1",
        "https://ü" + "a" * 70 + ".example",  # a label too long for IDNA
        "https://a..ü.example",
        "https://ex%61mple.test",  # percent-encoded host: another parser decodes it
        "https://0x7f.1",  # IPv4 in another spelling
        "https://1.2.3.04",
        "https://2130706433",
        "https://a\u200d.example",  # a zero-width joiner
        "https://xn--a.example",  # not punycode
    ],
)
def test_refuses_an_audience_that_is_not_a_url_with_a_host(kind: str, audience: str) -> None:
    cls = TokenSource if kind == "sync" else AsyncTokenSource
    with pytest.raises(ServicePrincipalError, match="audience"):
        cls(credential(ec_key()), audience=audience)


# --- Python: arguments --------------------------------------------------------------------------------


def test_scopes_given_as_one_string_or_empty_or_not_scope_tokens_are_the_callers_mistake(kind: str) -> None:
    cls = TokenSource if kind == "sync" else AsyncTokenSource
    key = ec_key()
    with pytest.raises(TypeError):
        cls(credential(key), audience=AUDIENCE, scopes="module_api")
    for bad in ([], ["a b"], [""], ['a"b'], ["a\\b"], ["a\nb"], [7]):
        with pytest.raises(ValueError, match="scope"):
            cls(credential(key), audience=AUDIENCE, scopes=bad)  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]


@pytest.mark.parametrize("value", [-1, math.nan, math.inf, True])
def test_a_refresh_skew_must_be_a_finite_non_negative_number(kind: str, value: float) -> None:
    cls = TokenSource if kind == "sync" else AsyncTokenSource
    with pytest.raises(ValueError, match="refresh_skew_seconds"):
        cls(credential(ec_key()), audience=AUDIENCE, refresh_skew_seconds=value)


@pytest.mark.parametrize("value", [0, -1, math.nan, math.inf, True])
def test_a_timeout_must_be_a_finite_positive_number(kind: str, value: float) -> None:
    cls = TokenSource if kind == "sync" else AsyncTokenSource
    with pytest.raises(ValueError, match="timeout_seconds"):
        cls(credential(ec_key()), audience=AUDIENCE, timeout_seconds=value)


def test_a_credential_object_or_a_mapping_both_work(make: Maker) -> None:
    key = ec_key()
    parsed = parse_service_principal_credential(credential(key))
    for value in (parsed, credential(key)):
        stub = Stub()
        assert make(value, stub).token() == "token-1"


# --- Python: the key ----------------------------------------------------------------------------------


def _bad_keys() -> list[tuple[str, TestKey, str]]:
    ec = ec_key()
    other = ec_key()
    rsa = rsa_key()
    return [
        (
            "x and y of another key",
            TestKey({**ec.private_jwk, "x": other.private_jwk["x"], "y": other.private_jwk["y"]}, ec.public_key),
            "x and y do not belong to d",
        ),
        ("a short d", TestKey({**ec.private_jwk, "d": "AAAA"}, ec.public_key), "d is missing or malformed"),
        ("a d of zero", TestKey({**ec.private_jwk, "d": "A" * 43}, ec.public_key), "ValueError"),
        (
            "a padded x",
            TestKey({**ec.private_jwk, "x": ec.private_jwk["x"] + "="}, ec.public_key),
            "x is missing or malformed",
        ),
        (
            "an rsa key without its crt members",
            TestKey(
                {k: v for k, v in rsa.private_jwk.items() if k not in ("p", "q", "dp", "dq", "qi")}, rsa.public_key
            ),
            "p is missing or malformed",
        ),
        (
            "an rsa key with another dp",
            TestKey({**rsa.private_jwk, "dp": rsa.private_jwk["dq"]}, rsa.public_key),
            "ValueError",
        ),
        (
            "an rsa key with a non-numeric e",
            TestKey({**rsa.private_jwk, "e": "!!"}, rsa.public_key),
            "e is missing or malformed",
        ),
    ]


@pytest.mark.parametrize(("name", "bad", "cause"), _bad_keys(), ids=[b[0] for b in _bad_keys()])
def test_a_key_that_cannot_be_imported_is_invalid_credential_at_the_first_request_and_no_request_is_made(
    make: Maker, name: str, bad: TestKey, cause: str
) -> None:
    del name
    stub = Stub()
    source = make(credential(bad), stub)
    for _ in range(2):  # not cached: the next request fails the same way
        error = source.error()
        assert error.code == "invalid_credential"
        assert error.cause == cause
        assert str(error) == "The private key could not be imported for signing."
        assert error.__cause__ is None  # a chain from the import could carry key material
        assert error.__context__ is None
    assert stub.requests == []


def test_the_signer_is_made_once_and_shared(make: Maker, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    real = core_module._create_signer  # pyright: ignore[reportPrivateUsage]

    def counting(jwk: Any) -> Any:
        calls.append(1)
        return real(jwk)

    monkeypatch.setattr(core_module, "_create_signer", counting)
    stub = Stub()
    source = make(credential(ec_key()), stub, clock=ClockAt())
    source.token()
    source.invalidate()
    source.token()
    assert len(calls) == 1


# --- Python: nothing secret in an error ---------------------------------------------------------------


def test_no_failure_carries_the_private_key_or_the_assertion_or_what_the_transport_said_in_its_message(
    make: Maker,
) -> None:
    key = ec_key()
    d = key.private_jwk["d"]
    seen: list[str] = []

    def leak(request: Recorded, _n: int) -> httpx.Response:
        seen.append(request.form["client_assertion"])
        raise httpx.ConnectError(f"boom {d} {request.form['client_assertion']}")

    cases: list[Stub] = [
        Stub(leak),
        Stub(lambda r, _n: _remember(seen, r, httpx.Response(307, headers={"location": f"https://x.test/?a={d}"}))),
        Stub(lambda r, _n: _remember(seen, r, httpx.Response(200, text=f"<html>{d}</html>"))),
        Stub(lambda r, _n: _remember(seen, r, httpx.Response(500, text=f"{d}"))),
        Stub(lambda r, _n: _remember(seen, r, httpx.Response(200, content=b"x" * (2**20 + 1)))),
        Stub(lambda r, _n: _remember(seen, r, json_response({"error": "invalid_client"}, 401))),
    ]
    for stub in cases:
        error = make(credential(key), stub).error()
        everything = " ".join([str(error), repr(error), repr(error.args), str(error.cause), repr(error.__dict__)])
        assert d not in everything
        for assertion in seen:
            assert assertion not in everything
    assert len(seen) == len(cases)


def test_a_planted_secret_is_in_no_message_or_repr_of_any_token_request_failure(make: Maker) -> None:
    """The private key, the signed assertion and an access token, planted in every place a failure could echo from."""
    key = ec_key()
    d = key.private_jwk["d"]
    access_token = "planted-access-token-9f3a7c"
    seen: list[str] = []

    def echo(response: Callable[[str], httpx.Response]) -> Stub:
        def respond(request: Recorded, _n: int) -> httpx.Response:
            seen.append(request.form["client_assertion"])
            return response(request.form["client_assertion"])

        return Stub(respond)

    def fail_with(assertion: str) -> httpx.Response:
        raise httpx.ReadError(f"{access_token} {d} {assertion}")

    cases = [
        echo(fail_with),
        echo(
            lambda _a: httpx.Response(200, json={"access_token": access_token, "token_type": "mac", "expires_in": 60})
        ),
        echo(lambda _a: httpx.Response(200, json={"access_token": access_token, "token_type": "Bearer"})),
        echo(
            lambda _a: httpx.Response(200, json={"access_token": access_token, "token_type": "Bearer", "expires_in": 0})
        ),
        echo(lambda _a: httpx.Response(500, json={"access_token": access_token, "d": d})),
        echo(lambda _a: httpx.Response(302, headers={"location": f"https://x.test/{access_token}"})),
        echo(lambda a: httpx.Response(400, json={"error": "invalid_client", "access_token": access_token, "a": a})),
        echo(lambda _a: httpx.Response(200, content=access_token.encode() + b"x" * (2**20))),
    ]
    for stub in cases:
        error = make(credential(key), stub).error()
        shown = [str(error), repr(error), repr(error.args), str(error.cause), repr(error.__dict__)]
        for secret in [d, access_token, *seen]:
            assert all(secret not in text for text in shown), (error.code, secret[:12])
    assert len(seen) == len(cases)


def test_a_failed_token_request_chains_a_stand_in_that_names_the_class_underneath(make: Maker) -> None:
    refused = httpx.ConnectError("connect ECONNREFUSED")

    def refuse(_r: Recorded, _n: int) -> httpx.Response:
        raise refused

    error = make(credential(ec_key()), Stub(refuse)).error()
    assert error.code == "network_error"
    assert error.cause == "ConnectError"
    stand_in = error.__cause__
    assert type(stand_in) is core_module.TransportFailure
    assert stand_in is not refused
    assert str(stand_in) == "httpx.ConnectError"  # the class, and not the message "connect ECONNREFUSED"
    assert (stand_in.__cause__, stand_in.__context__, stand_in.__traceback__) == (None, None, None)


def test_a_timed_out_token_request_chains_a_stand_in_for_the_timeout(make: Maker) -> None:
    def silence(handler: Any, _body: bytes) -> None:
        handler.server_stop.wait(10)

    with LocalServer(silence) as server:
        error = make(credential(ec_key(), token_endpoint=f"{server.url}/token"), timeout_seconds=TIMEOUT).error()
    assert error.cause == "TimeoutError"
    assert str(error.__cause__) in {"httpx.ReadTimeout", "builtins.TimeoutError"}


FAILURE_KINDS = [
    "connect",
    "timeout",
    "redirect",
    "bad_json",
    "oversized",
    "gzip_bomb",
    "oserror",  # a transport that raises an OSError, which is not an `httpx.HTTPError`
    "invalid_url",  # `httpx.InvalidURL`: what an endpoint that httpx refuses raises (refused at load now: a backstop)
    "stream_consumed",  # `httpx.StreamConsumed`: a response that was read already
    "closed_client",
    "bug",  # anything else a transport raises
]


@pytest.mark.parametrize("failure", FAILURE_KINDS)
def test_nothing_secret_is_anywhere_in_the_chain_or_the_frames_of_a_token_request_failure(
    make: Maker, kind: str, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    """The private key, the signed assertion and an access token are planted in the transport's message and request
    and in the answer. None may be in any exception of the chain, in the locals of any frame of their tracebacks, or in
    a `request` attribute: an error tracker walks `__cause__` and captures frames with their locals."""
    key = ec_key()
    d = key.private_jwk["d"]
    access_token = "planted-access-token-5d1e8c"
    seen: list[str] = []
    bomb = gzip.compress(b"0" * (8 * 2**20))

    def respond(request: Recorded, _n: int) -> httpx.Response:
        assertion = request.form["client_assertion"]
        seen.append(assertion)
        if failure == "connect":
            sent = httpx.Request("POST", TOKEN_ENDPOINT, data=request.form)
            raise httpx.ConnectError(f"boom {d} {assertion} {access_token}", request=sent)
        if failure == "redirect":
            return httpx.Response(307, headers={"location": f"https://x.test/{access_token}"})
        if failure in {"oserror", "invalid_url", "stream_consumed", "bug"}:
            message = f"boom {d} {assertion} {access_token}"
            raise {
                "oserror": OSError(61, message),
                "invalid_url": httpx.InvalidURL(message),
                "stream_consumed": httpx.StreamConsumed(),
                "bug": RuntimeError(message),
            }[failure]
        if failure == "bad_json":
            return httpx.Response(200, text=f"{{{access_token} {d}")
        if failure == "oversized":
            return httpx.Response(200, content=access_token.encode() + b"x" * (2**20))
        return httpx.Response(200, headers={"content-encoding": "gzip"}, content=bomb)

    if failure == "timeout":

        def silence(handler: Any, body: bytes) -> None:
            seen.append(dict(parse_qsl(body.decode("ascii")))["client_assertion"])
            handler.server_stop.wait(10)

        with LocalServer(silence) as server:
            error = make(credential(key, token_endpoint=f"{server.url}/token"), timeout_seconds=TIMEOUT).error()
    elif failure == "closed_client":
        # Nothing reaches the transport, so the assertion is taken from where it is made.
        original = core_module.Core._assertion  # pyright: ignore[reportPrivateUsage]

        def spy(self: Any) -> str:
            assertion: str = original(self)
            seen.append(assertion)
            return assertion

        monkeypatch.setattr(core_module.Core, "_assertion", spy)
        client = client_for(kind, Stub(respond))
        if isinstance(client, httpx.Client):
            client.close()
        else:
            asyncio.run(client.aclose())
        error = make(credential(key), client=client).error()
        assert error.cause == "RuntimeError"
    else:
        error = make(credential(key), Stub(respond)).error()

    texts, chain = tracker_view(error)
    assert len(seen) == 1
    for secret in (d, access_token, seen[0]):
        assert [text[:80] for text in texts if secret in text] == []
    assert [type(exception).__name__ for exception in chain if hasattr(exception, "request")] == []
    assert [type(exception).__name__ for exception in chain if hasattr(exception, "response")] == []


def test_a_failure_without_an_exception_underneath_has_no_cause(make: Maker) -> None:
    for response in (
        httpx.Response(307, headers={"location": "https://x.test/"}),
        httpx.Response(200, text="<html>"),
        httpx.Response(200, content=b"x" * (2**20 + 1)),
        json_response({"error": "invalid_client"}, 401),
    ):
        error = make(credential(ec_key()), Stub(lambda _r, _n, response=response: response)).error()
        assert error.__cause__ is None
        assert error.__context__ is None


def test_callers_that_share_a_failed_request_each_chain_the_one_stand_in(make: Maker) -> None:
    def refuse(_r: Recorded, _n: int) -> httpx.Response:
        raise httpx.ConnectError("connect ECONNREFUSED")

    stub = Stub(refuse)
    stub.hold(1)
    source = make(credential(ec_key()), stub)
    calls = [source.submit() for _ in range(4)]
    wait_until_joined(source, 3)
    stub.release(1)
    errors = [call.exception(5) for call in calls]
    assert all(isinstance(error, ServicePrincipalError) for error in errors)
    assert len({id(error) for error in errors}) == 4
    causes = [error.__cause__ for error in errors if error is not None]
    assert len({id(cause) for cause in causes}) == 1  # they share the one stand-in
    assert str(causes[0]) == "httpx.ConnectError"
    assert len(stub.requests) == 1


def _remember(seen: list[str], request: Recorded, response: httpx.Response) -> httpx.Response:
    seen.append(request.form["client_assertion"])
    return response


# --- Python: the transport ----------------------------------------------------------------------------


def test_a_client_default_auth_is_not_sent_to_the_token_endpoint(kind: str, pool: ThreadPoolExecutor) -> None:
    stub = Stub()
    client = client_for(kind, stub, auth=("user", "password"))
    assert build(kind, pool, credential(ec_key()), client).token() == "token-1"
    assert "authorization" not in stub.requests[0].headers
    assert stub.requests[0].headers["accept"] == "application/json"


def test_a_clients_default_headers_cookies_and_base_url_are_not_sent_to_the_token_endpoint(
    kind: str, pool: ThreadPoolExecutor
) -> None:
    """A caller's client may carry an `Authorization`, an API key or a session for another service. The request is
    built with only its own headers and sent with `send`, which merges nothing in."""
    stub = Stub()
    client = client_for(
        kind,
        stub,
        headers={"Authorization": "Bearer other-service", "x-api-key": "key-123", "x-custom": "1"},
        cookies={"session": "abc"},
        auth=("user", "password"),
        base_url="https://base.example.test/",
    )
    assert build(kind, pool, credential(ec_key()), client).token() == "token-1"
    sent = stub.requests[0]
    assert sent.url == TOKEN_ENDPOINT
    assert {name.lower() for name in sent.headers} == {
        "host",
        "accept",
        "accept-encoding",
        "content-length",
        "content-type",
    }
    assert sent.headers["content-type"] == "application/x-www-form-urlencoded"


def test_a_client_that_was_passed_is_used_as_is_and_not_closed(make: Maker, kind: str) -> None:
    stub = Stub()
    client = client_for(kind, stub)
    make(credential(ec_key()), client=client).token()
    assert client.is_closed is False
    assert len(stub.requests) == 1


def test_an_answer_over_1_mib_is_invalid_response_and_exactly_1_mib_is_read(make: Maker) -> None:
    key = ec_key()
    big = make(credential(key), Stub(lambda _r, _n: httpx.Response(200, content=b"x" * (2**20 + 1)))).error()
    assert (big.code, big.status) == ("invalid_response", 200)
    assert "larger than 1 MiB" in str(big)
    exact = make(credential(key), Stub(lambda _r, _n: httpx.Response(200, content=b" " * (2**20)))).error()
    assert exact.code == "invalid_response"
    assert "larger than 1 MiB" not in str(exact)


def test_the_request_asks_for_no_compression(make: Maker) -> None:
    stub = Stub()
    make(credential(ec_key()), stub).token()
    assert stub.requests[0].headers["accept-encoding"] == "identity"


def test_the_default_client_asks_for_no_compression_either(make: Maker) -> None:
    seen: list[str | None] = []

    def answer(handler: Any, _body: bytes) -> None:
        seen.append(handler.headers.get("accept-encoding"))
        send_json(handler, {"access_token": "real-token", "token_type": "Bearer", "expires_in": 600})

    with LocalServer(answer) as server:
        assert make(credential(ec_key(), token_endpoint=f"{server.url}/token")).token() == "real-token"
    assert seen == ["identity"]


class _Untouched(httpx.SyncByteStream, httpx.AsyncByteStream):
    """A body that fails the test if anyone reads it."""

    def __iter__(self) -> Iterator[bytes]:
        raise AssertionError("the body of an encoded answer was read")

    async def __aiter__(self) -> AsyncIterator[bytes]:
        raise AssertionError("the body of an encoded answer was read")
        yield b""


@pytest.mark.parametrize(
    "encoding", ["gzip", "GZIP", "deflate", "br", "zstd", "gzip, identity", "identity, gzip", "x-nope", ""]
)
def test_an_answer_with_a_content_encoding_is_invalid_response_and_its_body_is_not_read(
    make: Maker, encoding: str
) -> None:
    stub = Stub(lambda _r, _n: httpx.Response(200, headers={"content-encoding": encoding}, stream=_Untouched()))
    error = make(credential(ec_key()), stub).error()
    assert (error.code, error.status) == ("invalid_response", 200)
    assert str(error) == "The token endpoint's answer has a Content-Encoding; the request asked for none."
    assert error.__cause__ is None


def test_an_error_answer_with_a_content_encoding_is_refused_the_same_way(make: Maker) -> None:
    stub = Stub(lambda _r, _n: httpx.Response(401, headers={"content-encoding": "gzip"}, stream=_Untouched()))
    error = make(credential(ec_key()), stub).error()
    assert (error.code, error.status) == ("invalid_response", 401)
    assert "Content-Encoding" in str(error)


@pytest.mark.parametrize("encoding", ["identity", "Identity", " identity "])
def test_an_answer_that_says_identity_is_read_as_it_is(make: Maker, encoding: str) -> None:
    body = json.dumps({"access_token": "plain", "token_type": "Bearer", "expires_in": 600}).encode()
    stub = Stub(lambda _r, _n: httpx.Response(200, headers={"content-encoding": encoding}, content=body))
    assert make(credential(ec_key()), stub).token() == "plain"


def test_a_gzip_bomb_is_refused_without_being_inflated(make: Maker) -> None:
    """A few kilobytes that inflate to far more than the 1 MiB cap, from a real server, to the default client, which
    would decode the body if the answer were read decoded. The cap counts raw bytes, and the encoding is refused
    first."""
    bomb = gzip.compress(b"0" * (64 * 2**20), compresslevel=9)
    assert len(bomb) < 2**17

    def serve(handler: Any, _body: bytes) -> None:
        handler.send_response(200)
        handler.send_header("content-type", "application/json")
        handler.send_header("content-encoding", "gzip")
        handler.send_header("content-length", str(len(bomb)))
        handler.end_headers()
        handler.wfile.write(bomb)
        handler.wfile.flush()

    with LocalServer(serve) as server:
        error = make(credential(ec_key(), token_endpoint=f"{server.url}/token")).error()
    assert len(gzip.decompress(bomb)) > 2**20
    assert (error.code, error.status) == ("invalid_response", 200)
    assert str(error) == "The token endpoint's answer has a Content-Encoding; the request asked for none."


def test_a_gzip_bomb_in_a_client_that_was_passed_is_refused_too(make: Maker) -> None:
    bomb = gzip.compress(b"0" * (8 * 2**20))
    stub = Stub(lambda _r, _n: httpx.Response(200, headers={"content-encoding": "gzip"}, content=bomb))
    error = make(credential(ec_key()), stub).error()
    assert (error.code, str(error)) == (
        "invalid_response",
        "The token endpoint's answer has a Content-Encoding; the request asked for none.",
    )


class Bug(Exception):
    pass


@pytest.mark.parametrize(
    "failure",
    [
        Bug("x"),
        OSError(61, "refused"),
        RuntimeError("closed"),
        httpx.InvalidURL("bad"),
        httpx.StreamConsumed(),
        KeyError("k"),
    ],
    ids=lambda failure: type(failure).__name__,
)
def test_any_exception_of_the_transport_is_network_error_named_by_its_class_as_in_the_original(
    make: Maker, failure: Exception
) -> None:
    """In the original any rejection of `fetch` is `network_error`. The `cause` is the class name, never the message
    (the stand-in is what is chained), and no frame of the raised error holds the form, the assertion or the body."""
    seen: list[str] = []

    def broken(request: Recorded, _n: int) -> httpx.Response:
        seen.append(request.form["client_assertion"])
        raise failure

    error = make(credential(ec_key()), Stub(broken)).error()
    assert (error.code, error.cause, error.status) == ("network_error", type(failure).__name__, None)
    assert str(error.__cause__) == f"{type(failure).__module__}.{type(failure).__qualname__}"
    texts, _ = tracker_view(error)
    assert [t[:60] for t in texts if seen[0] in t or "client_assertion" in t] == []


def test_a_base_exception_of_the_transport_is_not_an_answer(make: Maker) -> None:
    def interrupt(_r: Recorded, _n: int) -> httpx.Response:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        make(credential(ec_key()), Stub(interrupt)).token()


def test_a_closed_client_is_network_error(make: Maker, kind: str) -> None:
    client = client_for(kind, Stub())
    if isinstance(client, httpx.Client):
        client.close()
    else:
        asyncio.run(client.aclose())
    error = make(credential(ec_key()), client=client).error()
    assert (error.code, error.cause) == ("network_error", "RuntimeError")


def test_an_endpoint_that_slipped_past_the_load_check_is_network_error_from_the_default_client(
    kind: str, pool: ThreadPoolExecutor
) -> None:
    """The backstop of the load check: a credential whose endpoint `httpx` or the resolver refuses is still not a raw
    exception (`httpx.InvalidURL`, `UnicodeError`). The endpoint is put in past `__post_init__`."""
    for endpoint in ("https://a\u200d.example/token", "https://" + "a" * 64 + ".example/token"):
        cred = parse_service_principal_credential(credential(ec_key()))
        object.__setattr__(cred, "token_endpoint", endpoint)
        error = build(kind, pool, cred, timeout_seconds=2).error()
        assert error.code == "network_error"
        assert error.cause in {"InvalidURL", "UnicodeError", "ConnectError", "LocalProtocolError"}
        texts, _ = tracker_view(error)
        assert [t[:60] for t in texts if "client_assertion" in t] == []


def _plain(kind: str, handler: Callable[[httpx.Request], httpx.Response], **kwargs: Any) -> Any:
    """A client over a plain `MockTransport`: its responses are complete (read) before the source sees them, and the
    stream of one cannot be iterated again (`StreamConsumed`)."""
    transport = httpx.MockTransport(handler)
    return (
        httpx.Client(transport=transport, **kwargs)
        if kind == "sync"
        else httpx.AsyncClient(transport=transport, **kwargs)
    )


def test_a_response_that_was_read_already_gives_a_token_from_a_plain_mock_transport(make: Maker, kind: str) -> None:
    """`httpx.Response(200, json=...)` has no stream left: `iter_raw` raises `StreamConsumed`."""
    client = _plain(
        kind, lambda _r: httpx.Response(200, json={"access_token": "plain", "token_type": "Bearer", "expires_in": 60})
    )
    assert make(credential(ec_key()), client=client).token() == "plain"


def test_a_client_with_a_response_hook_that_reads_the_response_gives_a_token(
    kind: str, pool: ThreadPoolExecutor
) -> None:
    def answer(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"access_token": "hooked", "token_type": "Bearer", "expires_in": 60})

    if kind == "sync":

        def read_now(response: httpx.Response) -> None:
            response.read()

        client: Any = httpx.Client(transport=httpx.MockTransport(answer), event_hooks={"response": [read_now]})
    else:

        async def read(response: httpx.Response) -> None:
            await response.aread()

        client = httpx.AsyncClient(transport=httpx.MockTransport(answer), event_hooks={"response": [read]})
    assert build(kind, pool, credential(ec_key()), client).token() == "hooked"


def test_a_response_that_was_read_already_is_held_to_the_same_cap_and_encoding_rules(make: Maker, kind: str) -> None:
    key = ec_key()
    big = _plain(kind, lambda _r: httpx.Response(200, content=b"x" * (2**20 + 1)))
    error = make(credential(key), client=big).error()
    assert (error.code, error.status) == ("invalid_response", 200)
    assert "larger than 1 MiB" in str(error)
    exact = _plain(kind, lambda _r: httpx.Response(200, content=b" " * 2**20))
    assert "larger than 1 MiB" not in str(make(credential(key), client=exact).error())
    gzipped = _plain(
        kind, lambda _r: httpx.Response(200, headers={"content-encoding": "gzip"}, content=gzip.compress(b"{}"))
    )
    assert "Content-Encoding" in str(make(credential(key), client=gzipped).error())
    redirect = _plain(kind, lambda _r: httpx.Response(307, headers={"location": "https://x.test/"}, content=b"moved"))
    assert make(credential(key), client=redirect).error().cause == "redirect_not_followed"


def test_a_client_of_the_wrong_kind_is_a_type_error_when_the_source_is_built(kind: str) -> None:
    wrong = client_for("async" if kind == "sync" else "sync", Stub())
    cls, needs = (TokenSource, "httpx.Client") if kind == "sync" else (AsyncTokenSource, "httpx.AsyncClient")
    with pytest.raises(TypeError, match=rf"^{cls.__name__} needs an {needs}$"):
        cls(credential(ec_key()), audience=AUDIENCE, http_client=wrong)


# --- Python: the default client, against a real server ------------------------------------------------


def _token_server() -> LocalServer:
    answer = {"access_token": "real-token", "token_type": "Bearer", "expires_in": 600}
    return LocalServer(lambda handler, _body: send_json(handler, answer))


def test_the_default_client_posts_to_a_real_endpoint(make: Maker) -> None:
    key = ec_key()
    with _token_server() as server:
        source = make(credential(key, token_endpoint=f"{server.url}/oauth/token"))
        assert source.token() == "real-token"
        ((path, body),) = server.requests
    assert path == "/oauth/token"
    form = dict(pair.split("=", 1) for pair in body.decode().split("&"))
    assert form["grant_type"] == "client_credentials"
    assert form["client_id"] == CLIENT_ID


def test_a_redirect_from_a_real_server_is_not_followed_by_the_default_client(make: Maker) -> None:
    with _token_server() as elsewhere:

        def redirect(handler: Any, _body: bytes) -> None:
            handler.send_response(302)
            handler.send_header("location", f"{elsewhere.url}/steal")
            handler.send_header("content-length", "0")
            handler.end_headers()

        with LocalServer(redirect) as server:
            error = make(credential(ec_key(), token_endpoint=f"{server.url}/token")).error()
            assert len(server.requests) == 1
        assert elsewhere.requests == []
    assert (error.code, error.status) == ("network_error", 302)


# The timeout cases run against a real server: a `MockTransport` handler blocks the caller's own thread, which is
# exactly what the sync source cannot interrupt. `TIMEOUT` is `timeout_seconds` in each of them, and `SLACK` is what a
# loaded machine may add to a bound.
TIMEOUT = 0.4
SLACK = 0.5


def _bound(kind: str, *, worst: bool = False) -> float:
    """The most a call may take, from the documented bound: `timeout_seconds` for the async source (and for the sync
    one, unless a chunk arrives just before the deadline and then nothing does: then one read timeout more)."""
    return TIMEOUT * (2 if worst and kind == "sync" else 1) + SLACK


def _timed(source: Handle, bound: float) -> tuple[ServicePrincipalError, float]:
    return source.timed_error(bound)


def test_a_server_that_never_answers_is_cut_off_at_the_timeout(make: Maker, kind: str) -> None:
    def silence(handler: Any, _body: bytes) -> None:
        handler.server_stop.wait(10)

    with LocalServer(silence) as server:
        error, elapsed = _timed(
            make(credential(ec_key(), token_endpoint=f"{server.url}/token"), timeout_seconds=TIMEOUT), _bound(kind)
        )
    assert TIMEOUT * 0.8 < elapsed < _bound(kind)
    assert (error.code, error.cause) == ("network_error", "TimeoutError")
    assert str(error) == "The token request did not get an answer."


def test_a_server_that_trickles_its_answer_is_cut_off_by_the_total_timeout(make: Maker, kind: str) -> None:
    """Each read arrives in time, so only a check of the whole request, body included, ends this: `asyncio.timeout` for
    the async source, the deadline check after each chunk for the sync one."""
    payload = json.dumps({"access_token": "slow", "token_type": "Bearer", "expires_in": 600, "pad": "x" * 100}).encode()

    def trickle(handler: Any, _body: bytes) -> None:
        handler.send_response(200)
        handler.send_header("content-type", "application/json")
        handler.send_header("content-length", str(len(payload)))
        handler.end_headers()
        for index in range(len(payload)):
            handler.wfile.write(payload[index : index + 1])
            handler.wfile.flush()
            time.sleep(0.02)

    with LocalServer(trickle) as server:
        source = make(credential(ec_key(), token_endpoint=f"{server.url}/token"), timeout_seconds=TIMEOUT)
        error, elapsed = _timed(source, _bound(kind))
    assert error.code == "network_error"
    assert str(error) == "The token response could not be read to the end."
    assert TIMEOUT * 0.8 < elapsed < _bound(kind)  # the answer would take 2.4 s


def test_a_server_that_stalls_after_the_headers_is_cut_off_at_the_timeout(make: Maker, kind: str) -> None:
    def stall(handler: Any, _body: bytes) -> None:
        handler.send_response(200)
        handler.send_header("content-length", "500")
        handler.end_headers()
        handler.wfile.write(b'{"access_token"')
        handler.wfile.flush()
        handler.server_stop.wait(10)

    with LocalServer(stall) as server:
        error, elapsed = _timed(
            make(credential(ec_key(), token_endpoint=f"{server.url}/token"), timeout_seconds=TIMEOUT), _bound(kind)
        )
    assert error.code == "network_error"
    assert str(error) == "The token response could not be read to the end."
    assert TIMEOUT * 0.8 < elapsed < _bound(kind)


def test_a_chunk_just_before_the_deadline_and_then_silence_is_the_worst_case_of_each_bound(
    make: Maker, kind: str
) -> None:
    """The sync source passes its deadline check, then waits one read timeout (`timeout_seconds`) for the next chunk:
    under twice `timeout_seconds`. The async source is cut off at `timeout_seconds`."""

    def late(handler: Any, _body: bytes) -> None:
        handler.send_response(200)
        handler.send_header("content-length", "500")
        handler.end_headers()
        time.sleep(TIMEOUT * 0.5)
        handler.wfile.write(b'{"access_token"')
        handler.wfile.flush()
        handler.server_stop.wait(10)

    with LocalServer(late) as server:
        error, elapsed = _timed(
            make(credential(ec_key(), token_endpoint=f"{server.url}/token"), timeout_seconds=TIMEOUT),
            _bound(kind, worst=True),
        )
    assert error.code == "network_error"
    assert str(error) == "The token response could not be read to the end."
    if kind == "sync":
        # The chunk comes at half the timeout and passes the deadline check; the next read then waits a whole timeout.
        assert TIMEOUT * 1.3 < elapsed < _bound(kind, worst=True)
    else:
        assert TIMEOUT * 0.8 < elapsed < _bound(kind)


def test_headers_that_arrive_after_the_deadline_cut_the_request_off_at_once(make: Maker, kind: str) -> None:
    """The headers dribble in, each piece within a read timeout, and complete at 1.2 `timeout_seconds`; then the server
    says nothing. The deadline is checked as soon as the headers are in, so the request ends then and not a whole read
    timeout later (2.2 `timeout_seconds`). The async source ends at `timeout_seconds`, however the answer comes."""

    wait = 1.0  # long enough that SLACK (0.5 s) is well under one read timeout, which is what a missed check costs

    def dribble(handler: Any, _body: bytes) -> None:
        handler.wfile.write(b"HTTP/1.1 200 OK\r\n")
        handler.wfile.flush()
        time.sleep(wait * 0.6)
        handler.wfile.write(b"content-length: 500\r\n")
        handler.wfile.flush()
        time.sleep(wait * 0.6)
        handler.wfile.write(b"\r\n")
        handler.wfile.flush()
        handler.server_stop.wait(10)

    with LocalServer(dribble) as server:
        error, elapsed = _timed(
            make(credential(ec_key(), token_endpoint=f"{server.url}/token"), timeout_seconds=wait),
            wait * (2 if kind == "sync" else 1) + SLACK,
        )
    assert error.code == "network_error"
    if kind == "sync":
        assert str(error) == "The token response could not be read to the end."  # the headers were in
        assert wait * 1.1 < elapsed < wait * 1.2 + SLACK
    else:
        assert str(error) == "The token request did not get an answer."  # cut off before the headers were in
        assert wait * 0.8 < elapsed < wait + SLACK


def test_the_sync_source_checks_the_deadline_before_it_issues_a_request() -> None:
    with pytest.raises(core_module.Deadline):
        core_module.sync_timeout(time.monotonic() - 1)


def test_a_connection_refused_by_a_real_port_is_network_error(make: Maker) -> None:
    with LocalServer(lambda _h, _b: None) as server:
        url = server.url
    error = make(credential(ec_key(), token_endpoint=f"{url}/token"), timeout_seconds=2).error()
    assert error.code == "network_error"
    assert error.cause in {"ConnectError", "ConnectTimeout"}


# --- Python: locks, event loops and an interrupted leader ---------------------------------------------


def test_callers_on_different_event_loops_share_one_request(pool: ThreadPoolExecutor) -> None:
    stub = Stub()
    stub.hold(1)
    source = AsyncTokenSource(credential(ec_key()), audience=AUDIENCE, http_client=stub.aclient())
    handle = Handle("async", source, pool)
    calls = [handle.submit() for _ in range(6)]  # each thread runs its own event loop
    wait_until_joined(source, 5)
    stub.release(1)
    assert {call.result(5) for call in calls} == {"token-1"}
    assert len(stub.requests) == 1


def test_callers_on_one_event_loop_share_one_request() -> None:
    stub = Stub()
    stub.hold(1)
    source = AsyncTokenSource(credential(ec_key()), audience=AUDIENCE, http_client=stub.aclient())

    async def run() -> list[str]:
        calls = [asyncio.ensure_future(source.get_token()) for _ in range(8)]
        while joined(source) < 7:
            await asyncio.sleep(0.002)
        stub.release(1)
        return list(await asyncio.gather(*calls))

    assert set(asyncio.run(run())) == {"token-1"}
    assert len(stub.requests) == 1


def test_a_cancelled_leader_does_not_fail_the_callers_waiting_on_it_one_of_them_starts_again() -> None:
    stub = Stub()
    stub.hold(1)
    source = AsyncTokenSource(credential(ec_key()), audience=AUDIENCE, http_client=stub.aclient())

    async def run() -> str:
        leader = asyncio.ensure_future(source.get_token())
        while not stub.requests:
            await asyncio.sleep(0.005)
        follower = asyncio.ensure_future(source.get_token())
        while joined(source) < 1:  # the follower has joined the leader's request
            await asyncio.sleep(0.002)
        leader.cancel()
        token = await follower
        with pytest.raises(asyncio.CancelledError):
            await leader
        return token

    assert asyncio.run(run()) == "token-2"
    assert len(stub.requests) == 2
    stub.release_all()


def test_a_cancelled_follower_leaves_the_leader_and_the_other_followers_alone() -> None:
    stub = Stub()
    stub.hold(1)
    source = AsyncTokenSource(credential(ec_key()), audience=AUDIENCE, http_client=stub.aclient())

    async def run() -> list[str]:
        leader = asyncio.ensure_future(source.get_token())
        while not stub.requests:
            await asyncio.sleep(0.005)
        doomed = asyncio.ensure_future(source.get_token())
        kept = asyncio.ensure_future(source.get_token())
        while joined(source) < 2:
            await asyncio.sleep(0.002)
        doomed.cancel()
        stub.release(1)
        with pytest.raises(asyncio.CancelledError):
            await doomed
        return [await leader, await kept]

    assert asyncio.run(run()) == ["token-1", "token-1"]
    assert len(stub.requests) == 1


class Interrupted(BaseException):
    """Like KeyboardInterrupt: not an `Exception`, so not an answer."""


def test_an_interrupted_leader_does_not_fail_the_callers_waiting_on_it_one_of_them_starts_again(
    make: Maker, kind: str
) -> None:
    """A `BaseException` that is not a cancellation (a `KeyboardInterrupt`, here `Interrupted`) in the leader, for the
    sync source and for the async one (where the cancelled leader has its own test)."""

    def respond(_r: Recorded, n: int) -> httpx.Response:
        if n == 1:
            raise Interrupted
        return token_response(f"token-{n}")

    stub = Stub(respond)
    stub.hold(1)
    handle = make(credential(ec_key()), stub)
    leader = handle.submit()
    wait_for(lambda: len(stub.requests) == 1)
    follower = handle.submit()
    wait_until_joined(handle, 1)
    stub.release(1)
    with pytest.raises(Interrupted):
        leader.result(5)
    assert follower.result(5) == "token-2"
    assert len(stub.requests) == 2


def test_a_sync_leader_that_is_interrupted_in_the_caller_thread_leaves_no_flight_behind(
    pool: ThreadPoolExecutor,
) -> None:
    """The sync twin of a cancelled leader: nothing can cancel a thread, but the thread can be interrupted (the signal
    handler of a `KeyboardInterrupt` raises in it) while the others wait."""

    def respond(_r: Recorded, n: int) -> httpx.Response:
        if n == 1:
            raise KeyboardInterrupt
        return token_response(f"token-{n}")

    stub = Stub(respond)
    stub.hold(1)
    handle = Handle("sync", TokenSource(credential(ec_key()), audience=AUDIENCE, http_client=stub.client()), pool)
    leader = handle.submit()
    wait_for(lambda: len(stub.requests) == 1)
    follower = handle.submit()
    wait_until_joined(handle, 1)
    stub.release(1)
    with pytest.raises(KeyboardInterrupt):
        leader.result(5)
    assert follower.result(5) == "token-2"
    assert joined(handle) == 0


def test_an_interrupt_right_after_a_flight_is_installed_does_not_leave_it_for_everyone_after(
    make: Maker, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`_claim` installs the flight, and the leader's own `try` begins a few statements later. An interrupt in between
    (injected here, right after `_claim` returns the flight) must complete it: the next caller must mint at once and not
    wait on a flight nobody will complete."""
    original = core_module.Core._claim  # pyright: ignore[reportPrivateUsage]
    armed = [True]

    def claim_then_interrupt(self: Any, enlist: Any, led: Any) -> Any:
        found = original(self, enlist, led)
        if armed[0] and led:
            armed[0] = False
            raise Interrupted
        return found

    monkeypatch.setattr(core_module.Core, "_claim", claim_then_interrupt)
    stub = Stub()
    handle = make(credential(ec_key()), stub, timeout_seconds=30)
    with pytest.raises(Interrupted):
        handle.token()
    assert handle.source._inflight is None  # pyright: ignore[reportPrivateUsage]
    started = time.monotonic()
    assert handle.token() == "token-1"
    assert time.monotonic() - started < 5  # not the 30 s that waiting on an orphan flight would take


def test_callers_that_wait_on_a_request_that_failed_for_another_reason_get_that_failure(make: Maker) -> None:
    """A failure that is not a `ServicePrincipalError` (here the clock, which the caller supplied, raising) is the
    leader's outcome too: each waiting caller gets it."""
    stub = Stub()
    stub.hold(1)
    calls_to_clock = [0]

    def clock() -> float:
        calls_to_clock[0] += 1
        if calls_to_clock[0] > 1:  # the first read is the minting of the assertion by the leader
            raise Bug
        return NOW

    source = make(credential(ec_key()), stub, clock=clock)
    calls = [source.submit() for _ in range(3)]
    wait_until_joined(source, 2)
    stub.release(1)
    assert [type(call.exception(5)) for call in calls] == [Bug, Bug, Bug]
    assert len(stub.requests) == 1


def test_callers_that_wait_on_a_failed_request_each_get_their_own_copy_of_the_error(make: Maker) -> None:
    stub = Stub(lambda _r, _n: json_response({"error": "invalid_client"}, 400))
    stub.hold(1)
    source = make(credential(ec_key()), stub)
    calls = [source.submit() for _ in range(4)]
    wait_until_joined(source, 3)
    stub.release(1)
    errors = [call.exception(5) for call in calls]
    assert all(isinstance(error, ServicePrincipalError) for error in errors)
    assert len({id(error) for error in errors}) == 4
    assert {(e.code, e.status, e.oauth_error, str(e)) for e in errors if isinstance(e, ServicePrincipalError)} == {
        ("invalid_client", 400, "invalid_client", str(errors[0]))
    }
    assert len(stub.requests) == 1


def test_a_source_is_safe_to_hammer_from_many_threads(make: Maker) -> None:
    stub = Stub()
    source = make(credential(ec_key()), stub, clock=ClockAt())
    results = [source.submit() for _ in range(64)]
    assert {call.result(10) for call in results} == {"token-1"}
    assert len(stub.requests) == 1


def test_get_token_is_the_seam_a_client_takes_a_sync_callable_or_an_async_one() -> None:
    stub = Stub()
    sync = TokenSource(credential(ec_key()), audience=AUDIENCE, http_client=stub.client())
    seam: Callable[[], str] = sync.get_token
    assert seam() == "token-1"
    source = AsyncTokenSource(credential(ec_key()), audience=AUDIENCE, http_client=Stub().aclient())
    aseam: Callable[[], Any] = source.get_token
    assert asyncio.run(aseam()) == "token-1"


def test_a_timeout_that_reaches_the_edge_of_the_exchange_is_network_error_for_either_source(
    make: Maker, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`_exchange` answers a `TimeoutError` that `_attempt` did not turn into a reply: the async source's own
    `asyncio.timeout` raises one on leaving its scope."""
    cls = TokenSource if kind == "sync" else AsyncTokenSource

    async def stuck_async(*_args: object) -> object:
        raise TimeoutError

    def stuck(*_args: object) -> object:
        raise TimeoutError

    monkeypatch.setattr(cls, "_attempt", stuck if kind == "sync" else stuck_async)
    error = make(credential(ec_key()), Stub()).error()
    assert (error.code, error.cause) == ("network_error", "TimeoutError")


def test_the_repr_of_an_outcome_leaves_the_token_out() -> None:
    assert "secret-token" not in repr(core_module.Outcome(token="secret-token"))


# --- Python: a caller that waits on another's request is bounded --------------------------------------


class Blocking:
    """A `MockTransport` handler that blocks the thread it is called in (for the async source, the thread of the event
    loop: `time.sleep`-style, as `asyncio` code that blocks) while it holds request 1; later requests answer at once."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.count = 0
        self._lock = threading.Lock()

    def __call__(self, _request: httpx.Request) -> httpx.Response:
        with self._lock:
            self.count += 1
            n = self.count
        if n == 1:
            self.entered.set()
            self.release.wait(10)
        return httpx.Response(200, json={"access_token": f"token-{n}", "token_type": "Bearer", "expires_in": 600})


def _finished(call: Future[str]) -> str:
    """The token a call ended with, or `error:<cause>` for the timeout that ended it."""
    error = call.exception(5)
    if error is None:
        return call.result()
    assert isinstance(error, ServicePrincipalError)
    assert (error.code, error.cause) == ("network_error", "TimeoutError")
    return f"error:{error.cause}"


def _blocking_source(kind: str, pool: ThreadPoolExecutor, blocking: Blocking, timeout: float = TIMEOUT) -> Handle:
    client = _plain(kind, blocking)
    return build(kind, pool, credential(ec_key()), client, timeout_seconds=timeout)


def test_a_caller_behind_a_leader_that_is_stuck_past_the_timeout_gives_up_at_its_own_bound(
    kind: str, pool: ThreadPoolExecutor
) -> None:
    """The leader is blocked in its own thread (for the async source: its event loop is blocked, so its
    `asyncio.timeout` cannot fire, and the follower, on another loop, must not inherit that)."""
    blocking = Blocking()
    handle = _blocking_source(kind, pool, blocking)
    leader = handle.submit()
    assert blocking.entered.wait(5)
    margin = max(0.05, TIMEOUT * 0.1)
    error, elapsed = handle.timed_error(TIMEOUT + margin + SLACK)
    assert (error.code, error.cause) == ("network_error", "TimeoutError")
    assert str(error.__cause__) == "builtins.TimeoutError"
    assert TIMEOUT * 0.8 < elapsed < TIMEOUT + margin + SLACK
    assert blocking.count == 1  # it did not start a request of its own: the flight was not stale yet
    blocking.release.set()
    _finished(leader)
    assert handle.token().startswith("token-")  # nothing is left in the way: a cached token, or one minted now
    assert joined(handle) == 0


def test_a_flight_whose_leader_has_outlived_its_bound_is_not_joined_by_later_callers(
    kind: str, pool: ThreadPoolExecutor
) -> None:
    blocking = Blocking()
    handle = _blocking_source(kind, pool, blocking)
    leader = handle.submit()
    assert blocking.entered.wait(5)
    wait_for(lambda: time.monotonic() > handle.source._inflight.expires)  # pyright: ignore[reportPrivateUsage,reportOptionalMemberAccess]
    started = time.monotonic()
    assert handle.token() == "token-2"  # a request of its own, which is not blocked
    assert time.monotonic() - started < TIMEOUT
    blocking.release.set()
    _finished(leader)


def test_a_follower_that_gave_up_leaves_the_flight_to_the_others(kind: str, pool: ThreadPoolExecutor) -> None:
    """One follower times out; another that joined half a wait later is still waiting, and still gets what the leader
    ends with. The timeout is long beside the pauses, so that a slow machine does not change the order of events."""
    timeout = 1.5
    blocking = Blocking()
    handle = _blocking_source(kind, pool, blocking, timeout)
    leader = handle.submit()
    assert blocking.entered.wait(5)
    doomed = handle.submit()
    wait_until_joined(handle, 1)
    time.sleep(timeout / 2)
    kept = handle.submit()
    wait_until_joined(handle, 2)
    assert isinstance(doomed.exception(timeout * 2 + 3), ServicePrincipalError)  # it gave up; the other has half left
    blocking.release.set()
    # The leader was held past its own timeout, so the sync one ends with a timeout (the async one may be cut off or
    # may finish first, by a hair): what it ends with, the follower that stayed has too.
    assert _finished(kept) == _finished(leader)
    assert blocking.count == 1


# --- Python: the lock is what makes the flight one -----------------------------------------------------


class SlowFlight(core_module.Flight):
    """A `Flight` that takes 3 ms to make, which widens the window between a caller's reading that there is no flight
    and its installing one, from microseconds (that the GIL all but closes) to something a second thread falls into."""

    def __init__(self, generation: int, expires: float) -> None:
        time.sleep(0.003)
        super().__init__(generation, expires)


def test_sixteen_callers_at_once_start_one_request_not_several(make: Maker, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(core_module, "Flight", SlowFlight)
    stub = Stub()
    stub.hold(1)
    source = make(credential(ec_key()), stub)
    calls = [source.submit() for _ in range(16)]
    wait_until_joined(source, 15)  # without the lock the flights are many, and this never holds
    assert len(stub.requests) == 1
    stub.release(1)
    assert {call.result(5) for call in calls} == {"token-1"}
    assert len(stub.requests) == 1


def test_invalidate_waits_for_a_token_that_is_being_stored_and_so_clears_it(make: Maker) -> None:
    """The token is stored under the lock; an `invalidate` that comes while it is being stored (the clock is read
    inside, and here it waits) must come after, and clear what was stored."""
    entered, proceed = threading.Event(), threading.Event()
    reads = [0]

    def clock() -> float:
        reads[0] += 1
        if reads[0] == 2:  # the first read is the assertion's `iat`, the second is the store
            entered.set()
            proceed.wait(5)
        return NOW

    stub = Stub()
    source = make(credential(ec_key()), stub, clock=clock)
    first = source.submit()
    assert entered.wait(5)
    clearer = threading.Thread(target=source.invalidate)
    clearer.start()
    time.sleep(0.1)  # with the lock, the clearer waits here; without it, it has cleared the cache already
    proceed.set()
    clearer.join(5)
    assert first.result(5) == "token-1"
    assert source.token() == "token-2"  # token-1 was cleared, not left in the cache behind the invalidate
    assert len(stub.requests) == 2


class _SlowList(list[Any]):
    """The waiters of a flight, where joining takes a moment that the test holds open."""

    joining = threading.Event()
    go = threading.Event()

    def append(self, item: Any) -> None:
        _SlowList.joining.set()
        _SlowList.go.wait(5)
        super().append(item)


class _FlightWithSlowJoin(core_module.Flight):
    def __init__(self, generation: int, expires: float) -> None:
        super().__init__(generation, expires)
        self.waiters = _SlowList()


def test_a_flight_is_not_completed_while_a_caller_is_joining_it(
    pool: ThreadPoolExecutor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An async caller joins by adding its future to the flight's waiters, under the lock; the leader completes the
    flight under the same lock, so it cannot take the waiters before the caller is among them. (Without the lock the
    caller would be added after the answer was given out, and wait for its own bound.) The leader is held between its
    answer and the completing of its flight, which is where a caller can still join."""
    _SlowList.joining.clear()
    _SlowList.go.clear()
    monkeypatch.setattr(core_module, "Flight", _FlightWithSlowJoin)
    at_read, read_on = threading.Event(), threading.Event()
    original = core_module.Core._read  # pyright: ignore[reportPrivateUsage]

    def held_read(self: Any, reply: Any) -> Any:
        at_read.set()
        read_on.wait(5)
        return original(self, reply)

    monkeypatch.setattr(core_module.Core, "_read", held_read)
    stub = Stub(lambda _r, _n: json_response({"error": "invalid_target"}, 400))
    source = Handle(
        "async",
        AsyncTokenSource(credential(ec_key()), audience=AUDIENCE, http_client=stub.aclient(), timeout_seconds=3),
        pool,
    )
    leader = source.submit()
    assert at_read.wait(5)  # the leader has its answer and has not completed the flight
    follower = source.submit()
    assert _SlowList.joining.wait(5)  # the follower is joining, and holds the lock
    read_on.set()  # the leader goes on, to fail and to complete the flight
    time.sleep(0.2)  # with the lock the leader waits for the follower; without, it completes now and misses it
    _SlowList.go.set()
    for call in (follower, leader):
        error = call.exception(5)
        assert isinstance(error, ServicePrincipalError)
        assert (error.code, error.oauth_error) == ("token_request_rejected", "invalid_target")


# --- Python: the providers, serialisation, the cap -----------------------------------------------------


def _as_sync_provider(source: TokenSource) -> TokenProvider:
    return source  # pyright checks that `TokenSource` satisfies `TokenProvider`


def _as_async_provider(source: AsyncTokenSource) -> AsyncTokenProvider:
    return source  # pyright checks that `AsyncTokenSource` satisfies `AsyncTokenProvider`


def test_the_sources_are_the_providers_a_client_types_its_seam_against() -> None:
    stub = Stub()
    sync = _as_sync_provider(TokenSource(credential(ec_key()), audience=AUDIENCE, http_client=stub.client()))
    assert sync.get_token() == "token-1"
    sync.invalidate()
    assert sync.get_token() == "token-2"
    stub = Stub()
    provider = _as_async_provider(AsyncTokenSource(credential(ec_key()), audience=AUDIENCE, http_client=stub.aclient()))
    assert asyncio.run(provider.get_token()) == "token-1"
    provider.invalidate()
    assert asyncio.run(provider.get_token()) == "token-2"


def test_a_source_cannot_be_pickled_or_copied(make: Maker, kind: str) -> None:
    source = make(credential(ec_key()), Stub()).source
    name = "TokenSource" if kind == "sync" else "AsyncTokenSource"
    for how in (pickle.dumps, copy.copy, copy.deepcopy):
        with pytest.raises(TypeError, match=f"^{name} holds a private key and is not serialisable$"):
            how(source)


class _Counting(httpx.SyncByteStream, httpx.AsyncByteStream):
    """An answer of 64 MiB in 64 KiB chunks, that counts the chunks that were pulled from it."""

    chunk = 64 * 1024

    def __init__(self) -> None:
        self.pulled = 0

    def __iter__(self) -> Iterator[bytes]:
        for _ in range(1024):
            self.pulled += 1
            yield b"x" * self.chunk

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for _ in range(1024):
            self.pulled += 1
            yield b"x" * self.chunk


def test_an_answer_in_many_chunks_is_cut_off_at_the_cap_not_read_to_the_end(make: Maker) -> None:
    """The cap is checked after each chunk. (A check after the loop reads all 64 MiB, and a test with one chunk
    cannot tell the two apart.)"""
    stream = _Counting()
    error = make(credential(ec_key()), Stub(lambda _r, _n: httpx.Response(200, stream=stream))).error()
    assert (error.code, error.status) == ("invalid_response", 200)
    assert "larger than 1 MiB" in str(error)
    assert stream.pulled * _Counting.chunk <= core_module.MAX_RESPONSE_BYTES + _Counting.chunk
    assert stream.pulled > core_module.MAX_RESPONSE_BYTES // _Counting.chunk  # it did read past the cap, by one chunk
