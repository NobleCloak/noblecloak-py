"""Support for the service-principal tests: keys, a stub token endpoint, a local HTTP server and an assertion verifier.

Every key is generated in memory by the test that asks for it. Nothing here is a credential.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import threading
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qsl

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

CLIENT_ID = "sp_0b8d1d6e-5c53-4b8e-9d3a-2f6f7a1c9e10"
ISSUER = "https://api.example.test"
TOKEN_ENDPOINT = f"{ISSUER}/auth/oauth/token"
AUDIENCE = "https://govern.example.test"
NOW = 1_800_000_000.0


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _int(value: int, length: int | None = None) -> str:
    return b64(value.to_bytes(length or (value.bit_length() + 7) // 8, "big"))


@dataclass(frozen=True)
class TestKey:
    __test__ = False  # not a pytest class

    private_jwk: dict[str, Any]
    public_key: ec.EllipticCurvePublicKey | rsa.RSAPublicKey


def ec_key() -> TestKey:
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.private_numbers()
    public = numbers.public_numbers
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _int(public.x, 32),
        "y": _int(public.y, 32),
        "d": _int(numbers.private_value, 32),
    }
    return TestKey(jwk, key.public_key())


_RSA_CACHE: dict[int, TestKey] = {}


def rsa_key(bits: int = 2048) -> TestKey:
    if bits not in _RSA_CACHE:
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        numbers = key.private_numbers()
        public = numbers.public_numbers
        jwk = {
            "kty": "RSA",
            "n": _int(public.n, bits // 8),
            "e": _int(public.e),
            "d": _int(numbers.d, bits // 8),
            "p": _int(numbers.p),
            "q": _int(numbers.q),
            "dp": _int(numbers.dmp1),
            "dq": _int(numbers.dmq1),
            "qi": _int(numbers.iqmp),
        }
        _RSA_CACHE[bits] = TestKey(jwk, key.public_key())
    return _RSA_CACHE[bits]


def credential(key: TestKey, **overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "client_id": CLIENT_ID,
        "token_endpoint": TOKEN_ENDPOINT,
        "assertion_audience": ISSUER,
        "private_jwk": key.private_jwk,
    }
    value.update(overrides)
    return value


def without(value: dict[str, Any], *names: str) -> dict[str, Any]:
    return {name: member for name, member in value.items() if name not in names}


@dataclass(frozen=True)
class VerifiedAssertion:
    header: dict[str, Any]
    claims: dict[str, Any]
    signature_valid: bool


def verify_assertion(jwt: str, key: TestKey) -> VerifiedAssertion:
    header_text, claims_text, signature_text = jwt.split(".")
    header = json.loads(unb64(header_text))
    claims = json.loads(unb64(claims_text))
    signature = unb64(signature_text)
    data = f"{header_text}.{claims_text}".encode("ascii")
    valid = True
    try:
        if header["alg"] == "ES256":
            assert isinstance(key.public_key, ec.EllipticCurvePublicKey)
            assert len(signature) == 64
            der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
            key.public_key.verify(der, data, ec.ECDSA(hashes.SHA256()))
        else:
            assert isinstance(key.public_key, rsa.RSAPublicKey)
            key.public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        valid = False
    return VerifiedAssertion(header, claims, valid)


# --- a stub token endpoint behind httpx's MockTransport ---------------------------------------------


@dataclass(frozen=True)
class Recorded:
    url: str
    method: str
    headers: httpx.Headers
    form: dict[str, str]


Responder = Callable[[Recorded, int], httpx.Response]


def token_response(access_token: str, expires_in: float = 600) -> httpx.Response:
    return httpx.Response(
        200,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": expires_in, "scope": "module_api"},
    )


def json_response(body: Any, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=body)


def _numbered_tokens(_request: Recorded, n: int) -> httpx.Response:
    return token_response(f"token-{n}")


class _Raw(httpx.SyncByteStream, httpx.AsyncByteStream):
    """A body that is read from the stream, as one from the network is. `httpx.Response(content=...)` is already read,
    and `iter_raw` refuses to stream a response that has been read."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def __iter__(self) -> Iterator[bytes]:
        yield self._data

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self._data


def _streamed(response: httpx.Response) -> httpx.Response:
    try:
        data = response.content
    except httpx.ResponseNotRead:
        return response  # already a stream
    return httpx.Response(response.status_code, headers=response.headers, stream=_Raw(data))


class Stub:
    """Records each request and answers with `respond` (default: a 600-second token named `token-<n>`).

    `hold(n)` makes request `n` wait, after it is recorded, until `release(n)`. A hold is a `threading.Event` that the
    sync handler waits on and the async handler polls (so it never blocks the event loop), which makes one hold work
    on any event loop and in any thread. `release_all` is for a test's cleanup: nothing is left waiting.
    """

    def __init__(self, respond: Responder | None = None) -> None:
        self.requests: list[Recorded] = []
        self._respond: Responder = respond or _numbered_tokens
        self._lock = threading.Lock()
        self._holds: dict[int, threading.Event] = {}

    def hold(self, n: int) -> None:
        self._holds[n] = threading.Event()

    def release(self, n: int) -> None:
        self._holds[n].set()

    def release_all(self) -> None:
        for event in self._holds.values():
            event.set()

    def _record(self, request: httpx.Request) -> int:
        recorded = Recorded(
            str(request.url),
            request.method,
            request.headers,
            dict(parse_qsl(request.content.decode("ascii"), keep_blank_values=True)),
        )
        with self._lock:
            self.requests.append(recorded)
            return len(self.requests)

    def handle(self, request: httpx.Request) -> httpx.Response:
        n = self._record(request)
        if n in self._holds:
            self._holds[n].wait(30)
        return _streamed(self._respond(self.requests[n - 1], n))

    async def ahandle(self, request: httpx.Request) -> httpx.Response:
        n = self._record(request)
        while n in self._holds and not self._holds[n].is_set():
            await asyncio.sleep(0.002)
        return _streamed(self._respond(self.requests[n - 1], n))

    def client(self, **kwargs: Any) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handle), **kwargs)

    def aclient(self, **kwargs: Any) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.ahandle), **kwargs)


class ClockAt:
    def __init__(self, start: float = NOW) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# --- a real local HTTP server, for the ephemeral client and for what MockTransport cannot do ---------

Behavior = Callable[[BaseHTTPRequestHandler, bytes], None]


class LocalServer:
    """A threaded HTTP/1.1 server on 127.0.0.1 whose answer is `behavior(handler, body)`. `stop` is set on close, so
    a behavior that waits for it (as `handler.server_stop`) ends with the test."""

    def __init__(self, behavior: Behavior) -> None:
        self.requests: list[tuple[str, bytes]] = []
        self.stop = threading.Event()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("content-length", "0")))
                outer.requests.append((self.path, body))
                self.server_stop = outer.stop  # a behavior that waits for the server to close waits on this
                with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                    behavior(self, body)

            def log_message(self, format: str, *args: Any) -> None:
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self.stop.set()
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> LocalServer:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def send_json(handler: BaseHTTPRequestHandler, body: Any, status: int = 200) -> None:
    data = json.dumps(body).encode("utf-8")
    handler.send_response(status)
    handler.send_header("content-type", "application/json")
    handler.send_header("content-length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)
    handler.wfile.flush()


# --- what an error tracker could see ---------------------------------------------------------------


def chain_of(error: BaseException) -> list[BaseException]:
    """`error` and everything reachable from it through `__cause__` and `__context__`."""
    found: list[BaseException] = []
    todo: list[BaseException] = [error]
    while todo:
        current = todo.pop()
        if any(current is seen for seen in found):
            continue
        found.append(current)
        todo += [e for e in (current.__cause__, current.__context__) if e is not None]
    return found


def tracker_view(error: BaseException, *, library_only: bool = False) -> tuple[list[str], list[BaseException]]:
    """The text of every exception in the chain, and every local of every frame of every one's traceback: what a
    tracker that walks `__cause__` and captures frames with their locals would send out. With `library_only`, only the
    frames of `noblecloak` itself (not the test that called it, which holds what it passed)."""
    chain = chain_of(error)
    texts: list[str] = []
    for exception in chain:
        texts += [str(exception), repr(exception), repr(exception.args), repr(vars(exception))]
        traceback = exception.__traceback__
        while traceback is not None:
            frame = traceback.tb_frame
            if not library_only or "service_principal" in frame.f_code.co_filename:
                for name, value in frame.f_locals.items():
                    texts += [name, repr(value)]
                    if isinstance(value, str):
                        texts.append(value)
                    if isinstance(value, bytes | bytearray):
                        texts.append(bytes(value).decode("latin-1"))
            traceback = traceback.tb_next
    return texts, chain
