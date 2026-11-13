"""Test support: mint validly signed Resumptions with a key of the test's own.

Only ever imported by tests. A signer here can produce a Resumption the server would never issue (another payload,
another header, the second valid signature of a payload), which is what a test of the verifier needs. Nothing in this
module is a credential: every key is generated in memory and discarded with the object.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from typing import Any, Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

__all__ = ["ResumptionSigner", "b64url_encode"]

# The order of the P-256 group, the `n` of `s -> n - s`.
_P256_ORDER: Final = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def b64url_encode(data: bytes) -> str:
    """Unpadded base64url, the only spelling a JWS segment may have."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _segment(value: Mapping[str, Any]) -> str:
    return b64url_encode(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


class ResumptionSigner:
    """An ES256 key with a `kid`, its JWKS, and a way to sign payloads (and, for tests, malformed ones)."""

    def __init__(self, kid: str = "test-key") -> None:
        self.kid = kid
        self._key = ec.generate_private_key(ec.SECP256R1())

    @property
    def jwk(self) -> dict[str, str]:
        numbers = self._key.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": b64url_encode(numbers.x.to_bytes(32, "big")),
            "y": b64url_encode(numbers.y.to_bytes(32, "big")),
            "kid": self.kid,
        }

    @property
    def jwks(self) -> dict[str, list[dict[str, str]]]:
        return {"keys": [self.jwk]}

    def raw_signature(self, signing_input: str, *, high_s: bool = False) -> bytes:
        """The 64-byte r||s signature of `signing_input`. `high_s` gives the other valid signature, `(r, n - s)`."""
        r, s = decode_dss_signature(self._key.sign(signing_input.encode("utf-8"), ec.ECDSA(hashes.SHA256())))
        if high_s != (s > _P256_ORDER // 2):
            s = _P256_ORDER - s
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def sign_segments(self, header_segment: str, payload_segment: str, *, high_s: bool = False) -> str:
        """A JWS over two ready-made segments, which need not be valid JSON."""
        signing_input = f"{header_segment}.{payload_segment}"
        return f"{signing_input}.{b64url_encode(self.raw_signature(signing_input, high_s=high_s))}"

    def sign(self, payload: Mapping[str, Any], *, header: Mapping[str, Any] | None = None, high_s: bool = False) -> str:
        """A JWS compact serialization of `payload`: ES256 with this key's `kid` unless `header` says otherwise."""
        protected = {"alg": "ES256", "kid": self.kid} if header is None else dict(header)
        return self.sign_segments(_segment(protected), _segment(payload), high_s=high_s)
