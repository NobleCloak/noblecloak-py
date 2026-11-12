"""noblecloak.resumption: verification of a Resumption (ES256 JWS) against a key set and the action about to run.

The fixtures are read from the pinned `@noblecloak/spec` install under `conformance/node_modules`. A missing
fixture fails the run; it never skips.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import json
import math
import pickle
import threading
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta, timezone
from functools import partial
from pathlib import Path
from typing import Any, ClassVar

import pytest
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

from noblecloak import resumption
from noblecloak.digest import DigestError, arg_digest
from noblecloak.resumption import (
    ExpectedAction,
    ForgettingReplayGuard,
    InMemoryReplayGuard,
    ResumptionError,
    averify_resumption,
    verify_resumption,
)
from noblecloak.testing import ResumptionSigner, b64url_encode

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = ROOT / "conformance/node_modules/@noblecloak/spec/fixtures/resumption"
FIXTURE_NAMES = ["expired", "tampered-digest", "unknown-kid", "valid", "valid-no-policy", "wrong-tool"]
NINE_CODES = {
    "malformed",
    "unsupported_alg",
    "unknown_kid",
    "bad_signature",
    "expired",
    "not_approved",
    "tool_mismatch",
    "digest_mismatch",
    "replayed",
}

NOW = datetime(2026, 10, 4, 12, 0, 0, tzinfo=UTC)
EXPIRES = "2026-10-04T12:05:00.000Z"
EXPIRES_AT = datetime(2026, 10, 4, 12, 5, 0, tzinfo=UTC)
TOOL = "mcp:tracker:create_issue"
ARGS = {"title": "x", "n": 1}
DIGEST = arg_digest(ARGS)
EXPECTED = ExpectedAction(tool_ref=TOOL, arg_digest=DIGEST)


def payload(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "approval_id": "appr-1",
        "action_id": "act_1",
        "tool_ref": TOOL,
        "action_digest": DIGEST,
        "resolution": "approved",
        "expires_at": EXPIRES,
    }
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not ...}


def verify(
    jws: str,
    signer: ResumptionSigner,
    *,
    expected: ExpectedAction = EXPECTED,
    guard: Any = None,
    now: datetime = NOW,
    **options: Any,
) -> dict[str, Any]:
    return verify_resumption(jws, signer.jwks, expected, replay_guard=guard, now=now, **options)


def code_of(call: Any) -> str:
    with pytest.raises(ResumptionError) as caught:
        call()
    return caught.value.code


def error_of(call: Any) -> ResumptionError:
    with pytest.raises(ResumptionError) as caught:
        call()
    return caught.value


def fixture(name: str) -> dict[str, Any]:
    path = FIXTURE_DIR / f"{name}.json"
    assert path.is_file(), f"missing {path}: run `bun install --frozen-lockfile` in conformance/ first"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def signer() -> ResumptionSigner:
    return ResumptionSigner("k1")


# --- the conformance fixtures ---------------------------------------------------------------------


def test_the_fixture_directory_holds_exactly_the_cases_this_port_knows() -> None:
    names = sorted(p.name.removesuffix(".json") for p in FIXTURE_DIR.glob("*.json") if ".payload" not in p.name)
    assert names == FIXTURE_NAMES


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_every_fixture_gives_the_outcome_it_records(name: str) -> None:
    case = fixture(name)
    expected = ExpectedAction(tool_ref=case["expected"]["tool_ref"], arg_digest=case["expected"]["arg_digest"])
    now = datetime.fromisoformat(case["now"])
    guard = InMemoryReplayGuard(lambda: now)

    def run() -> dict[str, Any]:
        return verify_resumption(case["jws"], case["jwks"], expected, replay_guard=guard, now=now)

    if case.get("outcome") == "valid":
        result = run()
        assert result["tool_ref"] == expected.tool_ref
        assert result["action_digest"] == expected.arg_digest
        assert "signature" not in result
        assert code_of(run) == "replayed"  # the same Resumption, a second time, with the same guard
    else:
        assert code_of(run) == case["code"]
        assert case["code"] in NINE_CODES


def test_the_valid_fixture_returns_its_documented_payload() -> None:
    case = fixture("valid")
    expected = ExpectedAction(tool_ref=case["expected"]["tool_ref"], arg_digest=case["expected"]["arg_digest"])
    result = verify_resumption(
        case["jws"], case["jwks"], expected, replay_guard=None, now=datetime.fromisoformat(case["now"])
    )
    assert result == json.loads((FIXTURE_DIR / "valid.payload.json").read_text(encoding="utf-8"))


def test_the_fixture_codes_are_the_failure_codes_the_error_type_names() -> None:
    codes = {fixture(n)["code"] for n in FIXTURE_NAMES if "code" in fixture(n)}
    assert codes == {"bad_signature", "tool_mismatch", "expired", "unknown_kid"}


# --- the happy path and the error type ------------------------------------------------------------


def test_a_validly_signed_resumption_returns_its_payload(signer: ResumptionSigner) -> None:
    jws = signer.sign(payload())
    assert verify(jws, signer) == payload()


def test_the_returned_payload_is_a_fresh_object(signer: ResumptionSigner) -> None:
    jws = signer.sign(payload())
    first = verify(jws, signer)
    first["tool_ref"] = "changed"
    assert verify(jws, signer)["tool_ref"] == TOOL


def test_a_resumption_error_carries_its_code_and_survives_pickle_and_copy() -> None:
    error = ResumptionError("expired", "gone")
    assert error.code == "expired"
    assert str(error) == "gone"
    for clone in (pickle.loads(pickle.dumps(error)), copy.copy(error), copy.deepcopy(error)):
        assert isinstance(clone, ResumptionError)
        assert (clone.code, str(clone)) == ("expired", "gone")


def test_the_error_type_is_not_a_value_or_type_error() -> None:
    assert not issubclass(ResumptionError, (ValueError, TypeError))


# --- structure ------------------------------------------------------------------------------------


@pytest.mark.parametrize("jws", ["", "a", "a.b", "a.b.c.d", "a..c", ".b.c", "a.b."])
def test_a_jws_is_three_non_empty_parts(jws: str, signer: ResumptionSigner) -> None:
    assert code_of(lambda: verify(jws, signer)) == "malformed"


@pytest.mark.parametrize("jws", [None, 5, b"a.b.c", ["a", "b", "c"]])
def test_a_jws_that_is_not_text_is_malformed_not_a_crash(jws: Any, signer: ResumptionSigner) -> None:
    assert code_of(lambda: verify(jws, signer)) == "malformed"


def replace_part(jws: str, index: int, value: str) -> str:
    """`jws` with one segment's text replaced and the rest left as it was (so the signature no longer matches)."""
    parts = jws.split(".")
    parts[index] = value
    return ".".join(parts)


@pytest.mark.parametrize("emptied", [0, 1, 2])
def test_a_validly_signed_jws_with_one_segment_emptied_is_malformed(emptied: int, signer: ResumptionSigner) -> None:
    """Real segments, so only the non-empty-part rule can decide: `h.p.` would otherwise be a bad signature."""
    jws = replace_part(signer.sign(payload()), emptied, "")
    assert jws.count(".") == 2
    assert code_of(lambda: verify(jws, signer)) == "malformed"


def with_segment(signer: ResumptionSigner, jws: str, index: int, value: str) -> str:
    """`jws` with the header (0) or payload (1) segment replaced and the whole re-signed, so the signature is valid
    over the new text; for the signature (2), only its text is replaced. The verifier decodes the payload only after
    the signature has checked out, so a payload segment must be validly signed to be judged for its spelling."""
    header, body, _ = jws.split(".")
    if index == 0:
        return signer.sign_segments(value, body)
    if index == 1:
        return signer.sign_segments(header, value)
    return replace_part(jws, 2, value)


@pytest.mark.parametrize("index", [0, 1, 2])
@pytest.mark.parametrize("bad", ["ab+c", "ab/c", "ab=c", "ab c", "abéc", "ab\nc", "\uff21\uff22\uff23\uff24"])
def test_a_segment_outside_the_base64url_alphabet_is_malformed(index: int, bad: str, signer: ResumptionSigner) -> None:
    jws = with_segment(signer, signer.sign(payload()), index, bad)
    error = error_of(lambda: verify(jws, signer))
    assert (error.code, "not base64url" in str(error)) == ("malformed", True)


@pytest.mark.parametrize("index", [0, 1, 2])
def test_a_trailing_newline_does_not_slip_past_the_alphabet_check(index: int, signer: ResumptionSigner) -> None:
    """`$` in a Python regex matches before a final newline; the decoder must not."""
    jws = signer.sign(payload())
    error = error_of(lambda: verify(with_segment(signer, jws, index, jws.split(".")[index] + "\n"), signer))
    assert (error.code, "not base64url" in str(error)) == ("malformed", True)


@pytest.mark.parametrize("index", [0, 1, 2])
def test_a_segment_of_an_impossible_length_is_malformed(index: int, signer: ResumptionSigner) -> None:
    jws = signer.sign(payload())
    segment = jws.split(".")[index]
    stretched = segment + "A" * ((1 - len(segment)) % 4)  # length % 4 == 1
    assert len(stretched) % 4 == 1
    error = error_of(lambda: verify(with_segment(signer, jws, index, stretched), signer))
    assert (error.code, "impossible" in str(error)) == ("malformed", True)


def last_char_with_set_trailing_bits(segment: str) -> str | None:
    """The same bytes spelled with the unused trailing bits of the last character set, or None if none are unused."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    unused = {2: 4, 3: 2}.get(len(segment) % 4)
    if unused is None:
        return None
    value = alphabet.index(segment[-1])
    return segment[:-1] + alphabet[value | (2**unused - 1)] if value & (2**unused - 1) == 0 else None


def test_a_non_canonical_trailing_bit_in_the_signature_is_malformed_not_a_second_spelling(
    signer: ResumptionSigner,
) -> None:
    """A 64-byte signature is 86 characters, the last of which carries 4 unused bits."""
    jws = signer.sign(payload())
    signature = jws.split(".")[2]
    assert len(signature) == 86
    twin = last_char_with_set_trailing_bits(signature)
    assert twin is not None
    assert twin != signature
    error = error_of(lambda: verify(replace_part(jws, 2, twin), signer))
    assert (error.code, "canonical" in str(error)) == ("malformed", True)
    assert verify(jws, signer) == payload()  # the canonical spelling is accepted


def test_a_non_canonical_trailing_bit_in_the_header_or_payload_is_malformed(signer: ResumptionSigner) -> None:
    for index in (0, 1):
        for candidate in range(60):
            header = {"alg": "ES256", "kid": "k1", "pad": "x" * candidate}
            body = payload(pad="y" * candidate)
            jws = signer.sign(body, header=header)
            twin = last_char_with_set_trailing_bits(jws.split(".")[index])
            if twin is not None:
                break
        else:  # pragma: no cover
            pytest.fail("no segment length with unused trailing bits")
        assert twin != jws.split(".")[index]
        error = error_of(partial(verify, with_segment(signer, jws, index, twin), signer))
        assert (error.code, "canonical" in str(error)) == ("malformed", True)


def test_a_header_that_is_not_json_or_not_an_object_is_malformed(signer: ResumptionSigner) -> None:
    body = b64url_encode(json.dumps(payload()).encode())
    for header in (b"not json", b'["ES256"]', b'"ES256"', b"null", b"5", b"", b"\xff\xfe", b"\xef\xbb\xbf{}"):
        jws = signer.sign_segments(b64url_encode(header), body)
        assert code_of(lambda jws=jws: verify(jws, signer)) == "malformed"


def test_a_payload_that_is_not_json_or_not_an_object_is_malformed(signer: ResumptionSigner) -> None:
    header = b64url_encode(b'{"alg":"ES256","kid":"k1"}')
    for body in (
        b"not json",
        b"[]",
        b'"x"',
        b"null",
        b"7",
        b"\xff",
    ):
        jws = signer.sign_segments(header, b64url_encode(body))
        assert code_of(lambda jws=jws: verify(jws, signer)) == "malformed"


def test_a_payload_that_is_otherwise_valid_but_not_strict_json_is_malformed(signer: ResumptionSigner) -> None:
    """Each of these would be accepted by a lenient parser (`NaN`, a repeated member that the last one wins, bytes
    that are not UTF-8 replaced with U+FFFD), so the claims around them are all valid."""
    header = b64url_encode(b'{"alg":"ES256","kid":"k1"}')
    valid = json.dumps(payload()).encode()[:-1]
    for tail in (
        b',"a":NaN}',
        b',"a":-Infinity}',
        b',"a":Infinity}',
        b',"a":1,"a":2}',
        b',"a":"\xff"}',
        b',"a":"\xc3"}',
    ):
        jws = signer.sign_segments(header, b64url_encode(valid + tail))
        assert code_of(lambda jws=jws: verify(jws, signer)) == "malformed", tail
    assert verify(signer.sign_segments(header, b64url_encode(valid + b',"a":"ok"}')), signer)["a"] == "ok"
    repeated = json.dumps(payload(tool_ref="other")).encode()[:-1] + b',"tool_ref":"' + TOOL.encode() + b'"}'
    assert code_of(lambda: verify(signer.sign_segments(header, b64url_encode(repeated)), signer)) == "malformed"


def test_a_header_that_is_otherwise_valid_but_not_strict_json_is_malformed(signer: ResumptionSigner) -> None:
    body = b64url_encode(json.dumps(payload()).encode())
    for header in (b'{"alg":"ES256","kid":"k1","a":NaN}', b'{"alg":"ES256","kid":"k1","a":"\xff"}'):
        assert code_of(lambda header=header: verify(signer.sign_segments(b64url_encode(header), body), signer)) == (
            "malformed"
        )
    assert verify(signer.sign_segments(b64url_encode(b'{"alg":"ES256","kid":"k1","a":1}'), body), signer)


def test_json_nested_beyond_the_parsers_stack_is_malformed_not_a_crash(signer: ResumptionSigner) -> None:
    header = b64url_encode(b'{"alg":"ES256","kid":"k1"}')
    jws = signer.sign_segments(header, b64url_encode(b"[" * 100_000 + b"]" * 100_000))
    assert code_of(lambda: verify(jws, signer)) == "malformed"


def test_a_header_with_a_repeated_member_is_malformed(signer: ResumptionSigner) -> None:
    header = b64url_encode(b'{"alg":"ES256","kid":"k1","kid":"other"}')
    jws = signer.sign_segments(header, b64url_encode(json.dumps(payload()).encode()))
    assert code_of(lambda: verify(jws, signer)) == "malformed"


@pytest.mark.parametrize("kid", [None, "", 5, ["k1"]])
def test_a_header_without_a_usable_kid_is_malformed(kid: Any, signer: ResumptionSigner) -> None:
    header = {"alg": "ES256", "kid": kid}
    if kid is None:
        del header["kid"]
    assert code_of(lambda: verify(signer.sign(payload(), header=header), signer)) == "malformed"


# --- the algorithm and crit -----------------------------------------------------------------------


@pytest.mark.parametrize("alg", ["none", "HS256", "RS256", "ES384", "es256", "ES256 ", None, 256, ["ES256"]])
def test_only_es256_is_accepted(alg: Any, signer: ResumptionSigner) -> None:
    header = {"alg": alg, "kid": "k1"}
    if alg is None:
        del header["alg"]
    assert code_of(lambda: verify(signer.sign(payload(), header=header), signer)) == "unsupported_alg"


@pytest.mark.parametrize("crit", [["exp"], [], ["b64"], "exp", None, 0, False])
def test_a_header_with_crit_is_refused_even_when_it_is_empty(crit: Any, signer: ResumptionSigner) -> None:
    """TypeScript has no crit check. This port refuses the member outright (RFC 7515 4.1.11: an unknown critical
    extension must be rejected, and this verifier understands none)."""
    jws = signer.sign(payload(), header={"alg": "ES256", "kid": "k1", "crit": crit})
    assert code_of(lambda: verify(jws, signer)) == "malformed"


def test_the_algorithm_is_checked_before_crit_and_before_the_kid(signer: ResumptionSigner) -> None:
    jws = signer.sign(payload(), header={"alg": "HS256", "kid": "nope", "crit": ["x"]})
    assert code_of(lambda: verify(jws, signer)) == "unsupported_alg"


# --- the key --------------------------------------------------------------------------------------


def verify_with_jwks(jws: str, jwks: Any, **options: Any) -> dict[str, Any]:
    return verify_resumption(jws, jwks, EXPECTED, replay_guard=None, now=NOW, **options)


def test_a_kid_that_is_not_in_the_key_set_is_unknown(signer: ResumptionSigner) -> None:
    jws = ResumptionSigner("other").sign(payload())
    assert code_of(lambda: verify(jws, signer)) == "unknown_kid"


def test_a_well_formed_key_set_without_the_kid_is_unknown(signer: ResumptionSigner) -> None:
    assert code_of(lambda: verify_with_jwks(signer.sign(payload()), {"keys": []})) == "unknown_kid"


class _ModelWithKeysAttribute:
    """What a typed client might return for the key set: it has `.keys`, but it is not a mapping."""

    keys: ClassVar[list[dict[str, str]]] = [{"kid": "k1"}]


@pytest.mark.parametrize(
    "jwks",
    [{}, {"keys": None}, {"keys": "k1"}, {"keys": {"kid": "k1"}}, [], [{"kid": "k1"}], None, _ModelWithKeysAttribute()],
)
def test_a_key_set_of_the_wrong_shape_is_the_callers_fault_not_a_verdict(jwks: Any, signer: ResumptionSigner) -> None:
    """The original's `jwks.keys.find` throws a TypeError here. A ResumptionError would read as key rotation."""
    with pytest.raises(TypeError, match="jwks"):
        verify_with_jwks(signer.sign(payload()), jwks)


def test_a_key_set_of_the_wrong_shape_is_not_looked_at_when_the_resumption_fails_an_earlier_check(
    signer: ResumptionSigner,
) -> None:
    assert code_of(lambda: verify_with_jwks("a.b.c", None)) == "malformed"
    assert code_of(lambda: verify_with_jwks(signer.sign(payload(), header={"alg": "none"}), None)) == "unsupported_alg"


def test_entries_without_the_kid_are_skipped_and_the_first_match_wins(signer: ResumptionSigner) -> None:
    decoy = {**signer.jwk, "x": ResumptionSigner("k1").jwk["x"]}
    jwks = {"keys": [{"no": "kid"}, {**signer.jwk, "kid": "other"}, signer.jwk, decoy]}
    assert verify_with_jwks(signer.sign(payload()), jwks) == payload()
    assert code_of(lambda: verify_with_jwks(signer.sign(payload()), {"keys": [decoy, signer.jwk]})) == "bad_signature"


class _AttributeJwk:
    def __init__(self, jwk: dict[str, Any]) -> None:
        self.__dict__.update(jwk)


@pytest.mark.parametrize("entry", [None, 5, "k1", ["k1"]])
def test_a_key_set_entry_that_is_not_a_mapping_is_a_type_error(entry: object, signer: ResumptionSigner) -> None:
    for jwks in ({"keys": [entry, signer.jwk]}, {"keys": [_AttributeJwk(signer.jwk)]}):
        with pytest.raises(TypeError, match="must be a mapping"):
            verify_with_jwks(signer.sign(payload()), jwks)


@pytest.mark.parametrize(
    "change",
    [{"kty": "RSA"}, {"kty": None}, {"crv": "P-384"}, {"crv": "secp256k1"}, {"crv": None}, {"kty": "ec"}],
)
def test_a_key_that_is_not_ec_p256_is_unknown(change: dict[str, Any], signer: ResumptionSigner) -> None:
    jwk = {**signer.jwk, **change}
    assert code_of(lambda: verify_with_jwks(signer.sign(payload()), {"keys": [jwk]})) == "unknown_kid"


@pytest.mark.parametrize("missing", ["x", "y"])
@pytest.mark.parametrize("value", [None, 5, ["a"]])
def test_a_key_without_string_coordinates_is_malformed(missing: str, value: Any, signer: ResumptionSigner) -> None:
    jwk = {**signer.jwk, missing: value}
    if value is None:
        del jwk[missing]
    assert code_of(lambda: verify_with_jwks(signer.sign(payload()), {"keys": [jwk]})) == "malformed"


def test_a_point_that_is_not_on_the_curve_is_a_bad_signature_not_a_crash(signer: ResumptionSigner) -> None:
    jwk = {**signer.jwk, "y": b64url_encode((int.from_bytes(_b64(signer.jwk["y"]), "big") ^ 1).to_bytes(32, "big"))}
    assert code_of(lambda: verify_with_jwks(signer.sign(payload()), {"keys": [jwk]})) == "bad_signature"


def _b64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@pytest.mark.parametrize(
    "coordinate",
    ["", "AA", b64url_encode(b"\x01" * 31), b64url_encode(b"\x01" * 33), "not base64url!", b64url_encode(b"\xff" * 32)],
)
@pytest.mark.parametrize("which", ["x", "y"])
def test_a_coordinate_of_the_wrong_size_or_form_is_a_bad_signature(
    which: str, coordinate: str, signer: ResumptionSigner
) -> None:
    jwk = {**signer.jwk, which: coordinate}
    assert code_of(lambda: verify_with_jwks(signer.sign(payload()), {"keys": [jwk]})) == "bad_signature"


def _signer_whose(coordinate: str, leading_zero: bool) -> ResumptionSigner:
    for _ in range(20000):
        candidate = ResumptionSigner("k1")
        if (_b64(candidate.jwk[coordinate])[0] == 0) == leading_zero:
            return candidate
    raise AssertionError("no key found")  # about 1 in 256 keys has a leading zero byte; this is not reachable


@pytest.mark.parametrize("which", ["x", "y"])
def test_a_real_coordinate_with_a_zero_byte_added_in_front_is_a_bad_signature(
    which: str, signer: ResumptionSigner
) -> None:
    """The padded value is the same integer, on the curve, and verifies; only the 32-byte rule refuses it."""
    jwk = {**signer.jwk, which: b64url_encode(b"\x00" + _b64(signer.jwk[which]))}
    assert code_of(lambda: verify_with_jwks(signer.sign(payload()), {"keys": [jwk]})) == "bad_signature"


@pytest.mark.parametrize("which", ["x", "y"])
def test_a_real_coordinate_with_its_leading_zero_byte_stripped_is_a_bad_signature(which: str) -> None:
    key = _signer_whose(which, leading_zero=True)
    jwk = {**key.jwk, which: b64url_encode(_b64(key.jwk[which]).lstrip(b"\x00"))}
    assert len(_b64(jwk[which])) < 32
    assert code_of(lambda: verify_with_jwks(key.sign(payload()), {"keys": [jwk]})) == "bad_signature"
    assert verify_with_jwks(key.sign(payload()), key.jwks) == payload()


def test_a_bad_key_is_judged_before_a_bad_signature_encoding(signer: ResumptionSigner) -> None:
    """TypeScript imports the key first; a key that cannot be imported is `bad_signature` even if the signature
    text is also malformed."""
    jws = replace_part(signer.sign(payload()), 2, "ab+c")
    off_curve = {**signer.jwk, "y": signer.jwk["x"]}
    assert code_of(lambda: verify_with_jwks(jws, {"keys": [off_curve]})) == "bad_signature"
    assert code_of(lambda: verify_with_jwks(jws, {"keys": [signer.jwk]})) == "malformed"


# --- the signature --------------------------------------------------------------------------------


def test_a_payload_segment_that_is_not_base64url_text_fails_the_signature_before_it_is_decoded(
    signer: ResumptionSigner,
) -> None:
    """The signature covers the segment's text as sent; TypeScript checks it before decoding the payload."""
    jws = signer.sign(payload())
    for junk in ("ab+c", "\uff21\uff22", "\u00e9"):
        assert code_of(lambda junk=junk: verify(replace_part(jws, 1, junk), signer)) == "bad_signature"


def test_a_changed_payload_is_a_bad_signature(signer: ResumptionSigner) -> None:
    jws = signer.sign(payload())
    other = signer.sign(payload(tool_ref="mcp:tracker:delete_everything"))
    forged = replace_part(jws, 1, other.split(".")[1])
    assert code_of(lambda: verify(forged, signer)) == "bad_signature"


def test_a_signature_by_another_key_with_the_same_kid_is_a_bad_signature(signer: ResumptionSigner) -> None:
    assert code_of(lambda: verify(ResumptionSigner("k1").sign(payload()), signer)) == "bad_signature"


@pytest.mark.parametrize("length", [0, 1, 32, 63, 65, 96])
def test_a_signature_that_is_not_64_bytes_is_a_bad_signature(length: int, signer: ResumptionSigner) -> None:
    header = b64url_encode(b'{"alg":"ES256","kid":"k1"}')
    body = b64url_encode(json.dumps(payload()).encode())
    jws = f"{header}.{body}.{b64url_encode(b'A' * length)}" if length else f"{header}.{body}.AA"
    assert code_of(lambda: verify(jws, signer)) == "bad_signature"


def test_a_valid_signature_padded_to_65_bytes_is_refused_not_read_as_the_same_signature(
    signer: ResumptionSigner,
) -> None:
    """A leading zero byte on s does not change the integer, so only the length check stops r || 0x00 || s."""
    jws = signer.sign(payload())
    header, body, _ = jws.split(".")
    raw = signer.raw_signature(f"{header}.{body}")
    assert verify(jws, signer) == payload()
    padded = f"{header}.{body}.{b64url_encode(raw[:32] + b'\x00' + raw[32:])}"
    error = error_of(lambda: verify(padded, signer))
    assert (error.code, "64 bytes" in str(error)) == ("bad_signature", True)
    short = f"{header}.{body}.{b64url_encode(raw[:32] + raw[33:])}"
    assert code_of(lambda: verify(short, signer)) == "bad_signature"


def test_a_signature_whose_r_and_s_are_out_of_range_is_a_bad_signature(signer: ResumptionSigner) -> None:
    header = b64url_encode(b'{"alg":"ES256","kid":"k1"}')
    body = b64url_encode(json.dumps(payload()).encode())
    for raw in (bytes(64), b"\xff" * 64, bytes(32) + b"\x01" * 32, b"\x01" * 32 + bytes(32)):
        assert code_of(lambda raw=raw: verify(f"{header}.{body}.{b64url_encode(raw)}", signer)) == "bad_signature"


def test_a_bad_signature_keeps_the_cause(signer: ResumptionSigner) -> None:
    jws = ResumptionSigner("k1").sign(payload())
    with pytest.raises(ResumptionError) as caught:
        verify(jws, signer)
    assert isinstance(caught.value.__cause__, InvalidSignature)


def test_a_fault_in_the_crypto_backend_propagates_as_itself(
    signer: ResumptionSigner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the failures that mean 'not a valid signature or key' are `bad_signature`; anything else is the
    environment (OpenSSL missing P-256, a bug) and must not look like a forgery."""

    def unsupported(*_: Any) -> None:
        raise UnsupportedAlgorithm("no P-256 here")

    monkeypatch.setattr(resumption, "_ecdsa_verify", unsupported)
    with pytest.raises(UnsupportedAlgorithm):
        verify(signer.sign(payload()), signer)

    def broken(*_: Any) -> None:
        raise RuntimeError("backend exploded")

    monkeypatch.setattr(resumption, "_ecdsa_verify", broken)
    with pytest.raises(RuntimeError, match="exploded"):
        verify(signer.sign(payload()), signer)


def test_a_fault_while_loading_the_key_propagates_as_itself(
    signer: ResumptionSigner, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_: Any) -> None:
        raise UnsupportedAlgorithm("no P-256 here")

    monkeypatch.setattr(resumption, "_load_p256_key", broken)
    with pytest.raises(UnsupportedAlgorithm):
        verify(signer.sign(payload()), signer)


# --- expiry ---------------------------------------------------------------------------------------


def test_expiry_is_expires_at_plus_skew_less_than_or_equal_to_now(signer: ResumptionSigner) -> None:
    jws = signer.sign(payload())
    just_before = EXPIRES_AT - timedelta(microseconds=1)
    assert verify(jws, signer, now=just_before) == payload()
    assert code_of(lambda: verify(jws, signer, now=EXPIRES_AT)) == "expired"
    assert code_of(lambda: verify(jws, signer, now=EXPIRES_AT + timedelta(seconds=1))) == "expired"


def test_the_skew_moves_the_boundary_by_exactly_that_many_seconds(signer: ResumptionSigner) -> None:
    jws = signer.sign(payload())
    edge = EXPIRES_AT + timedelta(seconds=30)
    assert verify(jws, signer, now=edge - timedelta(microseconds=1), clock_skew_seconds=30) == payload()
    assert code_of(lambda: verify(jws, signer, now=edge, clock_skew_seconds=30)) == "expired"
    assert verify(jws, signer, now=EXPIRES_AT, clock_skew_seconds=0.5) == payload()
    assert code_of(lambda: verify(jws, signer, now=EXPIRES_AT + timedelta(seconds=0.5), clock_skew_seconds=0.5)) == (
        "expired"
    )


def test_the_default_skew_is_zero_and_the_default_clock_is_the_current_time(signer: ResumptionSigner) -> None:
    past = signer.sign(payload(expires_at="2020-01-01T00:00:00Z"))
    assert code_of(lambda: verify_resumption(past, signer.jwks, EXPECTED, replay_guard=None)) == "expired"
    future = signer.sign(payload(expires_at="2999-01-01T00:00:00Z"))
    assert verify_resumption(future, signer.jwks, EXPECTED, replay_guard=None)["resolution"] == "approved"


def test_expiry_compares_instants_not_spellings(signer: ResumptionSigner) -> None:
    """12:05:00Z is 14:05:00+02:00 and 07:05:00-05:00; `now` in another zone is the same instant."""
    for spelling in ("2026-10-04T14:05:00+02:00", "2026-10-04T07:05:00-05:00", "2026-10-04t12:05:00z"):
        jws = signer.sign(payload(expires_at=spelling))
        assert verify(jws, signer, now=EXPIRES_AT - timedelta(seconds=1))["expires_at"] == spelling
        assert code_of(lambda jws=jws: verify(jws, signer, now=EXPIRES_AT)) == "expired"
    jws = signer.sign(payload())
    zone = timezone(timedelta(hours=-7))
    assert code_of(lambda: verify(jws, signer, now=EXPIRES_AT.astimezone(zone))) == "expired"
    assert verify(jws, signer, now=(EXPIRES_AT - timedelta(seconds=1)).astimezone(zone))


@pytest.mark.parametrize(
    "stamp",
    [
        None,
        5,
        True,
        ["2099-01-01T00:00:00Z"],
        "",
        "2099-01-01",
        "2099-01-01T00:00:00",  # no offset: naive
        "2099-01-01T00:00Z",
        "2099-01-01 00:00:00Z",  # a space, not T
        "20990101T000000Z",
        "2099-1-1T0:0:0Z",
        " 2099-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z ",
        "2099-01-01T00:00:00Z\n",
        "2099-01-01T00:00:00+0000",
        "2099-01-01T00:00:00+00",
        "2099-01-01T00:00:00.Z",
        "2099-01-01T00:00:00,5Z",
        "2099-02-30T00:00:00Z",
        "2099-13-01T00:00:00Z",
        "2099-01-01T24:00:00Z",
        "2099-01-01T00:60:00Z",
        "2099-01-01T00:00:60Z",
        "2099-01-01T00:00:00+24:00",
        "2099-01-01T00:00:00+00:60",
        "0000-01-01T00:00:00Z",
        "\uff12\uff10\uff19\uff19-01-01T00:00:00Z",  # full-width digits
        "2099-01-01T00:00:00Z+01:00",
        "Jan 1 2099",
        "1",
        "NaN",
    ],
)
def test_expires_at_must_be_strict_rfc_3339(stamp: Any, signer: ResumptionSigner) -> None:
    """TypeScript reads `expires_at` with the lenient `Date.parse`; this port accepts only the RFC 3339 form."""
    assert code_of(lambda: verify(signer.sign(payload(expires_at=stamp)), signer)) == "malformed"


def test_a_missing_expires_at_is_malformed(signer: ResumptionSigner) -> None:
    assert code_of(lambda: verify(signer.sign(payload(expires_at=...)), signer)) == "malformed"


@pytest.mark.parametrize(
    "stamp",
    ["2099-01-01T00:00:00Z", "2099-01-01T00:00:00.1Z", "2099-01-01T00:00:00.123456789012Z", "2099-12-31T23:59:59.999Z"],
)
def test_fractional_seconds_of_any_length_are_accepted(stamp: str, signer: ResumptionSigner) -> None:
    assert verify(signer.sign(payload(expires_at=stamp)), signer)["expires_at"] == stamp


def test_expiry_is_checked_after_the_signature_and_before_the_resolution(signer: ResumptionSigner) -> None:
    stale = payload(expires_at="2020-01-01T00:00:00Z", resolution="rejected", tool_ref="other", action_digest="0")
    assert code_of(lambda: verify(signer.sign(stale), signer)) == "expired"
    tampered = replace_part(signer.sign(stale), 1, signer.sign(payload()).split(".")[1])
    assert code_of(lambda: verify(tampered, signer)) == "bad_signature"


def test_a_resumption_that_expires_at_the_end_of_time_does_not_overflow(signer: ResumptionSigner) -> None:
    jws = signer.sign(payload(expires_at="9999-12-31T23:59:59.999999Z"))
    seen: list[datetime] = []

    class Spy:
        def first_use(self, key: str, expires_at: datetime) -> bool:
            seen.append(expires_at)
            return True

    assert verify(jws, signer, guard=Spy(), clock_skew_seconds=3600)["approval_id"] == "appr-1"
    assert seen == [datetime.max.replace(tzinfo=UTC)]


# --- the resolution -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "resolution", ["rejected", "Approved", "approved ", "", "expired", None, 1, True, ["approved"]]
)
def test_only_an_approved_resolution_is_acted_on_by_default(resolution: Any, signer: ResumptionSigner) -> None:
    jws = signer.sign(payload(resolution=resolution))
    assert code_of(lambda: verify(jws, signer)) == "not_approved"


def test_a_missing_resolution_is_not_approved(signer: ResumptionSigner) -> None:
    assert code_of(lambda: verify(signer.sign(payload(resolution=...)), signer)) == "not_approved"


def test_accept_resolutions_replaces_the_default(signer: ResumptionSigner) -> None:
    rejected = signer.sign(payload(resolution="rejected"))
    assert verify(rejected, signer, accept_resolutions=("rejected", "approved"))["resolution"] == "rejected"
    approved = signer.sign(payload())
    assert code_of(lambda: verify(approved, signer, accept_resolutions=("rejected",))) == "not_approved"
    assert code_of(lambda: verify(approved, signer, accept_resolutions=())) == "not_approved"
    assert verify(approved, signer, accept_resolutions=["approved"])["resolution"] == "approved"
    assert verify(approved, signer, accept_resolutions=frozenset({"approved"}))["resolution"] == "approved"


@pytest.mark.parametrize("accepted", ["approved", b"approved", None, 5])
def test_accept_resolutions_must_be_a_collection_of_strings_never_a_bare_string(
    accepted: Any, signer: ResumptionSigner
) -> None:
    """`"app" in "approved"` is true in Python, so a bare string would accept a prefix."""
    with pytest.raises(TypeError, match="accept_resolutions"):
        verify(signer.sign(payload()), signer, accept_resolutions=accepted)
    with pytest.raises(TypeError, match="accept_resolutions"):
        verify(signer.sign(payload()), signer, accept_resolutions=("approved", 5))


def test_a_prefix_of_an_accepted_resolution_is_not_accepted(signer: ResumptionSigner) -> None:
    assert code_of(lambda: verify(signer.sign(payload(resolution="app")), signer)) == "not_approved"


# --- the tool and the digest ----------------------------------------------------------------------


@pytest.mark.parametrize("tool", ["mcp:tracker:delete_issue", "", None, 5, TOOL.upper(), TOOL + " "])
def test_a_resumption_for_another_tool_is_a_tool_mismatch(tool: Any, signer: ResumptionSigner) -> None:
    assert code_of(lambda: verify(signer.sign(payload(tool_ref=tool)), signer)) == "tool_mismatch"
    assert code_of(lambda: verify(signer.sign(payload(tool_ref=...)), signer)) == "tool_mismatch"


@pytest.mark.parametrize("digest", ["0" * 64, "", None, 5, DIGEST.upper(), DIGEST[:-1], DIGEST + "0"])
def test_a_resumption_for_other_arguments_is_a_digest_mismatch(digest: Any, signer: ResumptionSigner) -> None:
    assert code_of(lambda: verify(signer.sign(payload(action_digest=digest)), signer)) == "digest_mismatch"
    assert code_of(lambda: verify(signer.sign(payload(action_digest=...)), signer)) == "digest_mismatch"


def test_the_expected_digest_is_the_one_arg_digest_computes(signer: ResumptionSigner) -> None:
    jws = signer.sign(payload())
    ok = ExpectedAction.for_call(TOOL, ARGS)
    assert ok == EXPECTED
    assert ok.arg_digest == arg_digest(ARGS)
    assert verify(jws, signer, expected=ok)["action_digest"] == DIGEST
    changed = ExpectedAction.for_call(TOOL, {"title": "x", "n": 2})
    assert code_of(lambda: verify(jws, signer, expected=changed)) == "digest_mismatch"
    assert ExpectedAction.for_call(TOOL, {"n": 1, "title": "x"}) == EXPECTED  # key order is canonicalised away


def test_for_call_refuses_arguments_that_have_no_digest() -> None:
    with pytest.raises(DigestError):
        ExpectedAction.for_call(TOOL, {"n": math.nan})


def test_an_expected_action_is_two_strings() -> None:
    for tool, digest in ((None, DIGEST), (TOOL, None), (5, DIGEST), (TOOL, b"abc")):
        with pytest.raises(TypeError):
            ExpectedAction(tool_ref=tool, arg_digest=digest)  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]


def test_the_tool_is_judged_before_the_digest(signer: ResumptionSigner) -> None:
    both = signer.sign(payload(tool_ref="other", action_digest="0" * 64))
    assert code_of(lambda: verify(both, signer)) == "tool_mismatch"


def test_the_resolution_is_judged_before_the_tool(signer: ResumptionSigner) -> None:
    both = signer.sign(payload(resolution="rejected", tool_ref="other"))
    assert code_of(lambda: verify(both, signer)) == "not_approved"


# --- the replay guard -----------------------------------------------------------------------------


def test_replay_guard_is_a_required_keyword(signer: ResumptionSigner) -> None:
    jws = signer.sign(payload())
    with pytest.raises(TypeError, match="replay_guard"):
        verify_resumption(jws, signer.jwks, EXPECTED, now=NOW)  # type: ignore[call-arg]  # pyright: ignore[reportCallIssue]
    with pytest.raises(TypeError):
        verify_resumption(jws, signer.jwks, EXPECTED, None)  # type: ignore[misc]  # pyright: ignore[reportCallIssue]


def test_none_is_an_explicit_opt_out_and_accepts_the_same_resumption_twice(signer: ResumptionSigner) -> None:
    jws = signer.sign(payload())
    assert verify(jws, signer, guard=None) == verify(jws, signer, guard=None)


def test_the_second_use_of_a_resumption_is_replayed(signer: ResumptionSigner) -> None:
    guard = InMemoryReplayGuard(lambda: NOW)
    jws = signer.sign(payload())
    verify(jws, signer, guard=guard)
    assert code_of(lambda: verify(jws, signer, guard=guard)) == "replayed"


def test_the_other_valid_signature_of_the_same_payload_is_replayed_not_accepted_twice(signer: ResumptionSigner) -> None:
    """ECDSA admits a second valid signature (r, n - s) for the same payload; the replay key is the approval, not
    the signature, so both spellings are one use."""
    guard = InMemoryReplayGuard(lambda: NOW)
    low = signer.sign(payload(), high_s=False)
    high = signer.sign(payload(), high_s=True)
    assert low != high
    assert verify(low, signer, guard=guard)["approval_id"] == "appr-1"
    assert code_of(lambda: verify(high, signer, guard=guard)) == "replayed"
    other = InMemoryReplayGuard(lambda: NOW)
    assert verify(high, signer, guard=other)["approval_id"] == "appr-1"  # the high-S form does verify
    assert code_of(lambda: verify(low, signer, guard=other)) == "replayed"


def test_a_different_approval_is_a_different_key(signer: ResumptionSigner) -> None:
    guard = InMemoryReplayGuard(lambda: NOW)
    verify(signer.sign(payload(approval_id="a")), signer, guard=guard)
    verify(signer.sign(payload(approval_id="b")), signer, guard=guard)
    assert code_of(lambda: verify(signer.sign(payload(approval_id="a", action_id="act_2")), signer, guard=guard)) == (
        "replayed"
    )


@pytest.mark.parametrize("approval_id", [None, "", 5, ["a"], {"a": 1}])
def test_a_guarded_resumption_without_a_usable_approval_id_is_malformed(
    approval_id: Any, signer: ResumptionSigner
) -> None:
    guard = InMemoryReplayGuard(lambda: NOW)
    assert code_of(lambda: verify(signer.sign(payload(approval_id=approval_id)), signer, guard=guard)) == "malformed"
    assert code_of(lambda: verify(signer.sign(payload(approval_id=...)), signer, guard=guard)) == "malformed"


def test_an_unguarded_resumption_needs_no_approval_id(signer: ResumptionSigner) -> None:
    assert verify(signer.sign(payload(approval_id=...)), signer, guard=None)["tool_ref"] == TOOL


class SpyGuard:
    def __init__(self, answer: Any = True) -> None:
        self.calls: list[tuple[str, datetime]] = []
        self.answer = answer

    def first_use(self, key: str, expires_at: datetime) -> Any:
        self.calls.append((key, expires_at))
        return self.answer


@pytest.mark.parametrize(
    "overrides",
    [
        {"resolution": "rejected"},
        {"tool_ref": "other"},
        {"action_digest": "0" * 64},
        {"expires_at": "2020-01-01T00:00:00Z"},
    ],
)
def test_the_guard_is_consulted_last_so_a_rejected_resumption_does_not_burn_its_key(
    overrides: dict[str, Any], signer: ResumptionSigner
) -> None:
    guard = SpyGuard()
    with pytest.raises(ResumptionError):
        verify(signer.sign(payload(**overrides)), signer, guard=guard)
    assert guard.calls == []
    assert verify(signer.sign(payload()), signer, guard=guard)["approval_id"] == "appr-1"
    assert len(guard.calls) == 1


def test_a_bad_signature_never_reaches_the_guard(signer: ResumptionSigner) -> None:
    guard = SpyGuard()
    with pytest.raises(ResumptionError):
        verify(ResumptionSigner("k1").sign(payload()), signer, guard=guard)
    assert guard.calls == []


def test_the_guard_is_asked_to_keep_the_key_until_expires_at_plus_the_skew(signer: ResumptionSigner) -> None:
    """A guard that forgot at `expires_at` would accept a duplicate during the skew window."""
    guard = SpyGuard()
    verify(signer.sign(payload()), signer, guard=guard, clock_skew_seconds=90)
    assert guard.calls == [("appr-1", EXPIRES_AT + timedelta(seconds=90))]
    guard.calls.clear()
    verify(signer.sign(payload()), signer, guard=guard)
    assert guard.calls == [("appr-1", EXPIRES_AT)]
    assert guard.calls[0][1].utcoffset() is not None


def test_a_real_guard_holds_a_duplicate_through_the_skew_window(signer: ResumptionSigner) -> None:
    clock = {"now": NOW}
    guard = InMemoryReplayGuard(lambda: clock["now"])
    jws = signer.sign(payload())
    skew = 60
    verify(jws, signer, guard=guard, clock_skew_seconds=skew)
    clock["now"] = EXPIRES_AT + timedelta(seconds=skew - 1)  # still passes the expiry check...
    assert code_of(lambda: verify(jws, signer, guard=guard, now=clock["now"], clock_skew_seconds=skew)) == "replayed"


@pytest.mark.parametrize("answer", [1, "yes", None, 0, "", [], object()])
def test_a_guard_that_does_not_answer_with_a_bool_is_refused_not_trusted(answer: Any, signer: ResumptionSigner) -> None:
    """A truthy non-bool would read as 'fresh'. Fail closed."""
    with pytest.raises(TypeError, match="bool"):
        verify(signer.sign(payload()), signer, guard=SpyGuard(answer))


def test_a_guard_that_raises_propagates_and_the_resumption_is_not_accepted(signer: ResumptionSigner) -> None:
    class Down:
        def first_use(self, key: str, expires_at: datetime) -> bool:
            raise ConnectionError("store down")

    with pytest.raises(ConnectionError):
        verify(signer.sign(payload()), signer, guard=Down())


def test_a_forgetting_guard_lets_a_failed_resume_try_again(signer: ResumptionSigner) -> None:
    guard = ForgettingReplayGuard(lambda: NOW)
    jws = signer.sign(payload())
    verify(jws, signer, guard=guard)
    assert code_of(lambda: verify(jws, signer, guard=guard)) == "replayed"
    guard.forget("appr-1")
    assert verify(jws, signer, guard=guard)["approval_id"] == "appr-1"


def test_many_threads_verifying_one_resumption_yield_exactly_one_acceptance(signer: ResumptionSigner) -> None:
    guard = InMemoryReplayGuard(lambda: NOW)
    jws = signer.sign(payload())
    threads = 24
    barrier = threading.Barrier(threads)
    outcomes: list[str] = []
    lock = threading.Lock()

    def run() -> None:
        barrier.wait()
        try:
            verify(jws, signer, guard=guard)
            result = "ok"
        except ResumptionError as error:
            result = error.code
        with lock:
            outcomes.append(result)

    workers = [threading.Thread(target=run) for _ in range(threads)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    assert sorted(outcomes) == ["ok"] + ["replayed"] * (threads - 1)


# --- clock and skew arguments ---------------------------------------------------------------------


def test_a_naive_now_is_refused(signer: ResumptionSigner) -> None:
    with pytest.raises(ValueError, match="timezone"):
        verify(signer.sign(payload()), signer, now=datetime(2026, 10, 4, 12, 0, 0))


@pytest.mark.parametrize("skew", [-1, -0.001, math.nan, math.inf, -math.inf, True, "30", None, 1e300, 10**30])
def test_a_skew_that_is_not_a_finite_non_negative_number_is_refused(skew: Any, signer: ResumptionSigner) -> None:
    with pytest.raises(ValueError, match="clock_skew_seconds"):
        verify(signer.sign(payload()), signer, clock_skew_seconds=skew)


# --- the async entry point ------------------------------------------------------------------------


class AsyncGuard:
    def __init__(self) -> None:
        self.seen: set[str] = set()

    async def first_use(self, key: str, expires_at: datetime) -> bool:
        await asyncio.sleep(0)
        if key in self.seen:
            return False
        self.seen.add(key)
        return True


def test_averify_accepts_an_async_guard_and_reports_a_replay(signer: ResumptionSigner) -> None:
    guard = AsyncGuard()
    jws = signer.sign(payload())

    async def run() -> list[str]:
        out: list[str] = []
        for _ in range(2):
            try:
                result = await averify_resumption(jws, signer.jwks, EXPECTED, replay_guard=guard, now=NOW)
                out.append(result["approval_id"])
            except ResumptionError as error:
                out.append(error.code)
        return out

    assert asyncio.run(run()) == ["appr-1", "replayed"]


def test_averify_accepts_a_sync_guard_and_none(signer: ResumptionSigner) -> None:
    jws = signer.sign(payload())

    async def run() -> list[str]:
        second = ""
        sync_guard = InMemoryReplayGuard(lambda: NOW)
        first = await averify_resumption(jws, signer.jwks, EXPECTED, replay_guard=sync_guard, now=NOW)
        try:
            await averify_resumption(jws, signer.jwks, EXPECTED, replay_guard=sync_guard, now=NOW)
        except ResumptionError as error:
            second = error.code
        opted_out = await averify_resumption(jws, signer.jwks, EXPECTED, replay_guard=None, now=NOW)
        return [first["approval_id"], second, opted_out["approval_id"]]

    assert asyncio.run(run()) == ["appr-1", "replayed", "appr-1"]


def test_averify_runs_every_check_the_sync_entry_point_runs(signer: ResumptionSigner) -> None:
    async def code(jws: str, **options: Any) -> str:
        try:
            await averify_resumption(jws, signer.jwks, EXPECTED, replay_guard=None, now=NOW, **options)
        except ResumptionError as error:
            return error.code
        return "ok"

    async def run() -> list[str]:
        return [
            await code("a.b"),
            await code(signer.sign(payload(), header={"alg": "none", "kid": "k1"})),
            await code(ResumptionSigner("k1").sign(payload())),
            await code(signer.sign(payload(expires_at="2020-01-01T00:00:00Z"))),
            await code(signer.sign(payload(resolution="rejected"))),
            await code(signer.sign(payload(tool_ref="x"))),
            await code(signer.sign(payload(action_digest="x"))),
            await code(signer.sign(payload())),
        ]

    assert asyncio.run(run()) == [
        "malformed",
        "unsupported_alg",
        "bad_signature",
        "expired",
        "not_approved",
        "tool_mismatch",
        "digest_mismatch",
        "ok",
    ]


@pytest.mark.parametrize("answer", [1, None, "yes"])
def test_averify_also_refuses_a_guard_that_does_not_answer_with_a_bool(answer: Any, signer: ResumptionSigner) -> None:
    class Odd:
        async def first_use(self, key: str, expires_at: datetime) -> Any:
            return answer

    with pytest.raises(TypeError, match="bool"):
        asyncio.run(averify_resumption(signer.sign(payload()), signer.jwks, EXPECTED, replay_guard=Odd(), now=NOW))


def test_the_sync_entry_point_refuses_an_async_guard_instead_of_reading_its_coroutine_as_fresh(
    signer: ResumptionSigner,
) -> None:
    """A coroutine is truthy. Treating it as a bool would accept every Resumption without ever recording one."""
    guard = AsyncGuard()
    with pytest.raises(TypeError, match="averify_resumption"):
        verify(signer.sign(payload()), signer, guard=guard)
    assert guard.seen == set()


def test_the_signed_payload_may_hold_any_json_and_unknown_members_are_returned(signer: ResumptionSigner) -> None:
    extra = payload(policy={"id": "pol", "version": 3}, continuation={"kind": "langgraph"}, extra=[1, 2.5, None, "é"])
    assert verify(signer.sign(extra), signer) == extra


def test_signer_jwks_and_signatures_have_the_shapes_the_verifier_expects(signer: ResumptionSigner) -> None:
    assert set(signer.jwk) == {"kty", "crv", "x", "y", "kid"}
    assert len(_b64(signer.sign(payload()).split(".")[2])) == 64
    low = _b64(signer.sign(payload(), high_s=False).split(".")[2])
    high = _b64(signer.sign(payload(), high_s=True).split(".")[2])
    assert int.from_bytes(low[32:], "big") <= int.from_bytes(high[32:], "big")


def test_a_header_given_to_the_signer_is_not_mutated(signer: ResumptionSigner) -> None:
    header: Mapping[str, Any] = {"alg": "ES256", "kid": "k1"}
    signer.sign(payload(), header=header)
    assert header == {"alg": "ES256", "kid": "k1"}


def test_the_sync_entry_point_refuses_any_awaitable_not_just_a_coroutine(signer: ResumptionSigner) -> None:
    class Later:
        def __await__(self) -> Any:
            yield from ()
            return True

    class Guard:
        def first_use(self, key: str, expires_at: datetime) -> Any:
            return Later()

    with pytest.raises(TypeError, match="averify_resumption"):
        verify(signer.sign(payload()), signer, guard=Guard())


def test_averify_awaits_an_awaitable_that_is_not_a_coroutine(signer: ResumptionSigner) -> None:
    class Later:
        def __await__(self) -> Any:
            yield from ()
            return False

    class Guard:
        def first_use(self, key: str, expires_at: datetime) -> Any:
            return Later()

    with pytest.raises(ResumptionError) as caught:
        asyncio.run(averify_resumption(signer.sign(payload()), signer.jwks, EXPECTED, replay_guard=Guard(), now=NOW))
    assert caught.value.code == "replayed"


def test_a_guard_whose_clock_is_ahead_of_now_fails_loudly_instead_of_ceasing_to_guard(
    signer: ResumptionSigner,
) -> None:
    """`now` is not given to the guard, so a guard clock past the key's expiry must not quietly forget it."""
    jws = signer.sign(payload())
    ahead = InMemoryReplayGuard(lambda: NOW + timedelta(days=365))  # the key's expiry is already past for this guard
    assert code_of(lambda: verify(jws, signer, guard=ahead)) == "expired"
    assert code_of(lambda: verify(jws, signer, guard=ahead)) == "expired"  # never recorded, never a silent pass
    agreeing = InMemoryReplayGuard(lambda: NOW)
    verify(jws, signer, guard=agreeing)
    assert code_of(lambda: verify(jws, signer, guard=agreeing)) == "replayed"
