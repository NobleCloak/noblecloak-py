"""noblecloak.digest: the argument digest, `sha256(RFC 8785 JCS(arguments as sent))`, lowercase hex.

The conformance corpus is read from the pinned `@noblecloak/spec` install under `conformance/node_modules`. A missing
corpus fails the run; it never skips.
"""

from __future__ import annotations

import copy
import enum
import hashlib
import json
import pickle
import struct
from collections import OrderedDict
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
import rfc8785

from noblecloak import digest
from noblecloak.digest import MAX_NESTING_DEPTH, DigestError, arg_digest, jcs, sha256_hex

ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = ROOT / "conformance/node_modules/@noblecloak/spec/corpus"
MAX_SAFE = 2**53 - 1


# --- the conformance corpus -----------------------------------------------------------------------------------


def corpus_hash_problem(corpus: bytes, recorded: str) -> str | None:
    """Why `corpus` is not the file whose SHA-256 `recorded` names, or None when it is."""
    actual = hashlib.sha256(corpus).hexdigest()
    if actual != recorded.strip():
        return f"corpus sha256 is {actual}, the .sha256 file says {recorded.strip()}"
    return None


def load_corpus() -> list[dict[str, str]]:
    corpus_file = CORPUS_DIR / "arg-digest-pairs.json"
    assert corpus_file.is_file(), "run `bun install --frozen-lockfile` in conformance/ first; a missing corpus fails"
    raw = corpus_file.read_bytes()
    problem = corpus_hash_problem(raw, (CORPUS_DIR / "arg-digest-pairs.sha256").read_text(encoding="utf-8"))
    assert problem is None, problem
    return json.loads(raw)["pairs"]


def test_corpus_hash_matches_the_recorded_hash() -> None:
    load_corpus()


def test_a_corrupted_corpus_hash_is_reported() -> None:
    raw = (CORPUS_DIR / "arg-digest-pairs.json").read_bytes()
    recorded = (CORPUS_DIR / "arg-digest-pairs.sha256").read_text(encoding="utf-8")
    assert corpus_hash_problem(raw, recorded) is None
    assert corpus_hash_problem(raw + b" ", recorded) is not None
    assert corpus_hash_problem(raw, "0" * 64) is not None


def test_the_corpus_has_seventeen_pairs() -> None:
    assert len(load_corpus()) == 17


@pytest.mark.parametrize("pair", load_corpus(), ids=lambda p: p["id"])
def test_every_corpus_pair_digests_to_the_recorded_value(pair: dict[str, str]) -> None:
    assert arg_digest(json.loads(pair["arguments_json"])) == pair["arg_digest"]


def digest_of(corpus_id: str) -> str:
    return next(p["arg_digest"] for p in load_corpus() if p["id"] == corpus_id)


def args_of(corpus_id: str) -> Any:
    return json.loads(next(p["arguments_json"] for p in load_corpus() if p["id"] == corpus_id))


def test_nfc_and_nfd_spellings_have_different_digests() -> None:
    assert digest_of("args-01") != digest_of("args-02")
    assert arg_digest(args_of("args-01")) != arg_digest(args_of("args-02"))


def test_an_integral_float_digests_like_the_integer() -> None:
    assert jcs(args_of("args-05")) == '{"amount":1000,"currency":"USD","to":"acct_42"}'
    assert arg_digest({"amount": 1000.0, "currency": "USD", "to": "acct_42"}) == digest_of("args-03")


def test_numeric_edge_cases_serialise_in_the_es6_format() -> None:
    assert jcs(args_of("args-15")) == (
        '{"max_safe":9007199254740991,"min_safe":-9007199254740991,"neg_zero":0,"one":1,'
        '"rate":0.1,"sum":0.30000000000000004,"tiny":1e-7}'
    )


def test_keys_sort_by_utf16_code_units_not_code_points() -> None:
    # U+FB33 (one unit, 0xFB33) sorts after U+1F600 (surrogate pair, 0xD83D 0xDE00); by code point it is the reverse.
    canonical = jcs(args_of("args-16"))
    assert canonical.index("\U0001f600") < canonical.index("דּ")


# --- RFC 8785 ---------------------------------------------------------------------------------------------------

# RFC 8785 Appendix B, "ES6 Number Serialization Samples": IEEE 754 bits (hex) to the text a conforming serializer
# writes, or None where the RFC says the value cannot be serialised. Written from the RFC; the pinned `rfc8785`
# reproduces every row (test_appendix_b_number_serialisation asserts it). `@noblecloak/spec` 0.12.0 does not carry them.
APPENDIX_B: list[tuple[str, str | None]] = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("7fffffffffffffff", None),
    ("7ff0000000000000", None),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]


def double_from_bits(bits: str) -> float:
    return struct.unpack(">d", bytes.fromhex(bits))[0]


@pytest.mark.parametrize(("bits", "text"), APPENDIX_B)
def test_appendix_b_number_serialisation(bits: str, text: str | None) -> None:
    """The pinned canonicaliser writes every Appendix B number as the RFC does; `jcs` refuses what the RFC refuses
    and, as TypeScript does, any integral number beyond ±(2^53 - 1) as well."""
    value = double_from_bits(bits)
    if text is None:
        with pytest.raises(DigestError) as refused:
            jcs([value])
        assert refused.value.code == "non_finite_number"
        return
    assert rfc8785.dumps(value).decode("utf-8") == text
    if value.is_integer() and abs(value) > MAX_SAFE:
        with pytest.raises(DigestError) as refused:
            jcs([value])
        assert refused.value.code == "integer_out_of_range"
    else:
        assert jcs([value]) == f"[{text}]"


def test_rfc8785_section_3_2_3_key_sorting_sample() -> None:
    # The RFC's sorting sample: keys in UTF-16 code unit order, text kept literal except the control characters.
    sample = {
        "€": "Euro Sign",
        "\r": "Carriage Return",
        "דּ": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\U0001f600": "Emoji: Grinning Face",
        "\x80": "Control",
        "ö": "Latin Small Letter O With Diaeresis",
    }
    assert list(json.loads(jcs(sample))) == ["\r", "1", "\x80", "ö", "€", "\U0001f600", "דּ"]
    assert jcs(sample).startswith('{"\\r":"Carriage Return","1":"One","\x80":"Control"')


# --- what is refused ------------------------------------------------------------------------------------------


def refusal(value: object) -> str:
    with pytest.raises(DigestError) as refused:
        jcs(value)  # pyright: ignore[reportUnknownArgumentType]
    return refused.value.code


class Colour(enum.IntEnum):
    RED = 1


class Label(enum.StrEnum):
    A = "a"


class IntSub(int):
    pass


class StrSub(str):
    pass


class FloatSub(float):
    pass


class DictSub(dict[str, Any]):
    pass


class ListSub(list[Any]):
    pass


def test_bool_is_a_json_boolean_never_the_integer() -> None:
    assert jcs(True) == "true"
    assert jcs(False) == "false"
    assert jcs({"a": True, "b": 1}) == '{"a":true,"b":1}'
    assert arg_digest({"a": True}) != arg_digest({"a": 1})


def test_a_bool_does_not_take_the_integer_path() -> None:
    assert jcs([True, False, None]) == "[true,false,null]"


@pytest.mark.parametrize("value", [2**53, -(2**53), 2**63, 10**30])
def test_integers_outside_the_exact_range_are_refused(value: int) -> None:
    assert refusal(value) == "integer_out_of_range"
    assert refusal({"id": value}) == "integer_out_of_range"


def test_the_exact_integer_range_is_accepted() -> None:
    assert jcs([MAX_SAFE, -MAX_SAFE]) == "[9007199254740991,-9007199254740991]"


@pytest.mark.parametrize("value", [1e300, -1e300, 2.0**53, 1e21, 9007199254740992.0])
def test_integral_floats_outside_the_exact_range_are_refused(value: float) -> None:
    assert refusal(value) == "integer_out_of_range"


def test_integral_floats_inside_the_exact_range_are_accepted() -> None:
    assert jcs([float(MAX_SAFE), -float(MAX_SAFE), 1e20 / 1e20]) == "[9007199254740991,-9007199254740991,1]"


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_numbers_are_refused(value: float) -> None:
    assert refusal(value) == "non_finite_number"
    assert refusal([{"x": value}]) == "non_finite_number"


def test_negative_zero_is_zero() -> None:
    assert jcs(-0.0) == "0"
    assert arg_digest({"a": -0.0}) == arg_digest({"a": 0})


# Built with chr(): a formatter may rewrite a surrogate-pair escape in source into one valid character.
LONE_SURROGATES = {
    "d800": chr(0xD800),
    "dbff": chr(0xDBFF),
    "dc00": chr(0xDC00),
    "dfff": chr(0xDFFF),
    "trailing-high": "ok" + chr(0xD83D),
    "leading-low": chr(0xDE00) + "ok",
    "pair-as-two-code-points": chr(0xD83D) + chr(0xDE00),
}


@pytest.mark.parametrize("text", list(LONE_SURROGATES.values()), ids=list(LONE_SURROGATES))
def test_a_lone_surrogate_in_a_string_is_refused(text: str) -> None:
    # A Python str holds a valid astral character as one code point, so any surrogate, even a high one followed by a
    # low one, is unpaired.
    assert refusal(text) == "invalid_string"
    assert refusal({"k": [text]}) == "invalid_string"


def test_a_lone_surrogate_in_a_key_is_refused() -> None:
    assert refusal({chr(0xD800): 1}) == "invalid_string"


def test_an_astral_character_is_one_valid_code_point() -> None:
    assert jcs("\U0001f600") == '"\U0001f600"'


UNSUPPORTED: list[object] = [
    (1, 2),
    (),
    {1, 2},
    frozenset({1}),
    b"bytes",
    bytearray(b"x"),
    Decimal("1.5"),
    1 + 2j,
    object(),
    len,
    range(3),
    Path("."),
    OrderedDict(a=1),
    Colour.RED,
    Label.A,
    IntSub(1),
    StrSub("s"),
    FloatSub(1.5),
    DictSub(a=1),
    ListSub([1]),
]


@pytest.mark.parametrize("value", UNSUPPORTED, ids=[type(v).__name__ for v in UNSUPPORTED])
def test_anything_that_is_not_an_exact_json_type_is_unsupported(value: object) -> None:
    assert refusal(value) == "unsupported_type"
    assert refusal({"k": [value]}) == "unsupported_type"


@pytest.mark.parametrize("key", [1, 1.5, None, True, b"k", (1,), Colour.RED, Label.A, StrSub("k")])
def test_object_keys_must_be_exact_str(key: object) -> None:
    assert refusal({key: 1}) == "unsupported_type"


def test_a_cyclic_list_or_dict_is_refused() -> None:
    cyclic_list: list[Any] = []
    cyclic_list.append(cyclic_list)
    assert refusal(cyclic_list) == "unsupported_type"
    cyclic_dict: dict[str, Any] = {}
    cyclic_dict["self"] = {"inner": cyclic_dict}
    assert refusal(cyclic_dict) == "unsupported_type"


def test_a_shared_but_acyclic_reference_is_accepted() -> None:
    shared = {"a": 1}
    assert jcs({"x": shared, "y": [shared, shared]}) == '{"x":{"a":1},"y":[{"a":1},{"a":1}]}'


def nested_lists(depth: int) -> list[Any]:
    value: list[Any] = []
    for _ in range(depth - 1):
        value = [value]
    return value


def nested_dicts(depth: int) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for _ in range(depth - 1):
        value = {"k": value}
    return value


def test_validation_of_a_value_built_from_shared_references_is_not_exponential(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0
    original = getattr(digest, "_check_container")  # noqa: B009 - private, patched to count visits

    def counting(*args: Any) -> None:
        nonlocal calls
        calls += 1
        original(*args)

    monkeypatch.setattr(digest, "_check_container", counting)
    node: list[Any] = []
    for _ in range(20):
        node = [node, node]  # 2**20 paths reach the innermost list
    getattr(digest, "_check")(node, 0, [], {})  # noqa: B009 - the validator alone; canonicalising 2**20 paths is not
    assert calls <= 100


def test_canonicalising_a_value_built_from_shared_references_writes_every_path() -> None:
    node: list[Any] = []
    for _ in range(10):
        node = [node, node]
    text = jcs(node)  # the real canonicaliser, not a stub
    assert text.count("[") == 2**11 - 1  # one list per path: 1 + 2 + ... + 2**10
    assert text == json.dumps(node, separators=(",", ":"))


def test_a_shared_container_first_seen_shallow_is_checked_again_when_reached_deeper() -> None:
    chain: list[Any] = []
    for _ in range(59):
        chain = [chain]  # depth 60 on its own
    assert refusal([chain, [[[[chain]]]]]) == "nesting_too_deep"  # chain sits at depth 2, then at depth 6
    assert jcs([chain, [chain]]).startswith("[[[")  # depth 61 at most


def test_the_nesting_limit_is_64() -> None:
    assert MAX_NESTING_DEPTH == 64


def test_depth_64_passes_and_depth_65_is_refused() -> None:
    assert jcs(nested_lists(64)) == "[" * 64 + "]" * 64
    assert refusal(nested_lists(65)) == "nesting_too_deep"
    assert jcs(nested_dicts(64)).count("{") == 64
    assert refusal(nested_dicts(65)) == "nesting_too_deep"


def test_a_very_deep_value_is_refused_not_recursed_into() -> None:
    assert refusal(nested_lists(100_000)) == "nesting_too_deep"


def test_scalars_do_not_count_towards_depth() -> None:
    assert jcs([nested_lists(63), "x", 1, None, True]) == "[" + "[" * 63 + "]" * 63 + ',"x",1,null,true]'
    assert jcs({"a": nested_dicts(63), "b": "x"}).endswith(',"b":"x"}')


# --- the digest -------------------------------------------------------------------------------------------------


def test_sha256_hex_of_text_and_bytes() -> None:
    expected = hashlib.sha256(b"abc").hexdigest()
    assert sha256_hex("abc") == expected
    assert sha256_hex(b"abc") == expected
    assert sha256_hex(bytearray(b"abc")) == expected
    assert sha256_hex(memoryview(b"abc")) == expected
    assert sha256_hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_sha256_hex_hashes_text_as_utf8() -> None:
    assert sha256_hex("Zoë") == hashlib.sha256("Zoë".encode()).hexdigest()
    assert sha256_hex("Zoë") != sha256_hex("Zoë")


def test_sha256_hex_refuses_a_lone_surrogate_and_other_types() -> None:
    with pytest.raises(DigestError) as surrogate:
        sha256_hex(chr(0xD800))
    assert surrogate.value.code == "invalid_string"
    with pytest.raises(DigestError) as wrong_type:
        sha256_hex(5)  # pyright: ignore[reportArgumentType]
    assert wrong_type.value.code == "unsupported_type"


def test_sha256_hex_refuses_subclasses_of_text_and_bytes() -> None:
    class Overriding(str):
        def encode(self, encoding: str = "utf-8", errors: str = "strict") -> bytes:
            return b"other"

    class BytesSub(bytes):
        pass

    for subclass in (Overriding("abc"), StrSub("abc"), BytesSub(b"abc")):
        with pytest.raises(DigestError) as refused:
            sha256_hex(subclass)
        assert refused.value.code == "unsupported_type"


def test_arg_digest_is_the_hash_of_the_canonical_form() -> None:
    args = {"b": [1, 2.5, "x"], "a": None}
    assert arg_digest(args) == hashlib.sha256(b'{"a":null,"b":[1,2.5,"x"]}').hexdigest()
    assert len(arg_digest({})) == 64


def test_arg_digest_does_not_depend_on_key_order_or_spacing() -> None:
    assert arg_digest({"a": 1, "b": 2}) == arg_digest({"b": 2, "a": 1})


def test_arg_digest_refuses_what_jcs_refuses() -> None:
    with pytest.raises(DigestError) as refused:
        arg_digest({"n": float("nan")})
    assert refused.value.code == "non_finite_number"


def test_digest_error_is_a_type_error_carrying_its_code() -> None:
    error = DigestError("unsupported_type", "nope")
    assert isinstance(error, TypeError)
    assert error.code == "unsupported_type"
    assert str(error) == "nope"
    assert error.args == ("nope",)


def test_digest_error_survives_pickle_and_copy() -> None:
    error = DigestError("integer_out_of_range", "an integer is outside the range")
    for clone in (pickle.loads(pickle.dumps(error)), copy.copy(error), copy.deepcopy(error)):
        assert type(clone) is DigestError
        assert clone.code == "integer_out_of_range"
        assert str(clone) == "an integer is outside the range"
        assert clone.args == ("an integer is outside the range",)


def test_the_first_fault_in_insertion_order_decides_the_code() -> None:
    # Documented in the module docstring: with several faults only the refusal, not the code, matches the original.
    assert refusal({"b": float("inf"), "1": chr(0xD800)}) == "non_finite_number"
    assert refusal({"1": chr(0xD800), "b": float("inf")}) == "invalid_string"


def test_refusal_messages_never_echo_a_value_or_a_key() -> None:
    secret = "hunter2-secret"
    cases: list[object] = [
        {secret: object()},
        {"k": secret + chr(0xD800)},
        {secret + chr(0xD800): 1},
        {"k": 10**29},
        {1: secret},
        {"k": Decimal("123456789")},
        [secret, float("nan")],
        {secret: StrSub(secret)},
    ]
    for value in cases:
        with pytest.raises(DigestError) as refused:
            jcs(value)  # pyright: ignore[reportUnknownArgumentType]
        message = str(refused.value)
        assert secret not in message
        assert "10000000000000000" not in message
        assert "123456789" not in message
