"""The differential test (`-m e2e`): the Python argument digest against the TypeScript one.

The mock digests every decision's arguments with `argDigest` from `@noblecloak/client` and answers it as
`action_digest`. Hypothesis generates arguments (including the ones the digest refuses) and the two must agree: the same
digest, or both refuse. TypeScript's refusal is the mock's 500. Whatever the two disagree on is a finding: it is
reported, and `arg_digest` is not bent to fit.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any

import pytest
from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st

from e2e_support import ROOT, Mock, decide_digest, differential_check, spawn_mock
from noblecloak.digest import DigestError, arg_digest

pytestmark = pytest.mark.e2e

EXAMPLES = 500
MAX_SAFE = 2**53 - 1

# Strings the digest has to get right: normalisation forms, UTF-16 order, escapes and a key that JavaScript treats
# specially. Lone surrogates are refused, so they come apart and rarer: most of the arguments should have a digest.
INTERESTING_STRINGS = ["", "\u00e9", "e\u0301", "\ufb33", "\U0001f600", "\u2028", "\x00", "\x7f", "__proto__", '"\\/']
LONE_SURROGATES = ["\ud800", "\udfff"]
# Numbers with a digest, and the ones the digest refuses (outside +-(2^53-1), or a float too large to be an integer).
DIGESTIBLE_NUMBERS: list[float] = [
    0,
    -0.0,
    1000.0,
    0.30000000000000004,
    1e-7,
    5e-324,
    float(MAX_SAFE),
    -float(MAX_SAFE),
    MAX_SAFE,
    -MAX_SAFE,
]
REFUSED_NUMBERS: list[float] = [1e21, 1e300, 1.7976931348623157e308, float(2**53), MAX_SAFE + 1, -MAX_SAFE - 1, 2**63]

# Two pools. `clean` has a digest, so most of what is generated reaches the comparison of two digests; `dirty` adds what
# the digest refuses, so the comparison of two refusals is reached too. One refused leaf refuses the whole arguments,
# and the arguments have up to 30 leaves, which is why the refused ones are not mixed in everywhere.
clean_text = st.one_of(st.sampled_from(INTERESTING_STRINGS), st.text(max_size=8))
dirty_text = st.one_of(
    clean_text,
    st.sampled_from(LONE_SURROGATES),
    # Cs (surrogates) are excluded from `st.text()` by default; ask for them.
    st.text(alphabet=st.characters(exclude_categories=()), max_size=4),
)
clean_numbers = st.one_of(
    st.sampled_from(DIGESTIBLE_NUMBERS),
    st.integers(min_value=-MAX_SAFE, max_value=MAX_SAFE),
    st.floats(min_value=-1e15, max_value=1e15, allow_nan=False, allow_infinity=False),
)
dirty_numbers = st.one_of(
    clean_numbers,
    st.sampled_from(REFUSED_NUMBERS),
    st.integers(min_value=-(2**60), max_value=2**60),
    st.floats(allow_nan=False, allow_infinity=False),
)


def containers(texts: st.SearchStrategy[str], numbers: st.SearchStrategy[float]) -> st.SearchStrategy[dict[str, Any]]:
    leaves = st.one_of(st.none(), st.booleans(), numbers, texts)
    values: st.SearchStrategy[Any] = st.recursive(
        leaves,
        lambda children: st.one_of(st.lists(children, max_size=4), st.dictionaries(texts, children, max_size=4)),
        max_leaves=30,
    )
    return st.dictionaries(texts, values, max_size=6)


arguments = st.one_of(
    containers(clean_text, clean_numbers),
    containers(clean_text, clean_numbers),
    containers(clean_text, clean_numbers),
    containers(dirty_text, dirty_numbers),
)


def nested(depth: int) -> dict[str, Any]:
    """`depth` objects inside one another, the outermost being the arguments themselves."""
    value: dict[str, Any] = {}
    for _ in range(depth - 1):
        value = {"a": value}
    return value


@settings(max_examples=EXAMPLES, deadline=None, database=None, suppress_health_check=[HealthCheck.too_slow])
@given(arguments)
@example({})
@example({"b": 1, "a": 2})  # the order of the keys is the point of JCS
@example({"é": 1, "é": 2})  # NFC and NFD are different keys
@example({"דּ": 1, "\U0001f600": 2})  # UTF-16 order, not code point order
@example({"__proto__": 1, "a": 2})
@example({"n": 1000.0, "m": -0.0, "k": 1e-7})
@example({"n": MAX_SAFE})
@example({"n": MAX_SAFE + 1})
@example({"n": 1e300})
@example({"s": "\ud800"})
@example(nested(64))  # the deepest the digest accepts
@example(nested(65))  # one deeper
def test_python_and_typescript_digest_arguments_alike(mock: Mock, args: dict[str, Any]) -> None:
    differential_check(mock, args)


def test_the_digest_not_jcs_break_is_caught_by_the_differential() -> None:
    # `digest_not_jcs` makes the mock hash `JSON.stringify` instead of the canonical form: the order of keys then
    # shows. Without this the differential could pass against a mock that digests the wrong way.
    with spawn_mock("digest_not_jcs") as broken, pytest.raises(AssertionError, match="the mock as"):
        differential_check(broken, {"b": 1, "a": 2})


# One JSON text for each kind of input Python's `arg_digest` refuses.
REFUSED_TEXTS = [
    '{"n":1e300}',  # a float that is not an integer-valued safe number
    '{"n":9007199254740992}',  # 2^53, past the safe integers
    '{"s":"\\ud800"}',  # a lone surrogate in a value
    '{"\\udfff":1}',  # a lone surrogate in a key
    json.dumps(nested(65)),  # one level deeper than the digest accepts
]

TYPESCRIPT_REFUSES = """
import { argDigest } from "@noblecloak/client";
const results = [];
for (const text of JSON.parse(process.env.CASES)) {
  try { await argDigest(JSON.parse(text)); results.push("digest"); } catch { results.push("refused"); }
}
console.log(JSON.stringify(results));
"""


def test_the_mocks_500_is_argdigest_refusing(mock: Mock) -> None:
    # The differential reads the mock's 500 `internal_error` as "TypeScript refused", and that answer is generic. This
    # pins it: for each kind of input Python refuses, `argDigest` itself throws (run here under `bun`, from the same
    # install the mock uses) and the mock answers 500 for it. A mock that crashed on something else would not be
    # distinguished per input, but a kind that `argDigest` accepts, or that the mock does not 500 on, fails here.
    # `mock` has already started `nc-mock` from the same install under `bun`, and says so clearly when either is
    # missing, so a failure of this script is the test's own: report it with bun's stderr.
    ran = subprocess.run(
        ["bun", "-e", TYPESCRIPT_REFUSES],
        cwd=ROOT / "conformance",
        env={**os.environ, "CASES": json.dumps(REFUSED_TEXTS)},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert ran.returncode == 0, f"bun exited {ran.returncode}: {ran.stderr}"
    assert json.loads(ran.stdout) == ["refused"] * len(REFUSED_TEXTS), ran.stdout
    for text in REFUSED_TEXTS:
        with pytest.raises(DigestError):
            arg_digest(json.loads(text))
        assert decide_digest(mock, text)[0] == 500, text
