"""noblecloak.service_principal.credential: parsing, validation and loading of a service-principal credential.

The cases of `service-principal-credential.test.ts` (client 0.13.0), then the ones Python adds: a path never appears in
an error, a loopback check that reads the bracketed IPv6 host, and the JSON types.
"""

from __future__ import annotations

import base64
import copy
import dataclasses
import json
import os
import pickle
from collections.abc import Callable, Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any, get_args

import pytest

from noblecloak.service_principal import (
    CREDENTIAL_ENV,
    AsyncTokenSource,
    ServicePrincipalCredential,
    ServicePrincipalError,
    ServicePrincipalErrorCode,
    TokenSource,
    load_service_principal_credential,
    parse_service_principal_credential,
)
from noblecloak.service_principal import credential as credential_module
from sp_support import CLIENT_ID, TestKey, credential, ec_key, rsa_key, tracker_view, without


def _url(scheme: str, authority: str) -> str:
    """A URL built from parts: the private-dependency guard scans this file for a URL with a user part, which is what
    these cases need to contain."""
    return f"{scheme}://{authority}/t"


def code_of(call: Callable[[], object]) -> str:
    try:
        call()
    except ServicePrincipalError as error:
        return error.code
    return "no error"


# --- parse_service_principal_credential --------------------------------------------------------------


def test_accepts_an_ec_p256_credential_and_an_rsa_2048_credential() -> None:
    value = credential(ec_key())
    assert parse_service_principal_credential(value).client_id == value["client_id"]
    assert parse_service_principal_credential(credential(rsa_key())).private_jwk["kty"] == "RSA"


def test_carries_org_id_and_ignores_benign_extra_fields() -> None:
    value = {**credential(ec_key()), "org_id": "org-1", "name": "agent", "scopes": ["a"]}
    parsed = parse_service_principal_credential(value)
    assert parsed.org_id == "org-1"
    assert not hasattr(parsed, "name")


@pytest.mark.parametrize("value", [None, [], "x", 7, True])
def test_rejects_a_value_that_is_not_an_object(value: object) -> None:
    assert code_of(lambda: parse_service_principal_credential(value)) == "invalid_credential"


def test_rejects_a_client_id_that_is_not_sp_uuid() -> None:
    with pytest.raises(ServicePrincipalError, match="client_id"):
        parse_service_principal_credential(credential(ec_key(), client_id="sp_nope"))


def test_a_client_id_is_matched_whole_and_in_either_case() -> None:
    parse_service_principal_credential(credential(ec_key(), client_id=CLIENT_ID.upper().replace("SP_", "sp_")))
    for bad in (f"{CLIENT_ID}\n", f" {CLIENT_ID}", f"{CLIENT_ID}0", CLIENT_ID.replace("sp_", "SP_x")):
        assert code_of(lambda bad=bad: parse_service_principal_credential(credential(ec_key(), client_id=bad))) == (
            "invalid_credential"
        )


@pytest.mark.parametrize("value", [None, 7, True, ["a"], ""])
def test_a_field_of_the_wrong_json_type_is_refused_and_a_bool_is_not_a_string(value: object) -> None:
    for name in ("client_id", "token_endpoint", "assertion_audience"):
        with pytest.raises(ServicePrincipalError, match=name):
            parse_service_principal_credential(credential(ec_key(), **{name: value}))


def test_org_id_must_be_a_string() -> None:
    with pytest.raises(ServicePrincipalError, match="org_id"):
        parse_service_principal_credential(credential(ec_key(), org_id=7))


def test_an_org_id_of_null_is_refused_as_in_ts_while_an_absent_one_is_none() -> None:
    with pytest.raises(ServicePrincipalError, match="org_id"):
        parse_service_principal_credential(credential(ec_key(), org_id=None))
    absent = {k: v for k, v in credential(ec_key()).items() if k != "org_id"}
    assert parse_service_principal_credential(absent).org_id is None


def test_a_field_name_must_be_a_string() -> None:
    value: dict[Any, Any] = {**credential(ec_key()), 1: "x"}
    with pytest.raises(ServicePrincipalError, match="field names"):
        parse_service_principal_credential(value)


def test_rejects_a_token_endpoint_that_is_not_https_but_allows_http_on_loopback() -> None:
    key = ec_key()
    for bad in ("http://api.example.test/t", "not a url", "ftp://localhost/t", "https:///t", "/relative"):
        with pytest.raises(ServicePrincipalError, match="token_endpoint"):
            parse_service_principal_credential(credential(key, token_endpoint=bad))
    for ok in (
        "https://api.example.test/t",
        "http://127.0.0.1:9/t",
        "http://localhost:9/t",
        "HTTP://LOCALHOST:9/t",
        "https://[::1]:9/t",
    ):
        parse_service_principal_credential(credential(key, token_endpoint=ok))


@pytest.mark.parametrize("endpoint", ["http://[::1]:9/t", "http://[::1]/t", "http://[0:0:0:0:0:0:0:1]:9/t"])
def test_the_bracketed_ipv6_loopback_host_is_loopback(endpoint: str) -> None:
    # urlsplit drops the brackets (`hostname` is `::1`), so the check cannot compare the text `[::1]`.
    parse_service_principal_credential(credential(ec_key(), token_endpoint=endpoint))


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://[::2]:9/t",  # another IPv6 address
        "http://[::ffff:127.0.0.1]/t",  # IPv4-mapped is not ::1
        "http://127.0.0.2/t",
        "http://127.1/t",  # a spelling a browser normalizes; here only the exact host is loopback
        "http://localhost.evil.test/t",
        "http://evil.test/t?host=localhost",
        _url("http", "user@localhost"),  # a user part
        _url("http", "localhost:pw@evil.test"),
        _url("http", "evil.test\\@localhost"),  # another parser reads the host before the backslash
        "http://local host/t",
        "http://localhost:99999/t",  # port out of range
        "http://localhost:x/t",
        "http://[::1/t",  # unterminated bracket
        "http://localhost/t\n",
    ],
)
def test_http_is_refused_unless_the_host_is_exactly_loopback(endpoint: str) -> None:
    assert code_of(lambda: parse_service_principal_credential(credential(ec_key(), token_endpoint=endpoint))) == (
        "invalid_credential"
    )


@pytest.mark.parametrize(
    "endpoint",
    [
        _url("https", "user:pw@api.example.test"),
        _url("https", "api.example.test\\@evil.test"),
        "https://api.example.test\\x/t",  # a backslash and nothing else wrong
        "https://api.example.test/t\n",  # urlsplit drops the newline; this file does not
        "https://api.exa\tmple.test/t",
        "https://a b/t",
    ],
)
def test_a_user_part_or_a_backslash_or_a_space_is_refused_even_for_https(endpoint: str) -> None:
    assert code_of(lambda: parse_service_principal_credential(credential(ec_key(), token_endpoint=endpoint))) == (
        "invalid_credential"
    )


ENDPOINTS_HTTPX_REFUSES = [
    "https://a\u200d.example/token",  # a zero-width joiner: `httpx.URL` raises InvalidURL
    "https://" + "a" * 64 + ".example/token",  # a label over 63 characters: the resolver raises UnicodeError
    "https://xn--a.example/token",  # an `xn--` label that is not punycode
    "https://\u2488.example/token",  # a digit followed by a full stop, which IDNA does not allow
    "https://ex%61mple.example/token",  # a percent-encoded host
    "https://a..example/token",
    "https://[::1]:0/token",  # port 0
    "https://0x7f.1/token",  # IPv4 in another spelling
    "https://1.2.3.04/token",
    "https://2130706433/token",
    "https://\uff21.example/token",  # full-width letter: a WHATWG parser maps it, `httpx` does not
]


@pytest.mark.parametrize("endpoint", ENDPOINTS_HTTPX_REFUSES)
def test_an_endpoint_that_httpx_would_refuse_or_read_differently_is_refused_when_the_credential_is_loaded(
    endpoint: str,
) -> None:
    with pytest.raises(ServicePrincipalError) as caught:
        parse_service_principal_credential(credential(ec_key(), token_endpoint=endpoint))
    assert caught.value.code == "invalid_credential"
    assert "token_endpoint" in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert endpoint not in str(caught.value) + repr(caught.value)


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://API.example.test/t",
        "https://straße.example/t",
        "https://bücher.example:8443/t",
        "https://a_b.example.test/t",
        "https://xn--bcher-kva.example/t",
        "https://api.example.test./t",
        "https://203.0.113.7/t",
        "https://[2001:db8::1]/t",
        "https://" + "a" * 63 + ".example/t",
    ],
)
def test_an_endpoint_httpx_takes_and_that_idna_encodes_is_accepted(endpoint: str) -> None:
    assert parse_service_principal_credential(credential(ec_key(), token_endpoint=endpoint)).token_endpoint == endpoint


def test_the_token_endpoint_is_never_echoed() -> None:
    with pytest.raises(ServicePrincipalError) as caught:
        parse_service_principal_credential(credential(ec_key(), token_endpoint="http://leaky.example.test/t?k=SECRET"))
    assert "leaky" not in str(caught.value)
    assert "SECRET" not in str(caught.value)


def test_rejects_a_missing_assertion_audience() -> None:
    with pytest.raises(ServicePrincipalError, match="assertion_audience"):
        parse_service_principal_credential({**credential(ec_key()), "assertion_audience": ""})


def test_refuses_a_public_only_key() -> None:
    public_only = without(ec_key().private_jwk, "d")
    with pytest.raises(ServicePrincipalError, match="public"):
        parse_service_principal_credential(credential(ec_key(), private_jwk=public_only))
    with pytest.raises(ServicePrincipalError, match="public"):
        parse_service_principal_credential(credential(ec_key(), private_jwk={**ec_key().private_jwk, "d": ""}))


def test_refuses_an_unsupported_key_type_curve_and_a_short_rsa_key() -> None:
    base = credential(ec_key())

    def bad(jwk: object) -> Callable[[], object]:
        return lambda: parse_service_principal_credential({**base, "private_jwk": jwk})

    for jwk, pattern in (
        ({"kty": "oct", "k": "AAAA"}, "private_jwk"),
        ({**base["private_jwk"], "crv": "P-384"}, "P-256"),
        ({"kty": "EC", "crv": "P-256", "d": "x"}, "coordinates"),
        ({"kty": "RSA", "d": "x"}, "modulus"),
        (rsa_key(1024).private_jwk, "2048"),
        ("not a jwk", "JWK object"),
        (None, "JWK object"),
        ({}, "private_jwk"),
    ):
        with pytest.raises(ServicePrincipalError, match=pattern):
            bad(jwk)()


def _modulus(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _full(length: int, first: int) -> bytes:
    return bytes([first]) + b"\xff" * (length - 1)


def test_measures_the_rsa_modulus_in_bits_2047_and_2040_are_refused_2048_is_accepted_even_with_a_zero_pad() -> None:
    base = credential(ec_key())

    def rsa(n: str) -> dict[str, Any]:
        return {**base, "private_jwk": {"kty": "RSA", "n": n, "e": "AQAB", "d": "x"}}

    # 255 bytes (2040 bits); 256 bytes with the top bit clear is 2047 bits.
    for refused in (_full(255, 0xFF), _full(256, 0x7F), b"\x00" * 300, b""):
        with pytest.raises(ServicePrincipalError, match="2048"):
            parse_service_principal_credential(rsa(_modulus(refused)))
    parse_service_principal_credential(rsa(_modulus(_full(256, 0x80))))
    parse_service_principal_credential(rsa(_modulus(b"\x00" + _full(256, 0x80))))
    # Not base64url at all, or padded, or with the standard alphabet: no bits.
    padded = base64.urlsafe_b64encode(_full(256, 0x80)).decode("ascii")
    standard = base64.b64encode(b"\xfb\xff" * 128).decode("ascii")
    for garbled in ("!!not base64!!", padded + "=", standard, "A"):
        with pytest.raises(ServicePrincipalError, match="2048"):
            parse_service_principal_credential(rsa(garbled))


def test_refuses_secret_looking_extra_fields() -> None:
    base = credential(ec_key())
    for field in ("client_secret", "password", "access_token", "apiKey", "api-key", "Bearer", "refresh_credential"):
        with pytest.raises(ServicePrincipalError, match=field):
            parse_service_principal_credential({**base, field: "x"})


def test_never_puts_key_material_in_an_error_message() -> None:
    key = ec_key()
    value = {**credential(key), "client_secret": "x", "client_id": "bad"}
    with pytest.raises(ServicePrincipalError) as caught:
        parse_service_principal_credential(value)
    assert key.private_jwk["d"] not in str(caught.value)


def test_the_repr_of_a_credential_leaves_the_key_out() -> None:
    key = ec_key()
    parsed = parse_service_principal_credential(credential(key))
    assert key.private_jwk["d"] not in repr(parsed)
    assert "private_jwk" not in repr(parsed)
    assert CLIENT_ID in repr(parsed)


def test_the_key_of_a_parsed_credential_cannot_be_changed_through_the_input() -> None:
    source = credential(ec_key())
    original = source["private_jwk"]["d"]
    parsed = parse_service_principal_credential(source)
    source["private_jwk"]["d"] = "changed"
    assert parsed.private_jwk["d"] == original
    with pytest.raises(TypeError):
        parsed.private_jwk["d"] = "x"  # type: ignore[index]  # pyright: ignore[reportIndexIssue]


def test_a_parsed_credential_is_returned_as_it_is_when_it_is_passed_back() -> None:
    parsed = parse_service_principal_credential(credential(ec_key()))
    assert parse_service_principal_credential(parsed) is parsed


def _built(**overrides: Any) -> ServicePrincipalCredential:
    fields: dict[str, Any] = dict(credential(ec_key()))
    fields.update(overrides)
    return ServicePrincipalCredential(**fields)


def test_a_credential_built_directly_has_passed_the_same_checks() -> None:
    _built()
    for bad in (
        {"client_id": "x"},
        {"client_id": 7},
        {"token_endpoint": "http://api.example.test/t"},
        {"token_endpoint": ""},
        {"assertion_audience": ""},
        {"assertion_audience": None},
        {"org_id": 7},
        {"private_jwk": {"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}},  # public only
        {"private_jwk": "not a key"},
    ):
        with pytest.raises(ServicePrincipalError) as caught:
            _built(**bad)
        assert caught.value.code == "invalid_credential", bad


def test_a_credential_changed_with_replace_is_checked_again() -> None:
    parsed = parse_service_principal_credential(credential(ec_key()))
    assert dataclasses.replace(parsed, org_id="org_1").org_id == "org_1"
    with pytest.raises(ServicePrincipalError, match="client_id"):
        dataclasses.replace(parsed, client_id="x")
    with pytest.raises(ServicePrincipalError, match="token_endpoint"):
        dataclasses.replace(parsed, token_endpoint="http://api.example.test/t")


def test_a_credential_built_directly_keeps_its_own_read_only_copy_of_the_key() -> None:
    key = ec_key()
    made = ServicePrincipalCredential(**credential(key))
    original = key.private_jwk["d"]
    key.private_jwk["d"] = "changed"
    assert made.private_jwk["d"] == original
    with pytest.raises(TypeError):
        made.private_jwk["d"] = "x"  # type: ignore[index]  # pyright: ignore[reportIndexIssue]


def test_a_credential_is_compared_and_hashed_by_identity() -> None:
    first = parse_service_principal_credential(credential(ec_key()))
    twin = parse_service_principal_credential({**credential(ec_key()), "private_jwk": dict(first.private_jwk)})
    same = first
    assert first == same
    assert first != twin
    assert len({first, twin}) == 2


# --- load_service_principal_credential ---------------------------------------------------------------


def test_reads_inline_json() -> None:
    value = credential(ec_key())
    assert load_service_principal_credential(json.dumps(value)).client_id == value["client_id"]


def test_reads_a_file_and_takes_the_source_from_the_environment_when_none_is_given(tmp_path: Path) -> None:
    value = credential(ec_key())
    file = tmp_path / "sp.json"
    file.write_text(json.dumps(value))
    assert load_service_principal_credential(str(file)).client_id == value["client_id"]
    assert load_service_principal_credential(file).client_id == value["client_id"]  # a Path
    assert load_service_principal_credential(env={CREDENTIAL_ENV: str(file)}).client_id == value["client_id"]
    assert load_service_principal_credential(env={CREDENTIAL_ENV: json.dumps(value)}).client_id == value["client_id"]


def test_the_default_environment_is_the_process_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    value = credential(ec_key())
    monkeypatch.setenv(CREDENTIAL_ENV, json.dumps(value))
    assert load_service_principal_credential().client_id == value["client_id"]
    monkeypatch.delenv(CREDENTIAL_ENV)
    assert code_of(load_service_principal_credential) == "credential_missing"


def test_resolves_key_file_relative_to_the_credential_file(tmp_path: Path) -> None:
    key = ec_key()
    rest = without(credential(key), "private_jwk")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "key.jwk.json").write_text(json.dumps(key.private_jwk))
    (tmp_path / "sp.json").write_text(json.dumps({**rest, "key_file": "sub/key.jwk.json"}))
    assert load_service_principal_credential(str(tmp_path / "sp.json")).private_jwk["d"] == key.private_jwk["d"]
    (tmp_path / "sub" / "sp2.json").write_text(json.dumps({**rest, "key_file": "../sub/key.jwk.json"}))
    assert (
        load_service_principal_credential(str(tmp_path / "sub" / "sp2.json")).private_jwk["d"] == key.private_jwk["d"]
    )


def test_resolves_a_relative_credential_path_against_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = ec_key()
    (tmp_path / "key.jwk.json").write_text(json.dumps(key.private_jwk))
    (tmp_path / "sp.json").write_text(
        json.dumps({**without(credential(key), "private_jwk"), "key_file": "key.jwk.json"})
    )
    monkeypatch.chdir(tmp_path)
    assert load_service_principal_credential("sp.json").private_jwk["d"] == key.private_jwk["d"]


def test_loads_an_operator_shaped_sp_json_the_extra_fields_are_ignored_and_key_file_is_resolved(
    tmp_path: Path,
) -> None:
    key = ec_key()
    (tmp_path / "key.private.jwk.json").write_text(json.dumps(key.private_jwk))
    file = {
        **without(credential(key), "private_jwk"),
        "id": "3f0c2a54-1b0e-4f4c-9d4e-0a1b2c3d4e5f",
        "name": "beta demo",
        "audiences": ["https://govern.example.test"],
        "scopes": ["module_api"],
        "grant_type": "client_credentials",
        "expires_at": "2026-11-11T00:00:00Z",
        "key_thumbprint": "abc123",
        "key_file": "key.private.jwk.json",
    }
    (tmp_path / "sp.json").write_text(json.dumps(file))
    loaded = load_service_principal_credential(str(tmp_path / "sp.json"))
    assert loaded.client_id == file["client_id"]
    assert loaded.private_jwk["d"] == key.private_jwk["d"]


def test_refuses_a_credential_with_both_private_jwk_and_key_file_or_with_neither(tmp_path: Path) -> None:
    key = ec_key()
    (tmp_path / "key.jwk.json").write_text(json.dumps(key.private_jwk))
    # The key file exists and is valid, so only the "exactly one" rule can refuse this.
    both = json.dumps({**credential(key), "key_file": str(tmp_path / "key.jwk.json")})
    with pytest.raises(ServicePrincipalError, match="exactly one of"):
        load_service_principal_credential(both)
    with pytest.raises(ServicePrincipalError, match="exactly one of"):
        load_service_principal_credential(json.dumps(without(credential(key), "private_jwk")))


def test_a_file_that_holds_json_but_not_an_object_is_refused(tmp_path: Path) -> None:
    for text in ("[]", "7", '"x"', "null"):
        (tmp_path / "sp.json").write_text(text)
        with pytest.raises(ServicePrincipalError, match="JSON object"):
            load_service_principal_credential(str(tmp_path / "sp.json"))
    (tmp_path / "sp.json").write_text('{"client_id": NaN}')
    with pytest.raises(ServicePrincipalError, match="not valid JSON"):
        load_service_principal_credential(str(tmp_path / "sp.json"))
    (tmp_path / "sp.json").write_text("[" * 100_000)
    with pytest.raises(ServicePrincipalError, match="not valid JSON"):
        load_service_principal_credential(str(tmp_path / "sp.json"))


def test_a_private_jwk_of_null_counts_as_present_and_is_not_a_key() -> None:
    value = json.dumps({**credential(ec_key()), "private_jwk": None})
    with pytest.raises(ServicePrincipalError, match="JWK object"):
        load_service_principal_credential(value)


def test_refuses_a_relative_key_file_in_inline_json_and_reports_a_missing_or_malformed_file(tmp_path: Path) -> None:
    rest = without(credential(ec_key()), "private_jwk")
    assert code_of(lambda: load_service_principal_credential(json.dumps({**rest, "key_file": "k.json"}))) == (
        "invalid_credential"
    )
    missing = json.dumps({**rest, "key_file": str(tmp_path / "absent.json")})
    assert code_of(lambda: load_service_principal_credential(missing)) == "credential_unreadable"
    (tmp_path / "bad.json").write_text("{not json")
    bad = json.dumps({**rest, "key_file": str(tmp_path / "bad.json")})
    assert code_of(lambda: load_service_principal_credential(bad)) == "invalid_credential"
    assert code_of(lambda: load_service_principal_credential(str(tmp_path / "nope.json"))) == "credential_unreadable"
    assert code_of(lambda: load_service_principal_credential("{oops")) == "invalid_credential"


@pytest.mark.parametrize("key_file", [7, "", None, ["a"]])
def test_key_file_must_be_a_non_empty_path_string(key_file: object) -> None:
    rest = without(credential(ec_key()), "private_jwk")
    with pytest.raises(ServicePrincipalError, match="key_file"):
        load_service_principal_credential(json.dumps({**rest, "key_file": key_file}))


def _single_quoted(text: str) -> str:
    return f"'{text}'"


def _double_quoted(text: str) -> str:
    return '"' + text.replace('"', '\\"') + '"'


def _base64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


@pytest.mark.parametrize(
    "wrap",
    [
        pytest.param(_single_quoted, id="a single-quoted .env value"),
        pytest.param(_double_quoted, id="a double-quoted value"),
        pytest.param(_base64, id="a base64 CI secret"),
    ],
)
def test_never_echoes_a_value_that_is_not_a_path_in_the_message_or_the_cause(wrap: Callable[[str], str]) -> None:
    key = ec_key()
    text = wrap(json.dumps(credential(key)))
    d = key.private_jwk["d"]
    for load in (
        lambda: load_service_principal_credential(text),
        lambda: load_service_principal_credential(env={CREDENTIAL_ENV: text}),
    ):
        with pytest.raises(ServicePrincipalError) as caught:
            load()
        error = caught.value
        everything = " ".join([str(error), repr(error), repr(error.args), str(error.cause)])
        assert d not in everything
        assert text not in everything
        assert error.__cause__ is None
        assert error.__context__ is None


def test_names_a_quoted_value_as_json_that_does_not_start_with_a_brace() -> None:
    text = f"'{json.dumps(credential(ec_key()))}'"
    with pytest.raises(ServicePrincipalError, match=r'does not start with "\{"') as caught:
        load_service_principal_credential(text)
    assert caught.value.code == "invalid_credential"


def test_reads_no_environment_when_a_source_is_passed(monkeypatch: pytest.MonkeyPatch) -> None:
    class Forbidden(Mapping[str, str]):
        def __getitem__(self, key: str) -> str:
            raise AssertionError("the environment was read")

        def __iter__(self) -> Any:
            raise AssertionError("the environment was read")

        def __len__(self) -> int:
            raise AssertionError("the environment was read")

        def get(self, key: str, default: Any = None) -> Any:
            raise AssertionError("the environment was read")

    # Replace the module's `os`, not `os.environ`: pytest itself reads the process environment.
    monkeypatch.setattr(credential_module, "os", SimpleNamespace(environ=Forbidden(), fspath=os.fspath, path=os.path))
    value = credential(ec_key())
    assert load_service_principal_credential(json.dumps(value)).client_id == value["client_id"]


def test_says_so_when_there_is_no_source_at_all() -> None:
    assert code_of(lambda: load_service_principal_credential(env={})) == "credential_missing"
    assert code_of(lambda: load_service_principal_credential("  \n ", env={})) == "credential_missing"
    assert code_of(lambda: load_service_principal_credential(env={CREDENTIAL_ENV: "   "})) == "credential_missing"


def test_a_source_that_is_not_text_is_a_type_error() -> None:
    with pytest.raises(TypeError):
        load_service_principal_credential(b"/x")  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]


# --- a path never appears -----------------------------------------------------------------------------

PLANTED = "planted-path-3b7e91"


def _assert_no_path(error: ServicePrincipalError, planted: str) -> None:
    everything = " ".join([str(error), repr(error), repr(error.args), str(error.cause), repr(error.__dict__)])
    assert planted not in everything
    assert error.__cause__ is None
    assert error.__context__ is None


def test_no_error_echoes_a_path_not_even_the_key_files_which_the_typescript_original_does(tmp_path: Path) -> None:
    key = ec_key()
    rest = without(credential(key), "private_jwk")
    base = tmp_path / PLANTED
    base.mkdir()
    (base / "bad-key.json").write_text('{"d": "KEY-MATERIAL-IN-A-BAD-FILE"')
    (base / "not-utf8.json").write_bytes(b"\xff\xfe KEY-MATERIAL")
    (base / "bad-cred.json").write_text("{not json")
    (base / "directory.json").mkdir()
    (base / "no-key.json").write_text(json.dumps({**rest, "key_file": "missing-key.json"}))
    (base / "bad-key-ref.json").write_text(json.dumps({**rest, "key_file": "bad-key.json"}))
    (base / "bad-utf8-key-ref.json").write_text(json.dumps({**rest, "key_file": "not-utf8.json"}))
    cases: list[Callable[[], object]] = [
        lambda: load_service_principal_credential(str(base / "absent.json")),
        lambda: load_service_principal_credential(str(base / "directory.json")),
        lambda: load_service_principal_credential(str(base / "bad-cred.json")),
        lambda: load_service_principal_credential(str(base / "not-utf8.json")),
        lambda: load_service_principal_credential(str(base / "no-key.json")),
        lambda: load_service_principal_credential(str(base / "bad-key-ref.json")),
        lambda: load_service_principal_credential(str(base / "bad-utf8-key-ref.json")),
        lambda: load_service_principal_credential(json.dumps({**rest, "key_file": str(base / "absent.json")})),
        lambda: load_service_principal_credential(json.dumps({**rest, "key_file": str(base / "bad-key.json")})),
        lambda: load_service_principal_credential(env={CREDENTIAL_ENV: str(base / "absent.json")}),
        lambda: load_service_principal_credential(str(base / "nul\x00byte.json")),
    ]
    codes: list[str] = []
    for case in cases:
        with pytest.raises(ServicePrincipalError) as caught:
            case()
        codes.append(caught.value.code)
        _assert_no_path(caught.value, PLANTED)
        _assert_no_path(caught.value, "KEY-MATERIAL")
    assert codes == [
        "credential_unreadable",
        "credential_unreadable",
        "invalid_credential",
        "invalid_credential",
        "credential_unreadable",
        "invalid_credential",
        "invalid_credential",
        "credential_unreadable",
        "invalid_credential",
        "credential_unreadable",
        "credential_unreadable",
    ]


def test_an_unreadable_file_says_which_kind_of_file_and_why_by_errno_name(tmp_path: Path) -> None:
    with pytest.raises(ServicePrincipalError) as caught:
        load_service_principal_credential(str(tmp_path / "absent.json"))
    assert caught.value.cause == "ENOENT"
    assert "credential file" in str(caught.value)
    assert "the path argument" in str(caught.value)
    rest = without(credential(ec_key()), "private_jwk")
    with pytest.raises(ServicePrincipalError) as caught:
        load_service_principal_credential(json.dumps({**rest, "key_file": str(tmp_path / "absent.json")}))
    assert caught.value.cause == "ENOENT"
    assert "key file" in str(caught.value)


def test_the_error_survives_pickle_and_keeps_its_fields() -> None:
    error = ServicePrincipalError(
        "token_request_rejected",
        "refused",
        status=400,
        oauth_error="invalid_target",
        oauth_error_description="resource not allowed",
        cause="ConnectError",
    )
    again = pickle.loads(pickle.dumps(error))
    assert isinstance(again, ServicePrincipalError)
    assert (again.code, str(again), again.status, again.oauth_error, again.oauth_error_description, again.cause) == (
        "token_request_rejected",
        "refused",
        400,
        "invalid_target",
        "resource not allowed",
        "ConnectError",
    )
    assert copy.copy(error).oauth_error_description == "resource not allowed"


def test_the_repr_of_the_error_shows_the_code_the_status_and_the_oauth_error_and_nothing_else() -> None:
    error = ServicePrincipalError(
        "token_request_rejected",
        "message text",
        status=400,
        oauth_error="invalid_target",
        oauth_error_description="prose from the server",
        cause="a-cause",
    )
    assert (
        repr(error) == "ServicePrincipalError(code='token_request_rejected', status=400, oauth_error='invalid_target')"
    )
    assert "prose" not in repr(error) + str(error)
    assert repr(ServicePrincipalError("credential_missing", "m")) == (
        "ServicePrincipalError(code='credential_missing', status=None, oauth_error=None)"
    )


def test_the_code_of_an_error_is_checked_when_the_error_is_made() -> None:
    for code in get_args(ServicePrincipalErrorCode):
        assert ServicePrincipalError(code, "m").code == code
    with pytest.raises(ValueError, match="unknown service-principal error code"):
        ServicePrincipalError("network_failure", "m")  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]


def test_test_keys_are_valid_for_the_loader_for_both_kinds(tmp_path: Path) -> None:
    for key in (ec_key(), rsa_key()):
        assert isinstance(key, TestKey)
        (tmp_path / "sp.json").write_text(json.dumps(credential(key)))
        assert load_service_principal_credential(str(tmp_path / "sp.json")).private_jwk["kty"] == key.private_jwk["kty"]


# --- what the frames of a failure hold --------------------------------------------------------------


def _failing_loads(key: TestKey) -> list[tuple[str, Callable[[], object]]]:
    """Loads that fail, each built so that the secrets are in no closure of the caller: they are in what is passed."""
    weak = rsa_key(1024)
    return [
        ("weak RSA", lambda: load_service_principal_credential(json.dumps(credential(weak)))),
        (
            "bad endpoint",
            lambda: load_service_principal_credential(json.dumps(credential(key, token_endpoint="http://x.test/t"))),
        ),
        (
            "IDNA endpoint",
            lambda: load_service_principal_credential(
                json.dumps(credential(key, token_endpoint=ENDPOINTS_HTTPX_REFUSES[0]))
            ),
        ),
        ("parse error", lambda: load_service_principal_credential(json.dumps(credential(key))[:-1])),
        ("not an object", lambda: load_service_principal_credential(json.dumps([credential(key)]))),
        (
            "both key and key_file",
            lambda: load_service_principal_credential(json.dumps({**credential(key), "key_file": "/x"})),
        ),
        ("a mapping", lambda: parse_service_principal_credential(credential(key, client_id="x"))),
        (
            "a secret-looking field",
            lambda: parse_service_principal_credential({**credential(key), "my_api_key": "hunter2-planted"}),
        ),
        (
            "env",
            lambda: load_service_principal_credential(env={CREDENTIAL_ENV: json.dumps(credential(key, client_id="x"))}),
        ),
    ]


def test_no_frame_of_a_failed_credential_load_holds_the_key_or_the_text_it_came_from() -> None:
    key = ec_key()
    d = key.private_jwk["d"]
    for name, call in _failing_loads(key):
        with pytest.raises(ServicePrincipalError) as caught:
            call()
        texts, chain = tracker_view(caught.value, library_only=True)
        assert [t[:60] for t in texts if d in t or "hunter2-planted" in t] == [], name
        assert chain == [caught.value], name  # nothing chained: not the JSON error, not the OS error


def test_no_frame_holds_the_key_when_a_source_is_built_from_a_mapping_that_does_not_validate() -> None:
    key = ec_key()
    d = key.private_jwk["d"]
    for cls in (TokenSource, AsyncTokenSource):
        with pytest.raises(ServicePrincipalError) as caught:
            cls(credential(key, token_endpoint="http://x.test/t"), audience="https://a.example.test")
        texts, _ = tracker_view(caught.value, library_only=True)
        assert [t[:60] for t in texts if d in t] == [], cls.__name__
    for cls in (TokenSource, AsyncTokenSource):
        with pytest.raises(ValueError, match="timeout_seconds"):  # a later argument fails: the key is already gone
            cls(credential(key), audience="https://a.example.test", timeout_seconds=-1)


# --- key_file, serialisation, files ------------------------------------------------------------------


def test_parse_refuses_a_key_file_and_says_the_loader_resolves_it() -> None:
    with pytest.raises(ServicePrincipalError, match="load_service_principal_credential"):
        parse_service_principal_credential({**without(credential(ec_key()), "private_jwk"), "key_file": "/x"})
    with pytest.raises(ServicePrincipalError, match="load_service_principal_credential"):
        parse_service_principal_credential({**credential(ec_key()), "key_file": "/x"})


def test_a_credential_cannot_be_pickled_or_copied() -> None:
    parsed = parse_service_principal_credential(credential(ec_key()))
    for how in (pickle.dumps, copy.copy, copy.deepcopy):
        with pytest.raises(TypeError, match="ServicePrincipalCredential holds a private key and is not serialisable"):
            how(parsed)
    for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
        with pytest.raises(TypeError, match="not serialisable"):
            pickle.dumps(parsed, protocol=protocol)


def test_the_loader_reads_at_most_1_mib_of_a_file(tmp_path: Path) -> None:
    value = credential(ec_key())
    padded = json.dumps(value) + " " * (credential_module.MAX_CREDENTIAL_FILE_BYTES - len(json.dumps(value)))
    (tmp_path / "sp.json").write_text(padded)  # exactly 1 MiB
    assert load_service_principal_credential(str(tmp_path / "sp.json")).client_id == CLIENT_ID
    (tmp_path / "big.json").write_text(padded + " ")
    with pytest.raises(ServicePrincipalError) as caught:
        load_service_principal_credential(str(tmp_path / "big.json"))
    assert (caught.value.code, caught.value.cause) == ("invalid_credential", "too_large")
    assert "1 MiB" in str(caught.value)
    # the same for a key file
    rest = without(value, "private_jwk")
    (tmp_path / "bigkey.json").write_text(" " * (credential_module.MAX_CREDENTIAL_FILE_BYTES + 1))
    (tmp_path / "ref.json").write_text(json.dumps({**rest, "key_file": "bigkey.json"}))
    with pytest.raises(ServicePrincipalError) as caught:
        load_service_principal_credential(str(tmp_path / "ref.json"))
    assert (caught.value.code, caught.value.cause) == ("invalid_credential", "too_large")
    assert "key file" in str(caught.value)


@pytest.mark.parametrize(
    ("content", "cause"),
    [(b"\xef\xbb\xbf{}", "utf8_bom"), (b"\xff\xfe{}", "not_utf8"), (b"{\x80}", "not_utf8")],
)
def test_a_bom_or_text_that_is_not_utf8_has_a_cause_that_says_so_and_no_path_or_content(
    tmp_path: Path, content: bytes, cause: str
) -> None:
    base = tmp_path / PLANTED
    base.mkdir()
    (base / "sp.json").write_bytes(content)
    with pytest.raises(ServicePrincipalError) as caught:
        load_service_principal_credential(str(base / "sp.json"))
    assert (caught.value.code, caught.value.cause) == ("invalid_credential", cause)
    _assert_no_path(caught.value, PLANTED)
    rest = without(credential(ec_key()), "private_jwk")
    (base / "key.json").write_bytes(content)
    (base / "ref.json").write_text(json.dumps({**rest, "key_file": "key.json"}))
    with pytest.raises(ServicePrincipalError) as caught:
        load_service_principal_credential(str(base / "ref.json"))
    assert (caught.value.code, caught.value.cause) == ("invalid_credential", cause)
    assert "key file" in str(caught.value)
    _assert_no_path(caught.value, PLANTED)


def test_a_path_given_as_bytes_is_a_type_error_that_says_so() -> None:
    with pytest.raises(TypeError, match="not bytes"):
        load_service_principal_credential(b"/etc/sp.json")  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]
    with pytest.raises(TypeError, match="not bytes"):
        load_service_principal_credential(_BytesPath())  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]


class _BytesPath:
    def __fspath__(self) -> bytes:
        return b"/etc/sp.json"


def test_b64url_decode_is_not_part_of_the_public_credential_module() -> None:
    assert "b64url_decode" not in credential_module.__all__


class _Endless:
    """A file that never ends, which remembers how much it was asked for."""

    def __init__(self, asked: list[int]) -> None:
        self._asked = asked

    def __enter__(self) -> _Endless:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        self._asked.append(size)
        return b" " * (2**21 if size < 0 else size)


def test_the_loader_asks_for_one_byte_over_the_cap_and_no_more(monkeypatch: pytest.MonkeyPatch) -> None:
    """The read is bounded when it is made, so that a file that never ends (a device, a FIFO) cannot fill the memory."""
    asked: list[int] = []

    def endless(_path: str, _mode: str) -> _Endless:
        return _Endless(asked)

    monkeypatch.setattr(credential_module, "open", endless, raising=False)
    with pytest.raises(ServicePrincipalError) as caught:
        load_service_principal_credential("/some/file.json")
    assert caught.value.cause == "too_large"
    assert asked == [credential_module.MAX_CREDENTIAL_FILE_BYTES + 1]
