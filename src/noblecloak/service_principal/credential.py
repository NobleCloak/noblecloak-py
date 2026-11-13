"""The service-principal credential: its shape, its validation and the loader that reads it from a file, inline JSON
or `NOBLECLOAK_SP_CREDENTIALS`. Server-side only: it holds a private key.

Python port of `service-principal-credential.ts` in `@noblecloak/client` 0.13.0 (public `NobleCloak/noblecloak-ts` at
`bb1be4c`). The checks, the error codes and the rule that a credential carries exactly one of `private_jwk` and
`key_file` are the original's.

Where this port is stricter than the TypeScript original, on purpose:

- No error message, `cause` or exception chain echoes a path, not even the key file's path, which the original puts in
  the message (`credential.ts:233`). A message says which kind of file it could not read, never which one. A failure
  is raised outside the `except` block that caught it, so `__context__` does not hold the OS error (whose `filename` is
  the path), a `JSONDecodeError` (whose `doc` is the text) or a `UnicodeDecodeError` (whose `object` is the bytes).
- A `token_endpoint` with a user part, a backslash, a space or a control character is refused. An authority such as
  `evil.example\\@localhost` is host `localhost` to one URL parser and `evil.example` to another, which would let a
  plain-http endpoint pass the loopback check; refusing those characters leaves one reading. `127.1` and
  other spellings of the loopback host that a browser's URL parser normalizes are not accepted: the host is exactly
  `localhost`, `127.0.0.1` or `::1` (any spelling of the IPv6 address).
- A `token_endpoint` whose host `httpx` would refuse or read differently from a WHATWG URL parser is refused when the
  credential is loaded, not at the first request: an IDNA label that does not encode, a label over 63 characters, an
  `xn--` label that is not punycode, a percent-encoded host, an IPv4 address that is not a plain dotted quad. See
  `_host.py`.
- Base64url members of the key are decoded strictly: unpadded, canonical and in the URL-safe alphabet, as RFC 7515
  says (the modulus here, the other members when `_core.py` imports the key). The original's `atob` also takes `+`,
  `/` and padding. A modulus that cannot be decoded counts as 0 bits, as there.
- Values must be of the JSON types: a `bool` is not a string; keys of the credential must be strings.

A credential that fails a check is raised from a frame that holds neither the key nor the text it came from: the
checks return the error, and a thin outer function deletes its arguments and raises it, so that an error tracker that
captures the locals of the frames of the traceback does not send the private key out. (A `ServicePrincipalCredential`
built directly with a bad key raises from `__post_init__`, whose frame holds what the caller passed.) A credential
holds a private key, so it is not hashable by value, not comparable and not picklable or copyable.

`urlsplit` drops the brackets of an IPv6 host (`http://[::1]:9/` has the host `::1`), so the loopback test compares the
parsed address, not the text.
"""

from __future__ import annotations

import errno
import ipaddress
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Final, NoReturn
from urllib.parse import urlsplit

import httpx

from noblecloak.service_principal._b64 import b64url_decode
from noblecloak.service_principal._host import normal_host
from noblecloak.service_principal._json import INVALID, parse_json
from noblecloak.service_principal.error import ServicePrincipalError

__all__ = [
    "CREDENTIAL_ENV",
    "ServicePrincipalCredential",
    "load_service_principal_credential",
    "parse_service_principal_credential",
]

CREDENTIAL_ENV: Final = "NOBLECLOAK_SP_CREDENTIALS"
"""The environment variable the loader reads when no source is passed: a path, or inline JSON for CI secrets."""

MAX_CREDENTIAL_FILE_BYTES: Final = 1024 * 1024
"""The largest credential file or key file the loader reads. A real one is a few kilobytes."""

_CLIENT_ID: Final = re.compile(
    r"sp_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE | re.ASCII
)
# A top-level field that looks like a secret other than the private key.
_SECRET_NAME: Final = re.compile(r"secret|passw|token|api[_-]?key|credential|bearer", re.IGNORECASE)
_LOOPBACK_HOSTS: Final = frozenset({"localhost"})
_LOOPBACK_ADDRESSES: Final = (ipaddress.IPv4Address("127.0.0.1"), ipaddress.IPv6Address("::1"))
_FORBIDDEN_IN_URL: Final = re.compile(r"[\x00-\x20\x7f\\]")
_NOT_SERIALISABLE: Final = "{} holds a private key and is not serialisable"


def _invalid(message: str, *, cause: str | None = None) -> ServicePrincipalError:
    return ServicePrincipalError("invalid_credential", message, cause=cause)


def _text_problem(value: object, name: str) -> ServicePrincipalError | None:
    if not isinstance(value, str) or value == "":
        return _invalid(f"Service-principal credential: {name} must be a non-empty string.")
    return None


def _is_loopback(host: str) -> bool:
    if host in _LOOPBACK_HOSTS:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address in _LOOPBACK_ADDRESSES


def _same_host(url_host: str, normal: str) -> bool:
    """Whether `httpx` will connect to `normal`, the host that `normal_host` says the URL has."""
    if ":" not in normal:
        return url_host.lower() == normal
    return ipaddress.IPv6Address(url_host) == ipaddress.IPv6Address(normal)


def _check_endpoint(value: str, name: str) -> ServicePrincipalError | None:
    """The error for a value that is not an https URL (http only for a loopback host, for local stubs) that `httpx`
    can send to, or None. Raises nothing, and never echoes the value."""
    not_a_url = _invalid(f"Service-principal credential: {name} is not a URL.")
    if _FORBIDDEN_IN_URL.search(value):
        return not_a_url
    try:
        parts = urlsplit(value)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return not_a_url
    if parts.scheme == "" or not host or port == 0:
        return not_a_url
    if "@" in parts.netloc:
        return _invalid(f"Service-principal credential: {name} must not carry a user name or password.")
    scheme = parts.scheme.lower()
    if scheme != "https" and not (scheme == "http" and _is_loopback(host)):
        return _invalid(f"Service-principal credential: {name} must be an https URL.")
    # The host must be one that `httpx` accepts and that a WHATWG parser reads the same way. A transport that is passed
    # in could take a host that `httpx` refuses, so this is a check of the credential, not only of the default client.
    normal = normal_host(host)
    if normal is None:
        return not_a_url
    try:
        same = _same_host(httpx.URL(value).raw_host.decode("ascii"), normal)
    except (httpx.InvalidURL, ValueError):  # ValueError: not an address, or not ASCII
        return not_a_url
    return None if same else not_a_url


def _modulus_bits(n: str) -> int:
    """The bit length of a base64url big-endian modulus, ignoring leading zero bytes; 0 when it cannot be decoded."""
    raw = b64url_decode(n)
    return 0 if raw is None else int.from_bytes(raw, "big").bit_length()


def _check_private_key(jwk: object) -> Mapping[str, Any] | ServicePrincipalError:
    """The key as a read-only copy, or the error for anything but a private EC P-256 or RSA (>= 2048 bit) JWK."""
    if not isinstance(jwk, Mapping):
        return _invalid("Service-principal credential: private_jwk must be a JWK object.")
    key: dict[str, Any] = {str(name): member for name, member in jwk.items()}  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType]
    kty: Any = key.get("kty")
    if kty == "EC":
        if key.get("crv") != "P-256":
            return _invalid("Service-principal credential: an EC private_jwk must use curve P-256.")
        if not isinstance(key.get("x"), str) or not isinstance(key.get("y"), str):
            return _invalid("Service-principal credential: private_jwk is missing its public coordinates.")
    elif kty == "RSA":
        n: Any = key.get("n")
        if not isinstance(n, str) or not isinstance(key.get("e"), str):
            return _invalid("Service-principal credential: private_jwk is missing its modulus or exponent.")
        if _modulus_bits(n) < 2048:
            return _invalid("Service-principal credential: an RSA private_jwk must be at least 2048 bits.")
    else:
        return _invalid("Service-principal credential: private_jwk must be an EC P-256 or RSA key.")
    d: Any = key.get("d")
    if not isinstance(d, str) or d == "":
        return _invalid(
            "Service-principal credential: private_jwk is a public key; "
            'the credential needs the private key (its "d" member).'
        )
    return MappingProxyType(key)


def _validate(
    client_id: object,
    token_endpoint: object,
    assertion_audience: object,
    private_jwk: object,
    org_id: object,
) -> Mapping[str, Any] | ServicePrincipalError:
    """The checked private key, or the first error. Returns the error and does not raise it, so that no frame of the
    error's traceback holds the key."""
    problem = _text_problem(client_id, "client_id")
    if problem is None and not _CLIENT_ID.fullmatch(str(client_id)):
        problem = _invalid("Service-principal credential: client_id must look like sp_<uuid>.")
    if problem is None:
        problem = _text_problem(token_endpoint, "token_endpoint") or _check_endpoint(
            str(token_endpoint), "token_endpoint"
        )
    if problem is None:
        problem = _text_problem(assertion_audience, "assertion_audience")
    if problem is None and org_id is not None and not isinstance(org_id, str):
        problem = _invalid("Service-principal credential: org_id must be a string.")
    if problem is not None:
        return problem
    return _check_private_key(private_jwk)


@dataclass(frozen=True, slots=True, eq=False)
class ServicePrincipalCredential:
    """A validated service-principal credential. Its `repr` leaves the key out. Whichever way it is made (the parser,
    the loader, the constructor, `dataclasses.replace`) it has passed the same checks, and it keeps its own read-only
    copy of the key. It is compared and hashed by identity, and it cannot be pickled or copied: it holds a private key.
    """

    client_id: str
    """`sp_<uuid>`: the principal's `client_id`, used as `iss` and `sub` of the assertion."""
    token_endpoint: str
    """The OAuth token endpoint the assertion is posted to."""
    assertion_audience: str
    """The assertion's `aud`: the authorization server's issuer."""
    private_jwk: Mapping[str, Any] = field(repr=False)
    """The private key: an EC P-256 key (ES256) or an RSA key of at least 2048 bits (RS256), as a JWK. It may carry a
    `kid`, which becomes the assertion's key id."""
    org_id: str | None = None

    def __post_init__(self) -> None:
        checked = _validate(self.client_id, self.token_endpoint, self.assertion_audience, self.private_jwk, self.org_id)
        if isinstance(checked, ServicePrincipalError):
            raise checked
        object.__setattr__(self, "private_jwk", checked)

    def __reduce_ex__(self, protocol: object) -> NoReturn:
        # `pickle`, `copy.copy` and `copy.deepcopy` all go through this.
        raise TypeError(_NOT_SERIALISABLE.format(type(self).__name__))


def check_credential(value: object) -> ServicePrincipalCredential | ServicePrincipalError:
    """The credential for `value` (a mapping, or a `ServicePrincipalCredential`), or the error, returned and not
    raised: the caller raises it from a frame that does not hold `value`. Not part of the public API."""
    if isinstance(value, ServicePrincipalCredential):
        return value  # it was checked when it was made
    if not isinstance(value, Mapping):
        return _invalid("Service-principal credential must be a JSON object.")
    record: Mapping[Any, Any] = value  # pyright: ignore[reportUnknownVariableType]
    for name in record:
        if not isinstance(name, str):
            return _invalid("Service-principal credential: field names must be strings.")
    if "key_file" in record:
        return _invalid(
            "Service-principal credential: key_file is resolved by load_service_principal_credential; "
            "this takes the key inline, as private_jwk."
        )
    for name in record:
        if _SECRET_NAME.search(name) and name not in _KNOWN:
            return _invalid(f'Service-principal credential: field "{name}" looks like a secret and is not accepted.')
    fields: Mapping[str, Any] = record
    client_id, token_endpoint = fields.get("client_id"), fields.get("token_endpoint")
    assertion_audience, private_jwk, org_id = (
        fields.get("assertion_audience"),
        fields.get("private_jwk"),
        fields.get("org_id"),
    )
    if "org_id" in fields and org_id is None:
        # As in TS: org_id is optional, but when present it must be a string; null is not absent.
        return _invalid("Service-principal credential: org_id must be a string.")
    checked = _validate(client_id, token_endpoint, assertion_audience, private_jwk, org_id)
    if isinstance(checked, ServicePrincipalError):
        return checked
    return ServicePrincipalCredential(
        client_id=str(client_id),
        token_endpoint=str(token_endpoint),
        assertion_audience=str(assertion_audience),
        private_jwk=checked,
        org_id=None if org_id is None else str(org_id),
    )


# The fields this package knows; `key_file` is resolved by the loader, `private_jwk` is the key.
_KNOWN: Final = frozenset({"client_id", "token_endpoint", "assertion_audience", "private_jwk", "key_file", "org_id"})


def parse_service_principal_credential(value: object) -> ServicePrincipalCredential:
    """Validates a credential whose key is inline: a mapping, or a `ServicePrincipalCredential` (returned as it is: it
    was checked when it was made).

    Refuses a public-only key, an unsupported key, a non-https token endpoint, a `key_file` (that is for
    `load_service_principal_credential` to resolve) and any extra field whose name looks like a secret. Raises
    `ServicePrincipalError` (`invalid_credential`), from a frame that holds neither the mapping nor the key.
    """
    result = check_credential(value)
    del value
    if isinstance(result, ServicePrincipalError):
        raise result
    return result


# --- loader ---------------------------------------------------------------------------------------

_NOT_UTF8: Final = "not_utf8"
_UTF8_BOM: Final = "utf8_bom"
_TOO_LARGE: Final = "too_large"
_CONTENT_CAUSES: Final = frozenset({_NOT_UTF8, _UTF8_BOM, _TOO_LARGE})
_CONTENT_PROBLEMS: Final = {
    _NOT_UTF8: "is not valid UTF-8",
    _UTF8_BOM: "starts with a UTF-8 byte order mark; save it without one",
    _TOO_LARGE: f"is larger than {MAX_CREDENTIAL_FILE_BYTES // 1024 // 1024} MiB",
}


def _read_text(path: str) -> tuple[str | None, str | None]:
    """The text of the file at `path` and None, or None and a safe name for why: an errno name, `unknown`, `not_utf8`,
    `utf8_bom` or `too_large`."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_CREDENTIAL_FILE_BYTES + 1)
    except OSError as exc:
        return None, errno.errorcode.get(exc.errno or 0, "unknown")
    except ValueError:  # an embedded NUL in the path
        return None, "unknown"
    if len(raw) > MAX_CREDENTIAL_FILE_BYTES:
        return None, _TOO_LARGE
    if raw.startswith(b"\xef\xbb\xbf"):
        return None, _UTF8_BOM
    try:
        return raw.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, _NOT_UTF8


def _file_problem(what: str, cause: str) -> ServicePrincipalError:
    """The error for a file that `_read_text` could not give: its content is wrong (`invalid_credential`) or the
    operating system would not read it (`credential_unreadable`). Names the kind of file, never the file."""
    if cause in _CONTENT_CAUSES:
        return _invalid(f"{what[:1].upper()}{what[1:]} {_CONTENT_PROBLEMS[cause]}.", cause=cause)
    return ServicePrincipalError("credential_unreadable", f"Cannot read {what}.", cause=cause)


def _source_text(source: str | os.PathLike[str] | None, env: Mapping[str, str] | None) -> str:
    """The trimmed text of the source: the argument, else `NOBLECLOAK_SP_CREDENTIALS` in `env` (default `os.environ`,
    read only here, only when there is no argument)."""
    if source is None:
        return (os.environ if env is None else env).get(CREDENTIAL_ENV, "").strip()
    text = os.fspath(source)
    if not isinstance(text, str):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise TypeError("source must be a str or an os.PathLike[str] (a path or inline JSON), not bytes")
    return text.strip()


def _read_key_file(record: dict[str, Any], credential_file: str | None) -> dict[str, Any] | ServicePrincipalError:
    """`record` with its `key_file` replaced by the `private_jwk` that file holds, or the error."""
    key_file: Any = record["key_file"]
    if not isinstance(key_file, str) or key_file == "":
        return _invalid("Service-principal credential: key_file must be a path.")
    if credential_file is None:
        if not os.path.isabs(key_file):
            return _invalid(
                "Service-principal credential: key_file must be absolute when the credential is inline JSON."
            )
        key_path = key_file
    else:
        key_path = os.path.abspath(os.path.join(os.path.dirname(credential_file), key_file))
    key_text, cause = _read_text(key_path)
    if key_text is None:
        return _file_problem(
            "the key file named by key_file" if cause not in _CONTENT_CAUSES else "the key file", str(cause)
        )
    jwk = parse_json(key_text)
    if jwk is INVALID:
        return _invalid("The key file is not valid JSON.")
    return {**{name: member for name, member in record.items() if name != "key_file"}, "private_jwk": jwk}


def _load(
    source: str | os.PathLike[str] | None, env: Mapping[str, str] | None
) -> ServicePrincipalCredential | ServicePrincipalError:
    text = _source_text(source, env)
    origin = "the path argument" if source is not None else f"the path in {CREDENTIAL_ENV}"
    if text == "":
        return ServicePrincipalError(
            "credential_missing", f"No service-principal credential: pass a path or JSON, or set {CREDENTIAL_ENV}."
        )
    file: str | None = None
    json_text = text
    if not text.startswith("{"):
        # Text that is not a path is never echoed: a quoted .env value or a base64 CI secret holds the key.
        if re.search(r"[\"'\r\n{]", text):
            return _invalid(
                f"Service-principal credential: {origin} looks like JSON "
                'but does not start with "{" (check for surrounding quotes).'
            )
        file = os.path.abspath(text)
        content, cause = _read_text(file)
        if content is None:
            return _file_problem(
                f"the service-principal credential file named by {origin}"
                if cause not in _CONTENT_CAUSES
                else "the service-principal credential file",
                str(cause),
            )
        json_text = content
    raw = parse_json(json_text)
    if raw is INVALID:
        return _invalid("The service-principal credential is not valid JSON.")
    if not isinstance(raw, dict):
        return _invalid("Service-principal credential must be a JSON object.")
    record: dict[str, Any] = raw  # pyright: ignore[reportUnknownVariableType]
    if ("private_jwk" in record) == ("key_file" in record):
        return _invalid(
            "Service-principal credential must carry exactly one of "
            "private_jwk (inline key) and key_file (path to a JWK file)."
        )
    if "key_file" in record:
        resolved = _read_key_file(record, file)
        if isinstance(resolved, ServicePrincipalError):
            return resolved
        record = resolved
    return check_credential(record)


def load_service_principal_credential(
    source: str | os.PathLike[str] | None = None, *, env: Mapping[str, str] | None = None
) -> ServicePrincipalCredential:
    """Loads a credential from `source`: inline JSON (the text starts with `{`) or the path of a JSON file.

    Without `source` it reads `NOBLECLOAK_SP_CREDENTIALS` from `env` (default `os.environ`), which holds either. The
    environment is read only when no source is passed. The key is either inline (`private_jwk`) or in a separate JWK
    file (`key_file`), resolved relative to the credential file; inline JSON may name only an absolute `key_file`. A
    credential carrying both, or neither, is refused. A file larger than 1 MiB, one that is not UTF-8 and one that
    starts with a byte order mark are `invalid_credential` (`cause` is `too_large`, `not_utf8` or `utf8_bom`). A path
    given as bytes is a `TypeError`.

    Raises `ServicePrincipalError`, from a frame that holds neither the text nor the key.
    """
    result = _load(source, env)
    del source, env
    if isinstance(result, ServicePrincipalError):
        raise result
    return result
