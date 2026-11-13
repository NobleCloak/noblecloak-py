"""Errors of `noblecloak.service_principal`. A message is fixed text, or the OAuth error code the token endpoint
returned once it has been checked to be one (see `ServicePrincipalError.oauth_error`): it never carries key material,
an assertion, an access token, a path, or any other text from the server. What the server said in prose is in
`oauth_error_description`, capped, stripped of control characters and with the assertion that was sent redacted, and is
in neither `str()` nor `repr()`."""

from __future__ import annotations

from typing import Literal, get_args

__all__ = ["ServicePrincipalError", "ServicePrincipalErrorCode"]

ServicePrincipalErrorCode = Literal[
    "credential_missing",
    "credential_unreadable",
    "invalid_credential",
    "invalid_client",
    "token_request_rejected",
    "invalid_response",
    "network_error",
]
"""
- `credential_missing`: no credential source was given and `NOBLECLOAK_SP_CREDENTIALS` is unset.
- `credential_unreadable`: a credential file or key file could not be read.
- `invalid_credential`: the credential is not valid JSON, has the wrong shape, or carries a key this package refuses.
- `invalid_client`: the token endpoint answered `invalid_client`: the principal is revoked or expired, or the key is
  unknown, or the machine's clock is off.
- `token_request_rejected`: the token endpoint refused the request for another OAuth reason (`oauth_error` names it).
- `invalid_response`: the token endpoint did not answer with a usable token response.
- `network_error`: the request never got an answer (connection failure, timeout, a redirect, an unreadable body).
"""


class ServicePrincipalError(Exception):
    """Why a service-principal credential could not be loaded or a token could not be minted.

    A bad argument to `TokenSource` that is no fault of the credential (`scopes` given as one string, a negative
    timeout) is a `TypeError` or `ValueError` instead; see `_core.py` (`_join_scopes`, `_positive`).
    """

    code: ServicePrincipalErrorCode
    status: int | None
    """The HTTP status of the token endpoint's answer, when there was one."""
    oauth_error: str | None
    """The OAuth `error` the token endpoint returned, when there was one and it is an error code: 1 to 64 characters
    of the RFC 6749 §5.2 set (`%x20-21 / %x23-5B / %x5D-7E`) that do not contain the whole assertion or key member,
    and are not themselves a piece of one 16 or more characters long. A code that mixes other text with a piece of
    the assertion's header or payload (which the server was sent) is kept. Anything else is None, and the error says
    the answer had no usable OAuth error."""
    oauth_error_description: str | None
    """The OAuth `error_description` the token endpoint returned, as text for a person to read and for nothing else:
    at most 200 characters, control characters removed, every occurrence of the assertion that was sent (and of the
    key's private members) replaced with `[redacted]`. Not in `str()` or `repr()`; it is server text, so a server that
    is not the token endpoint, or a hostile one, chose it."""
    cause: str | None
    """A short, safe description of what went wrong underneath: an OS error name such as `ENOENT`, the class name of
    the transport failure such as `ConnectError` (`TimeoutError` for any timeout), `redirect_not_followed`,
    `unexpected_3xx`, a fixed reason a key could not be imported or a credential file could not be read (`too_large`,
    `not_utf8`, `utf8_bom`), or, for an answer with a status that is not 2xx and no usable OAuth error, a few facts
    about the answer: `content_type=<type/subtype>` (only if it is an RFC 7230 token), `body_bytes=<n>` and
    `json=true|false`. Never a message of the underlying exception, and never the body.

    For a failed token request the error's `__cause__` is a stand-in that names the class of the exception underneath
    (`httpx.ReadTimeout`), with no message, request or traceback: the real exception holds the request, and the request
    holds the signed assertion. Loading a credential never keeps a chain: it could carry a path or the credential's
    text."""

    def __init__(
        self,
        code: ServicePrincipalErrorCode,
        message: str,
        *,
        status: int | None = None,
        oauth_error: str | None = None,
        oauth_error_description: str | None = None,
        cause: str | None = None,
    ) -> None:
        if code not in get_args(ServicePrincipalErrorCode):
            raise ValueError(f"unknown service-principal error code: {code!r}")
        super().__init__(message)
        self.code = code
        self.status = status
        self.oauth_error = oauth_error
        self.oauth_error_description = oauth_error_description
        self.cause = cause

    def __repr__(self) -> str:
        # The message and the description are left out: `repr` is what a log line or a tracker shows.
        return f"ServicePrincipalError(code={self.code!r}, status={self.status!r}, oauth_error={self.oauth_error!r})"

    def __reduce__(
        self,
    ) -> tuple[object, tuple[ServicePrincipalErrorCode, str], dict[str, object]]:
        # `args` is `(message,)`, so the default reconstruction `cls(message)` fails; pickle and copy use this instead.
        return (
            type(self),
            (self.code, str(self)),
            {
                "status": self.status,
                "oauth_error": self.oauth_error,
                "oauth_error_description": self.oauth_error_description,
                "cause": self.cause,
            },
        )
