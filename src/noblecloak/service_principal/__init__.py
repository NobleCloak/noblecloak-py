"""Service principals: a credential, and the access tokens it can mint. Server-side only: it handles a private key.

`load_service_principal_credential` reads a credential; `TokenSource` and `AsyncTokenSource` turn it into access
tokens for the client's `get_token` seam (`TokenProvider` and `AsyncTokenProvider` are the shapes of that seam).
Python port of the `@noblecloak/client` service-principal subpath.
"""

from noblecloak.service_principal._async.token import AsyncTokenSource
from noblecloak.service_principal._sync.token import TokenSource
from noblecloak.service_principal.credential import (
    CREDENTIAL_ENV,
    ServicePrincipalCredential,
    load_service_principal_credential,
    parse_service_principal_credential,
)
from noblecloak.service_principal.error import ServicePrincipalError, ServicePrincipalErrorCode
from noblecloak.service_principal.provider import AsyncTokenProvider, TokenProvider

__all__ = [
    "CREDENTIAL_ENV",
    "AsyncTokenProvider",
    "AsyncTokenSource",
    "ServicePrincipalCredential",
    "ServicePrincipalError",
    "ServicePrincipalErrorCode",
    "TokenProvider",
    "TokenSource",
    "load_service_principal_credential",
    "parse_service_principal_credential",
]
