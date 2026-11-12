"""What a client's token seam takes: the two shapes of a token source, as `Protocol`s.

`TokenSource` satisfies `TokenProvider` and `AsyncTokenSource` satisfies `AsyncTokenProvider`; so does anything else
with the same two methods (a source that wraps one, or a stub in a test). Code that is given a token source types the
argument with one of these and not with the classes, which also own the credential and the transport.
"""

from __future__ import annotations

from typing import Protocol

__all__ = ["AsyncTokenProvider", "TokenProvider"]


class TokenProvider(Protocol):
    """A synchronous source of access tokens."""

    def get_token(self) -> str:
        """An access token: cached, or minted. Raises `ServicePrincipalError` when none can be."""
        ...

    def invalidate(self) -> None:
        """Drops the cached token, so that the next `get_token` mints a new one."""
        ...


class AsyncTokenProvider(Protocol):
    """An asynchronous source of access tokens. `invalidate` is synchronous: it only drops the cache."""

    async def get_token(self) -> str:
        """An access token: cached, or minted. Raises `ServicePrincipalError` when none can be."""
        ...

    def invalidate(self) -> None:
        """Drops the cached token, so that the next `get_token` mints a new one."""
        ...
