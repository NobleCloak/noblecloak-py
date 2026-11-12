"""What the client's operations return and raise: `Ok`, `Problem`, `Answer`, `ModuleApiError`, `is_transient`.

Python port of the answer types of the `@noblecloak/client` `governance-api` subpath (`transient.ts`,
`module-api-error.ts`). A 4xx comes back as a `Problem` and is never raised; a network failure, a 5xx or a body that
cannot be read as an answer is raised as `ModuleApiError("unreachable")`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar, Literal

if TYPE_CHECKING:
    from noblecloak.models import Approval

__all__ = [
    "Answer",
    "ApprovalsPage",
    "DpopRequest",
    "ModuleApiError",
    "ModuleApiErrorCode",
    "Ok",
    "Problem",
    "is_transient",
    "is_transient_status",
]

ModuleApiErrorCode = Literal["unreachable"]
"""`unreachable`: the request got no usable answer (a network failure, a 5xx, or a body that is not an answer)."""


class ModuleApiError(Exception):
    """The one failure the typed operations raise: the module API could not be read as an answer.

    Raised for a network failure, a 5xx, or a body that cannot be read. A 4xx is never raised: it comes back as a
    `Problem`. `code` is the stable part and the message is for people. The exception that caused it, when there was
    one, is `__cause__`. For a 5xx whose body was read, `problem` is what the body said (the status, the code that is
    the last segment of its `type`, its `detail`) and `request_id` is its `request_id`; both are None otherwise.
    """

    code: ModuleApiErrorCode
    problem: Problem | None
    request_id: str | None

    def __init__(
        self,
        code: ModuleApiErrorCode,
        message: str,
        *,
        problem: Problem | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.problem = problem
        self.request_id = request_id

    def __reduce__(self) -> tuple[type[ModuleApiError], tuple[ModuleApiErrorCode, str], dict[str, object]]:
        # the default would call `ModuleApiError(message)`
        return (type(self), (self.code, str(self)), {"problem": self.problem, "request_id": self.request_id})


@dataclass(frozen=True, slots=True)
class Ok[T]:
    """A successful answer: `data` is what the envelope's `data` member held, validated as the operation's model."""

    data: T
    ok: ClassVar[Literal[True]] = True


@dataclass(frozen=True, slots=True)
class Problem:
    """A 4xx answer (or any other non-2xx status below 500): the status, and the problem type's code, which is the
    last segment of its `type` URI (empty when the body had none). `detail` is only set when the body had a string one.
    (`noblecloak.models.Problem` is the spec's whole problem document; this is what a caller branches on.)"""

    status: int
    code: str
    detail: str | None = None
    ok: ClassVar[Literal[False]] = False


type Answer[T] = Ok[T] | Problem
"""What an operation resolves to: `Ok` with the data, or a `Problem`."""


@dataclass(frozen=True, slots=True)
class ApprovalsPage:
    """One page of approvals and the cursor of the next one (None on the last page)."""

    rows: list[Approval]
    next: str | None


@dataclass(frozen=True, slots=True)
class DpopRequest:
    """What a DPoP proof is requested for (RFC 9449 §4.2): `url` has neither query nor fragment, as `htu` requires.
    `access_token` is left out of `repr`, so that logging a request does not log the credential."""

    method: str
    url: str
    access_token: str = field(repr=False)


def is_transient_status(status: int) -> bool:
    """Whether an HTTP status is one a caller may send the same request again for: 5xx, 408 and 429."""
    return status >= 500 or status in (408, 429)


def is_transient(subject: object) -> bool:
    """The single place that says which failures are transient. Takes an `Answer`, a `Problem` or a raised error.

    True for a `ModuleApiError` (its one code is `unreachable`), including one from another installed copy of this
    package (an exception whose class is named `ModuleApiError` and whose `code` is `unreachable`), and for a
    `Problem` whose status is 5xx, 408 or 429. False for an `Ok`, for any other status (400, 403, 404, 409 ...), and
    for any other object, an exception that carries a `status` among them. `jwks` and `stream_approvals` raise
    `ModuleApiError` for every non-2xx status, 4xx included, so `is_transient` is true for those.
    """
    if isinstance(subject, ModuleApiError):
        return True
    if isinstance(subject, Exception):
        return type(subject).__name__ == "ModuleApiError" and getattr(subject, "code", None) == "unreachable"
    return isinstance(subject, Problem) and is_transient_status(subject.status)
