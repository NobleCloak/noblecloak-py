"""The module API client: `AsyncModuleClient` and the sync `ModuleClient`, and the answers they return.

Python port of `@noblecloak/client`: `createClient` and the `governance-api` subpath (`GovernanceApi`, `ModuleApiError`,
`isTransient`). Every operation resolves to an `Ok` or a `Problem` (an `Answer`) or raises `ModuleApiError`;
`is_transient` says whether to retry. `request` is the raw, authenticated request the operations are made of.

Where this differs from the TypeScript client (stricter, unless said otherwise):

- A response is validated as the spec's model (`noblecloak.models`), where the original only casts. Data that does not
  validate raises `ModuleApiError("unreachable")`; its message names where the faults are and never what was there.
- `base_url` is `https`, or `http` for `localhost`, `127.0.0.1` and `[::1]`; it has no user part, query or fragment.
- A redirect is never followed, because the credential would go with it; a 3xx comes back as a `Problem`.
- `get_token` and `dpop_proof` must return printable ASCII without spaces. Anything else is a `TypeError`, raised as
  itself and not as `unreachable` (which a caller retries). The sync client refuses an awaitable the same way.
- A model field that is `None` is left out of the body of a typed operation (`decide`, `append_record`), also in a
  model inside a `Mapping`: no request schema of those operations has a nullable member, and the server answers 400 to
  a `null` where it expects an object. `request` sends it as `null`. A `Mapping` or a list holding models is accepted
  as a body. A request body with NaN or an infinity, or one that contains itself, is a `ValueError`, and nothing is
  sent. An id is percent-encoded as one path segment and must be neither empty nor `.` or `..`; an idempotency key is
  1 to 255 characters of printable ASCII without spaces; `wait_approval` takes a whole number of seconds.
- The credential is the one `get_token` gave: the caller's `Authorization` and `DPoP` headers, and the `auth` of a
  caller's `httpx` client, are not used; a `DPoP` default header of that client is replaced by the proof, or removed
  when there is no `dpop_proof`. With a body, the caller's `Content-Type` is not used either; it is JSON.
- There is no `signal` argument. Cancelling the task that awaits an async operation cancels its request; a sync call
  cannot be cancelled.
- A 5xx raises `ModuleApiError("unreachable")` with the problem's code and `request_id` in the message (each cut at 200
  characters, control characters replaced) and the whole problem, `detail` included, on its `problem` and `request_id`
  attributes; the server's `detail` never goes into `str()` or `repr()`. The original's message is only
  `/v1 answered <status>`. `jwks` and `stream_approvals` still drop the body of a non-2xx.
- `timeout_seconds` (default 30) is the `httpx` timeout of each phase of a request; the original sets none.
- `stream_approvals` is a context manager that yields the raw body as chunks of bytes and closes the response; `jwks`
  returns the key set as a dict, which is what `verify_resumption` takes.
"""

from noblecloak.client._async.client import AsyncModuleClient
from noblecloak.client._sync.client import ModuleClient
from noblecloak.client.types import (
    Answer,
    ApprovalsPage,
    DpopRequest,
    ModuleApiError,
    ModuleApiErrorCode,
    Ok,
    Problem,
    is_transient,
    is_transient_status,
)

__all__ = [
    "Answer",
    "ApprovalsPage",
    "AsyncModuleClient",
    "DpopRequest",
    "ModuleApiError",
    "ModuleApiErrorCode",
    "ModuleClient",
    "Ok",
    "Problem",
    "is_transient",
    "is_transient_status",
]
