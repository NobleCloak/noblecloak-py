# noblecloak-py

The common Python library for NobleCloak governed approvals: the Python counterpart of `@noblecloak/client`, against the same `/v1` module API contract.

**Status:** 0.1.0, the first release. Until 1.0, a minor version may change the API.

## Install

```sh
pip install noblecloak
```

Python 3.12 or later.

## Use

```python
import asyncio

from noblecloak.client import AsyncModuleClient, Ok
from noblecloak.service_principal import AsyncTokenSource, load_service_principal_credential


async def main() -> None:
    # Reads the credential from NOBLECLOAK_SP_CREDENTIALS (inline JSON or a file path).
    tokens = AsyncTokenSource(load_service_principal_credential(), audience="https://api.example.com")
    async with AsyncModuleClient("https://api.example.com", get_token=tokens.get_token) as client:
        action = {"tool_ref": "ext:local:send_email", "arguments": {"to": "ap@example.com"}}
        answer = await client.decide({"action": action})
        if isinstance(answer, Ok):
            print(answer.data.decision)  # allow, deny, step_up or defer
        else:
            print(answer.status, answer.code)


asyncio.run(main())
```

`ModuleClient` and `TokenSource` are the sync equivalents.

## Modules

- `noblecloak.client`: the `/v1` module API (`AsyncModuleClient`, the sync `ModuleClient`, `Answer`, `is_transient`).
- `noblecloak.service_principal`: a service-principal credential and the access tokens it mints, sync and async.
- `noblecloak.digest`: argument digests (`jcs`, `arg_digest`), identical to `@noblecloak/client`.
- `noblecloak.resumption`: verification of a Resumption, with replay guards.
- `noblecloak.models`: pydantic models generated from the pinned spec.
- `noblecloak.testing`: helpers for tests only.

See `CONTRIBUTING.md` for the local gate and the rules the tree enforces.

Licensed under Apache-2.0. See `LICENSE`.
