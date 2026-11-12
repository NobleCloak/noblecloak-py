# noblecloak-py

The common Python library for NobleCloak governed approvals: the Python counterpart of `@noblecloak/client`, against the same `/v1` module API contract.

**Status:** under construction. No release yet. The package has `noblecloak.digest` (argument digests), `noblecloak.resumption` (verification of a Resumption, with replay guards), `noblecloak.service_principal` (a service-principal credential and the access tokens it mints, with a sync and an async source), `noblecloak.client` (the `/v1` module API: `AsyncModuleClient` and a generated sync `ModuleClient`, answers, `is_transient`), `noblecloak.models` (pydantic models generated from the pinned spec), and the test-only `noblecloak.testing`.

See `CONTRIBUTING.md` for the local gate and the rules the tree enforces.

Licensed under Apache-2.0. See `LICENSE`.
