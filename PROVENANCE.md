# Provenance

This repository started empty (LICENSE and README only). Its code was written for the Python client, as a port of the
TypeScript client and adapter that NobleCloak publishes: `@noblecloak/client` 0.13.0 in
[`NobleCloak/noblecloak-ts`](https://github.com/NobleCloak/noblecloak-ts) (read at `bb1be4c`) and the LangGraph
adapter in [`NobleCloak/noblecloak-langgraph-ts`](https://github.com/NobleCloak/noblecloak-langgraph-ts). No file was
copied across and no git history came with it. What was carried over is design, not text.

## Repository scaffold

- `scripts/check_private_deps.py` follows `scripts/check-private-deps.ts` of the LangGraph adapter's repository: the
  same violation classes, with the Python side (pypi.org, `pyproject.toml`, `uv.lock`) added to the npm side
  (`conformance/`). The scan of every other text file in the tree for PyPI, npm and GitHub tokens is new here; the
  TypeScript guard has no equivalent.
- `tests/test_repo_policy.py` follows `scripts/repo-policy.test.ts` there: the NOTICE holder, SHA-pinned actions with
  a version comment, `persist-credentials: false`, write scopes only where listed, no `secrets` context.
- `contract.json` has the same shape as that repository's `contract.json`. It pins the published line
  `contract-v1-rev18`, `@noblecloak/client` 0.13.0, `@noblecloak/spec` 0.12.0, which the `@noblecloak/spec` 0.12.0
  README names as its contract revision.
- `.github/workflows/ci.yml`, `.github/dependabot.yml`, `.githooks/pre-commit`, `.gitleaks.toml`, `CODEOWNERS`,
  `SECURITY.md` and the DCO rule in `CONTRIBUTING.md` follow the files of the same name there. The pinned action SHAs
  for `actions/checkout`, `oven-sh/setup-bun` and the actionlint digest are the ones that repository pins;
  `astral-sh/setup-uv` is new here.

## Modules

`src/noblecloak/digest.py` is a port of `packages/client/src/digest.ts` in `@noblecloak/client` 0.13.0: the five error
codes, `MAX_NESTING_DEPTH = 64`, and the refusal rules. Canonicalisation is the `rfc8785` package (locked at 0.1.4 for
CI, `>=0.1.4,<0.2` for consumers) behind a validator that is stricter than the original: exact types only (no
subclasses, enums or tuples), and error messages that carry no key and no string or integer text. The RFC 8785
Appendix B number vectors in `tests/test_digest.py` were written from the RFC and the pinned `rfc8785` 0.1.4 reproduces
every row; `@noblecloak/spec` 0.12.0 does not ship them.

`src/noblecloak/resumption.py` is a port of `packages/client/src/resumption.ts` in `@noblecloak/client` 0.13.0 and, for
`ForgettingReplayGuard`, of `packages/langgraph/src/replay.ts` in the LangGraph adapter. The nine error codes, the order
of the checks with the replay guard last, the strict canonical base64url decoding, the EC P-256 key rule, the expiry
rule `expires_at + skew <= now`, the `accept_resolutions` default and the `approval_id` replay key are the original's.
ECDSA is done with `cryptography` (Apache-2.0 or BSD-3-Clause, at the holder's option; the Apache-2.0 terms apply here)
in place of WebCrypto. Where Python is deliberately stricter than the original is listed in the module docstring: a
`crit` header is refused, `expires_at` is strict RFC 3339, and a `replay_guard` is required.
`src/noblecloak/testing.py` is the equivalent of `packages/langgraph/test/sign.ts` in the LangGraph adapter: a
test-only signer. Its High-S option and the padded and non-canonical signatures in `tests/test_resumption.py` are new
here.

`src/noblecloak/service_principal/` is a port of `service-principal-credential.ts`, `service-principal-error.ts` and
`service-principal-token.ts` in `@noblecloak/client` 0.13.0, and its tests port `service-principal.test.ts` (every case
but `feeds createClient`, which is in `tests/test_client.py`) and `service-principal-credential.test.ts`. The seven
error codes, the credential rules (`sp_<uuid>`, https or loopback http, EC P-256 or RSA of at least 2048 bits, exactly
one of `private_jwk` and `key_file`, secret-shaped field names refused), the 120 s assertion with `iss` = `sub` =
`client_id`, the RFC 7638 key id, the RFC 8707 `resource`, the cache rule `life - min(skew, life / 2)`, the shared
in-flight request, the generation counter and the rule that a failure is not cached are the original's. Keys are signed
with `cryptography` and requests go through `httpx` in place of WebCrypto and `fetch`. The async source is written by
hand and the sync one is generated from it with `unasync` (`scripts/generate_sync.py`). Where Python is deliberately
stricter than the original is listed in the docstrings of `credential.py` and `_core.py`; the main ones are that no
error message, `cause` or exception chain ever echoes a path (the original puts the key file's path in the message),
that the timeout covers the whole request, and that an answer over 1 MiB is refused.

`src/noblecloak/models.py` is generated, not ported: `scripts/generate_models.py` runs `datamodel-code-generator` 0.92.0
over `dist/openapi.public.yaml` of `@noblecloak/spec` 0.12.0, the document that `packages/client/src/schema.ts` in
`@noblecloak/client` 0.13.0 is generated from with `openapi-typescript`. The script follows `scripts/generate_sync.py`:
a generator, the same ruff pass and a `--check` mode.

`src/noblecloak/client/` is a port of `client.ts`, `governance-api.ts`, `module-api-error.ts` and `transient.ts` in
`@noblecloak/client` 0.13.0, and its tests port the cases of `client.test.ts`, of `governance-api.test.ts` (but for
those about an abort `signal` and a stream answer with no body, which have no Python counterpart) and the
`feeds createClient` case of `service-principal.test.ts`. The operations and their routes, the envelope check, the code
taken from the last segment of the problem `type`, the transient statuses (5xx, 408, 429), the `created_by=me` listing,
`isPassThrough` and the rule that a 4xx is an answer and a 5xx or an unreadable body is `unreachable` are the
original's. Requests go through `httpx` in place of `openapi-fetch` and `fetch`; the async client is written by hand
and the sync one is generated from it with `unasync`. Where Python is deliberately stricter than, or differs from, the
original is listed in the docstring of `noblecloak/client/__init__.py`.

`.github/workflows/publish.yml` was written here. The SHA pins of `actions/upload-artifact`, `actions/download-artifact`
and `pypa/gh-action-pypi-publish` are the ones the name-reservation `publish.yml` of this repository used;
`astral-sh/setup-uv` and `actions/checkout` are the pins `ci.yml` uses.
