# Contributing to the NobleCloak Python client

## Developer Certificate of Origin

Every commit must be signed off under the [Developer Certificate of Origin](https://developercertificate.org/):

```
Signed-off-by: Your Name <you@example.com>
```

`git commit -s` adds the line. There is no CLA.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat(digest): ...`, `fix(client): ...`,
`chore: ...`, `docs: ...`.

## Local gate

Run these before you open a pull request. Each is a separate CI step:

```sh
uv sync --locked
(cd conformance && bun install --frozen-lockfile)            # the pinned spec corpus the digest tests read
uv run --frozen ruff check
uv run --frozen ruff format --check
uv run --frozen pyright                                      # strict
uv run --frozen pytest                                       # branch coverage must stay at or above 90%
uv run --frozen python scripts/check_private_deps.py         # the private-dependency guard
uv run --frozen python scripts/generate_sync.py --check      # the generated sync sources are fresh
uv run --frozen python scripts/generate_models.py --check    # the generated models are what the pinned spec gives
```

CI also runs actionlint over `.github/workflows/` (a pinned Docker image). To run it locally:
`docker run --rm -v "$PWD:/repo" -w /repo rhysd/actionlint@sha256:<digest from ci.yml>`.

Enable the pre-commit hook once per clone: `git config core.hooksPath .githooks`. It runs the guard before every
commit.

## Toolchain

- Python 3.12 or newer (`requires-python = ">=3.12"`; `.python-version` selects 3.12 locally).
- [uv](https://docs.astral.sh/uv/) with the hatchling build backend. `uv.lock` is committed; CI syncs with `--locked`, which fails when `uv.lock` has drifted from `pyproject.toml`.
- Build, dev and optional requirements are pinned with `==`. Dependabot (uv and github-actions, monthly,
  grouped, at most three open) is the way they move.
- Runtime dependencies (`[project].dependencies`) are bounded ranges, `name>=floor,<ceiling`, so `noblecloak` can
  be installed next to other packages that use them. `uv.lock`
  resolves each one to its floor, and a test checks that, so CI runs the tests against the oldest release a
  consumer can get. The ceiling stops before the next minor release (`rfc8785` is pre-1.0); raising it is a
  reviewed change that passes the digest corpus, because the canonical form `rfc8785` writes is what gets hashed.
  A floor is never below the first release that fixes a known security advisory: CI tests the floor, so a
  vulnerable floor would mean testing, and allowing, a release with a published advisory. When an advisory lands
  against a floor, raise the floor to its first patched release (Dependabot's security PRs do this), relock and run
  the gate. If that leaves a range one release wide, widening the ceiling is a separate reviewed change.
  `cryptography` (ES256 verification of a Resumption, the service-principal assertion) is `>=50.0.0,<51`. The floor
  was raised from 44.0.1 on 2026-11-10 under the advisory rule (five advisories, the bundled OpenSSL among them;
  #5), which leaves one major release; its ceiling is the next major release, and raising it is a reviewed change
  that passes the resumption and service-principal tests. After `uv lock`, a bare lock keeps the
  floor; to move the floor, use `uv lock --upgrade-package cryptography==<new floor>`.
  `httpx` (the service-principal token requests, `noblecloak.service_principal`) is `>=0.25.1,<0.29`. The
  floor is 0.25.1, the first release whose changelog adds support for Python 3.12, which `requires-python` here
  demands. What the token source uses (`Client.send` and `AsyncClient.send` with a per-request `stream`, `auth` and
  `follow_redirects`, an `httpx.Request` built with the timeout in its `extensions`, `httpx.Timeout.as_dict`,
  `Response.is_stream_consumed`, `close` and `aclose`, `iter_raw` and `aiter_raw`, `MockTransport`, `SyncByteStream`
  and `AsyncByteStream`) was checked on 2026-11-10 by running the service-principal tests, after the review fixes of
  the token source, with the floor, 0.25.2, 0.26.0, 0.27.0, 0.27.2, 0.28.0 and 0.28.1 (the newest stable release, and
  the one the ceiling was chosen from; all but the floor outside CI),
  on Python 3.12. The client (`noblecloak.client`) adds `Client.build_request` with a `timeout`, `Client.send` with
  `stream=True` and `follow_redirects=False`, `Response.iter_bytes` and `aiter_bytes`, `URL.copy_with(query=None,
  fragment=None)` and `httpx.Timeout(read=None)`; its tests (`tests/test_client*.py`) were run on 2026-11-10 with the
  floor (CI), 0.27.2 and 0.28.1, on Python 3.12. The ceiling stops before the next minor release because `httpx` is pre-1.0 and its minors
  change the API (0.20 renamed `allow_redirects`; 0.28 removed `proxies` and `app`); raising it is a reviewed
  change that passes the service-principal tests, including the ones against a local server (redirect, stalled
  and trickled body). `httpx` 1.0 so far exists only as development releases, which `<0.29` excludes. To move the
  floor, use `uv lock --upgrade-package httpx==<new floor>`.
  `idna` (UTS46 checking of the token endpoint and audience hosts, `service_principal/_host.py`) is `>=3.15,<4`. It
  is declared even though `httpx` pulls it in, because the code imports it directly and UTS46 acceptance differs
  between releases. Used: `idna.encode(..., uts46=True, transitional=False)`, `idna.decode` and `idna.IDNAError`.
  The floor was raised from 3.4 on 2026-11-10 under the advisory rule (two `idna.encode()` denial-of-service
  advisories; #8); CI runs the host and credential tests at 3.15, and before the raise they also passed on 3.4,
  3.7 and 3.10. The ceiling stops before the next major release.
  `pydantic` (`noblecloak.models`) is `>=2.8.0,<3`. The generated models use `BaseModel`, `RootModel`, `ConfigDict`,
  `Field` with `pattern`, `min_length`, `ge` and `le` through `Annotated`, and `AwareDatetime`; the client adds
  `model_validate`, `model_dump(mode="json", by_alias=True, exclude_unset=True)` and
  `ValidationError.errors(include_url=False, include_context=False, include_input=False)`; the generator is run
  with `--target-pydantic-version 2`. The floor is the first release whose `pydantic-core` (2.20.0) has CPython 3.13
  wheels: 2.7.4 locks `pydantic-core` 2.18.4, which has cp312 wheels only, so on 3.13 uv builds the sdist and needs a
  Rust toolchain (OSV lists no advisory for 2.8.0 or `pydantic-core` 2.20.0; the last pydantic one, GHSA-mr82-8j83-vxmv,
  is fixed in 2.4.0). `tests/test_generated_models.py` was run on 2026-11-10 against 2.8.0 (the locked floor), 2.9.2,
  2.12.5 and 2.14.3 on both Python 3.12 and 3.13, and against 2.11.9 on 3.12 only; `uv sync --locked --python 3.13`
  installs from wheels. `tests/test_repo_policy.py` checks that the locked `pydantic-core` has a wheel for every CPython
  minor from `requires-python` up to 3.13. The ceiling is the next major release. `datamodel-code-generator` (dev)
  needs pydantic 2.12 on Python 3.14 and 2.14 on 3.15, so a constraint in `[tool.uv]`
  (`pydantic==2.8.0; python_full_version < '3.14'`) holds the floor below 3.14, which includes the Python CI runs (3.12)
  and 3.13, and `uv.lock` has a second pydantic entry for the later ones. To move the floor, change the range and that
  constraint together, then `uv lock`.
- [bun](https://bun.sh/) is used only inside `conformance/`, for the spec package.
- Async first, sync generated. `src/noblecloak/service_principal/_async/token.py` (`AsyncTokenSource`) and
  `src/noblecloak/client/_async/client.py` (`AsyncModuleClient`) are written by hand; `_sync/token.py` (`TokenSource`)
  and `_sync/client.py` (`ModuleClient`) are generated from them by `scripts/generate_sync.py`, which runs
  [`unasync`](https://github.com/python-trio/unasync) (a dev dependency) with a table of renames for each file (the
  `Unit`s in the script), then the pinned `ruff`. Never edit a generated file: change the async source (or the
  `async_x` / `sync_x` pairs in that package's `_core.py`, which are what the renames lead to), run
  `uv run python scripts/generate_sync.py`, and commit both. CI runs the script with `--check`, and
  `tests/test_generated_sync.py` does the same locally. Everything else the two sources of a package share is in its
  `_core.py`. Code that runs once per call and is not async (the cache, the key, the form, the reading of an answer)
  belongs there.

- Generated models. `src/noblecloak/models.py` (pydantic v2) is generated by `scripts/generate_models.py` from
  `conformance/node_modules/@noblecloak/spec/dist/openapi.public.yaml` with `datamodel-code-generator` (a dev
  dependency, pinned exactly). Never edit it: change the pin in `conformance/` (see below) or the generator's options,
  run `uv run python scripts/generate_models.py`, and commit the result. The file's header names the spec version and
  the SHA-256 of the document it was generated from. CI runs the script with `--check`, and
  `tests/test_generated_models.py` does the same locally; both need `bun install --frozen-lockfile` in
  `conformance/` first, and a missing document fails them. The options and what they trade are in the script's
  docstring. The models are for reading responses: every object keeps members it does not know (`extra="allow"`, even
  where the schema says `additionalProperties: false`), a `oneOf` request body such as `Action` does not enforce
  "exactly one of", and an optional member the schema gives no default is `None` when absent (`model_fields_set` says
  whether it was sent; dump with `model_dump(mode="json", by_alias=True, exclude_unset=True)` to send only what was
  set, under the wire names: without `by_alias=True` a member whose name is a Python keyword comes out as its Python
  name, `LooseningItem.from_` as `from_` and not `from`, and the models do not accept the Python name as input).
  Classes the generator numbers for an inline schema (`Kind1`, `Agent1`, `ConnectionAuth2`, ...) are not public API:
  the numbers follow the order of the document and a spec bump can change them. Import the components, which are named
  by the spec. A bump that changes the numbered set fails `test_the_classes_the_generator_numbers_are_the_ones_listed`.

## The contract and `conformance/`

`contract.json` records the contract this client implements: the phase, `contractRevision`, and the
`@noblecloak/client` and `@noblecloak/spec` versions. `conformance/package.json` and `conformance/bun.lock` pin
`@noblecloak/spec` (the mock, the corpus and the fixtures) to the exact version in `contract.json`, from the
public npm registry. Nothing is vendored. `noblecloak.__contract_revision__` must equal `contractRevision`;
`tests/test_contract.py` fails when any of the three disagree.

To move to a new contract: change `contract.json`, `conformance/package.json` (then `bun install` in
`conformance/` to rewrite `bun.lock`), `__contract_revision__` and the generated models (`scripts/generate_models.py`)
together. A contract change is a STOP
condition for an implementation run and needs a decision first.

## End-to-end tests (`-m e2e`)

`tests/test_e2e_mock.py` and `tests/test_e2e_differential.py` run against the pinned `nc-mock`. The default
`uv run --frozen pytest` leaves them out (`-m "not e2e"` is in `addopts`); CI's `e2e / mock` job and a developer select
them with `uv run --frozen pytest -m e2e --no-cov` (they add no coverage to the floor, which the unit tests keep).
They need `bun` on `PATH`, because the `nc-mock` bin from `conformance/node_modules` runs under it. With
`NOBLECLOAK_E2E_URL` set they use the mock listening there (CI starts one on port 8787); without it they start one on
a free port. A mock that does not start or answer fails the run; nothing skips.

- The flows: decide on an external tool, resolve as the approver (a token from `/__mock/tokens`), fetch the
  Resumption, fetch the JWKS, `verify_resumption`, then `consume`; a second consume conflicts. Around it: a stale
  digest, a service resolving an approval (its own, or another service's) and a consume of other arguments are
  refused; an approval withdrawn has no Resumption, whether it was withdrawn pending or after approval, and only the
  requester withdraws it or reads the Resumption (the approver gets 403 on both); a Resumption expires when the
  mock's clock (`/__mock/advance`) passes its time; forged, expired, wrong-audience and missing tokens are refused.
- Every flow but the expiry one is run again against a mock started with one `--break` that it guards
  (`nc-mock --break <name>`), and must go red. A new check on a flow gets its break; the table is `BREAKS` in `tests/test_e2e_mock.py`.
- The differential (Hypothesis, `hypothesis` is a dev dependency, MPL-2.0, never shipped): arguments are posted to
  `/v1/decisions` for a tool the mock does not know. The mock digests them with `argDigest` from `@noblecloak/client` and
  answers `action_digest`, and `noblecloak.digest.arg_digest` must give the same value, or refuse where the mock answers
  500 `internal_error`. That 500 is only a proxy for a refusal, because the mock answers every crash that way;
  `test_the_mocks_500_is_argdigest_refusing` pins it by running `argDigest` itself (under `bun`) on one input of each
  kind Python refuses. A disagreement is reported, and the digest is not bent to match: the corpus and RFC 8785 decide which one is wrong.

## Rules the tree enforces

- One index: pypi.org. No git, URL or path dependency, no `[tool.uv.sources]`, no extra index, no
  `find-links`. `conformance/` uses registry.npmjs.org only, with no `.npmrc` auth and no scope mapping.
- No credential anywhere: no PyPI, npm or GitHub token, no URL with a user part, no `.pypirc`, `.netrc`,
  `pip.conf` or `pip.ini`. `scripts/check_private_deps.py` checks the manifests, lockfiles and registry configs
  for all of it, and scans every other UTF-8 text file in the working tree for those tokens and URLs (it skips
  `.git`, `.venv`, `node_modules`, `__pycache__`, the pytest and ruff caches, `dist`, `build`, `htmlcov` and
  `artifacts`). It matches token formats, not arbitrary secrets. `.gitleaks.toml` extends gitleaks' default
  rules for a local scan of the tree or the history, which must find nothing; CI does not run gitleaks. Its only
  exceptions are two fake values planted in tests, each allowed by its exact value, and `tests/test_repo_policy.py`
  pins that list.
- Apache-2.0 everywhere, and NOTICE names NobleCloak as the holder.
- Workflows: every action is pinned to a full commit SHA with a `# vX.Y.Z` comment (the actionlint image to a
  digest with `# X.Y.Z`), every checkout sets `persist-credentials: false`, the workflow and every job hold
  `contents: read` and nothing more (except the two jobs of `publish.yml` below), no workflow reads the `secrets`
  context, no job but `github release` hands a step `github.token`, and no run line passes an index or registry
  flag (`--index-url`, `-i`, `--registry` and the like).
  `tests/test_repo_policy.py` asserts these properties.

## CI

`.github/workflows/ci.yml` runs on every pull request and every push to `main`, on two runners with no matrix:
`gate` (the commands above plus actionlint) and `e2e / mock` (installs the pinned spec package, starts `nc-mock`
on port 8787, waits for it to answer and runs `pytest -m e2e` against it, see below). Neither job is handed a token.

`.github/workflows/publish.yml` runs on a `v*` tag and by hand. Its `build` job builds the sdist and the wheel once
and writes `SHA256SUMS`. Two jobs then run only for a tag in `NobleCloak/noblecloak-py`: `github release` (the only job
with `contents: write`; it installs nothing) creates the GitHub Release, and `pypi publish` (the only job with
`id-token: write`; it installs nothing and runs no shell line, and it runs only after `github release` succeeded) publishes through PyPI trusted publishing, only when the repository variable
`PUBLIC_RELEASE_ENABLED` is `true` and a reviewer of the `pypi-publish` environment approves (once the maintainers have applied the environment hardening, it does not let the tag's pusher approve their own run or an
admin bypass the reviewers). Outside `NobleCloak/noblecloak-py` only `build` runs. The maintainers keep the
release runbook. `tests/test_publish_workflow.py` asserts the above.
