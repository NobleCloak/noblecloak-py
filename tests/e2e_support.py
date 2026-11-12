"""Support for the end-to-end tests: start the pinned `nc-mock`, and the flows the tests run against it.

The mock comes from the frozen install in `conformance/` (`@noblecloak/spec`, pinned in `conformance/package.json`),
and its `bun` shebang means `bun` must be on `PATH`. A missing bin, a missing `bun` or a mock that does not answer
fails the run; nothing here skips. Every token is one the mock itself minted for the run (`/__mock/tokens`).
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast

import httpx

from noblecloak.client import ModuleClient, Ok, Problem
from noblecloak.digest import DigestError, arg_digest
from noblecloak.models import Decision
from noblecloak.resumption import ExpectedAction, InMemoryReplayGuard, ResumptionError, verify_resumption

ROOT = Path(__file__).resolve().parent.parent
NC_MOCK = ROOT / "conformance/node_modules/.bin/nc-mock"
STARTUP_SECONDS = 30.0

# An external tool the mock does not know: its default policy asks, and an approval for it carries a resume token.
EXTERNAL_TOOL = "ext:local:send_email"
# A tool the mock does not know at all: `deny unknown_tool`, and the answer still carries the action digest.
UNKNOWN_TOOL = "tool:differential:probe"
STALE_DIGEST = "0" * 64


def check(condition: object, message: str) -> None:
    """The failure of a flow: an `AssertionError` that names what the mock did instead."""
    if not condition:
        raise AssertionError(message)


@dataclass(frozen=True)
class Mock:
    """A running `nc-mock`: where it is and the tokens it minted."""

    base_url: str
    tokens: dict[str, str]

    def client(self, who: str) -> ModuleClient:
        """A client that sends the mock's `who` token (`creator`, `approver`, `forged` ...) with every request."""
        token = self.tokens[who]
        return ModuleClient(self.base_url, get_token=lambda: token)

    def advance(self, seconds: float) -> datetime:
        """Moves the mock's clock forward and returns what it now says the time is."""
        response = httpx.post(f"{self.base_url}/__mock/advance", json={"seconds": seconds})
        check(response.status_code == 200, f"/__mock/advance answered {response.status_code}")
        return datetime.fromisoformat(response.json()["now"])


def attach(base_url: str) -> Mock:
    """The mock already listening at `base_url`, which is the one CI started."""
    response = httpx.get(f"{base_url}/__mock/tokens", timeout=10.0)
    response.raise_for_status()
    tokens = {name: token for name, token in response.json().items() if name != "audience"}
    return Mock(base_url, tokens)


@contextmanager
def spawn_mock(*breaks: str) -> Generator[Mock]:
    """Starts `nc-mock` on a free port with `--break` for each name in `breaks`, and stops it on leaving the block.

    The mock prints `{base_url, deployment, tokens}` on startup; that is how the port and the tokens are learned.
    """
    if not NC_MOCK.is_file():
        raise RuntimeError("run `bun install --frozen-lockfile` in conformance/ first; a missing mock fails the run")
    arguments = [str(NC_MOCK), "--port", "0"]
    for name in breaks:
        arguments += ["--break", name]
    with tempfile.TemporaryDirectory() as directory:
        out_path, err_path = Path(directory) / "out", Path(directory) / "err"
        with out_path.open("wb") as out, err_path.open("wb") as err:
            process = subprocess.Popen(arguments, stdout=out, stderr=err, cwd=ROOT / "conformance")
        try:
            yield _started(process, out_path, err_path)
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover - a mock that ignores SIGTERM
                process.kill()
                process.wait()


def _started(process: subprocess.Popen[bytes], out_path: Path, err_path: Path) -> Mock:
    deadline = time.monotonic() + STARTUP_SECONDS
    while time.monotonic() < deadline:
        try:
            info: object = json.loads(out_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            info = None
        if isinstance(info, dict):
            started = cast("dict[str, Any]", info)
            tokens = cast("dict[str, str]", started["tokens"])
            return Mock(str(started["base_url"]), {name: token for name, token in tokens.items() if name != "audience"})
        if process.poll() is not None:
            break
        time.sleep(0.05)
    stderr = err_path.read_text(encoding="utf-8", errors="replace")
    raise RuntimeError(f"nc-mock did not start (exit {process.poll()}): {stderr.strip()}")


# --- the flows ------------------------------------------------------------------------------------


def _unique_arguments() -> dict[str, Any]:
    """Arguments no other approval in the mock has, so that one flow never joins another's pending approval."""
    return {"to": "someone@example.test", "nonce": uuid.uuid4().hex}


def _ok[T](answer: Ok[T] | Problem, what: str) -> T:
    check(isinstance(answer, Ok), f"{what}: expected an Ok, got {answer!r}")
    assert isinstance(answer, Ok)
    return answer.data  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType]


def _refused(answer: object, status: int, what: str, code: str | None = None) -> None:
    """`answer` is a Problem with this status and, when `code` is given, this problem code."""
    check(isinstance(answer, Problem), f"{what}: expected a {status} Problem, got {answer!r}")
    assert isinstance(answer, Problem)
    check(answer.status == status, f"{what}: expected {status}, got {answer.status} ({answer.code})")
    if code is not None:
        check(answer.code == code, f"{what}: expected the code {code}, got {answer.code}")


def _open_approval(mock: Mock, arguments: dict[str, Any]) -> Decision:
    decision = _ok(
        mock.client("creator").decide({"action": {"tool_ref": EXTERNAL_TOOL, "arguments": arguments}}),
        "decide on an external tool",
    )
    check(decision.decision.value == "step_up", f"an external tool should ask, the decision was {decision.decision}")
    check(decision.approval is not None, "a step_up decision carries an approval handle")
    assert decision.approval is not None
    check(decision.approval.resume_token_will_issue is True, "an external tool's approval issues a resume token")
    return decision


def _resolve(mock: Mock, approval_id: str, digest: str, who: str = "approver") -> Any:
    """The approver step. There is no typed operation for it, so it goes through the raw request."""
    return mock.client(who).request(
        "POST",
        f"/v1/approvals/{approval_id}/resolve",
        json={"resolution": "approved", "expected_action_digest": digest},
    )


def flow_approve_and_consume(mock: Mock) -> None:
    """decide -> resolve as the approver -> resumption -> jwks -> verify -> consume, and the refusals around it."""
    creator = mock.client("creator")
    arguments = _unique_arguments()
    decision = _open_approval(mock, arguments)
    assert decision.approval is not None
    approval_id = decision.approval.id
    digest = decision.action_digest.root
    check(digest == arg_digest(arguments), "the mock's action_digest is not the Python digest of the arguments")

    # Nobody but an approver resolves: not the service that asked, and not an answer to a digest that has moved on.
    refused = _resolve(mock, approval_id, digest, who="creator")
    check(refused.status_code in {401, 403}, f"a service resolved its own approval: {refused.status_code}")
    # A service that did not ask is refused too. This is the one that isolates the mock's service check: the creator
    # above is also stopped by the creator-is-not-the-approver check, which `--break allow_service_resolve` leaves on.
    other = _resolve(mock, approval_id, digest, who="other_service")
    check(other.status_code in {401, 403}, f"a service that did not ask resolved the approval: {other.status_code}")
    stale = _resolve(mock, approval_id, STALE_DIGEST)
    check(stale.status_code == 409, f"a resolution of a stale digest answered {stale.status_code}, not 409")
    resolved = _resolve(mock, approval_id, digest)
    check(resolved.status_code == 200, f"the approver's resolution answered {resolved.status_code}")

    resumption = _ok(creator.get_resumption(approval_id), "the resumption of an approved approval")
    check(resumption.resume_token is not None, "a resumption for /consume carries a resume token")
    assert resumption.resume_token is not None
    # Only the service that asked reads it: the approver who resolved it does not get the token to spend.
    snooping = mock.client("approver").request("GET", f"/v1/approvals/{approval_id}/resumption")
    check(snooping.status_code == 403, f"the approver read the Resumption: {snooping.status_code}, not 403")
    jwks = creator.jwks()
    expected = ExpectedAction.for_call(EXTERNAL_TOOL, arguments)
    guard = InMemoryReplayGuard()
    payload = verify_resumption(resumption.signature, jwks, expected, replay_guard=guard)
    check(payload["approval_id"] == approval_id, "the verified payload names another approval")
    try:
        verify_resumption(resumption.signature, jwks, expected, replay_guard=guard)
    except ResumptionError as error:
        check(error.code == "replayed", f"the second verification failed as {error.code}, not replayed")
    else:
        raise AssertionError("the second verification with the same guard was accepted")

    # The approval is for these arguments only, and a refused consume spends nothing.
    other = {**arguments, "nonce": uuid.uuid4().hex}
    _refused(
        creator.consume(approval_id, resumption.resume_token, EXTERNAL_TOOL, other), 409, "consume with other arguments"
    )
    consumed = _ok(
        creator.consume(approval_id, resumption.resume_token, EXTERNAL_TOOL, arguments), "the consume of the approval"
    )
    check(consumed.state == "consumed", f"the consume answered state {consumed.state}")
    _refused(creator.consume(approval_id, resumption.resume_token, EXTERNAL_TOOL, arguments), 409, "the second consume")


def flow_withdrawn_has_no_resumption(mock: Mock) -> None:
    """Only the service that asked withdraws; a withdrawn approval is not resolved afterwards and issues no Resumption,
    whether it was withdrawn while pending or after the approver approved it."""
    creator = mock.client("creator")

    # Approved first: the Resumption exists until the requester withdraws, and is refused as withdrawn after. This is
    # the path `--break resumption_after_withdraw` is on, so it runs before the pending case, which that break would
    # also turn red but only through a 404 (a pending approval never had a Resumption to serve).
    decision = _open_approval(mock, _unique_arguments())
    assert decision.approval is not None
    approval_id = decision.approval.id
    check(_resolve(mock, approval_id, decision.action_digest.root).status_code == 200, "the resolution was refused")
    _ok(creator.get_resumption(approval_id), "the resumption of an approved approval, before the withdrawal")
    _ok(creator.withdraw(approval_id), "the withdrawal of an approved approval")
    _refused(
        creator.get_resumption(approval_id),
        409,
        "the resumption of an approval withdrawn after it was approved",
        code="obligation_withdrawn",
    )

    # Pending: the approver cannot withdraw it, the requester can, and nothing is resolved or issued afterwards.
    decision = _open_approval(mock, _unique_arguments())
    assert decision.approval is not None
    approval_id = decision.approval.id
    by_approver = mock.client("approver").request("POST", f"/v1/approvals/{approval_id}/withdraw")
    check(by_approver.status_code == 403, f"the approver withdrew a request: {by_approver.status_code}, not 403")
    withdrawn = _ok(creator.withdraw(approval_id), "the withdrawal of a pending approval")
    check(withdrawn.state.value == "withdrawn", f"the withdrawal answered state {withdrawn.state}")
    late = _resolve(mock, approval_id, decision.action_digest.root)
    check(late.status_code == 409, f"a resolution after the withdrawal answered {late.status_code}, not 409")
    _refused(creator.get_resumption(approval_id), 409, "the resumption of a withdrawn pending approval")


def flow_expiry(mock: Mock) -> None:
    """A Resumption whose time has passed on the mock's clock fails as `expired`; the clock is moved with
    `/__mock/advance`, and `now` is what the mock says it is, not the machine's."""
    creator = mock.client("creator")
    arguments = _unique_arguments()
    decision = _open_approval(mock, arguments)
    assert decision.approval is not None
    approval_id = decision.approval.id
    check(_resolve(mock, approval_id, decision.action_digest.root).status_code == 200, "the resolution was refused")
    resumption = _ok(creator.get_resumption(approval_id), "the resumption of an approved approval")
    jwks = creator.jwks()
    expected = ExpectedAction.for_call(EXTERNAL_TOOL, arguments)
    before = mock.advance(0)
    verify_resumption(resumption.signature, jwks, expected, replay_guard=None, now=before)
    after = mock.advance(2 * 60 * 60)
    try:
        verify_resumption(resumption.signature, jwks, expected, replay_guard=None, now=after)
    except ResumptionError as error:
        check(error.code == "expired", f"an expired Resumption failed as {error.code}")
    else:
        raise AssertionError("a Resumption was accepted after the mock's clock passed its expiry")


def flow_no_self_approval(mock: Mock) -> None:
    """The user who asked cannot approve their own request: the mock answers 403 `not_eligible`."""
    arguments = _unique_arguments()
    mine = mock.client("creator_user")
    decision = _ok(mine.decide({"action": {"tool_ref": EXTERNAL_TOOL, "arguments": arguments}}), "decide as a user")
    check(decision.approval is not None, "a step_up decision carries an approval handle")
    assert decision.approval is not None
    answer = _resolve(mock, decision.approval.id, decision.action_digest.root, who="creator_user")
    check(answer.status_code == 403, f"a user approved their own request: {answer.status_code}")


def flow_credentials(mock: Mock) -> None:
    """The mock refuses a token it should not accept: forged, expired, for another audience, and none at all."""
    for who in ("forged", "expired", "wrong_audience"):
        _refused(mock.client(who).capabilities(), 401, f"a {who} token")
    bare = httpx.get(f"{mock.base_url}/v1/capabilities")
    check(bare.status_code == 401, f"a request with no token answered {bare.status_code}")


def decide_digest(mock: Mock, arguments_text: str) -> tuple[int, str | None, str]:
    """POSTs `arguments_text` (JSON, written by the test) as the arguments of a decision on an unknown tool. The mock
    digests the arguments with TypeScript (`argDigest` from `@noblecloak/client`) and answers `action_digest` on every
    decision, including `deny unknown_tool`, which opens no approval. Returns the status, that digest (None when the
    mock did not answer 200) and the response's `type` (the problem type of a refusal, else empty)."""
    response = httpx.post(
        f"{mock.base_url}/v1/decisions",
        content=f'{{"action":{{"tool_ref":"{UNKNOWN_TOOL}","arguments":{arguments_text}}}}}'.encode("ascii"),
        headers={"authorization": f"Bearer {mock.tokens['creator']}", "content-type": "application/json"},
    )
    if response.status_code != 200:
        try:
            problem_type = str(response.json().get("type", ""))
        except ValueError:
            problem_type = ""
        return response.status_code, None, problem_type
    return 200, response.json()["data"]["action_digest"], ""


def differential_check(mock: Mock, arguments: dict[str, Any]) -> None:
    """Python and TypeScript agree on `arguments`: the same digest, or both refuse. The JSON is written with
    `ensure_ascii`, so a lone surrogate reaches the mock as the escape `\\ud800`, which TypeScript parses."""
    text = json.dumps(arguments, allow_nan=False, ensure_ascii=True, separators=(",", ":"))
    status, theirs, problem_type = decide_digest(mock, text)
    try:
        ours: str | None = arg_digest(arguments)
    except DigestError:
        ours = None
    if ours is None:
        # The mock's refusal is a generic 500 `internal_error`; that it is `argDigest` refusing and not some other
        # crash is pinned for the kinds of input Python refuses by `test_the_mocks_500_is_argdigest_refusing`.
        check(
            status == 500 and problem_type.endswith("/internal_error"),
            f"Python refuses {text[:120]}, the mock answered {status} {problem_type or 'with digest ' + str(theirs)}",
        )
    else:
        check(theirs == ours, f"Python digests {text[:120]} as {ours}, the mock as {theirs} (status {status})")
