"""End to end against the pinned `nc-mock` (`-m e2e`, see `e2e_support.py`), and the proof that these flows can fail:
each `--break` the mock offers that one of them guards is switched on, and the flow must go red.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from e2e_support import (
    Mock,
    check,
    flow_approve_and_consume,
    flow_credentials,
    flow_expiry,
    flow_no_self_approval,
    flow_withdrawn_has_no_resumption,
    spawn_mock,
)
from noblecloak.resumption import ResumptionError

pytestmark = pytest.mark.e2e

Flow = Callable[[Mock], None]

FLOWS: dict[str, Flow] = {
    "approve_and_consume": flow_approve_and_consume,
    "withdrawn_has_no_resumption": flow_withdrawn_has_no_resumption,
    "expiry": flow_expiry,
    "no_self_approval": flow_no_self_approval,
    "credentials": flow_credentials,
}

# break -> the flow that must fail with it. A flow that goes red for some other reason (the mock not starting, a
# connection error) does not count: only a failed `check` or a Resumption the verifier refuses does.
BREAKS: dict[str, Flow] = {
    "allow_token_replay": flow_approve_and_consume,
    "sign_unlisted_key": flow_approve_and_consume,
    "unbound_resumption_signature": flow_approve_and_consume,
    "consume_ignores_action": flow_approve_and_consume,
    "external_tool_no_resume_token": flow_approve_and_consume,
    "ignore_stale_digest": flow_approve_and_consume,
    "digest_not_jcs": flow_approve_and_consume,
    "resumption_after_withdraw": flow_withdrawn_has_no_resumption,
    "allow_service_resolve": flow_approve_and_consume,
    "resumption_open_to_approver": flow_approve_and_consume,
    "withdraw_by_anyone": flow_withdrawn_has_no_resumption,
    "allow_creator_self_resolve": flow_no_self_approval,
    "accept_forged_signature": flow_credentials,
    "accept_expired_token": flow_credentials,
    "ignore_audience": flow_credentials,
    "accept_missing_token": flow_credentials,
}


@pytest.mark.parametrize("flow", FLOWS.values(), ids=FLOWS.keys())
def test_the_flow_passes_against_the_mock(mock: Mock, flow: Flow) -> None:
    flow(mock)


@pytest.mark.parametrize("name", BREAKS)
def test_a_break_turns_its_flow_red(name: str) -> None:
    with spawn_mock(name) as broken, pytest.raises((AssertionError, ResumptionError)):
        BREAKS[name](broken)


def test_an_unknown_break_stops_the_mock_from_starting() -> None:
    # `--break` with a name the mock does not know exits 2, so a misspelt name above fails loudly instead of leaving a
    # flow to "pass" against an unbroken mock.
    with pytest.raises(RuntimeError, match="did not start"), spawn_mock("no_such_break"):
        pass


def test_check_raises_an_assertion_error() -> None:
    check(True, "unused")
    with pytest.raises(AssertionError, match="why"):
        check(False, "why")
