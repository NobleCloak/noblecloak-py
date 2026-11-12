"""noblecloak.client: the operations, the answers and `unreachable`.

The cases of `governance-api.test.ts` (client 0.13.0) run against both clients (but for the ones about an abort
`signal` and a stream answer with no body, which have no Python counterpart), then the cases Python adds: responses
are validated as the spec's models, an id cannot add a path segment, the arguments of an operation are checked before
anything is sent, a body that is not JSON.
"""

from __future__ import annotations

import pickle
import traceback
from collections.abc import AsyncIterator, Callable, Iterator
from types import MappingProxyType
from typing import Any

import httpx
import pytest

from client_support import (
    APPROVAL,
    BASE,
    CAPABILITIES,
    CONSUMED,
    DECISION,
    RECORD,
    RESUMPTION,
    RUN,
    Rig,
    ok,
    problem,
    status,
)
from noblecloak.client import (
    Answer,
    ApprovalsPage,
    ModuleApiError,
    Ok,
    Problem,
    is_transient,
)
from noblecloak.models import (
    Action,
    Approval,
    ApprovalState,
    Capabilities,
    ConsumeResult,
    Decision,
    DecisionRequest,
    DecisionValue,
    Record,
    RecordCreate,
    Resumption,
    Run,
)


@pytest.fixture(params=["sync", "async"])
def kind(request: pytest.FixtureRequest) -> str:
    return str(request.param)


def by_path(request: httpx.Request) -> httpx.Response:
    """The right body for each route, for a case that calls every operation."""
    path = request.url.path
    bodies: dict[str, Any] = {
        "/v1/capabilities": CAPABILITIES,
        "/v1/runs": RUN,
        "/v1/decisions": DECISION,
        "/v1/approvals/a1": APPROVAL,
        "/v1/approvals/a1/wait": APPROVAL,
        "/v1/approvals/a1/resumption": RESUMPTION,
        "/v1/approvals/a1/consume": CONSUMED,
        "/v1/approvals/a1/withdraw": APPROVAL,
        "/v1/records": RECORD,
        "/v1/approvals": [APPROVAL],
    }
    return ok(bodies[path])


# --- requests -----------------------------------------------------------------------------------------


def test_sends_each_operation_as_the_module_api_specifies_with_the_bearer_token(kind: str) -> None:
    rig = Rig(kind, by_path)
    rig.call("capabilities")
    rig.call("create_run", "key-1")
    rig.call("decide", {"action": {"tool_ref": "t", "arg_digest": "d"}})
    rig.call("get_approval", "a1")
    rig.call("wait_approval", "a1", 25)
    rig.call("get_resumption", "a1")
    rig.call("consume", "a1", "rt", "tool:x", {"q": 1})
    rig.call("withdraw", "a1")
    rig.call("append_record", {"tool_ref": "t"}, "key-2")
    rig.call("list_approvals", "pending", "c1")

    assert [f"{s.method} {s.url.path}{'?' + s.url.query.decode() if s.url.query else ''}" for s in rig.seen] == [
        "GET /v1/capabilities",
        "POST /v1/runs",
        "POST /v1/decisions",
        "GET /v1/approvals/a1",
        "GET /v1/approvals/a1/wait?timeout=25",
        "GET /v1/approvals/a1/resumption",
        "POST /v1/approvals/a1/consume",
        "POST /v1/approvals/a1/withdraw",
        "POST /v1/records",
        "GET /v1/approvals?state=pending&created_by=me&cursor=c1",
    ]
    assert all(s.headers["authorization"] == "Bearer tok" for s in rig.seen)
    assert rig.seen[1].headers["idempotency-key"] == "key-1"
    assert rig.seen[1].body == b'{"kind":"external"}'
    assert rig.seen[6].body == b'{"resume_token":"rt","action":{"tool_ref":"tool:x","arguments":{"q":1}}}'
    assert rig.seen[8].headers["idempotency-key"] == "key-2"
    assert "idempotency-key" not in rig.seen[2].headers


def test_asks_for_the_approvals_of_this_principal_only_whatever_the_state(kind: str) -> None:
    rig = Rig(kind, lambda _r: ok([], next=None))
    rig.call("list_approvals", "pending")
    rig.call("list_approvals", ApprovalState.EXPIRED)
    assert rig.seen[0].url.params["created_by"] == "me"
    assert "cursor" not in rig.seen[0].url.params
    assert rig.seen[1].url.params["state"] == "expired"


def test_a_state_that_is_not_an_approval_state_is_refused_before_anything_is_sent(kind: str) -> None:
    rig = Rig(kind)
    with pytest.raises(ValueError, match="not a valid ApprovalState"):
        rig.call("list_approvals", "done")
    assert rig.seen == []


def test_an_id_cannot_add_a_path_segment_or_a_query(kind: str) -> None:
    rig = Rig(kind, lambda _r: ok(APPROVAL))
    rig.call("get_approval", "a/../../x?y=1#z")
    assert rig.seen[0].url.raw_path == b"/v1/approvals/a%2F..%2F..%2Fx%3Fy%3D1%23z"
    rig.call("get_approval", "é ü")
    assert rig.seen[1].url.raw_path == b"/v1/approvals/%C3%A9%20%C3%BC"


@pytest.mark.parametrize("operation", ["get_approval", "get_resumption", "withdraw", "consume", "wait_approval"])
@pytest.mark.parametrize("dots", [".", ".."])
def test_an_id_of_dots_is_refused_because_httpx_would_resolve_it_into_another_route(
    kind: str, operation: str, dots: str
) -> None:
    rig = Rig(kind)
    args: tuple[Any, ...] = (
        ("rt", "tool:x", {}) if operation == "consume" else (5,) if operation == "wait_approval" else ()
    )
    with pytest.raises(ValueError, match=r"approval_id must not be '\.' or '\.\.'"):
        rig.call(operation, dots, *args)
    assert rig.seen == []
    rig = Rig(kind, lambda _r: ok(APPROVAL))
    rig.call("get_approval", "a..")
    rig.call("get_approval", "...")
    assert [s.url.raw_path for s in rig.seen] == [b"/v1/approvals/a..", b"/v1/approvals/..."]


@pytest.mark.parametrize("operation", ["get_approval", "get_resumption", "withdraw"])
def test_an_empty_id_is_refused(kind: str, operation: str) -> None:
    rig = Rig(kind)
    with pytest.raises(ValueError, match="approval_id must not be empty"):
        rig.call(operation, "")
    with pytest.raises(TypeError, match="approval_id must be a string"):
        rig.call(operation, 7)
    assert rig.seen == []


@pytest.mark.parametrize("bad", ["", "two words", "new\nline", "é", " "])
def test_an_idempotency_key_is_printable_ascii_without_spaces(kind: str, bad: str) -> None:
    rig = Rig(kind)
    with pytest.raises(ValueError, match="idempotency_key must be 1 to 255 characters"):
        rig.call("create_run", bad)
    with pytest.raises(ValueError, match="idempotency_key must be 1 to 255 characters"):
        rig.call("append_record", {"tool_ref": "t"}, bad)
    with pytest.raises(TypeError, match="idempotency_key must be a string"):
        rig.call("create_run", None)
    assert rig.seen == []


def test_an_idempotency_key_may_be_255_characters_and_not_256(kind: str) -> None:
    rig = Rig(kind, lambda r: ok(RUN if r.url.path == "/v1/runs" else RECORD))
    rig.call("create_run", "k" * 255)
    rig.call("append_record", {"tool_ref": "t"}, "k" * 255)
    assert [len(s.headers["idempotency-key"]) for s in rig.seen] == [255, 255]
    with pytest.raises(ValueError, match="idempotency_key must be 1 to 255 characters"):
        rig.call("create_run", "k" * 256)
    with pytest.raises(ValueError, match="idempotency_key must be 1 to 255 characters"):
        rig.call("append_record", {"tool_ref": "t"}, "k" * 256)
    assert len(rig.seen) == 2


@pytest.mark.parametrize(("bad", "error"), [(-1, ValueError), (True, TypeError), (1.5, TypeError), ("5", TypeError)])
def test_a_wait_takes_a_whole_number_of_seconds_from_zero(kind: str, bad: Any, error: type[Exception]) -> None:
    rig = Rig(kind)
    with pytest.raises(error, match="timeout_seconds must"):
        rig.call("wait_approval", "a1", bad)
    assert rig.seen == []


def test_a_wait_of_zero_seconds_is_sent(kind: str) -> None:
    rig = Rig(kind, lambda _r: ok(APPROVAL))
    rig.call("wait_approval", "a1", 0)
    assert rig.seen[0].url.params["timeout"] == "0"


def test_a_model_is_sent_as_what_was_set_on_it_under_its_wire_names(kind: str) -> None:
    rig = Rig(kind, by_path)
    rig.call("decide", DecisionRequest.model_validate({"action": {"tool_ref": "t", "arg_digest": "d" * 64}}))
    rig.call("append_record", RecordCreate.model_validate({"tool_ref": "t", "decision": "allow"}), "k")
    assert rig.seen[0].body == b'{"action":{"tool_ref":"t","arg_digest":"' + b"d" * 64 + b'"}}'
    assert rig.seen[1].body == b'{"tool_ref":"t","decision":"allow"}'


# --- answers ------------------------------------------------------------------------------------------


def test_each_operation_validates_the_data_as_its_model(kind: str) -> None:
    rig = Rig(kind, by_path)
    expected: dict[str, tuple[type, tuple[Any, ...]]] = {
        "capabilities": (Capabilities, ()),
        "get_approval": (Approval, ("a1",)),
        "get_resumption": (Resumption, ("a1",)),
        "withdraw": (Approval, ("a1",)),
        "create_run": (Run, ("k",)),
        "decide": (Decision, ({"action": {"tool_ref": "t"}},)),
        "consume": (ConsumeResult, ("a1", "rt", "t", {})),
        "append_record": (Record, ({"tool_ref": "t"}, "k")),
        "wait_approval": (Approval, ("a1", 1)),
    }
    for name, (model, args) in expected.items():
        answer: Any = rig.call(name, *args)
        assert isinstance(answer, Ok), name
        assert answer.ok is True
        data: object = answer.data  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        assert isinstance(data, model), name


def test_unwraps_data_from_the_envelope(kind: str) -> None:
    rig = Rig(kind, lambda _r: ok(APPROVAL))
    answer = rig.call("get_approval", "a1")
    assert answer == Ok(Approval.model_validate(APPROVAL))
    assert answer.data.id == "a1"
    assert answer.data.state is ApprovalState.PENDING


def test_a_member_the_spec_does_not_know_is_kept(kind: str) -> None:
    rig = Rig(kind, lambda _r: ok({**APPROVAL, "added_later": {"x": 1}}))
    answer = rig.call("get_approval", "a1")
    assert answer.data.model_extra == {"added_later": {"x": 1}}


def test_returns_a_4xx_as_a_problem_whose_code_is_the_last_segment_of_the_type_uri(kind: str) -> None:
    rig = Rig(kind, lambda _r: problem(409, "consume-conflict", "already consumed"))
    answer = rig.call("get_approval", "a1")
    assert answer == Problem(status=409, code="consume-conflict", detail="already consumed")
    assert answer.ok is False


def test_a_body_nested_too_deeply_to_parse_is_unreadable_like_any_other_body_that_is_not_json(kind: str) -> None:
    deep = httpx.Response(200, content=b"[" * 200_000)
    rig = Rig(kind, lambda _r: deep)
    with pytest.raises(ModuleApiError) as raised:
        rig.call("capabilities")
    assert raised.value.code == "unreachable"
    assert is_transient(raised.value)
    rig = Rig(kind, lambda _r: httpx.Response(400, content=b"[" * 200_000))
    assert rig.call("capabilities") == Problem(status=400, code="")


def test_returns_a_problem_without_a_detail_when_the_body_has_none(kind: str) -> None:
    rig = Rig(kind, lambda _r: status(404, "not json shaped"))
    assert rig.call("get_approval", "a1") == Problem(status=404, code="")
    rig = Rig(kind, lambda _r: httpx.Response(404, content=b"<html>not found</html>"))
    assert rig.call("get_approval", "a1") == Problem(status=404, code="")
    rig = Rig(kind, lambda _r: httpx.Response(404))
    assert rig.call("get_approval", "a1") == Problem(status=404, code="")


def test_a_type_or_detail_that_is_not_a_string_is_ignored(kind: str) -> None:
    rig = Rig(kind, lambda _r: status(400, {"type": 7, "detail": ["x"]}))
    assert rig.call("get_approval", "a1") == Problem(status=400, code="")
    rig = Rig(kind, lambda _r: status(400, {"type": "plain_code"}))
    assert rig.call("get_approval", "a1") == Problem(status=400, code="plain_code")


def test_reads_a_list_page_into_rows_and_the_next_cursor(kind: str) -> None:
    rig = Rig(kind, lambda _r: ok([APPROVAL], next="c2"))
    answer = rig.call("list_approvals", "pending")
    assert answer == Ok(ApprovalsPage(rows=[Approval.model_validate(APPROVAL)], next="c2"))


def test_reads_a_page_without_meta_next_as_the_last_page(kind: str) -> None:
    rig = Rig(kind, lambda _r: ok([]))
    assert rig.call("list_approvals", "pending") == Ok(ApprovalsPage(rows=[], next=None))
    rig = Rig(kind, lambda _r: httpx.Response(200, json={"data": []}))
    assert rig.call("list_approvals", "pending") == Ok(ApprovalsPage(rows=[], next=None))
    rig = Rig(kind, lambda _r: httpx.Response(200, json={"data": [], "meta": "x"}))
    assert rig.call("list_approvals", "pending") == Ok(ApprovalsPage(rows=[], next=None))


# --- unreachable --------------------------------------------------------------------------------------


def unreachable(rig: Rig, name: str, *args: Any) -> ModuleApiError:
    with pytest.raises(ModuleApiError) as caught:
        rig.call(name, *args)
    assert caught.value.code == "unreachable"
    return caught.value


def test_a_list_page_whose_data_is_not_an_array_is_unreachable_never_an_empty_page(kind: str) -> None:
    error = unreachable(Rig(kind, lambda _r: ok({"rows": []}, next=None)), "list_approvals", "pending")
    assert str(error) == "/v1 answered an approvals page whose data is not an array"


def test_a_list_page_whose_meta_next_is_neither_a_string_nor_null_is_unreachable(kind: str) -> None:
    error = unreachable(Rig(kind, lambda _r: ok([], next=7)), "list_approvals", "pending")
    assert str(error) == "/v1 answered an approvals page whose meta.next is not a string or null"


def test_a_row_that_is_not_an_approval_makes_the_page_unreachable(kind: str) -> None:
    error = unreachable(Rig(kind, lambda _r: ok([APPROVAL, {"id": "a2"}])), "list_approvals", "pending")
    assert str(error).startswith("/v1 answered data that is not a Approval (at: state, tool_ref")


def test_a_2xx_body_without_a_data_member_is_unreachable(kind: str) -> None:
    error = unreachable(Rig(kind, lambda _r: status(200, {"meta": {}})), "capabilities")
    assert str(error) == "/v1 answered 200 without a data member"


@pytest.mark.parametrize("body", [b"", b"[]", b"null", b'"data"', b"7"])
def test_a_2xx_body_that_is_not_an_envelope_is_unreachable_without_a_data_member(kind: str, body: bytes) -> None:
    error = unreachable(Rig(kind, lambda _r: httpx.Response(200, content=body)), "capabilities")
    assert str(error) == "/v1 answered 200 without a data member"


def test_a_2xx_body_that_is_not_json_is_unreachable(kind: str) -> None:
    error = unreachable(Rig(kind, lambda _r: httpx.Response(200, content=b"<html>")), "capabilities")
    assert str(error) == "/v1 answered 200 with a body that is not JSON"
    error = unreachable(Rig(kind, lambda _r: httpx.Response(200, content=b"\xff\xfe\x00")), "capabilities")
    assert str(error) == "/v1 answered 200 with a body that is not JSON"


def test_data_that_is_not_the_operations_model_is_unreachable_and_says_where_not_what(kind: str) -> None:
    secret = "rt-SECRET-0123456789"
    bad = {**RESUMPTION, "resume_token": {"leaked": secret}, "approver": {"kind": "wizard", "id": secret}}
    error = unreachable(Rig(kind, lambda _r: ok(bad)), "get_resumption", "a1")
    assert str(error) == "/v1 answered data that is not a Resumption (at: approver.kind, resume_token)"
    assert secret not in "".join(traceback.format_exception(error))
    assert error.__cause__ is None
    assert error.__context__ is None  # a ValidationError holds the input; nothing that walks the chain may reach it


def test_every_fault_location_is_named_for_the_first_five_only(kind: str) -> None:
    error = unreachable(Rig(kind, lambda _r: ok({})), "capabilities")
    assert (
        str(error)
        == "/v1 answered data that is not a Capabilities (at: deployment, entitlements, jwks_uri, kids, resolutions)"
    )
    error = unreachable(Rig(kind, lambda _r: ok("a string")), "capabilities")
    assert str(error) == "/v1 answered data that is not a Capabilities (at: (root))"


def test_a_dropped_connection_is_unreachable_and_keeps_its_cause(kind: str) -> None:
    cause = httpx.ConnectError("connection refused")

    def reply(request: httpx.Request) -> httpx.Response:
        raise cause

    error = unreachable(Rig(kind, reply), "capabilities")
    assert str(error) == "/v1 could not be reached: connection refused"
    assert error.__cause__ is cause


def test_an_error_with_no_message_is_named_by_its_class(kind: str) -> None:
    def reply(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("")

    assert str(unreachable(Rig(kind, reply), "capabilities")) == "/v1 could not be reached: ReadTimeout"


def test_the_key_set_and_the_stream_are_unreachable_on_any_non_2xx_status_4xx_included(kind: str) -> None:
    error = unreachable(Rig(kind, lambda _r: status(404)), "jwks")
    assert str(error) == "the key set answered 404"
    with pytest.raises(ModuleApiError) as caught:
        Rig(kind, lambda _r: status(403)).stream()
    assert str(caught.value) == "the approval stream answered 403"
    assert is_transient(caught.value)


def test_the_key_set_must_carry_a_keys_array(kind: str) -> None:
    error = unreachable(Rig(kind, lambda _r: status(200, {"nope": True})), "jwks")
    assert str(error) == "the key set answered 200"
    assert str(unreachable(Rig(kind, lambda _r: status(200, {"keys": "x"})), "jwks")) == "the key set answered 200"
    assert str(unreachable(Rig(kind, lambda _r: status(200, [])), "jwks")) == "the key set answered 200"
    assert Rig(kind, lambda _r: status(200, {"keys": []})).call("jwks") == {"keys": []}


def test_the_key_set_is_the_dict_verify_resumption_takes_and_is_read_with_the_token(kind: str) -> None:
    keys = {"keys": [{"kty": "EC", "kid": "k1"}], "extra": 1}
    rig = Rig(kind, lambda _r: status(200, keys))
    assert rig.call("jwks") == keys
    assert str(rig.seen[0].url) == f"{BASE}/.well-known/jwks.json"
    assert rig.seen[0].headers["authorization"] == "Bearer tok"


def test_a_key_set_that_is_not_json_is_unreachable_with_the_reason(kind: str) -> None:
    error = unreachable(Rig(kind, lambda _r: httpx.Response(200, content=b"<html>")), "jwks")
    assert str(error).startswith("the key set could not be read: ")
    assert isinstance(error.__cause__, ValueError)
    # An error page that is not JSON is an answer of its status, as for any operation.
    assert (
        str(unreachable(Rig(kind, lambda _r: httpx.Response(502, content=b"<html>")), "jwks"))
        == "the key set answered 502"
    )


def test_opens_the_approval_stream_as_the_raw_body_and_asks_for_this_principals_approvals(kind: str) -> None:
    frames = [b"event: approval.updated\n", b'data: {"id":"a1"}\n\n']
    rig = Rig(
        kind, lambda _r: httpx.Response(200, content=b"".join(frames), headers={"content-type": "text/event-stream"})
    )
    assert b"".join(rig.stream()) == b"".join(frames)
    assert rig.seen[0].url.query == b"created_by=me"
    assert str(rig.seen[0].url.copy_with(query=None)) == f"{BASE}/v1/approvals/stream"
    assert rig.seen[0].headers["authorization"] == "Bearer tok"


def test_a_network_failure_opening_the_key_set_or_the_stream_is_unreachable(kind: str) -> None:
    def reply(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    assert str(unreachable(Rig(kind, reply), "jwks")) == "the key set could not be read: down"
    with pytest.raises(ModuleApiError) as caught:
        Rig(kind, reply).stream()
    assert str(caught.value) == "the approval stream could not be opened: down"
    assert isinstance(caught.value.__cause__, httpx.ConnectError)


def test_the_stream_is_closed_when_the_block_ends_and_when_it_fails_to_open(kind: str) -> None:
    closed: list[str] = []

    class Body(httpx.SyncByteStream, httpx.AsyncByteStream):
        def __iter__(self) -> Iterator[bytes]:
            yield b"x"
            yield b"y"

        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b"x"
            yield b"y"

        def close(self) -> None:
            closed.append("body")

        async def aclose(self) -> None:
            closed.append("body")

    rig = Rig(kind, lambda _r: httpx.Response(200, stream=Body()))
    rig.stream()
    assert closed == ["body"]
    closed.clear()
    assert rig.stream(first_only=True) == [b"x"]  # leaving the block closes a body that was not read to its end
    assert closed == ["body"]
    closed.clear()
    rig = Rig(kind, lambda _r: httpx.Response(500, stream=Body()))
    with pytest.raises(ModuleApiError):
        rig.stream()
    assert closed == ["body"]


# --- transient classification, one case per status ----------------------------------------------------


@pytest.mark.parametrize("code", [500, 502, 503])
def test_a_5xx_raises_unreachable_which_is_transient(kind: str, code: int) -> None:
    error = unreachable(Rig(kind, lambda _r: status(code)), "capabilities")
    assert str(error) == f"/v1 answered {code}"
    assert is_transient(error) is True


@pytest.mark.parametrize("code", [408, 429])
def test_a_408_or_429_comes_back_as_a_problem_and_is_transient(kind: str, code: int) -> None:
    answer = Rig(kind, lambda _r: problem(code, "slow-down")).call("capabilities")
    assert isinstance(answer, Problem)
    assert answer.status == code
    assert is_transient(answer) is True


@pytest.mark.parametrize("code", [400, 403, 409])
def test_other_4xx_are_not_transient(kind: str, code: int) -> None:
    answer = Rig(kind, lambda _r: problem(code, "refused")).call("capabilities")
    assert answer.status == code
    assert is_transient(answer) is False


def test_a_dropped_connection_is_transient_and_a_success_is_not(kind: str) -> None:
    def reply(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("fetch failed")

    assert is_transient(unreachable(Rig(kind, reply), "capabilities")) is True
    assert is_transient(Rig(kind, lambda _r: ok(CAPABILITIES)).call("capabilities")) is False


# --- is_pass_through ----------------------------------------------------------------------------------


class Principal(Exception):
    pass


def failing(kind: str, error: Exception, is_pass_through: Callable[[Exception], bool] | None = None) -> Rig:
    def refuse() -> str:
        raise error

    return Rig(kind, get_token=refuse, is_pass_through=is_pass_through)


def test_rethrows_an_error_the_predicate_accepts_unwrapped_from_every_operation_that_can_fail_on_the_token(
    kind: str,
) -> None:
    error = Principal("wrong principal")
    rig = failing(kind, error, is_pass_through=lambda e: isinstance(e, Principal))
    for name, args in [("capabilities", ()), ("jwks", ()), ("get_approval", ("a1",)), ("list_approvals", ("pending",))]:
        with pytest.raises(Principal) as caught:
            rig.call(name, *args)
        assert caught.value is error, name
    with pytest.raises(Principal) as caught:
        rig.stream()
    assert caught.value is error
    assert rig.seen == []


def test_wraps_any_other_error_from_get_token_as_unreachable(kind: str) -> None:
    rig = failing(kind, RuntimeError("token endpoint down"), is_pass_through=lambda e: isinstance(e, Principal))
    error = unreachable(rig, "capabilities")
    assert str(error) == "/v1 could not be reached: token endpoint down"
    assert unreachable(rig, "jwks").code == "unreachable"
    with pytest.raises(ModuleApiError):
        rig.stream()


def test_wraps_every_error_when_no_predicate_is_given(kind: str) -> None:
    assert unreachable(failing(kind, Principal("x")), "capabilities").code == "unreachable"


def test_a_caller_mistake_is_raised_as_itself_even_when_a_predicate_accepts_nothing(kind: str) -> None:
    rig = Rig(kind, get_token=lambda: "", is_pass_through=lambda _e: False)
    with pytest.raises(TypeError, match="get_token must return"):
        rig.call("jwks")
    with pytest.raises(TypeError, match="get_token must return"):
        rig.stream()


# --- the error and the answers ------------------------------------------------------------------------


def test_module_api_error_pickles_with_its_code_and_message() -> None:
    error = pickle.loads(pickle.dumps(ModuleApiError("unreachable", "/v1 answered 503")))
    assert isinstance(error, ModuleApiError)
    assert (error.code, str(error)) == ("unreachable", "/v1 answered 503")


def test_ok_and_problem_are_frozen_values_that_can_be_matched() -> None:
    answers: list[Answer[int]] = [Ok(1), Problem(409, "c", "d")]
    seen: list[str] = []
    for answer in answers:
        match answer:
            case Ok(data=value):
                seen.append(f"ok {value}")
            case Problem(status=code, code=name, detail=text):
                seen.append(f"problem {code} {name} {text}")
    assert seen == ["ok 1", "problem 409 c d"]
    with pytest.raises(AttributeError):
        Ok(1).data = 2  # pyright: ignore[reportAttributeAccessIssue]
    assert Ok(1) == Ok(1)
    assert Ok(1) != Problem(500, "")


# --- a request body: None model fields, Mappings and models inside them ------------------------------


def _decision_request(**members: Any) -> DecisionRequest:
    return DecisionRequest(action=Action.model_validate({"tool_ref": "tool:x", "arguments": {"n": None}}), **members)


def test_a_none_model_field_is_left_out_of_a_typed_operations_body(kind: str) -> None:
    rig = Rig(kind, lambda r: ok(RECORD if r.url.path == "/v1/records" else DECISION))
    rig.call("decide", _decision_request(actor=None, context=None))
    rig.call("append_record", RecordCreate(tool_ref="t", decision=DecisionValue.ALLOW, approval_id=None), "k")
    assert rig.seen[0].body == b'{"action":{"tool_ref":"tool:x","arguments":{"n":null}}}'
    assert b"null" not in rig.seen[1].body
    assert b"approval_id" not in rig.seen[1].body


def test_a_none_in_a_dict_or_a_list_is_a_value_and_is_sent(kind: str) -> None:
    rig = Rig(kind, lambda _r: ok(CONSUMED))
    rig.call("consume", "a1", "rt", "tool:x", {"n": None, "l": [None]})
    assert rig.seen[0].body == b'{"resume_token":"rt","action":{"tool_ref":"tool:x","arguments":{"n":null,"l":[null]}}}'


def test_request_sends_a_none_model_field_as_null(kind: str) -> None:
    rig = Rig(kind)
    rig.call("request", "POST", "/v1/decisions", json=_decision_request(actor=None))
    assert rig.seen[0].body == b'{"actor":null,"action":{"tool_ref":"tool:x","arguments":{"n":null}}}'


def test_a_mapping_that_is_not_a_dict_and_a_model_inside_a_dict_are_accepted_as_a_body(kind: str) -> None:
    rig = Rig(kind, lambda r: ok(DECISION if r.url.path == "/v1/decisions" else CONSUMED))
    rig.call("consume", "a1", "rt", "tool:x", MappingProxyType({"x": 1, "t": (1, 2)}))
    action = Action.model_validate({"tool_ref": "tool:x", "arguments": {}})
    rig.call("decide", {"action": action, "list": [action], "none": None})
    assert rig.seen[0].body == b'{"resume_token":"rt","action":{"tool_ref":"tool:x","arguments":{"x":1,"t":[1,2]}}}'
    assert rig.seen[1].body == (
        b'{"action":{"tool_ref":"tool:x","arguments":{}},"list":[{"tool_ref":"tool:x","arguments":{}}],"none":null}'
    )


def test_a_body_that_contains_itself_is_a_value_error_and_nothing_is_sent(kind: str) -> None:
    loop: dict[str, Any] = {}
    loop["me"] = loop
    rig = Rig(kind)
    with pytest.raises(ValueError, match="contain itself"):
        rig.call("decide", loop)
    assert rig.seen == []


# --- a 5xx keeps what its body says -----------------------------------------------------------------------


def test_a_5xx_carries_the_problem_and_the_request_id_from_its_body(kind: str) -> None:
    body = {
        "type": f"{BASE}/problems/upstream_unavailable",
        "title": "x",
        "status": 503,
        "detail": "policy store timed out",
        "request_id": "req_123",
    }
    error = unreachable(Rig(kind, lambda _r: status(503, body)), "capabilities")
    assert str(error) == "/v1 answered 503 (upstream_unavailable, request_id req_123)"
    assert "policy store" not in repr(error)
    assert error.problem == Problem(503, "upstream_unavailable", "policy store timed out")
    assert error.request_id == "req_123"
    assert is_transient(error) is True


def test_a_5xx_message_keeps_the_detail_out_and_replaces_control_characters(kind: str) -> None:
    body = {"type": "t/bo\u202eom", "detail": "a\nb\x1b[31m" + "z" * 500, "request_id": "r\n1\u2028" + "q" * 300}
    error = unreachable(Rig(kind, lambda _r: status(500, body)), "capabilities")
    message = str(error)
    for character in ("\n", "\x1b", "\u2028", "\u202e"):
        assert character not in message
    assert "z" not in message
    assert "zzz" not in repr(error)
    assert message == "/v1 answered 500 (bo om, request_id " + ("r 1 " + "q" * 300)[:200] + ")"
    assert error.problem is not None
    assert error.problem.detail is not None
    assert len(error.problem.detail) > 500  # the attribute is what the server said


@pytest.mark.parametrize(
    "body", [b"", b"<html>", b"[1]", b'{"detail": 5, "request_id": 7, "type": 3}', b'{"request_id": ""}']
)
def test_a_5xx_without_a_readable_problem_keeps_the_bare_message(kind: str, body: bytes) -> None:
    error = unreachable(Rig(kind, lambda _r: httpx.Response(502, content=body)), "capabilities")
    assert str(error) == "/v1 answered 502"
    assert error.problem == Problem(502, "")
    assert error.request_id is None


def test_module_api_error_pickles_its_problem_and_request_id() -> None:
    error = ModuleApiError("unreachable", "m", problem=Problem(503, "c", "d"), request_id="r1")
    again = pickle.loads(pickle.dumps(error))
    assert (again.problem, again.request_id, str(again)) == (Problem(503, "c", "d"), "r1", "m")
