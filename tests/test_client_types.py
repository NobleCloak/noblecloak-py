"""noblecloak.client.types: `is_transient` and `is_transient_status` (the cases of `governance-api.test.ts`)."""

from __future__ import annotations

from typing import Any

import pytest

from noblecloak import client
from noblecloak.client import DpopRequest, ModuleApiError, Ok, Problem, is_transient, is_transient_status


def test_a_dpop_request_does_not_show_its_access_token_in_its_repr() -> None:
    request = DpopRequest(method="GET", url="https://x.test/v1", access_token="SECRET-TOKEN")
    assert "SECRET-TOKEN" not in repr(request)
    assert "SECRET-TOKEN" not in str(request)
    assert request.access_token == "SECRET-TOKEN"


@pytest.mark.parametrize(
    ("status", "transient"),
    [
        (200, False),
        (302, False),
        (400, False),
        (403, False),
        (404, False),
        (407, False),
        (408, True),
        (409, False),
        (429, True),
        (499, False),
        (500, True),
        (502, True),
        (503, True),
        (599, True),
    ],
)
def test_a_status_is_transient_when_it_is_5xx_408_or_429(status: int, transient: bool) -> None:
    assert is_transient_status(status) is transient


def test_reads_a_bare_problem_and_rejects_things_that_are_not_answers_or_api_errors() -> None:
    assert is_transient(Problem(429, "x")) is True
    assert is_transient(Problem(404, "x")) is False
    assert is_transient(Problem(500, "x")) is True
    assert is_transient(Problem(499, "x")) is False
    assert is_transient(Problem(599, "x", "detail")) is True
    assert is_transient(Ok(1)) is False
    assert is_transient(Ok(Problem(503, "x"))) is False
    assert is_transient(Exception("boom")) is False
    assert is_transient(ConnectionError("fetch failed")) is False
    assert is_transient(TimeoutError()) is False
    assert is_transient(None) is False
    assert is_transient("429") is False
    assert is_transient(429) is False
    assert is_transient([]) is False
    assert is_transient({"status": 503}) is False


def test_an_exception_that_carries_a_status_is_not_a_problem() -> None:
    error = Exception("boom")
    error.status = 503  # type: ignore[attr-defined]  # pyright: ignore[reportAttributeAccessIssue]
    assert is_transient(error) is False


def test_every_module_api_error_is_transient() -> None:
    assert is_transient(ModuleApiError("unreachable", "x")) is True


def test_reads_an_unreachable_module_api_error_from_another_copy_of_the_package_by_name_and_code() -> None:
    def foreign(name: str, code: Any) -> Exception:
        copy = type(name, (Exception,), {})("unreachable")
        copy.code = code  # type: ignore[attr-defined]  # pyright: ignore[reportAttributeAccessIssue]
        return copy

    copy = foreign("ModuleApiError", "unreachable")
    assert not isinstance(copy, ModuleApiError)
    assert is_transient(copy) is True
    assert is_transient(foreign("ModuleApiError", "other")) is False
    assert is_transient(foreign("SomeOtherError", "unreachable")) is False
    assert is_transient(type("ModuleApiError", (Exception,), {})("no code")) is False


def test_sets_the_name_the_cross_copy_check_reads() -> None:
    assert type(ModuleApiError("unreachable", "x")).__name__ == "ModuleApiError"


def test_the_package_exports_what_it_lists() -> None:
    assert all(hasattr(client, name) for name in client.__all__)
    assert client.ModuleClient.__module__ == "noblecloak.client._sync.client"
    assert client.AsyncModuleClient.__module__ == "noblecloak.client._async.client"
