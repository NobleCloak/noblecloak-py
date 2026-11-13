"""noblecloak.resumption replay guards: `InMemoryReplayGuard` and `ForgettingReplayGuard`."""

from __future__ import annotations

import contextlib
import threading
import time
from datetime import UTC, datetime, timedelta

import pytest

from noblecloak.resumption import ForgettingReplayGuard, InMemoryReplayGuard, ReplayGuard, ResumptionError

T0 = datetime(2026, 10, 4, 12, 0, 0, tzinfo=UTC)


class Clock:
    def __init__(self, at: datetime = T0) -> None:
        self.at = at

    def __call__(self) -> datetime:
        return self.at


def test_the_first_use_of_a_key_is_fresh_and_the_second_is_not() -> None:
    guard = InMemoryReplayGuard(Clock())
    assert guard.first_use("a", T0 + timedelta(minutes=5)) is True
    assert guard.first_use("a", T0 + timedelta(minutes=5)) is False
    assert guard.first_use("b", T0 + timedelta(minutes=5)) is True


def test_a_key_is_forgotten_once_it_expires_and_not_before() -> None:
    clock = Clock()
    guard = InMemoryReplayGuard(clock)
    expires = T0 + timedelta(minutes=5)
    assert guard.first_use("a", expires) is True
    clock.at = expires - timedelta(microseconds=1)
    assert guard.first_use("a", expires) is False
    clock.at = expires  # `until <= now` forgets it, as the TypeScript guard does
    assert guard.first_use("a", expires + timedelta(minutes=5)) is True


def test_a_replayed_key_does_not_extend_its_own_life() -> None:
    clock = Clock()
    guard = InMemoryReplayGuard(clock)
    assert guard.first_use("a", T0 + timedelta(minutes=5)) is True
    assert guard.first_use("a", T0 + timedelta(days=9)) is False
    clock.at = T0 + timedelta(minutes=5)
    assert guard.first_use("a", T0 + timedelta(minutes=10)) is True


def test_the_default_clock_is_the_current_time() -> None:
    guard = InMemoryReplayGuard()
    assert guard.first_use("a", datetime.now(UTC) + timedelta(minutes=5)) is True
    assert guard.first_use("a", datetime.now(UTC) + timedelta(minutes=5)) is False


def test_a_key_already_expired_by_the_guards_clock_is_refused_and_not_recorded() -> None:
    guard = InMemoryReplayGuard(Clock())
    for expires in (T0 - timedelta(minutes=5), T0):  # `expires_at <= now` is expired
        with pytest.raises(ResumptionError) as caught:
            guard.first_use("gone", expires)
        assert caught.value.code == "expired"
    assert guard.first_use("gone", T0 + timedelta(minutes=5)) is True  # nothing was recorded by the refusals


def test_a_naive_expiry_is_refused() -> None:
    with pytest.raises(ValueError, match="timezone"):
        InMemoryReplayGuard(Clock()).first_use("a", datetime(2026, 10, 4, 12, 0, 0))


def test_a_non_string_key_is_refused() -> None:
    with pytest.raises(TypeError):
        InMemoryReplayGuard(Clock()).first_use(1, T0 + timedelta(minutes=5))  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]


def test_exactly_one_of_many_concurrent_callers_gets_the_key() -> None:
    guard = InMemoryReplayGuard(Clock())
    expires = T0 + timedelta(hours=1)
    threads = 32
    rounds = 200
    barrier = threading.Barrier(threads)
    wins: list[int] = [0] * threads

    def run(index: int) -> None:
        for round_number in range(rounds):
            barrier.wait()
            if guard.first_use(f"key-{round_number}", expires):
                wins[index] += 1

    workers = [threading.Thread(target=run, args=(i,)) for i in range(threads)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    assert sum(wins) == rounds


class _SlowLookupDict(dict[str, datetime]):
    """A `_seen` whose membership test yields the GIL after answering, so a guard that looks up and inserts in two
    separate steps lets every other thread in between."""

    def __contains__(self, key: object) -> bool:
        answer = super().__contains__(key)
        time.sleep(0.02)
        return answer


def test_the_lookup_and_the_insert_are_one_step() -> None:
    """Forces the interleaving: without the lock all eight threads see the key absent and all are granted it."""
    guard = InMemoryReplayGuard(Clock())
    guard._seen = _SlowLookupDict()  # pyright: ignore[reportPrivateUsage]
    expires = T0 + timedelta(hours=1)
    results: list[bool] = []

    workers = [threading.Thread(target=lambda: results.append(guard.first_use("k", expires))) for _ in range(8)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    assert results.count(True) == 1
    assert len(results) == 8


def test_the_guard_holds_while_other_threads_sweep_expired_keys() -> None:
    """Sweeping deletes from the dict while others insert; without the lock this raises or double-grants."""
    clock = Clock()
    guard = InMemoryReplayGuard(clock)
    stop = threading.Event()
    errors: list[BaseException] = []

    def churn() -> None:
        index = 0
        try:
            while not stop.is_set():
                with contextlib.suppress(ResumptionError):  # the clock passed this short-lived key; not under test
                    guard.first_use(f"churn-{index}", clock.at + timedelta(microseconds=1))
                index += 1
        except BaseException as error:
            errors.append(error)

    workers = [threading.Thread(target=churn) for _ in range(4)]
    for worker in workers:
        worker.start()
    grants = 0
    for round_number in range(300):
        clock.at = clock.at + timedelta(microseconds=2)
        if guard.first_use(f"real-{round_number}", clock.at + timedelta(hours=1)):
            grants += 1
        if guard.first_use(f"real-{round_number}", clock.at + timedelta(hours=1)):
            grants += 1
    stop.set()
    for worker in workers:
        worker.join()
    assert errors == []
    assert grants == 300


def test_forget_lets_a_key_be_used_again() -> None:
    guard = ForgettingReplayGuard(Clock())
    expires = T0 + timedelta(minutes=5)
    assert guard.first_use("a", expires) is True
    assert guard.first_use("a", expires) is False
    guard.forget("a")
    assert guard.first_use("a", expires) is True
    guard.forget("never-seen")  # forgetting a key that is not there is not an error


def test_forget_only_forgets_the_named_key() -> None:
    guard = ForgettingReplayGuard(Clock())
    expires = T0 + timedelta(minutes=5)
    guard.first_use("a", expires)
    guard.first_use("b", expires)
    guard.forget("a")
    assert guard.first_use("b", expires) is False


def test_both_guards_satisfy_the_replay_guard_protocol() -> None:
    guards: list[ReplayGuard] = [InMemoryReplayGuard(), ForgettingReplayGuard()]
    assert [g.first_use("k", datetime.now(UTC) + timedelta(minutes=1)) for g in guards] == [True, True]
