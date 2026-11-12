"""The synchronous sources are generated from the asynchronous ones (`scripts/generate_sync.py`, `unasync`).

These fail locally the way `generate_sync.py --check` fails in CI: when a generated file is not what the generator
writes from its async source, because someone edited the generated file or forgot to regenerate it.
"""

from __future__ import annotations

import ast
from dataclasses import replace
from pathlib import Path

import pytest

import generate_sync
from generate_sync import Unit

CLASSES = {generate_sync.TOKEN: ["TokenSource"], generate_sync.CLIENT: ["ModuleClient"]}


@pytest.fixture(params=generate_sync.UNITS, ids=lambda unit: unit.target.name)
def unit(request: pytest.FixtureRequest) -> Unit:
    return request.param


def test_the_checked_in_sync_sources_are_what_the_generator_writes(unit: Unit) -> None:
    assert unit.target.read_text(encoding="utf-8") == generate_sync.generate(unit)
    assert generate_sync.main(["--check"]) == 0


def test_there_is_a_unit_for_each_async_source() -> None:
    sources = {
        path.relative_to(generate_sync.PACKAGE).as_posix() for path in generate_sync.PACKAGE.rglob("_async/*.py")
    }
    wanted = {unit.source.relative_to(generate_sync.PACKAGE).as_posix() for unit in generate_sync.UNITS}
    assert sources - {"service_principal/_async/__init__.py", "client/_async/__init__.py"} == wanted


def test_a_generated_file_says_not_to_edit_it_and_holds_no_async_code(unit: Unit) -> None:
    text = unit.target.read_text(encoding="utf-8")
    assert text.startswith("# GENERATED FILE. DO NOT EDIT BY HAND.\n")
    assert f"# Generated from {unit.source.relative_to(generate_sync.PACKAGE).as_posix()} by" in text
    tree = ast.parse(text)
    nodes = list(ast.walk(tree))
    assert not [n for n in nodes if isinstance(n, ast.AsyncFunctionDef | ast.Await | ast.AsyncWith | ast.AsyncFor)]
    names = {n.id for n in nodes if isinstance(n, ast.Name)} | {n.attr for n in nodes if isinstance(n, ast.Attribute)}
    assert not {name for name in names if "async" in name.lower() or name in ("aiter_raw", "aiter_bytes", "aclose")}
    assert [n.name for n in nodes if isinstance(n, ast.ClassDef)] == CLASSES[unit]


def test_a_hand_edit_of_a_generated_file_fails_the_check(
    unit: Unit, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    edited = tmp_path / "edited.py"
    edited.write_text(generate_sync.generate(unit) + "# a hand edit\n", encoding="utf-8")
    monkeypatch.setattr(generate_sync, "UNITS", (replace(unit, target=edited),))
    assert generate_sync.main(["--check"]) == 1
    assert "is not what scripts/generate_sync.py writes" in capsys.readouterr().err


def test_a_missing_generated_file_fails_the_check(unit: Unit, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(generate_sync, "UNITS", (replace(unit, target=tmp_path / "_sync" / "gone.py"),))
    assert generate_sync.main(["--check"]) == 1


def test_one_stale_file_fails_the_check_whichever_unit_it_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    stale = tmp_path / "client.py"
    stale.write_text("# stale\n", encoding="utf-8")
    monkeypatch.setattr(
        generate_sync,
        "UNITS",
        (generate_sync.TOKEN, replace(generate_sync.CLIENT, target=stale)),
    )
    assert generate_sync.main(["--check"]) == 1
    err = capsys.readouterr().err
    assert str(stale) in err
    assert str(generate_sync.TOKEN.target) not in err


def test_the_generator_writes_the_files_it_checks(unit: Unit, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "_sync" / unit.target.name
    monkeypatch.setattr(generate_sync, "UNITS", (replace(unit, target=target),))
    assert generate_sync.main([]) == 0
    assert generate_sync.main(["--check"]) == 0
    assert target.read_text(encoding="utf-8") == generate_sync.generate(unit)


def test_an_unknown_argument_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert generate_sync.main(["--nope"]) == 2
    assert "usage" in capsys.readouterr().err
