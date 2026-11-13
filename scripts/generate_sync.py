"""Generates the synchronous sources in `src/noblecloak/` from their asynchronous ones with `unasync`:

- `service_principal/_sync/token.py` from `service_principal/_async/token.py`;
- `client/_sync/client.py` from `client/_async/client.py`.

    uv run python scripts/generate_sync.py            write the generated files
    uv run python scripts/generate_sync.py --check    fail (exit 1) when a file on disk is not what this would write

The async source is the only one edited by hand. `unasync` drops `async` and `await` and renames the names in a unit's
`replacements`; the result has its imports sorted and is formatted with `ruff` (pinned in `pyproject.toml`, so the
output is stable) and given a header that says not to edit it. The pairs `async_x` / `sync_x` that the renames lead
to are in `service_principal/_core.py` and `client/_core.py`. CI runs `--check`, and so does
`tests/test_generated_sync.py`.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

import unasync as _unasync  # pyright: ignore[reportMissingTypeStubs]

unasync: Any = _unasync  # no type stubs

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "src" / "noblecloak"


@dataclass(frozen=True, eq=False)
class Unit:
    """One generated file: the async `source`, the `target` written from it, and the names that differ."""

    source: Path
    target: Path
    replacements: Mapping[str, str]
    format_as: Path
    """The path `ruff` is told the source has, so that its settings are the project's wherever `target` points."""


TOKEN = Unit(
    source=PACKAGE / "service_principal" / "_async" / "token.py",
    target=PACKAGE / "service_principal" / "_sync" / "token.py",
    format_as=PACKAGE / "service_principal" / "_sync" / "token.py",
    replacements=MappingProxyType(
        {
            "AsyncTokenSource": "TokenSource",
            "AsyncClient": "Client",
            "aiter_raw": "iter_raw",
            "aclose": "close",
            "async_scope": "sync_scope",
            "async_timeout": "sync_timeout",
            "async_tick": "sync_tick",
            "async_enlist": "sync_enlist",
            "async_check_client": "sync_check_client",
            "async_wait": "sync_wait",
        }
    ),
)

CLIENT = Unit(
    source=PACKAGE / "client" / "_async" / "client.py",
    target=PACKAGE / "client" / "_sync" / "client.py",
    format_as=PACKAGE / "client" / "_sync" / "client.py",
    replacements=MappingProxyType(
        {
            "AsyncModuleClient": "ModuleClient",
            "AsyncClient": "Client",
            "AsyncBaseTransport": "BaseTransport",
            "AsyncTokenGetter": "TokenGetter",
            "AsyncProofHook": "ProofHook",
            "aiter_bytes": "iter_bytes",
            "aclose": "close",
            "async_token": "sync_token",
            "async_proof": "sync_proof",
            "async_check_client": "sync_check_client",
        }
    ),
)

UNITS = (TOKEN, CLIENT)


def header(unit: Unit) -> str:
    source = unit.source.relative_to(PACKAGE).as_posix()
    return (
        "# GENERATED FILE. DO NOT EDIT BY HAND.\n"
        f"# Generated from {source} by scripts/generate_sync.py (unasync). Edit the async source,\n"
        "# then run `uv run python scripts/generate_sync.py`; CI fails when this file is not what that writes.\n"
    )


def generate(unit: Unit) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "_async" / unit.source.name
        source.parent.mkdir()
        source.write_bytes(unit.source.read_bytes())
        unasync.unasync_files(
            [str(source)],
            [unasync.Rule(f"{tmp}/_async/", f"{tmp}/_sync/", additional_replacements=dict(unit.replacements))],
        )
        raw = (Path(tmp) / "_sync" / unit.source.name).read_text(encoding="utf-8")
    return header(unit) + _ruff(unit, _ruff(unit, raw, "check", "--select", "I", "--fix-only"), "format")


def _ruff(unit: Unit, source: str, *args: str) -> str:
    """Runs the pinned `ruff` over `source` as if it were the target file, so the project's settings apply."""
    return subprocess.run(
        [sys.executable, "-m", "ruff", args[0], *args[1:], "--stdin-filename", str(unit.format_as), "-"],
        input=source,
        capture_output=True,
        text=True,
        check=True,
        cwd=ROOT,
    ).stdout


def main(argv: list[str]) -> int:
    if argv not in ([], ["--check"]):
        print("usage: generate_sync.py [--check]", file=sys.stderr)
        return 2
    stale = 0
    for unit in UNITS:
        wanted = generate(unit)
        if argv == ["--check"]:
            current = unit.target.read_text(encoding="utf-8") if unit.target.exists() else None
            if current != wanted:
                print(
                    f"{unit.target} is not what scripts/generate_sync.py writes from {unit.source}. "
                    "Run `uv run python scripts/generate_sync.py` and commit the result.",
                    file=sys.stderr,
                )
                stale = 1
        else:
            unit.target.parent.mkdir(parents=True, exist_ok=True)
            unit.target.write_text(wanted, encoding="utf-8")
    return stale


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
