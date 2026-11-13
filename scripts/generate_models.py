"""Generates `src/noblecloak/models.py` from the pinned `openapi.public.yaml` with `datamodel-code-generator`.

    uv run python scripts/generate_models.py            write the models
    uv run python scripts/generate_models.py --check    fail (exit 1) when the file on disk is not what this writes

Exit codes: 0 ok, 1 drift (--check only), 2 usage error or spec not installed, 3 the generator or ruff failed
or the renames no longer apply.

The document is the one `@noblecloak/spec` ships (`conformance/node_modules/@noblecloak/spec/dist/openapi.public.yaml`,
installed by `bun install --frozen-lockfile` in `conformance/`). A missing document fails the run (exit 2); it never
skips. A generator or `ruff` run that fails exits 3 with the tool's own stderr, so it is not read as drift (exit 1).
The generated file starts with a header that names the spec version and the SHA-256 of the document, so a
spec bump that was not regenerated is a drift, and so is a hand edit. The result is formatted with the pinned
`ruff` under this project's settings. CI runs `--check`, and so does `tests/test_generated_models.py`.

Options, and why:

- `--extra-fields allow`: an object the server sends with a member this version does not know is kept, not refused.
- `--type-mappings uri=string`: `format: uri` stays a `str`. pydantic's `AnyUrl` normalises the value (a bare
  host-only value gains a trailing slash, while the spec's token audience is an origin with none) and drops the
  schema's `pattern` (https, or loopback http for an origin, on three members).
- `--use-annotated --field-constraints`: the schema's bounds and patterns are kept on the fields.
- No `--use-default`: an optional member that the schema gives no `default` is `None` when absent, and
  `model_fields_set` says whether it was sent. Where the document does state a `default`, the model carries it.
- `--set-default-enum-member --capitalise-enum-members`: a default on an enum field is the member, not the bare
  string, and no member is named after a `str` method (the enum `Type` has a member `count`).
- Names: the generator names an inline schema after its property and numbers the second claim on a name, so
  `Approval.agent`, `Approval.run` and the items of `PolicySetProposal.tools` took `Agent`, `Run` and `Tool` and the
  components of those names became `Agent2`, `Run1` and `Tool2`. `INLINE_RENAMES` and `COMPONENT_RENAMES` undo that
  after generation, so `models.Tool`, `models.Agent` and `models.Run` are the component schemas. The run fails
  (exit 3) when the generator no longer defines one of those classes, when a new name is already taken, or when
  an anchor in `RENAME_ANCHORS` is false: each names a member (`Approval.agent`, `PolicySetProposal.tools`,
  `AgentEnvelope.data`, ...) whose annotation, read from the generated source with `ast` before anything is
  renamed, must be exactly the class the rename expects. A spec bump that adds another inline `agent` object
  renumbers the classes while the names all still exist; the anchors are what notices that. They are not a check
  of the result: `tests/test_generated_models.py` checks each model's members against its schema.
- Closed enums stay `StrEnum`: a value outside the contract revision this release was generated from is refused
  at the boundary.
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import re
import subprocess
import sys
import tempfile
import tokenize
from importlib.metadata import version
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SPEC_PACKAGE = ROOT / "conformance" / "node_modules" / "@noblecloak" / "spec"
SPEC = SPEC_PACKAGE / "dist" / "openapi.public.yaml"
TARGET = ROOT / "src" / "noblecloak" / "models.py"
_FORMAT_AS = TARGET  # the path ruff is told the source has, so its settings are the project's wherever TARGET points

OPTIONS = [
    "--input-file-type",
    "openapi",
    "--output-model-type",
    "pydantic_v2.BaseModel",
    "--target-python-version",
    "3.12",
    "--target-pydantic-version",
    "2",
    "--extra-fields",
    "allow",
    "--use-standard-collections",
    "--use-union-operator",
    "--use-annotated",
    "--field-constraints",
    "--type-mappings",
    "uri=string",
    "--set-default-enum-member",
    "--capitalise-enum-members",
    "--disable-timestamp",
    "--formatters",
    "builtin",
]


# Inline schemas the generator named like a component schema, renamed first.
INLINE_RENAMES = {"Agent": "ApprovalAgent", "Run": "ApprovalRun", "Tool": "PolicySetProposalTool"}
# The component schemas that the generator numbered because an inline schema had the plain name.
COMPONENT_RENAMES = {"Agent2": "Agent", "Run1": "Run", "Tool2": "Tool"}
# What the renames stand on: the class that the annotation of `Owner.member` names in the generated source before
# renaming. The first three are the inline schemas (the generator gave them the plain component name), the others
# the members that reference the components (so the generator numbered those). A renumbering that keeps the names
# but moves them (a second inline `agent` object, say) makes an anchor false instead of renaming the wrong class.
RENAME_ANCHORS = {
    ("Approval", "agent"): "Agent",
    ("Approval", "run"): "Run",
    ("PolicySetProposal", "tools"): "Tool",
    ("AgentEnvelope", "data"): "Agent2",
    ("RunEnvelope", "data"): "Run1",
    ("ToolEnvelope", "data"): "Tool2",
}


class SpecMissingError(Exception):
    """The pinned spec document is not installed."""


class RenameError(Exception):
    """The generator's output no longer has the classes `INLINE_RENAMES` and `COMPONENT_RENAMES` expect."""


class ToolFailedError(Exception):
    """A tool this script runs (the generator or `ruff`) exited non-zero. The message carries the tool's stderr."""

    def __init__(self, tool: str, error: subprocess.CalledProcessError) -> None:
        stderr = (error.stderr or "").strip() or "(no stderr)"
        super().__init__(f"{tool} failed with exit status {error.returncode}:\n{stderr}")


def _run(tool: str, command: list[str], **kwargs: Any) -> str:
    try:
        return subprocess.run(command, check=True, capture_output=True, text=True, cwd=ROOT, **kwargs).stdout
    except subprocess.CalledProcessError as error:
        raise ToolFailedError(tool, error) from error


def spec_version() -> str:
    """The version in the installed `@noblecloak/spec` package, which `conformance/package.json` pins exactly."""
    data = json.loads((SPEC_PACKAGE / "package.json").read_text(encoding="utf-8"))
    return str(data["version"])


def header() -> str:
    digest = hashlib.sha256(SPEC.read_bytes()).hexdigest()
    return (
        "# GENERATED FILE. DO NOT EDIT BY HAND.\n"
        f"# Generated from dist/openapi.public.yaml of @noblecloak/spec {spec_version()} (sha256 {digest})\n"
        f"# by scripts/generate_models.py (datamodel-code-generator {version('datamodel-code-generator')}).\n"
        "# Update the pin in conformance/, run `bun install` there and `uv run python scripts/generate_models.py`,\n"
        "# and commit the result; CI fails when this file is not what that writes.\n"
    )


def generate() -> str:
    if not SPEC.is_file():
        raise SpecMissingError(f"{SPEC} is not installed; run `bun install --frozen-lockfile` in conformance/")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "models.py"
        _run(
            "datamodel-code-generator",
            [
                sys.executable,
                "-m",
                "datamodel_code_generator",
                "--input",
                str(SPEC),
                "--output",
                str(out),
                "--custom-file-header",
                header(),
                *OPTIONS,
            ],
        )
        raw = out.read_text(encoding="utf-8")
    return _ruff(_ruff(rename_classes(raw), "check", "--select", "I", "--fix-only"), "format")


def _names_in(annotation: ast.expr) -> list[str]:
    """The class names an annotation uses: `Annotated[list[X] | None, Field(...)]` gives `["X"]`. Of an `Annotated`
    only the type counts (its metadata is not a class), and `None` and the generic `list` are not classes."""
    if isinstance(annotation, ast.Name):
        return [] if annotation.id == "list" else [annotation.id]
    if isinstance(annotation, ast.BinOp):
        return _names_in(annotation.left) + _names_in(annotation.right)
    if isinstance(annotation, ast.Subscript):
        inner = annotation.slice
        if (
            isinstance(annotation.value, ast.Name)
            and annotation.value.id == "Annotated"
            and isinstance(inner, ast.Tuple)
        ):
            return _names_in(inner.elts[0])
        return _names_in(annotation.value) + _names_in(inner)
    return []


def _check_anchors(source: str) -> None:
    """Raises `RenameError` for each of `RENAME_ANCHORS` whose member does not annotate exactly the expected class."""
    annotations: dict[tuple[str, str], ast.expr] = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                    annotations[(node.name, item.target.id)] = item.annotation
    wrong: list[str] = []
    for (owner, member), expected in RENAME_ANCHORS.items():
        annotation = annotations.get((owner, member))
        if annotation is None:
            wrong.append(
                f"{owner}.{member} is not a member in the generated source (expected it to annotate {expected})"
            )
            continue
        found = _names_in(annotation)
        if found != [expected]:
            wrong.append(f"{owner}.{member} annotates {', '.join(found) or 'no class'}, expected {expected}")
    if wrong:
        raise RenameError("the generated classes are not numbered as the renames expect; " + "; ".join(wrong))


def rename_classes(source: str) -> str:
    """Renames `INLINE_RENAMES` and `COMPONENT_RENAMES` at once, on identifier tokens only (never in a docstring)."""
    renames = {**INLINE_RENAMES, **COMPONENT_RENAMES}
    defined = set(re.findall(r"^class (\w+)\(", source, flags=re.MULTILINE))
    absent = sorted(set(renames) - defined)
    if absent:
        raise RenameError(f"the generator no longer defines {', '.join(absent)}; update the renames in {__file__}")
    taken = sorted((defined - set(renames)) & set(renames.values()))
    if taken:
        raise RenameError(f"{', '.join(taken)} already exists in the generated models; update the renames")
    _check_anchors(source)
    lines = source.splitlines(keepends=True)
    tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    edits = [
        (token.start, token.end, renames[token.string])
        for token in tokens
        if token.type == tokenize.NAME and token.string in renames
    ]
    for (row, start), (_, end), name in reversed(edits):
        line = lines[row - 1]
        lines[row - 1] = line[:start] + name + line[end:]
    return "".join(lines)


def _ruff(source: str, *args: str) -> str:
    """Runs the pinned `ruff` over `source` as if it were the target file, so the project's settings apply."""
    return _run(
        "ruff",
        [sys.executable, "-m", "ruff", args[0], *args[1:], "--stdin-filename", str(_FORMAT_AS), "-"],
        input=source,
    )


def main(argv: list[str]) -> int:
    if argv not in ([], ["--check"]):
        print("usage: generate_models.py [--check]", file=sys.stderr)
        return 2
    try:
        wanted = generate()
    except SpecMissingError as error:
        print(error, file=sys.stderr)
        return 2
    except (ToolFailedError, RenameError) as error:
        print(error, file=sys.stderr)
        return 3
    if argv == ["--check"]:
        current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else None
        if current != wanted:
            print(
                f"{TARGET} is not what scripts/generate_models.py writes from {SPEC}. "
                "Run `uv run python scripts/generate_models.py` and commit the result.",
                file=sys.stderr,
            )
            return 1
        return 0
    TARGET.write_text(wanted, encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
