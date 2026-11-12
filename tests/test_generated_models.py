"""`noblecloak.models` is generated from the pinned `openapi.public.yaml` (`scripts/generate_models.py`).

The first group fails locally the way `generate_models.py --check` fails in CI: when `models.py` is not what the
generator writes from the installed spec, because someone edited it by hand, bumped the spec pin without
regenerating, or changed the generator's options. The second group reads the models the way a client will: a response
is validated at the boundary, an unknown member is kept, and a member whose absence means something is `None` and
not in `model_fields_set`.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import shutil
import subprocess
from collections.abc import Callable
from enum import Enum
from pathlib import Path
from typing import Any, Literal, cast, get_args, get_origin

import pytest
import yaml
from pydantic import AwareDatetime, BaseModel, RootModel, ValidationError
from pydantic_core import PydanticUndefined

import generate_models
from noblecloak import models

ROOT = Path(__file__).resolve().parent.parent
HEADER_LINE = re.compile(
    r"# Generated from dist/openapi\.public\.yaml of @noblecloak/spec (?P<version>\S+) \(sha256 (?P<sha>[0-9a-f]{64})\)"
)


def checked_in() -> str:
    return generate_models.TARGET.read_text(encoding="utf-8")


# --- the drift check ------------------------------------------------------------------------------


def test_the_checked_in_models_are_what_the_generator_writes() -> None:
    assert checked_in() == generate_models.generate()
    assert generate_models.main(["--check"]) == 0


def test_a_hand_edit_of_the_models_fails_the_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    edited = tmp_path / "models.py"
    edited.write_text(checked_in().replace("class Problem(BaseModel):", "class Problem(BaseModel):  # edited"))
    assert edited.read_text() != checked_in()
    monkeypatch.setattr(generate_models, "TARGET", edited)
    assert generate_models.main(["--check"]) == 1
    assert "is not what scripts/generate_models.py writes" in capsys.readouterr().err


def test_a_missing_models_file_fails_the_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(generate_models, "TARGET", tmp_path / "absent.py")
    assert generate_models.main(["--check"]) == 1


def test_a_spec_that_changed_without_regenerating_fails_the_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = tmp_path / "spec"
    shutil.copytree(generate_models.SPEC_PACKAGE, package)
    changed = package / "dist" / "openapi.public.yaml"
    text = changed.read_text(encoding="utf-8")
    edited = text.replace("minimum: 400", "minimum: 401", 1)
    assert edited != text
    changed.write_text(edited, encoding="utf-8")
    monkeypatch.setattr(generate_models, "SPEC_PACKAGE", package)
    monkeypatch.setattr(generate_models, "SPEC", changed)
    assert generate_models.generate() != checked_in()
    assert generate_models.main(["--check"]) == 1


def test_a_missing_spec_fails_and_never_skips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(generate_models, "SPEC", tmp_path / "openapi.public.yaml")
    assert generate_models.main(["--check"]) == 2
    assert generate_models.main([]) == 2
    assert "bun install --frozen-lockfile" in capsys.readouterr().err


@pytest.mark.parametrize("failing", ["datamodel_code_generator", "ruff"])
def test_a_failing_tool_exits_3_with_its_stderr_and_is_not_read_as_drift(
    failing: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    real_run = cast("Callable[..., subprocess.CompletedProcess[str]]", subprocess.run)

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if failing in command:
            raise subprocess.CalledProcessError(2, command, output="", stderr=f"{failing}: unknown option --nope")
        return real_run(command, **kwargs)

    monkeypatch.setattr(generate_models.subprocess, "run", run)
    assert generate_models.main(["--check"]) == 3
    err = capsys.readouterr().err
    assert f"{failing.replace('_', '-')} failed with exit status 2" in err
    assert f"{failing}: unknown option --nope" in err
    assert "is not what scripts/generate_models.py writes" not in err
    assert generate_models.main([]) == 3


def test_a_failing_tool_with_no_stderr_still_says_so() -> None:
    error = generate_models.ToolFailedError("ruff", subprocess.CalledProcessError(1, ["ruff"], stderr=None))
    assert "ruff failed with exit status 1" in str(error)
    assert "(no stderr)" in str(error)


ANCHOR_ANNOTATIONS = {
    ("Approval", "agent"): "Annotated[Agent | None, Field(description='x')] = None",
    ("Approval", "run"): "Run | None = None",
    ("PolicySetProposal", "tools"): "Annotated[list[Tool] | None, Field(max_length=50)] = None",
    ("AgentEnvelope", "data"): "Agent2",
    ("RunEnvelope", "data"): "Run1",
    ("ToolEnvelope", "data"): "Tool2",
}


def generated_source(annotations: dict[tuple[str, str], str] = ANCHOR_ANNOTATIONS) -> str:
    """What the generator writes, reduced to the classes the renames use and the members they are anchored on."""
    classes = "".join(
        f"class {name}(BaseModel):\n    x: int\n"
        for name in (*generate_models.INLINE_RENAMES, *generate_models.COMPONENT_RENAMES)
    )
    owners = {owner for owner, _ in annotations}
    members = "".join(
        f"class {owner}(BaseModel):\n" + "".join(f"    {m}: {a}\n" for (o, m), a in annotations.items() if o == owner)
        for owner in sorted(owners)
    )
    return classes + members


ALL_CLASSES = generated_source()


def test_the_renames_touch_identifiers_and_not_strings() -> None:
    source = ALL_CLASSES + 'y: Tool2 = Field(description="See `Tool2` and `Agent`.")\n'
    renamed = generate_models.rename_classes(source)
    assert "class Tool(BaseModel)" in renamed
    assert "class PolicySetProposalTool(BaseModel)" in renamed
    assert "y: Tool = Field" in renamed
    assert 'description="See `Tool2` and `Agent`."' in renamed


def test_a_class_the_renames_expect_but_the_generator_no_longer_writes_is_an_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(generate_models.RenameError, match="no longer defines Run1"):
        generate_models.rename_classes(ALL_CLASSES.replace("class Run1(", "class Run2("))
    monkeypatch.setattr(generate_models, "generate", lambda: generate_models.rename_classes("x = 1\n"))
    assert generate_models.main(["--check"]) == 3
    assert "no longer defines" in capsys.readouterr().err


def test_a_renumbering_that_keeps_every_name_but_moves_one_is_an_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Another inline `agent` object takes the plain `Agent`, the old one becomes `Agent1`: every name the renames list
    # still exists, so only the anchor on `Approval.agent` notices.
    moved = {**ANCHOR_ANNOTATIONS, ("Approval", "agent"): "Annotated[Agent1 | None, Field(description='x')] = None"}
    with pytest.raises(generate_models.RenameError, match=r"Approval\.agent annotates Agent1, expected Agent"):
        generate_models.rename_classes(generated_source(moved))
    monkeypatch.setattr(generate_models, "generate", lambda: generate_models.rename_classes(generated_source(moved)))
    assert generate_models.main(["--check"]) == 3
    assert "Approval.agent annotates Agent1" in capsys.readouterr().err


@pytest.mark.parametrize(("owner", "member"), list(generate_models.RENAME_ANCHORS))
def test_each_anchor_is_enforced(owner: str, member: str) -> None:
    other = {**ANCHOR_ANNOTATIONS, (owner, member): "Problem | None = None"}
    with pytest.raises(generate_models.RenameError, match=rf"{owner}\.{member} annotates Problem"):
        generate_models.rename_classes(generated_source(other))
    gone = {k: v for k, v in ANCHOR_ANNOTATIONS.items() if k != (owner, member)}
    gone[(owner, "other")] = "int"
    with pytest.raises(generate_models.RenameError, match=rf"{owner}\.{member} is not a member"):
        generate_models.rename_classes(generated_source(gone))


def test_an_anchor_may_be_wrapped_but_must_name_only_the_expected_class() -> None:
    wrapped = {**ANCHOR_ANNOTATIONS, ("Approval", "run"): "Annotated[list[Run] | None, Field(max_length=1)] = None"}
    assert generate_models.rename_classes(generated_source(wrapped))
    two = {**ANCHOR_ANNOTATIONS, ("Approval", "run"): "Run | Run1 | None = None"}
    with pytest.raises(generate_models.RenameError, match=r"Approval\.run annotates Run, Run1, expected Run"):
        generate_models.rename_classes(generated_source(two))


def test_each_anchor_is_true_in_the_spec() -> None:
    # The renames are undone by name; what makes a name the right class is where the spec uses it. An inline anchor is a
    # member whose schema is an object (the generator names it after the member, and the component of that name makes
    # the second claim); a component anchor is a member that references the component the numbered name stands for.
    schemas = spec_schemas()
    assert set(generate_models.RENAME_ANCHORS.values()) == {
        *generate_models.INLINE_RENAMES,
        *generate_models.COMPONENT_RENAMES,
    }
    for (owner, member), expected in generate_models.RENAME_ANCHORS.items():
        sub = schemas[owner]["properties"][member]
        target = sub["items"] if sub.get("type") == "array" else sub
        if expected in generate_models.INLINE_RENAMES:
            assert "$ref" not in target, (owner, member)
            assert target.get("properties") or target.get("allOf"), (owner, member)
            assert expected in schemas, f"{expected} is also a component, which is why the inline class is renamed"
        else:
            assert ref_name(target) == generate_models.COMPONENT_RENAMES[expected], (owner, member)


def test_a_rename_onto_a_name_that_already_exists_is_an_error() -> None:
    with pytest.raises(generate_models.RenameError, match="ApprovalAgent already exists"):
        generate_models.rename_classes(ALL_CLASSES + "class ApprovalAgent(BaseModel):\n    x: int\n")


def test_write_mode_writes_what_check_mode_accepts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "models.py"
    monkeypatch.setattr(generate_models, "TARGET", target)
    assert generate_models.main([]) == 0
    assert target.read_text(encoding="utf-8") == checked_in()
    assert generate_models.main(["--check"]) == 0


def test_an_unknown_argument_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert generate_models.main(["--fix"]) == 2
    assert "usage: generate_models.py" in capsys.readouterr().err


def test_the_header_names_the_pinned_spec_and_its_digest() -> None:
    text = checked_in()
    assert text.startswith("# GENERATED FILE. DO NOT EDIT BY HAND.\n")
    match = HEADER_LINE.search(text)
    assert match
    contract = json.loads((ROOT / "contract.json").read_text(encoding="utf-8"))
    manifest = json.loads((ROOT / "conformance" / "package.json").read_text(encoding="utf-8"))
    assert match["version"] == contract["packages"]["@noblecloak/spec"]["version"]
    assert match["version"] == manifest["dependencies"]["@noblecloak/spec"]
    assert match["sha"] == hashlib.sha256(generate_models.SPEC.read_bytes()).hexdigest()


# --- the models cover the document ----------------------------------------------------------------


class SpecLoader(yaml.SafeLoader):
    """`yaml.SafeLoader` reads YAML 1.1, where the bare words `off` and `on` are booleans; the spec is YAML 1.2, where
    only `true` and `false` are (`Capabilities.dpop` has the value `off`)."""


SpecLoader.yaml_implicit_resolvers = {
    first: [(tag, pattern) for tag, pattern in resolvers if tag != "tag:yaml.org,2002:bool"]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
cast("Any", SpecLoader).add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), "tTfF"
)


def spec_schemas() -> dict[str, Any]:
    document = yaml.load(generate_models.SPEC.read_text(encoding="utf-8"), Loader=SpecLoader)
    return document["components"]["schemas"]


def test_every_schema_of_the_document_has_a_model() -> None:
    schemas = spec_schemas()
    assert len(schemas) > 100
    missing = [name for name in schemas if not isinstance(getattr(models, name, None), type)]
    assert missing == []


def ref_name(schema: dict[str, Any]) -> str | None:
    ref = schema.get("$ref")
    return None if ref is None else str(ref).rsplit("/", 1)[-1]


def classes_in(annotation: Any) -> list[type]:
    """Every class an annotation names, in order: `list[A] | B | None` gives `[A, B, NoneType]`."""
    found: list[type] = [annotation] if isinstance(annotation, type) else []
    for argument in get_args(annotation):
        found.extend(classes_in(argument))
    return found


def alternative_problems(arms: list[dict[str, Any]], named: list[type], path: str) -> list[str]:
    """A member typed as a union: each alternative that is a component or `null` is in the annotation."""
    problems: list[str] = []
    for arm in arms:
        referenced = ref_name(arm)
        if referenced is not None and getattr(models, referenced) not in named:
            problems.append(f"{path}: does not name models.{referenced}")
        elif arm.get("type") == "null" and type(None) not in named:
            problems.append(f"{path}: does not allow None")
    return problems


def all_of_problems(parts: list[dict[str, Any]], named: list[type], path: str) -> list[str]:
    """A member typed `allOf: [$ref, ..., {inline}]`: some class its annotation names is each referenced component or a
    subclass of it, and has every member of the inline part (by wire name)."""
    referenced = [getattr(models, name) for part in parts if (name := ref_name(part)) is not None]
    inline = [set(part.get("properties", {})) for part in parts if ref_name(part) is None]
    candidates = [c for c in named if issubclass(c, BaseModel)]
    for candidate in candidates:
        aliases = {info.alias or field_name for field_name, info in getattr(candidate, "model_fields", {}).items()}
        if all(issubclass(candidate, r) for r in referenced) and all(members <= aliases for members in inline):
            return []
    names = [c.__name__ for c in candidates]
    return [f"{path}: no class of {names} is {', '.join(r.__name__ for r in referenced)} with the inline members"]


def object_problems(model: Any, schema: dict[str, Any], path: str) -> list[str]:
    """What differs between an object schema and the model for it: its members (by wire name), which are required,
    and for each member the class its annotation names (the component it references, or a model of the inline
    object)."""
    if not (isinstance(model, type) and issubclass(model, BaseModel)) or issubclass(model, RootModel):
        return [f"{path}: {model!r} is not an object model"]
    problems: list[str] = []
    declared = schema["properties"]
    fields = {info.alias or field_name: info for field_name, info in model.model_fields.items()}
    if set(declared) != set(fields):
        problems.append(f"{path}: members differ by {sorted(set(declared) ^ set(fields))}")
    if not schema.get("allOf"):
        required = {member for member, info in fields.items() if info.is_required()}
        if set(schema.get("required", [])) != required:
            problems.append(f"{path}: required members differ by {sorted(set(schema.get('required', [])) ^ required)}")
    for member, sub in declared.items():
        if member not in fields:
            continue
        target = sub.get("items") if sub.get("type") == "array" and "items" in sub else sub
        named = classes_in(fields[member].annotation)
        referenced = ref_name(target)
        if referenced is not None:
            if getattr(models, referenced) not in named:
                problems.append(f"{path}.{member}: does not name models.{referenced}")
        elif target.get("oneOf") or target.get("anyOf"):
            problems.extend(alternative_problems(target.get("oneOf") or target["anyOf"], named, f"{path}.{member}"))
        elif target.get("allOf"):
            problems.extend(all_of_problems(target["allOf"], named, f"{path}.{member}"))
        elif target.get("properties") or target.get("enum"):
            inline = [c for c in named if issubclass(c, BaseModel | Enum)]
            if not any(not shape_problems(c, f"{path}.{member}", target) for c in inline):
                names = [c.__name__ for c in inline]
                problems.append(f"{path}.{member}: no class of {names} has the shape of the inline schema")
    return problems


def root_problems(model: Any, path: str) -> tuple[list[str], Any]:
    if not (isinstance(model, type) and issubclass(model, RootModel)):
        return [f"{path}: {model!r} is not a root model"], None
    return [], model.model_fields["root"]


def enum_problems(model: type, name: str, schema: dict[str, Any]) -> list[str]:
    if not issubclass(model, Enum):
        return [f"{name}: {model!r} is not an Enum"]
    diff = set(schema["enum"]) ^ {member.value for member in model}
    return [f"{name}: values differ by {sorted(diff, key=repr)}"] if diff else []


def union_problems(model: type, name: str, schema: dict[str, Any]) -> list[str]:
    problems, root = root_problems(model, name)
    if root is None:
        return problems
    arms = schema.get("oneOf") or schema["anyOf"]
    named = classes_in(root.annotation)
    if len(named) != len(arms):
        return [f"{name}: {len(named)} alternatives for {len(arms)} in the schema"]
    for index, (arm, cls) in enumerate(zip(arms, named, strict=True)):
        referenced = ref_name(arm)
        if referenced is not None and cls is not getattr(models, referenced):
            problems.append(f"{name}[{index}]: is not models.{referenced}")
        elif referenced is None and arm.get("properties"):
            problems.extend(object_problems(cls, arm, f"{name}[{index}]"))
        elif referenced is None and not (issubclass(cls, BaseModel) and not issubclass(cls, RootModel)):
            problems.append(f"{name}[{index}]: {cls!r} is not an object model")
        if schema.get("properties"):
            # `Action`: the members are on the schema and each alternative only says which of them is required.
            shared = object_problems(cls, {"properties": schema["properties"], "allOf": True}, name)
            problems.extend(f"{name}[{index}]: {problem}" for problem in shared if "members differ" in problem)
    return problems


def string_problems(model: type, name: str, schema: dict[str, Any]) -> list[str]:
    problems, root = root_problems(model, name)
    if root is None:
        return problems
    expected = AwareDatetime if schema.get("format") == "date-time" else str
    if root.annotation is not expected:
        problems.append(f"{name}: root is {root.annotation!r}, not {expected!r}")
    patterns = [m.pattern for m in root.metadata if hasattr(m, "pattern")]
    if patterns != ([schema["pattern"]] if "pattern" in schema else []):
        problems.append(f"{name}: patterns are {patterns}, the schema's is {schema.get('pattern')}")
    return problems


def bound_problems(root: Any, name: str, bounds: dict[str, Any]) -> list[str]:
    """`bounds` maps an annotated-types attribute (`min_length`) to the schema's value, or None for no bound."""
    problems: list[str] = []
    for attribute, wanted in bounds.items():
        have = [getattr(m, attribute) for m in root.metadata if hasattr(m, attribute)]
        if have != ([] if wanted is None else [wanted]):
            problems.append(f"{name}: {attribute} is {have}, the schema's is {wanted}")
    return problems


def array_problems(model: type, name: str, schema: dict[str, Any]) -> list[str]:
    problems, root = root_problems(model, name)
    if root is None:
        return problems
    bounds = {"min_length": schema.get("minItems"), "max_length": schema.get("maxItems")}
    problems.extend(bound_problems(root, name, bounds))
    item = ref_name(schema["items"])
    if get_origin(root.annotation) is not list or (item and getattr(models, item) not in classes_in(root.annotation)):
        problems.append(f"{name}: root is {root.annotation!r}, not a list of {item}")
    return problems


def map_problems(model: type, name: str, schema: dict[str, Any]) -> list[str]:
    problems, root = root_problems(model, name)
    if root is None:
        return problems
    problems.extend(bound_problems(root, name, {"max_length": schema.get("maxProperties")}))
    value = ref_name(schema["additionalProperties"])
    if get_origin(root.annotation) is not dict or (value and getattr(models, value) not in classes_in(root.annotation)):
        problems.append(f"{name}: root is {root.annotation!r}, not a dict of {value}")
    return problems


def component_problems(name: str, schema: dict[str, Any]) -> list[str]:
    """What differs between a component schema and `models.<name>`."""
    model = getattr(models, name, None)
    return shape_problems(model, name, schema) if isinstance(model, type) else [f"{name}: no model"]


def shape_problems(model: type, name: str, schema: dict[str, Any]) -> list[str]:
    """What differs between a schema and a class, by the kind of schema it is."""
    kind = schema.get("type")
    checks: list[tuple[bool, Callable[[type, str, dict[str, Any]], list[str]]]] = [
        ("enum" in schema, enum_problems),
        ("oneOf" in schema or "anyOf" in schema, union_problems),
        (kind == "string", string_problems),
        (kind == "array", array_problems),
        (kind == "object" and not schema.get("properties"), map_problems),
        (bool(schema.get("properties")), lambda m, n, s: object_problems(m, s, n)),
    ]
    for applies, check in checks:
        if applies:
            return check(model, name, schema)
    return [f"{name}: a kind of schema this check does not know"]


def test_every_component_has_the_structure_of_its_schema() -> None:
    # Not just a type of the same name: an inline schema that took a component's name would pass a name check and
    # parse the wrong shape (`Agent`, `Run` and `Tool` did, as `Approval.agent`, `Approval.run` and a proposal's
    # tool). Every kind of schema is held to its kind: an enum is an Enum with the schema's values, a string a root
    # model with the schema's format and pattern, a `oneOf` or `anyOf` a root model over its alternatives, an array
    # or map a root model with its bounds, an object a class with the schema's members, and each member names the
    # component it references or a class of the inline object's shape.
    schemas = spec_schemas()
    assert len(schemas) > 100
    assert schemas["Capabilities"]["properties"]["dpop"]["enum"] == ["off", "optional", "required"]
    assert {name: problems for name, schema in schemas.items() if (problems := component_problems(name, schema))} == {}


SWAPS = [
    ("DecisionValue", "ApprovalAgent"),
    ("DecisionValue", "ApprovalState"),
    ("PolicyMode", "DecisionValue"),
    ("Digest", "FactName"),
    ("Resolution", "ApprovalRun"),
    ("Timestamp", "Digest"),
    ("PolicyConfig", "Problem"),
    ("ResolveBatchResult", "ApprovalHandle"),
    ("PolicyConditions", "PolicyKind"),
    ("ToolFacts", "PolicyConditions"),
    ("Problem", "DecisionValue"),
]


@pytest.mark.parametrize(("name", "replacement"), SWAPS)
def test_a_component_replaced_by_a_class_of_another_shape_is_reported(
    name: str, replacement: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    schema = spec_schemas()[name]
    assert component_problems(name, schema) == []
    monkeypatch.setattr(models, name, getattr(models, replacement))
    assert component_problems(name, schema) != []


def test_an_inline_class_that_holds_the_shape_of_another_inline_schema_is_reported() -> None:
    approval = copy.deepcopy(spec_schemas()["Approval"])
    properties = approval["properties"]
    properties["agent"], properties["run"] = properties["run"], properties["agent"]
    assert component_problems("Approval", spec_schemas()["Approval"]) == []
    problems = object_problems(models.Approval, approval, "Approval")
    assert any(problem.startswith("Approval.agent:") for problem in problems)
    assert any(problem.startswith("Approval.run:") for problem in problems)


def test_a_member_that_names_the_wrong_component_is_reported() -> None:
    schema = copy.deepcopy(spec_schemas()["ToolEnvelope"])
    schema["properties"]["data"] = {"$ref": "#/components/schemas/Problem"}
    assert object_problems(models.ToolEnvelope, schema, "ToolEnvelope") == [
        "ToolEnvelope.data: does not name models.Problem"
    ]


ALL_OF_MEMBERS = [("PolicySetProposal", "tools"), ("ConsumeRequest", "action")]


def test_a_member_given_as_all_of_is_checked() -> None:
    # `object_problems` used to match no branch for these two and check nothing. Each is an `allOf` of a component
    # and, for the items of `tools`, an inline part: the class must be that component (or extend it) and carry the
    # inline members.
    schemas = spec_schemas()
    found = [
        (name, member)
        for name, schema in schemas.items()
        for member, sub in cast(dict[str, dict[str, Any]], schema.get("properties", {})).items()
        if sub.get("allOf") or cast(dict[str, Any], sub.get("items", {})).get("allOf")
    ]
    assert found == ALL_OF_MEMBERS
    for name, _member in ALL_OF_MEMBERS:
        assert object_problems(getattr(models, name), schemas[name], name) == []


def test_an_all_of_member_that_names_a_class_of_another_component_is_reported() -> None:
    schema = copy.deepcopy(spec_schemas()["ConsumeRequest"])
    schema["properties"]["action"]["allOf"] = [{"$ref": "#/components/schemas/Problem"}]
    problems = object_problems(models.ConsumeRequest, schema, "ConsumeRequest")
    assert [p.split(":")[0] for p in problems] == ["ConsumeRequest.action"]


def test_an_all_of_items_member_whose_class_does_not_extend_the_component_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    schema = spec_schemas()["PolicySetProposal"]
    assert object_problems(models.PolicySetProposal, schema, "PolicySetProposal") == []
    # The class for the items no longer extends `ToolWrite`, though it has every member of the inline part.
    stand_in = type("PolicySetProposalTool", (BaseModel,), {"__annotations__": {"tool_ref": str, "owner_kind": str}})
    monkeypatch.setattr(models.PolicySetProposal.model_fields["tools"], "annotation", list[stand_in] | None)
    problems = object_problems(models.PolicySetProposal, schema, "PolicySetProposal")
    assert [p.split(":")[0] for p in problems] == ["PolicySetProposal.tools"]


def test_an_all_of_inline_member_the_class_lacks_is_reported() -> None:
    schema = copy.deepcopy(spec_schemas()["PolicySetProposal"])
    schema["properties"]["tools"]["items"]["allOf"][1]["properties"]["invented"] = {"type": "string"}
    problems = object_problems(models.PolicySetProposal, schema, "PolicySetProposal")
    assert [p.split(":")[0] for p in problems] == ["PolicySetProposal.tools"]


def test_the_inline_schemas_that_share_a_component_name_are_not_that_component() -> None:
    assert set(models.Tool.model_fields) >= {"id", "tool_ref", "transport", "side_effect_level", "data_routing"}
    assert set(models.Agent.model_fields) >= {"id", "name", "parent_id", "created_at", "principal_id"}
    assert set(models.Run.model_fields) >= {"id", "kind", "scope_id", "agent_id", "created_at"}
    assert models.ToolEnvelope.model_fields["data"].annotation is models.Tool
    assert not hasattr(models, "Tool2")
    assert not hasattr(models, "Agent2")
    assert not hasattr(models, "Run1")


INLINE_USES = {
    ("Approval", "agent"): "ApprovalAgent",
    ("Approval", "run"): "ApprovalRun",
    ("PolicySetProposal", "tools"): "PolicySetProposalTool",
}


def test_the_renamed_inline_classes_are_the_ones_their_member_names() -> None:
    # `generate_models.INLINE_RENAMES` gives these the names of where they are used; swapping two of its values keeps
    # every shape check green (the shapes move with the classes) and puts `Approval.agent` in a class called
    # `ApprovalRun`. The members are the inline schemas, which `object_problems` holds to their shape.
    assert set(INLINE_USES.values()) == set(generate_models.INLINE_RENAMES.values())
    for (model, member), class_name in INLINE_USES.items():
        named = classes_in(getattr(models, model).model_fields[member].annotation)
        assert getattr(models, class_name) in named, (model, member)
        assert object_problems(getattr(models, model), spec_schemas()[model], model) == []


NUMBERED = {
    "Action1", "Action2", "Kind1", "Kind2", "Kind3", "Approval1", "Agent1", "Problem1", "PolicyApprover1",
    "PolicyApprover2", "ApproverRef1", "ApproverRef2", "PolicySubject1", "PolicySubject2", "Tool1", "Policy1",
    "ConnectionAuth1", "ConnectionAuth2", "ConnectionAuth3", "Transport2", "State1",
}  # fmt: skip


def test_the_classes_the_generator_numbers_are_the_ones_listed() -> None:
    # The generator numbers an inline schema by the order it meets them, so a spec bump can renumber or rename them
    # without any component changing. They are not public API (CONTRIBUTING.md): this list is where a bump that
    # changes them is noticed. The objects and enums among them are held to their schemas through the member or
    # alternative that names them; `Tool1`, the non-empty string item of `PolicyTargets.tools`, is only listed.
    found = {
        name for name, value in vars(models).items() if re.fullmatch(r"[A-Za-z]+\d+", name) and isinstance(value, type)
    }
    assert found == NUMBERED


def test_every_numbered_class_is_reached_from_a_component() -> None:
    # A numbered class nothing refers to would be a class no check reads.
    reached: set[type] = set()
    pending = [getattr(models, name) for name in spec_schemas()]
    while pending:
        model = pending.pop()
        for annotation in [info.annotation for info in getattr(model, "model_fields", {}).values()]:
            pending.extend(cls for cls in classes_in(annotation) if cls not in reached)
            reached.update(classes_in(annotation))
    assert {getattr(models, n) for n in NUMBERED} <= reached


def test_every_object_model_keeps_unknown_members() -> None:
    # A `oneOf` schema (`Action`) is a root model over its alternatives, which are the objects.
    objects = [
        name
        for name, schema in spec_schemas().items()
        if schema.get("properties") and not issubclass(getattr(models, name), RootModel)
    ]
    assert len(objects) > 50
    closed = [name for name in objects if getattr(models, name).model_config.get("extra") != "allow"]
    assert closed == []
    assert models.Action1.model_config.get("extra") == "allow"


# --- reading a response ---------------------------------------------------------------------------

DIGEST = "ab" * 32
NOW = "2026-11-10T12:00:00Z"


def capabilities(**more: Any) -> dict[str, Any]:
    return {
        "deployment": "hosted",
        "entitlements": [],
        "jwks_uri": "https://govern.beta.noblecloak.com/.well-known/jwks.json",
        "kids": ["k1"],
        "resolutions": ["approved", "rejected"],
        "features": ["approvals.requirements"],
        "authzen_configuration": "https://govern.beta.noblecloak.com/.well-known/authzen-configuration",
        **more,
    }


def decision(**more: Any) -> dict[str, Any]:
    return {"decision": "allow", "action_digest": DIGEST, "enforced": True, **more}


def test_an_absent_continuation_kinds_is_none_and_was_not_set() -> None:
    # Rev 17: absent means the seven kinds of rev 16, and a model that filled a default would hide that.
    absent = models.Capabilities.model_validate(capabilities())
    assert absent.continuation_kinds is None
    assert "continuation_kinds" not in absent.model_fields_set
    assert "continuation_kinds" not in absent.model_dump(exclude_unset=True)
    listed = models.Capabilities.model_validate(capabilities(continuation_kinds=["claude_agent_sdk", "callback"]))
    assert listed.continuation_kinds == ["claude_agent_sdk", "callback"]
    assert "continuation_kinds" in listed.model_fields_set


def test_a_member_this_version_does_not_know_is_kept() -> None:
    parsed = models.Capabilities.model_validate(capabilities(a_member_of_a_later_revision={"x": 1}))
    assert parsed.model_extra == {"a_member_of_a_later_revision": {"x": 1}}
    assert parsed.model_dump(exclude_unset=True)["a_member_of_a_later_revision"] == {"x": 1}


def test_a_response_missing_a_required_member_is_refused() -> None:
    body = capabilities()
    del body["jwks_uri"]
    with pytest.raises(ValidationError) as error:
        models.Capabilities.model_validate(body)
    assert [e["loc"] for e in error.value.errors()] == [("jwks_uri",)]


def test_a_member_of_the_wrong_type_is_refused() -> None:
    with pytest.raises(ValidationError):
        models.Capabilities.model_validate(capabilities(kids="k1"))
    with pytest.raises(ValidationError):
        models.Problem.model_validate({"type": "t", "title": "x", "status": 200, "request_id": "r"})


def test_a_schema_bound_and_pattern_are_enforced() -> None:
    with pytest.raises(ValidationError):
        models.Decision.model_validate(decision(action_digest="AB" * 32))
    with pytest.raises(ValidationError):
        models.Decision.model_validate(decision(missing_facts=["Not A Fact"]))
    with pytest.raises(ValidationError):
        models.Decision.model_validate(decision(missing_facts=[]))


def test_an_enum_value_outside_the_contract_is_refused() -> None:
    parsed = models.Decision.model_validate(decision(decision="step_up"))
    assert parsed.decision is models.DecisionValue.STEP_UP
    with pytest.raises(ValidationError):
        models.Decision.model_validate(decision(decision="maybe"))


def test_rev_16_missing_facts_are_read() -> None:
    parsed = models.Decision.model_validate(decision(decision="defer", missing_facts=["amount", "region"]))
    assert parsed.missing_facts is not None
    assert [fact.root for fact in parsed.missing_facts] == ["amount", "region"]
    assert models.Decision.model_validate(decision()).missing_facts is None


def test_a_uri_is_kept_as_written_and_a_timestamp_must_carry_an_offset() -> None:
    # The spec's token audience is an origin with no trailing slash; `AnyUrl` writes one back onto a bare host.
    problem = models.Problem.model_validate(
        {"type": "https://docs.noblecloak.com", "title": "x", "status": 409, "request_id": "r1"}
    )
    assert problem.type == "https://docs.noblecloak.com"
    handle = {"id": "a1", "state": "pending", "created": True, "created_at": NOW, "resume_token_will_issue": False}
    assert models.ApprovalHandle.model_validate(handle).created_at.root.utcoffset() is not None
    with pytest.raises(ValidationError):
        models.ApprovalHandle.model_validate({**handle, "created_at": "2026-11-10T12:00:00"})


def enum_types(annotation: Any) -> list[type[Enum]]:
    """The enum classes in a field's annotation (`OwnerKind | None` gives `[OwnerKind]`)."""
    found = [annotation] if isinstance(annotation, type) and issubclass(annotation, Enum) else []
    for argument in get_args(annotation):
        found.extend(enum_types(argument))
    return found


def test_a_default_the_document_states_is_the_enum_member() -> None:
    defaulted = [
        (f"{name}.{field_name}", field)
        for name, model in vars(models).items()
        if isinstance(model, type) and issubclass(model, BaseModel)
        for field_name, field in model.model_fields.items()
        if enum_types(field.annotation) and field.default is not PydanticUndefined and field.default is not None
    ]
    assert defaulted, "the document no longer gives an enum field a default; this test reaches nothing"
    assert [name for name, field in defaulted if not isinstance(field.default, Enum)] == []
    assert models.ToolWrite.model_fields["owner_kind"].default is models.OwnerKind.PRINCIPAL


def test_the_subclass_the_pyright_ignore_names_narrows_its_parents_field() -> None:
    # pyproject's `[tool.pyright] ignore` comment gives this as the reason models.py is not type-checked.
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert '`PolicySetProposalTool.owner_kind` narrows `ToolWrite.owner_kind` to `Literal["org"]`' in pyproject
    assert issubclass(models.PolicySetProposalTool, models.ToolWrite)
    assert models.PolicySetProposalTool.model_fields["owner_kind"].annotation == Literal["org"]
    assert models.ToolWrite.model_fields["owner_kind"].annotation == (models.OwnerKind | None)
    assert "owner_kind" not in models.Tool.model_fields


def test_a_dump_that_sends_only_what_was_set_needs_by_alias_to_keep_the_wire_name() -> None:
    # CONTRIBUTING.md tells the request builders to dump with by_alias=True; `from` is a Python keyword.
    item = models.LooseningItem.model_validate({"tool_ref": "t", "from": "ask", "to": "deny"})
    assert item.model_dump(mode="json", by_alias=True, exclude_unset=True) == {
        "tool_ref": "t",
        "from": "ask",
        "to": "deny",
    }
    assert "from_" in item.model_dump(mode="json", exclude_unset=True)
    assert "from" not in item.model_dump(mode="json", exclude_unset=True)
    assert 'model_dump(mode="json", by_alias=True, exclude_unset=True)' in (ROOT / "CONTRIBUTING.md").read_text(
        encoding="utf-8"
    )
    # Not accepted as input by its Python name: it lands in the extras and the required `from` is missing.
    with pytest.raises(ValidationError):
        models.LooseningItem(tool_ref="t", from_="ask", to="deny")  # type: ignore[call-arg]
