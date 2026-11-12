"""Private-dependency guard.

Walks the tree and fails when it names a source a stranger could not install from, or a credential.
The Python side installs from one index, pypi.org, by name and version. The `conformance/` workspace
installs from one registry, registry.npmjs.org. Nothing maps either to anything else, and nothing holds a
credential.

Python side (pyproject.toml, uv.toml, uv.lock, requirements*.txt, requirements*.in, constraints*.txt, and every
other *.toml, which uv can be pointed at with `UV_CONFIG_FILE` or `--config-file` and is checked by the uv.toml
rules):
  - a requirement that is not a name plus a version specifier: a direct reference (`name @ url`), a URL, a
    `git+` source or a path. Checked in build-system.requires, project.dependencies, optional-dependencies,
    dependency-groups and, in `[tool.uv]` (pyproject.toml) and at the root of uv.toml, `dev-dependencies`,
    `override-dependencies`, `constraint-dependencies`, `build-constraint-dependencies` and every list under
    `extra-build-dependencies` (string items and the `requirement` of a table item), and the `requires-dist` of
    every `dependency-metadata` entry. A requirement that names a wheel or sdist file counts as a path;
  - in pyproject.toml, any URL whose host is not pypi.org or files.pythonhosted.org on a line in a `[tool.uv]` or
    `[tool.uv.*]` section (or a `uv.` key under `[tool]`), and in uv.toml on any line;
  - a `[tool.uv.sources]` or `[tool.uv.workspace]` table, and any setting that names another source or trusts a
    host (`index`, `index-url`, `extra-index-url`, `find-links`, `publish-url`, `check-url`,
    `python-install-mirror`, `pypy-install-mirror`, `python-downloads-json-url`, `allow-insecure-host`) in
    `[tool.uv]`, `[tool.uv.pip]` or uv.toml;
  - in uv.lock, a package whose source is not the pypi.org registry (or the project itself, virtual or
    editable at "."), and any URL whose host is not pypi.org or files.pythonhosted.org;
  - in requirements files, an index, find-links or `--trusted-host` option, an editable install, or a URL, git
    or path source (a wheel or sdist file included);
  - a credential: a PyPI, npm or GitHub token (`pypi-AgE...`, `npm_`, `gh[pousr]_`, `github_pat_`) or a URL with a
    user part (except the `git@` SSH remote) in every text file the guard reads, a `username`, `password` or `token`
    setting in pyproject.toml, uv.toml or any other *.toml, or a `.pypirc`, `.netrc`, `pip.conf` or `pip.ini` file;
  - a pyproject.toml whose `project.license` is not `Apache-2.0`.

conformance/ side (package.json, .npmrc, bunfig.toml, bun.lock): the same rules as the TypeScript
repositories' guard. A dependency specifier that is not a registry version or range, any URL other than
registry.npmjs.org, any scope-to-registry mapping, any registry setting that is not the public registry, an
auth line, a lockfile entry that bun resolved other than by version, and a package.json whose `license` is not
`Apache-2.0`.

Every other UTF-8 text file in the tree (source, tests, docs, workflows; not binaries and not the skipped
directories such as `.git`, `.venv` and `node_modules`) is scanned for the same tokens and URLs with a user part.

Run with `uv run python scripts/check_private_deps.py`. Exit code 1 and one line per violation
(`file: key - reason`).
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

ViolationKind = Literal[
    "foreign-source-dependency",
    "foreign-registry",
    "credential",
    "missing-apache-license",
    "unreadable-file",
]


@dataclass(frozen=True, order=True)
class Violation:
    """One finding: the file (relative, forward slashes), the offending key or line, and why."""

    file: str
    key: str
    kind: ViolationKind


REASONS: dict[ViolationKind, str] = {
    "foreign-source-dependency": "resolves from outside the public index (pypi.org / registry.npmjs.org)",
    "foreign-registry": "names an index or registry other than the public one, or maps a scope to one",
    "credential": "contains a registry credential; the tree installs from the public index without one",
    "missing-apache-license": 'license must be "Apache-2.0"',
    "unreadable-file": "is not valid UTF-8 text, JSON or TOML",
}

SKIPPED_DIRECTORIES = frozenset(
    {
        ".git",
        ".venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        "htmlcov",
        "artifacts",
    }
)

CREDENTIAL_FILES = frozenset({".pypirc", ".netrc", "pip.conf", "pip.ini"})
GUARDED_FILES = frozenset(
    {
        "pyproject.toml",
        "uv.toml",
        "uv.lock",
        "package.json",
        ".npmrc",
        "bunfig.toml",
        "bun.lock",
    }
)

PYPI_HOSTS = frozenset({"pypi.org", "files.pythonhosted.org"})
NPM_HOST = "registry.npmjs.org"
PYPI_REGISTRY = "https://pypi.org/simple"

# Settings that name somewhere other than pypi.org to fetch from, publish to or trust (Python installs included).
UV_SOURCE_SETTING_KEYS = frozenset(
    {
        "index",
        "index-url",
        "extra-index-url",
        "find-links",
        "publish-url",
        "check-url",
        "python-install-mirror",
        "pypy-install-mirror",
        "python-downloads-json-url",
        "allow-insecure-host",
    }
)

# A `name[extras] @ ...` direct reference, a bare URL or path, or a VCS prefix.
DIRECT_REFERENCE = re.compile(r"^\s*[A-Za-z0-9][A-Za-z0-9._-]*\s*(?:\[[^\]]*\])?\s*@")
VCS_PREFIX = re.compile(r"(?:^|[\s@])(?:git|hg|svn|bzr)\+", re.IGNORECASE)
PATH_PREFIX = re.compile(r"^\s*(?:\.{1,2}/|/|~|file:)", re.IGNORECASE)
# A wheel or sdist named by file (`dist/foo-1.0-py3-none-any.whl`, `foo-1.0.tar.gz`), before any marker.
ARCHIVE_PATH = re.compile(r"\.(?:whl|zip|tgz|tar\.gz|tar\.bz2|tar\.xz)\s*$", re.IGNORECASE)

# A PyPI, npm or GitHub token (classic `gh[pousr]_` and fine-grained `github_pat_`).
TOKEN = re.compile(
    r"\bpypi-AgE[A-Za-z0-9_-]{20,}|\bnpm_[A-Za-z0-9]{36}\b|\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}"
)
# A URL with a user part. `git@` (`ssh://git@github.com/...`, the SSH remote form) carries no secret and is exempt.
URL_USER = re.compile(r"\b[a-z][a-z+.-]*://(?!git@[^\s/@\"']+(?:[/\s\"']|$))[^\s/@\"']+@", re.IGNORECASE)
CREDENTIAL_KEY = re.compile(r"^\s*(?:username|password|token)\s*=", re.IGNORECASE)
URL_IN_LINE = re.compile(r"\b[a-z][a-z+.-]*://([^\s/\"'\\]+)", re.IGNORECASE)


def _host(authority: str) -> str:
    """The host of a URL authority (`user:pw@host:port` -> `host`)."""
    host = authority.rsplit("@", 1)[-1]
    return host.split(":", 1)[0].lower()


def _foreign_urls(line: str, allowed: frozenset[str]) -> bool:
    return any(_host(m.group(1)) not in allowed for m in URL_IN_LINE.finditer(line))


def _is_foreign_requirement(requirement: str) -> bool:
    """True when a PEP 508 requirement is not a name plus a version specifier."""
    return bool(
        DIRECT_REFERENCE.match(requirement)
        or "://" in requirement
        or VCS_PREFIX.search(requirement)
        or PATH_PREFIX.match(requirement)
        or ARCHIVE_PATH.search(requirement.split(";", 1)[0])
    )


def _credential_lines(text: str, *, keys: bool) -> list[str]:
    """`line N` for each line holding a token or a URL with a user part (and, if `keys`, a credential key)."""
    found: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.split("#", 1)[0] if keys else line
        if TOKEN.search(line) or URL_USER.search(line) or (keys and CREDENTIAL_KEY.match(stripped)):
            found.append(f"line {number}")
    return found


def _load_toml(file: str, text: str) -> tuple[dict[str, Any] | None, list[Violation]]:
    try:
        return tomllib.loads(text), []
    except tomllib.TOMLDecodeError:
        return None, [Violation(file, "(file)", "unreadable-file")]


def _requirement_lists(data: dict[str, Any]) -> list[tuple[str, list[str]]]:
    """Every list of PEP 508 requirement strings in a pyproject, with the key it lives under."""
    lists: list[tuple[str, list[str]]] = []

    def add(key: str, value: Any) -> None:
        if isinstance(value, list):
            items: list[Any] = value  # pyright: ignore[reportUnknownVariableType]
            lists.append((key, [item for item in items if isinstance(item, str)]))

    add("build-system.requires", data.get("build-system", {}).get("requires"))
    project = data.get("project", {})
    add("project.dependencies", project.get("dependencies"))
    for name, value in project.get("optional-dependencies", {}).items():
        add(f"project.optional-dependencies.{name}", value)
    for name, value in data.get("dependency-groups", {}).items():
        add(f"dependency-groups.{name}", value)
    uv = data.get("tool", {}).get("uv", {})
    if isinstance(uv, dict):
        lists.extend(_uv_requirement_lists("tool.uv", uv))  # pyright: ignore[reportUnknownArgumentType]
    return lists


UV_REQUIREMENT_KEYS = (
    "dev-dependencies",
    "override-dependencies",
    "constraint-dependencies",
    "build-constraint-dependencies",
)


def _requirement_of(item: Any) -> str | None:
    """A requirement string, or the `requirement` of a table item (`{ requirement = "...", match-runtime = true }`)."""
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        requirement = item.get("requirement")  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        if isinstance(requirement, str):
            return requirement
    return None


def _uv_requirement_lists(prefix: str, table: dict[str, Any]) -> list[tuple[str, list[str]]]:
    """The requirement lists a uv settings table can carry (`[tool.uv]` in pyproject.toml, the root of uv.toml)."""
    lists: list[tuple[str, list[str]]] = []

    def add(key: str, value: Any) -> None:
        if isinstance(value, list):
            items: list[Any] = value  # pyright: ignore[reportUnknownVariableType]
            lists.append((key, [requirement for item in items if (requirement := _requirement_of(item)) is not None]))

    for name in UV_REQUIREMENT_KEYS:
        add(f"{prefix}.{name}", table.get(name))
    extra_build = table.get("extra-build-dependencies")
    if isinstance(extra_build, dict):
        for package, value in extra_build.items():  # pyright: ignore[reportUnknownVariableType]
            add(f"{prefix}.extra-build-dependencies.{package}", value)
    metadata = table.get("dependency-metadata")
    if isinstance(metadata, list):
        for index, entry in enumerate(metadata):  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType]
            if isinstance(entry, dict):
                name = entry.get("name", index)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
                add(f"{prefix}.dependency-metadata.{name}.requires-dist", entry.get("requires-dist"))  # pyright: ignore[reportUnknownMemberType]
    return lists


def _foreign_requirements(file: str, lists: list[tuple[str, list[str]]]) -> list[Violation]:
    return [
        Violation(file, f"{key}: {requirement}", "foreign-source-dependency")
        for key, requirements in lists
        for requirement in requirements
        if _is_foreign_requirement(requirement)
    ]


def _uv_table_violations(file: str, prefix: str, table: dict[str, Any]) -> list[Violation]:
    found: list[Violation] = []
    for key in sorted(UV_SOURCE_SETTING_KEYS & table.keys()):
        found.append(Violation(file, f"{prefix}.{key}", "foreign-registry"))
    if "sources" in table:
        found.append(Violation(file, f"{prefix}.sources", "foreign-source-dependency"))
    if "workspace" in table:
        found.append(Violation(file, f"{prefix}.workspace", "foreign-source-dependency"))
    pip = table.get("pip")
    if isinstance(pip, dict):
        found.extend(_uv_table_violations(file, f"{prefix}.pip", pip))  # pyright: ignore[reportUnknownArgumentType]
    return found


TOML_HEADER = re.compile(r"^\s*\[\[?([^\]]*)\]\]?\s*(?:#.*)?$")
DOTTED_UV_KEY = re.compile(r"""^\s*["']?uv["']?\s*\.""")


def _tool_uv_lines(text: str) -> list[tuple[int, str]]:
    """(line number, line) for every line in a `[tool.uv]` or `[tool.uv.*]` section, or a `uv.` key under `[tool]`."""
    found: list[tuple[int, str]] = []
    section = ""
    for number, line in enumerate(text.splitlines(), start=1):
        header = TOML_HEADER.match(line)
        if header is not None:
            section = re.sub(r"""[\s"']""", "", header.group(1))
            continue
        if section == "tool.uv" or section.startswith("tool.uv.") or (section == "tool" and DOTTED_UV_KEY.match(line)):
            found.append((number, line))
    return found


def check_pyproject(file: str, text: str) -> list[Violation]:
    data, found = _load_toml(file, text)
    if data is None:
        return found
    found.extend(_foreign_requirements(file, _requirement_lists(data)))
    uv = data.get("tool", {}).get("uv", {})
    if isinstance(uv, dict):
        found.extend(_uv_table_violations(file, "tool.uv", uv))  # pyright: ignore[reportUnknownArgumentType]
    for number, line in _tool_uv_lines(text):
        if _foreign_urls(line, PYPI_HOSTS):
            found.append(Violation(file, f"line {number}", "foreign-registry"))
    if data.get("project", {}).get("license") != "Apache-2.0":
        found.append(Violation(file, "project.license", "missing-apache-license"))
    found.extend(Violation(file, line, "credential") for line in _credential_lines(text, keys=True))
    return found


def check_uv_toml(file: str, text: str, prefix: str = "uv.toml") -> list[Violation]:
    data, found = _load_toml(file, text)
    if data is None:
        return found
    found.extend(_uv_table_violations(file, prefix, data))
    found.extend(_foreign_requirements(file, _uv_requirement_lists(prefix, data)))
    for number, line in enumerate(text.splitlines(), start=1):
        if _foreign_urls(line, PYPI_HOSTS):
            found.append(Violation(file, f"line {number}", "foreign-registry"))
    found.extend(Violation(file, line, "credential") for line in _credential_lines(text, keys=True))
    return found


def check_toml(file: str, text: str) -> list[Violation]:
    """Any other `*.toml`: uv reads settings from any file named by `UV_CONFIG_FILE` or `--config-file`.

    The same rules as uv.toml at the root, and a `[tool.uv]` table (a pyproject under another name) too.
    """
    found = check_uv_toml(file, text, prefix="(root)")
    data, _ = _load_toml(file, text)
    tool: Any = data.get("tool") if data is not None else None
    uv: Any = tool.get("uv") if isinstance(tool, dict) else None  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    if isinstance(uv, dict):
        table = cast("dict[str, Any]", uv)
        found.extend(_uv_table_violations(file, "tool.uv", table))
        found.extend(_foreign_requirements(file, _uv_requirement_lists("tool.uv", table)))
    return found


def check_uv_lock(file: str, text: str) -> list[Violation]:
    data, found = _load_toml(file, text)
    if data is None:
        return found
    for package in data.get("package", []):
        source = package.get("source", {})
        name = package.get("name", "(unnamed)")
        registry = source.get("registry")
        own_project = source.get("virtual") == "." or source.get("editable") == "."
        if registry is not None:
            if registry != PYPI_REGISTRY:
                found.append(Violation(file, f"package.{name}.source.registry", "foreign-registry"))
        elif not own_project:
            found.append(Violation(file, f"package.{name}.source", "foreign-source-dependency"))
    for number, line in enumerate(text.splitlines(), start=1):
        if _foreign_urls(line, PYPI_HOSTS):
            found.append(Violation(file, f"line {number}", "foreign-registry"))
    found.extend(Violation(file, line, "credential") for line in _credential_lines(text, keys=False))
    return found


# `-i`, `-f` and `-e` also match with the value fused on (`-ihttps://...`).
REQUIREMENTS_OPTION = re.compile(
    r"^\s*(?:-[ife]|--index-url\b|--extra-index-url\b|--find-links\b|--editable\b|--trusted-host\b)"
)


def check_requirements(file: str, text: str) -> list[Violation]:
    found: list[Violation] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        key = f"line {number}"
        if REQUIREMENTS_OPTION.match(line):
            found.append(Violation(file, key, "foreign-registry"))
        elif _is_foreign_requirement(line):
            found.append(Violation(file, key, "foreign-source-dependency"))
    found.extend(Violation(file, line, "credential") for line in _credential_lines(text, keys=False))
    return found


# --- conformance/ (npm side) -------------------------------------------------------------------------

DEPENDENCY_FIELDS = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")

NPMRC_AUTH_LINE = re.compile(r"_auth(Token)?\s*=|_password\s*=")
BUNFIG_AUTH_LINE = re.compile(r"\b(?:username|password|token)\s*=")
ANY_SCOPE_MAPPING = re.compile(r'^\s*(?:@[^:\s]+:registry\s*=|"?@[^"\s=]+"?\s*=)')
BUNFIG_REGISTRY_TABLE = re.compile(
    r'^\s*\[\s*"?install"?\s*\.\s*"?(?:scopes|registry)"?\s*(?:\.[^\]]*)?\]'
    r'|^\s*"?install"?\s*\.\s*"?(?:scopes|registry)"?\s*[.=]'
    r'|^\s*"?scopes"?\s*[.=]'
)
NPMRC_EXPANDED_KEY = re.compile(r"^\s*(?![#;])[^=]*\$\{[^=]*=")
REGISTRY_SETTING = re.compile(r"^\s*registry\s*=\s*(.*?)\s*$")
PUBLIC_NPM_REGISTRY = re.compile(r"""^(["']?)https://registry\.npmjs\.org/?\1$""", re.IGNORECASE)
NON_REGISTRY_SOURCE = re.compile(r"""(?:^|["@\s])(?:github|gitlab|bitbucket|git\+[a-z]+|git):""", re.IGNORECASE)
LOCAL_PATH_SOURCE = re.compile(r"^(?:file|link):", re.IGNORECASE)
GITHUB_SHORTHAND = re.compile(r"^[\w.-]+/[\w.-]+(?:#.*)?$")
LOCK_ENTRY = re.compile(r'^ {4}"([^"]+)":\s*\[\s*"([^"]*)"(?:,\s*"([^"]*)")?')


def _sets_other_registry(line: str) -> bool:
    match = REGISTRY_SETTING.match(line)
    return match is not None and not PUBLIC_NPM_REGISTRY.match(match.group(1))


def _foreign_npm_url(line: str) -> bool:
    return _foreign_urls(line, frozenset({NPM_HOST}))


def _is_foreign_specifier(spec: str) -> bool:
    value = spec.removeprefix("npm:")
    return bool(
        LOCAL_PATH_SOURCE.match(value)
        or _foreign_npm_url(value)
        or NON_REGISTRY_SOURCE.search(value)
        or GITHUB_SHORTHAND.match(value)
    )


def _is_non_registry_lock_entry(line: str) -> bool:
    match = LOCK_ENTRY.match(line)
    if match is None:
        return False
    resolved = match.group(2)
    at = resolved.rfind("@")
    version = resolved[at + 1 :]
    return at <= 0 or not re.match(r"(\d|workspace:)", version)


def check_package_json(file: str, text: str) -> list[Violation]:
    try:
        manifest: Any = json.loads(text)
    except json.JSONDecodeError:
        return [Violation(file, "(file)", "unreadable-file")]
    if not isinstance(manifest, dict):
        return [Violation(file, "(file)", "unreadable-file")]
    found: list[Violation] = []
    for field in DEPENDENCY_FIELDS:
        deps = manifest.get(field)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():  # pyright: ignore[reportUnknownVariableType]
            if isinstance(spec, str) and _is_foreign_specifier(spec):
                found.append(Violation(file, f"{field}.{name}", "foreign-source-dependency"))
    publish_config = manifest.get("publishConfig")  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    if isinstance(publish_config, dict):
        registry = publish_config.get("registry")  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        if isinstance(registry, str) and _foreign_npm_url(registry):
            found.append(Violation(file, "publishConfig.registry", "foreign-registry"))
    if manifest.get("license") != "Apache-2.0":  # pyright: ignore[reportUnknownMemberType]
        found.append(Violation(file, "license", "missing-apache-license"))
    return found


def check_npm_config(file: str, text: str) -> list[Violation]:
    is_npmrc = file.endswith(".npmrc")
    is_bunfig = file.endswith("bunfig.toml")
    is_lockfile = file.endswith("bun.lock")
    found: list[Violation] = []
    for number, line in enumerate(text.splitlines(), start=1):
        key = f"line {number}"
        if is_lockfile:
            if _is_non_registry_lock_entry(line) or _foreign_npm_url(line) or NON_REGISTRY_SOURCE.search(line):
                found.append(Violation(file, key, "foreign-source-dependency"))
            continue
        if is_npmrc and NPMRC_AUTH_LINE.search(line):
            found.append(Violation(file, key, "credential"))
            continue
        if is_bunfig and BUNFIG_AUTH_LINE.search(line):
            found.append(Violation(file, key, "credential"))
        if (
            _foreign_npm_url(line)
            or ANY_SCOPE_MAPPING.match(line)
            or _sets_other_registry(line)
            or (is_bunfig and BUNFIG_REGISTRY_TABLE.match(line))
            or (is_npmrc and NPMRC_EXPANDED_KEY.match(line))
        ):
            found.append(Violation(file, key, "foreign-registry"))
    return found


# --- walk --------------------------------------------------------------------------------------------


def _walk(directory: Path) -> list[Path]:
    found: list[Path] = []
    for entry in sorted(directory.iterdir(), key=lambda p: p.name):
        if entry.is_dir():
            if entry.name not in SKIPPED_DIRECTORIES:
                found.extend(_walk(entry))
        else:
            found.append(entry)
    return found


# pip requirement files: requirements*.txt, pip-tools inputs (requirements*.in) and constraint files.
REQUIREMENTS_FILE = re.compile(r"requirements.*\.(?:txt|in)|constraints.*\.txt")


def _is_guarded(path: Path) -> bool:
    """A manifest, lockfile, registry config or credential file: checked by its own rules."""
    name = path.name
    return (
        name in GUARDED_FILES
        or name in CREDENTIAL_FILES
        or name.endswith(".toml")
        or bool(REQUIREMENTS_FILE.fullmatch(name))
    )


def _text_of(path: Path) -> str | None:
    """The file as UTF-8 text, or None for a binary (a NUL byte) or non-UTF-8 file."""
    data = path.read_bytes()
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


CHECKERS: dict[str, Callable[[str, str], list[Violation]]] = {
    "pyproject.toml": check_pyproject,
    "uv.toml": check_uv_toml,
    "uv.lock": check_uv_lock,
    "package.json": check_package_json,
    ".npmrc": check_npm_config,
    "bunfig.toml": check_npm_config,
    "bun.lock": check_npm_config,
}


def _check_file(file: str, name: str, text: str) -> list[Violation]:
    default = check_toml if name.endswith(".toml") else check_requirements
    return CHECKERS.get(name, default)(file, text)


def _scan(root: Path) -> tuple[list[Violation], int, int]:
    """(violations in path order, guarded files checked, other text files scanned for tokens)."""
    found: list[Violation] = []
    guarded = scanned = 0
    for path in _walk(root):
        file = path.relative_to(root).as_posix()
        if path.name in CREDENTIAL_FILES:
            guarded += 1
            found.append(Violation(file, "(file)", "credential"))
            continue
        text = _text_of(path)
        if _is_guarded(path):
            guarded += 1
            if text is None:
                found.append(Violation(file, "(file)", "unreadable-file"))
            else:
                found.extend(_check_file(file, path.name, text))
            continue
        if text is not None:
            scanned += 1
            found.extend(Violation(file, line, "credential") for line in _credential_lines(text, keys=False))
    return found, guarded, scanned


def find_violations(root: Path) -> list[Violation]:
    """Every violation under `root`, in path order."""
    return _scan(root)[0]


def run_guard(root: Path, out: Callable[[str], None]) -> int:
    """Run the guard over `root`, writing one line per violation to `out`. Returns the exit code."""
    violations, guarded, scanned = _scan(root)
    if not violations:
        out(
            f"private-dependency guard: OK ({guarded} manifest files checked, {scanned} other files scanned for tokens)"
        )
        return 0
    for violation in violations:
        out(f"{violation.file}: {violation.key} - {REASONS[violation.kind]}")
    out(f"private-dependency guard: {len(violations)} violation(s)")
    return 1


def main() -> int:
    return run_guard(Path.cwd(), print)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
