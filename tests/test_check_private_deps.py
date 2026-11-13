"""The private-dependency guard: each rule turns a planted violation red, and the real tree is clean."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from check_private_deps import (
    Violation,
    check_npm_config,
    check_package_json,
    check_pyproject,
    check_requirements,
    check_toml,
    check_uv_lock,
    check_uv_toml,
    find_violations,
    main,
    run_guard,
)

ROOT = Path(__file__).resolve().parent.parent

# Planted credentials are assembled at run time: written out whole, they would turn this file red in the
# guard's own scan of the tree (test_the_tree_passes_the_guard).
PYPI_TOKEN = "pypi-" + "AgEIcHlwaS5vcmcCJDEyMzQ1Njc4OTA"
NPM_TOKEN = "npm_" + "a1B2" * 9
GITHUB_TOKENS = ["gh" + kind + "_" + "Z9y8" * 9 for kind in "pousr"] + ["github_" + "pat_" + "11AB" * 6 + "_x"]
URL_WITH_USER = "https://__token__:secret" + "@upload.pypi.org/legacy/"

CLEAN_PYPROJECT = """\
[build-system]
requires = ["hatchling==1.33.0"]
build-backend = "hatchling.build"

[project]
name = "x"
version = "0.0.0"
license = "Apache-2.0"
dependencies = ["httpx==0.28.1", "cryptography>=45; python_version >= '3.12'"]

[project.urls]
Repository = "https://github.com/NobleCloak/noblecloak-py"

[dependency-groups]
dev = ["pytest==9.2.0"]
"""


def kinds(violations: list[Violation]) -> set[str]:
    return {v.kind for v in violations}


def with_pyproject(extra: str, base: str = CLEAN_PYPROJECT) -> str:
    return base + "\n" + extra


# --- pyproject.toml -------------------------------------------------------------------------------


def test_clean_pyproject_passes() -> None:
    assert check_pyproject("pyproject.toml", CLEAN_PYPROJECT) == []


@pytest.mark.parametrize(
    "requirement",
    [
        "evil @ git+https://github.com/x/evil.git",
        "evil @ https://example.com/evil-1.0.tar.gz",
        "evil[extra] @ file:///tmp/evil",
        "git+https://github.com/x/evil.git",
        "https://example.com/evil.whl",
        "./vendor/evil",
        "../evil",
        "/abs/evil",
        "file:evil",
        "evil==1.0 ; python_version >= '3.12' and extra == 'x'  @ git+https://x",
    ],
)
def test_foreign_requirement_in_every_requirement_list_is_flagged(requirement: str) -> None:
    for header in (
        'dependencies = ["{r}"]',
        'optional-dependencies = {{ extra = ["{r}"] }}',
    ):
        base = CLEAN_PYPROJECT.replace(
            'dependencies = ["httpx==0.28.1", "cryptography>=45; python_version >= \'3.12\'"]', ""
        )
        text = base.replace('license = "Apache-2.0"', 'license = "Apache-2.0"\n' + header.format(r=requirement))
        found = check_pyproject("pyproject.toml", text)
        assert "foreign-source-dependency" in kinds(found), (header, requirement)
    group = CLEAN_PYPROJECT.replace('dev = ["pytest==9.2.0"]', f'dev = ["{requirement}"]')
    assert "foreign-source-dependency" in kinds(check_pyproject("pyproject.toml", group))
    build = CLEAN_PYPROJECT.replace('"hatchling==1.33.0"', f'"{requirement}"')
    assert "foreign-source-dependency" in kinds(check_pyproject("pyproject.toml", build))


UV_REQUIREMENT_PLANTS = [
    ("tool.uv.dev-dependencies", "[tool.uv]\ndev-dependencies = ['{r}']"),
    ("tool.uv.override-dependencies", "[tool.uv]\noverride-dependencies = ['{r}']"),
    ("tool.uv.constraint-dependencies", "[tool.uv]\nconstraint-dependencies = ['{r}']"),
    ("tool.uv.build-constraint-dependencies", "[tool.uv]\nbuild-constraint-dependencies = ['{r}']"),
    ("tool.uv.extra-build-dependencies.baz", "[tool.uv.extra-build-dependencies]\nbaz = ['{r}']"),
]


@pytest.mark.parametrize("requirement", ["foo @ git+https://evil/x.git", "bar @ https://evil/b.whl", "./vendor/x"])
@pytest.mark.parametrize(("key", "plant"), UV_REQUIREMENT_PLANTS)
def test_foreign_requirement_in_a_uv_requirement_list_is_flagged(key: str, plant: str, requirement: str) -> None:
    found = check_pyproject("pyproject.toml", with_pyproject(plant.format(r=requirement)))
    # A requirement that carries a URL is also caught by the line-wide URL scan of the [tool.uv*] sections.
    assert Violation("pyproject.toml", f"{key}: {requirement}", "foreign-source-dependency") in found
    assert kinds(found) <= {"foreign-source-dependency", "foreign-registry"}


@pytest.mark.parametrize(("key", "plant"), UV_REQUIREMENT_PLANTS)
def test_registry_requirement_in_a_uv_requirement_list_passes(key: str, plant: str) -> None:
    assert check_pyproject("pyproject.toml", with_pyproject(plant.format(r="foo>=1,<2"))) == []


TABLE_ITEM = "{{ requirement = '{r}', match-runtime = true }}"


@pytest.mark.parametrize("requirement", ["cython @ git+https://evil.example/cython", "./vendor/cython"])
def test_table_form_extra_build_dependency_is_flagged(requirement: str) -> None:
    plant = "[tool.uv.extra-build-dependencies]\nnoblecloak = [" + TABLE_ITEM.format(r=requirement) + "]"
    found = check_pyproject("pyproject.toml", with_pyproject(plant))
    key = f"tool.uv.extra-build-dependencies.noblecloak: {requirement}"
    assert Violation("pyproject.toml", key, "foreign-source-dependency") in found
    clean = plant.replace(requirement, "cython==3.1.0")
    assert check_pyproject("pyproject.toml", with_pyproject(clean)) == []


def test_table_form_extra_build_dependency_in_uv_toml_is_flagged() -> None:
    requirement = "./vendor/cython"
    text = "[extra-build-dependencies]\nnoblecloak = [" + TABLE_ITEM.format(r=requirement) + "]\n"
    found = check_uv_toml("uv.toml", text)
    key = f"uv.toml.extra-build-dependencies.noblecloak: {requirement}"
    assert found == [Violation("uv.toml", key, "foreign-source-dependency")]


@pytest.mark.parametrize(
    "plant",
    [
        "[tool.uv]\nsome-future-setting = 'https://evil.example/x'",
        "[tool.uv.extra-build-dependencies]\nx = [{ requirement = 'y', url = 'https://evil.example/y' }]",
        "[[tool.uv.index]]\nname = 'x'\nurl = 'https://evil.example/simple'",
        "[tool]\nuv.some-future-setting = 'https://evil.example/x'",
    ],
)
def test_a_foreign_url_anywhere_in_a_tool_uv_section_is_flagged(plant: str) -> None:
    found = check_pyproject("pyproject.toml", with_pyproject(plant))
    assert "foreign-registry" in kinds(found)
    assert any(v.key.startswith("line ") for v in found)


def test_the_tool_uv_url_scan_ignores_other_sections_and_pypi_urls() -> None:
    # project.urls legitimately names github.com; a pypi.org URL under [tool.uv] is not foreign.
    assert check_pyproject("pyproject.toml", with_pyproject("[tool.uv]\n# https://pypi.org/simple")) == []
    after = with_pyproject("[tool.uv]\ncompile-bytecode = true\n\n[tool.ruff]\nsrc = ['https://example.com']")
    assert check_pyproject("pyproject.toml", after) == []


def test_planted_git_dependency_is_red_with_its_key() -> None:
    text = CLEAN_PYPROJECT.replace('"httpx==0.28.1"', '"httpx @ git+https://github.com/encode/httpx"')
    assert check_pyproject("pyproject.toml", text) == [
        Violation(
            "pyproject.toml",
            "project.dependencies: httpx @ git+https://github.com/encode/httpx",
            "foreign-source-dependency",
        )
    ]


@pytest.mark.parametrize(
    ("extra", "key"),
    [
        ("[tool.uv.sources]\nx = { git = 'https://github.com/x/x' }", "tool.uv.sources"),
        ("[tool.uv]\nindex-url = 'https://example.com/simple'", "tool.uv.index-url"),
        ("[tool.uv]\nextra-index-url = ['https://example.com/simple']", "tool.uv.extra-index-url"),
        ("[tool.uv]\nfind-links = ['./wheels']", "tool.uv.find-links"),
        ("[tool.uv]\npublish-url = 'https://example.com/legacy/'", "tool.uv.publish-url"),
        ("[[tool.uv.index]]\nname = 'x'\nurl = 'https://example.com/simple'", "tool.uv.index"),
        ("[tool.uv.pip]\nindex-url = 'https://example.com/simple'", "tool.uv.pip.index-url"),
        ("[tool.uv.workspace]\nmembers = ['x']", "tool.uv.workspace"),
        ("[tool.uv]\ncheck-url = 'https://pypi.org/simple'", "tool.uv.check-url"),
        ("[tool.uv]\npython-install-mirror = 'https://example.com/py'", "tool.uv.python-install-mirror"),
        ("[tool.uv]\npypy-install-mirror = 'https://example.com/pypy'", "tool.uv.pypy-install-mirror"),
        ("[tool.uv]\npython-downloads-json-url = './downloads.json'", "tool.uv.python-downloads-json-url"),
        ("[tool.uv]\nallow-insecure-host = ['localhost']", "tool.uv.allow-insecure-host"),
        ("[tool.uv.pip]\nallow-insecure-host = ['localhost']", "tool.uv.pip.allow-insecure-host"),
    ],
)
def test_planted_extra_index_or_source_is_red(extra: str, key: str) -> None:
    found = check_pyproject("pyproject.toml", with_pyproject(extra))
    assert key in {v.key for v in found}


@pytest.mark.parametrize(
    "line",
    [
        'token = "abc"',
        'password = "abc"',
        'username = "abc"',
        f'x = "{PYPI_TOKEN}"',
        f'x = "{URL_WITH_USER}"',
        'x = "https://user' + '@example.com/simple"',
        f'x = "{NPM_TOKEN}"',
        *(f'x = "{token}"' for token in GITHUB_TOKENS),
    ],
)
def test_planted_token_is_red(line: str) -> None:
    found = check_pyproject("pyproject.toml", with_pyproject(f"[tool.x]\n{line}"))
    assert kinds(found) == {"credential"}


def test_pyproject_license_must_be_apache() -> None:
    mit = CLEAN_PYPROJECT.replace('"Apache-2.0"', '"MIT"')
    assert kinds(check_pyproject("pyproject.toml", mit)) == {"missing-apache-license"}
    missing = CLEAN_PYPROJECT.replace('license = "Apache-2.0"\n', "")
    assert kinds(check_pyproject("pyproject.toml", missing)) == {"missing-apache-license"}


def test_unparseable_toml_is_a_violation() -> None:
    for check in (check_pyproject, check_uv_toml, check_uv_lock):
        assert check("f.toml", "this is = = not toml") == [Violation("f.toml", "(file)", "unreadable-file")]


@pytest.mark.parametrize("requirement", ["y @ https://evil.example/y.whl", "./vendor/y"])
def test_dependency_metadata_requires_dist_is_checked(requirement: str) -> None:
    plant = f"[[tool.uv.dependency-metadata]]\nname = 'x'\nversion = '1.0'\nrequires-dist = ['{requirement}']"
    found = check_pyproject("pyproject.toml", with_pyproject(plant))
    key = f"tool.uv.dependency-metadata.x.requires-dist: {requirement}"
    assert Violation("pyproject.toml", key, "foreign-source-dependency") in found
    assert check_pyproject("pyproject.toml", with_pyproject(plant.replace(requirement, "y>=1"))) == []
    in_uv_toml = check_uv_toml("uv.toml", plant.replace("tool.uv.", "") + "\n")
    assert (
        Violation("uv.toml", f"uv.toml.dependency-metadata.x.requires-dist: {requirement}", "foreign-source-dependency")
        in in_uv_toml
    )


# --- uv.toml --------------------------------------------------------------------------------------


def test_uv_toml_rules() -> None:
    assert check_uv_toml("uv.toml", "python-preference = 'managed'\n") == []
    bad = check_uv_toml("uv.toml", "index-url = 'https://example.com/simple'\n[pip]\nfind-links = ['x']\n")
    assert {v.key for v in bad} >= {"uv.toml.index-url", "uv.toml.pip.find-links", "line 1"}
    assert "credential" in kinds(check_uv_toml("uv.toml", "token = 'x'\n"))
    assert check_uv_toml("uv.toml", "# https://pypi.org/simple\n") == []


@pytest.mark.parametrize(
    ("key", "plant"),
    [
        ("uv.toml.override-dependencies", "override-dependencies = ['{r}']"),
        ("uv.toml.constraint-dependencies", "constraint-dependencies = ['{r}']"),
        ("uv.toml.build-constraint-dependencies", "build-constraint-dependencies = ['{r}']"),
        ("uv.toml.extra-build-dependencies.baz", "[extra-build-dependencies]\nbaz = ['{r}']"),
    ],
)
def test_uv_toml_requirement_lists(key: str, plant: str) -> None:
    requirement = "foo @ git+https://evil/x.git"
    found = check_uv_toml("uv.toml", plant.format(r=requirement) + "\n")
    assert Violation("uv.toml", f"{key}: {requirement}", "foreign-source-dependency") in found
    assert check_uv_toml("uv.toml", plant.format(r="foo==1") + "\n") == []


# --- uv.lock --------------------------------------------------------------------------------------

CLEAN_LOCK = """\
version = 1

[[package]]
name = "httpx"
version = "0.28.1"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/aa/httpx-0.28.1.tar.gz", hash = "sha256:00" }

[[package]]
name = "noblecloak"
version = "0.0.0"
source = { editable = "." }
"""


def test_clean_lock_passes() -> None:
    assert check_uv_lock("uv.lock", CLEAN_LOCK) == []
    assert check_uv_lock("uv.lock", CLEAN_LOCK.replace("editable", "virtual")) == []


@pytest.mark.parametrize(
    "source",
    [
        '{ git = "https://github.com/x/x?rev=abc#abc" }',
        '{ url = "https://example.com/x-1.0.tar.gz" }',
        '{ path = "../x" }',
        '{ directory = "../x" }',
        '{ editable = "../x" }',
        '{ virtual = "../x" }',
    ],
)
def test_lock_source_other_than_pypi_is_red(source: str) -> None:
    text = CLEAN_LOCK.replace('{ registry = "https://pypi.org/simple" }', source)
    assert "foreign-source-dependency" in kinds(check_uv_lock("uv.lock", text))


def test_lock_extra_index_and_foreign_download_url_are_red() -> None:
    other_index = CLEAN_LOCK.replace("https://pypi.org/simple", "https://example.com/simple")
    assert "foreign-registry" in kinds(check_uv_lock("uv.lock", other_index))
    foreign_file = CLEAN_LOCK.replace("files.pythonhosted.org", "example.com")
    assert {v.key for v in check_uv_lock("uv.lock", foreign_file)} == {"line 7"}


def test_lock_credential_is_red() -> None:
    text = CLEAN_LOCK.replace("https://files.", "https://__token__:s3cret" + "@files.")
    assert "credential" in kinds(check_uv_lock("uv.lock", text))


# --- requirements*.txt ----------------------------------------------------------------------------


def test_requirements_rules() -> None:
    assert check_requirements("requirements.txt", "# c\nhttpx==0.28.1  # pin\n-r other.txt\n-c pins.txt\n\n") == []
    cases = {
        "--index-url https://example.com/simple": "foreign-registry",
        "--extra-index-url https://example.com/simple": "foreign-registry",
        "-i https://example.com/simple": "foreign-registry",
        "--find-links ./wheels": "foreign-registry",
        "-e ./local": "foreign-registry",
        "git+https://github.com/x/x": "foreign-source-dependency",
        "x @ https://example.com/x.whl": "foreign-source-dependency",
        "https://__token__:" + PYPI_TOKEN + "@example.com/x": "credential",
        "--trusted-host example.com": "foreign-registry",
        "-ihttps://example.com/simple": "foreign-registry",
        "-f./wheels": "foreign-registry",
        "dist/foo-1.0-py3-none-any.whl": "foreign-source-dependency",
        "foo-1.0.tar.gz": "foreign-source-dependency",
        "vendor/foo-1.0.zip ; python_version >= '3.12'": "foreign-source-dependency",
    }
    for line, kind in cases.items():
        assert kind in kinds(check_requirements("requirements.txt", line + "\n")), line


# --- conformance/ (npm side) ----------------------------------------------------------------------

CLEAN_MANIFEST = {
    "name": "c",
    "license": "Apache-2.0",
    "dependencies": {"@noblecloak/spec": "0.12.0"},
}


def manifest(**overrides: object) -> str:
    return json.dumps({**CLEAN_MANIFEST, **overrides})


def test_clean_manifest_passes() -> None:
    assert check_package_json("conformance/package.json", manifest()) == []


@pytest.mark.parametrize(
    "spec",
    [
        "git+https://github.com/x/x.git",
        "github:x/x",
        "x/x",
        "x/x#main",
        "file:../x",
        "link:../x",
        "https://example.com/x.tgz",
        "npm:git+https://github.com/x/x",
        "gitlab:x/x",
    ],
)
def test_foreign_npm_specifier_is_red(spec: str) -> None:
    for field in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        found = check_package_json("p.json", manifest(**{field: {"x": spec}}))
        assert [v.key for v in found] == [f"{field}.x"], spec


def test_registry_urls_and_aliases_on_the_public_registry_are_accepted() -> None:
    deps = {"a": "https://registry.npmjs.org/a/-/a-1.0.0.tgz", "b": "npm:a@1.0.0", "c": "^1.2.3"}
    assert check_package_json("p.json", manifest(dependencies=deps)) == []


def test_npm_license_and_publish_config_and_json_errors() -> None:
    assert kinds(check_package_json("p.json", manifest(license="MIT"))) == {"missing-apache-license"}
    pc = check_package_json("p.json", manifest(publishConfig={"registry": "https://npm.pkg.github.com"}))
    assert [v.key for v in pc] == ["publishConfig.registry"]
    ok = check_package_json("p.json", manifest(publishConfig={"registry": "https://registry.npmjs.org"}))
    assert ok == []
    assert kinds(check_package_json("p.json", "{")) == {"unreadable-file"}
    assert kinds(check_package_json("p.json", "[]")) == {"unreadable-file"}


@pytest.mark.parametrize(
    ("file", "line", "kind"),
    [
        (".npmrc", "//npm.pkg.github.com/:_authToken=abc", "credential"),
        (".npmrc", "_password=abc", "credential"),
        (".npmrc", "registry=https://npm.pkg.github.com", "foreign-registry"),
        (".npmrc", "registry=${REGISTRY}", "foreign-registry"),
        (".npmrc", "@noblecloak:registry=https://registry.npmjs.org", "foreign-registry"),
        (".npmrc", "${K}=${V}", "foreign-registry"),
        ("bunfig.toml", "token = 'abc'", "credential"),
        ("bunfig.toml", "[install.scopes]", "foreign-registry"),
        ("bunfig.toml", "[install.registry]", "foreign-registry"),
        ("bunfig.toml", "install.scopes.x = 'y'", "foreign-registry"),
        ("bunfig.toml", '"@noblecloak" = "https://registry.npmjs.org"', "foreign-registry"),
        ("bunfig.toml", "registry = 'https://example.com'", "foreign-registry"),
    ],
)
def test_npm_config_violations(file: str, line: str, kind: str) -> None:
    assert kind in kinds(check_npm_config(f"conformance/{file}", line + "\n"))


def test_npm_config_allows_the_public_registry_only() -> None:
    assert check_npm_config("conformance/.npmrc", "registry=https://registry.npmjs.org/\n# c\n") == []
    assert check_npm_config("conformance/bunfig.toml", '[install]\nregistry = "https://registry.npmjs.org"\n') == []


LOCK_LINE = '    "@noblecloak/spec": ["@noblecloak/spec@0.12.0", "", {}, "sha512-x"],'


@pytest.mark.parametrize(
    "line",
    [
        '    "x": ["x@./vendor/x.tgz", {}, ""],',
        '    "x": ["x@file:../x", {}],',
        '    "x": ["x@github:a/b", {}],',
        '    "x": ["x@git+https://github.com/a/b", {}],',
        '    "x": ["x", {}],',
        '    "x": ["x@1.0.0", "https://example.com/x.tgz", {}],',
        "    // https://example.com/x",
    ],
)
def test_bun_lock_violations(line: str) -> None:
    found = check_npm_config("conformance/bun.lock", line + "\n")
    assert kinds(found) == {"foreign-source-dependency"}


def test_bun_lock_accepts_registry_and_workspace_entries() -> None:
    text = (
        LOCK_LINE + '\n    "w": ["w@workspace:packages/w"],\n    "s": ["@s/x@1.0.0", "https://registry.npmjs.org/x"],\n'
    )
    assert check_npm_config("conformance/bun.lock", text) == []


# --- walk and CLI ---------------------------------------------------------------------------------


def write(root: Path, name: str, text: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_walk_dispatches_every_guarded_file_and_skips_vendored_directories(tmp_path: Path) -> None:
    write(tmp_path, "pyproject.toml", CLEAN_PYPROJECT)
    write(tmp_path, "uv.toml", "index-url = 'https://example.com'\n")
    write(tmp_path, "uv.lock", CLEAN_LOCK)
    write(tmp_path, "requirements-dev.txt", "git+https://github.com/x/x\n")
    write(tmp_path, "conformance/package.json", manifest(dependencies={"x": "file:../x"}))
    write(tmp_path, "conformance/.npmrc", "_authToken=abc\n")
    write(tmp_path, "conformance/bunfig.toml", "[install.scopes]\n")
    write(tmp_path, "conformance/bun.lock", '    "x": ["x@./x.tgz", {}],\n')
    write(tmp_path, ".pypirc", "[pypi]\n")
    write(tmp_path, "node_modules/p/package.json", manifest(license="MIT"))
    write(tmp_path, ".venv/pyproject.toml", "not toml = =")
    write(tmp_path, "pip.conf", "[global]\n")
    found = {(v.file, v.kind) for v in find_violations(tmp_path)}
    assert found == {
        ("uv.toml", "foreign-registry"),
        ("requirements-dev.txt", "foreign-source-dependency"),
        ("conformance/package.json", "foreign-source-dependency"),
        ("conformance/.npmrc", "credential"),
        ("conformance/bunfig.toml", "foreign-registry"),
        ("conformance/bun.lock", "foreign-source-dependency"),
        (".pypirc", "credential"),
        ("pip.conf", "credential"),
    }


def test_a_token_in_any_text_file_is_red(tmp_path: Path) -> None:
    write(tmp_path, "pyproject.toml", CLEAN_PYPROJECT)
    write(tmp_path, "src/pkg/__init__.py", f'_TOKEN = "{PYPI_TOKEN}"\n')
    write(tmp_path, ".github/workflows/ci.yml", f"# //registry.npmjs.org/:_authToken={NPM_TOKEN}\n")
    write(tmp_path, "README.md", "ok\n" + "\n".join(GITHUB_TOKENS) + "\n")
    write(tmp_path, "docs/notes.txt", f"see {URL_WITH_USER}\n")
    write(tmp_path, "src/pkg/clean.py", "x = 1  # https://pypi.org/simple\n")
    write(tmp_path, "node_modules/p/index.js", f"// {NPM_TOKEN}\n")
    (tmp_path / "blob.bin").write_bytes(b"\x00" + PYPI_TOKEN.encode())
    (tmp_path / "latin1.txt").write_bytes(b"\xff\xfe" + PYPI_TOKEN.encode())
    found = find_violations(tmp_path)
    readme = [Violation("README.md", f"line {n}", "credential") for n in range(2, 2 + len(GITHUB_TOKENS))]
    assert found == [
        Violation(".github/workflows/ci.yml", "line 1", "credential"),
        *readme,
        Violation("docs/notes.txt", "line 1", "credential"),
        Violation("src/pkg/__init__.py", "line 1", "credential"),
    ]


def test_run_guard_reports_ok_and_violations(tmp_path: Path) -> None:
    write(tmp_path, "pyproject.toml", CLEAN_PYPROJECT)
    write(tmp_path, "README.md", "hello\n")
    (tmp_path / "blob.bin").write_bytes(b"\x00")
    lines: list[str] = []
    assert run_guard(tmp_path, lines.append) == 0
    assert lines == ["private-dependency guard: OK (1 manifest files checked, 1 other files scanned for tokens)"]

    write(tmp_path, "pyproject.toml", with_pyproject("[tool.uv.sources]\nx = { path = '.' }"))
    lines = []
    assert run_guard(tmp_path, lines.append) == 1
    assert lines == [
        "pyproject.toml: tool.uv.sources - resolves from outside the public index (pypi.org / registry.npmjs.org)",
        "private-dependency guard: 1 violation(s)",
    ]


def test_the_tree_passes_the_guard() -> None:
    assert find_violations(ROOT) == []


def test_main_runs_over_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    write(tmp_path, "pyproject.toml", CLEAN_PYPROJECT)
    monkeypatch.chdir(tmp_path)
    assert main() == 0
    assert "OK" in capsys.readouterr().out
    write(tmp_path, ".pypirc", "")
    assert main() == 1
    assert ".pypirc: (file)" in capsys.readouterr().out


# --- any *.toml (uv reads UV_CONFIG_FILE / --config-file from any name) ---------------------------


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("index-url = 'https://pkgs.example.internal/simple'\n", "foreign-registry"),
        ("allow-insecure-host = ['pkgs.example.internal']\n", "foreign-registry"),
        ("[pip]\nextra-index-url = ['https://pkgs.example.internal/simple']\n", "foreign-registry"),
        ("[tool.uv]\nindex-url = 'https://pkgs.example.internal/simple'\n", "foreign-registry"),
        ("override-dependencies = ['x @ https://example.com/x.whl']\n", "foreign-source-dependency"),
        ("[tool.uv]\noverride-dependencies = ['git+https://github.com/x/x']\n", "foreign-source-dependency"),
        ("[tool.uv.sources]\nx = { path = '.' }\n", "foreign-source-dependency"),
        ("note = 'https://pkgs.example.internal/simple'\n", "foreign-registry"),
    ],
)
def test_a_uv_setting_in_any_toml_file_is_red(tmp_path: Path, text: str, kind: str) -> None:
    write(tmp_path, "pyproject.toml", CLEAN_PYPROJECT)
    write(tmp_path, "ci/uv-ci.toml", text)
    found = find_violations(tmp_path)
    assert {v.file for v in found} == {"ci/uv-ci.toml"}
    assert kind in kinds(found)


def test_a_clean_toml_file_passes_and_a_broken_one_is_unreadable(tmp_path: Path) -> None:
    write(tmp_path, "pyproject.toml", CLEAN_PYPROJECT)
    write(tmp_path, "ci/uv-ci.toml", "[pip]\nindex-strategy = 'first-index'\nlink-mode = 'copy'\n")
    assert find_violations(tmp_path) == []
    write(tmp_path, "ci/other.toml", "not toml = =")
    assert [(v.file, v.kind) for v in find_violations(tmp_path)] == [("ci/other.toml", "unreadable-file")]
    assert check_toml("c.toml", "[tool.x]\ny = 1\n") == []
    assert check_toml("c.toml", "tool = 1\n") == []


# --- token shape and git@ URLs -----------------------------------------------------------------------


def test_hyphenated_prose_is_not_a_pypi_token_but_a_real_shaped_token_is(tmp_path: Path) -> None:
    write(tmp_path, "pyproject.toml", CLEAN_PYPROJECT)
    write(tmp_path, "README.md", "Use the pypi-trusted-publishing-environment and pypi-publish-job-name-here.\n")
    assert find_violations(tmp_path) == []
    write(tmp_path, "README.md", f"token {PYPI_TOKEN}\n")
    assert find_violations(tmp_path) == [Violation("README.md", "line 1", "credential")]


def test_an_ssh_git_remote_is_not_a_credential_but_other_user_parts_are(tmp_path: Path) -> None:
    write(tmp_path, "pyproject.toml", CLEAN_PYPROJECT)
    write(tmp_path, "docs.md", "clone ssh://git@github.com/NobleCloak/noblecloak-py.git\n")
    assert find_violations(tmp_path) == []
    for line in (
        "clone ssh://deploy" + "@github.com/x/y.git",
        "clone https://git:hunter2" + "@github.com/x/y.git",
        "clone https://bob" + "@github.com/x/y.git",
        "clone https://git" + "@tok:secret" + "@host/x",
        "clone ssh://git" + "@evil" + "@host/x",
    ):
        write(tmp_path, "docs.md", line + "\n")
        assert find_violations(tmp_path) == [Violation("docs.md", "line 1", "credential")], line


# --- unreadable guarded files ---------------------------------------------------------------------


@pytest.mark.parametrize("name", ["requirements-ci.txt", "pyproject.toml", "uv.lock", "conformance/package.json"])
def test_a_guarded_file_that_is_not_utf8_is_an_unreadable_file_violation(tmp_path: Path, name: str) -> None:
    write(tmp_path, "pyproject.toml", CLEAN_PYPROJECT)
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\xff\xfe" + b"httpx==0.28.1\n")
    assert Violation(name, "(file)", "unreadable-file") in find_violations(tmp_path)
    lines: list[str] = []
    assert run_guard(tmp_path, lines.append) == 1
    assert any(line.startswith(f"{name}: (file) - ") for line in lines)


# --- requirements inputs and constraint files -----------------------------------------------------


@pytest.mark.parametrize(
    ("name", "text", "kind"),
    [
        ("requirements.in", "--index-url https://pkgs.example.internal/simple\nhttpx\n", "foreign-registry"),
        ("requirements-dev.in", "git+https://github.com/x/x\n", "foreign-source-dependency"),
        ("constraints.txt", "git+https://github.com/x/x\n", "foreign-source-dependency"),
        ("constraints-ci.txt", "--extra-index-url https://x/simple\n", "foreign-registry"),
        ("requirements-ci.txt", "-i https://x/simple\n", "foreign-registry"),
    ],
)
def test_requirements_inputs_and_constraint_files_are_guarded(tmp_path: Path, name: str, text: str, kind: str) -> None:
    write(tmp_path, "pyproject.toml", CLEAN_PYPROJECT)
    write(tmp_path, name, text)
    assert {(v.file, v.kind) for v in find_violations(tmp_path)} == {(name, kind)}


def test_clean_requirements_inputs_and_constraints_pass(tmp_path: Path) -> None:
    write(tmp_path, "pyproject.toml", CLEAN_PYPROJECT)
    write(tmp_path, "requirements.in", "httpx==0.28.1\n-c constraints.txt\n")
    write(tmp_path, "constraints.txt", "httpx==0.28.1  # pin\n")
    write(tmp_path, "notes-constraints.md", "git+https://example.com is prose here\n")
    assert find_violations(tmp_path) == []
