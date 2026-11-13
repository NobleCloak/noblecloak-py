"""contract.json, conformance/ and noblecloak.__contract_revision__ must name the same contract."""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import noblecloak

ROOT = Path(__file__).resolve().parent.parent
REVISION = re.compile(r"contract-v\d+-rev\d+")
EXACT_VERSION = re.compile(r"\d+\.\d+\.\d+(?:-[\w.]+)?")
PACKAGES = ("@noblecloak/client", "@noblecloak/spec")


def lock_version(lock_text: str, package: str) -> str | None:
    """The version bun.lock resolved `package` to (the `"name@version"` head of its entry)."""
    match = re.search(rf'^ {{4}}"{re.escape(package)}":\s*\[\s*"{re.escape(package)}@([^"]+)"', lock_text, re.M)
    return match.group(1) if match else None


def contract_violations(contract: dict[str, Any], manifest: dict[str, Any], lock_text: str, revision: str) -> list[str]:
    """Every way the three records disagree, one line each."""
    found: list[str] = []
    if contract.get("phase") != "registry":
        found.append("contract.json phase is not 'registry'")
    declared = contract.get("contractRevision")
    if not isinstance(declared, str) or not REVISION.fullmatch(declared):
        found.append("contract.json contractRevision is not a contract-vN-revM label")
    if declared != revision:
        found.append(f"contractRevision {declared!r} != noblecloak.__contract_revision__ {revision!r}")
    packages: dict[str, Any] = contract.get("packages", {})
    if sorted(packages) != list(PACKAGES):
        found.append(f"contract.json packages are {sorted(packages)}, expected {list(PACKAGES)}")
    versions: dict[str, str] = {}
    for name in PACKAGES:
        version = packages.get(name, {}).get("version")
        if not isinstance(version, str) or not EXACT_VERSION.fullmatch(version):
            found.append(f"contract.json {name} version is not an exact version")
        else:
            versions[name] = version
    spec = versions.get("@noblecloak/spec")
    if manifest.get("dependencies") != {"@noblecloak/spec": spec}:
        found.append(f"conformance/package.json must depend on exactly @noblecloak/spec {spec!r}")
    for name, version in versions.items():
        locked = lock_version(lock_text, name)
        if locked != version:
            found.append(f"conformance/bun.lock resolves {name} to {locked!r}, contract.json says {version!r}")
    return found


def load() -> tuple[dict[str, Any], dict[str, Any], str]:
    contract = json.loads((ROOT / "contract.json").read_text(encoding="utf-8"))
    manifest = json.loads((ROOT / "conformance/package.json").read_text(encoding="utf-8"))
    return contract, manifest, (ROOT / "conformance/bun.lock").read_text(encoding="utf-8")


def test_contract_json_conformance_and_revision_agree() -> None:
    contract, manifest, lock = load()
    assert contract_violations(contract, manifest, lock, noblecloak.__contract_revision__) == []


def test_contract_json_has_exactly_the_documented_keys() -> None:
    contract, _, _ = load()
    assert sorted(contract) == ["contractRevision", "packages", "phase"]
    assert all(sorted(entry) == ["version"] for entry in contract["packages"].values())


def test_conformance_pins_spec_exactly_and_is_private() -> None:
    _, manifest, _ = load()
    assert manifest["private"] is True
    assert re.fullmatch(r"\d+\.\d+\.\d+", manifest["dependencies"]["@noblecloak/spec"])


MUTATIONS: dict[str, tuple[str, Callable[[dict[str, Any]], object]]] = {
    "revision drifts in contract.json": ("contract", lambda c: c.update(contractRevision="contract-v1-rev16")),
    "revision is not a label": ("contract", lambda c: c.update(contractRevision="rev18")),
    "phase changes": ("contract", lambda c: c.update(phase="github-packages")),
    "spec version drifts in contract.json": (
        "contract",
        lambda c: c["packages"]["@noblecloak/spec"].update(version="0.11.0"),
    ),
    "client version drifts in contract.json": (
        "contract",
        lambda c: c["packages"]["@noblecloak/client"].update(version="0.11.0"),
    ),
    "spec version is a range": (
        "contract",
        lambda c: c["packages"]["@noblecloak/spec"].update(version="^0.12.0"),
    ),
    "a package is dropped": ("contract", lambda c: c["packages"].pop("@noblecloak/client")),
    "conformance spec pin drifts": (
        "manifest",
        lambda m: m["dependencies"].update({"@noblecloak/spec": "0.11.0"}),
    ),
    "conformance gains a dependency": ("manifest", lambda m: m["dependencies"].update(extra="1.0.0")),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_a_disagreement_turns_the_check_red(name: str) -> None:
    target, mutate = MUTATIONS[name]
    contract, manifest, lock = load()
    contract, manifest = copy.deepcopy(contract), copy.deepcopy(manifest)
    mutate(contract if target == "contract" else manifest)
    assert contract_violations(contract, manifest, lock, noblecloak.__contract_revision__) != []


def test_a_package_revision_that_differs_from_contract_json_turns_the_check_red() -> None:
    contract, manifest, lock = load()
    assert contract_violations(contract, manifest, lock, "contract-v1-rev99") != []


def test_a_lock_that_resolves_another_version_turns_the_check_red() -> None:
    contract, manifest, lock = load()
    stale = lock.replace('"@noblecloak/spec@0.12.0"', '"@noblecloak/spec@0.11.0"')
    assert stale != lock
    assert contract_violations(contract, manifest, stale, noblecloak.__contract_revision__) != []
    assert lock_version("", "@noblecloak/spec") is None
