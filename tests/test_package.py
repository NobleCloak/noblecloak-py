"""The package surface U1 ships: a version, the contract revision, and the typing marker."""

import re
import tomllib
from importlib import metadata, resources
from pathlib import Path

import noblecloak


def test_version_is_a_semver_string() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", noblecloak.__version__)


def test_contract_revision_has_the_label_shape() -> None:
    assert re.fullmatch(r"contract-v\d+-rev\d+", noblecloak.__contract_revision__)


def test_package_ships_the_typing_marker() -> None:
    assert resources.files("noblecloak").joinpath("py.typed").is_file()


def test_installed_metadata_version_is_the_module_version() -> None:
    """The version has one source, `__version__`; after bumping it, re-run `uv sync` to refresh the metadata."""
    assert metadata.version("noblecloak") == noblecloak.__version__


def test_pyproject_takes_the_version_from_the_module() -> None:
    pyproject = tomllib.loads((Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8"))
    assert "version" not in pyproject["project"]
    assert "version" in pyproject["project"]["dynamic"]
    assert pyproject["tool"]["hatch"]["version"] == {"path": "src/noblecloak/__init__.py"}
