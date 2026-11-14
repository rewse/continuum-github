"""Tests that the package version has a single source."""

import importlib.metadata
import tomllib
from pathlib import Path

import continuum_scan

ROOT = Path(__file__).parent.parent


def test_package_version_comes_from_the_module() -> None:
    assert continuum_scan.__version__ == "0.1.1"
    assert importlib.metadata.version("continuum-github") == continuum_scan.__version__


def test_pyproject_reads_the_version_from_the_module() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert "version" not in project["project"]
    assert project["project"]["dynamic"] == ["version"]
    assert project["tool"]["hatch"]["version"] == {
        "path": "src/continuum_scan/__init__.py"
    }
