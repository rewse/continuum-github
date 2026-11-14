"""Tests that the package version has a single source."""

import re
import tomllib
from pathlib import Path

import continuum_github

ROOT = Path(__file__).parent.parent
VERSION_FILE = ROOT / "src" / "continuum_github" / "__init__.py"


def test_package_version_is_the_line_the_bump_script_rewrites() -> None:
    # scripts/bump_version.sh rewrites exactly this line, so the value
    # changes with every release and is not pinned here.
    (version,) = re.findall(
        r'^__version__ = "(\d+\.\d+\.\d+)"$', VERSION_FILE.read_text(), re.MULTILINE
    )
    assert continuum_github.__version__ == version


def test_pyproject_reads_the_version_from_the_module() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert "version" not in project["project"]
    assert project["project"]["dynamic"] == ["version"]
    assert project["tool"]["hatch"]["version"] == {
        "path": "src/continuum_github/__init__.py"
    }
