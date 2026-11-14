"""Checks that the package and the CLI use the continuum-github names."""

import importlib
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).parent.parent
OLD_NAMES = ("continuum" + "-scan", "continuum" + "_scan")


def _tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout
    return [
        ROOT / name
        for name in out.splitlines()
        if not name.startswith("docs/superpowers/") and name != "uv.lock"
    ]


def test_entry_point_is_continuum_github() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert project["project"]["scripts"] == {
        "continuum-github": "continuum_github.cli:main"
    }
    module = importlib.import_module("continuum_github.cli")
    assert callable(module.main)


def test_no_tracked_file_uses_the_old_names() -> None:
    for path in _tracked_files():
        if path.is_file():
            text = path.read_text(errors="ignore")
            for old in OLD_NAMES:
                assert old not in text, f"{path.relative_to(ROOT)}: {old}"


def test_state_marker_keeps_its_name() -> None:
    from continuum_github import state

    assert state._PREFIX == "<!-- continuum-state: "  # pyright: ignore[reportPrivateUsage]
