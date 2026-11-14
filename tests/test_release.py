"""Checks on the release workflow and the release notes configuration."""

import re
import tomllib
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
PINNED_USE = re.compile(r"^[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40}$")
USE_LINE = re.compile(r"^\s*(?:- )?uses: \S+@[0-9a-f]{40}  # v\d+\.\d+\.\d+$")


def _load(name: str) -> dict[Any, Any]:
    return yaml.safe_load((WORKFLOWS / name).read_text())


def _steps(name: str) -> list[dict[str, Any]]:
    (job,) = _load(name)["jobs"].values()
    return job["steps"]


def _index(steps: list[dict[str, Any]], predicate: Any) -> int:
    (index,) = [i for i, step in enumerate(steps) if predicate(step)]
    return index


def test_release_runs_only_on_version_tags() -> None:
    workflow = _load("release.yml")
    assert workflow[True] == {"push": {"tags": ["v*"]}}


def test_release_has_only_contents_write() -> None:
    (job,) = _load("release.yml")["jobs"].values()
    assert job["permissions"] == {"contents": "write"}
    assert "environment" not in job


def test_release_does_not_publish_to_pypi() -> None:
    assert "pypi" not in (WORKFLOWS / "release.yml").read_text().lower()


def test_release_verifies_the_tag_and_uploads_the_build() -> None:
    runs = "\n".join(s.get("run", "") for s in _steps("release.yml"))
    assert "uv build" in runs
    assert "--verify-tag" in runs
    assert "dist/*" in runs


def test_release_sets_up_safe_chain_before_building() -> None:
    steps = _steps("release.yml")
    safe_chain = _index(
        steps, lambda s: s.get("uses", "").startswith("rewse/actions/setup-safe-chain@")
    )
    build = _index(steps, lambda s: "uv build" in s.get("run", ""))
    assert safe_chain < build


def test_release_pins_every_action_with_a_version_comment() -> None:
    for step in _steps("release.yml"):
        if "uses" in step:
            assert PINNED_USE.fullmatch(step["uses"]), step["uses"]
    text = (WORKFLOWS / "release.yml").read_text()
    for line in text.splitlines():
        if "uses:" in line:
            assert USE_LINE.fullmatch(line), line


def test_release_keeps_expressions_out_of_run_scripts() -> None:
    for step in _steps("release.yml"):
        assert "${{" not in step.get("run", ""), step.get("name")


def test_release_notes_skip_version_bumps() -> None:
    parsers = tomllib.loads((ROOT / "cliff.toml").read_text())["git"]["commit_parsers"]
    assert {"message": "^chore: bump version", "skip": True} in parsers
