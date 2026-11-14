"""Tests that no owner-specific value reaches the public repository."""

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent

# Each pattern wraps one character in a class so that this file never
# matches its own patterns.
FORBIDDEN = [
    pytest.param(r"0703925994[4]2", id="account-id"),
    pytest.param(r"[@]rewse", id="mention"),
    pytest.param(r"86895[1]", id="owner-id"),
    pytest.param(r"138966822[4]", id="actions-repository-id"),
    pytest.param(r"7411515[4]", id="dotfiles-repository-id"),
    pytest.param(r"142661354[1]", id="repository-id"),
    pytest.param(r"\b[f]ox\b", id="host-name"),
    pytest.param(r"rewse\.j[p]", id="domain"),
]


def _repository_files() -> list[Path]:
    # Untracked files count too, so the check holds before the first commit.
    output = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [ROOT / name for name in output.split("\0") if name]


@pytest.mark.parametrize("pattern", FORBIDDEN)
def test_no_file_contains_the_pattern(pattern: str) -> None:
    regex = re.compile(pattern)
    matches = [
        str(path.relative_to(ROOT))
        for path in _repository_files()
        if path.is_file() and regex.search(path.read_text(errors="replace"))
    ]
    assert matches == []
