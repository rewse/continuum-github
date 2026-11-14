"""Tests that cooldown exemptions in pyproject.toml are removed on time."""

import datetime
import tomllib
from pathlib import Path

PYPROJECT = Path(__file__).parent.parent / "pyproject.toml"

# The day each exemption from the uv cooldown must be gone. A package frozen
# at an exemption cutoff never receives later releases, so a forgotten entry
# blocks future security fixes.
EXEMPTION_EXPIRY: dict[str, datetime.date] = {}


def test_every_cooldown_exemption_has_an_expiry():
    with PYPROJECT.open("rb") as f:
        exempt = tomllib.load(f)["tool"]["uv"].get("exclude-newer-package", {})
    assert set(exempt) <= set(EXEMPTION_EXPIRY)


def test_cooldown_exemptions_are_removed_after_expiry():
    with PYPROJECT.open("rb") as f:
        exempt = tomllib.load(f)["tool"]["uv"].get("exclude-newer-package", {})
    today = datetime.datetime.now(tz=datetime.UTC).date()
    expired = sorted(p for p in exempt if today >= EXEMPTION_EXPIRY[p])
    assert not expired, (
        f"Remove {expired} from [tool.uv] exclude-newer-package in "
        "pyproject.toml and from EXEMPTION_EXPIRY, then run uv lock"
    )
