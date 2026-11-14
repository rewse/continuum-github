"""Checks on the setup guide."""

from pathlib import Path

ROOT = Path(__file__).parent.parent


def test_setup_tells_upgraders_to_drop_the_kiro_secret() -> None:
    setup = (ROOT / "docs/setup.md").read_text()
    assert "kiro-api-key" in setup
    assert "gh secret delete KIRO_API_KEY --repo example-org/security-findings" in setup
