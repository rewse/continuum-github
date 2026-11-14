"""Checks on the setup guide."""

from pathlib import Path

ROOT = Path(__file__).parent.parent


def test_setup_tells_upgraders_to_drop_the_kiro_secret() -> None:
    setup = (ROOT / "docs/setup.md").read_text()
    assert "kiro-api-key" in setup
    assert "gh secret delete KIRO_API_KEY --repo example-org/security-findings" in setup


def test_setup_tells_upgraders_to_keep_japanese() -> None:
    setup = (ROOT / "docs/setup.md").read_text()
    assert (
        "gh variable set LANGUAGE --repo example-org/security-findings --body ja_JP"
        in setup
    )
    for name in ("README.md", "docs/setup.md"):
        assert "Japanese visual report" not in (ROOT / name).read_text()


MODEL_ID = "global.anthropic.claude-sonnet-5-5"


def test_docs_recommend_the_global_inference_profile() -> None:
    names = ("README.md", "docs/setup.md", "sync/action.yml", "report/action.yml")
    for name in names:
        text = (ROOT / name).read_text()
        assert "us.anthropic" not in text, name
        assert MODEL_ID in text, name
    setup = (ROOT / "docs/setup.md").read_text()
    assert (
        f"gh variable set BEDROCK_MODEL_ID --repo example-org/security-findings --body {MODEL_ID}"
        in setup
    )
    assert "runs only in US Regions" not in setup
