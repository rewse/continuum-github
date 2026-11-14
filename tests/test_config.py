"""Tests for loading scan targets and settings."""

from pathlib import Path

import pytest

from continuum_scan.config import Repository
from continuum_scan.config import Settings
from continuum_scan.config import Site
from continuum_scan.config import Targets
from continuum_scan.config import code_review_title
from continuum_scan.config import environment_name
from continuum_scan.config import load_settings
from continuum_scan.config import load_targets

TARGETS = Path(__file__).parent / "targets.toml"


def test_load_targets_reads_repositories_and_sites() -> None:
    targets = load_targets(TARGETS)
    assert targets.owner == "example-org"
    assert len(targets.repositories) == 5
    assert targets.get("api").private is True
    assert targets.get("web").private is False
    assert sum(r.private for r in targets.repositories) == 2
    assert len(targets.sites) == 3
    assert {s.repository for s in targets.sites} == {"api", "web"}


def test_site_repository_must_be_a_target(tmp_path: Path) -> None:
    path = tmp_path / "t.toml"
    path.write_text(
        'owner = "example-org"\n[[repositories]]\nname = "a"\nprivate = false\n'
        '[[sites]]\ndomain = "x.example.com"\npentest = "weekly-x"\nrepository = "b"\n'
    )
    with pytest.raises(ValueError, match="Unknown repository: b"):
        load_targets(path)


def test_private_flag_must_be_a_boolean(tmp_path: Path) -> None:
    path = tmp_path / "t.toml"
    path.write_text(
        'owner = "example-org"\n[[repositories]]\nname = "a"\nprivate = "false"\n'
    )
    with pytest.raises(TypeError):
        load_targets(path)


def test_load_settings_defaults_and_requirements() -> None:
    with pytest.raises(ValueError, match="AGENT_SPACE_ID"):
        load_settings({"GITHUB_TOKEN": "t", "REPORT_REPOSITORY": "o/r"})
    settings = load_settings(
        {"AGENT_SPACE_ID": "as-1", "GITHUB_TOKEN": "t", "REPORT_REPOSITORY": "o/r"}
    )
    assert settings.region == "us-east-1"
    assert settings.report_repository == "o/r"
    assert settings.mention == ""
    assert settings.kiro_cli == Path.home() / ".local/bin/kiro-cli"
    assert settings.kiro_model is None
    assert settings.visual_explainer_dir == Path(
        "node_modules/visual-explainer/plugins/visual-explainer"
    )


def test_environment_name_uses_the_owner() -> None:
    assert environment_name("example-org", "api") == "example-org-api"
    assert environment_name("example-org", "web-app") == "example-org-web-app"


def test_settings_require_the_report_repository() -> None:
    with pytest.raises(ValueError, match="REPORT_REPOSITORY"):
        load_settings({"AGENT_SPACE_ID": "as-1", "GITHUB_TOKEN": "t"})


def test_settings_read_the_mention() -> None:
    env = {"AGENT_SPACE_ID": "as-1", "GITHUB_TOKEN": "t", "REPORT_REPOSITORY": "o/r"}
    assert load_settings(env).mention == ""
    assert load_settings({**env, "MENTION": "@octocat"}).mention == "@octocat"


def test_sites_keep_the_file_order() -> None:
    targets = load_targets(TARGETS)
    assert targets.sites[0] == Site("www.example.com", "weekly-www-example-com", "web")
    assert [s.domain for s in targets.sites] == [
        "www.example.com",
        "api.example.com",
        "example.com",
    ]


def test_get_unknown_repository_raises_value_error() -> None:
    targets = Targets("o", (Repository("a", False),), ())
    assert targets.get("a") == Repository("a", False)
    with pytest.raises(ValueError, match="Unknown repository: nope"):
        targets.get("nope")


def test_load_settings_requires_github_token() -> None:
    with pytest.raises(ValueError, match="GITHUB_TOKEN"):
        load_settings({"AGENT_SPACE_ID": "as-1", "REPORT_REPOSITORY": "o/r"})


def test_load_settings_overrides() -> None:
    settings = load_settings(
        {
            "AGENT_SPACE_ID": "as-1",
            "AWS_REGION": "ap-northeast-1",
            "GITHUB_TOKEN": "t",
            "KIRO_CLI": "/opt/kiro-cli",
            "KIRO_MODEL": "m",
            "MENTION": "@octocat",
            "REPORT_REPOSITORY": "o/r",
            "VISUAL_EXPLAINER_DIR": "/ve",
        }
    )
    assert settings == Settings(
        agent_space_id="as-1",
        region="ap-northeast-1",
        report_repository="o/r",
        github_token="t",
        kiro_cli=Path("/opt/kiro-cli"),
        kiro_model="m",
        mention="@octocat",
        visual_explainer_dir=Path("/ve"),
    )


def test_load_settings_treats_empty_kiro_model_as_none() -> None:
    settings = load_settings(
        {
            "AGENT_SPACE_ID": "as-1",
            "GITHUB_TOKEN": "t",
            "KIRO_MODEL": "",
            "REPORT_REPOSITORY": "o/r",
        }
    )
    assert settings.kiro_model is None


def test_code_review_title_replaces_characters_security_agent_rejects() -> None:
    assert code_review_title(".github") == "weekly-_github"
    assert code_review_title("textlint-config") == "weekly-textlint-config"
