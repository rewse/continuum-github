"""Scan targets and runtime settings."""

import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

DEFAULT_REGION = "us-east-1"
DEFAULT_LANGUAGE = "en_US"
# The language goes into model prompts, so only a bare locale is accepted.
LANGUAGE_RE = re.compile(r"[a-z]{2,3}(_[A-Z]{2})?")
DEFAULT_VISUAL_EXPLAINER_DIR = Path(
    "node_modules/visual-explainer/plugins/visual-explainer"
)


@dataclass(frozen=True)
class Repository:
    name: str
    private: bool


@dataclass(frozen=True)
class Site:
    """A site, the pentest that covers it, and the repository that receives
    its findings."""

    domain: str
    pentest: str
    repository: str


@dataclass(frozen=True)
class Targets:
    owner: str
    repositories: tuple[Repository, ...]
    sites: tuple[Site, ...]

    def get(self, name: str) -> Repository:
        for repository in self.repositories:
            if repository.name == name:
                return repository
        raise ValueError(f"Unknown repository: {name}")


@dataclass(frozen=True)
class Settings:
    agent_space_id: str
    region: str
    report_repository: str
    github_token: str
    bedrock_model_id: str | None
    bedrock_region: str
    mention: str
    visual_explainer_dir: Path
    language: str = DEFAULT_LANGUAGE


def _language(env: Mapping[str, str]) -> str:
    """Returns CONTINUUM_LANGUAGE, or the default when it is unset or empty.

    Raises:
        ValueError: the value is not a locale such as ja or ja_JP.
    """
    value = env.get("CONTINUUM_LANGUAGE") or DEFAULT_LANGUAGE
    if not LANGUAGE_RE.fullmatch(value):
        raise ValueError("CONTINUUM_LANGUAGE must be a locale such as ja_JP")
    return value


def _repository(entry: Mapping[str, object]) -> Repository:
    name = entry["name"]
    private = entry["private"]
    # A quoted "false" is truthy and would route findings to a public issue.
    if not isinstance(name, str) or not isinstance(private, bool):
        raise TypeError(f"Repository {name!r} needs a boolean private flag")
    return Repository(name=name, private=private)


def load_targets(path: Path) -> Targets:
    with path.open("rb") as f:
        data = tomllib.load(f)
    targets = Targets(
        owner=data["owner"],
        repositories=tuple(_repository(r) for r in data["repositories"]),
        sites=tuple(
            Site(domain=s["domain"], pentest=s["pentest"], repository=s["repository"])
            for s in data.get("sites", ())
        ),
    )
    # Raises ValueError when a site repository is not a scan target.
    for site in targets.sites:
        targets.get(site.repository)
    return targets


def _require(env: Mapping[str, str], key: str) -> str:
    value = env.get(key)
    if not value:
        raise ValueError(f"Environment variable {key} is required")
    return value


def load_settings(env: Mapping[str, str]) -> Settings:
    """Reads settings from the environment."""
    visual_explainer_dir = env.get("VISUAL_EXPLAINER_DIR")
    region = env.get("AWS_REGION") or DEFAULT_REGION
    return Settings(
        agent_space_id=_require(env, "AGENT_SPACE_ID"),
        region=region,
        report_repository=_require(env, "REPORT_REPOSITORY"),
        github_token=_require(env, "GITHUB_TOKEN"),
        # An unset workflow variable arrives as an empty string and turns
        # the model off.
        bedrock_model_id=env.get("BEDROCK_MODEL_ID") or None,
        bedrock_region=env.get("BEDROCK_REGION") or region,
        mention=env.get("MENTION", ""),
        visual_explainer_dir=(
            Path(visual_explainer_dir)
            if visual_explainer_dir
            else DEFAULT_VISUAL_EXPLAINER_DIR
        ),
        language=_language(env),
    )


def environment_name(owner: str, repository: str) -> str:
    """Returns the Continuum environment name for a repository of owner."""
    return f"{owner}-{repository}"


def code_review_title(repository: str) -> str:
    """Returns the Security Agent code review title for a repository.

    Security Agent accepts only letters, digits, "-", and "_" in a title, so
    every other character becomes "_".
    """
    return "weekly-" + re.sub(r"[^A-Za-z0-9_-]", "_", repository)
