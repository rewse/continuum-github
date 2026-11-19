"""Command line entry points."""

import argparse
import dataclasses
import json
import os
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC
from datetime import datetime
from pathlib import Path
from typing import Any

import boto3
import httpx
from botocore.config import Config

from continuum_github.bedrock import Bedrock
from continuum_github.bedrock import bedrock_client
from continuum_github.bedrock import severity_summaries
from continuum_github.codereview import CodeReviewClient
from continuum_github.codevuln import CodeVulnClient
from continuum_github.config import DEFAULT_REGION
from continuum_github.config import Settings
from continuum_github.config import Targets
from continuum_github.config import load_settings
from continuum_github.config import load_targets
from continuum_github.github import GitHub
from continuum_github.models import Severity
from continuum_github.pentest import PentestClient
from continuum_github.records import records_from_issues
from continuum_github.report import WeeklyData
from continuum_github.report import build_visual_report
from continuum_github.report import build_weekly
from continuum_github.report import publish_weekly
from continuum_github.report import render_weekly
from continuum_github.report import unavailable_parts
from continuum_github.setup import configure_pr_review
from continuum_github.setup import ensure_code_reviews
from continuum_github.setup import ensure_collector
from continuum_github.setup import ensure_environments
from continuum_github.setup import label_definitions
from continuum_github.sync import SyncCounts
from continuum_github.sync import collect_scans
from continuum_github.sync import fill_sections
from continuum_github.sync import run_sync
from continuum_github.sync import start_code_reviews

DEFAULT_TARGETS = Path("targets.toml")
GITHUB_API = "https://api.github.com"
GITHUB_TIMEOUT_SECONDS = 30
_AWS_CONFIG = Config(connect_timeout=10, read_timeout=60, retries={"mode": "standard"})


@contextmanager
def _github_for(token: str, repository: str) -> Iterator[GitHub]:
    with httpx.Client(
        base_url=GITHUB_API,
        headers={"Authorization": f"Bearer {token}"},
        timeout=GITHUB_TIMEOUT_SECONDS,
    ) as client:
        yield GitHub(client, repository)


@contextmanager
def _github(settings: Settings) -> Iterator[GitHub]:
    with _github_for(settings.github_token, settings.report_repository) as github:
        yield github


def _security_agent_client(region: str) -> Any:
    return boto3.client("securityagent", region_name=region, config=_AWS_CONFIG)


def _continuum_client(region: str) -> Any:
    return boto3.client("continuum", region_name=region, config=_AWS_CONFIG)


@contextmanager
def _clients(
    settings: Settings,
) -> Iterator[tuple[GitHub, PentestClient, CodeVulnClient, CodeReviewClient]]:
    security_agent = _security_agent_client(settings.region)
    pentest = PentestClient(security_agent, settings.agent_space_id)
    code_vuln = CodeVulnClient(_continuum_client(settings.region))
    code_review = CodeReviewClient(security_agent, settings.agent_space_id)
    with _github(settings) as github:
        yield github, pentest, code_vuln, code_review


def _sync(settings: Settings, targets: Targets) -> SyncCounts:
    with _clients(settings) as (github, pentest, code_vuln, code_review):
        started, start_failed = start_code_reviews(
            targets, code_review, datetime.now(UTC)
        )
        counts = run_sync(
            targets, github, pentest, code_vuln, code_review, settings.mention
        )
    return dataclasses.replace(
        counts, started=started, failed=counts.failed + start_failed
    )


def _model(settings: Settings) -> Bedrock | None:
    """Returns the Bedrock model, or None when no model ID is set."""
    if settings.bedrock_model_id is None:
        return None
    return Bedrock(
        bedrock_client(settings.bedrock_region),
        settings.bedrock_model_id,
        # A page call can run for the whole read timeout, and the report may
        # ask twice; more attempts would outlast the report job's timeout.
        page_client=bedrock_client(settings.bedrock_region, attempts=1),
    )


def _sections(settings: Settings, targets: Targets) -> int:
    model = _model(settings)
    if model is None:
        return 0
    with _clients(settings) as (github, pentest, code_vuln, code_review):
        return fill_sections(
            targets,
            github,
            pentest,
            code_vuln,
            code_review,
            model,
            settings.mention,
            settings.language,
        )


def _build_report(
    settings: Settings, targets: Targets, model: Bedrock | None
) -> tuple[WeeklyData, dict[Severity, str], dict[Severity, str]]:
    """Returns the week's data, the model's summaries, and why any are missing."""
    with _clients(settings) as (github, pentest, code_vuln, code_review):
        records = records_from_issues(github.issues())
        scans = collect_scans(targets, pentest, code_vuln, code_review)
    data = build_weekly(records, scans, datetime.now(UTC), settings.pentest_max_age)
    if model is None:
        return data, {}, {}
    summaries, failures = severity_summaries(model, data, settings.language)
    return data, summaries, failures


def _publish(
    settings: Settings,
    title: str,
    body: str,
    comments: list[str],
    html_url: str | None,
) -> str:
    with _github(settings) as github:
        return publish_weekly(github, title, body, comments, html_url)


def _report_build(settings: Settings, targets: Targets, out: Path) -> None:
    model = _model(settings)
    data, summaries, failures = _build_report(settings, targets, model)
    out.mkdir(parents=True, exist_ok=True)
    if model is None:
        # A file left by an earlier run must not be uploaded.
        (out / "report.html").unlink(missing_ok=True)
        html = False
        unavailable: list[str] = []
    else:
        html_failure = build_visual_report(
            model,
            data,
            settings.visual_explainer_dir,
            out / "report.html",
            language=settings.language,
        )
        html = html_failure is None
        unavailable = unavailable_parts(data, summaries, failures, html_failure)
    body, comments = render_weekly(data, summaries, unavailable)
    (out / "body.md").write_text(body, encoding="utf-8")
    (out / "comments.json").write_text(json.dumps(comments), encoding="utf-8")
    (out / "title.txt").write_text(data.title, encoding="utf-8")
    opened = sum(row[0] for row in data.counts.values())
    new = sum(row[1] for row in data.counts.values())
    closed = sum(row[2] for row in data.counts.values())
    # Only counts are printed; finding details never reach the workflow log.
    print(
        f"open={opened} new={new} closed={closed} "
        f"incomplete={len(data.incomplete)} html={int(html)}"
    )


def _report_publish(settings: Settings, directory: Path, html_url: str) -> None:
    title = (directory / "title.txt").read_text(encoding="utf-8").strip()
    body = (directory / "body.md").read_text(encoding="utf-8")
    comments = json.loads((directory / "comments.json").read_text(encoding="utf-8"))
    if not isinstance(comments, list) or not all(
        isinstance(text, str) for text in comments
    ):
        raise ValueError("comments.json must be a list of strings")
    result = _publish(settings, title, body, comments, html_url or None)
    print(f"published={result}")


def _ensure_labels(
    token: str, repository: str, labels: dict[str, tuple[str, str]]
) -> int:
    with _github_for(token, repository) as github:
        return github.ensure_labels(labels)


def _configure_pr_review(
    region: str, agent_space_id: str, integration_id: str, targets: Targets
) -> int:
    return configure_pr_review(
        _security_agent_client(region), agent_space_id, integration_id, targets
    )


def _configure_code_review(
    region: str,
    agent_space_id: str,
    integration_id: str,
    role_arn: str,
    targets: Targets,
) -> tuple[int, int]:
    return ensure_code_reviews(
        _security_agent_client(region),
        agent_space_id,
        integration_id,
        role_arn,
        targets,
    )


def _configure_code_vuln(
    region: str,
    targets: Targets,
    integration_id: str,
    role_arn: str | None,
    collector_repository: str | None,
) -> tuple[int, str | None]:
    """Sets up the private environments and the optional AWS collector.

    The collector is attached to the environment of `collector_repository`;
    without one, no collector is created and the ARN is None.
    """
    client = _continuum_client(region)
    environments = ensure_environments(client, targets, integration_id)
    if collector_repository is None or role_arn is None:
        return len(environments), None
    collector_arn = ensure_collector(
        client, environments[collector_repository], role_arn
    )
    return len(environments), collector_arn


def _check_collector_repository(
    targets: Targets, repository: str | None, role_arn: str | None
) -> None:
    if repository is None:
        return
    if not any(r.private and r.name == repository for r in targets.repositories):
        raise ValueError(
            f"--collector-repository {repository} is not a private repository "
            "in targets"
        )
    if not role_arn:
        raise ValueError("--collector-role-arn is required with --collector-repository")


def _require_env(key: str) -> str:
    value = os.environ.get(key)
    if not value:
        raise ValueError(f"Environment variable {key} is required")
    return value


def _setup(args: argparse.Namespace) -> None:
    # Setup reads only the environment variables each subcommand needs.
    targets = load_targets(args.targets)
    region = os.environ.get("AWS_REGION") or DEFAULT_REGION
    if args.setup_command == "labels":
        created = _ensure_labels(
            _require_env("GITHUB_TOKEN"),
            _require_env("REPORT_REPOSITORY"),
            label_definitions(targets),
        )
        print(f"labels_created={created}")
    elif args.setup_command == "pr-review":
        configured = _configure_pr_review(
            region, _require_env("AGENT_SPACE_ID"), args.integration_id, targets
        )
        print(f"configured={configured} repositories")
    elif args.setup_command == "code-review":
        code_reviews, created = _configure_code_review(
            region,
            _require_env("AGENT_SPACE_ID"),
            args.integration_id,
            args.service_role_arn,
            targets,
        )
        print(f"code_reviews={code_reviews} created={created}")
    else:
        _check_collector_repository(
            targets, args.collector_repository, args.collector_role_arn
        )
        environments, collector_arn = _configure_code_vuln(
            region,
            targets,
            args.integration_id,
            args.collector_role_arn,
            args.collector_repository,
        )
        print(f"environments={environments} collector={collector_arn or 'none'}")


def _write_output(name: str, value: int) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{name}={value}\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="continuum-github")
    commands = parser.add_subparsers(dest="command", required=True)
    sync = commands.add_parser("sync")
    sync.add_argument("--targets", type=Path, default=DEFAULT_TARGETS)
    sections = commands.add_parser("sections")
    sections.add_argument("--targets", type=Path, default=DEFAULT_TARGETS)
    report = commands.add_parser("report")
    report_commands = report.add_subparsers(dest="report_command", required=True)
    build = report_commands.add_parser("build")
    build.add_argument("--targets", type=Path, default=DEFAULT_TARGETS)
    build.add_argument("--out", type=Path, required=True)
    publish = report_commands.add_parser("publish")
    publish.add_argument("--dir", type=Path, required=True)
    publish.add_argument("--html-url", required=True)
    setup = commands.add_parser("setup")
    setup_commands = setup.add_subparsers(dest="setup_command", required=True)
    labels = setup_commands.add_parser("labels")
    labels.add_argument("--targets", type=Path, default=DEFAULT_TARGETS)
    pr_review = setup_commands.add_parser("pr-review")
    pr_review.add_argument("--targets", type=Path, default=DEFAULT_TARGETS)
    pr_review.add_argument("--integration-id", required=True)
    code_review = setup_commands.add_parser("code-review")
    code_review.add_argument("--targets", type=Path, default=DEFAULT_TARGETS)
    code_review.add_argument("--integration-id", required=True)
    code_review.add_argument("--service-role-arn", required=True)
    code_vuln = setup_commands.add_parser("code-vuln")
    code_vuln.add_argument("--targets", type=Path, default=DEFAULT_TARGETS)
    code_vuln.add_argument("--integration-id", required=True)
    code_vuln.add_argument("--collector-repository")
    code_vuln.add_argument("--collector-role-arn")
    args = parser.parse_args(argv)

    if args.command == "setup":
        _setup(args)
        return 0

    settings = load_settings(os.environ)
    if args.command == "report" and args.report_command == "publish":
        _report_publish(settings, args.dir, args.html_url)
        return 0
    targets = load_targets(args.targets)
    if args.command == "report":
        _report_build(settings, targets, args.out)
        return 0
    if args.command == "sections":
        # Only the count is printed; finding details never reach the workflow log.
        print(f"filled={_sections(settings, targets)}")
        return 0
    counts = _sync(settings, targets)
    # Only counts are printed; finding details never reach the workflow log.
    print(
        f"created={counts.created} pending={counts.pending} "
        f"closed={counts.closed} reopened={counts.reopened} "
        f"revalidations={counts.revalidations} "
        f"needs_sections={counts.needs_sections} failed={counts.failed} "
        f"started={counts.started}"
    )
    _write_output("needs-sections", counts.needs_sections)
    return 0
