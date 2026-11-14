"""Tests for the one-time setup of labels, PR review, and code-vuln."""

from dataclasses import replace
from datetime import UTC
from datetime import datetime
from typing import Any

import boto3
import pytest
from botocore.stub import ANY
from botocore.stub import Stubber
from fakes import TARGETS_PATH

from continuum_scan import cli
from continuum_scan.config import Repository
from continuum_scan.config import Site
from continuum_scan.config import Targets
from continuum_scan.config import load_targets
from continuum_scan.setup import configure_pr_review
from continuum_scan.setup import ensure_code_reviews
from continuum_scan.setup import ensure_collector
from continuum_scan.setup import ensure_environments
from continuum_scan.setup import environment_configuration
from continuum_scan.setup import label_definitions
from continuum_scan.setup import pr_review_items

ACCOUNT = "111122223333"
COLLECTOR_ARN = f"arn:aws:continuum:us-east-1:{ACCOUNT}:collectors/c1"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/continuum-collector"
NOW = datetime(2026, 11, 8, tzinfo=UTC)
TARGETS = load_targets(TARGETS_PATH)
TWO_REPOS = Targets(
    owner="example-org",
    repositories=(Repository("actions", False), Repository("continuum", True)),
    sites=(),
)
THREE_REPOS = Targets(
    owner="example-org",
    repositories=(
        Repository("actions", False),
        Repository("dotfiles", False),
        Repository("continuum", True),
    ),
    sites=(),
)
SERVICE_ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/service-role/continuum-example-org"


@pytest.fixture
def cv_client():
    return boto3.client(
        "continuum",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


@pytest.fixture
def sa_client():
    return boto3.client(
        "securityagent",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


def _arn(environment_id: str) -> str:
    return f"arn:aws:continuum:us-east-1:{ACCOUNT}:environments/{environment_id}"


def _env(environment_id: str, name: str) -> dict[str, Any]:
    return {
        "environmentId": environment_id,
        "environmentArn": _arn(environment_id),
        "name": name,
        "status": "ACTIVE",
        "createdAt": NOW,
    }


def _updated(environment_id: str, name: str) -> dict[str, Any]:
    return {
        "environmentId": environment_id,
        "environmentArn": _arn(environment_id),
        "name": name,
        "status": "ACTIVE",
        "statusUpdatedAt": NOW,
        "createdAt": NOW,
        "configuration": {},
    }


def _created(environment_id: str) -> dict[str, Any]:
    return {
        "environmentId": environment_id,
        "environmentArn": _arn(environment_id),
        "status": "ACTIVE",
        "createdAt": NOW,
    }


def _collector(collector_id: str, status: str) -> dict[str, Any]:
    return {
        "collectorId": collector_id,
        "collectorArn": f"arn:aws:continuum:us-east-1:{ACCOUNT}:collectors/{collector_id}",
        "type": "AWS_COLLECTOR",
        "status": status,
        "createdAt": NOW,
    }


def _associated(environment_id: str, collector_id: str) -> dict[str, Any]:
    return {
        "environmentId": environment_id,
        "environmentArn": _arn(environment_id),
        "associatedCollector": {
            "collectorId": collector_id,
            "collectorArn": f"arn:aws:continuum:us-east-1:{ACCOUNT}:collectors/{collector_id}",
        },
    }


def test_label_definitions_cover_every_repository() -> None:
    labels = label_definitions(TARGETS)
    assert labels["pending"] == ("C5DEF5", "Not found in the latest completed scan")
    assert {n for n in labels if n.startswith("repo:")} == {
        f"repo:{r.name}" for r in TARGETS.repositories
    }
    assert {n for n in labels if n.startswith("site:")} == {
        f"site:{s.domain}" for s in TARGETS.sites
    }
    assert len(labels) == 11 + len(TARGETS.repositories) + len(TARGETS.sites)


def test_site_label_definition() -> None:
    site = Site("nas.example.com", "weekly-nas-example-com", "ansible-playbooks")
    labels = label_definitions(replace(TWO_REPOS, sites=(site,)))
    assert labels["site:nas.example.com"] == ("EDEDED", "Findings for nas.example.com")


def test_label_definitions_match_the_label_table() -> None:
    labels = label_definitions(TWO_REPOS)
    assert labels == {
        "new": ("1D76DB", "Not triaged yet"),
        "wip": ("FBCA04", "Being fixed"),
        "pending": ("C5DEF5", "Not found in the latest completed scan"),
        "severity:critical": ("B60205", "Critical severity"),
        "severity:high": ("D93F0B", "High severity"),
        "severity:medium": ("FEF2C0", "Medium severity"),
        "pentest": ("5319E7", "Continuum for Penetration Testing"),
        "code-review": ("0052CC", "Security Agent full-repository code review"),
        "code-vuln": ("006B75", "Continuum for Code Vulnerabilities"),
        "urgent": ("B60205", "Do not wait for the weekly report"),
        "weekly-report": ("0E8A16", "Weekly Continuum report"),
        "repo:actions": ("EDEDED", "Findings for example-org/actions"),
        "repo:continuum": ("EDEDED", "Findings for example-org/continuum"),
    }


def test_pr_review_items_enable_comments_only_on_private_repositories() -> None:
    items = {
        i["resource"]["githubRepository"]["name"]: i["capabilities"]["github"]
        for i in pr_review_items(TARGETS)
    }
    assert items["continuum"] == {"leaveComments": True, "remediateCode": False}
    assert items["actions"] == {"leaveComments": False, "remediateCode": False}
    assert all("triggerFilterGroups" not in c for c in items.values())


def test_configure_pr_review_sends_every_repository_in_one_call(sa_client) -> None:
    with Stubber(sa_client) as stub:
        stub.add_response(
            "update_integrated_resources",
            {},
            {
                "agentSpaceId": "as1",
                "integrationId": "int1",
                "items": pr_review_items(TARGETS),
            },
        )
        assert configure_pr_review(sa_client, "as1", "int1", TARGETS) == len(
            TARGETS.repositories
        )
        stub.assert_no_pending_responses()


def test_environment_configuration_enables_patches_only_when_private() -> None:
    private = environment_configuration(
        Repository("continuum", True), "int1", "example-org"
    )
    public = environment_configuration(
        Repository("actions", False), "int1", "example-org"
    )
    assert private["codeConfiguration"]["environmentConfiguration"] == {
        "scanFrequency": "P7D",
        "patchCreationPolicy": "ENABLED",
    }
    assert (
        public["codeConfiguration"]["environmentConfiguration"]["patchCreationPolicy"]
        == "DISABLED"
    )
    assert public["codeConfiguration"]["sourceConfiguration"]["repositorySources"] == [
        {
            "integrationId": "int1",
            "repository": "example-org/actions",
            "defaultBranch": "main",
        }
    ]


def test_ensure_environments_skips_public_repositories(cv_client) -> None:
    # TWO_REPOS is actions (public) and continuum (private).
    with Stubber(cv_client) as stub:
        stub.add_response("list_environments", {"items": []}, {})
        stub.add_response(
            "create_environment",
            _created("e2"),
            {"name": "example-org-continuum", "configuration": ANY},
        )
        assert ensure_environments(cv_client, TWO_REPOS, "int1") == {"continuum": "e2"}
        stub.assert_no_pending_responses()


def test_ensure_environments_updates_existing(cv_client) -> None:
    with Stubber(cv_client) as stub:
        stub.add_response(
            "list_environments",
            {
                "items": [
                    _env("e1", "example-org-actions"),
                    _env("e2", "example-org-continuum"),
                ]
            },
            {},
        )
        stub.add_response(
            "update_environment",
            _updated("e2", "example-org-continuum"),
            {"environmentId": "e2", "configuration": ANY},
        )
        assert ensure_environments(cv_client, TWO_REPOS, "int1") == {"continuum": "e2"}
        stub.assert_no_pending_responses()


def test_ensure_environments_sends_the_repository_configuration(cv_client) -> None:
    with Stubber(cv_client) as stub:
        stub.add_response(
            "list_environments",
            {"items": [_env("e9", "other")], "nextToken": "n"},
            {},
        )
        stub.add_response(
            "list_environments",
            {"items": [_env("e2", "example-org-continuum")]},
            {"nextToken": "n"},
        )
        stub.add_response(
            "update_environment",
            _updated("e2", "example-org-continuum"),
            {
                "environmentId": "e2",
                "configuration": environment_configuration(
                    Repository("continuum", True), "int1", "example-org"
                ),
            },
        )
        assert ensure_environments(cv_client, TWO_REPOS, "int1") == {
            "continuum": "e2",
        }
        stub.assert_no_pending_responses()


def _code_review(title: str) -> dict[str, Any]:
    return {
        "codeReviewId": f"cr-{title}",
        "agentSpaceId": "as1",
        "title": title,
        "createdAt": NOW,
        "updatedAt": NOW,
    }


def _resource(name: str, provider_resource_id: str) -> dict[str, Any]:
    return {
        "integrationId": "i-1",
        "resource": {
            "githubRepository": {
                "name": name,
                "owner": "example-org",
                "providerResourceId": provider_resource_id,
            }
        },
    }


def test_ensure_code_reviews_creates_missing_public_reviews(sa_client) -> None:
    expected = {
        "agentSpaceId": "as1",
        "title": "weekly-actions",
        "assets": {
            "integratedRepositories": [
                {"integrationId": "i-1", "providerResourceId": "1000000001"}
            ]
        },
        "serviceRole": SERVICE_ROLE_ARN,
        "codeRemediationStrategy": "DISABLED",
        "validationMode": "SIMULATED",
    }
    with Stubber(sa_client) as stub:
        stub.add_response(
            "list_code_reviews",
            {"codeReviewSummaries": [_code_review("other")], "nextToken": "c"},
            {"agentSpaceId": "as1"},
        )
        stub.add_response(
            "list_code_reviews",
            {"codeReviewSummaries": [_code_review("weekly-dotfiles")]},
            {"agentSpaceId": "as1", "nextToken": "c"},
        )
        stub.add_response(
            "list_integrated_resources",
            {
                "integratedResourceSummaries": [_resource("actions", "1000000001")],
                "nextToken": "r",
            },
            {"agentSpaceId": "as1", "integrationId": "i-1"},
        )
        stub.add_response(
            "list_integrated_resources",
            {
                "integratedResourceSummaries": [
                    _resource("dotfiles", "1000000002"),
                    _resource("continuum", "1000000003"),
                ]
            },
            {"agentSpaceId": "as1", "integrationId": "i-1", "nextToken": "r"},
        )
        stub.add_response(
            "create_code_review",
            {
                "codeReviewId": "cr-a",
                "title": "weekly-actions",
                "createdAt": NOW,
                "updatedAt": NOW,
            },
            expected,
        )
        assert ensure_code_reviews(
            sa_client, "as1", "i-1", SERVICE_ROLE_ARN, THREE_REPOS
        ) == (2, 1)
        stub.assert_no_pending_responses()


def test_ensure_code_reviews_raises_for_an_unconnected_repository(sa_client) -> None:
    with Stubber(sa_client) as stub:
        stub.add_response(
            "list_code_reviews", {"codeReviewSummaries": []}, {"agentSpaceId": "as1"}
        )
        stub.add_response(
            "list_integrated_resources",
            {"integratedResourceSummaries": [_resource("continuum", "1000000003")]},
            {"agentSpaceId": "as1", "integrationId": "i-1"},
        )
        with pytest.raises(
            LookupError,
            match="^Not connected to integration i-1: example-org/actions, example-org/dotfiles$",
        ):
            ensure_code_reviews(sa_client, "as1", "i-1", SERVICE_ROLE_ARN, THREE_REPOS)
        stub.assert_no_pending_responses()


def test_ensure_collector_reuses_an_active_collector(cv_client) -> None:
    with Stubber(cv_client) as stub:
        stub.add_response(
            "list_collectors", {"items": [_collector("c1", "ACTIVE")]}, {}
        )
        stub.add_response(
            "associate_collector",
            _associated("e2", "c1"),
            {
                "environmentId": "e2",
                "collectorArn": COLLECTOR_ARN,
                "collectorDataAccessRoleArn": ROLE_ARN,
            },
        )
        assert ensure_collector(cv_client, "e2", ROLE_ARN) == COLLECTOR_ARN


def test_ensure_collector_creates_one_when_none_is_active(cv_client) -> None:
    with Stubber(cv_client) as stub:
        stub.add_response(
            "list_collectors", {"items": [_collector("c0", "PENDING_DELETION")]}, {}
        )
        stub.add_response(
            "create_collector",
            _collector("c1", "ACTIVE"),
            {"type": "AWS_COLLECTOR", "clientToken": "continuum-collector"},
        )
        stub.add_response(
            "associate_collector",
            _associated("e2", "c1"),
            {
                "environmentId": "e2",
                "collectorArn": COLLECTOR_ARN,
                "collectorDataAccessRoleArn": ROLE_ARN,
            },
        )
        assert ensure_collector(cv_client, "e2", ROLE_ARN) == COLLECTOR_ARN
        stub.assert_no_pending_responses()


def test_ensure_collector_treats_an_existing_association_as_success(
    cv_client,
) -> None:
    with Stubber(cv_client) as stub:
        stub.add_response(
            "list_collectors", {"items": [_collector("c1", "ACTIVE")]}, {}
        )
        stub.add_client_error(
            "associate_collector",
            service_error_code="ConflictException",
            http_status_code=409,
        )
        assert ensure_collector(cv_client, "e2", ROLE_ARN) == COLLECTOR_ARN


def test_ensure_collector_raises_other_association_errors(cv_client) -> None:
    with Stubber(cv_client) as stub:
        stub.add_response(
            "list_collectors", {"items": [_collector("c1", "ACTIVE")]}, {}
        )
        stub.add_client_error(
            "associate_collector",
            service_error_code="AccessDeniedException",
            http_status_code=403,
        )
        with pytest.raises(cv_client.exceptions.AccessDeniedException):
            ensure_collector(cv_client, "e2", ROLE_ARN)


def test_cli_setup_labels_prints_the_created_count(monkeypatch, capsys) -> None:
    monkeypatch.delenv("AGENT_SPACE_ID", raising=False)
    monkeypatch.setenv("REPORT_REPOSITORY", "example-org/security-findings")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    seen = []

    def fake_labels(token, repository, labels):
        seen.append((token, repository, len(labels)))
        return 4

    monkeypatch.setattr(cli, "_ensure_labels", fake_labels)
    assert cli.main(["setup", "labels", "--targets", str(TARGETS_PATH)]) == 0
    assert capsys.readouterr().out == "labels_created=4\n"
    assert seen == [
        (
            "t",
            "example-org/security-findings",
            11 + len(TARGETS.repositories) + len(TARGETS.sites),
        )
    ]


def test_cli_setup_labels_requires_the_report_repository(monkeypatch) -> None:
    monkeypatch.delenv("REPORT_REPOSITORY", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setattr(cli, "_ensure_labels", pytest.fail)
    with pytest.raises(ValueError, match="REPORT_REPOSITORY"):
        cli.main(["setup", "labels", "--targets", str(TARGETS_PATH)])


def test_cli_setup_pr_review_prints_the_repository_count(monkeypatch, capsys) -> None:
    monkeypatch.setenv("AGENT_SPACE_ID", "as1")
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    seen = []

    def fake_pr_review(region, agent_space_id, integration_id, targets):
        seen.append((region, agent_space_id, integration_id))
        return len(targets.repositories)

    monkeypatch.setattr(cli, "_configure_pr_review", fake_pr_review)
    argv = [
        "setup",
        "pr-review",
        "--targets",
        str(TARGETS_PATH),
        "--integration-id",
        "int1",
    ]
    assert cli.main(argv) == 0
    assert (
        capsys.readouterr().out
        == f"configured={len(TARGETS.repositories)} repositories\n"
    )
    assert seen == [("us-east-1", "as1", "int1")]


def test_cli_setup_code_vuln_prints_environments_and_collector(
    monkeypatch, capsys
) -> None:
    monkeypatch.delenv("AGENT_SPACE_ID", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    seen = []

    def fake_code_vuln(region, targets, integration_id, role_arn, repository):
        seen.append((region, integration_id, role_arn, repository))
        return len(targets.repositories), COLLECTOR_ARN

    monkeypatch.setattr(cli, "_configure_code_vuln", fake_code_vuln)
    argv = [
        "setup",
        "code-vuln",
        "--targets",
        str(TARGETS_PATH),
        "--integration-id",
        "int1",
        "--collector-repository",
        "api",
        "--collector-role-arn",
        ROLE_ARN,
    ]
    assert cli.main(argv) == 0
    assert capsys.readouterr().out == (
        f"environments={len(TARGETS.repositories)} collector={COLLECTOR_ARN}\n"
    )
    assert seen == [("us-west-2", "int1", ROLE_ARN, "api")]


def test_cli_setup_code_vuln_without_a_collector_repository_prints_none(
    monkeypatch, capsys
) -> None:
    monkeypatch.delenv("AWS_REGION", raising=False)
    seen = []

    def fake_code_vuln(region, targets, integration_id, role_arn, repository):
        seen.append((region, integration_id, role_arn, repository))
        return 2, None

    monkeypatch.setattr(cli, "_configure_code_vuln", fake_code_vuln)
    argv = [
        "setup",
        "code-vuln",
        "--targets",
        str(TARGETS_PATH),
        "--integration-id",
        "int1",
    ]
    assert cli.main(argv) == 0
    assert capsys.readouterr().out == "environments=2 collector=none\n"
    assert seen == [("us-east-1", "int1", None, None)]


@pytest.mark.parametrize("repository", ["actions", "missing"])
def test_cli_setup_code_vuln_rejects_a_collector_repository_that_is_not_private(
    monkeypatch, repository
) -> None:
    monkeypatch.setattr(cli, "_configure_code_vuln", pytest.fail)
    argv = [
        "setup",
        "code-vuln",
        "--targets",
        str(TARGETS_PATH),
        "--integration-id",
        "int1",
        "--collector-repository",
        repository,
        "--collector-role-arn",
        ROLE_ARN,
    ]
    with pytest.raises(ValueError, match=f"{repository}.*private repository"):
        cli.main(argv)


def test_cli_setup_code_vuln_requires_a_role_arn_with_a_collector_repository(
    monkeypatch,
) -> None:
    monkeypatch.setattr(cli, "_configure_code_vuln", pytest.fail)
    argv = [
        "setup",
        "code-vuln",
        "--targets",
        str(TARGETS_PATH),
        "--integration-id",
        "int1",
        "--collector-repository",
        "api",
    ]
    with pytest.raises(ValueError, match="--collector-role-arn"):
        cli.main(argv)


def test_cli_setup_code_review_prints_counts(monkeypatch, capsys) -> None:
    monkeypatch.setenv("AGENT_SPACE_ID", "as1")
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    seen = []

    def fake(region, agent_space_id, integration_id, role_arn, targets):
        seen.append((region, agent_space_id, integration_id, role_arn))
        return 11, 11

    monkeypatch.setattr(cli, "_configure_code_review", fake)
    argv = [
        "setup",
        "code-review",
        "--targets",
        str(TARGETS_PATH),
        "--integration-id",
        "i-1",
        "--service-role-arn",
        SERVICE_ROLE_ARN,
    ]
    assert cli.main(argv) == 0
    assert capsys.readouterr().out == "code_reviews=11 created=11\n"
    assert seen == [("us-east-1", "as1", "i-1", SERVICE_ROLE_ARN)]


def test_configure_code_review_uses_the_security_agent_client(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(
        cli, "_security_agent_client", lambda region: calls.append(region) or "client"
    )
    monkeypatch.setattr(
        cli,
        "ensure_code_reviews",
        lambda client, agent_space_id, integration_id, role_arn, targets: (
            calls.append((client, agent_space_id, integration_id, role_arn, targets))
            or (2, 1)
        ),
    )
    assert cli._configure_code_review(
        "us-east-1", "as1", "i-1", SERVICE_ROLE_ARN, THREE_REPOS
    ) == (2, 1)
    assert calls == [
        "us-east-1",
        ("client", "as1", "i-1", SERVICE_ROLE_ARN, THREE_REPOS),
    ]


def test_configure_code_vuln_associates_the_collector_with_the_named_repository(
    monkeypatch,
) -> None:
    calls = []
    monkeypatch.setattr(
        cli, "_continuum_client", lambda region: calls.append(region) or "client"
    )
    monkeypatch.setattr(
        cli,
        "ensure_environments",
        lambda client, targets, integration_id: {"api": "e1", "continuum": "e2"},
    )
    monkeypatch.setattr(
        cli,
        "ensure_collector",
        lambda client, environment_id, role_arn: (
            calls.append((client, environment_id, role_arn)) or COLLECTOR_ARN
        ),
    )
    assert cli._configure_code_vuln("us-east-1", TARGETS, "int1", ROLE_ARN, "api") == (
        2,
        COLLECTOR_ARN,
    )
    assert calls == ["us-east-1", ("client", "e1", ROLE_ARN)]


def test_configure_code_vuln_creates_no_collector_without_a_repository(
    monkeypatch,
) -> None:
    monkeypatch.setattr(cli, "_continuum_client", lambda region: "client")
    monkeypatch.setattr(
        cli,
        "ensure_environments",
        lambda client, targets, integration_id: {"continuum": "e2"},
    )
    monkeypatch.setattr(cli, "ensure_collector", pytest.fail)
    assert cli._configure_code_vuln("us-east-1", TWO_REPOS, "int1", None, None) == (
        1,
        None,
    )
