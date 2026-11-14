"""One-time setup of labels, PR review, code reviews, and code-vuln environments."""

from typing import Any

from continuum_github.config import Repository
from continuum_github.config import Targets
from continuum_github.config import code_review_title
from continuum_github.config import environment_name
from continuum_github.render import site_label

COLLECTOR_CLIENT_TOKEN = "continuum-collector"
SCAN_FREQUENCY = "P7D"

_LABELS: dict[str, tuple[str, str]] = {
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
}
_REPOSITORY_LABEL_COLOR = "EDEDED"


def label_definitions(targets: Targets) -> dict[str, tuple[str, str]]:
    """Maps each label name to its color and description."""
    labels = dict(_LABELS)
    for repository in targets.repositories:
        labels[f"repo:{repository.name}"] = (
            _REPOSITORY_LABEL_COLOR,
            f"Findings for {targets.owner}/{repository.name}",
        )
    for site in targets.sites:
        labels[site_label(site.domain)] = (
            _REPOSITORY_LABEL_COLOR,
            f"Findings for {site.domain}",
        )
    return labels


def pr_review_items(targets: Targets) -> list[dict[str, Any]]:
    """Returns the integrated resources for UpdateIntegratedResources.

    Private repositories get PR comments without remediation pull requests.
    Security Agent rejects PR comments on public repositories, so those stay
    connected with comments and remediation off.
    """
    return [
        {
            "resource": {
                "githubRepository": {"name": repository.name, "owner": targets.owner}
            },
            "capabilities": {
                "github": {
                    "leaveComments": repository.private,
                    "remediateCode": False,
                }
            },
        }
        for repository in targets.repositories
    ]


def configure_pr_review(
    client: Any, agent_space_id: str, integration_id: str, targets: Targets
) -> int:
    """Configures PR review for every repository and returns how many it sent.

    UpdateIntegratedResources replaces the resources of an integration, and no
    other API removes one, so every repository goes in a single call. Sending
    one repository per call would disconnect the others.
    """
    items = pr_review_items(targets)
    client.update_integrated_resources(
        agentSpaceId=agent_space_id, integrationId=integration_id, items=items
    )
    return len(items)


def environment_configuration(
    repository: Repository, integration_id: str, owner: str
) -> dict[str, Any]:
    """Returns the code-vuln environment configuration for a repository.

    Patches are created only for private repositories, whose findings stay
    private.
    """
    return {
        "codeConfiguration": {
            "sourceConfiguration": {
                "repositorySources": [
                    {
                        "integrationId": integration_id,
                        "repository": f"{owner}/{repository.name}",
                        "defaultBranch": "main",
                    }
                ]
            },
            "environmentConfiguration": {
                "scanFrequency": SCAN_FREQUENCY,
                "patchCreationPolicy": "ENABLED" if repository.private else "DISABLED",
            },
        }
    }


def _environment_ids(client: Any) -> dict[str, str]:
    ids: dict[str, str] = {}
    kwargs: dict[str, str] = {}
    while True:
        response = client.list_environments(**kwargs)
        for item in response["items"]:
            ids[item["name"]] = item["environmentId"]
        token = response.get("nextToken")
        if not token:
            return ids
        kwargs = {"nextToken": token}


def ensure_environments(
    client: Any, targets: Targets, integration_id: str
) -> dict[str, str]:
    """Creates or updates an environment per private repository.

    Continuum rejects public repositories, which get a code review instead.
    Returns the environment ID of each private repository by repository name.
    """
    existing = _environment_ids(client)
    result: dict[str, str] = {}
    for repository in targets.repositories:
        if not repository.private:
            continue
        name = environment_name(targets.owner, repository.name)
        configuration = environment_configuration(
            repository, integration_id, targets.owner
        )
        environment_id = existing.get(name)
        if environment_id:
            client.update_environment(
                environmentId=environment_id, configuration=configuration
            )
        else:
            environment_id = client.create_environment(
                name=name, configuration=configuration
            )["environmentId"]
        result[repository.name] = environment_id
    return result


def _code_review_titles(client: Any, agent_space_id: str) -> set[str]:
    titles: set[str] = set()
    kwargs: dict[str, str] = {"agentSpaceId": agent_space_id}
    while True:
        response = client.list_code_reviews(**kwargs)
        titles.update(item["title"] for item in response["codeReviewSummaries"])
        token = response.get("nextToken")
        if not token:
            return titles
        kwargs = {"agentSpaceId": agent_space_id, "nextToken": token}


def _provider_resource_ids(
    client: Any, agent_space_id: str, integration_id: str
) -> dict[tuple[str, str], str]:
    ids: dict[tuple[str, str], str] = {}
    kwargs: dict[str, str] = {
        "agentSpaceId": agent_space_id,
        "integrationId": integration_id,
    }
    while True:
        response = client.list_integrated_resources(**kwargs)
        for item in response["integratedResourceSummaries"]:
            repository = item["resource"].get("githubRepository")
            if repository:
                ids[(repository["owner"], repository["name"])] = repository[
                    "providerResourceId"
                ]
        token = response.get("nextToken")
        if not token:
            return ids
        kwargs = {
            "agentSpaceId": agent_space_id,
            "integrationId": integration_id,
            "nextToken": token,
        }


def ensure_code_reviews(
    client: Any,
    agent_space_id: str,
    integration_id: str,
    service_role_arn: str,
    targets: Targets,
) -> tuple[int, int]:
    """Creates a code review for each public repository that lacks one.

    Code reviews are matched by title. ListCodeReviews can lag a few
    minutes behind CreateCodeReview, so a call right after another one may
    not see the reviews it created and create them again. Every public
    repository must be connected to the integration; otherwise LookupError
    names the unconnected ones before any code review is created. Returns
    the number of public code reviews that exist afterwards and the number
    created.
    """
    titles = _code_review_titles(client, agent_space_id)
    resource_ids = _provider_resource_ids(client, agent_space_id, integration_id)
    public = [r for r in targets.repositories if not r.private]
    unconnected = [
        f"{targets.owner}/{r.name}"
        for r in public
        if (targets.owner, r.name) not in resource_ids
    ]
    if unconnected:
        raise LookupError(
            f"Not connected to integration {integration_id}: {', '.join(unconnected)}"
        )
    created = 0
    for repository in public:
        title = code_review_title(repository.name)
        if title in titles:
            continue
        client.create_code_review(
            agentSpaceId=agent_space_id,
            title=title,
            assets={
                "integratedRepositories": [
                    {
                        "integrationId": integration_id,
                        "providerResourceId": resource_ids[
                            (targets.owner, repository.name)
                        ],
                    }
                ]
            },
            serviceRole=service_role_arn,
            codeRemediationStrategy="DISABLED",
            validationMode="SIMULATED",
        )
        created += 1
    return len(public), created


def ensure_collector(client: Any, environment_id: str, role_arn: str) -> str:
    """Associates an active AWS collector with an environment.

    Creates the collector when none is active and returns its ARN. An
    environment that already has the collector counts as associated.
    """
    collector_arn = next(
        (
            item["collectorArn"]
            for item in client.list_collectors()["items"]
            if item["type"] == "AWS_COLLECTOR" and item["status"] == "ACTIVE"
        ),
        None,
    )
    if collector_arn is None:
        collector_arn = client.create_collector(
            type="AWS_COLLECTOR", clientToken=COLLECTOR_CLIENT_TOKEN
        )["collectorArn"]
    try:
        client.associate_collector(
            environmentId=environment_id,
            collectorArn=collector_arn,
            collectorDataAccessRoleArn=role_arn,
        )
    except client.exceptions.ConflictException:
        pass
    return collector_arn
