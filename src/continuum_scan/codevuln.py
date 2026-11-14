"""Reads Continuum code vulnerability scans and issues."""

from collections.abc import Callable, Iterator, Mapping
from typing import Any

from botocore.exceptions import ClientError

from continuum_scan.config import Repository
from continuum_scan.models import CompletedScan
from continuum_scan.models import Detection
from continuum_scan.models import Severity
from continuum_scan.models import TargetScan
from continuum_scan.models import code_vuln_key

MISSING = "MISSING"
# An environment that has no code scan at all, as right after it is created.
NEVER_RUN = "NEVER_RUN"
_DETAILS = (
    ("Synopsis", "synopsis"),
    ("Summary", "summary"),
    ("Severity reasoning", "severityReasoning"),
)
_LATEST_STATUS = {"SUCCEEDED": "COMPLETED", "FAILED": "FAILED"}
# Finding statuses of a scan that is still validating what it found.
_UNSETTLED = frozenset({"SUBMITTED", "VALIDATING"})
# The issue status after Continuum has settled the issue's severity.
_ISSUE_COMPLETED = "COMPLETED"


def _pages(
    call: Callable[..., Mapping[str, Any]], key: str, **params: Any
) -> Iterator[Mapping[str, Any]]:
    """Yields every item under `key`, following nextToken."""
    token: str | None = None
    while True:
        page = call(**params, **({"nextToken": token} if token else {}))
        yield from page.get(key) or ()
        token = page.get("nextToken")
        if not token:
            return


def _detection(
    repository: Repository,
    environment_id: str,
    issue: Mapping[str, Any],
    details: tuple[tuple[str, str], ...] = (),
) -> Detection:
    severity = Severity.parse(issue.get("severity"))
    confidence = issue.get("confidence")
    return Detection(
        source="code-vuln",
        target=repository.name,
        repository=repository.name,
        key=code_vuln_key(environment_id, issue["issueId"]),
        external_id=issue["issueId"],
        name=issue.get("name") or "",
        severity=severity,
        urgent=severity in (Severity.HIGH, Severity.CRITICAL),
        confidence="" if confidence is None else str(confidence),
        detected_at=issue["createdAt"],
        details=details,
    )


class CodeVulnClient:
    def __init__(self, client: Any) -> None:
        self._client = client

    def environments(self) -> dict[str, str]:
        """Maps each environment name to its environment ID."""
        return {
            environment["name"]: environment["environmentId"]
            for environment in _pages(self._client.list_environments, "items")
        }

    def target_scan(
        self, repository: Repository, environment_id: str | None
    ) -> TargetScan:
        """Reads the code scans and issues of the repository's environment.

        Every issue whose status is COMPLETED and whose severity is filed
        is a candidate. A COMPLETED issue rated below Medium is withdrawn and
        not found. The newest successful scan whose findings are all settled
        finds the issues its findings created or duplicated. While the
        newest scan succeeded but still validates findings, the latest
        status is IN_PROGRESS.
        """
        if environment_id is None:
            return self._empty(repository, MISSING)
        scans = list(
            _pages(self._client.list_code_scans, "scans", environmentId=environment_id)
        )
        if not scans:
            return self._empty(repository, NEVER_RUN)
        scans.sort(key=lambda scan: scan["createdAt"])
        latest_status = _LATEST_STATUS.get(scans[-1].get("status") or "", "IN_PROGRESS")
        succeeded = [scan for scan in scans if scan.get("status") == "SUCCEEDED"]
        findings: list[Mapping[str, Any]] = []
        if succeeded:
            findings = list(
                _pages(
                    self._client.list_code_findings,
                    "items",
                    environmentId=environment_id,
                )
            )
        unsettled = {
            finding.get("scanRunId")
            for finding in findings
            if finding.get("status") in _UNSETTLED
        }
        # A scan whose findings are still being validated has not finished
        # finding issues, so the newest settled success stands in for it.
        if scans[-1].get("status") == "SUCCEEDED" and (
            scans[-1]["scanRunId"] in unsettled
        ):
            latest_status = "IN_PROGRESS"
        settled = next(
            (
                scan
                for scan in reversed(succeeded)
                if scan["scanRunId"] not in unsettled
            ),
            None,
        )
        found_ids: list[str] = []
        if settled is not None:
            for finding in findings:
                if finding.get("scanRunId") != settled["scanRunId"]:
                    continue
                issue_id = finding.get("createdIssueId") or finding.get(
                    "duplicateOfIssueId"
                )
                if issue_id:
                    found_ids.append(issue_id)
        issues = list(
            _pages(self._client.list_code_issues, "items", environmentId=environment_id)
        )
        detections = {
            issue["issueId"]: _detection(repository, environment_id, issue)
            for issue in issues
        }
        statuses = {issue["issueId"]: issue.get("status") for issue in issues}
        # An issue gets its final severity when its status is COMPLETED.
        # Until then it is not filed, and once rated below Medium it counts
        # as withdrawn, so an issue filed on a provisional severity closes.
        settled_ids = {
            issue_id
            for issue_id, status in statuses.items()
            if status == _ISSUE_COMPLETED
        }
        withdrawn_ids = {
            issue_id
            for issue_id in settled_ids
            if not detections[issue_id].severity.filed
        }
        completed = None
        if settled is not None:
            completed = CompletedScan(
                scan_id=settled["scanRunId"],
                started_at=settled["createdAt"],
                found={
                    detections[issue_id].key: detections[issue_id]
                    for issue_id in found_ids
                    if issue_id in detections and issue_id not in withdrawn_ids
                },
            )
        return TargetScan(
            source="code-vuln",
            target=repository.name,
            candidates=tuple(
                detection
                for issue_id, detection in detections.items()
                if issue_id in settled_ids and detection.severity.filed
            ),
            withdrawn=frozenset(detections[i].key for i in withdrawn_ids),
            completed=completed,
            latest_status=latest_status,
            completed_at=settled.get("completedAt") if settled is not None else None,
        )

    def _empty(self, repository: Repository, status: str) -> TargetScan:
        return TargetScan(
            source="code-vuln",
            target=repository.name,
            candidates=(),
            withdrawn=frozenset(),
            completed=None,
            latest_status=status,
            completed_at=None,
        )

    def detection(
        self, repository: Repository, environment_id: str, issue_id: str
    ) -> Detection | None:
        """Reads one issue with its details, or None when it is not found."""
        try:
            issue = self._client.get_code_issue(
                environmentId=environment_id, issueId=issue_id
            )
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") == (
                "ResourceNotFoundException"
            ):
                return None
            raise
        details = tuple(
            (heading, issue[field]) for heading, field in _DETAILS if issue.get(field)
        )
        return _detection(repository, environment_id, issue, details)
