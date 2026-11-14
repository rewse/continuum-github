"""Reads and starts Security Agent full-repository code reviews."""

import dataclasses
from collections.abc import Mapping, Sequence
from datetime import datetime
from datetime import timedelta
from typing import Any

from botocore.exceptions import ClientError

from continuum_scan.config import Repository
from continuum_scan.config import code_review_title
from continuum_scan.models import CompletedScan
from continuum_scan.models import Detection
from continuum_scan.models import Severity
from continuum_scan.models import TargetScan
from continuum_scan.models import code_review_key
from continuum_scan.models import pentest_severity
from continuum_scan.pentest import _alive
from continuum_scan.pentest import _pages

MISSING = "MISSING"
# A code review that has no job at all, as right after it is created.
NEVER_RUN = "NEVER_RUN"
# Security Agent rejects a start beyond this many concurrent code reviews.
MAX_CONCURRENT_CODE_REVIEWS = 10
# Sync runs every two hours, so an interval slightly under seven days lets it
# start a repository's next review before the seven-day mark.
CODE_REVIEW_INTERVAL = timedelta(days=6, hours=12)
# The most finding IDs one batch_get_findings call accepts.
_BATCH_SIZE = 100
_BUSY_STATUSES = frozenset({"IN_PROGRESS", "STOPPING"})
_QUALIFYING_STATUSES = frozenset({"IN_PROGRESS", "STOPPING", "COMPLETED"})
_DETAILS = (
    ("Description", "description"),
    ("Reasoning", "reasoning"),
)


def _first_location(finding: Mapping[str, Any]) -> Mapping[str, Any] | None:
    locations = finding.get("codeLocations") or ()
    return locations[0] if locations else None


def _location(location: Mapping[str, Any] | None) -> str | None:
    """Formats a code location as path, path:start, or path:start-end."""
    if location is None:
        return None
    path = location["filePath"]
    start = location.get("lineStart")
    end = location.get("lineEnd")
    if start is None:
        return path
    if end is None or end == start:
        return f"{path}:{start}"
    return f"{path}:{start}-{end}"


@dataclasses.dataclass(frozen=True)
class StartResult:
    """How many code review jobs a start_due call started and failed to start."""

    started: int
    failed: int


class CodeReviewClient:
    def __init__(self, client: Any, agent_space_id: str) -> None:
        self._client = client
        self._space = agent_space_id
        self._ids: dict[str, str] | None = None

    def _code_review_ids(self) -> dict[str, str]:
        """Maps each code review title in the Agent Space to its ID.

        Callers look titles up with code_review_title(), because a title
        replaces characters that Security Agent rejects and cannot be turned
        back into the repository name.
        """
        if self._ids is None:
            self._ids = {
                summary["title"]: summary["codeReviewId"]
                for summary in _pages(
                    self._client.list_code_reviews,
                    "codeReviewSummaries",
                    agentSpaceId=self._space,
                )
            }
        return self._ids

    def _jobs(self, code_review_id: str) -> list[Mapping[str, Any]]:
        """Lists the jobs of a code review that have a creation time."""
        return [
            job
            for job in _pages(
                self._client.list_code_review_jobs_for_code_review,
                "codeReviewJobSummaries",
                agentSpaceId=self._space,
                codeReviewId=code_review_id,
            )
            if job.get("createdAt") is not None
        ]

    def _batch(self, finding_ids: Sequence[str]) -> list[Mapping[str, Any]]:
        response = self._client.batch_get_findings(
            agentSpaceId=self._space, findingIds=list(finding_ids)
        )
        return list(response.get("findings") or ())

    def _findings(self, job_id: str) -> list[Mapping[str, Any]]:
        """Reads every finding of a job in full, in the order listed.

        Only full findings carry codeLocations, so the summaries are read
        again in batches.
        """
        ids = [
            summary["findingId"]
            for summary in _pages(
                self._client.list_findings,
                "findingsSummaries",
                agentSpaceId=self._space,
                codeReviewJobId=job_id,
            )
        ]
        full: dict[str, Mapping[str, Any]] = {}
        for start in range(0, len(ids), _BATCH_SIZE):
            for finding in self._batch(ids[start : start + _BATCH_SIZE]):
                full[finding["findingId"]] = finding
        return [
            full[finding_id] for finding_id in dict.fromkeys(ids) if finding_id in full
        ]

    def _detection(
        self,
        title: str,
        repository: Repository,
        finding: Mapping[str, Any],
        fallback_time: datetime | None,
        details: tuple[tuple[str, str], ...] = (),
    ) -> Detection:
        severity = pentest_severity(finding.get("riskLevel"))
        urgent = severity is Severity.CRITICAL or (
            severity is Severity.HIGH and finding.get("validationStatus") == "CONFIRMED"
        )
        name = finding.get("name") or ""
        location = _first_location(finding)
        path = location["filePath"] if location is not None else ""
        detected_at = finding.get("createdAt") or fallback_time
        if detected_at is None:
            raise ValueError(f"Finding {finding['findingId']} has no createdAt")
        return Detection(
            source="code-review",
            target=title,
            repository=repository.name,
            key=code_review_key(title, finding.get("riskType") or "", name, path),
            external_id=finding["findingId"],
            name=name,
            severity=severity,
            urgent=urgent,
            confidence=finding.get("confidence") or "",
            detected_at=detected_at,
            location=_location(location),
            details=details,
        )

    def target_scan(self, repository: Repository) -> TargetScan:
        """Reads the latest completed job of the repository's code review.

        Alive findings of that job form `found`, and those whose severity is
        filed are candidates. Within the job, the worst finding of a key
        represents it and lists the other alive finding IDs of the key in
        extra_finding_ids. Jobs still in progress are not read.
        """
        title = code_review_title(repository.name)
        code_review_id = self._code_review_ids().get(title)
        if code_review_id is None:
            return self._empty(title, MISSING)
        jobs = self._jobs(code_review_id)
        if not jobs:
            return self._empty(title, NEVER_RUN)
        jobs.sort(key=lambda job: job["createdAt"])
        latest_status = jobs[-1].get("status") or "UNKNOWN"
        completed_job = next(
            (job for job in reversed(jobs) if job.get("status") == "COMPLETED"), None
        )
        if completed_job is None:
            return self._empty(title, latest_status)
        withdrawn: set[str] = set()
        # Every alive finding ID under each key.
        ids: dict[str, list[str]] = {}
        found: dict[str, Detection] = {}
        for finding in self._findings(completed_job["codeReviewJobId"]):
            detection = self._detection(
                title, repository, finding, completed_job["createdAt"]
            )
            if not _alive(finding):
                withdrawn.add(detection.key)
                continue
            ids.setdefault(detection.key, []).append(detection.external_id)
            # The worst finding represents a key found more than once.
            previous = found.get(detection.key)
            if previous is None or detection.severity.rank >= previous.severity.rank:
                found[detection.key] = detection

        def with_ids(detection: Detection) -> Detection:
            extra = tuple(
                finding_id
                for finding_id in dict.fromkeys(ids[detection.key])
                if finding_id != detection.external_id
            )
            return dataclasses.replace(detection, extra_finding_ids=extra)

        found = {key: with_ids(detection) for key, detection in found.items()}
        return TargetScan(
            source="code-review",
            target=title,
            candidates=tuple(
                detection for detection in found.values() if detection.severity.filed
            ),
            withdrawn=frozenset(withdrawn - found.keys()),
            completed=CompletedScan(
                scan_id=completed_job["codeReviewJobId"],
                started_at=completed_job["createdAt"],
                found=found,
            ),
            latest_status=latest_status,
            completed_at=completed_job.get("updatedAt"),
        )

    def _empty(self, title: str, status: str) -> TargetScan:
        return TargetScan(
            source="code-review",
            target=title,
            candidates=(),
            withdrawn=frozenset(),
            completed=None,
            latest_status=status,
            completed_at=None,
        )

    def detection(self, repository: Repository, finding_id: str) -> Detection | None:
        """Reads one finding with its details.

        Returns None when the finding or the repository's code review is not
        found, when the finding belongs to another code review, or when the
        finding has no creation time.
        """
        title = code_review_title(repository.name)
        code_review_id = self._code_review_ids().get(title)
        if code_review_id is None:
            return None
        for finding in self._batch([finding_id]):
            if finding.get("findingId") != finding_id:
                continue
            if finding.get("codeReviewId") not in (None, code_review_id):
                return None
            if finding.get("createdAt") is None:
                return None
            details = tuple(
                (heading, finding[field])
                for heading, field in _DETAILS
                if finding.get(field)
            )
            return self._detection(title, repository, finding, None, details)
        return None

    def start_due(
        self, repositories: Sequence[Repository], now: datetime
    ) -> StartResult:
        """Starts the due repositories that fit in the free concurrency slots
        and returns how many started and how many failed to start.

        A repository is due unless it has a running job, or a job created
        within CODE_REVIEW_INTERVAL that completed. The oldest qualifying job
        goes first, and a repository that never ran goes before all others. A
        repository without a code review is skipped. Stops quietly when
        Security Agent throttles a start, because the next run picks up what
        is left. Any other rejected start counts as failed, and the next
        repository is started.
        """
        ids = self._code_review_ids()
        busy = 0
        # Each entry is (last qualifying job time or None, code review ID).
        due: list[tuple[datetime | None, str]] = []
        for repository in repositories:
            code_review_id = ids.get(code_review_title(repository.name))
            if code_review_id is None:
                continue
            jobs = self._jobs(code_review_id)
            running = sum(1 for job in jobs if job.get("status") in _BUSY_STATUSES)
            busy += running
            if running:
                continue
            last = max(
                (
                    job["createdAt"]
                    for job in jobs
                    if job.get("status") in _QUALIFYING_STATUSES
                ),
                default=None,
            )
            if last is None or now - last >= CODE_REVIEW_INTERVAL:
                due.append((last, code_review_id))
        # The sort is stable, so ties keep the order of `repositories`.
        due.sort(key=lambda item: (item[0] is not None, item[0] or now))
        started = failed = 0
        for _, code_review_id in due[: max(MAX_CONCURRENT_CODE_REVIEWS - busy, 0)]:
            try:
                self._client.start_code_review_job(
                    agentSpaceId=self._space, codeReviewId=code_review_id
                )
            except ClientError as e:
                if e.response["Error"]["Code"] == "ThrottlingException":
                    break
                failed += 1
            else:
                started += 1
        return StartResult(started, failed)
