"""In-memory stand-ins for the GitHub and Continuum clients."""

from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from continuum_github.bedrock import Purpose
from continuum_github.codereview import StartResult
from continuum_github.config import Repository
from continuum_github.config import Site
from continuum_github.config import code_review_title
from continuum_github.models import Detection
from continuum_github.models import RevalidationResult
from continuum_github.models import TargetScan

# A targets file for tests that run the command line.
TARGETS_PATH = Path(__file__).parent / "targets.toml"


def _missing(source: Any, target: str) -> TargetScan:
    return TargetScan(
        source=source,
        target=target,
        candidates=(),
        withdrawn=frozenset(),
        completed=None,
        latest_status="MISSING",
        completed_at=None,
    )


class FakeGitHub:
    def __init__(
        self,
        issues: Sequence[Mapping[str, Any]] = (),
        canonicals: Mapping[int, int] | None = None,
    ) -> None:
        self._issues = [dict(item) for item in issues]
        self._canonicals = dict(canonicals or {})
        self.bodies: dict[int, str] = {}
        self.canonical_calls: list[int] = []
        self.comments: list[tuple[int, str]] = []
        self.created: list[tuple[str, str, list[str]]] = []
        self.labels: dict[int, list[str]] = {}
        self.label_sets: list[Mapping[str, tuple[str, str]]] = []
        self.titles: dict[int, str] = {}
        self.updates: list[tuple[int, dict[str, str]]] = []

    def issues(self) -> list[dict[str, Any]]:
        return self._issues

    def create_issue(
        self, title: str, body: str, labels: Sequence[str]
    ) -> tuple[int, str]:
        numbers = [item["number"] for item in self._issues]
        number = max([*numbers, *self.bodies, 0]) + 1
        self.created.append((title, body, list(labels)))
        self.bodies[number] = body
        return number, f"https://github.com/example-org/continuum/issues/{number}"

    def update_issue(
        self,
        number: int,
        *,
        body: str | None = None,
        labels: Sequence[str] | None = None,
        state: str | None = None,
        state_reason: str | None = None,
        title: str | None = None,
    ) -> None:
        if title is not None:
            self.titles[number] = title
        if body is not None:
            self.bodies[number] = body
        if labels is not None:
            self.labels[number] = list(labels)
        fields = {}
        if state is not None:
            fields["state"] = state
        if state_reason is not None:
            fields["state_reason"] = state_reason
        if fields:
            self.updates.append((number, fields))

    def comment(self, number: int, body: str) -> None:
        self.comments.append((number, body))

    def duplicate_canonical(self, number: int) -> int | None:
        self.canonical_calls.append(number)
        return self._canonicals.get(number)

    def ensure_labels(self, labels: Mapping[str, tuple[str, str]]) -> int:
        self.label_sets.append(labels)
        return 0


class FakePentest:
    def __init__(
        self,
        scans: Mapping[str, TargetScan],
        revalidation_job: str | None = None,
        detections: Mapping[str, Detection] | None = None,
        results: Mapping[str, RevalidationResult] | None = None,
        start_error: Exception | None = None,
    ) -> None:
        self._scans = dict(scans)
        self._revalidation_job = revalidation_job
        self._start_error = start_error
        self.detections = dict(detections or {})
        self.detection_calls: list[tuple[str, datetime | None]] = []
        self._results = dict(results or {})
        self.result_calls: list[tuple[str, str, str]] = []
        self.started: list[tuple[str, str]] = []

    def target_scan(self, site: Site) -> TargetScan:
        return self._scans.get(site.pentest) or _missing("pentest", site.pentest)

    def detection(
        self,
        site: Site,
        finding_id: str,
        fallback_detected_at: datetime | None = None,
    ) -> Detection | None:
        self.detection_calls.append((finding_id, fallback_detected_at))
        return self.detections.get(finding_id)

    def start_revalidation(self, pentest_id: str, finding_id: str) -> str:
        self.started.append((pentest_id, finding_id))
        if self._start_error is not None:
            raise self._start_error
        assert self._revalidation_job is not None
        return self._revalidation_job

    def revalidation_result(
        self, pentest_id: str, job_id: str, finding_id: str
    ) -> RevalidationResult:
        self.result_calls.append((pentest_id, job_id, finding_id))
        return self._results.get(job_id, RevalidationResult("IN_PROGRESS", None))


class FakeModel:
    """Gives one answer to every prompt; failure is the reason for None."""

    def __init__(self, answer: str | None, failure: str | None = None) -> None:
        self._answer = answer
        self._failure = failure
        self.last_failure: str | None = None
        self.prompts: list[str] = []
        self.purposes: list[str] = []

    def ask(
        self, prompt: str, purpose: Purpose, resources: Sequence[Path] = ()
    ) -> str | None:
        self.prompts.append(prompt)
        self.purposes.append(purpose)
        self.last_failure = self._failure if self._answer is None else None
        return self._answer


class RecordingModel:
    """Returns the given answers in order and records each prompt.

    failures, in the same order, give the reason for each None answer.
    """

    def __init__(
        self, answers: Sequence[str | None], failures: Sequence[str | None] = ()
    ) -> None:
        self._answers = list(answers)
        self._failures = list(failures)
        self.last_failure: str | None = None
        self.prompts: list[str] = []
        self.purposes: list[str] = []
        self.resources: list[list[Path]] = []

    def ask(
        self, prompt: str, purpose: Purpose, resources: Sequence[Path] = ()
    ) -> str | None:
        self.prompts.append(prompt)
        self.purposes.append(purpose)
        self.resources.append(list(resources))
        answer = self._answers.pop(0)
        failure = self._failures.pop(0) if self._failures else None
        self.last_failure = failure if answer is None else None
        return answer


class FakeCodeVuln:
    def __init__(
        self,
        scans: Mapping[str, TargetScan] | None = None,
        environments: Mapping[str, str] | None = None,
        detections: Mapping[str, Detection] | None = None,
    ) -> None:
        self._scans = dict(scans or {})
        self._environments = dict(environments or {})
        self.detections = dict(detections or {})
        self.scan_calls: list[tuple[str, str | None]] = []

    def environments(self) -> dict[str, str]:
        return dict(self._environments)

    def target_scan(
        self, repository: Repository, environment_id: str | None
    ) -> TargetScan:
        self.scan_calls.append((repository.name, environment_id))
        return self._scans.get(repository.name) or _missing(
            "code-vuln", repository.name
        )

    def detection(
        self, repository: Repository, environment_id: str, issue_id: str
    ) -> Detection | None:
        return self.detections.get(issue_id)


class FakeCodeReview:
    def __init__(
        self,
        scans: Mapping[str, TargetScan] | None = None,
        detections: Mapping[str, Detection] | None = None,
        started: int = 0,
        start_error: Exception | None = None,
    ) -> None:
        self._scans = dict(scans or {})
        self._started = started
        self._start_error = start_error
        self.detections = dict(detections or {})
        self.scan_calls: list[str] = []
        self.start_calls: list[tuple[list[str], datetime]] = []

    def target_scan(self, repository: Repository) -> TargetScan:
        self.scan_calls.append(repository.name)
        return self._scans.get(repository.name) or _missing(
            "code-review", code_review_title(repository.name)
        )

    def detection(self, repository: Repository, finding_id: str) -> Detection | None:
        return self.detections.get(finding_id)

    def start_due(
        self, repositories: Sequence[Repository], now: datetime
    ) -> StartResult:
        self.start_calls.append(([repository.name for repository in repositories], now))
        if self._start_error is not None:
            raise self._start_error
        return StartResult(self._started, 0)
