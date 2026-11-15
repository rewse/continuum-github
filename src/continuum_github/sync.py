"""Applies sync plans to GitHub issues and pentest revalidations."""

import dataclasses
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, Protocol

import httpx
from botocore.exceptions import BotoCoreError
from botocore.exceptions import ClientError

from continuum_github.bedrock import Failure
from continuum_github.bedrock import ModelLike
from continuum_github.bedrock import finding_sections
from continuum_github.codereview import StartResult
from continuum_github.config import DEFAULT_LANGUAGE
from continuum_github.config import Repository
from continuum_github.config import Site
from continuum_github.config import Targets
from continuum_github.config import code_review_title
from continuum_github.config import environment_name
from continuum_github.models import Detection
from continuum_github.models import RevalidationResult
from continuum_github.models import Severity
from continuum_github.models import Source
from continuum_github.models import TargetScan
from continuum_github.reconcile import Update
from continuum_github.reconcile import plan_sync
from continuum_github.records import Record
from continuum_github.records import records_from_issues
from continuum_github.render import FALLBACK_NOTE
from continuum_github.render import add_mention
from continuum_github.render import fit_body
from continuum_github.render import initial_state
from continuum_github.render import issue_body
from continuum_github.render import issue_labels
from continuum_github.render import issue_title
from continuum_github.render import replace_severity
from continuum_github.render import retitle
from continuum_github.state import IssueState
from continuum_github.state import replace_state

_CODE_VULN_PREFIX = "cv:"
# Errors that fail one creation or update without stopping the run.
_ISOLATED = (ClientError, httpx.HTTPStatusError, ValueError)


class PentestLike(Protocol):
    def target_scan(self, site: Site) -> TargetScan: ...

    def detection(
        self,
        site: Site,
        finding_id: str,
        fallback_detected_at: datetime | None = None,
    ) -> Detection | None: ...

    def start_revalidation(self, pentest_id: str, finding_id: str) -> str: ...

    def revalidation_result(
        self, pentest_id: str, job_id: str, finding_id: str
    ) -> RevalidationResult: ...


class CodeVulnLike(Protocol):
    def environments(self) -> dict[str, str]: ...

    def target_scan(
        self, repository: Repository, environment_id: str | None
    ) -> TargetScan: ...

    def detection(
        self, repository: Repository, environment_id: str, issue_id: str
    ) -> Detection | None: ...


class CodeReviewLike(Protocol):
    def target_scan(self, repository: Repository) -> TargetScan: ...

    def detection(
        self, repository: Repository, finding_id: str
    ) -> Detection | None: ...

    def start_due(
        self, repositories: Sequence[Repository], now: datetime
    ) -> StartResult: ...


class GitHubLike(Protocol):
    def issues(self) -> list[dict[str, Any]]: ...

    def create_issue(
        self, title: str, body: str, labels: Sequence[str]
    ) -> tuple[int, str]: ...

    def update_issue(
        self,
        number: int,
        *,
        body: str | None = None,
        labels: Sequence[str] | None = None,
        state: Literal["open", "closed"] | None = None,
        state_reason: Literal["completed", "not_planned", "reopened"] | None = None,
        title: str | None = None,
    ) -> None: ...

    def comment(self, number: int, body: str) -> None: ...

    def duplicate_canonical(self, number: int) -> int | None: ...

    def ensure_labels(self, labels: Mapping[str, tuple[str, str]]) -> int: ...


@dataclass(frozen=True)
class SyncCounts:
    created: int
    pending: int
    closed: int
    reopened: int
    revalidations: int
    needs_sections: int
    failed: int = 0
    started: int = 0


def _site(targets: Targets, pentest: str) -> Site | None:
    return next((site for site in targets.sites if site.pentest == pentest), None)


def _code_review_repository(targets: Targets, title: str) -> Repository | None:
    return next(
        (
            repository
            for repository in targets.repositories
            if not repository.private and code_review_title(repository.name) == title
        ),
        None,
    )


def full_detection(
    targets: Targets,
    pentest: PentestLike,
    code_vuln: CodeVulnLike,
    code_review: CodeReviewLike,
    source: Source,
    target: str,
    key: str,
    external_id: str,
    fallback_detected_at: datetime | None = None,
) -> Detection | None:
    """Reads a detection with its details.

    fallback_detected_at stands in for a pentest finding's missing creation
    time. Returns None when the target is not in targets or the detection is
    not found.
    """
    if source == "pentest":
        site = _site(targets, target)
        if site is None:
            return None
        return pentest.detection(site, external_id, fallback_detected_at)
    if source == "code-review":
        repository = _code_review_repository(targets, target)
        if repository is None:
            return None
        return code_review.detection(repository, external_id)
    try:
        repository = targets.get(target)
    except ValueError:
        return None
    if not key.startswith(_CODE_VULN_PREFIX):
        return None
    environment_id, _, issue_id = key.removeprefix(_CODE_VULN_PREFIX).partition("/")
    if not environment_id or not issue_id:
        return None
    return code_vuln.detection(repository, environment_id, issue_id)


def collect_scans(
    targets: Targets,
    pentest: PentestLike,
    code_vuln: CodeVulnLike,
    code_review: CodeReviewLike,
) -> list[TargetScan]:
    """Reads the pentest scan of every site, then the scan of every repository
    in targets order: code-vuln for a private one, code-review for a public
    one."""
    scans = [pentest.target_scan(site) for site in targets.sites]
    environments = code_vuln.environments()
    for repository in targets.repositories:
        if repository.private:
            scans.append(
                code_vuln.target_scan(
                    repository,
                    environments.get(environment_name(targets.owner, repository.name)),
                )
            )
        else:
            scans.append(code_review.target_scan(repository))
    return scans


def start_code_reviews(
    targets: Targets, code_review: CodeReviewLike, now: datetime
) -> tuple[int, int]:
    """Starts the code reviews of the public repositories that are due.

    Returns the number started and the number failed. Each rejected start
    counts as one failure, and an AWS error outside the starts, such as one
    from listing the code reviews, counts as one failure with none started.
    Errors are not reported, because they can repeat finding details.
    """
    public = [
        repository for repository in targets.repositories if not repository.private
    ]
    try:
        result = code_review.start_due(public, now)
    except (BotoCoreError, ClientError):
        return 0, 1
    return result.started, result.failed


def _canonicals(github: GitHubLike, records: Sequence[Record]) -> dict[int, int]:
    """Looks up the canonical of each duplicate not merged in an earlier run."""
    canonicals = {}
    for record in records:
        if record.open or record.state_reason != "duplicate":
            continue
        if record.state.merged_into is not None:
            continue
        canonical = github.duplicate_canonical(record.number)
        if canonical is not None:
            canonicals[record.number] = canonical
    return canonicals


def _revalidations(
    pentest: PentestLike, records: Sequence[Record]
) -> dict[str, RevalidationResult]:
    results = {}
    for record in records:
        state = record.state
        if state.source != "pentest" or state.revalidation_done:
            continue
        if state.revalidation_job is None or state.pentest_id is None:
            continue
        if not state.finding_ids:
            continue
        # The first finding ID is the issue's own; later ones may come from
        # merged duplicates of another source.
        results[state.revalidation_job] = pentest.revalidation_result(
            state.pentest_id, state.revalidation_job, state.finding_ids[0]
        )
    return results


@dataclass(frozen=True)
class _Applied:
    open_without_sections: bool
    revalidated: bool


def _body(record: Record, state: IssueState, mention: str) -> str:
    """Returns the record's body brought up to date with state.

    A changed severity rewrites the metadata table, and an issue that has
    become urgent gets mention as its first line.
    """
    body = record.body
    if state.severity != record.state.severity:
        body = replace_severity(body, Severity.parse(state.severity))
    if state.urgent and not record.state.urgent:
        body = add_mention(body, mention)
    return replace_state(body, state)


def _apply(
    github: GitHubLike,
    pentest: PentestLike,
    record: Record,
    update: Update,
    mention: str,
) -> _Applied:
    """Applies one update and reports what it did.

    A revalidation that fails to start leaves the state without a job, so
    the next run plans it again, and the rest of the update still applies.
    """
    for text in update.comments:
        github.comment(update.number, text)
    state = update.state
    revalidated = False
    if update.revalidate:
        if state.pentest_id is None or not state.finding_ids:
            raise ValueError("revalidation planned without pentest_id or finding_ids")
        # A job started here is not recorded if the update below fails, and the
        # next run starts another. StartPentestJob is not idempotent, and the
        # update right after it rarely fails, so this is accepted.
        try:
            job = pentest.start_revalidation(state.pentest_id, state.finding_ids[0])
        except ClientError:
            pass
        else:
            state = dataclasses.replace(state, revalidation_job=job)
            revalidated = True
    fields: dict[str, Any] = {}
    if state != record.state:
        fields["body"] = fit_body(_body(record, state, mention))
    if state.severity != record.state.severity:
        fields["title"] = retitle(record.title, Severity.parse(state.severity))
    if update.add_labels or update.remove_labels:
        fields["labels"] = sorted(
            (record.labels - update.remove_labels) | update.add_labels
        )
    is_open = record.open
    if update.close is not None:
        fields["state"] = "closed"
        fields["state_reason"] = update.close
        is_open = False
    elif update.reopen:
        fields["state"] = "open"
        fields["state_reason"] = "reopened"
        is_open = True
    if fields:
        github.update_issue(update.number, **fields)
    return _Applied(
        open_without_sections=is_open and not state.sections, revalidated=revalidated
    )


def _create(
    targets: Targets,
    github: GitHubLike,
    pentest: PentestLike,
    code_vuln: CodeVulnLike,
    code_review: CodeReviewLike,
    candidate: Detection,
    mention: str,
) -> None:
    full = full_detection(
        targets,
        pentest,
        code_vuln,
        code_review,
        candidate.source,
        candidate.target,
        candidate.key,
        candidate.external_id,
        candidate.detected_at,
    )
    detection = (
        candidate
        if full is None
        else dataclasses.replace(full, extra_finding_ids=candidate.extra_finding_ids)
    )
    github.create_issue(
        issue_title(detection),
        fit_body(issue_body(detection, initial_state(detection), None, mention)),
        issue_labels(detection),
    )


def run_sync(
    targets: Targets,
    github: GitHubLike,
    pentest: PentestLike,
    code_vuln: CodeVulnLike,
    code_review: CodeReviewLike,
    mention: str = "",
) -> SyncCounts:
    """Brings the finding issues in line with the latest scans.

    mention leads the body of an urgent issue and the comment on an issue
    that becomes urgent; an empty mention leaves both out.

    A creation or update that fails with an AWS, GitHub, or body error is
    counted as failed and the run goes on with the next; the error itself is
    not reported, because it can repeat finding details. A failed update is
    planned again by the next run.
    """
    records = records_from_issues(github.issues())
    canonicals = _canonicals(github, records)
    revalidations = _revalidations(pentest, records)
    plan = plan_sync(
        collect_scans(targets, pentest, code_vuln, code_review),
        records,
        canonicals,
        revalidations,
        {site.pentest: site.domain for site in targets.sites},
        mention,
    )

    created = failed = 0
    for candidate in plan.creations:
        try:
            _create(
                targets, github, pentest, code_vuln, code_review, candidate, mention
            )
        except _ISOLATED:
            failed += 1
        else:
            created += 1

    updated = {update.number: update for update in plan.updates}
    applied: list[Update] = []
    revalidations_started = 0
    needs_sections = created
    for record in records:
        update = updated.get(record.number)
        if update is not None:
            try:
                result = _apply(github, pentest, record, update, mention)
            except _ISOLATED:
                failed += 1
            else:
                applied.append(update)
                revalidations_started += result.revalidated
                needs_sections += result.open_without_sections
                continue
        needs_sections += record.open and not record.state.sections

    return SyncCounts(
        created=created,
        pending=sum("pending" in update.add_labels for update in applied),
        closed=sum(update.close is not None for update in applied),
        reopened=sum(update.reopen for update in applied),
        revalidations=revalidations_started,
        needs_sections=needs_sections,
        failed=failed,
    )


def fill_sections(
    targets: Targets,
    github: GitHubLike,
    pentest: PentestLike,
    code_vuln: CodeVulnLike,
    code_review: CodeReviewLike,
    model: ModelLike,
    mention: str = "",
    language: str = DEFAULT_LANGUAGE,
) -> int:
    """Has the model write the summary sections of open issues that lack them.

    The sections are written in the language of the locale language.
    The rewritten body of an urgent issue starts with mention unless it is
    empty. Issues whose detection cannot be read are left for a later run.
    An issue for which the model gives no valid answer gets FALLBACK_NOTE
    once and is retried by a later run. Returns the number of issues filled.
    """
    filled = 0
    for record in records_from_issues(github.issues()):
        state = record.state
        if not record.open or state.sections:
            continue
        if not state.keys or not state.finding_ids:
            continue
        detection = full_detection(
            targets,
            pentest,
            code_vuln,
            code_review,
            state.source,
            state.target,
            state.keys[0],
            state.finding_ids[0],
        )
        if detection is None:
            continue
        sections = finding_sections(model, detection, language)
        if isinstance(sections, Failure):
            # Marks the issue once; a later run retries the sections.
            if FALLBACK_NOTE not in record.body:
                github.update_issue(
                    record.number,
                    body=fit_body(
                        issue_body(detection, state, None, mention, fallback=True)
                    ),
                )
            continue
        state = dataclasses.replace(state, sections=True)
        github.update_issue(
            record.number,
            body=fit_body(issue_body(detection, state, sections, mention)),
        )
        filled += 1
    return filled
