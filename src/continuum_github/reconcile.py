"""Plans issue state changes from scans, issue records, and revalidations."""

import dataclasses
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from continuum_github.models import CompletedScan
from continuum_github.models import Detection
from continuum_github.models import RevalidationResult
from continuum_github.models import Severity
from continuum_github.models import TargetScan
from continuum_github.records import Record
from continuum_github.render import CLOSED_ABSENT
from continuum_github.render import CLOSED_WITHDRAWN
from continuum_github.render import REOPENED
from continuum_github.render import REVALIDATED_FIXED
from continuum_github.render import REVALIDATED_STILL
from continuum_github.render import REVALIDATION_FAILED
from continuum_github.render import SITE_PREFIX
from continuum_github.render import STATUS_LABELS
from continuum_github.render import URGENT
from continuum_github.render import severity_label
from continuum_github.render import site_label
from continuum_github.render import urgent_notice
from continuum_github.state import IssueState

Close = Literal["completed", "not_planned"]

_SEVERITY_PREFIX = "severity:"
_FAILED_JOBS = ("FAILED", "STOPPED")


@dataclass(frozen=True)
class Update:
    number: int
    state: IssueState
    add_labels: frozenset[str] = frozenset()
    remove_labels: frozenset[str] = frozenset()
    close: Close | None = None
    reopen: bool = False
    comments: tuple[str, ...] = ()
    revalidate: bool = False


@dataclass(frozen=True)
class SyncPlan:
    creations: tuple[Detection, ...]
    updates: tuple[Update, ...]


class _Draft:
    """Accumulates the changes to one issue before they become an Update."""

    def __init__(self, record: Record, mention: str) -> None:
        self.record = record
        self.urgent_notice = urgent_notice(mention)
        self.state = record.state
        self.labels = set(record.labels)
        self.close: Close | None = None
        self.reopen = False
        self.comments: list[str] = []
        self.revalidate = False

    @property
    def open(self) -> bool:
        """Returns whether the issue is open once the planned changes apply."""
        if self.close is not None:
            return False
        return self.record.open or self.reopen

    def set(self, **changes) -> None:
        self.state = dataclasses.replace(self.state, **changes)

    def comment(self, text: str) -> None:
        if text not in self.comments:
            self.comments.append(text)

    def set_status(self, status: str) -> None:
        self.labels -= STATUS_LABELS
        self.labels.add(status)

    def do_close(self, reason: Close, auto_closed: str, text: str) -> None:
        self.close = reason
        self.set(auto_closed=auto_closed)
        self.comment(text)

    def do_reopen(self, text: str) -> None:
        self.reopen = True
        self.set_status("new")
        self.set(
            misses=0,
            auto_closed=None,
            revalidation_job=None,
            revalidation_done=False,
        )
        self.comment(text)

    def to_update(self) -> Update | None:
        if self.reopen and self.state.urgent:
            self.comment(self.urgent_notice)
        add = frozenset(self.labels - self.record.labels)
        remove = frozenset(self.record.labels - self.labels)
        changed = (
            self.state != self.record.state
            or add
            or remove
            or self.close is not None
            or self.reopen
            or self.comments
            or self.revalidate
        )
        if not changed:
            return None
        return Update(
            number=self.record.number,
            state=self.state,
            add_labels=add,
            remove_labels=remove,
            close=self.close,
            reopen=self.reopen,
            comments=tuple(self.comments),
            revalidate=self.revalidate,
        )


def _reopenable(draft: _Draft) -> bool:
    """Returns whether a scan that finds the closed issue again may reopen it.

    Completed closes and the bot's withdrawn close may be reopened. The
    owner's not planned and duplicate closes are final.
    """
    reason = draft.record.state_reason
    if reason == "completed":
        return True
    return reason == "not_planned" and draft.state.auto_closed == "withdrawn"


def _note_owner_action(draft: _Draft) -> None:
    """Brings the state in line with the owner's changes to the issue.

    An open issue labeled wip keeps only that status label, since the owner
    added it. An open issue with a revalidation was reopened by the owner,
    so a later completed close revalidates again. An open issue with the
    bot's close marker was reopened by the owner; one reopened from a
    withdrawn close stays open while the finding is withdrawn. A closed
    issue whose close reason differs from the bot's was closed again by the
    owner.
    """
    if draft.record.open:
        if "wip" in draft.labels:
            draft.set_status("wip")
        if draft.state.revalidation_job is not None or draft.state.revalidation_done:
            draft.set(revalidation_job=None, revalidation_done=False)
    auto_closed = draft.state.auto_closed
    if auto_closed is None:
        return
    if draft.record.open:
        draft.set(
            auto_closed=None,
            misses=0,
            keep_open=draft.state.keep_open or auto_closed == "withdrawn",
        )
        return
    bot_reason = "completed" if auto_closed == "absent" else "not_planned"
    if draft.record.state_reason != bot_reason:
        draft.set(auto_closed=None)


def _merged(values: Iterable[str], extra: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys((*values, *extra)))


def _is_duplicate(record: Record) -> bool:
    return not record.open and record.state_reason == "duplicate"


def _canonical(
    number: int,
    records: Mapping[int, Record],
    canonicals: Mapping[int, int],
) -> int | None:
    """Follows canonicals past duplicates to the issue that absorbs number.

    A duplicate without an entry in canonicals was merged in an earlier run,
    so its merged_into continues the chain. Returns None on a cycle or when
    the chain ends outside the records.
    """

    def following(current: int) -> int | None:
        if current in canonicals:
            return canonicals[current]
        return records[current].state.merged_into if current in records else None

    seen = {number}
    target = following(number)
    while target is not None and target in records:
        if target in seen:
            return None
        if not _is_duplicate(records[target]):
            return target
        seen.add(target)
        target = following(target)
    return None


def _merge_duplicates(
    drafts: Mapping[int, _Draft],
    records: Mapping[int, Record],
    canonicals: Mapping[int, int],
) -> None:
    for number, draft in drafts.items():
        if not _is_duplicate(draft.record):
            continue
        target = _canonical(number, records, canonicals)
        if target is None or target not in drafts:
            continue
        canonical = drafts[target]
        canonical.set(
            keys=_merged(canonical.state.keys, draft.state.keys),
            finding_ids=_merged(canonical.state.finding_ids, draft.state.finding_ids),
        )
        draft.set(merged_into=target)


def _found_detection(draft: _Draft, completed: CompletedScan) -> Detection | None:
    """Returns the worst detection among the keys of the issue.

    Returns None when the scan found none of the keys at a filed severity,
    so a finding rated below Medium counts as a miss.
    """
    found = [completed.found[key] for key in draft.state.keys if key in completed.found]
    if not found:
        return None
    worst = max(found, key=lambda detection: detection.severity.rank)
    return worst if worst.severity.filed else None


def _add_finding_ids(draft: _Draft, completed: CompletedScan) -> None:
    """Appends the finding IDs the scan found under the issue's keys."""
    ids = [
        finding_id
        for key in draft.state.keys
        if key in completed.found
        for finding_id in completed.found[key].finding_ids
    ]
    draft.set(finding_ids=_merged(draft.state.finding_ids, ids))


def _apply_detection(
    draft: _Draft, detection: Detection, relabel: bool = False
) -> None:
    """Brings the severity and urgency of the issue up to date.

    relabel restores the severity label even when the severity is unchanged,
    for an issue reopened after a withdrawn close dropped the label.
    """
    severity = detection.severity
    label = severity_label(severity)
    if relabel or severity != Severity.parse(draft.state.severity):
        draft.labels = {
            name for name in draft.labels if not name.startswith(_SEVERITY_PREFIX)
        }
        draft.labels.add(label)
        draft.set(severity=severity.value)
    if detection.urgent:
        if URGENT not in draft.labels:
            draft.labels.add(URGENT)
            if not draft.state.urgent:
                draft.comment(draft.urgent_notice)
    else:
        draft.labels.discard(URGENT)
    draft.set(urgent=detection.urgent)


def _evaluate(draft: _Draft, completed: CompletedScan) -> None:
    _add_finding_ids(draft, completed)
    if completed.started_at <= draft.record.created_at:
        draft.set(checked_scan=completed.scan_id)
        return
    detection = _found_detection(draft, completed)
    if draft.open:
        if detection is None:
            misses = draft.state.misses + 1
            draft.set(misses=misses)
            if misses == 1:
                draft.set_status("pending")
            else:
                draft.do_close("completed", "absent", CLOSED_ABSENT)
        else:
            draft.set(misses=0)
            if "pending" in draft.labels:
                draft.set_status("new")
            _apply_detection(draft, detection)
    elif (
        detection is not None
        and _reopenable(draft)
        and draft.record.closed_at is not None
        and completed.started_at > draft.record.closed_at
    ):
        was_withdrawn = draft.state.auto_closed == "withdrawn"
        draft.do_reopen(REOPENED)
        _apply_detection(draft, detection, relabel=was_withdrawn)
    draft.set(checked_scan=completed.scan_id)


def _revalidation(
    draft: _Draft, revalidations: Mapping[str, RevalidationResult]
) -> None:
    state = draft.state
    if state.source != "pentest" or draft.open or draft.record.open:
        return
    if state.revalidation_done:
        return
    if state.revalidation_job is None:
        if draft.record.state_reason == "completed" and state.auto_closed is None:
            draft.revalidate = True
        return
    result = revalidations.get(state.revalidation_job)
    if result is None:
        return
    if result.job_status == "COMPLETED" and result.validation_status == "CONFIRMED":
        draft.do_reopen(REVALIDATED_STILL)
        return
    if (
        result.job_status == "COMPLETED"
        and result.validation_status == "NOT_REPRODUCED"
    ):
        draft.comment(REVALIDATED_FIXED)
    elif result.job_status == "COMPLETED" or result.job_status in _FAILED_JOBS:
        draft.comment(REVALIDATION_FAILED)
    else:
        return
    draft.set(revalidation_done=True)


def _add_site_label(draft: _Draft, site_domains: Mapping[str, str]) -> None:
    """Adds the site label to a pentest issue that has none.

    An issue that already carries a site label, or whose pentest is not a
    listed site, is left alone.
    """
    state = draft.state
    if state.source != "pentest":
        return
    domain = site_domains.get(state.target)
    if domain is None:
        return
    if any(label.startswith(SITE_PREFIX) for label in draft.labels):
        return
    draft.labels.add(site_label(domain))


def plan_sync(
    scans: Sequence[TargetScan],
    records: Sequence[Record],
    canonicals: Mapping[int, int],
    revalidations: Mapping[str, RevalidationResult],
    site_domains: Mapping[str, str] | None = None,
    mention: str = "",
) -> SyncPlan:
    """Returns the issues to create and the changes to existing issues.

    Records already merged into another issue take part only in getting a
    missing site label. canonicals maps the number of an issue closed as
    duplicate to the issue it duplicates, revalidations maps revalidation
    job IDs to their results, and site_domains maps pentest titles to the
    domains of their sites. mention leads the comment on an issue that
    becomes urgent.
    """
    site_domains = site_domains or {}
    by_number = {record.number: record for record in records}
    drafts = {
        record.number: _Draft(record, mention)
        for record in sorted(records, key=lambda record: record.number)
        if record.state.merged_into is None
    }
    index: dict[str, _Draft] = {}
    for draft in drafts.values():
        for key in draft.record.state.keys:
            index.setdefault(key, draft)

    creations: list[Detection] = []
    seen: set[str] = set()
    for scan in scans:
        for detection in scan.candidates:
            if detection.key in index or detection.key in seen:
                continue
            seen.add(detection.key)
            creations.append(detection)

    _merge_duplicates(drafts, by_number, canonicals)
    # Records merged in this run take no further part in the plan.
    active = [draft for draft in drafts.values() if draft.state.merged_into is None]

    for draft in active:
        _note_owner_action(draft)

    withdrawn: set[int] = set()
    for scan in scans:
        reported = {detection.key for detection in scan.candidates}
        if scan.completed is not None:
            reported.update(scan.completed.found)
        for draft in active:
            keys = set(draft.state.keys)
            if not draft.open or draft.state.keep_open or not keys:
                continue
            if not keys <= scan.withdrawn or keys & reported:
                continue
            draft.do_close("not_planned", "withdrawn", CLOSED_WITHDRAWN)
            # A withdrawn finding has no filed severity and is not urgent.
            draft.labels = {
                label
                for label in draft.labels
                if not label.startswith(_SEVERITY_PREFIX) and label != URGENT
            }
            draft.set(urgent=False)
            withdrawn.add(draft.record.number)

    for scan in scans:
        completed = scan.completed
        if completed is None:
            continue
        for draft in active:
            state = draft.state
            if (state.source, state.target) != (scan.source, scan.target):
                continue
            if draft.record.number in withdrawn:
                continue
            if completed.scan_id == state.checked_scan:
                continue
            _evaluate(draft, completed)

    for draft in active:
        _revalidation(draft, revalidations)

    # Records merged in an earlier run get no draft above, so they get one
    # here for the site label alone.
    merged = [
        _Draft(record, mention)
        for record in sorted(records, key=lambda record: record.number)
        if record.state.merged_into is not None
    ]
    for draft in (*drafts.values(), *merged):
        _add_site_label(draft, site_domains)

    updates = [
        update
        for draft in sorted(
            (*drafts.values(), *merged), key=lambda draft: draft.record.number
        )
        if (update := draft.to_update()) is not None
    ]
    return SyncPlan(creations=tuple(creations), updates=tuple(updates))
