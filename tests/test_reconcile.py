"""Tests for planning issue state changes."""

from dataclasses import replace
from datetime import UTC
from datetime import datetime

from continuum_scan.models import CompletedScan
from continuum_scan.models import Detection
from continuum_scan.models import RevalidationResult
from continuum_scan.models import Severity
from continuum_scan.models import TargetScan
from continuum_scan.reconcile import plan_sync
from continuum_scan.records import Record
from continuum_scan.render import CLOSED_ABSENT
from continuum_scan.render import CLOSED_WITHDRAWN
from continuum_scan.render import REOPENED
from continuum_scan.render import REVALIDATED_FIXED
from continuum_scan.render import REVALIDATED_STILL
from continuum_scan.render import REVALIDATION_FAILED
from continuum_scan.render import urgent_notice
from continuum_scan.state import IssueState

DAY1 = datetime(2026, 11, 1, tzinfo=UTC)
DAY8 = datetime(2026, 11, 8, tzinfo=UTC)
SITES = {"weekly-x": "x.example.com"}


def _det(
    key: str, severity: Severity = Severity.MEDIUM, urgent: bool = False
) -> Detection:
    return Detection(
        source="pentest",
        target="weekly-x",
        repository="example-org/x",
        key=key,
        external_id="f1",
        name="finding",
        severity=severity,
        urgent=urgent,
        confidence="HIGH",
        detected_at=DAY1,
        pentest_id="pt-1",
    )


def _record(
    number: int,
    *,
    open: bool = True,
    labels: tuple[str, ...] | None = None,
    state_reason: str | None = None,
    closed_at: datetime | None = None,
    **state,
) -> Record:
    # Open issues default to "new"; closed ones default to no status label so
    # a reopen visibly adds "new".
    if labels is None:
        labels = ("new",) if open else ()
    base = IssueState(
        source="pentest",
        target="weekly-x",
        keys=(),
        finding_ids=("f1",),
        pentest_id="pt-1",
    )
    return Record(
        number=number,
        url=f"u{number}",
        title="t",
        body="b",
        open=open,
        state_reason=state_reason,
        labels=frozenset(labels),
        created_at=DAY1,
        closed_at=closed_at,
        state=replace(base, **state),
    )


def _scan(
    found: tuple[Detection, ...] = (),
    candidates: tuple[Detection, ...] = (),
    withdrawn: tuple[str, ...] = (),
    scan_id: str = "j2",
    started: datetime = DAY8,
    completed: bool = True,
) -> TargetScan:
    return TargetScan(
        source="pentest",
        target="weekly-x",
        candidates=candidates,
        withdrawn=frozenset(withdrawn),
        completed=CompletedScan(scan_id, started, {d.key: d for d in found})
        if completed
        else None,
        latest_status="COMPLETED" if completed else "IN_PROGRESS",
        completed_at=started if completed else None,
    )


def test_new_candidate_is_created_once() -> None:
    d = _det("k1")
    plan = plan_sync(
        [_scan(candidates=(d,)), _scan(candidates=(d,), scan_id="j3")], [], {}, {}
    )
    assert plan.creations == (d,)


def test_known_candidate_is_not_created_again() -> None:
    plan = plan_sync(
        [_scan(candidates=(_det("k1"),), found=(_det("k1"),))],
        [_record(1, keys=("k1",))],
        {},
        {},
    )
    assert plan.creations == ()


def test_first_miss_marks_pending() -> None:
    plan = plan_sync([_scan()], [_record(1, keys=("k1",), labels=("wip",))], {}, {})
    (update,) = plan.updates
    assert update.add_labels == {"pending"} and update.remove_labels == {"wip"}
    assert update.state.misses == 1 and update.state.checked_scan == "j2"
    assert update.close is None


def test_second_miss_closes_as_completed() -> None:
    plan = plan_sync(
        [_scan(scan_id="j3")],
        [_record(1, keys=("k1",), labels=("pending",), misses=1, checked_scan="j2")],
        {},
        {},
    )
    (update,) = plan.updates
    assert update.close == "completed" and update.state.auto_closed == "absent"
    assert update.comments == (CLOSED_ABSENT,)


def test_found_again_while_pending_goes_back_to_new() -> None:
    plan = plan_sync(
        [_scan(found=(_det("k1"),), scan_id="j3")],
        [_record(1, keys=("k1",), labels=("pending",), misses=1, checked_scan="j2")],
        {},
        {},
    )
    (update,) = plan.updates
    assert update.add_labels == {"new"} and update.remove_labels == {"pending"}
    assert update.state.misses == 0


def test_same_completed_scan_counts_once() -> None:
    record = _record(1, keys=("k1",), labels=("pending",), misses=1, checked_scan="j2")
    assert plan_sync([_scan(scan_id="j2")], [record], {}, {}).updates == ()


def test_failed_or_running_scan_counts_no_miss() -> None:
    record = _record(1, keys=("k1",))
    assert plan_sync([_scan(completed=False)], [record], {}, {}).updates == ()


def test_withdrawn_finding_closes_as_not_planned() -> None:
    plan = plan_sync(
        [_scan(withdrawn=("k1",), completed=False)], [_record(1, keys=("k1",))], {}, {}
    )
    (update,) = plan.updates
    assert update.close == "not_planned" and update.state.auto_closed == "withdrawn"
    assert update.comments == (CLOSED_WITHDRAWN,)


def test_severity_rise_relabels_and_notifies() -> None:
    record = _record(
        1,
        keys=("k1",),
        labels=("new", "severity:medium"),
        severity="MEDIUM",
        urgent=False,
    )
    plan = plan_sync(
        [_scan(found=(_det("k1", severity=Severity.HIGH, urgent=True),))],
        [record],
        {},
        {},
        mention="@octocat",
    )
    (update,) = plan.updates
    assert update.add_labels == {"severity:high", "urgent"}
    assert update.remove_labels == {"severity:medium"}
    assert update.comments == (urgent_notice("@octocat"),)
    assert (update.state.severity, update.state.urgent) == ("HIGH", True)


def test_closed_issue_found_by_a_later_scan_is_reopened() -> None:
    record = _record(
        1,
        keys=("k1",),
        open=False,
        state_reason="completed",
        closed_at=DAY1,
        auto_closed="absent",
    )
    plan = plan_sync([_scan(found=(_det("k1"),), started=DAY8)], [record], {}, {})
    (update,) = plan.updates
    assert (
        update.reopen
        and update.add_labels == {"new"}
        and update.comments == (REOPENED,)
    )
    assert update.state.auto_closed is None


def test_scan_that_started_before_the_close_does_not_reopen() -> None:
    record = _record(
        1,
        keys=("k1",),
        open=False,
        state_reason="completed",
        closed_at=DAY8,
        auto_closed="absent",
    )
    plan = plan_sync([_scan(found=(_det("k1"),), started=DAY1)], [record], {}, {})
    assert all(not u.reopen for u in plan.updates)


def test_owner_not_planned_is_never_reopened_or_refiled() -> None:
    record = _record(
        1, keys=("k1",), open=False, state_reason="not_planned", closed_at=DAY1
    )
    plan = plan_sync(
        [_scan(found=(_det("k1"),), candidates=(_det("k1"),), started=DAY8)],
        [record],
        {},
        {},
    )
    assert plan.creations == () and all(not u.reopen for u in plan.updates)


def test_owner_close_starts_one_revalidation() -> None:
    record = _record(
        1, keys=("k1",), open=False, state_reason="completed", closed_at=DAY1
    )
    (update,) = plan_sync([], [record], {}, {}).updates
    assert update.revalidate is True
    started = _record(
        1,
        keys=("k1",),
        open=False,
        state_reason="completed",
        closed_at=DAY1,
        revalidation_job="rv1",
    )
    assert plan_sync([], [started], {}, {}).updates == ()


def test_revalidation_result_reopens_or_comments() -> None:
    record = _record(
        1,
        keys=("k1",),
        open=False,
        state_reason="completed",
        closed_at=DAY1,
        revalidation_job="rv1",
    )
    (still,) = plan_sync(
        [], [record], {}, {"rv1": RevalidationResult("COMPLETED", "CONFIRMED")}
    ).updates
    assert still.reopen and still.comments == (REVALIDATED_STILL,)
    assert still.state.revalidation_job is None
    (fixed,) = plan_sync(
        [], [record], {}, {"rv1": RevalidationResult("COMPLETED", "NOT_REPRODUCED")}
    ).updates
    assert not fixed.reopen and fixed.comments == (REVALIDATED_FIXED,)
    (failed,) = plan_sync(
        [], [record], {}, {"rv1": RevalidationResult("FAILED", None)}
    ).updates
    assert failed.comments == (REVALIDATION_FAILED,)
    assert (
        plan_sync(
            [], [record], {}, {"rv1": RevalidationResult("IN_PROGRESS", None)}
        ).updates
        == ()
    )


def test_duplicate_moves_keys_to_the_canonical_issue() -> None:
    canonical = _record(4, keys=("k1",), finding_ids=("f1",))
    duplicate = _record(
        9,
        keys=("k2",),
        finding_ids=("f2",),
        open=False,
        state_reason="duplicate",
        closed_at=DAY1,
    )
    plan = plan_sync([], [canonical, duplicate], {9: 4}, {})
    by_number = {u.number: u for u in plan.updates}
    assert by_number[4].state.keys == ("k1", "k2")
    assert by_number[4].state.finding_ids == ("f1", "f2")
    assert by_number[9].state.merged_into == 4


def test_code_vuln_issue_is_never_revalidated() -> None:
    record = _record(
        1,
        source="code-vuln",
        keys=("cv:e/i",),
        open=False,
        state_reason="completed",
        closed_at=DAY1,
    )
    assert plan_sync([], [record], {}, {}).updates == ()


def test_completed_revalidation_without_a_verdict_is_a_failure() -> None:
    record = _record(
        1,
        keys=("k1",),
        open=False,
        state_reason="completed",
        closed_at=DAY1,
        revalidation_job="rv1",
    )
    (update,) = plan_sync(
        [], [record], {}, {"rv1": RevalidationResult("COMPLETED", None)}
    ).updates
    assert not update.reopen and update.comments == (REVALIDATION_FAILED,)
    assert update.state.revalidation_done


def test_stopped_revalidation_is_a_failure() -> None:
    record = _record(
        1,
        keys=("k1",),
        open=False,
        state_reason="completed",
        closed_at=DAY1,
        revalidation_job="rv1",
    )
    (update,) = plan_sync(
        [], [record], {}, {"rv1": RevalidationResult("STOPPED", None)}
    ).updates
    assert update.comments == (REVALIDATION_FAILED,) and update.state.revalidation_done


def test_finished_revalidation_is_not_reported_again() -> None:
    record = _record(
        1,
        keys=("k1",),
        open=False,
        state_reason="completed",
        closed_at=DAY1,
        revalidation_job="rv1",
        revalidation_done=True,
    )
    assert (
        plan_sync(
            [], [record], {}, {"rv1": RevalidationResult("COMPLETED", "CONFIRMED")}
        ).updates
        == ()
    )


def test_owner_reopened_issue_clears_auto_closed() -> None:
    record = _record(1, keys=("k1",), auto_closed="absent")
    (update,) = plan_sync([], [record], {}, {}).updates
    assert update.state.auto_closed is None
    assert not update.reopen and update.close is None and update.comments == ()


def test_withdrawn_key_of_a_closed_issue_does_nothing() -> None:
    record = _record(
        1,
        keys=("k1",),
        open=False,
        state_reason="completed",
        closed_at=DAY1,
        auto_closed="absent",
    )
    assert (
        plan_sync([_scan(withdrawn=("k1",), completed=False)], [record], {}, {}).updates
        == ()
    )


def test_merged_duplicate_is_ignored_and_the_canonical_indexes_its_keys() -> None:
    duplicate = _record(
        9,
        keys=("k2",),
        open=False,
        state_reason="duplicate",
        closed_at=DAY1,
        merged_into=4,
    )
    candidate = _det("k2")
    holds = _record(4, keys=("k1", "k2"))
    plan = plan_sync(
        [_scan(candidates=(candidate,), completed=False)],
        [holds, duplicate],
        {9: 4},
        {},
    )
    assert plan.creations == () and plan.updates == ()
    lacks = _record(4, keys=("k1",))
    plan = plan_sync(
        [_scan(candidates=(candidate,), completed=False)],
        [lacks, duplicate],
        {9: 4},
        {},
    )
    assert plan.creations == (candidate,) and plan.updates == ()


def test_merged_duplicate_is_never_evaluated() -> None:
    duplicate = _record(9, keys=("k2",), open=True, merged_into=4)
    assert plan_sync([_scan()], [duplicate], {}, {}).updates == ()


def test_owner_duplicate_is_never_reopened() -> None:
    record = _record(
        1, keys=("k1",), open=False, state_reason="duplicate", closed_at=DAY1
    )
    plan = plan_sync(
        [_scan(found=(_det("k1"),), candidates=(_det("k1"),))], [record], {}, {}
    )
    assert plan.creations == () and all(not u.reopen for u in plan.updates)


def test_owner_completed_close_is_reopened_when_found_later() -> None:
    record = _record(
        1,
        keys=("k1",),
        open=False,
        labels=("wip",),
        state_reason="completed",
        closed_at=DAY1,
    )
    (update,) = plan_sync([_scan(found=(_det("k1"),))], [record], {}, {}).updates
    assert (
        update.reopen
        and update.add_labels == {"new"}
        and update.remove_labels == {"wip"}
    )
    assert update.revalidate is False and update.state.checked_scan == "j2"


def test_withdrawn_close_is_reopened_when_found_later() -> None:
    record = _record(
        1,
        keys=("k1",),
        open=False,
        state_reason="not_planned",
        closed_at=DAY1,
        auto_closed="withdrawn",
    )
    (update,) = plan_sync([_scan(found=(_det("k1"),))], [record], {}, {}).updates
    assert update.reopen and update.comments == (REOPENED,)


def test_found_below_medium_counts_as_a_miss() -> None:
    record = _record(1, keys=("k1",), labels=("new", "severity:medium"))
    low = _scan(found=(_det("k1", severity=Severity.LOW),))
    (update,) = plan_sync([low], [record], {}, {}).updates
    assert update.close is None and update.state.auto_closed is None
    assert update.add_labels == {"pending"} and update.state.misses == 1
    assert update.comments == ()
    pending = _record(
        1,
        keys=("k1",),
        labels=("pending", "severity:medium"),
        misses=1,
        checked_scan="j2",
    )
    (closed,) = plan_sync(
        [_scan(found=(_det("k1", severity=Severity.LOW),), scan_id="j3")],
        [pending],
        {},
        {},
    ).updates
    assert closed.close == "completed" and closed.state.auto_closed == "absent"
    assert closed.comments == (CLOSED_ABSENT,)


def test_found_below_medium_does_not_reopen() -> None:
    record = _record(
        1,
        keys=("k1",),
        open=False,
        state_reason="completed",
        closed_at=DAY1,
        auto_closed="absent",
    )
    low = _scan(found=(_det("k1", severity=Severity.LOW),))
    assert all(not u.reopen for u in plan_sync([low], [record], {}, {}).updates)


def test_wip_drops_the_other_status_labels() -> None:
    record = _record(1, keys=("k1",), labels=("new", "pending", "wip"))
    (update,) = plan_sync([], [record], {}, {}).updates
    assert update.remove_labels == {"new", "pending"} and update.add_labels == set()
    closed = _record(
        2, keys=("k2",), open=False, labels=("new", "wip"), state_reason="not_planned"
    )
    assert plan_sync([], [closed], {}, {}).updates == ()


def test_wip_issue_found_again_keeps_wip() -> None:
    record = _record(1, keys=("k1",), labels=("pending", "wip"), misses=1)
    (update,) = plan_sync([_scan(found=(_det("k1"),))], [record], {}, {}).updates
    assert update.remove_labels == {"pending"} and update.add_labels == set()
    assert update.state.misses == 0


def test_found_detection_adds_its_finding_ids_in_order() -> None:
    record = _record(1, keys=("k1",), finding_ids=("f1",))
    detection = replace(_det("k1"), external_id="f2", extra_finding_ids=("f1", "f3"))
    (update,) = plan_sync([_scan(found=(detection,))], [record], {}, {}).updates
    assert update.state.finding_ids == ("f1", "f2", "f3")
    same = _record(1, keys=("k1",), finding_ids=("f1", "f2", "f3"), checked_scan="j1")
    (unchanged,) = plan_sync([_scan(found=(detection,))], [same], {}, {}).updates
    assert unchanged.state == replace(same.state, checked_scan="j2")


def test_owner_reopen_resets_the_revalidation() -> None:
    done = _record(1, keys=("k1",), revalidation_job="rv1", revalidation_done=True)
    (update,) = plan_sync([], [done], {}, {}).updates
    assert update.state.revalidation_job is None
    assert update.state.revalidation_done is False
    running = _record(1, keys=("k1",), revalidation_job="rv1")
    (update,) = plan_sync([], [running], {}, {}).updates
    assert update.state.revalidation_job is None
    closed_again = replace(done, open=False, state_reason="completed", closed_at=DAY8)
    closed_again = replace(
        closed_again,
        state=replace(
            closed_again.state, revalidation_job=None, revalidation_done=False
        ),
    )
    (again,) = plan_sync([], [closed_again], {}, {}).updates
    assert again.revalidate is True


def test_urgency_drop_removes_the_label() -> None:
    record = _record(
        1,
        keys=("k1",),
        labels=("new", "severity:high", "urgent"),
        severity="HIGH",
        urgent=True,
    )
    (update,) = plan_sync(
        [_scan(found=(_det("k1", severity=Severity.MEDIUM),))], [record], {}, {}
    ).updates
    assert update.add_labels == {"severity:medium"}
    assert update.remove_labels == {"severity:high", "urgent"}
    assert update.comments == () and (update.state.severity, update.state.urgent) == (
        "MEDIUM",
        False,
    )


def test_unchanged_found_issue_only_records_the_scan() -> None:
    record = _record(1, keys=("k1",), labels=("wip", "severity:medium"))
    (update,) = plan_sync([_scan(found=(_det("k1"),))], [record], {}, {}).updates
    assert update.add_labels == frozenset() and update.remove_labels == frozenset()
    assert update.state == replace(record.state, checked_scan="j2")


def test_scans_of_other_targets_do_not_count() -> None:
    record = _record(1, keys=("k1",), target="weekly-y")
    assert plan_sync([_scan()], [record], {}, {}).updates == ()


def test_updates_are_sorted_by_number() -> None:
    records = [_record(n, keys=(f"k{n}",)) for n in (3, 1, 2)]
    numbers = [u.number for u in plan_sync([_scan()], records, {}, {}).updates]
    assert numbers == [1, 2, 3]


def test_owner_not_planned_after_auto_close_is_final() -> None:
    record = _record(
        1,
        keys=("k1",),
        open=False,
        state_reason="not_planned",
        closed_at=DAY1,
        auto_closed="absent",
    )
    plan = plan_sync(
        [_scan(found=(_det("k1"),), candidates=(_det("k1"),))], [record], {}, {}
    )
    (update,) = plan.updates
    assert plan.creations == () and not update.reopen
    assert update.state.auto_closed is None


def test_owner_duplicate_after_auto_close_is_merged_not_reopened() -> None:
    canonical = _record(2, keys=("k2",))
    record = _record(
        1,
        keys=("k1",),
        open=False,
        state_reason="duplicate",
        closed_at=DAY1,
        auto_closed="withdrawn",
    )
    plan = plan_sync([_scan(found=(_det("k1"),))], [canonical, record], {1: 2}, {})
    by_number = {u.number: u for u in plan.updates}
    assert not by_number[1].reopen and by_number[1].state.merged_into == 2
    assert by_number[1].state.checked_scan is None


def test_owner_completed_close_after_auto_close_is_revalidated() -> None:
    record = _record(
        1,
        keys=("k1",),
        open=False,
        state_reason="completed",
        closed_at=DAY1,
        auto_closed="withdrawn",
    )
    (update,) = plan_sync([], [record], {}, {}).updates
    assert update.revalidate and update.state.auto_closed is None


def test_bot_absent_close_is_not_revalidated() -> None:
    record = _record(
        1,
        keys=("k1",),
        open=False,
        state_reason="completed",
        closed_at=DAY1,
        auto_closed="absent",
    )
    assert plan_sync([], [record], {}, {}).updates == ()


def _duplicate(number: int, key: str) -> Record:
    return _record(
        number,
        keys=(key,),
        finding_ids=(f"f{number}",),
        open=False,
        state_reason="duplicate",
        closed_at=DAY1,
    )


def test_duplicate_chain_merges_into_the_final_canonical() -> None:
    records = [
        _record(2, keys=("k2",), finding_ids=("f2",)),
        _duplicate(4, "k4"),
        _duplicate(9, "k9"),
    ]
    plan = plan_sync([], records, {4: 2, 9: 4}, {})
    by_number = {u.number: u for u in plan.updates}
    assert by_number[2].state.keys == ("k2", "k4", "k9")
    assert by_number[2].state.finding_ids == ("f2", "f4", "f9")
    assert by_number[4].state.merged_into == 2
    assert by_number[9].state.merged_into == 2


def test_duplicate_cycle_merges_nothing() -> None:
    records = [_duplicate(4, "k4"), _duplicate(9, "k9")]
    assert plan_sync([], records, {4: 9, 9: 4}, {}).updates == ()


def test_withdrawn_key_does_not_close_an_issue_with_a_found_key() -> None:
    record = _record(1, keys=("k1", "k2"))
    found = plan_sync(
        [_scan(withdrawn=("k1",), found=(_det("k2"),))], [record], {}, {}
    ).updates
    assert all(u.close is None for u in found)
    candidate = plan_sync(
        [_scan(withdrawn=("k1",), candidates=(_det("k2"),), completed=False)],
        [record],
        {},
        {},
    ).updates
    assert all(u.close is None for u in candidate)
    both = plan_sync(
        [_scan(withdrawn=("k1", "k2"), completed=False)], [record], {}, {}
    ).updates
    assert both[0].close == "not_planned"


def test_owner_reopened_withdrawn_issue_stays_open() -> None:
    record = _record(1, keys=("k1",), auto_closed="withdrawn")
    (update,) = plan_sync(
        [_scan(withdrawn=("k1",), completed=False)], [record], {}, {}
    ).updates
    assert update.close is None and update.comments == ()
    assert update.state.auto_closed is None and update.state.keep_open
    kept = _record(1, keys=("k1",), keep_open=True)
    assert (
        plan_sync([_scan(withdrawn=("k1",), completed=False)], [kept], {}, {}).updates
        == ()
    )
    (low,) = plan_sync(
        [_scan(found=(_det("k1", severity=Severity.LOW),))], [kept], {}, {}
    ).updates
    assert low.close is None and low.add_labels == {"pending"}
    absent = replace(kept, labels=frozenset({"pending"}))
    absent = replace(absent, state=replace(absent.state, misses=1))
    (gone,) = plan_sync([_scan()], [absent], {}, {}).updates
    assert gone.close == "completed"


def test_scan_reopen_resets_misses() -> None:
    record = _record(
        1,
        keys=("k1",),
        open=False,
        state_reason="completed",
        closed_at=DAY1,
        auto_closed="absent",
        misses=2,
    )
    (update,) = plan_sync([_scan(found=(_det("k1"),))], [record], {}, {}).updates
    assert update.state.misses == 0


def test_revalidated_still_resets_misses_and_revalidation() -> None:
    record = _record(
        1,
        keys=("k1",),
        open=False,
        state_reason="completed",
        closed_at=DAY1,
        revalidation_job="rv1",
        misses=2,
    )
    (update,) = plan_sync(
        [], [record], {}, {"rv1": RevalidationResult("COMPLETED", "CONFIRMED")}
    ).updates
    assert update.reopen and update.state.misses == 0
    assert update.state.revalidation_job is None
    assert update.state.revalidation_done is False


def test_owner_reopen_resets_misses() -> None:
    record = _record(1, keys=("k1",), auto_closed="absent", misses=2)
    (update,) = plan_sync([], [record], {}, {}).updates
    assert update.state.misses == 0


def test_scan_started_before_the_issue_is_not_a_miss() -> None:
    record = replace(_record(1, keys=("k1",)), created_at=DAY8)
    (update,) = plan_sync([_scan(started=DAY8)], [record], {}, {}).updates
    assert update.state == replace(record.state, checked_scan="j2")
    assert update.add_labels == frozenset() and update.remove_labels == frozenset()


def test_completed_revalidation_with_an_unknown_verdict_is_a_failure() -> None:
    record = _record(
        1,
        keys=("k1",),
        open=False,
        state_reason="completed",
        closed_at=DAY1,
        revalidation_job="rv1",
    )
    (update,) = plan_sync(
        [], [record], {}, {"rv1": RevalidationResult("COMPLETED", "INCONCLUSIVE")}
    ).updates
    assert not update.reopen and update.comments == (REVALIDATION_FAILED,)


def test_reopening_an_urgent_issue_notifies() -> None:
    record = _record(
        1,
        keys=("k1",),
        open=False,
        labels=("severity:high", "urgent"),
        state_reason="completed",
        closed_at=DAY1,
        auto_closed="absent",
        severity="HIGH",
        urgent=True,
    )
    detection = _det("k1", severity=Severity.HIGH, urgent=True)
    (update,) = plan_sync(
        [_scan(found=(detection,))], [record], {}, {}, mention="@octocat"
    ).updates
    assert update.comments == (REOPENED, urgent_notice("@octocat"))
    revalidated = replace(record, state=replace(record.state, revalidation_job="rv1"))
    (still,) = plan_sync(
        [],
        [revalidated],
        {},
        {"rv1": RevalidationResult("COMPLETED", "CONFIRMED")},
        mention="@octocat",
    ).updates
    assert still.comments == (REVALIDATED_STILL, urgent_notice("@octocat"))


def test_duplicate_of_an_already_merged_duplicate_follows_its_merged_into() -> None:
    merged = _duplicate(4, "k4")
    records = [
        _record(2, keys=("k2",), finding_ids=("f2",)),
        replace(merged, state=replace(merged.state, merged_into=2)),
        _duplicate(9, "k9"),
    ]
    plan = plan_sync([], records, {9: 4}, {})
    by_number = {u.number: u for u in plan.updates}
    assert by_number[2].state.keys == ("k2", "k9")
    assert by_number[9].state.merged_into == 2


def test_withdrawn_close_drops_the_severity_and_urgent_labels() -> None:
    record = _record(
        1,
        keys=("k1",),
        labels=("new", "severity:high", "urgent"),
        severity="HIGH",
        urgent=True,
    )
    plan = plan_sync([_scan(withdrawn=("k1",), completed=False)], [record], {}, {})
    (update,) = plan.updates
    assert update.close == "not_planned"
    assert update.remove_labels == {"severity:high", "urgent"}
    assert update.state.urgent is False


def test_reopened_withdrawn_issue_gets_its_severity_label_back() -> None:
    record = _record(
        1,
        keys=("k1",),
        open=False,
        labels=("new",),
        state_reason="not_planned",
        closed_at=DAY1,
        auto_closed="withdrawn",
        severity="HIGH",
        urgent=False,
    )
    found = _det("k1", severity=Severity.HIGH, urgent=True)
    (update,) = plan_sync(
        [_scan(found=(found,))], [record], {}, {}, mention="@octocat"
    ).updates
    assert update.reopen
    assert {"severity:high", "urgent"} <= update.add_labels
    assert urgent_notice("@octocat") in update.comments


def test_pentest_issue_without_a_site_label_gets_one() -> None:
    (update,) = plan_sync([], [_record(1, keys=("k1",))], {}, {}, SITES).updates
    assert update.add_labels == {"site:x.example.com"}
    assert update.remove_labels == frozenset()
    assert update.close is None and not update.reopen and update.comments == ()


def test_site_label_is_added_once() -> None:
    record = _record(1, keys=("k1",), labels=("new", "site:x.example.com"))
    assert plan_sync([], [record], {}, {}, SITES).updates == ()


def test_closed_pentest_issue_gets_only_the_site_label() -> None:
    for reason in ("completed", "not_planned", "duplicate"):
        record = _record(
            1,
            open=False,
            state_reason=reason,
            closed_at=DAY1,
            keys=("k1",),
            revalidation_done=True,
        )
        (update,) = plan_sync([], [record], {}, {}, SITES).updates
        assert update.add_labels == {"site:x.example.com"}
        assert not update.reopen and update.close is None and not update.revalidate


def test_merged_duplicate_gets_the_site_label() -> None:
    record = _record(
        2,
        open=False,
        state_reason="duplicate",
        closed_at=DAY1,
        keys=("k1",),
        merged_into=1,
    )
    (update,) = plan_sync([], [record], {}, {}, SITES).updates
    assert update.number == 2
    assert update.add_labels == {"site:x.example.com"}
    assert update.state == record.state


def test_site_label_joins_other_changes() -> None:
    plan = plan_sync([_scan()], [_record(1, keys=("k1",))], {}, {}, SITES)
    (update,) = plan.updates
    assert update.add_labels == {"pending", "site:x.example.com"}


def test_unknown_pentest_gets_no_site_label() -> None:
    record = _record(1, keys=("k1",), target="weekly-unknown")
    assert plan_sync([], [record], {}, {}, SITES).updates == ()


def test_code_vuln_issue_gets_no_site_label() -> None:
    record = _record(1, keys=("k1",), source="code-vuln")
    assert plan_sync([], [record], {}, {}, SITES).updates == ()
