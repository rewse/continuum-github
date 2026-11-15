"""Tests for applying sync plans."""

from dataclasses import replace
from datetime import UTC
from datetime import datetime
from typing import Any

import httpx
from botocore.exceptions import ClientError
from botocore.exceptions import EndpointConnectionError
from fakes import FakeCodeReview
from fakes import FakeCodeVuln
from fakes import FakeGitHub
from fakes import FakeModel
from fakes import FakePentest

from continuum_github.config import Repository
from continuum_github.config import Site
from continuum_github.config import Targets
from continuum_github.models import CompletedScan
from continuum_github.models import Detection
from continuum_github.models import RevalidationResult
from continuum_github.models import Severity
from continuum_github.models import TargetScan
from continuum_github.render import CLOSED_ABSENT
from continuum_github.render import REOPENED
from continuum_github.render import REVALIDATED_FIXED
from continuum_github.render import fallback_note
from continuum_github.render import issue_body
from continuum_github.state import IssueState
from continuum_github.state import parse_state
from continuum_github.state import render_state
from continuum_github.sync import SyncCounts
from continuum_github.sync import collect_scans
from continuum_github.sync import fill_sections
from continuum_github.sync import full_detection
from continuum_github.sync import run_sync
from continuum_github.sync import start_code_reviews

DAY1 = datetime(2026, 11, 1, tzinfo=UTC)
DAY8 = datetime(2026, 11, 8, tzinfo=UTC)
TARGETS = Targets(
    owner="example-org",
    repositories=(Repository("ansible-playbooks", False),),
    sites=(Site("x.example.com", "weekly-x", "ansible-playbooks"),),
)


def _det(key: str, external_id: str = "f1", name: str = "finding") -> Detection:
    return Detection(
        source="pentest",
        target="weekly-x",
        repository="ansible-playbooks",
        key=key,
        external_id=external_id,
        name=name,
        severity=Severity.MEDIUM,
        urgent=False,
        confidence="HIGH",
        detected_at=DAY1,
        site="x.example.com",
        pentest_id="pt-1",
    )


def _scan(
    candidates: tuple[Detection, ...] = (),
    found: tuple[Detection, ...] | None = None,
    scan_id: str = "j2",
) -> TargetScan:
    found = candidates if found is None else found
    return TargetScan(
        source="pentest",
        target="weekly-x",
        candidates=candidates,
        withdrawn=frozenset(),
        completed=CompletedScan(scan_id, DAY8, {d.key: d for d in found}),
        latest_status="COMPLETED",
        completed_at=DAY8,
    )


def _issue_item(
    number: int,
    *,
    open: bool = True,
    labels: tuple[str, ...] = ("new",),
    state_reason: str | None = None,
    **state,
) -> dict[str, Any]:
    base = IssueState(
        source="pentest",
        target="weekly-x",
        keys=(),
        finding_ids=("f1",),
        pentest_id="pt-1",
    )
    return {
        "number": number,
        "html_url": f"https://github.com/example-org/continuum/issues/{number}",
        "title": "t",
        "state": "open" if open else "closed",
        "state_reason": state_reason,
        "labels": [{"name": label} for label in labels],
        "created_at": "2026-10-25T00:00:00Z",
        "closed_at": None if open else "2026-10-26T00:00:00Z",
        "user": {"login": "github-actions[bot]"},
        "body": "x\n\n" + render_state(replace(base, **state)) + "\n",
    }


def _state(body: str) -> IssueState:
    state = parse_state(body)
    assert state is not None
    return state


def test_run_sync_creates_and_closes() -> None:
    github = FakeGitHub(
        issues=[
            _issue_item(
                1, keys=("gone",), labels=("pending",), misses=1, checked_scan="j1"
            )
        ]
    )
    pentest = FakePentest(
        scans={"weekly-x": _scan(candidates=(_det("k1"),), scan_id="j2")}
    )
    counts = run_sync(TARGETS, github, pentest, FakeCodeVuln(), FakeCodeReview())
    assert counts == SyncCounts(
        created=1, pending=0, closed=1, reopened=0, revalidations=0, needs_sections=1
    )
    assert github.created[0][2] == [
        "new",
        "severity:medium",
        "pentest",
        "repo:ansible-playbooks",
        "site:x.example.com",
    ]
    assert github.updates == [(1, {"state": "closed", "state_reason": "completed"})]
    assert github.comments == [(1, CLOSED_ABSENT)]


def test_run_sync_starts_revalidation_and_saves_the_job() -> None:
    github = FakeGitHub(
        issues=[_issue_item(2, keys=("k1",), open=False, state_reason="completed")]
    )
    pentest = FakePentest(scans={}, revalidation_job="rv9")
    counts = run_sync(TARGETS, github, pentest, FakeCodeVuln(), FakeCodeReview())
    assert counts.revalidations == 1
    assert pentest.started == [("pt-1", "f1")]
    assert _state(github.bodies[2]).revalidation_job == "rv9"


def test_updated_body_of_a_near_limit_issue_stays_within_the_limit() -> None:
    # One-character lines let the truncation cut land within a character of
    # the limit.
    huge = replace(_det("k1"), details=(("Description", "a\n" * 35000),))
    item = _issue_item(2, keys=("k1",), open=False, state_reason="completed")
    item["body"] = issue_body(huge, _state(item["body"]), None, "@octocat")
    assert len(item["body"]) >= 65535
    github = FakeGitHub(issues=[item])
    pentest = FakePentest(scans={}, revalidation_job="rv9")
    run_sync(TARGETS, github, pentest, FakeCodeVuln(), FakeCodeReview())
    body = github.bodies[2]
    assert len(body) <= 65536
    assert _state(body).revalidation_job == "rv9"
    assert "</details>" in body


def test_revalidation_without_a_pentest_id_fails_only_that_issue() -> None:
    github = FakeGitHub(
        issues=[
            _issue_item(
                2, keys=("k1",), open=False, state_reason="completed", pentest_id=None
            ),
            _issue_item(
                3, keys=("gone",), labels=("pending",), misses=1, checked_scan="j1"
            ),
        ]
    )
    pentest = FakePentest(scans={"weekly-x": _scan()}, revalidation_job="rv9")
    counts = run_sync(TARGETS, github, pentest, FakeCodeVuln(), FakeCodeReview())
    assert (counts.failed, counts.revalidations, counts.closed) == (1, 0, 1)
    assert pentest.started == [] and 2 not in github.bodies
    assert github.updates == [(3, {"state": "closed", "state_reason": "completed"})]


def test_merged_code_vuln_duplicate_does_not_redirect_the_revalidation() -> None:
    duplicate = _issue_item(
        5,
        keys=("cv:env-a/i-9",),
        open=False,
        state_reason="duplicate",
        source="code-vuln",
        target="ansible-playbooks",
        finding_ids=("i-9",),
        pentest_id=None,
    )
    github = FakeGitHub(
        issues=[
            _issue_item(2, keys=("k1",), open=False, state_reason="completed"),
            duplicate,
        ],
        canonicals={5: 2},
    )
    pentest = FakePentest(scans={}, revalidation_job="rv9")
    counts = run_sync(TARGETS, github, pentest, FakeCodeVuln(), FakeCodeReview())
    assert counts.revalidations == 1 and pentest.started == [("pt-1", "f1")]
    state = _state(github.bodies[2])
    assert state.finding_ids == ("f1", "i-9") and state.revalidation_job == "rv9"


def test_revalidation_result_is_read_for_the_issues_own_finding() -> None:
    github = FakeGitHub(
        issues=[
            _issue_item(
                2,
                keys=("k1", "cv:env-a/i-9"),
                finding_ids=("f1", "i-9"),
                open=False,
                state_reason="completed",
                revalidation_job="rv1",
            )
        ]
    )
    pentest = FakePentest(scans={})
    run_sync(TARGETS, github, pentest, FakeCodeVuln(), FakeCodeReview())
    assert pentest.result_calls == [("pt-1", "rv1", "f1")]


def _client_error() -> ClientError:
    return ClientError(
        {"Error": {"Code": "ConflictException", "Message": "secret detail"}},
        "StartPentestJob",
    )


def test_failed_revalidation_start_leaves_no_job_and_applies_the_rest(
    capsys,
) -> None:
    github = FakeGitHub(
        issues=[
            _issue_item(
                2,
                keys=("k1",),
                open=False,
                state_reason="completed",
                labels=("new", "wip"),
                auto_closed="withdrawn",
            ),
            _issue_item(
                3, keys=("gone",), labels=("pending",), misses=1, checked_scan="j1"
            ),
        ]
    )
    pentest = FakePentest(scans={"weekly-x": _scan()}, start_error=_client_error())
    counts = run_sync(TARGETS, github, pentest, FakeCodeVuln(), FakeCodeReview())
    assert pentest.started == [("pt-1", "f1")]
    assert (counts.revalidations, counts.failed, counts.closed) == (0, 0, 1)
    state = _state(github.bodies[2])
    assert state.revalidation_job is None and state.auto_closed is None
    assert (3, {"state": "closed", "state_reason": "completed"}) in github.updates
    assert "secret detail" not in capsys.readouterr().out


def test_http_error_on_one_update_does_not_stop_the_next() -> None:
    request = httpx.Request("PATCH", "https://api.github.com/x")
    error = httpx.HTTPStatusError(
        "boom", request=request, response=httpx.Response(502, request=request)
    )

    class Failing(FakeGitHub):
        def update_issue(self, number: int, **fields) -> None:
            if number == 1:
                raise error
            super().update_issue(number, **fields)

    github = Failing(
        issues=[
            _issue_item(
                n, keys=(f"gone{n}",), labels=("pending",), misses=1, checked_scan="j1"
            )
            for n in (1, 2)
        ]
    )
    pentest = FakePentest(scans={"weekly-x": _scan(candidates=(_det("k9"),))})
    counts = run_sync(TARGETS, github, pentest, FakeCodeVuln(), FakeCodeReview())
    assert (counts.failed, counts.closed, counts.created) == (1, 1, 1)
    assert github.updates == [(2, {"state": "closed", "state_reason": "completed"})]
    # Issue 1 failed and still counts as open without sections, like the new one.
    assert counts.needs_sections == 2


def test_failed_creation_is_counted_and_the_run_goes_on() -> None:
    class Failing(FakeGitHub):
        def create_issue(self, title, body, labels):
            if "first" in title:
                raise ValueError("body exceeds the limit")
            return super().create_issue(title, body, labels)

    github = Failing()
    pentest = FakePentest(
        scans={
            "weekly-x": _scan(
                candidates=(_det("k1", "f1", "first"), _det("k2", "f2", "second"))
            )
        }
    )
    counts = run_sync(TARGETS, github, pentest, FakeCodeVuln(), FakeCodeReview())
    assert (counts.created, counts.failed, counts.needs_sections) == (1, 1, 1)
    assert [title for title, _, _ in github.created] == ["[MEDIUM] second"]


def test_severity_change_rewrites_the_table_and_the_title() -> None:
    detection = replace(_det("k1"), severity=Severity.HIGH)
    item = _issue_item(1, keys=("k1",), labels=("new", "severity:medium"))
    item["title"] = "[MEDIUM] finding"
    item["body"] = issue_body(_det("k1"), _state(item["body"]), None, "@octocat")
    github = FakeGitHub(issues=[item])
    pentest = FakePentest(scans={"weekly-x": _scan(found=(detection,))})
    run_sync(
        TARGETS, github, pentest, FakeCodeVuln(), FakeCodeReview(), mention="@octocat"
    )
    body = github.bodies[1]
    assert "| Severity | HIGH |" in body and "| Severity | MEDIUM |" not in body
    assert not body.startswith("@octocat")
    assert github.titles == {1: "[HIGH] finding"}
    assert _state(body).severity == "HIGH"


def test_newly_urgent_issue_gets_the_mention_once() -> None:
    detection = replace(_det("k1"), severity=Severity.CRITICAL, urgent=True)
    item = _issue_item(1, keys=("k1",), labels=("new", "severity:medium"))
    item["body"] = issue_body(_det("k1"), _state(item["body"]), None, "@octocat")
    github = FakeGitHub(issues=[item])
    run_sync(
        TARGETS,
        github,
        FakePentest(scans={"weekly-x": _scan(found=(detection,))}),
        FakeCodeVuln(),
        FakeCodeReview(),
        mention="@octocat",
    )
    body = github.bodies[1]
    assert body.startswith("@octocat\n\n| Field | Value |")
    assert body.count("@octocat") == 1
    assert github.titles == {1: "[CRITICAL] t"}


def test_unchanged_severity_leaves_the_title() -> None:
    github = FakeGitHub(issues=[_issue_item(1, keys=("gone",))])
    run_sync(
        TARGETS,
        github,
        FakePentest(scans={"weekly-x": _scan()}),
        FakeCodeVuln(),
        FakeCodeReview(),
    )
    assert github.titles == {}


def test_creation_records_every_finding_id_and_passes_the_detection_time() -> None:
    candidate = replace(_det("k1"), extra_finding_ids=("f0",))
    full = replace(_det("k1"), details=(("Description", "full text"),))
    pentest = FakePentest(
        scans={"weekly-x": _scan(candidates=(candidate,))}, detections={"f1": full}
    )
    github = FakeGitHub()
    run_sync(TARGETS, github, pentest, FakeCodeVuln(), FakeCodeReview())
    ((_, body, _),) = github.created
    assert _state(body).finding_ids == ("f1", "f0")
    assert pentest.detection_calls == [("f1", DAY1)]


def test_created_issue_uses_the_full_detection_and_its_state() -> None:
    full = replace(_det("k1"), details=(("Description", "full text"),))
    pentest = FakePentest(
        scans={"weekly-x": _scan(candidates=(_det("k1"),))}, detections={"f1": full}
    )
    github = FakeGitHub()
    run_sync(TARGETS, github, pentest, FakeCodeVuln(), FakeCodeReview())
    ((title, body, _),) = github.created
    assert title == "[MEDIUM] finding"
    assert "full text" in body
    state = parse_state(body)
    assert state is not None
    assert (state.keys, state.finding_ids) == (("k1",), ("f1",))


def test_first_miss_counts_pending_and_sends_sorted_labels() -> None:
    github = FakeGitHub(
        issues=[
            _issue_item(
                1,
                keys=("k1",),
                labels=("severity:medium", "new", "site:x.example.com"),
            )
        ]
    )
    pentest = FakePentest(scans={"weekly-x": _scan()})
    counts = run_sync(TARGETS, github, pentest, FakeCodeVuln(), FakeCodeReview())
    assert (counts.pending, counts.needs_sections) == (1, 1)
    assert github.labels == {1: ["pending", "severity:medium", "site:x.example.com"]}
    assert github.updates == []
    assert _state(github.bodies[1]).misses == 1


def test_unchanged_labels_and_state_are_not_sent() -> None:
    github = FakeGitHub(
        issues=[
            _issue_item(
                1,
                keys=("k1",),
                labels=("new", "site:x.example.com"),
                checked_scan="j2",
                sections=True,
            )
        ]
    )
    pentest = FakePentest(scans={"weekly-x": _scan(found=(_det("k1"),))})
    assert run_sync(
        TARGETS, github, pentest, FakeCodeVuln(), FakeCodeReview()
    ) == SyncCounts(0, 0, 0, 0, 0, 0)
    assert (github.bodies, github.labels, github.comments) == ({}, {}, [])


def test_reopen_sends_open_and_reopened() -> None:
    github = FakeGitHub(
        issues=[
            _issue_item(
                3,
                keys=("k1",),
                open=False,
                labels=("site:x.example.com",),
                state_reason="completed",
                auto_closed="absent",
                sections=True,
            )
        ]
    )
    pentest = FakePentest(scans={"weekly-x": _scan(candidates=(_det("k1"),))})
    counts = run_sync(TARGETS, github, pentest, FakeCodeVuln(), FakeCodeReview())
    assert (counts.reopened, counts.needs_sections, counts.created) == (1, 0, 0)
    assert github.updates == [(3, {"state": "open", "state_reason": "reopened"})]
    assert github.labels == {3: ["new", "site:x.example.com"]}
    assert github.comments == [(3, REOPENED)]


def test_comments_are_sent_before_the_update() -> None:
    calls: list[str] = []

    class Recording(FakeGitHub):
        def comment(self, number: int, body: str) -> None:
            calls.append("comment")
            super().comment(number, body)

        def update_issue(self, number: int, **fields) -> None:
            calls.append("update")
            super().update_issue(number, **fields)

    github = Recording(
        issues=[
            _issue_item(
                1, keys=("gone",), labels=("pending",), misses=1, checked_scan="j1"
            )
        ]
    )
    run_sync(
        TARGETS,
        github,
        FakePentest(scans={"weekly-x": _scan()}),
        FakeCodeVuln(),
        FakeCodeReview(),
    )
    assert calls == ["comment", "update"]


def test_finished_revalidation_is_read_and_recorded() -> None:
    github = FakeGitHub(
        issues=[
            _issue_item(
                2,
                keys=("k1",),
                open=False,
                state_reason="completed",
                revalidation_job="rv1",
            )
        ]
    )
    pentest = FakePentest(
        scans={},
        results={"rv1": RevalidationResult("COMPLETED", "NOT_REPRODUCED")},
    )
    counts = run_sync(TARGETS, github, pentest, FakeCodeVuln(), FakeCodeReview())
    assert pentest.result_calls == [("pt-1", "rv1", "f1")]
    assert counts.revalidations == 0
    assert github.comments == [(2, REVALIDATED_FIXED)]
    assert _state(github.bodies[2]).revalidation_done is True


def test_done_revalidation_is_not_read_again() -> None:
    github = FakeGitHub(
        issues=[
            _issue_item(
                2,
                keys=("k1",),
                open=False,
                state_reason="completed",
                revalidation_job="rv1",
                revalidation_done=True,
            )
        ]
    )
    pentest = FakePentest(scans={})
    run_sync(TARGETS, github, pentest, FakeCodeVuln(), FakeCodeReview())
    assert pentest.result_calls == []


def test_only_unmerged_duplicates_are_looked_up() -> None:
    github = FakeGitHub(
        issues=[
            _issue_item(2, keys=("k2",), sections=True),
            _issue_item(
                4, keys=("k4",), open=False, state_reason="duplicate", merged_into=2
            ),
            _issue_item(9, keys=("k9",), open=False, state_reason="duplicate"),
        ],
        canonicals={9: 4},
    )
    run_sync(TARGETS, github, FakePentest(scans={}), FakeCodeVuln(), FakeCodeReview())
    assert github.canonical_calls == [9]
    assert _state(github.bodies[2]).keys == ("k2", "k9")
    assert _state(github.bodies[9]).merged_into == 2


def test_collect_scans_reads_code_vuln_for_private_and_code_review_for_public() -> None:
    targets = replace(
        TARGETS,
        repositories=(Repository("ansible-playbooks", False), Repository("x", True)),
    )
    code_vuln = FakeCodeVuln(environments={"example-org-x": "env-x"})
    code_review = FakeCodeReview()
    scans = collect_scans(targets, FakePentest(scans={}), code_vuln, code_review)
    assert [(s.source, s.target) for s in scans] == [
        ("pentest", "weekly-x"),
        ("code-review", "weekly-ansible-playbooks"),
        ("code-vuln", "x"),
    ]
    assert code_vuln.scan_calls == [("x", "env-x")]
    assert code_review.scan_calls == ["ansible-playbooks"]


def test_full_detection_reads_code_review_details_by_title() -> None:
    full = replace(
        _det("cr:1"), source="code-review", target="weekly-ansible-playbooks"
    )
    code_review = FakeCodeReview(detections={"f1": full})
    assert (
        full_detection(
            TARGETS,
            FakePentest(scans={}),
            FakeCodeVuln(),
            code_review,
            "code-review",
            "weekly-ansible-playbooks",
            "cr:1",
            "f1",
        )
        == full
    )
    assert (
        full_detection(
            TARGETS,
            FakePentest(scans={}),
            FakeCodeVuln(),
            code_review,
            "code-review",
            "weekly-unknown",
            "cr:1",
            "f1",
        )
        is None
    )


def test_start_code_reviews_passes_only_public_repositories() -> None:
    targets = replace(
        TARGETS,
        repositories=(Repository("ansible-playbooks", False), Repository("x", True)),
    )
    code_review = FakeCodeReview(started=1)
    assert start_code_reviews(targets, code_review, DAY8) == (1, 0)
    assert code_review.start_calls == [(["ansible-playbooks"], DAY8)]


def test_start_code_reviews_counts_an_aws_error_as_failed() -> None:
    error = ClientError(
        {"Error": {"Code": "AccessDeniedException"}}, "StartCodeReviewJob"
    )
    code_review = FakeCodeReview(start_error=error)
    assert start_code_reviews(TARGETS, code_review, DAY8) == (0, 1)


def test_start_code_reviews_counts_a_connection_error_as_failed() -> None:
    error = EndpointConnectionError(endpoint_url="https://x")
    code_review = FakeCodeReview(start_error=error)
    assert start_code_reviews(TARGETS, code_review, DAY8) == (0, 1)


def test_full_detection_reads_pentest_and_code_vuln_details() -> None:
    pentest_full = _det("k1", name="pentest full")
    code_full = replace(_det("cv:env-a/i-1"), source="code-vuln", name="code full")
    pentest = FakePentest(scans={}, detections={"f1": pentest_full})
    code_vuln = FakeCodeVuln(detections={"i-1": code_full})
    assert (
        full_detection(
            TARGETS,
            pentest,
            code_vuln,
            FakeCodeReview(),
            "pentest",
            "weekly-x",
            "k1",
            "f1",
        )
        == pentest_full
    )
    assert (
        full_detection(
            TARGETS,
            pentest,
            code_vuln,
            FakeCodeReview(),
            "code-vuln",
            "ansible-playbooks",
            "cv:env-a/i-1",
            "i-1",
        )
        == code_full
    )
    assert (
        full_detection(
            TARGETS,
            pentest,
            code_vuln,
            FakeCodeReview(),
            "pentest",
            "unknown",
            "k1",
            "f1",
        )
        is None
    )


def test_fill_sections_updates_only_unfilled_open_issues() -> None:
    github = FakeGitHub(
        issues=[
            _issue_item(1, keys=("k1",)),
            _issue_item(2, keys=("k2",), sections=True),
            _issue_item(3, keys=("k3",), open=False, state_reason="completed"),
        ]
    )
    pentest = FakePentest(scans={}, detections={"f1": _det("k1")})
    model = FakeModel('{"summary": "S", "why": "W", "risk": "R"}')
    assert (
        fill_sections(TARGETS, github, pentest, FakeCodeVuln(), FakeCodeReview(), model)
        == 1
    )
    assert list(github.bodies) == [1]
    assert _state(github.bodies[1]).sections is True
    assert "## Summary\n\nS" in github.bodies[1]


def test_fill_sections_keeps_the_recorded_state() -> None:
    github = FakeGitHub(
        issues=[_issue_item(1, keys=("k1", "k0"), finding_ids=("f0", "f1"), misses=1)]
    )
    pentest = FakePentest(scans={}, detections={"f0": _det("k1")})
    model = FakeModel('{"summary": "S", "why": "W", "risk": "R"}')
    assert (
        fill_sections(TARGETS, github, pentest, FakeCodeVuln(), FakeCodeReview(), model)
        == 1
    )
    state = _state(github.bodies[1])
    assert state.keys == ("k1", "k0") and state.finding_ids == ("f0", "f1")
    assert state.misses == 1 and state.sections is True
    assert pentest.detection_calls == [("f0", None)]


def test_fill_sections_skips_missing_detections_and_failed_answers() -> None:
    github = FakeGitHub(issues=[_issue_item(1, keys=("k1",))])
    found = FakePentest(scans={}, detections={"f1": _det("k1")})
    missing = FakePentest(scans={})
    assert (
        fill_sections(
            TARGETS, github, missing, FakeCodeVuln(), FakeCodeReview(), FakeModel("{}")
        )
        == 0
    )
    assert github.bodies == {}
    assert (
        fill_sections(
            TARGETS,
            github,
            found,
            FakeCodeVuln(),
            FakeCodeReview(),
            FakeModel(None, "content_filtered"),
        )
        == 0
    )
    assert github.bodies[1].count(fallback_note("content_filtered")) == 1
    assert _state(github.bodies[1]).sections is False


def test_fill_sections_leaves_an_already_marked_issue_alone() -> None:
    detection = _det("k1")
    state = IssueState(
        source="pentest",
        target="weekly-x",
        keys=("k1",),
        finding_ids=("f1",),
        pentest_id="pt-1",
    )
    item = _issue_item(1, keys=("k1",))
    item["body"] = issue_body(detection, state, None, "", failure="content_filtered")
    github = FakeGitHub(issues=[item])
    pentest = FakePentest(scans={}, detections={"f1": detection})
    assert (
        fill_sections(
            TARGETS,
            github,
            pentest,
            FakeCodeVuln(),
            FakeCodeReview(),
            FakeModel(None, "content_filtered"),
        )
        == 0
    )
    assert github.updates == []


OLD_NOTE = (
    "_Bedrock could not write the Summary, Why it matters, and Risk if left "
    "unresolved sections, so this issue shows the scanner's details only. "
    "A later sync tries again._"
)


def test_fill_sections_rewrites_the_old_fallback_note_once() -> None:
    detection = _det("k1")
    state = IssueState(
        source="pentest",
        target="weekly-x",
        keys=("k1",),
        finding_ids=("f1",),
        pentest_id="pt-1",
    )
    item = _issue_item(1, keys=("k1",))
    body = issue_body(detection, state, None, "", failure="content_filtered")
    item["body"] = body.replace(fallback_note("content_filtered"), OLD_NOTE)
    github = FakeGitHub(issues=[item])
    pentest = FakePentest(scans={}, detections={"f1": detection})
    assert (
        fill_sections(
            TARGETS,
            github,
            pentest,
            FakeCodeVuln(),
            FakeCodeReview(),
            FakeModel(None, "content_filtered"),
        )
        == 0
    )
    assert list(github.bodies) == [1]
    assert github.bodies[1].count(fallback_note("content_filtered")) == 1
    assert OLD_NOTE not in github.bodies[1]


def test_fill_sections_rewrites_the_note_only_when_the_reason_changes() -> None:
    detection = _det("k1")
    state = IssueState(
        source="pentest",
        target="weekly-x",
        keys=("k1",),
        finding_ids=("f1",),
        pentest_id="pt-1",
    )
    item = _issue_item(1, keys=("k1",))
    item["body"] = issue_body(detection, state, None, "", failure="content_filtered")
    pentest = FakePentest(scans={}, detections={"f1": detection})
    same = FakeGitHub(issues=[item])
    fill_sections(
        TARGETS,
        same,
        pentest,
        FakeCodeVuln(),
        FakeCodeReview(),
        FakeModel(None, "content_filtered"),
    )
    assert same.bodies == {}
    changed = FakeGitHub(issues=[item])
    fill_sections(
        TARGETS,
        changed,
        pentest,
        FakeCodeVuln(),
        FakeCodeReview(),
        FakeModel(None, "ThrottlingException"),
    )
    assert fallback_note("ThrottlingException") in changed.bodies[1]
    assert fallback_note("content_filtered") not in changed.bodies[1]


def test_fill_sections_adds_headings_to_a_body_without_them() -> None:
    detection = _det("k1")
    state = IssueState(
        source="pentest",
        target="weekly-x",
        keys=("k1",),
        finding_ids=("f1",),
        pentest_id="pt-1",
    )
    item = _issue_item(1, keys=("k1",))
    item["body"] = issue_body(detection, state, None, "", failure="content_filtered")
    github = FakeGitHub(issues=[item])
    pentest = FakePentest(scans={}, detections={"f1": detection})
    model = FakeModel('{"summary": "S", "why": "W", "risk": "R"}')
    assert (
        fill_sections(TARGETS, github, pentest, FakeCodeVuln(), FakeCodeReview(), model)
        == 1
    )
    assert "## Summary\n\nS" in github.bodies[1]
    assert "Bedrock could not write" not in github.bodies[1]


def test_run_sync_adds_the_site_label_to_existing_issues() -> None:
    github = FakeGitHub(issues=[_issue_item(1, keys=("k1",))])
    run_sync(TARGETS, github, FakePentest(scans={}), FakeCodeVuln(), FakeCodeReview())
    assert github.labels == {1: ["new", "site:x.example.com"]}
    assert github.updates == [] and github.comments == []


def test_fill_sections_passes_the_language() -> None:
    github = FakeGitHub(issues=[_issue_item(1, keys=("k1",))])
    pentest = FakePentest(scans={}, detections={"f1": _det("k1")})
    model = FakeModel(None)
    fill_sections(
        TARGETS,
        github,
        pentest,
        FakeCodeVuln(),
        FakeCodeReview(),
        model,
        language="ja_JP",
    )
    (prompt,) = model.prompts
    assert "in the language of the locale ja_JP" in prompt
