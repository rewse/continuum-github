"""Tests for reading issue records."""

from datetime import UTC
from datetime import datetime

from continuum_scan.records import records_from_issues
from continuum_scan.state import IssueState
from continuum_scan.state import render_state

STATE = IssueState(
    source="pentest",
    target="weekly-x",
    keys=("0123456789abcdef",),
    finding_ids=("f-1",),
    pentest_id="pt-1",
)


def _item(**overrides):
    item = {
        "number": 5,
        "html_url": "u5",
        "title": "t",
        "state": "open",
        "state_reason": None,
        "labels": [{"name": "new"}],
        "created_at": "2026-11-01T00:00:00Z",
        "closed_at": None,
        "user": {"login": "github-actions[bot]"},
        "body": "x\n" + render_state(STATE),
    }
    item.update(overrides)
    return item


def test_record_reads_state_and_labels() -> None:
    (record,) = records_from_issues([_item()])
    assert (record.number, record.open, record.labels, record.state) == (
        5,
        True,
        frozenset({"new"}),
        STATE,
    )
    assert record.created_at == datetime(2026, 11, 1, tzinfo=UTC)
    assert record.closed_at is None


def test_closed_record_reads_reason_and_time() -> None:
    (record,) = records_from_issues(
        [
            _item(
                state="closed",
                state_reason="completed",
                closed_at="2026-11-02T03:04:05Z",
            )
        ]
    )
    assert (record.open, record.state_reason) == (False, "completed")
    assert record.closed_at == datetime(2026, 11, 2, 3, 4, 5, tzinfo=UTC)


def test_untrusted_author_is_ignored() -> None:
    assert records_from_issues([_item(user={"login": "octocat"})]) == []
    assert records_from_issues([_item(user={"login": "mallory"})]) == []


def test_issue_without_marker_is_ignored() -> None:
    assert records_from_issues([_item(body="no marker")]) == []
    assert records_from_issues([_item(body=None)]) == []


def test_pull_requests_are_ignored() -> None:
    assert records_from_issues([_item(pull_request={"url": "p"})]) == []
