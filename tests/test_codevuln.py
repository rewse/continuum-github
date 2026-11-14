from datetime import UTC
from datetime import datetime
from typing import Any

import boto3
import pytest
from botocore.stub import Stubber

from continuum_scan.codevuln import CodeVulnClient
from continuum_scan.config import Repository
from continuum_scan.models import Severity

REPO = Repository("actions", False)
ENV = "env1"
DAY1 = datetime(2026, 11, 1, tzinfo=UTC)
DAY1_END = datetime(2026, 11, 1, 6, 0, tzinfo=UTC)
DAY8 = datetime(2026, 11, 8, tzinfo=UTC)
DAY8_END = datetime(2026, 11, 8, 6, 0, tzinfo=UTC)


@pytest.fixture
def client():
    return boto3.client(
        "continuum",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


def _scan(
    scan_id: str, status: str, created: datetime, completed: datetime | None = None
) -> dict[str, Any]:
    scan: dict[str, Any] = {
        "scanRunId": scan_id,
        "status": status,
        "origin": "SCHEDULED",
        "createdAt": created,
    }
    if completed is not None:
        scan["completedAt"] = completed
    return scan


def _finding(
    finding_id: str,
    scan_id: str,
    created_issue: str | None = None,
    duplicate_of: str | None = None,
) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "findingId": finding_id,
        "findingArn": f"arn:aws:continuum:us-east-1:111122223333:finding/{finding_id}",
        "environmentId": ENV,
        "source": "SCANNER",
        "sourceFindingId": f"src-{finding_id}",
        "reportedAt": DAY1,
        "status": "COMPLETED",
        "statusUpdatedAt": DAY1,
        "createdAt": DAY1,
        "scanRunId": scan_id,
        "type": "VULNERABILITY",
        "title": f"title-{finding_id}",
        "severity": "HIGH",
    }
    if created_issue is not None:
        finding["createdIssueId"] = created_issue
    if duplicate_of is not None:
        finding["duplicateOfIssueId"] = duplicate_of
    return finding


def _issue(
    issue_id: str,
    severity: str | None,
    confidence: int | None = 80,
    status: str = "COMPLETED",
) -> dict[str, Any]:
    issue: dict[str, Any] = {
        "issueId": issue_id,
        "issueArn": f"arn:aws:continuum:us-east-1:111122223333:issue/{issue_id}",
        "name": f"name-{issue_id}",
        "status": status,
        "statusUpdatedAt": DAY1,
        "createdAt": DAY1,
    }
    if severity is not None:
        issue["severity"] = severity
    if confidence is not None:
        issue["confidence"] = confidence
    return issue


def _full_issue(
    issue_id: str, synopsis: str, summary: str, reasoning: str
) -> dict[str, Any]:
    issue = _issue(issue_id, "CRITICAL")
    issue.update(synopsis=synopsis, findingIds=["x1"])
    # The model rejects empty optional strings, so an empty value is omitted.
    issue.update(
        (field, value)
        for field, value in (("summary", summary), ("severityReasoning", reasoning))
        if value
    )
    return issue


def _env(env_id: str, name: str) -> dict[str, Any]:
    return {
        "environmentId": env_id,
        "environmentArn": f"arn:aws:continuum:us-east-1:111122223333:environment/{env_id}",
        "name": name,
        "status": "ACTIVE",
        "createdAt": DAY1,
    }


def _expect_scans(stub, scans) -> None:
    stub.add_response("list_code_scans", {"scans": scans}, {"environmentId": ENV})


def _expect_findings(stub, findings) -> None:
    stub.add_response("list_code_findings", {"items": findings}, {"environmentId": ENV})


def _expect_issues(stub, issues) -> None:
    stub.add_response("list_code_issues", {"items": issues}, {"environmentId": ENV})


def test_missing_environment(client) -> None:
    scan = CodeVulnClient(client).target_scan(REPO, None)
    assert scan.latest_status == "MISSING"
    assert (scan.source, scan.target) == ("code-vuln", "actions")
    assert (scan.candidates, scan.completed, scan.completed_at) == ((), None, None)


def test_environment_without_scans_is_never_run(client) -> None:
    with Stubber(client) as stub:
        _expect_scans(stub, [])
        scan = CodeVulnClient(client).target_scan(REPO, ENV)
        stub.assert_no_pending_responses()
    assert (scan.latest_status, scan.candidates, scan.completed) == (
        "NEVER_RUN",
        (),
        None,
    )
    assert scan.completed_at is None


def test_completed_scan_maps_findings_to_issues(client) -> None:
    with Stubber(client) as stub:
        _expect_scans(
            stub,
            [_scan("s2", "SCANNING", DAY8), _scan("s1", "SUCCEEDED", DAY1, DAY1_END)],
        )
        _expect_findings(
            stub,
            [
                _finding("x1", "s1", created_issue="i1"),
                _finding("x2", "s1", duplicate_of="i2"),
                _finding("x3", "s0", created_issue="i3"),
                _finding("x4", "s1"),
            ],
        )
        _expect_issues(
            stub,
            [
                _issue("i1", "HIGH"),
                _issue("i2", "MEDIUM"),
                _issue("i3", "LOW"),
                _issue("i4", None),
            ],
        )
        scan = CodeVulnClient(client).target_scan(REPO, ENV)
    assert scan.latest_status == "IN_PROGRESS"
    assert scan.completed is not None
    assert scan.completed.scan_id == "s1"
    assert scan.completed.started_at == DAY1
    assert scan.completed_at == DAY1_END
    assert set(scan.completed.found) == {"cv:env1/i1", "cv:env1/i2"}
    assert [(d.external_id, d.urgent) for d in scan.candidates] == [
        ("i1", True),
        ("i2", False),
    ]
    assert scan.withdrawn == frozenset({"cv:env1/i3", "cv:env1/i4"})


def test_candidate_carries_the_issue_fields(client) -> None:
    with Stubber(client) as stub:
        _expect_scans(stub, [_scan("s1", "SUCCEEDED", DAY1, DAY1_END)])
        _expect_findings(stub, [])
        _expect_issues(stub, [_issue("i1", "CRITICAL", confidence=None)])
        scan = CodeVulnClient(client).target_scan(REPO, ENV)
    assert scan.latest_status == "COMPLETED"
    (candidate,) = scan.candidates
    assert candidate.source == "code-vuln"
    assert (candidate.target, candidate.repository) == ("actions", "actions")
    assert candidate.key == "cv:env1/i1"
    assert candidate.name == "name-i1"
    assert candidate.severity is Severity.CRITICAL
    assert candidate.urgent is True
    assert candidate.confidence == ""
    assert candidate.detected_at == DAY1
    assert (candidate.site, candidate.pentest_id) == (None, None)


def test_found_skips_issues_missing_from_the_list(client) -> None:
    with Stubber(client) as stub:
        _expect_scans(stub, [_scan("s1", "SUCCEEDED", DAY1, DAY1_END)])
        _expect_findings(
            stub,
            [
                _finding("x1", "s1", created_issue="i1"),
                _finding("x2", "s1", created_issue="gone"),
            ],
        )
        _expect_issues(stub, [_issue("i1", "LOW", confidence=42, status="IN_PROGRESS")])
        scan = CodeVulnClient(client).target_scan(REPO, ENV)
    assert scan.completed is not None
    assert list(scan.completed.found) == ["cv:env1/i1"]
    assert scan.completed.found["cv:env1/i1"].confidence == "42"
    assert scan.candidates == ()


def test_failed_latest_scan_keeps_the_earlier_success(client) -> None:
    with Stubber(client) as stub:
        _expect_scans(
            stub,
            [
                _scan("s1", "SUCCEEDED", DAY1, DAY1_END),
                _scan("s2", "FAILED", DAY8, DAY8_END),
            ],
        )
        _expect_findings(stub, [])
        _expect_issues(stub, [])
        scan = CodeVulnClient(client).target_scan(REPO, ENV)
    assert scan.latest_status == "FAILED"
    assert scan.completed is not None
    assert scan.completed.scan_id == "s1"
    assert scan.completed_at == DAY1_END


def test_without_a_successful_scan_nothing_is_completed(client) -> None:
    with Stubber(client) as stub:
        _expect_scans(stub, [_scan("s1", "FAILED", DAY1, DAY1_END)])
        _expect_issues(stub, [_issue("i1", "HIGH")])
        scan = CodeVulnClient(client).target_scan(REPO, ENV)
        stub.assert_no_pending_responses()
    assert scan.latest_status == "FAILED"
    assert (scan.completed, scan.completed_at) == (None, None)
    assert [d.external_id for d in scan.candidates] == ["i1"]


def test_unsettled_latest_success_falls_back_to_the_settled_one(client) -> None:
    validating = {**_finding("x2", "s2", created_issue="i2"), "status": "VALIDATING"}
    with Stubber(client) as stub:
        _expect_scans(
            stub,
            [
                _scan("s1", "SUCCEEDED", DAY1, DAY1_END),
                _scan("s2", "SUCCEEDED", DAY8, DAY8_END),
            ],
        )
        _expect_findings(
            stub,
            [
                {**_finding("x1", "s1", created_issue="i1"), "status": "CONFIRMED"},
                validating,
            ],
        )
        _expect_issues(stub, [_issue("i1", "HIGH"), _issue("i2", "HIGH")])
        scan = CodeVulnClient(client).target_scan(REPO, ENV)
    assert scan.latest_status == "IN_PROGRESS"
    assert scan.completed is not None
    assert scan.completed.scan_id == "s1"
    assert scan.completed_at == DAY1_END
    assert set(scan.completed.found) == {"cv:env1/i1"}


def test_unsettled_only_success_is_not_completed(client) -> None:
    submitted = {**_finding("x1", "s1", created_issue="i1"), "status": "SUBMITTED"}
    with Stubber(client) as stub:
        _expect_scans(stub, [_scan("s1", "SUCCEEDED", DAY1, DAY1_END)])
        _expect_findings(stub, [submitted])
        _expect_issues(stub, [_issue("i1", "HIGH")])
        scan = CodeVulnClient(client).target_scan(REPO, ENV)
    assert scan.latest_status == "IN_PROGRESS"
    assert (scan.completed, scan.completed_at) == (None, None)
    assert [d.external_id for d in scan.candidates] == ["i1"]


def test_lists_follow_next_token(client) -> None:
    with Stubber(client) as stub:
        stub.add_response(
            "list_code_scans",
            {"scans": [_scan("s1", "SUCCEEDED", DAY1, DAY1_END)], "nextToken": "t1"},
            {"environmentId": ENV},
        )
        stub.add_response(
            "list_code_scans",
            {"scans": [_scan("s2", "SUCCEEDED", DAY8, DAY8_END)]},
            {"environmentId": ENV, "nextToken": "t1"},
        )
        stub.add_response(
            "list_code_findings",
            {"items": [], "nextToken": "t2"},
            {"environmentId": ENV},
        )
        stub.add_response(
            "list_code_findings",
            {"items": [_finding("x1", "s2", created_issue="i1")]},
            {"environmentId": ENV, "nextToken": "t2"},
        )
        stub.add_response(
            "list_code_issues",
            {"items": [], "nextToken": "t3"},
            {"environmentId": ENV},
        )
        stub.add_response(
            "list_code_issues",
            {"items": [_issue("i1", "HIGH")]},
            {"environmentId": ENV, "nextToken": "t3"},
        )
        scan = CodeVulnClient(client).target_scan(REPO, ENV)
        stub.assert_no_pending_responses()
    assert scan.completed is not None
    assert scan.completed.scan_id == "s2"
    assert set(scan.completed.found) == {"cv:env1/i1"}


def test_environments_maps_names(client) -> None:
    with Stubber(client) as stub:
        stub.add_response(
            "list_environments", {"items": [_env("e1", "example-org-actions")]}, {}
        )
        assert CodeVulnClient(client).environments() == {"example-org-actions": "e1"}


def test_environments_follow_next_token(client) -> None:
    with Stubber(client) as stub:
        stub.add_response(
            "list_environments",
            {"items": [_env("e1", "example-org-actions")], "nextToken": "t"},
            {},
        )
        stub.add_response(
            "list_environments",
            {"items": [_env("e2", "example-org-chezmoi")]},
            {"nextToken": "t"},
        )
        assert CodeVulnClient(client).environments() == {
            "example-org-actions": "e1",
            "example-org-chezmoi": "e2",
        }


def test_detection_reads_issue_details(client) -> None:
    with Stubber(client) as stub:
        stub.add_response(
            "get_code_issue",
            _full_issue("i1", synopsis="s", summary="", reasoning="r"),
            {"environmentId": ENV, "issueId": "i1"},
        )
        detection = CodeVulnClient(client).detection(REPO, ENV, "i1")
    assert detection is not None
    assert detection.details == (("Synopsis", "s"), ("Severity reasoning", "r"))
    assert detection.key == "cv:env1/i1"
    assert (detection.severity, detection.urgent) == (Severity.CRITICAL, True)


def test_detection_lists_details_in_order(client) -> None:
    with Stubber(client) as stub:
        stub.add_response(
            "get_code_issue",
            _full_issue("i1", synopsis="s", summary="m", reasoning="r"),
            {"environmentId": ENV, "issueId": "i1"},
        )
        detection = CodeVulnClient(client).detection(REPO, ENV, "i1")
    assert detection is not None
    assert [heading for heading, _ in detection.details] == [
        "Synopsis",
        "Summary",
        "Severity reasoning",
    ]


def test_detection_of_an_absent_issue_is_none(client) -> None:
    with Stubber(client) as stub:
        stub.add_client_error(
            "get_code_issue",
            service_error_code="ResourceNotFoundException",
            http_status_code=404,
            expected_params={"environmentId": ENV, "issueId": "i1"},
        )
        assert CodeVulnClient(client).detection(REPO, ENV, "i1") is None


def test_detection_raises_other_errors(client) -> None:
    with Stubber(client) as stub:
        stub.add_client_error(
            "get_code_issue",
            service_error_code="AccessDeniedException",
            http_status_code=403,
            expected_params={"environmentId": ENV, "issueId": "i1"},
        )
        with pytest.raises(client.exceptions.AccessDeniedException):
            CodeVulnClient(client).detection(REPO, ENV, "i1")


def test_issue_still_being_prioritized_is_found_but_not_filed(client) -> None:
    with Stubber(client) as stub:
        _expect_scans(stub, [_scan("s1", "SUCCEEDED", DAY1, DAY1_END)])
        _expect_findings(stub, [_finding("x1", "s1", created_issue="i1")])
        _expect_issues(stub, [_issue("i1", "HIGH", status="IN_PROGRESS")])
        scan = CodeVulnClient(client).target_scan(REPO, ENV)
        stub.assert_no_pending_responses()
    assert scan.candidates == ()
    assert scan.completed is not None
    assert list(scan.completed.found) == ["cv:env1/i1"]
    assert scan.withdrawn == frozenset()


def test_issue_rated_below_medium_is_withdrawn_and_not_found(client) -> None:
    with Stubber(client) as stub:
        _expect_scans(stub, [_scan("s1", "SUCCEEDED", DAY1, DAY1_END)])
        _expect_findings(
            stub,
            [
                _finding("x1", "s1", created_issue="i1"),
                _finding("x2", "s1", created_issue="i2"),
            ],
        )
        _expect_issues(stub, [_issue("i1", "LOW"), _issue("i2", "MEDIUM")])
        scan = CodeVulnClient(client).target_scan(REPO, ENV)
        stub.assert_no_pending_responses()
    assert [d.external_id for d in scan.candidates] == ["i2"]
    assert scan.completed is not None
    assert list(scan.completed.found) == ["cv:env1/i2"]
    assert scan.withdrawn == frozenset({"cv:env1/i1"})
