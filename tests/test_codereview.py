from datetime import UTC
from datetime import datetime
from datetime import timedelta
from typing import Any

import boto3
import pytest
from botocore.stub import Stubber

from continuum_scan.codereview import CODE_REVIEW_INTERVAL
from continuum_scan.codereview import MAX_CONCURRENT_CODE_REVIEWS
from continuum_scan.codereview import MISSING
from continuum_scan.codereview import NEVER_RUN
from continuum_scan.codereview import CodeReviewClient
from continuum_scan.codereview import StartResult
from continuum_scan.config import Repository
from continuum_scan.models import Severity
from continuum_scan.models import code_review_key

SPACE = "space-1"
REPO = Repository("actions", False)
REPOS = (Repository("a", False), Repository("b", False), Repository("c", False))
DAY1 = datetime(2026, 11, 1, tzinfo=UTC)
DAY1_END = datetime(2026, 11, 1, 6, 0, tzinfo=UTC)
DAY8 = datetime(2026, 11, 8, tzinfo=UTC)
NOW = datetime(2026, 11, 9, tzinfo=UTC)
LOCATION = {"filePath": "src/a.py", "lineStart": 10, "lineEnd": 12}


@pytest.fixture
def client():
    return boto3.client(
        "securityagent",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


def _key(fid: str, path: str = "src/a.py") -> str:
    return code_review_key("weekly-actions", "XSS", f"name-{fid}", path)


def _summary(
    fid: str,
    risk_level: str,
    validation: str | None = None,
    confidence: str | None = None,
    status: str = "ACTIVE",
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "findingId": fid,
        "agentSpaceId": SPACE,
        "codeReviewId": "cr-1",
        "name": f"name-{fid}",
        "status": status,
        "riskType": "XSS",
        "riskLevel": risk_level,
        "createdAt": DAY1,
    }
    if validation is not None:
        summary["validationStatus"] = validation
    if confidence is not None:
        summary["confidence"] = confidence
    return summary


def _full(summary: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"codeLocations": [LOCATION], **summary, **extra}


def _review(cid: str, title: str) -> dict[str, Any]:
    return {
        "codeReviewId": cid,
        "agentSpaceId": SPACE,
        "title": title,
        "createdAt": DAY1,
        "updatedAt": DAY1,
    }


def _job(
    jid: str, status: str, created: datetime, updated: datetime, cid: str = "cr-1"
) -> dict[str, Any]:
    return {
        "codeReviewJobId": jid,
        "codeReviewId": cid,
        "status": status,
        "createdAt": created,
        "updatedAt": updated,
    }


def _expect_reviews(stub, reviews=None) -> None:
    if reviews is None:
        reviews = [_review("cr-x", "other"), _review("cr-1", "weekly-actions")]
    stub.add_response(
        "list_code_reviews", {"codeReviewSummaries": reviews}, {"agentSpaceId": SPACE}
    )


def _expect_jobs(stub, jobs, cid: str = "cr-1") -> None:
    stub.add_response(
        "list_code_review_jobs_for_code_review",
        {"codeReviewJobSummaries": jobs},
        {"agentSpaceId": SPACE, "codeReviewId": cid},
    )


def _expect_findings(stub, job_id: str, summaries) -> None:
    stub.add_response(
        "list_findings",
        {"findingsSummaries": summaries},
        {"agentSpaceId": SPACE, "codeReviewJobId": job_id},
    )


def _expect_batch(stub, findings, ids=None) -> None:
    stub.add_response(
        "batch_get_findings",
        {"findings": findings},
        {
            "agentSpaceId": SPACE,
            "findingIds": ids
            if ids is not None
            else [f["findingId"] for f in findings],
        },
    )


def _completed_scan(client, summaries, findings=None):
    with Stubber(client) as stub:
        _expect_reviews(stub)
        _expect_jobs(stub, [_job("j1", "COMPLETED", DAY1, DAY1_END)])
        _expect_findings(stub, "j1", summaries)
        _expect_batch(stub, findings or [_full(s) for s in summaries])
        scan = CodeReviewClient(client, SPACE).target_scan(REPO)
        stub.assert_no_pending_responses()
    return scan


def test_constants() -> None:
    assert MAX_CONCURRENT_CODE_REVIEWS == 10
    assert CODE_REVIEW_INTERVAL == timedelta(days=6, hours=12)
    assert (MISSING, NEVER_RUN) == ("MISSING", "NEVER_RUN")


def test_target_scan_files_alive_medium_and_above_of_the_latest_completed_job(
    client,
) -> None:
    summaries = [
        _summary("f1", "HIGH", validation="CONFIRMED"),
        _summary("f2", "LOW"),
        _summary("f3", "MEDIUM", confidence="FALSE_POSITIVE"),
    ]
    with Stubber(client) as stub:
        _expect_reviews(stub)
        _expect_jobs(
            stub,
            [
                _job("j2", "IN_PROGRESS", DAY8, DAY8),
                _job("j1", "COMPLETED", DAY1, DAY1_END),
            ],
        )
        _expect_findings(stub, "j1", summaries)
        _expect_batch(stub, [_full(s) for s in summaries])
        scan = CodeReviewClient(client, SPACE).target_scan(REPO)
        stub.assert_no_pending_responses()
    assert scan.source == "code-review"
    assert scan.target == "weekly-actions"
    assert scan.latest_status == "IN_PROGRESS"
    assert scan.completed_at == DAY1_END
    assert [d.external_id for d in scan.candidates] == ["f1"]
    f1 = scan.candidates[0]
    assert f1.source == "code-review"
    assert f1.target == "weekly-actions"
    assert f1.repository == "actions"
    assert f1.urgent is True
    assert f1.severity is Severity.HIGH
    assert f1.location == "src/a.py:10-12"
    assert f1.key == code_review_key("weekly-actions", "XSS", "name-f1", "src/a.py")
    assert f1.detected_at == DAY1
    assert (f1.site, f1.pentest_id) == (None, None)
    assert scan.completed is not None and scan.completed.scan_id == "j1"
    assert scan.completed.started_at == DAY1
    assert set(scan.completed.found) == {f1.key, _key("f2")}
    assert scan.withdrawn == frozenset({_key("f3")})


def test_high_without_confirmation_is_not_urgent_and_unknown_is_medium(
    client,
) -> None:
    scan = _completed_scan(
        client,
        [
            _summary("f1", "HIGH", validation="NOT_VALIDATED"),
            _summary("f2", "UNKNOWN", confidence="LOW"),
        ],
    )
    by_id = {d.external_id: d for d in scan.candidates}
    assert by_id["f1"].urgent is False
    assert by_id["f2"].severity is Severity.MEDIUM
    assert by_id["f2"].confidence == "LOW"


def test_critical_is_urgent(client) -> None:
    scan = _completed_scan(client, [_summary("f1", "CRITICAL")])
    assert scan.candidates[0].urgent is True


def test_finding_without_code_locations_keys_on_an_empty_path(client) -> None:
    summary = _summary("f1", "HIGH")
    scan = _completed_scan(client, [summary], [summary])
    assert scan.candidates[0].key == code_review_key(
        "weekly-actions", "XSS", "name-f1", ""
    )
    assert scan.candidates[0].location is None


@pytest.mark.parametrize(
    ("location", "expected"),
    [
        ({"filePath": "src/b.py", "lineStart": 7, "lineEnd": 7}, "src/b.py:7"),
        ({"filePath": "src/b.py", "lineStart": 7}, "src/b.py:7"),
        ({"filePath": "src/b.py"}, "src/b.py"),
    ],
)
def test_location_formats(client, location, expected) -> None:
    summary = _summary("f1", "HIGH")
    scan = _completed_scan(
        client, [summary], [{**summary, "codeLocations": [location, LOCATION]}]
    )
    assert scan.candidates[0].location == expected
    assert scan.candidates[0].key == _key("f1", "src/b.py")


def test_key_alive_in_the_same_job_is_not_withdrawn(client) -> None:
    scan = _completed_scan(
        client,
        [
            _summary("f1", "LOW"),
            {**_summary("f1", "LOW", status="RESOLVED"), "findingId": "f1b"},
        ],
    )
    assert scan.withdrawn == frozenset()


def test_key_found_twice_keeps_every_finding_id(client) -> None:
    scan = _completed_scan(
        client,
        [
            _summary("f1", "MEDIUM"),
            {**_summary("f1", "HIGH"), "findingId": "f1b"},
            {**_summary("f1", "LOW"), "findingId": "f1c"},
        ],
    )
    (candidate,) = scan.candidates
    assert (candidate.external_id, candidate.severity) == ("f1b", Severity.HIGH)
    assert candidate.finding_ids == ("f1b", "f1", "f1c")
    assert scan.completed is not None
    assert scan.completed.found[_key("f1")] == candidate


def test_findings_are_read_100_at_a_time(client) -> None:
    summaries = [_summary(f"n{i}", "LOW") for i in range(101)]
    ids = [s["findingId"] for s in summaries]
    with Stubber(client) as stub:
        _expect_reviews(stub)
        _expect_jobs(stub, [_job("j1", "COMPLETED", DAY1, DAY1_END)])
        _expect_findings(stub, "j1", summaries)
        _expect_batch(stub, [_full(s) for s in summaries[:100]], ids[:100])
        _expect_batch(stub, [_full(s) for s in summaries[100:]], ids[100:])
        scan = CodeReviewClient(client, SPACE).target_scan(REPO)
        stub.assert_no_pending_responses()
    assert scan.completed is not None
    assert len(scan.completed.found) == 101


def test_detected_at_falls_back_to_the_job_time(client) -> None:
    summary = _summary("f1", "HIGH")
    del summary["createdAt"]
    scan = _completed_scan(client, [summary])
    assert scan.candidates[0].detected_at == DAY1


def test_no_completed_job_has_no_findings(client) -> None:
    with Stubber(client) as stub:
        _expect_reviews(stub)
        _expect_jobs(stub, [_job("j2", "IN_PROGRESS", DAY8, DAY8)])
        scan = CodeReviewClient(client, SPACE).target_scan(REPO)
        stub.assert_no_pending_responses()
    assert (scan.latest_status, scan.candidates, scan.completed) == (
        "IN_PROGRESS",
        (),
        None,
    )
    assert scan.completed_at is None


def test_missing_code_review_and_never_run(client) -> None:
    with Stubber(client) as stub:
        _expect_reviews(stub, [_review("cr-x", "other")])
        missing = CodeReviewClient(client, SPACE).target_scan(REPO)
        _expect_reviews(stub)
        _expect_jobs(stub, [])
        never = CodeReviewClient(client, SPACE).target_scan(REPO)
        stub.assert_no_pending_responses()
    assert missing.latest_status == MISSING
    assert never.latest_status == NEVER_RUN
    for scan in (missing, never):
        assert (scan.source, scan.target) == ("code-review", "weekly-actions")
        assert (scan.candidates, scan.withdrawn, scan.completed) == (
            (),
            frozenset(),
            None,
        )


def test_detection_reads_details_and_rejects_other_code_reviews(client) -> None:
    with Stubber(client) as stub:
        _expect_reviews(stub)
        _expect_batch(
            stub,
            [
                _full(
                    _summary("f1", "HIGH", validation="CONFIRMED"),
                    description="D",
                    reasoning="R",
                )
            ],
        )
        _expect_batch(stub, [_full(_summary("f9", "HIGH"), codeReviewId="cr-9")])
        reader = CodeReviewClient(client, SPACE)
        detection = reader.detection(REPO, "f1")
        assert reader.detection(REPO, "f9") is None
        stub.assert_no_pending_responses()
    assert detection is not None
    assert detection.details == (("Description", "D"), ("Reasoning", "R"))
    assert detection.key == _key("f1")
    assert detection.location == "src/a.py:10-12"
    assert detection.urgent is True


def test_detection_skips_empty_details(client) -> None:
    with Stubber(client) as stub:
        _expect_reviews(stub)
        _expect_batch(
            stub, [_full(_summary("f1", "HIGH"), description="", reasoning="R")]
        )
        detection = CodeReviewClient(client, SPACE).detection(REPO, "f1")
        stub.assert_no_pending_responses()
    assert detection is not None
    assert detection.details == (("Reasoning", "R"),)


def test_detection_without_the_code_review_or_finding_is_none(client) -> None:
    with Stubber(client) as stub:
        _expect_reviews(stub, [])
        assert CodeReviewClient(client, SPACE).detection(REPO, "f1") is None
        _expect_reviews(stub)
        stub.add_response(
            "batch_get_findings",
            {"findings": [], "notFound": ["f1"]},
            {"agentSpaceId": SPACE, "findingIds": ["f1"]},
        )
        assert CodeReviewClient(client, SPACE).detection(REPO, "f1") is None
        stub.assert_no_pending_responses()


def test_code_review_ids_are_read_once_per_client(client) -> None:
    with Stubber(client) as stub:
        _expect_reviews(stub)
        for _ in range(2):
            _expect_batch(stub, [_full(_summary("f1", "HIGH"))])
        reader = CodeReviewClient(client, SPACE)
        reader.detection(REPO, "f1")
        reader.detection(REPO, "f1")
        stub.assert_no_pending_responses()


def _start_response(cid: str) -> dict[str, Any]:
    return {"codeReviewId": cid, "codeReviewJobId": f"job-{cid}"}


def test_start_due_starts_the_oldest_first_within_free_slots(client) -> None:
    with Stubber(client) as stub:
        _expect_reviews(
            stub,
            [_review(f"cr-{n}", f"weekly-{n}") for n in ("a", "b", "c")],
        )
        _expect_jobs(stub, [], cid="cr-a")
        _expect_jobs(
            stub,
            [_job("jb", "COMPLETED", NOW - timedelta(days=8), NOW, cid="cr-b")],
            cid="cr-b",
        )
        _expect_jobs(
            stub,
            [
                _job(
                    f"jc{i}",
                    "IN_PROGRESS",
                    NOW - timedelta(days=1),
                    NOW,
                    cid="cr-c",
                )
                for i in range(9)
            ],
            cid="cr-c",
        )
        stub.add_response(
            "start_code_review_job",
            _start_response("cr-a"),
            {"agentSpaceId": SPACE, "codeReviewId": "cr-a"},
        )
        assert CodeReviewClient(client, SPACE).start_due(REPOS, NOW) == StartResult(
            1, 0
        )
        stub.assert_no_pending_responses()


def test_start_due_skips_recent_and_failed_jobs_count_as_not_run(client) -> None:
    with Stubber(client) as stub:
        _expect_reviews(
            stub, [_review("cr-a", "weekly-a"), _review("cr-b", "weekly-b")]
        )
        _expect_jobs(
            stub,
            [_job("ja", "COMPLETED", NOW - timedelta(days=6), NOW, cid="cr-a")],
            cid="cr-a",
        )
        _expect_jobs(
            stub,
            [_job("jb", "FAILED", NOW - timedelta(days=1), NOW, cid="cr-b")],
            cid="cr-b",
        )
        stub.add_response(
            "start_code_review_job",
            _start_response("cr-b"),
            {"agentSpaceId": SPACE, "codeReviewId": "cr-b"},
        )
        assert CodeReviewClient(client, SPACE).start_due(REPOS[:2], NOW) == StartResult(
            1, 0
        )
        stub.assert_no_pending_responses()


def test_start_due_stops_quietly_on_throttling_and_skips_missing(client) -> None:
    with Stubber(client) as stub:
        _expect_reviews(
            stub, [_review("cr-b", "weekly-b"), _review("cr-c", "weekly-c")]
        )
        _expect_jobs(
            stub,
            [_job("jb", "COMPLETED", NOW - timedelta(days=9), NOW, cid="cr-b")],
            cid="cr-b",
        )
        _expect_jobs(
            stub,
            [_job("jc", "COMPLETED", NOW - timedelta(days=8), NOW, cid="cr-c")],
            cid="cr-c",
        )
        stub.add_client_error(
            "start_code_review_job",
            service_error_code="ThrottlingException",
            expected_params={"agentSpaceId": SPACE, "codeReviewId": "cr-b"},
        )
        assert CodeReviewClient(client, SPACE).start_due(REPOS, NOW) == StartResult(
            0, 0
        )
        stub.assert_no_pending_responses()


def test_start_due_counts_a_failed_start_and_goes_on(client) -> None:
    with Stubber(client) as stub:
        _expect_reviews(
            stub, [_review("cr-a", "weekly-a"), _review("cr-b", "weekly-b")]
        )
        _expect_jobs(stub, [], cid="cr-a")
        _expect_jobs(
            stub,
            [_job("jb", "COMPLETED", NOW - timedelta(days=8), NOW, cid="cr-b")],
            cid="cr-b",
        )
        stub.add_client_error(
            "start_code_review_job",
            service_error_code="ConflictException",
            expected_params={"agentSpaceId": SPACE, "codeReviewId": "cr-a"},
        )
        stub.add_response(
            "start_code_review_job",
            _start_response("cr-b"),
            {"agentSpaceId": SPACE, "codeReviewId": "cr-b"},
        )
        assert CodeReviewClient(client, SPACE).start_due(REPOS[:2], NOW) == StartResult(
            started=1, failed=1
        )
        stub.assert_no_pending_responses()


def test_start_due_skips_a_running_job_of_any_age(client) -> None:
    with Stubber(client) as stub:
        _expect_reviews(stub, [_review("cr-a", "weekly-a")])
        _expect_jobs(
            stub,
            [_job("ja", "IN_PROGRESS", NOW - timedelta(days=8), NOW, cid="cr-a")],
            cid="cr-a",
        )
        assert CodeReviewClient(client, SPACE).start_due(REPOS[:1], NOW) == StartResult(
            0, 0
        )
        stub.assert_no_pending_responses()
