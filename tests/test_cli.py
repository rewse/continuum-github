"""Tests for the command line."""

from contextlib import contextmanager
from datetime import UTC
from datetime import datetime

import pytest
from botocore.exceptions import ClientError
from fakes import TARGETS_PATH
from fakes import FakeCodeReview
from fakes import FakeCodeVuln
from fakes import FakeGitHub
from fakes import FakePentest

from continuum_github import cli
from continuum_github.config import Repository
from continuum_github.config import Site
from continuum_github.config import Targets
from continuum_github.config import load_settings
from continuum_github.models import CompletedScan
from continuum_github.models import Detection
from continuum_github.models import Severity
from continuum_github.models import TargetScan
from continuum_github.sync import SyncCounts

DAY1 = datetime(2026, 11, 1, tzinfo=UTC)


def test_sync_prints_counts_and_writes_github_output(
    tmp_path, monkeypatch, capsys
) -> None:
    output = tmp_path / "out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("AGENT_SPACE_ID", "as-1")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("REPORT_REPOSITORY", "example-org/security-findings")
    monkeypatch.setattr(
        cli, "_sync", lambda settings, targets: SyncCounts(1, 0, 0, 0, 0, 1, 2, 3)
    )
    assert cli.main(["sync", "--targets", str(TARGETS_PATH)]) == 0
    assert capsys.readouterr().out == (
        "created=1 pending=0 closed=0 reopened=0 revalidations=0 "
        "needs_sections=1 failed=2 started=3\n"
    )
    assert output.read_text() == "needs-sections=1\n"


def test_sync_without_github_output_only_prints(tmp_path, monkeypatch, capsys) -> None:
    targets = tmp_path / "targets.toml"
    targets.write_text(
        'owner = "example-org"\n\n[[repositories]]\nname = "actions"\nprivate = false\n'
    )
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.setenv("AGENT_SPACE_ID", "as-1")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("REPORT_REPOSITORY", "example-org/security-findings")
    seen = []

    def fake_sync(settings, targets):
        seen.append((settings.agent_space_id, len(targets.repositories)))
        return SyncCounts(0, 2, 0, 0, 0, 0)

    monkeypatch.setattr(cli, "_sync", fake_sync)
    assert cli.main(["sync", "--targets", str(targets)]) == 0
    assert capsys.readouterr().out == (
        "created=0 pending=2 closed=0 reopened=0 revalidations=0 "
        "needs_sections=0 failed=0 started=0\n"
    )
    assert seen == [("as-1", 1)]


def test_sections_prints_the_filled_count(monkeypatch, capsys) -> None:
    monkeypatch.setenv("AGENT_SPACE_ID", "as-1")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("REPORT_REPOSITORY", "example-org/security-findings")
    monkeypatch.setenv("BEDROCK_MODEL_ID", "m1")
    seen = []

    def fake_sections(settings, targets):
        seen.append(settings.bedrock_model_id)
        return 3

    monkeypatch.setattr(cli, "_sections", fake_sections)
    assert cli.main(["sections", "--targets", str(TARGETS_PATH)]) == 0
    assert capsys.readouterr().out == "filled=3\n"
    assert seen == ["m1"]


def _refuse(*args, **kwargs):
    raise AssertionError("must not be called without a model")


def test_sections_without_a_model_reads_nothing(monkeypatch, capsys) -> None:
    monkeypatch.setenv("AGENT_SPACE_ID", "as-1")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("REPORT_REPOSITORY", "example-org/security-findings")
    monkeypatch.delenv("BEDROCK_MODEL_ID", raising=False)
    monkeypatch.setattr(cli, "_clients", _refuse)
    monkeypatch.setattr(cli, "bedrock_client", _refuse)
    assert cli.main(["sections", "--targets", str(TARGETS_PATH)]) == 0
    assert capsys.readouterr().out == "filled=0\n"


@pytest.mark.parametrize(
    ("code_review", "started", "failed"),
    [
        (FakeCodeReview(started=2, start_error=None), 2, 0),
        (
            FakeCodeReview(
                start_error=ClientError(
                    {"Error": {"Code": "ConflictException"}}, "StartCodeReviewJob"
                )
            ),
            0,
            1,
        ),
    ],
)
def test_sync_merges_the_code_review_starts(
    monkeypatch, code_review, started, failed
) -> None:
    @contextmanager
    def fake_clients(settings):
        yield FakeGitHub(), FakePentest(scans={}), FakeCodeVuln(), code_review

    monkeypatch.setattr(cli, "_clients", fake_clients)
    settings = load_settings(
        {"AGENT_SPACE_ID": "as-1", "GITHUB_TOKEN": "t", "REPORT_REPOSITORY": "o/r"}
    )
    targets = Targets("example-org", (Repository("actions", False),), ())
    counts = cli._sync(settings, targets)
    assert (counts.started, counts.failed) == (started, failed)
    assert code_review.start_calls[0][0] == ["actions"]


def test_sync_puts_the_configured_mention_on_an_urgent_issue(monkeypatch) -> None:
    candidate = Detection(
        source="pentest",
        target="weekly-x",
        repository="actions",
        key="k1",
        external_id="f1",
        name="finding",
        severity=Severity.CRITICAL,
        urgent=True,
        confidence="HIGH",
        detected_at=DAY1,
        site="x.example.com",
        pentest_id="pt-1",
    )
    scan = TargetScan(
        source="pentest",
        target="weekly-x",
        candidates=(candidate,),
        withdrawn=frozenset(),
        completed=CompletedScan("j1", DAY1, {"k1": candidate}),
        latest_status="COMPLETED",
        completed_at=DAY1,
    )
    github = FakeGitHub()

    @contextmanager
    def fake_clients(settings):
        yield (
            github,
            FakePentest(scans={"weekly-x": scan}),
            FakeCodeVuln(),
            FakeCodeReview(),
        )

    monkeypatch.setattr(cli, "_clients", fake_clients)
    settings = load_settings(
        {
            "AGENT_SPACE_ID": "as-1",
            "GITHUB_TOKEN": "t",
            "MENTION": "@octocat",
            "REPORT_REPOSITORY": "o/r",
        }
    )
    targets = Targets(
        "example-org",
        (Repository("actions", False),),
        (Site("x.example.com", "weekly-x", "actions"),),
    )
    cli._sync(settings, targets)
    ((_, body, _),) = github.created
    assert body.startswith("@octocat\n\n| Field | Value |")
