"""Tests for the weekly report."""

import json
import subprocess
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC
from datetime import datetime
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal

import pytest
from fakes import TARGETS_PATH
from fakes import FakeGitHub
from fakes import FakeModel
from fakes import RecordingModel

from continuum_scan import cli
from continuum_scan.bedrock import severity_summaries
from continuum_scan.bedrock import visual_report_source
from continuum_scan.models import Severity
from continuum_scan.models import TargetScan
from continuum_scan.records import BOT
from continuum_scan.records import Record
from continuum_scan.report import build_visual_report
from continuum_scan.report import build_weekly
from continuum_scan.report import color_unstyled_svg_text
from continuum_scan.report import publish_weekly
from continuum_scan.report import render_weekly
from continuum_scan.report import set_html_lang
from continuum_scan.report import strip_external_fonts
from continuum_scan.report import unavailable_parts
from continuum_scan.report import weekly_title
from continuum_scan.state import IssueState

NOW = datetime(2026, 11, 13, 21, 35, tzinfo=UTC)


def _rec(
    n: int,
    severity_label: str,
    *,
    created: datetime = NOW - timedelta(days=30),
    open: bool = True,
    closed: datetime | None = None,
    reason: str | None = None,
    merged_into: int | None = None,
    title: str | None = None,
    body: str = "",
    auto_closed: Literal["absent", "withdrawn"] | None = None,
    status: str = "new",
) -> Record:
    return Record(
        number=n,
        url=f"u{n}",
        title=title or f"t{n}",
        body=body,
        open=open,
        state_reason=reason,
        labels=frozenset(
            {*status.split(), severity_label, "pentest", "repo:ansible-playbooks"}
        ),
        created_at=created,
        closed_at=closed,
        state=IssueState(
            source="pentest",
            target="weekly-x",
            keys=(f"k{n}",),
            finding_ids=(f"f{n}",),
            merged_into=merged_into,
            auto_closed=auto_closed,
        ),
    )


def _ts(
    source: Any, target: str, latest_status: str, completed_at: datetime | None
) -> TargetScan:
    return TargetScan(
        source=source,
        target=target,
        candidates=(),
        withdrawn=frozenset(),
        completed=None,
        latest_status=latest_status,
        completed_at=completed_at,
    )


def _weekly(n: int, title: str, open: bool) -> dict[str, Any]:
    return {
        "number": n,
        "html_url": f"u{n}",
        "title": title,
        "state": "open" if open else "closed",
        "state_reason": None if open else "completed",
        "labels": [{"name": "weekly-report"}],
        "created_at": "2026-11-01T00:00:00Z",
        "closed_at": None if open else "2026-11-02T00:00:00Z",
        "user": {"login": BOT},
        "body": "old",
    }


DATA = build_weekly(
    [
        _rec(7, "severity:high", title="SQL injection", body="## Summary\n\nsum7\n"),
        _rec(8, "severity:medium"),
    ],
    [_ts("pentest", "weekly-a", "FAILED", None)],
    NOW,
)
SKILL_DIR = Path("/nonexistent-skill-dir")
_SKILL_FILES = (
    "SKILL.md",
    "references/kit.md",
    "references/diagrams.md",
    "references/style-guide.md",
)


@pytest.fixture(autouse=True, scope="module")
def _skill_dir(tmp_path_factory: pytest.TempPathFactory) -> None:
    """Points SKILL_DIR at a skill folder with empty reference files."""
    global SKILL_DIR
    SKILL_DIR = tmp_path_factory.mktemp("skill")
    for name in _SKILL_FILES:
        (SKILL_DIR / name).parent.mkdir(parents=True, exist_ok=True)
        (SKILL_DIR / name).write_text("")


def test_weekly_title_uses_the_iso_week() -> None:
    assert (
        weekly_title(datetime(2026, 11, 13, 21, 35, tzinfo=UTC))
        == "Continuum weekly report 2026-W46"
    )


def test_build_weekly_counts_open_new_and_closed() -> None:
    records = [
        _rec(1, "severity:high", created=NOW - timedelta(days=2)),
        _rec(2, "severity:medium", created=NOW - timedelta(days=20)),
        _rec(
            3,
            "severity:medium",
            open=False,
            closed=NOW - timedelta(days=1),
            reason="completed",
        ),
        _rec(
            4,
            "severity:medium",
            open=False,
            closed=NOW - timedelta(days=30),
            reason="completed",
        ),
        _rec(
            5,
            "severity:high",
            merged_into=1,
            open=False,
            closed=NOW - timedelta(days=1),
            reason="duplicate",
        ),
    ]
    data = build_weekly(records, [], NOW)
    assert data.counts == {Severity.HIGH: (1, 1, 0), Severity.MEDIUM: (1, 0, 1)}
    assert [i.number for i in data.open_items] == [1, 2]
    assert [i.number for i in data.closed_items] == [3]


def test_build_weekly_lists_incomplete_scans() -> None:
    scans = [
        _ts("pentest", "weekly-a", "FAILED", NOW - timedelta(days=1)),
        _ts("code-vuln", "actions", "COMPLETED", NOW - timedelta(days=9)),
        _ts("pentest", "weekly-b", "COMPLETED", NOW - timedelta(days=1)),
        _ts("code-vuln", "dotfiles", "NEVER_RUN", None),
    ]
    assert build_weekly([], scans, NOW).incomplete == (
        "pentest: weekly-a (FAILED)",
        "code-vuln: actions (COMPLETED)",
        "code-vuln: dotfiles (NEVER_RUN)",
    )


def test_render_weekly_orders_sections_and_hides_empty_ones() -> None:
    body, comments = render_weekly(
        build_weekly([_rec(1, "severity:high")], [], NOW), {Severity.HIGH: "Two XSS."}
    )
    assert comments == []
    assert body.index(
        "| Severity | Open | New this week | Closed this week |"
    ) < body.index("## High")
    assert "Two XSS." in body and "## Medium" not in body
    assert "## Incomplete scans" not in body
    assert "Visual report: {{CONTINUUM_HTML_URL}}" in body
    assert "- #1 [new] [high] [pentest] ansible-playbooks: t1" in body


TWO_SEVERITIES = build_weekly(
    [_rec(1, "severity:high"), _rec(2, "severity:medium")], [], NOW
)


def test_render_weekly_leaves_out_missing_summaries() -> None:
    body, _ = render_weekly(TWO_SEVERITIES, {Severity.MEDIUM: "Medium summary."})
    assert "## High\n\n" not in body
    assert "## Medium\n\nMedium summary." in body
    assert "Written without Bedrock" not in body


def test_render_weekly_ends_with_the_fallback_note() -> None:
    body, _ = render_weekly(TWO_SEVERITIES, {}, ["High summary", "Visual report"])
    assert body.rstrip().endswith(
        "_Written without Bedrock this week: High summary, Visual report._"
    )


def test_render_weekly_keeps_the_note_last_when_lists_overflow() -> None:
    records = [_rec(n, "severity:medium", title="x" * 200) for n in range(1, 600)]
    body, comments = render_weekly(
        build_weekly(records, [], NOW), {}, ["Medium summary"]
    )
    assert len(body) <= 65000 and comments
    assert body.rstrip().endswith(
        "_Written without Bedrock this week: Medium summary._"
    )


def test_unavailable_parts_lists_missing_summaries_and_html() -> None:
    assert unavailable_parts(TWO_SEVERITIES, {Severity.MEDIUM: "s"}, html=False) == [
        "High summary",
        "Visual report",
    ]
    both = {Severity.HIGH: "s", Severity.MEDIUM: "s"}
    assert unavailable_parts(TWO_SEVERITIES, both, html=True) == []


def test_publish_weekly_with_html_links_it() -> None:
    url = "https://github.com/example-org/security-findings/actions/runs/1/artifacts/2"
    github = FakeGitHub()
    body, comments = render_weekly(TWO_SEVERITIES, {})
    publish_weekly(github, "Continuum weekly report 2026-W46", body, comments, url)
    (posted,) = github.bodies.values()
    assert f"Visual report: {url}" in posted


def test_publish_weekly_without_html_removes_the_line() -> None:
    github = FakeGitHub()
    body, comments = render_weekly(TWO_SEVERITIES, {})
    publish_weekly(github, "Continuum weekly report 2026-W46", body, comments, None)
    (posted,) = github.bodies.values()
    assert "Visual report" not in posted
    assert "{{CONTINUUM_HTML_URL}}" not in posted


def test_list_lines_drop_the_severity_tag_of_the_title() -> None:
    record = _rec(1, "severity:high", title="[HIGH] Reflected XSS")
    body, _ = render_weekly(build_weekly([record], [], NOW), {})
    assert "- #1 [new] [high] [pentest] ansible-playbooks: Reflected XSS" in body


def test_overflow_moves_whole_lines_to_comments() -> None:
    records = [_rec(n, "severity:medium", title="x" * 200) for n in range(1, 600)]
    body, comments = render_weekly(build_weekly(records, [], NOW), {})
    assert len(body) <= 65000 and comments and all(len(c) <= 65000 for c in comments)
    assert "Continued in the comments below." in body
    lines = [
        l
        for part in (body, *comments)
        for l in part.splitlines()
        if l.startswith("- #")
    ]
    assert len(lines) == 599 and all(l.endswith("x" * 200) for l in lines)


def test_publish_weekly_updates_same_week_and_closes_older() -> None:
    github = FakeGitHub(
        issues=[
            _weekly(10, "Continuum weekly report 2026-W45", open=True),
            _weekly(11, "Continuum weekly report 2026-W46", open=False),
        ]
    )
    result = publish_weekly(
        github,
        "Continuum weekly report 2026-W46",
        "head\n\nVisual report: {{CONTINUUM_HTML_URL}}\n\nlists\n",
        [],
        None,
    )
    assert result == "updated"
    assert github.bodies[11] == "head\n\nlists\n"
    assert (11, {"state": "open"}) in github.updates and (
        10,
        {"state": "closed", "state_reason": "completed"},
    ) in github.updates


def test_critical_row_appears_only_when_non_zero() -> None:
    data = build_weekly([_rec(1, "severity:high")], [], NOW)
    assert list(data.counts) == [Severity.HIGH, Severity.MEDIUM]
    body, _ = render_weekly(data, {})
    assert "| Critical |" not in body and "## Critical" not in body

    data = build_weekly(
        [_rec(1, "severity:critical"), _rec(2, "severity:high")], [], NOW
    )
    assert list(data.counts) == [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]
    assert data.repositories == {
        "ansible-playbooks": {Severity.CRITICAL: 1, Severity.HIGH: 1}
    }
    body, _ = render_weekly(data, {Severity.CRITICAL: "One critical."})
    assert "| Critical | 1 | 0 | 0 |" in body and "## Critical" in body
    assert "| Repository | Critical | High | Medium |" in body
    assert "| ansible-playbooks | 1 | 1 | 0 |" in body
    assert [i.number for i in data.open_items] == [1, 2]


def test_record_without_severity_label_counts_as_medium() -> None:
    data = build_weekly([_rec(1, "unrelated")], [], NOW)
    assert data.counts[Severity.MEDIUM] == (1, 0, 0)


def test_closed_line_shows_the_reason() -> None:
    records = [
        _rec(
            3,
            "severity:medium",
            open=False,
            closed=NOW - timedelta(days=1),
            reason="completed",
        ),
        _rec(
            4,
            "severity:medium",
            open=False,
            closed=NOW - timedelta(days=1),
            reason="not_planned",
            auto_closed="withdrawn",
        ),
    ]
    body, _ = render_weekly(build_weekly(records, [], NOW), {})
    assert "- #3 [completed] [medium] [pentest] ansible-playbooks: t3" in body
    assert "- #4 [not planned] [medium] [pentest] ansible-playbooks: t4" in body
    assert "<details><summary>Closed this week (2)</summary>" in body


def test_owner_not_planned_and_duplicate_closes_are_not_closed_this_week() -> None:
    week = NOW - timedelta(days=1)
    records = [
        _rec(1, "severity:medium", open=False, closed=week, reason="completed"),
        _rec(2, "severity:medium", open=False, closed=week, reason="not_planned"),
        _rec(
            3,
            "severity:medium",
            open=False,
            closed=week,
            reason="not_planned",
            auto_closed="withdrawn",
        ),
        _rec(4, "severity:medium", open=False, closed=week, reason="duplicate"),
        _rec(
            5,
            "severity:medium",
            open=False,
            closed=week,
            reason="not_planned",
            auto_closed="absent",
        ),
    ]
    data = build_weekly(records, [], NOW)
    assert [item.number for item in data.closed_items] == [1, 3]
    assert data.counts[Severity.MEDIUM] == (0, 0, 2)


def test_status_prefers_wip_then_pending_then_new() -> None:
    records = [
        _rec(1, "severity:medium", status="new pending wip"),
        _rec(2, "severity:medium", status="new pending"),
        _rec(3, "severity:medium", status="new"),
    ]
    data = build_weekly(records, [], NOW)
    assert [item.status for item in data.open_items] == ["wip", "pending", "new"]


def test_titles_and_summaries_are_escaped() -> None:
    data = build_weekly([_rec(1, "severity:high", title="<script>")], [], NOW)
    body, _ = render_weekly(data, {Severity.HIGH: "<!-- x"})
    assert "<script>" not in body and "&lt;script>" in body
    assert "<!-- x" not in body and "&lt;!-- x" in body


def test_open_item_reads_the_summary_section() -> None:
    record = _rec(
        1, "severity:high", body="## Summary\n\nXSS in q.\n\n## Why it matters\n\nw"
    )
    (item,) = build_weekly([record], [], NOW).open_items
    assert item.summary == "XSS in q."


def test_overflowed_comments_render_collapsed() -> None:
    records = [_rec(n, "severity:medium", title="x" * 200) for n in range(1, 600)]
    records += [
        _rec(
            n,
            "severity:medium",
            title="y" * 200,
            open=False,
            closed=NOW - timedelta(days=1),
            reason="completed",
        )
        for n in range(600, 700)
    ]
    body, comments = render_weekly(build_weekly(records, [], NOW), {})
    assert body.count("<details>") == body.count("</details>") == 2
    for comment in comments:
        assert comment.startswith("<details><summary>")
        assert comment.count("<details>") == comment.count("</details>")
    joined = "\n".join(comments)
    assert "<details><summary>Open findings (continued)</summary>" in joined
    assert "<details><summary>Closed this week (continued)</summary>" in joined


def test_publish_weekly_creates_when_absent_and_posts_comments() -> None:
    github = FakeGitHub(
        issues=[_weekly(10, "Continuum weekly report 2026-W45", open=True)]
    )
    result = publish_weekly(
        github,
        "Continuum weekly report 2026-W46",
        "see {{CONTINUUM_HTML_URL}}",
        ["c1", "c2"],
        "https://h",
    )
    assert result == "created"
    assert github.created == [
        ("Continuum weekly report 2026-W46", "see https://h", ["weekly-report"])
    ]
    assert github.comments == [(11, "c1"), (11, "c2")]
    assert github.updates == [(10, {"state": "closed", "state_reason": "completed"})]


def test_publish_weekly_ignores_issues_by_others() -> None:
    other = _weekly(10, "Continuum weekly report 2026-W46", open=True)
    other["user"] = {"login": "mallory"}
    github = FakeGitHub(issues=[other])
    assert (
        publish_weekly(github, "Continuum weekly report 2026-W46", "b", [], None)
        == "created"
    )
    assert github.updates == []


def test_severity_summaries_asks_once_per_severity() -> None:
    data = build_weekly(
        [
            _rec(1, "severity:high"),
            _rec(2, "severity:high"),
            _rec(3, "severity:medium"),
        ],
        [],
        NOW,
    )
    model = FakeModel(" Two findings. ")
    assert severity_summaries(model, data) == {
        Severity.HIGH: "Two findings.",
        Severity.MEDIUM: "Two findings.",
    }
    assert len(model.prompts) == 2
    assert model.purposes == ["summary", "summary"]
    assert (
        "t1" in model.prompts[0]
        and "t2" in model.prompts[0]
        and "t3" not in model.prompts[0]
    )


def test_severity_summaries_drops_bad_answers() -> None:
    data = build_weekly([_rec(1, "severity:high")], [], NOW)
    assert severity_summaries(FakeModel(None), data) == {}
    assert severity_summaries(FakeModel("  "), data) == {}
    assert severity_summaries(FakeModel("x" * 1501), data) == {}


def test_cli_report_build_writes_files_and_prints_counts(
    tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("AGENT_SPACE_ID", "as-1")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("REPORT_REPOSITORY", "example-org/security-findings")
    monkeypatch.setenv("BEDROCK_MODEL_ID", "m1")
    monkeypatch.setenv("CONTINUUM_LANGUAGE", "ja_JP")
    records = [
        _rec(1, "severity:high", created=NOW - timedelta(days=2)),
        _rec(
            3,
            "severity:medium",
            open=False,
            closed=NOW - timedelta(days=1),
            reason="completed",
        ),
    ]
    data = build_weekly(records, [_ts("pentest", "weekly-a", "FAILED", None)], NOW)
    monkeypatch.setattr(
        cli,
        "_build_report",
        lambda settings, targets, model: (data, {Severity.HIGH: "High summary."}),
    )
    visual = []

    def fake_visual(model, data_, skill_dir, out_, language):
        visual.append((data_, skill_dir, out_, language))
        return True

    monkeypatch.setattr(cli, "build_visual_report", fake_visual)
    monkeypatch.setenv("VISUAL_EXPLAINER_DIR", "/ve")
    out = tmp_path / "out"
    assert (
        cli.main(["report", "build", "--targets", str(TARGETS_PATH), "--out", str(out)])
        == 0
    )
    assert capsys.readouterr().out == "open=1 new=1 closed=1 incomplete=1 html=1\n"
    assert visual == [(data, Path("/ve"), out / "report.html", "ja_JP")]
    body = (out / "body.md").read_text()
    assert (body, []) == render_weekly(data, {Severity.HIGH: "High summary."})
    assert "Written without Bedrock" not in body
    assert json.loads((out / "comments.json").read_text()) == []
    assert (out / "title.txt").read_text() == "Continuum weekly report 2026-W46"


def test_cli_report_publish_prints_the_result(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("AGENT_SPACE_ID", "as-1")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("REPORT_REPOSITORY", "example-org/security-findings")
    (tmp_path / "body.md").write_text("body")
    (tmp_path / "comments.json").write_text('["c1"]')
    (tmp_path / "title.txt").write_text("Continuum weekly report 2026-W46\n")
    seen = []

    def fake_publish(settings, title, body, comments, html_url):
        seen.append((title, body, comments, html_url))
        return "updated"

    monkeypatch.setattr(cli, "_publish", fake_publish)
    assert (
        cli.main(["report", "publish", "--dir", str(tmp_path), "--html-url", ""]) == 0
    )
    assert capsys.readouterr().out == "published=updated\n"
    assert seen == [("Continuum weekly report 2026-W46", "body", ["c1"], None)]


def test_cli_report_build_counts_a_missing_visual_report(
    tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("AGENT_SPACE_ID", "as-1")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("REPORT_REPOSITORY", "example-org/security-findings")
    monkeypatch.setenv("BEDROCK_MODEL_ID", "m1")
    monkeypatch.setattr(
        cli, "_build_report", lambda settings, targets, model: (DATA, {})
    )
    monkeypatch.setattr(cli, "build_visual_report", lambda *args, **kwargs: False)
    assert (
        cli.main(
            ["report", "build", "--targets", str(TARGETS_PATH), "--out", str(tmp_path)]
        )
        == 0
    )
    assert capsys.readouterr().out.endswith(" html=0\n")
    assert (
        (tmp_path / "body.md")
        .read_text()
        .rstrip()
        .endswith(
            "_Written without Bedrock this week: High summary, Medium summary, "
            "Visual report._"
        )
    )


def test_cli_report_build_without_a_model_skips_summaries_and_html(
    tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("AGENT_SPACE_ID", "as-1")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("REPORT_REPOSITORY", "example-org/security-findings")
    monkeypatch.delenv("BEDROCK_MODEL_ID", raising=False)

    def refuse(*args, **kwargs):
        raise AssertionError("must not be called without a model")

    @contextmanager
    def clients(settings):
        yield FakeGitHub(), None, None, None

    monkeypatch.setattr(cli, "bedrock_client", refuse)
    monkeypatch.setattr(cli, "build_visual_report", refuse)
    monkeypatch.setattr(cli, "_clients", clients)
    monkeypatch.setattr(
        cli,
        "records_from_issues",
        lambda issues: [_rec(7, "severity:high", created=NOW - timedelta(days=2))],
    )
    monkeypatch.setattr(cli, "collect_scans", lambda *args: [])
    out = tmp_path / "out"
    (out).mkdir()
    (out / "report.html").write_text("stale")
    assert (
        cli.main(["report", "build", "--targets", str(TARGETS_PATH), "--out", str(out)])
        == 0
    )
    assert not (out / "report.html").exists()
    body = (out / "body.md").read_text()
    assert "## High\n\n" not in body
    assert "Written without Bedrock" not in body
    assert capsys.readouterr().out.rstrip().endswith("html=0")


def test_strip_external_fonts_removes_google_links_only() -> None:
    html = (
        '<head><link rel="preconnect" href="https://fonts.googleapis.com">'
        '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
        '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=X">'
        '<link rel="icon" href="data:,"></head>'
    )
    assert strip_external_fonts(html) == '<head><link rel="icon" href="data:,"></head>'


def test_build_visual_report_retries_once_with_render_errors(tmp_path) -> None:
    calls = []

    def runner(args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            return subprocess.CompletedProcess(
                args, 1, stdout="", stderr="line 3 <ve-bar>: bad"
            )
        Path(args[args.index("-o") + 1]).write_text(
            '<link href="https://fonts.googleapis.com/x" rel="stylesheet"><p>ok</p>'
        )
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    model = RecordingModel(["<html>1</html>", "<html>2</html>"])
    out = tmp_path / "report.html"
    assert build_visual_report(model, DATA, SKILL_DIR, out, runner=runner) is True
    assert out.read_text() == "<p>ok</p>"
    assert "line 3 <ve-bar>: bad" in model.prompts[1]
    assert (
        calls[0][:2] == ["node", str(SKILL_DIR / "kit" / "render.mjs")]
        and calls[0][-1] == "--no-check"
    )


def test_build_visual_report_gives_up_without_writing(tmp_path) -> None:
    out = tmp_path / "report.html"
    always_fail = lambda args, **kw: subprocess.CompletedProcess(
        args, 1, stdout="", stderr="e"
    )
    assert (
        build_visual_report(
            RecordingModel(["a", "b"]), DATA, SKILL_DIR, out, runner=always_fail
        )
        is False
    )
    assert (
        build_visual_report(
            RecordingModel([None]), DATA, SKILL_DIR, out, runner=always_fail
        )
        is False
    )
    assert not out.exists()


def test_build_visual_report_writes_the_source_and_removes_partial_output(
    tmp_path,
) -> None:
    sources = []

    def runner(args, **kwargs):
        sources.append(Path(args[2]).read_text())
        assert kwargs == {"capture_output": True, "text": True, "timeout": 300}
        Path(args[args.index("-o") + 1]).write_text("partial")
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="e")

    out = tmp_path / "report.html"
    model = RecordingModel(["<p>1</p>", "<p>2</p>"])
    assert build_visual_report(model, DATA, SKILL_DIR, out, runner=runner) is False
    assert sources == ["<p>1</p>", "<p>2</p>"]
    assert not out.exists()


def test_build_visual_report_ignores_a_stale_output_file(tmp_path) -> None:
    out = tmp_path / "report.html"
    out.write_text("stale")
    no_output = lambda args, **kw: subprocess.CompletedProcess(
        args, 0, stdout="", stderr=""
    )
    model = RecordingModel(["a", "b"])
    assert build_visual_report(model, DATA, SKILL_DIR, out, runner=no_output) is False
    assert not out.exists()


def test_build_visual_report_keeps_the_last_render_errors(tmp_path) -> None:
    stderr = "x" * 100 + "y" * 8000
    long_fail = lambda args, **kw: subprocess.CompletedProcess(
        args, 1, stdout="", stderr=stderr
    )
    model = RecordingModel(["a", "b"])
    out = tmp_path / "report.html"
    assert build_visual_report(model, DATA, SKILL_DIR, out, runner=long_fail) is False
    assert "y" * 8000 in model.prompts[1]
    assert "xy" not in model.prompts[1]


def test_build_visual_report_fails_when_node_cannot_run(tmp_path) -> None:
    def runner(args, **kwargs):
        raise subprocess.TimeoutExpired(args, 300)

    out = tmp_path / "report.html"
    model = RecordingModel(["a", "b"])
    assert build_visual_report(model, DATA, SKILL_DIR, out, runner=runner) is False
    assert not out.exists()


def test_visual_report_source_passes_skill_files_and_data() -> None:
    model = RecordingModel(["<html>page</html>"])
    assert visual_report_source(model, DATA, SKILL_DIR) == "<html>page</html>"
    assert model.resources[0] == [SKILL_DIR / name for name in _SKILL_FILES]
    assert model.purposes == ["page"]
    prompt = model.prompts[0]
    assert "in the language of the locale en_US" in prompt
    assert '<link rel="stylesheet" href="kit.css" data-ve-kit>' in prompt
    for text in ("#7", "high", "pentest", "ansible-playbooks", "SQL injection", "sum7"):
        assert text in prompt
    assert "pentest: weekly-a (FAILED)" in prompt
    assert "rendering errors" not in prompt


def test_visual_report_source_skips_missing_files_and_adds_errors(tmp_path) -> None:
    (tmp_path / "SKILL.md").write_text("")
    model = RecordingModel([None])
    assert visual_report_source(model, DATA, tmp_path, errors="line 9: bad") is None
    assert model.resources[0] == [tmp_path / "SKILL.md"]
    assert "line 9: bad" in model.prompts[0]


def test_color_unstyled_svg_text_adds_one_low_priority_rule_to_the_head() -> None:
    html = "<html><head><title>t</title></head><body><svg><text>x</text></svg></body></html>"
    result = color_unstyled_svg_text(html)
    rule = (
        "<style>:where(svg text:not([class]):not([fill])) "
        "{ fill: var(--text); }</style></head>"
    )
    assert result == html.replace("</head>", rule, 1)
    assert color_unstyled_svg_text(result) == result


def test_color_unstyled_svg_text_leaves_a_page_without_head_unchanged() -> None:
    assert color_unstyled_svg_text("<p>ok</p>") == "<p>ok</p>"


def test_build_visual_report_colors_unstyled_svg_text(tmp_path) -> None:
    def runner(args, **kwargs):
        Path(args[args.index("-o") + 1]).write_text("<head></head><svg></svg>")
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    out = tmp_path / "report.html"
    model = RecordingModel(["<html>1</html>"])
    assert build_visual_report(model, DATA, SKILL_DIR, out, runner=runner) is True
    assert "fill: var(--text)" in out.read_text()
    assert "class from the kit" in model.prompts[0]


def test_withdrawn_issue_without_a_severity_label_counts_its_recorded_severity() -> (
    None
):
    record = _rec(
        1,
        "",
        created=NOW - timedelta(days=1),
        open=False,
        closed=NOW - timedelta(hours=1),
        reason="not_planned",
        auto_closed="withdrawn",
    )
    record = replace(record, state=replace(record.state, severity="HIGH"))
    data = build_weekly([record], [], NOW)
    assert data.counts[Severity.HIGH] == (0, 1, 1)
    assert data.counts[Severity.MEDIUM] == (0, 0, 0)
    assert [item.severity for item in data.closed_items] == [Severity.HIGH]


def test_severity_summaries_prompt_names_the_locale() -> None:
    model = FakeModel("s")
    data = build_weekly([_rec(1, "severity:high")], [], NOW)
    severity_summaries(model, data, "ja_JP")
    assert "in the language of the locale ja_JP" in model.prompts[0]
    assert "English" not in model.prompts[0]


def test_visual_report_source_names_the_locale() -> None:
    model = RecordingModel(["<html>page</html>"])
    visual_report_source(model, DATA, SKILL_DIR, language="ja_JP")
    prompt = model.prompts[0]
    assert "in the language of the locale ja_JP" in prompt
    assert "Japanese" not in prompt


def test_set_html_lang_adds_or_replaces_the_attribute() -> None:
    assert set_html_lang("<html><head></head></html>", "ja_JP") == (
        '<html lang="ja-JP"><head></head></html>'
    )
    assert set_html_lang('<html lang="en" class="x"><body></body></html>', "en") == (
        '<html lang="en" class="x"><body></body></html>'
    )
    assert set_html_lang('<HTML LANG="en"><body></body></HTML>', "ja_JP") == (
        '<HTML lang="ja-JP"><body></body></HTML>'
    )
    assert set_html_lang("<p>broken</p>", "ja_JP") == "<p>broken</p>"


def test_build_visual_report_sets_the_page_language(tmp_path) -> None:
    def runner(args, **kwargs):
        Path(args[args.index("-o") + 1]).write_text(
            "<html><head></head><body></body></html>"
        )
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    out = tmp_path / "report.html"
    model = RecordingModel(["<html>1</html>"])
    assert build_visual_report(
        model, DATA, SKILL_DIR, out, runner=runner, language="ja_JP"
    )
    assert '<html lang="ja-JP">' in out.read_text()


def test_unavailable_parts_names_the_visual_report() -> None:
    assert unavailable_parts(TWO_SEVERITIES, {}, html=False)[-1] == "Visual report"
