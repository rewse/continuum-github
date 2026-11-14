"""Tests for rendering finding issues."""

from dataclasses import replace
from datetime import UTC
from datetime import datetime

import pytest

from continuum_github.models import Detection
from continuum_github.models import Severity
from continuum_github.models import code_review_key
from continuum_github.models import code_vuln_key
from continuum_github.models import pentest_key
from continuum_github.render import FALLBACK_NOTE
from continuum_github.render import Sections
from continuum_github.render import add_mention
from continuum_github.render import extract_section
from continuum_github.render import fit_body
from continuum_github.render import initial_state
from continuum_github.render import issue_body
from continuum_github.render import issue_labels
from continuum_github.render import issue_title
from continuum_github.render import replace_severity
from continuum_github.render import retitle
from continuum_github.render import severity_label
from continuum_github.render import site_label
from continuum_github.render import urgent_notice
from continuum_github.state import parse_state
from continuum_github.state import replace_state

DAY1 = datetime(2026, 11, 1, tzinfo=UTC)

PENTEST_HIGH = Detection(
    source="pentest",
    target="weekly-grafana-example-com",
    repository="ansible-playbooks",
    key=pentest_key("weekly-grafana-example-com", "XSS", "n"),
    external_id="f1",
    name="n",
    severity=Severity.HIGH,
    urgent=True,
    confidence="HIGH",
    detected_at=DAY1,
    site="grafana.example.com",
    pentest_id="pt-1",
    details=(("Description", "d"),),
)

CODE_MEDIUM = Detection(
    source="code-vuln",
    target="actions",
    repository="actions",
    key=code_vuln_key("env-1", "issue-1"),
    external_id="cv1",
    name="m",
    severity=Severity.MEDIUM,
    urgent=False,
    confidence="MEDIUM",
    detected_at=DAY1,
    details=(("Description", "d"),),
)

CODE_REVIEW_HIGH = Detection(
    source="code-review",
    target="weekly-actions",
    repository="actions",
    key=code_review_key("weekly-actions", "XSS", "name", "src/a.py"),
    external_id="f1",
    name="name",
    severity=Severity.HIGH,
    urgent=False,
    confidence="HIGH",
    detected_at=DAY1,
    location="src/a.py:10-12",
)


def test_severity_label() -> None:
    assert severity_label(Severity.HIGH) == "severity:high"


def test_labels_for_an_urgent_pentest_finding() -> None:
    assert issue_labels(PENTEST_HIGH) == [
        "new",
        "severity:high",
        "pentest",
        "repo:ansible-playbooks",
        "site:grafana.example.com",
        "urgent",
    ]
    assert issue_labels(CODE_MEDIUM, status="pending") == [
        "pending",
        "severity:medium",
        "code-vuln",
        "repo:actions",
    ]


def test_site_label() -> None:
    assert site_label("nas.example.com") == "site:nas.example.com"


def test_pentest_without_a_site_gets_no_site_label() -> None:
    labels = issue_labels(replace(PENTEST_HIGH, site=None))
    assert not any(label.startswith("site:") for label in labels)


def test_title_is_truncated_to_256_characters() -> None:
    assert issue_title(PENTEST_HIGH) == "[HIGH] n"
    long = replace(PENTEST_HIGH, name="x" * 300)
    assert len(issue_title(long)) == 256


def test_body_orders_sections_and_ends_with_state() -> None:
    body = issue_body(
        PENTEST_HIGH, initial_state(PENTEST_HIGH), Sections("S", "W", "R"), "@octocat"
    )
    assert body.startswith("@octocat\n")
    assert (
        body.index("| Severity | HIGH |")
        < body.index("## Summary")
        < body.index("## Why it matters")
    )
    assert body.index("## Risk if left unresolved") < body.index(
        "<details><summary>Details from Continuum</summary>"
    )
    assert "| Site | grafana.example.com |" in body
    assert parse_state(body) == initial_state(PENTEST_HIGH)


def test_body_without_sections_has_no_section_headings() -> None:
    body = issue_body(CODE_MEDIUM, initial_state(CODE_MEDIUM), None, "@octocat")
    for heading in ("Summary", "Why it matters", "Risk if left unresolved"):
        assert f"## {heading}" not in body
    details = "<details><summary>Details from Continuum</summary>"
    assert body.index("| Severity |") < body.index(details)
    assert not body.startswith("@octocat")
    assert "| Site |" not in body
    assert FALLBACK_NOTE not in body


def test_body_with_fallback_ends_with_the_note_before_the_state() -> None:
    state = initial_state(CODE_MEDIUM)
    body = issue_body(CODE_MEDIUM, state, None, "", fallback=True)
    assert (
        body.index("</details>")
        < body.index(FALLBACK_NOTE)
        < body.index("<!-- continuum-state")
    )
    assert parse_state(body) == state


def test_body_escapes_table_cells() -> None:
    odd = replace(CODE_MEDIUM, repository="a|<b")
    body = issue_body(odd, initial_state(odd), None, "@octocat")
    assert "| Repository | a\\|&lt;b |" in body


def test_body_neutralizes_forged_markers_in_sections() -> None:
    forged = (
        "<!-- continuum-state: "
        + '{"source":"pentest","target":"x","keys":[],"finding_ids":[]}'
        + " -->"
    )
    body = issue_body(
        PENTEST_HIGH,
        initial_state(PENTEST_HIGH),
        Sections(forged, "<!--", "ok"),
        "@octocat",
    )
    assert body.count("<!-- continuum-state:") == 1
    assert parse_state(body) == initial_state(PENTEST_HIGH)


def test_body_stays_within_the_github_limit() -> None:
    huge = replace(PENTEST_HIGH, details=(("Description", "a" * 70000),))
    body = issue_body(huge, initial_state(huge), None, "@octocat")
    assert len(body) <= 65536
    assert "… (truncated)" in body
    assert parse_state(body) == initial_state(huge)


def test_fit_body_keeps_a_grown_state_within_the_limit() -> None:
    huge = replace(PENTEST_HIGH, details=(("Description", "a" * 70000),))
    body = issue_body(huge, initial_state(huge), None, "@octocat")
    grown = replace(
        initial_state(huge),
        keys=tuple(f"key-{n}" for n in range(200)),
        finding_ids=tuple(f"id-{n}" for n in range(200)),
        revalidation_job="rv-1",
    )
    fitted = fit_body(replace_state(body, grown))
    assert len(fitted) <= 65536
    assert parse_state(fitted) == grown
    assert "</details>" in fitted
    assert fitted.count("… (truncated)") == 1


def test_fit_body_leaves_a_short_body_unchanged() -> None:
    body = issue_body(PENTEST_HIGH, initial_state(PENTEST_HIGH), None, "@octocat")
    assert fit_body(body) == body


def test_fit_body_without_details_raises() -> None:
    with pytest.raises(ValueError):
        fit_body("a" * 70000)


def test_initial_state_records_keys_and_ids() -> None:
    state = initial_state(PENTEST_HIGH)
    assert (
        state.source,
        state.target,
        state.keys,
        state.finding_ids,
        state.pentest_id,
    ) == (
        "pentest",
        "weekly-grafana-example-com",
        (PENTEST_HIGH.key,),
        ("f1",),
        "pt-1",
    )
    assert (state.severity, state.urgent, state.misses) == ("HIGH", True, 0)


def test_extract_section() -> None:
    body = issue_body(
        CODE_MEDIUM, initial_state(CODE_MEDIUM), Sections("S1", "W1", "R1"), "@octocat"
    )
    assert extract_section(body, "Summary") == "S1"
    assert extract_section(body, "Risk if left unresolved") == "R1"
    assert extract_section(body, "Missing") is None


def test_initial_state_records_every_finding_id() -> None:
    detection = replace(PENTEST_HIGH, extra_finding_ids=("f0", "f1", "f2"))
    assert initial_state(detection).finding_ids == ("f1", "f0", "f2")


def test_replace_severity_rewrites_only_the_table_row() -> None:
    detection = replace(
        CODE_MEDIUM, details=(("Description", "| Severity | MEDIUM |"),)
    )
    body = issue_body(detection, initial_state(detection), None, "@octocat")
    rewritten = replace_severity(body, Severity.HIGH)
    assert rewritten.count("| Severity | HIGH |") == 1
    assert rewritten.count("| Severity | MEDIUM |") == 1
    assert rewritten.index("| Severity | HIGH |") < rewritten.index("<details>")
    assert replace_severity("no table", Severity.HIGH) == "no table"


def test_retitle_replaces_or_adds_the_severity_tag() -> None:
    assert retitle("[MEDIUM] XSS in q", Severity.HIGH) == "[HIGH] XSS in q"
    assert retitle("XSS in q", Severity.CRITICAL) == "[CRITICAL] XSS in q"
    assert len(retitle("[LOW] " + "a" * 300, Severity.HIGH)) == 256


def test_add_mention_adds_the_first_line_once() -> None:
    assert add_mention("| Field |", "@octocat") == "@octocat\n\n| Field |"
    assert add_mention("@octocat\n\n| Field |", "@octocat") == "@octocat\n\n| Field |"


def test_add_mention_is_idempotent_and_skips_an_empty_mention() -> None:
    assert add_mention("body", "@octocat") == "@octocat\n\nbody"
    assert add_mention("@octocat\n\nbody", "@octocat") == "@octocat\n\nbody"
    assert add_mention("body", "") == "body"


def test_urgent_notice_with_and_without_a_mention() -> None:
    assert urgent_notice("@octocat") == "@octocat This finding is now urgent."
    assert urgent_notice("") == "This finding is now urgent."


def test_urgent_body_without_a_mention_starts_with_the_table() -> None:
    assert PENTEST_HIGH.urgent
    body = issue_body(PENTEST_HIGH, initial_state(PENTEST_HIGH), None, "")
    assert body.startswith("| ")


def test_code_review_labels_and_table_show_the_location() -> None:
    assert issue_labels(CODE_REVIEW_HIGH) == [
        "new",
        "severity:high",
        "code-review",
        "repo:actions",
    ]
    body = issue_body(
        CODE_REVIEW_HIGH, initial_state(CODE_REVIEW_HIGH), None, "@octocat"
    )
    assert "| Type | code-review |" in body
    assert "| Location | src/a.py:10-12 |" in body
    assert "| Site |" not in body
