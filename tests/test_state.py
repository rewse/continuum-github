"""Tests for the hidden issue state marker."""

from dataclasses import replace

from continuum_scan.state import IssueState
from continuum_scan.state import parse_state
from continuum_scan.state import render_state
from continuum_scan.state import replace_state

STATE = IssueState(
    source="pentest",
    target="weekly-x",
    keys=("0123456789abcdef",),
    finding_ids=("f-1",),
    pentest_id="pt-1",
    misses=1,
)


def test_state_round_trips() -> None:
    body = "text\n\n" + render_state(STATE) + "\n"
    assert parse_state(body) == STATE


def test_full_state_round_trips() -> None:
    state = replace(
        STATE,
        severity="HIGH",
        urgent=True,
        checked_scan="scan-1",
        auto_closed="withdrawn",
        revalidation_job="job-1",
        revalidation_done=True,
        merged_into=12,
        sections=True,
        keep_open=True,
    )
    assert parse_state(render_state(state)) == state


def test_last_marker_wins_and_bad_json_is_ignored() -> None:
    older = replace(STATE, misses=0)
    body = render_state(older) + "\n" + render_state(STATE)
    assert parse_state(body) == STATE
    assert parse_state("<!-- continuum-state: {not json} -->") is None
    assert parse_state('<!-- continuum-state: {"source":"x"} -->') is None
    assert parse_state(None) is None


def test_mistyped_fields_are_rejected() -> None:
    good = '"source":"pentest","target":"t","keys":["k"],"finding_ids":["f"]'
    assert parse_state("<!-- continuum-state: {" + good + "} -->") is not None
    assert parse_state("<!-- continuum-state: {" + good + ',"extra":1} -->') is not None
    for bad in (
        '"source":"other","target":"t","keys":["k"],"finding_ids":["f"]',
        '"source":"pentest","target":1,"keys":["k"],"finding_ids":["f"]',
        '"source":"pentest","target":"t","keys":"k","finding_ids":["f"]',
        '"source":"pentest","target":"t","keys":[1],"finding_ids":["f"]',
        '"source":"pentest","target":"t","keys":["k"]',
        good + ',"misses":"1"',
        good + ',"misses":true',
        good + ',"urgent":1',
        good + ',"auto_closed":"gone"',
        good + ',"merged_into":"3"',
        good + ',"pentest_id":3',
        good + ',"keep_open":1',
    ):
        assert parse_state("<!-- continuum-state: {" + bad + "} -->") is None, bad
    assert parse_state("<!-- continuum-state: [] -->") is None


def test_rendered_state_has_no_angle_brackets_inside() -> None:
    marker = render_state(replace(STATE, target="a<b>c"))
    inner = marker.removeprefix("<!-- continuum-state: ").removesuffix(" -->")
    assert "<" not in inner and ">" not in inner
    parsed = parse_state(marker)
    assert parsed is not None
    assert parsed.target == "a<b>c"


def test_replace_state_swaps_the_last_marker_only() -> None:
    body = "a\n" + render_state(replace(STATE, misses=0)) + "\n"
    updated = replace_state(body, STATE)
    assert updated.startswith("a\n")
    assert updated.count("continuum-state") == 1
    assert parse_state(updated) == STATE
    assert parse_state(replace_state("no marker", STATE)) == STATE


def test_replace_state_keeps_earlier_markers() -> None:
    body = render_state(replace(STATE, misses=0)) + "\nmid\n"
    body += render_state(replace(STATE, misses=2))
    updated = replace_state(body, STATE)
    assert updated.count("continuum-state") == 2
    assert "\nmid\n" in updated
    assert parse_state(updated) == STATE


def test_code_review_state_round_trips() -> None:
    state = IssueState(
        source="code-review",
        target="weekly-actions",
        keys=("cr:1",),
        finding_ids=("f1",),
    )
    assert parse_state(render_state(state)) == state
