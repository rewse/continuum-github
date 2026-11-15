"""Tests for the GitHub client."""

import json

import httpx
import pytest

from continuum_github.github import GitHub


def _client(handler) -> httpx.Client:
    return httpx.Client(
        base_url="https://api.github.com",
        transport=httpx.MockTransport(handler),
    )


def _github(handler) -> GitHub:
    return GitHub(_client(handler), "example-org/continuum", min_write_interval=0)


def _graphql(nodes) -> dict:
    return {"data": {"repository": {"issue": {"timelineItems": {"nodes": nodes}}}}}


def test_issues_skip_pull_requests_and_paginate() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("page") == "2":
            return httpx.Response(200, json=[{"number": 3}])
        assert request.url.path == "/repos/example-org/continuum/issues"
        assert request.url.params["state"] == "all"
        assert request.url.params["per_page"] == "100"
        return httpx.Response(
            200,
            json=[{"number": 1}, {"number": 2, "pull_request": {}}],
            headers={
                "Link": '<https://api.github.com/repos/example-org/continuum/issues?page=2>; rel="next"'
            },
        )

    assert [i["number"] for i in _github(handler).issues()] == [1, 3]


def test_create_issue_returns_number_and_url() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/repos/example-org/continuum/issues"
        return httpx.Response(
            201, json={"number": 7, "html_url": "u", "labels": [{"name": "new"}]}
        )

    assert _github(handler).create_issue("t", "b", ["new"]) == (7, "u")


def test_create_issue_returns_number_and_checks_labels() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert json.loads(request.content) == {
            "title": "t",
            "body": "b",
            "labels": ["new", "pentest"],
        }
        return httpx.Response(
            201, json={"number": 7, "html_url": "u", "labels": [{"name": "new"}]}
        )

    with pytest.raises(RuntimeError, match="label not applied: pentest"):
        _github(handler).create_issue("t", "b", ["new", "pentest"])


def test_update_issue_sends_only_given_fields() -> None:
    sent = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append((request.method, request.url.path, json.loads(request.content)))
        return httpx.Response(200, json={})

    gh = _github(handler)
    gh.update_issue(7, labels=["pending"], state="closed", state_reason="completed")
    gh.update_issue(8, body="b")
    assert sent == [
        (
            "PATCH",
            "/repos/example-org/continuum/issues/7",
            {"labels": ["pending"], "state": "closed", "state_reason": "completed"},
        ),
        ("PATCH", "/repos/example-org/continuum/issues/8", {"body": "b"}),
    ]


def test_update_issue_sends_labels_as_list() -> None:
    sent = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={})

    _github(handler).update_issue(7, labels=("a", "b"))
    assert sent == [{"labels": ["a", "b"]}]


def test_comment_posts_body() -> None:
    sent = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append((request.method, request.url.path, json.loads(request.content)))
        return httpx.Response(201, json={})

    _github(handler).comment(7, "hello")
    assert sent == [
        ("POST", "/repos/example-org/continuum/issues/7/comments", {"body": "hello"})
    ]


def test_duplicate_canonical_reads_graphql() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/graphql"
        query = json.loads(request.content)
        assert "MARKED_AS_DUPLICATE_EVENT" in query["query"]
        assert query["variables"] == {
            "owner": "example-org",
            "name": "continuum",
            "number": 9,
        }
        return httpx.Response(
            200,
            json=_graphql(
                [
                    {
                        "canonical": {
                            "number": 4,
                            "repository": {"nameWithOwner": "example-org/continuum"},
                        }
                    }
                ]
            ),
        )

    assert _github(handler).duplicate_canonical(9) == 4


def test_duplicate_canonical_matches_repository_case_insensitively() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_graphql(
                [
                    {
                        "canonical": {
                            "number": 4,
                            "repository": {"nameWithOwner": "Example-Org/Continuum"},
                        }
                    }
                ]
            ),
        )

    assert _github(handler).duplicate_canonical(9) == 4


def test_duplicate_canonical_ignores_other_repositories() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_graphql(
                [
                    {
                        "canonical": {
                            "number": 4,
                            "repository": {"nameWithOwner": "other/repo"},
                        }
                    }
                ]
            ),
        )

    assert _github(handler).duplicate_canonical(9) is None


@pytest.mark.parametrize(
    "payload",
    [
        _graphql([]),
        _graphql([{"canonical": None}]),
        # A pull request canonical matches no `... on Issue` fragment.
        _graphql([{"canonical": {}}]),
        {"data": {"repository": {"issue": None}}},
        {"data": None, "errors": [{"message": "boom"}]},
        {"errors": [{"message": "boom"}]},
    ],
)
def test_duplicate_canonical_returns_none_without_issue_canonical(payload) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    assert _github(handler).duplicate_canonical(9) is None


def test_ensure_labels_creates_only_missing() -> None:
    created = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            assert request.url.path == "/repos/example-org/continuum/labels"
            return httpx.Response(200, json=[{"name": "new"}])
        assert request.url.path == "/repos/example-org/continuum/labels"
        created.append(json.loads(request.content))
        return httpx.Response(201, json={})

    labels = {"new": ("1D76DB", "New finding"), "wip": ("FBCA04", "Being fixed")}
    assert _github(handler).ensure_labels(labels) == 1
    assert created == [{"name": "wip", "color": "FBCA04", "description": "Being fixed"}]


def test_ensure_labels_paginates_existing_labels() -> None:
    created = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            if request.url.params.get("page") == "2":
                return httpx.Response(200, json=[{"name": "wip"}])
            return httpx.Response(
                200,
                json=[{"name": "new"}],
                headers={
                    "Link": '<https://api.github.com/repos/example-org/continuum/labels?page=2>; rel="next"'
                },
            )
        created.append(json.loads(request.content))
        return httpx.Response(201, json={})

    labels = {"new": ("1D76DB", "New finding"), "wip": ("FBCA04", "Being fixed")}
    assert _github(handler).ensure_labels(labels) == 0
    assert created == []


def test_errors_raise_http_status_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={})

    gh = _github(handler)
    with pytest.raises(httpx.HTTPStatusError):
        gh.issues()
    with pytest.raises(httpx.HTTPStatusError):
        gh.update_issue(1, state="open")
    with pytest.raises(httpx.HTTPStatusError):
        gh.comment(1, "b")
    with pytest.raises(httpx.HTTPStatusError):
        gh.duplicate_canonical(1)


class _FakeTime:
    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _paced_github(handler, fake: _FakeTime) -> GitHub:
    return GitHub(
        _client(handler), "example-org/continuum", sleep=fake.sleep, clock=fake.clock
    )


def _ok_handler(request: httpx.Request) -> httpx.Response:
    if request.method == "GET":
        return httpx.Response(200, json=[])
    return httpx.Response(201, json={"number": 1, "html_url": "https://github.com/x"})


def test_consecutive_posts_are_paced() -> None:
    fake = _FakeTime()
    gh = _paced_github(_ok_handler, fake)
    gh.comment(1, "a")
    fake.now += 0.25
    gh.comment(1, "b")
    assert fake.sleeps == [pytest.approx(0.75)]


def test_get_requests_are_not_paced() -> None:
    fake = _FakeTime()
    gh = _paced_github(_ok_handler, fake)
    gh.comment(1, "a")
    gh.issues()
    gh.issues()
    assert fake.sleeps == []


def test_secondary_limit_with_retry_after_is_retried() -> None:
    fake = _FakeTime()
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(403, headers={"Retry-After": "30"}, json={})
        return httpx.Response(
            201, json={"number": 5, "html_url": "https://github.com/x", "labels": []}
        )

    gh = _paced_github(handler, fake)
    assert gh.create_issue("t", "b", []) == (5, "https://github.com/x")
    assert fake.sleeps == [30.0]
    assert len(calls) == 2


def test_429_waits_until_ratelimit_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeTime()
    monkeypatch.setattr("continuum_github.github.time.time", lambda: 5000.0)
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(429, headers={"X-RateLimit-Reset": "5042"})
        return httpx.Response(200, json=[])

    gh = _paced_github(handler, fake)
    assert gh.issues() == []
    assert fake.sleeps == [42.0]


def test_rate_limit_message_defaults_to_60_seconds() -> None:
    fake = _FakeTime()
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(
                403, json={"message": "You have exceeded a Rate Limit"}
            )
        return httpx.Response(200, json=[])

    gh = _paced_github(handler, fake)
    gh.issues()
    assert fake.sleeps == [60.0]


def test_wait_is_capped_at_15_minutes() -> None:
    fake = _FakeTime()
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "99999"})
        return httpx.Response(200, json=[])

    _paced_github(handler, fake).issues()
    assert fake.sleeps == [900.0]


def test_retry_after_as_an_http_date_waits_until_that_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeTime()
    # 30 seconds before the Retry-After date below.
    monkeypatch.setattr("continuum_github.github.time.time", lambda: 784111747.0)
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(
                429, headers={"Retry-After": "Sun, 06 Nov 1994 08:49:37 GMT"}
            )
        return httpx.Response(200, json=[])

    _paced_github(handler, fake).issues()
    assert fake.sleeps == [30.0]


def test_an_unreadable_retry_after_falls_back_to_the_reset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeTime()
    monkeypatch.setattr("continuum_github.github.time.time", lambda: 5000.0)
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) == 1:
            headers = {"Retry-After": "soon", "X-RateLimit-Reset": "5042"}
            return httpx.Response(429, headers=headers)
        return httpx.Response(200, json=[])

    _paced_github(handler, fake).issues()
    assert fake.sleeps == [42.0]


def test_a_past_reset_still_waits_one_second(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeTime()
    monkeypatch.setattr("continuum_github.github.time.time", lambda: 5000.0)
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(429, headers={"X-RateLimit-Reset": "10"})
        return httpx.Response(200, json=[])

    _paced_github(handler, fake).issues()
    assert fake.sleeps == [1.0]


def test_plain_403_raises_immediately() -> None:
    fake = _FakeTime()
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(403, json={"message": "Resource not accessible"})

    gh = _paced_github(handler, fake)
    with pytest.raises(httpx.HTTPStatusError):
        gh.comment(1, "b")
    assert len(calls) == 1
    assert fake.sleeps == []


def test_gives_up_after_three_retries() -> None:
    fake = _FakeTime()
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(429, headers={"Retry-After": "1"})

    gh = _paced_github(handler, fake)
    with pytest.raises(httpx.HTTPStatusError):
        gh.issues()
    assert len(calls) == 4
    assert fake.sleeps == [1.0, 1.0, 1.0]
