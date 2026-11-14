"""Minimal GitHub client for the finding issues of one repository."""

import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Any, Literal

import httpx

_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}
_MUTATING_METHODS = frozenset({"PATCH", "POST"})
_DEFAULT_WAIT = 60.0
_MAX_WAIT = 15 * 60.0
_MAX_RETRIES = 3
_DUPLICATE_QUERY = """
query($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    issue(number: $number) {
      timelineItems(itemTypes: [MARKED_AS_DUPLICATE_EVENT], last: 1) {
        nodes {
          ... on MarkedAsDuplicateEvent {
            canonical {
              ... on Issue {
                number
                repository { nameWithOwner }
              }
            }
          }
        }
      }
    }
  }
}
"""


def _is_rate_limited(response: httpx.Response) -> bool:
    if response.status_code == 429:
        return True
    if response.status_code != 403:
        return False
    if "Retry-After" in response.headers:
        return True
    if response.headers.get("X-RateLimit-Remaining") == "0":
        return True
    try:
        message = response.json().get("message", "")
    except (ValueError, AttributeError):
        return False
    return isinstance(message, str) and "rate limit" in message.lower()


def _retry_delay(response: httpx.Response, clock: Callable[[], float]) -> float:
    """Returns seconds to wait: Retry-After, else rate-limit reset, else 60."""
    delay = _DEFAULT_WAIT
    retry_after = response.headers.get("Retry-After")
    reset = response.headers.get("X-RateLimit-Reset")
    try:
        if retry_after is not None:
            delay = float(retry_after)
        elif reset is not None:
            delay = float(reset) - time.time()
    except ValueError:
        delay = _DEFAULT_WAIT
    return min(max(delay, 0.0), _MAX_WAIT)


class GitHub:
    """Client scoped to one repository. Errors surface as httpx.HTTPStatusError."""

    def __init__(
        self,
        client: httpx.Client,
        repository: str,
        min_write_interval: float = 1.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = client
        self._repository = repository
        self._owner, self._name = repository.split("/", 1)
        self._base = f"/repos/{self._owner}/{self._name}"
        self._min_write_interval = min_write_interval
        self._sleep = sleep
        self._clock = clock
        self._last_write: float | None = None

    def issues(self) -> list[dict[str, Any]]:
        """Returns every issue in any state, excluding pull requests."""
        return [
            item
            for item in self._paginate(f"{self._base}/issues", {"state": "all"})
            if "pull_request" not in item
        ]

    def create_issue(
        self, title: str, body: str, labels: Sequence[str]
    ) -> tuple[int, str]:
        """Creates an issue and returns its number and URL."""
        response = self._request(
            "POST",
            f"{self._base}/issues",
            json={"title": title, "body": body, "labels": list(labels)},
        )
        response.raise_for_status()
        issue = response.json()
        # GitHub silently drops a label the token may not create, and the
        # lifecycle depends on the labels being present.
        applied = {label["name"] for label in issue.get("labels") or ()}
        for label in labels:
            if label not in applied:
                raise RuntimeError(f"label not applied: {label}")
        return issue["number"], issue["html_url"]

    def update_issue(
        self,
        number: int,
        *,
        body: str | None = None,
        labels: Sequence[str] | None = None,
        state: Literal["open", "closed"] | None = None,
        state_reason: Literal["completed", "not_planned", "reopened"] | None = None,
        title: str | None = None,
    ) -> None:
        """Updates the given fields of an issue; None fields are left as is."""
        fields: dict[str, Any] = {}
        if title is not None:
            fields["title"] = title
        if body is not None:
            fields["body"] = body
        if labels is not None:
            fields["labels"] = list(labels)
        if state is not None:
            fields["state"] = state
        if state_reason is not None:
            fields["state_reason"] = state_reason
        response = self._request("PATCH", f"{self._base}/issues/{number}", json=fields)
        response.raise_for_status()

    def comment(self, number: int, body: str) -> None:
        response = self._request(
            "POST", f"{self._base}/issues/{number}/comments", json={"body": body}
        )
        response.raise_for_status()

    def duplicate_canonical(self, number: int) -> int | None:
        """Returns the issue this one was last marked a duplicate of.

        Returns None unless the canonical is an issue in this repository.
        """
        response = self._request(
            "POST",
            "/graphql",
            json={
                "query": _DUPLICATE_QUERY,
                "variables": {
                    "owner": self._owner,
                    "name": self._name,
                    "number": number,
                },
            },
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("errors"):
            return None
        issue = ((payload.get("data") or {}).get("repository") or {}).get("issue")
        nodes = ((issue or {}).get("timelineItems") or {}).get("nodes") or []
        if not nodes:
            return None
        canonical = (nodes[-1] or {}).get("canonical") or {}
        repository = (canonical.get("repository") or {}).get("nameWithOwner")
        if not isinstance(repository, str):
            return None
        if repository.lower() != self._repository.lower():
            return None
        canonical_number = canonical.get("number")
        return canonical_number if isinstance(canonical_number, int) else None

    def ensure_labels(self, labels: Mapping[str, tuple[str, str]]) -> int:
        """Creates the labels that do not exist and returns how many it made.

        `labels` maps each name to its color and description.
        """
        existing = {
            item.get("name") for item in self._paginate(f"{self._base}/labels", {})
        }
        created = 0
        for name, (color, description) in labels.items():
            if name in existing:
                continue
            response = self._request(
                "POST",
                f"{self._base}/labels",
                json={"name": name, "color": color, "description": description},
            )
            response.raise_for_status()
            created += 1
        return created

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Sends a request, pacing writes and retrying rate-limited responses.

        Request and response bodies are never logged because they contain
        vulnerability details.
        """
        mutating = method in _MUTATING_METHODS
        for attempt in range(_MAX_RETRIES + 1):
            if mutating:
                self._pace_write()
            response = self._client.request(method, url, headers=_HEADERS, **kwargs)
            if mutating:
                self._last_write = self._clock()
            if attempt == _MAX_RETRIES or not _is_rate_limited(response):
                return response
            self._sleep(_retry_delay(response, self._clock))
        raise AssertionError("unreachable")

    def _pace_write(self) -> None:
        if self._last_write is None:
            return
        remaining = self._min_write_interval - (self._clock() - self._last_write)
        if remaining > 0:
            self._sleep(remaining)

    def _paginate(self, path: str, params: dict[str, str]) -> Iterator[dict[str, Any]]:
        response = self._request("GET", path, params={**params, "per_page": "100"})
        while True:
            response.raise_for_status()
            yield from response.json()
            next_url = response.links.get("next", {}).get("url")
            if not next_url:
                return
            response = self._request("GET", next_url)
