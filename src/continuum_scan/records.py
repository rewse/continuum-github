"""Issue records read back from GitHub."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from continuum_scan.state import IssueState
from continuum_scan.state import parse_state

BOT = "github-actions[bot]"


@dataclass(frozen=True)
class Record:
    number: int
    url: str
    title: str
    body: str
    open: bool
    state_reason: str | None
    labels: frozenset[str]
    created_at: datetime
    closed_at: datetime | None
    state: IssueState


def _parse_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value)


def records_from_issues(items: Iterable[Mapping[str, Any]]) -> list[Record]:
    """Returns records for the issues this workflow filed.

    Pull requests, issues by any other author, and issues without a valid
    state marker are skipped, so nobody else can inject state.
    """
    records = []
    for item in items:
        if "pull_request" in item:
            continue
        if (item.get("user") or {}).get("login") != BOT:
            continue
        body = item.get("body") or ""
        state = parse_state(body)
        if state is None:
            continue
        created_at = _parse_time(item["created_at"])
        assert created_at is not None
        records.append(
            Record(
                number=item["number"],
                url=item["html_url"],
                title=item["title"],
                body=body,
                open=item["state"] == "open",
                state_reason=item.get("state_reason"),
                labels=frozenset(label["name"] for label in item.get("labels", ())),
                created_at=created_at,
                closed_at=_parse_time(item.get("closed_at")),
                state=state,
            )
        )
    return records
