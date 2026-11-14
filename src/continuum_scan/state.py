"""Issue state kept in a hidden HTML comment in the issue body."""

import dataclasses
import json
import re
from dataclasses import dataclass
from typing import Any, Literal

from continuum_scan.models import Source

_PREFIX = "<!-- continuum-state: "
_SUFFIX = " -->"
_MARKER_RE = re.compile(r"<!-- continuum-state: (.*?) -->", re.DOTALL)
_SOURCES = ("pentest", "code-vuln", "code-review")
_AUTO_CLOSED = ("absent", "withdrawn")


@dataclass(frozen=True)
class IssueState:
    source: Source
    target: str
    keys: tuple[str, ...]
    finding_ids: tuple[str, ...]
    pentest_id: str | None = None
    severity: str = "MEDIUM"
    urgent: bool = False
    misses: int = 0
    checked_scan: str | None = None
    auto_closed: Literal["absent", "withdrawn"] | None = None
    revalidation_job: str | None = None
    revalidation_done: bool = False
    merged_into: int | None = None
    sections: bool = False
    keep_open: bool = False


def render_state(state: IssueState) -> str:
    """Returns the hidden marker that records state.

    Angle brackets are escaped so the JSON cannot end the HTML comment.
    """
    data = dataclasses.asdict(state)
    text = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    text = text.replace("<", "\\u003c").replace(">", "\\u003e")
    return f"{_PREFIX}{text}{_SUFFIX}"


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_str_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _optional_str(value: Any) -> bool:
    return value is None or isinstance(value, str)


def _optional_int(value: Any) -> bool:
    return value is None or _is_int(value)


_OPTIONAL_CHECKS = {
    "auto_closed": lambda value: value is None or value in _AUTO_CLOSED,
    "checked_scan": _optional_str,
    "keep_open": lambda value: isinstance(value, bool),
    "merged_into": _optional_int,
    "misses": _is_int,
    "pentest_id": _optional_str,
    "revalidation_done": lambda value: isinstance(value, bool),
    "revalidation_job": _optional_str,
    "sections": lambda value: isinstance(value, bool),
    "severity": lambda value: isinstance(value, str),
    "urgent": lambda value: isinstance(value, bool),
}


def _from_json(data: Any) -> IssueState | None:
    if not isinstance(data, dict):
        return None
    if data.get("source") not in _SOURCES:
        return None
    if not isinstance(data.get("target"), str):
        return None
    if not _is_str_list(data.get("keys")):
        return None
    if not _is_str_list(data.get("finding_ids")):
        return None
    optional = {}
    for name, check in _OPTIONAL_CHECKS.items():
        if name in data:
            if not check(data[name]):
                return None
            optional[name] = data[name]
    return IssueState(
        source=data["source"],
        target=data["target"],
        keys=tuple(data["keys"]),
        finding_ids=tuple(data["finding_ids"]),
        **optional,
    )


def parse_state(body: str | None) -> IssueState | None:
    """Returns the state in the last marker of body.

    Returns None when there is no marker or its JSON or field types are
    invalid. Unknown keys are ignored.
    """
    if not body:
        return None
    matches = _MARKER_RE.findall(body)
    if not matches:
        return None
    try:
        data = json.loads(matches[-1])
    except ValueError:
        return None
    return _from_json(data)


def replace_state(body: str, state: IssueState) -> str:
    """Returns body with its last marker replaced by state.

    Appends the marker when body has none.
    """
    marker = render_state(state)
    matches = list(_MARKER_RE.finditer(body))
    if not matches:
        separator = "" if not body or body.endswith("\n") else "\n\n"
        return f"{body}{separator}{marker}\n"
    last = matches[-1]
    return body[: last.start()] + marker + body[last.end() :]
