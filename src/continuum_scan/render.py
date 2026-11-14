"""Titles, labels, bodies, and comments of finding issues."""

import re
from dataclasses import dataclass

from continuum_scan.models import Detection
from continuum_scan.models import Severity
from continuum_scan.state import IssueState
from continuum_scan.state import render_state

STATUS_LABELS = frozenset({"new", "pending", "wip"})
URGENT = "urgent"
SOURCE_LABELS = frozenset({"code-review", "code-vuln", "pentest"})
SITE_PREFIX = "site:"

CLOSED_ABSENT = "Not found in two completed scans in a row. Closing as resolved."
CLOSED_WITHDRAWN = (
    "Continuum withdrew this finding or rated it below Medium. Closing as not planned."
)
REOPENED = (
    "Detected again by a scan that started after this issue was closed. Reopening."
)
REVALIDATED_FIXED = "Revalidated: not reproduced."
REVALIDATED_STILL = "Revalidated: still reproducible. Reopening."
REVALIDATION_FAILED = "Revalidation did not complete."

_MAX_BODY = 65536
_MAX_TITLE = 256
_PENDING = "_Pending summary._"
_TRUNCATED = "… (truncated)"
_DETAILS_OPEN = "<details><summary>Details from Continuum</summary>"
_DETAILS_CLOSE = "</details>"
_SECTION_HEADINGS = ("Summary", "Why it matters", "Risk if left unresolved")
_TITLE_TAG_RE = re.compile(r"\A\[[A-Z]+\] ")
_SEVERITY_ROW_RE = re.compile(r"^\| Severity \| [^|\n]* \|$", re.MULTILINE)


@dataclass(frozen=True)
class Sections:
    summary: str
    why: str
    risk: str


def severity_label(severity: Severity) -> str:
    """Returns the label for severity, such as "severity:high"."""
    return f"severity:{severity.lower()}"


def repo_label(repository: str) -> str:
    """Returns the label for a repository."""
    return f"repo:{repository}"


def site_label(domain: str) -> str:
    """Returns the label for a pentest site, such as "site:www.example.com"."""
    return f"{SITE_PREFIX}{domain}"


def issue_labels(detection: Detection, status: str = "new") -> list[str]:
    """Returns the labels of a finding issue.

    The order is status, severity, source, repo, then site for a pentest
    finding and urgent for an urgent one.
    """
    labels = [
        status,
        severity_label(detection.severity),
        detection.source,
        repo_label(detection.repository),
    ]
    if detection.site is not None:
        labels.append(site_label(detection.site))
    if detection.urgent:
        labels.append(URGENT)
    return labels


def issue_title(detection: Detection) -> str:
    """Returns the issue title, cut to GitHub's 256-character limit."""
    return f"[{detection.severity}] {detection.name}"[:_MAX_TITLE]


def strip_severity_tag(title: str) -> str:
    """Returns title without its leading severity tag, such as "[HIGH] "."""
    return _TITLE_TAG_RE.sub("", title, count=1)


def retitle(title: str, severity: Severity) -> str:
    """Returns title with its leading severity tag replaced by severity.

    Adds the tag when title has none, and cuts the result to GitHub's
    256-character limit.
    """
    name = strip_severity_tag(title)
    return f"[{severity}] {name}"[:_MAX_TITLE]


def replace_severity(body: str, severity: Severity) -> str:
    """Returns body with the value of its first Severity table row replaced.

    The metadata table precedes the sections and details, so the first row
    is the table's own. Returns body unchanged when it has no such row.
    """
    return _SEVERITY_ROW_RE.sub(f"| Severity | {severity} |", body, count=1)


def urgent_notice(mention: str) -> str:
    """Returns the comment announcing that a finding has become urgent."""
    return " ".join(filter(None, (mention, "This finding is now urgent.")))


def add_mention(body: str, mention: str) -> str:
    """Returns body with mention as its first line, once.

    An empty mention leaves body unchanged.
    """
    if not mention or body.startswith(f"{mention}\n"):
        return body
    return f"{mention}\n\n{body}"


def initial_state(detection: Detection) -> IssueState:
    """Returns the state of a newly filed issue for detection."""
    return IssueState(
        source=detection.source,
        target=detection.target,
        keys=(detection.key,),
        finding_ids=detection.finding_ids,
        pentest_id=detection.pentest_id,
        severity=str(detection.severity),
        urgent=detection.urgent,
    )


def _escape(text: str) -> str:
    """Neutralizes HTML so untrusted text cannot open comments or tags."""
    return text.replace("<", "&lt;")


def _cell(text: str) -> str:
    return _escape(" ".join(text.split())).replace("|", "\\|")


def _table(detection: Detection) -> str:
    rows = [("Severity", str(detection.severity)), ("Type", detection.source)]
    rows.append(("Repository", detection.repository))
    if detection.source == "code-review" and detection.location is not None:
        rows.append(("Location", detection.location))
    if detection.source == "pentest" and detection.site is not None:
        rows.append(("Site", detection.site))
    rows += [
        ("Confidence", detection.confidence),
        ("Detected", detection.detected_at.isoformat()),
        ("Continuum ID", detection.external_id),
    ]
    lines = ["| Field | Value |", "|---|---|"]
    lines += [f"| {name} | {_cell(value)} |" for name, value in rows]
    return "\n".join(lines)


def _sections(sections: Sections | None) -> str:
    texts = (
        (_PENDING,) * 3
        if sections is None
        else (sections.summary, sections.why, sections.risk)
    )
    parts = []
    for heading, text in zip(_SECTION_HEADINGS, texts, strict=True):
        body = text if sections is None else _escape(text.strip())
        parts.append(f"## {heading}\n\n{body}")
    return "\n\n".join(parts)


def issue_body(
    detection: Detection,
    state: IssueState,
    sections: Sections | None,
    mention: str,
) -> str:
    """Returns the issue body, within GitHub's 65,536-character limit.

    An urgent detection puts mention on the first line unless it is empty.
    The details text is cut from the end when the body would be too long,
    so the state marker at the end always survives.
    """
    head = []
    if detection.urgent and mention:
        head.append(mention)
    head += [_table(detection), _sections(sections), _DETAILS_OPEN]
    prefix = "\n\n".join(head) + "\n\n"
    inner = "\n\n".join(
        f"### {_escape(heading)}\n\n{_escape(text)}"
        for heading, text in detection.details
    )
    suffix = f"\n\n{_DETAILS_CLOSE}\n\n{render_state(state)}\n"
    if len(prefix) + len(inner) + len(suffix) > _MAX_BODY:
        room = max(0, _MAX_BODY - len(prefix) - len(suffix) - len(_TRUNCATED))
        inner = inner[:room] + _TRUNCATED
    return prefix + inner + suffix


def fit_body(body: str, limit: int = _MAX_BODY) -> str:
    """Returns body cut to limit characters by shortening the details text.

    The details text is cut from its end and marked as truncated once, so
    the closing tag and the state marker after it survive.

    Raises:
        ValueError: body is too long and has no details block that can
            absorb the excess.
    """
    if len(body) <= limit:
        return body
    start = body.find(_DETAILS_OPEN)
    end = -1 if start < 0 else body.find(_DETAILS_CLOSE, start)
    if end < 0:
        raise ValueError("body exceeds the limit and has no details block")
    start += len(_DETAILS_OPEN)
    separator = "\n\n"
    if body[start:end].endswith(separator):
        end -= len(separator)
    region = body[start:end]
    inner = region.removesuffix(_TRUNCATED)
    room = limit - (len(body) - len(region)) - len(_TRUNCATED)
    if room < 0:
        raise ValueError("body exceeds the limit even without details")
    return body[:start] + inner[:room] + _TRUNCATED + body[end:]


def extract_section(body: str, heading: str) -> str | None:
    """Returns the text under "## <heading>" up to the next heading or details block.

    Returns None when the heading is absent.
    """
    match = re.search(rf"^## {re.escape(heading)}[ \t]*$", body, re.MULTILINE)
    if match is None:
        return None
    rest = body[match.end() :]
    end = re.search(rf"^## |{re.escape(_DETAILS_OPEN)}", rest, re.MULTILINE)
    if end is not None:
        rest = rest[: end.start()]
    return rest.strip()
