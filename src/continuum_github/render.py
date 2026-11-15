"""Titles, labels, bodies, and comments of finding issues."""

import re
from dataclasses import dataclass

from continuum_github.models import Detection
from continuum_github.models import Severity
from continuum_github.state import IssueState
from continuum_github.state import render_state

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
FALLBACK_NOTE = (
    "_Bedrock could not write the Summary, Why it matters, and Risk if left "
    "unresolved sections, so this issue shows the scanner's details only. "
    "Each later sync tries again, and this note stays until one succeeds._"
)

_MAX_BODY = 65536
_MAX_TITLE = 256
_TRUNCATED = "… (truncated)"
_DETAILS_OPEN = "<details><summary>Details from Continuum</summary>"
_DETAILS_CLOSE = "</details>"
_SECTION_HEADINGS = ("Summary", "Why it matters", "Risk if left unresolved")
_TITLE_TAG_RE = re.compile(r"\A\[[A-Z]+\] ")
_SEVERITY_ROW_RE = re.compile(r"^\| Severity \| [^|\n]* \|$", re.MULTILINE)
_FENCE_RE = re.compile(r"(`{3,}|~{3,})(.*)")
# Splits after \r\n, \r, or \n only; str.splitlines also splits on
# separators such as \x1c and \u2028 that CommonMark keeps inside a line.
_LINE_RE = re.compile(r"(?<=\n)|(?<=\r)(?!\n)")
_TICKS_RE = re.compile(r"`+")
_MENTION_RE = re.compile(r"(?<![A-Za-z0-9])@(?=[A-Za-z0-9])")


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


def _inert(text: str) -> str:
    # GitHub decodes character references such as &#64; before it looks for
    # mentions, so & is escaped first.
    text = text.replace("&", "&amp;")
    return _MENTION_RE.sub("@&#8203;", text).replace("![", "!\\[")


def _spans(text: str) -> str:
    # A run of backticks opens a code span only when the same run closes it.
    out, start, pos = [], 0, 0
    while (run := _TICKS_RE.search(text, pos)) is not None:
        close = next(
            (
                c
                for c in _TICKS_RE.finditer(text, run.end())
                if c.group() == run.group()
            ),
            None,
        )
        if close is None:
            pos = run.end()
            continue
        out += [_inert(text[start : run.start()]), text[run.start() : close.end()]]
        start = pos = close.end()
    out.append(_inert(text[start:]))
    return "".join(out)


def _lines(text: str) -> list[str]:
    return [line for line in _LINE_RE.split(text) if line]


def _self_paired(line: str) -> bool:
    """Returns whether every backtick run in line pairs within line.

    A run right after a backslash also counts as unpaired, since CommonMark
    makes an escaped backtick outside code a plain character.
    """
    pos = 0
    while (run := _TICKS_RE.search(line, pos)) is not None:
        if run.start() > 0 and line[run.start() - 1] == "\\":
            return False
        close = next(
            (
                c
                for c in _TICKS_RE.finditer(line, run.end())
                if c.group() == run.group()
            ),
            None,
        )
        if close is None:
            return False
        pos = close.end()
    return True


def _paragraph(lines: list[str]) -> str:
    # CommonMark pairs backtick runs across the lines of a paragraph. When
    # every run pairs within its own line, it makes the same pairs, so code
    # spans stay on one line; otherwise the whole paragraph is prose.
    if all(_self_paired(line) for line in lines):
        return "".join(_spans(line) for line in lines)
    return _inert("".join(lines))


def _by_paragraph(text: str) -> str:
    out: list[str] = []
    paragraph: list[str] = []
    for line in _lines(text):
        if line.strip():
            paragraph.append(line)
            continue
        out += [_paragraph(paragraph), line]
        paragraph = []
    out.append(_paragraph(paragraph))
    return "".join(out)


def escape_text(text: str, *, inline: bool = False) -> str:
    """Neutralizes untrusted text for an issue body.

    Outside code, `&` is escaped so character references such as `&#64;`
    stay literal, mentions become inert with a zero-width space, and images
    become plain text, so the text cannot notify users or load remote
    images. Everywhere, including code, `<` is escaped so the text cannot
    open comments or tags.

    Code is recognized more narrowly than CommonMark does: a code span is
    kept only on one line, in a paragraph whose every backtick run pairs
    within its own line; a fence opens only at the start of a line; and only
    \\r\\n, \\r, and \\n end a line. Text that GitHub renders as code but this
    misses only shows the inserted characters, while the reverse would
    leave a mention live. inline is for table cells and one-line items,
    where fences do not exist; the whole text is one paragraph.
    """
    if inline:
        return _paragraph(_lines(text)).replace("<", "&lt;")
    out, prose, fence = [], [], None
    for line in _lines(text):
        body = line.rstrip("\r\n")
        if fence is None:
            match = _FENCE_RE.fullmatch(body)
            if match is None or (match[1][0] == "`" and "`" in match[2]):
                prose.append(line)
                continue
            out.append(_by_paragraph("".join(prose)))
            prose, fence = [], match[1]
        elif re.fullmatch(
            rf" {{0,3}}{re.escape(fence[0])}{{{len(fence)},}}[ \t]*", body
        ):
            fence = None
        out.append(line)
    out.append(_by_paragraph("".join(prose)))
    return "".join(out).replace("<", "&lt;")


def _cell(text: str) -> str:
    return escape_text(" ".join(text.split()), inline=True).replace("|", "\\|")


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


def _sections(sections: Sections) -> str:
    texts = (sections.summary, sections.why, sections.risk)
    return "\n\n".join(
        f"## {heading}\n\n{escape_text(text.strip())}"
        for heading, text in zip(_SECTION_HEADINGS, texts, strict=True)
    )


def issue_body(
    detection: Detection,
    state: IssueState,
    sections: Sections | None,
    mention: str,
    fallback: bool = False,
) -> str:
    """Returns the issue body, within GitHub's 65,536-character limit.

    Without sections the body has no section headings. fallback puts
    FALLBACK_NOTE after the details to say the model could not write them.
    An urgent detection puts mention on the first line unless it is empty.
    The details text is cut from the end when the body would be too long,
    so the state marker at the end always survives.
    """
    head = []
    if detection.urgent and mention:
        head.append(mention)
    head.append(_table(detection))
    if sections is not None:
        head.append(_sections(sections))
    head.append(_DETAILS_OPEN)
    prefix = "\n\n".join(head) + "\n\n"
    inner = "\n\n".join(
        f"### {escape_text(heading, inline=True)}\n\n{escape_text(text)}"
        for heading, text in detection.details
    )
    note = f"{FALLBACK_NOTE}\n\n" if fallback else ""
    suffix = f"\n\n{_DETAILS_CLOSE}\n\n{note}{render_state(state)}\n"
    if len(prefix) + len(inner) + len(suffix) > _MAX_BODY:
        room = max(0, _MAX_BODY - len(prefix) - len(suffix) - len(_TRUNCATED))
        inner = _cut_at_line(inner, room) + _TRUNCATED
    return prefix + inner + suffix


def _cut_at_line(text: str, room: int) -> str:
    """Returns text[:room] cut back to its last line break, or "" without one.

    Escaped text keeps code spans on one line, so cutting at a line break
    never drops the closing backticks of a span whose mentions were left
    as they are.
    """
    cut = text[:room]
    end = max(cut.rfind("\n"), cut.rfind("\r"))
    return cut[: end + 1]


def fit_body(body: str, limit: int = _MAX_BODY) -> str:
    """Returns body cut to limit characters by shortening the details text.

    The details text is cut back to a line break before its end and marked
    as truncated once, so no code span loses its closing backticks and the
    closing tag and the state marker after it survive.

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
    return body[:start] + _cut_at_line(inner, room) + _TRUNCATED + body[end:]


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
