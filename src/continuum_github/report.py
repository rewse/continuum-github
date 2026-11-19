"""Counts, body, and posting of the English weekly report."""

import base64
import hashlib
import re
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from datetime import timedelta
from html.parser import HTMLParser
from pathlib import Path

from continuum_github.bedrock import ModelLike
from continuum_github.bedrock import visual_report_source
from continuum_github.config import DEFAULT_LANGUAGE
from continuum_github.config import DEFAULT_PENTEST_MAX_AGE
from continuum_github.models import Severity
from continuum_github.models import TargetScan
from continuum_github.records import BOT
from continuum_github.records import Record
from continuum_github.render import SOURCE_LABELS
from continuum_github.render import escape_text
from continuum_github.render import extract_section
from continuum_github.render import safe_reason
from continuum_github.render import strip_severity_tag
from continuum_github.sync import GitHubLike

HTML_URL_PLACEHOLDER = "{{CONTINUUM_HTML_URL}}"
WEEKLY_LABEL = "weekly-report"
MAX_BODY = 65000

CONTINUED = "Continued in the comments below."
HTML_PART = "Visual report"
_HTML_LINE = f"\n\n{HTML_PART}: {HTML_URL_PLACEHOLDER}"

_REPORTED = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
_STATUS_ORDER = ("wip", "pending", "new")
_INCOMPLETE_STATUSES = frozenset({"FAILED", "MISSING", "STOPPED"})
_WEEK = timedelta(days=7)
_STALE = timedelta(days=8)
_SEVERITY_PREFIX = "severity:"
_REPO_PREFIX = "repo:"
_DETAILS_CLOSE = "</details>"
_OPEN_LABEL = "Open findings"
_CLOSED_LABEL = "Closed this week"
_LINK_RE = re.compile(r"<link\b[^>]*>", re.IGNORECASE)
_HTML_TAG_RE = re.compile(r"<(?P<name>html)\b(?P<attributes>[^>]*)>", re.IGNORECASE)
_LANG_ATTR_RE = re.compile(
    r"""\s+lang\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)""", re.IGNORECASE
)
_EXTERNAL_FONT_HOSTS = ("fonts.googleapis.com", "fonts.gstatic.com")
_UNSTYLED_SVG_TEXT_RULE = (
    "<style>:where(svg text:not([class]):not([fill])) { fill: var(--text); }</style>"
)
# The script lists that kit/render.mjs joins into its <script data-ve-kit>:
# every kit page gets reply.js and kit.js, and a page with <ve-ask> also
# ask.js between them.
_KIT_SCRIPT_FILES = (("reply.js", "kit.js"), ("reply.js", "ask.js", "kit.js"))
_KIT_SCRIPT_OPEN = "<script data-ve-kit>"
_SCRIPT_END_RE = re.compile(r"</script", re.IGNORECASE)
_NO_KIT_ERRORS = (
    "The rendered page has no kit; add "
    '<link rel="stylesheet" href="kit.css" data-ve-kit> to <head>.'
)
# Model-written <meta http-equiv> values the page must not keep: refresh
# navigates away without script, which no CSP blocks, and a CSP of its own
# would only confuse readers of the page.
_DROPPED_HTTP_EQUIV = frozenset({"content-security-policy", "refresh"})
_WS = r"[\t\n\f\r ]"
_ATTR = rf"""(?:{_WS}+[^\t\n\f\r "'>/=]+(?:{_WS}*={_WS}*(?:"[^"]*"|'[^']*'|[^\t\n\f\r "'=<>`]+))?)"""
# The longest start of the page that a browser parses as nothing but a
# doctype, an <html> tag, and a <head> tag, so that no element precedes a
# meta inserted at its end.
_HEAD_START_RE = re.compile(
    rf"\A\ufeff?{_WS}*(?:<!doctype{_WS}+html{_WS}*>{_WS}*)?"
    rf"(?:<html{_ATTR}*{_WS}*>{_WS}*)?(?:<head{_ATTR}*{_WS}*>)?",
    re.IGNORECASE,
)
RENDER_TIMEOUT_SECONDS = 300
# Keeps the prompt that carries render errors back to the model within bounds.
RENDER_ERRORS_MAX_CHARS = 8000


@dataclass(frozen=True)
class ReportItem:
    number: int
    status: str
    severity: Severity
    source: str
    repository: str
    title: str
    summary: str | None
    closed_reason: str | None = None


@dataclass(frozen=True)
class WeeklyData:
    title: str
    counts: Mapping[Severity, tuple[int, int, int]]
    repositories: Mapping[str, Mapping[Severity, int]]
    incomplete: tuple[str, ...]
    open_items: tuple[ReportItem, ...]
    closed_items: tuple[ReportItem, ...]


def weekly_title(now: datetime) -> str:
    """Returns the report title for the ISO week of now."""
    iso = now.isocalendar()
    return f"Continuum weekly report {iso.year}-W{iso.week:02d}"


def _severity(record: Record) -> Severity:
    """Returns the severity in the record's label, or else in its state.

    A withdrawn close removes the severity label, so the severity recorded
    when the issue was filed stands in. Records with neither count as
    Medium, like an unrated finding when it is filed.
    """
    for label in record.labels:
        if label.startswith(_SEVERITY_PREFIX):
            severity = Severity.parse(label.removeprefix(_SEVERITY_PREFIX))
            if severity.filed:
                return severity
    recorded = Severity.parse(record.state.severity)
    return recorded if recorded.filed else Severity.MEDIUM


def _one_of(labels: frozenset[str], choices: frozenset[str]) -> str:
    return next(iter(sorted(labels & choices)), "")


def _status(labels: frozenset[str]) -> str:
    """Returns the status label, preferring wip, then pending, then new."""
    return next((status for status in _STATUS_ORDER if status in labels), "")


def _repository(labels: frozenset[str]) -> str:
    names = sorted(
        label.removeprefix(_REPO_PREFIX)
        for label in labels
        if label.startswith(_REPO_PREFIX)
    )
    return names[0] if names else ""


def _item(record: Record) -> ReportItem:
    return ReportItem(
        number=record.number,
        status=_status(record.labels),
        severity=_severity(record),
        source=_one_of(record.labels, SOURCE_LABELS),
        repository=_repository(record.labels),
        title=record.title,
        summary=extract_section(record.body, "Summary"),
        closed_reason=None if record.open else record.state_reason,
    )


def _order(item: ReportItem) -> tuple[int, int]:
    return (-item.severity.rank, item.number)


def _incomplete(
    scans: Sequence[TargetScan], now: datetime, pentest_max_age: timedelta
) -> tuple[str, ...]:
    def stale(scan: TargetScan) -> datetime:
        return now - (pentest_max_age if scan.source == "pentest" else _STALE)

    return tuple(
        f"{scan.source}: {scan.target} ({scan.latest_status})"
        for scan in scans
        if scan.latest_status in _INCOMPLETE_STATUSES
        or scan.completed_at is None
        or scan.completed_at < stale(scan)
    )


def _closed_this_week(record: Record, week_start: datetime) -> bool:
    """Returns whether the record was closed this week in a way the report shows.

    The owner's not planned and duplicate closes are left out; the bot's
    withdrawn close, also not planned, is shown.
    """
    if record.open or record.closed_at is None or record.closed_at <= week_start:
        return False
    if record.state_reason == "duplicate":
        return False
    return not (
        record.state_reason == "not_planned" and record.state.auto_closed != "withdrawn"
    )


def build_weekly(
    records: Sequence[Record],
    scans: Sequence[TargetScan],
    now: datetime,
    pentest_max_age: timedelta = DEFAULT_PENTEST_MAX_AGE,
) -> WeeklyData:
    """Counts the finding issues and incomplete scans for the week ending at now.

    Issues merged into another are left out. An issue is new or closed this
    week when it was created or closed after now minus seven days. Issues
    the owner closed as not planned or as duplicate are not closed this week.
    A scan is incomplete when its latest job failed, stopped, or is missing,
    or when its last completion is older than eight days, or than
    pentest_max_age for a pentest.
    """
    week_start = now - _WEEK
    live = [record for record in records if record.state.merged_into is None]
    items = [(_item(record), record) for record in live]
    open_items = sorted((item for item, record in items if record.open), key=_order)
    closed_items = sorted(
        (item for item, record in items if _closed_this_week(record, week_start)),
        key=_order,
    )
    new_items = [item for item, record in items if record.created_at > week_start]

    counts: dict[Severity, tuple[int, int, int]] = {}
    for severity in _REPORTED:
        row = tuple(
            sum(item.severity is severity for item in group)
            for group in (open_items, new_items, closed_items)
        )
        if severity is Severity.CRITICAL and not any(row):
            continue
        counts[severity] = (row[0], row[1], row[2])

    repositories: dict[str, dict[Severity, int]] = {}
    for item in open_items:
        if item.repository:
            row = repositories.setdefault(item.repository, {})
            row[item.severity] = row.get(item.severity, 0) + 1
    ordered = {
        name: {
            severity: repositories[name][severity]
            for severity in _REPORTED
            if severity in repositories[name]
        }
        for name in sorted(repositories)
    }

    return WeeklyData(
        title=weekly_title(now),
        counts=counts,
        repositories=ordered,
        incomplete=_incomplete(scans, now, pentest_max_age),
        open_items=tuple(open_items),
        closed_items=tuple(closed_items),
    )


def _cell(text: str) -> str:
    return escape_text(" ".join(text.split()), inline=True).replace("|", "\\|")


def _heading(severity: Severity) -> str:
    return severity.title()


def _table(header: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)


def _line(item: ReportItem, status: str) -> str:
    # The tags already carry the severity, so the title's own tag is dropped.
    tags = f"[{status}] [{item.severity.lower()}] [{item.source}]"
    title = escape_text(" ".join(strip_severity_tag(item.title).split()), inline=True)
    return (
        f"- #{item.number} {tags} {escape_text(item.repository, inline=True)}: {title}"
    )


def _open_line(item: ReportItem) -> str:
    return _line(item, item.status)


def _closed_line(item: ReportItem) -> str:
    """Returns the line of a closed item, with its reason in place of the status."""
    return _line(item, (item.closed_reason or "closed").replace("_", " "))


def _head(data: WeeklyData, summaries: Mapping[Severity, str]) -> str:
    severities = list(data.counts)
    parts = [
        _table(
            ("Severity", "Open", "New this week", "Closed this week"),
            [
                (_heading(severity), *(str(n) for n in data.counts[severity]))
                for severity in severities
            ],
        )
    ]
    for severity in severities:
        # A severity without open findings has nothing to summarize.
        if data.counts[severity][0] == 0:
            continue
        summary = summaries.get(severity)
        if not summary:
            continue
        parts.append(f"## {_heading(severity)}\n\n{escape_text(summary.strip())}")
    repositories = (
        _table(
            ("Repository", *(_heading(severity) for severity in severities)),
            [
                (_cell(name), *(str(row.get(severity, 0)) for severity in severities))
                for name, row in data.repositories.items()
            ],
        )
        if data.repositories
        else "_No open findings._"
    )
    parts.append(f"## Repositories\n\n{repositories}")
    if data.incomplete:
        lines = "\n".join(
            f"- {escape_text(name, inline=True)}" for name in data.incomplete
        )
        parts.append(f"## Incomplete scans\n\n{lines}")
    parts.append(f"{HTML_PART}: {HTML_URL_PLACEHOLDER}")
    return "\n\n".join(parts)


def _open_tag(label: str) -> str:
    return f"<details><summary>{label}</summary>"


def _block(label: str, lines: Sequence[str]) -> str:
    parts = [_open_tag(label)]
    if lines:
        parts.append("\n".join(lines))
    parts.append(_DETAILS_CLOSE)
    return "\n\n".join(parts)


def _block_len(label: str, line_lengths: Sequence[int]) -> int:
    """Returns len(_block(label, lines)) from the lengths of the lines."""
    size = len(_open_tag(label)) + 2 + len(_DETAILS_CLOSE)
    if line_lengths:
        size += sum(line_lengths) + len(line_lengths) - 1 + 2
    return size


def _fit(
    head: str,
    open_label: str,
    open_lines: list[str],
    closed_label: str,
    closed_lines: list[str],
    extra: int = 0,
) -> tuple[int, int]:
    """Returns how many open and closed lines fit in the body with the notice.

    extra is the length of the paragraphs that follow the notice.
    """
    fixed = len(head) + 2 + 2 + 2 + len(CONTINUED) + 1 + extra
    open_lengths = [len(line) for line in open_lines]
    closed_lengths = [len(line) for line in closed_lines]

    def size(k_open: int, k_closed: int) -> int:
        return (
            fixed
            + _block_len(open_label, open_lengths[:k_open])
            + _block_len(closed_label, closed_lengths[:k_closed])
        )

    k_open = 0
    while k_open < len(open_lines) and size(k_open + 1, 0) <= MAX_BODY:
        k_open += 1
    k_closed = 0
    if k_open == len(open_lines):
        while k_closed < len(closed_lines) and size(k_open, k_closed + 1) <= MAX_BODY:
            k_closed += 1
    return k_open, k_closed


def _comments(rest: Sequence[tuple[str, str]]) -> list[str]:
    """Packs (label, line) pairs into comments of collapsed blocks."""
    comments: list[str] = []
    segments: list[tuple[str, list[str]]] = []
    size = 0
    for label, line in rest:
        if segments and segments[-1][0] == label:
            grow = len(line) + 1
        else:
            grow = (2 if segments else 0) + _block_len(label, [len(line)])
        if segments and size + grow + 1 > MAX_BODY:
            comments.append(_render_segments(segments))
            segments, size = [], 0
            grow = _block_len(label, [len(line)])
        if segments and segments[-1][0] == label:
            segments[-1][1].append(line)
        else:
            segments.append((label, [line]))
        size += grow
    if segments:
        comments.append(_render_segments(segments))
    return comments


def _render_segments(segments: Sequence[tuple[str, list[str]]]) -> str:
    return "\n\n".join(_block(label, lines) for label, lines in segments) + "\n"


def unavailable_parts(
    data: WeeklyData,
    summaries: Mapping[Severity, str],
    failures: Mapping[Severity, str],
    html_failure: str | None,
) -> list[str]:
    """Names the parts the model was asked for but could not write.

    A severity with open findings and no summary is named "<Severity>
    summary", in report order, followed by the visual report when
    html_failure is not None. Each name ends with its reason in parentheses,
    from failures or html_failure, when one is known.
    """
    parts = [
        _with_reason(f"{_heading(severity)} summary", failures.get(severity))
        for severity, row in data.counts.items()
        if row[0] and not summaries.get(severity)
    ]
    if html_failure is not None:
        parts.append(_with_reason(HTML_PART, html_failure))
    return parts


def _with_reason(part: str, reason: str | None) -> str:
    return part if reason is None else f"{part} (`{safe_reason(reason)}`)"


def render_weekly(
    data: WeeklyData,
    summaries: Mapping[Severity, str],
    unavailable: Sequence[str] = (),
) -> tuple[str, list[str]]:
    """Returns the report body and the comments that continue its lists.

    The body and each comment stay within MAX_BODY characters. When the
    lists do not fit, whole lines from their end move to the comments, which
    keep them collapsed under "(continued)" headings. unavailable, when not
    empty, ends the body with a note naming the parts the model could not
    write.
    """
    head = _head(data, summaries)
    open_label = f"{_OPEN_LABEL} ({len(data.open_items)})"
    closed_label = f"{_CLOSED_LABEL} ({len(data.closed_items)})"
    open_lines = [_open_line(item) for item in data.open_items]
    closed_lines = [_closed_line(item) for item in data.closed_items]
    tail = (
        [f"_Written without Bedrock this week: {', '.join(unavailable)}._"]
        if unavailable
        else []
    )

    body = (
        "\n\n".join(
            (
                head,
                _block(open_label, open_lines),
                _block(closed_label, closed_lines),
                *tail,
            )
        )
        + "\n"
    )
    if len(body) <= MAX_BODY:
        return body, []

    k_open, k_closed = _fit(
        head,
        open_label,
        open_lines,
        closed_label,
        closed_lines,
        sum(len(text) + 2 for text in tail),
    )
    body = (
        "\n\n".join(
            (
                head,
                _block(open_label, open_lines[:k_open]),
                _block(closed_label, closed_lines[:k_closed]),
                CONTINUED,
                *tail,
            )
        )
        + "\n"
    )
    rest = [(f"{_OPEN_LABEL} (continued)", line) for line in open_lines[k_open:]]
    rest += [(f"{_CLOSED_LABEL} (continued)", line) for line in closed_lines[k_closed:]]
    return body, _comments(rest)


def publish_weekly(
    github: GitHubLike,
    title: str,
    body: str,
    comments: Sequence[str],
    html_url: str | None,
) -> str:
    """Posts the report and closes the reports of other weeks.

    Rewrites and reopens the report with the same title when this workflow
    filed one, and creates it otherwise. Without html_url, the line that
    links the visual report is removed. Returns "updated" or "created".
    """
    if html_url:
        body = body.replace(HTML_URL_PLACEHOLDER, html_url)
    else:
        body = body.replace(_HTML_LINE, "")
    reports = [
        item
        for item in github.issues()
        if "pull_request" not in item
        and (item.get("user") or {}).get("login") == BOT
        and WEEKLY_LABEL in {label["name"] for label in item.get("labels", ())}
    ]
    same = [item for item in reports if item["title"] == title]
    if same:
        current = max(same, key=lambda item: item["number"])
        number = current["number"]
        if current["state"] == "open":
            github.update_issue(number, body=body)
        else:
            github.update_issue(number, body=body, state="open")
        result = "updated"
    else:
        number, _ = github.create_issue(title, body, [WEEKLY_LABEL])
        result = "created"
    for text in comments:
        github.comment(number, text)
    for item in reports:
        if item["number"] != number and item["state"] == "open":
            github.update_issue(
                item["number"], state="closed", state_reason="completed"
            )
    return result


def strip_external_fonts(html: str) -> str:
    """Removes the <link> tags that load Google Fonts and leaves the rest as is.

    The rendered page then falls back to local fonts and loads nothing from
    outside.
    """

    def keep(match: re.Match[str]) -> str:
        tag = match.group(0)
        return "" if any(host in tag for host in _EXTERNAL_FONT_HOSTS) else tag

    return _LINK_RE.sub(keep, html)


def color_unstyled_svg_text(html: str) -> str:
    """Adds a rule that colors SVG text without a class or fill.

    The kit's stylesheet colors only SVG text that carries one of its
    classes, so other text keeps SVG's default black and disappears on the
    dark theme. The rule has zero specificity, so every kit rule and fill
    attribute still wins. Pages without a head are returned unchanged.
    """
    if _UNSTYLED_SVG_TEXT_RULE in html:
        return html
    return html.replace("</head>", _UNSTYLED_SVG_TEXT_RULE + "</head>", 1)


def _render(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    skill_dir: Path,
    src: Path,
    out: Path,
) -> str | None:
    """Renders src to out and returns None, or the render errors on failure.

    The errors keep the last RENDER_ERRORS_MAX_CHARS characters of stderr.
    """
    args = [
        "node",
        str(skill_dir / "kit" / "render.mjs"),
        str(src),
        "-o",
        str(out),
        "--no-check",
    ]
    try:
        result = runner(
            args, capture_output=True, text=True, timeout=RENDER_TIMEOUT_SECONDS
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return type(error).__name__
    if result.returncode != 0 or not out.is_file():
        return result.stderr[-RENDER_ERRORS_MAX_CHARS:] or (
            f"exit status {result.returncode}"
        )
    return None


def set_html_lang(html: str, language: str) -> str:
    """Sets the lang attribute of the first <html> tag to the locale language.

    ja_JP becomes ja-JP. An existing lang attribute is replaced, and a page
    without an <html> tag is returned unchanged.
    """
    match = _HTML_TAG_RE.search(html)
    if match is None:
        return html
    attributes = _LANG_ATTR_RE.sub("", match.group("attributes"))
    tag = f'<{match.group("name")} lang="{language.replace("_", "-")}"{attributes}>'
    return html[: match.start()] + tag + html[match.end() :]


def _kit_scripts(skill_dir: Path) -> list[str]:
    """Returns the texts of the script elements that kit/render.mjs can inline.

    Each text joins the files of one _KIT_SCRIPT_FILES entry with line
    breaks after a leading one and escapes "</script" as render.mjs does.
    An entry with a missing file is left out.
    """
    texts = []
    for names in _KIT_SCRIPT_FILES:
        try:
            js = "\n".join(
                (skill_dir / "kit" / name).read_bytes().decode("utf-8")
                for name in names
            )
        except (OSError, UnicodeDecodeError):
            continue
        texts.append("\n" + _SCRIPT_END_RE.sub(r"<\\/script", js))
    return texts


def _script_hash(text: str) -> str:
    """Returns the CSP hash source of an inline script with text.

    The browser hashes the script after its parser turns CR LF and CR into
    LF, so the text is normalized the same way first.
    """
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return f"'sha256-{base64.b64encode(digest).decode('ascii')}'"


class _DroppedMetaFinder(HTMLParser):
    """Collects the spans of the <meta> tags to drop, as the parser reads them.

    The parser skips script contents and comments, reads quoted attribute
    values that contain ">", and decodes character references in values, so
    "&#114;efresh" counts as refresh.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.spans: list[tuple[int, int, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "meta" and any(
            name == "http-equiv"
            and (value or "").strip().lower() in _DROPPED_HTTP_EQUIV
            for name, value in attrs
        ):
            line, column = self.getpos()
            self.spans.append((line, column, self.get_starttag_text() or ""))


def _drop_meta(html: str) -> str:
    """Removes the <meta> tags whose http-equiv is in _DROPPED_HTTP_EQUIV."""
    finder = _DroppedMetaFinder()
    finder.feed(html)
    finder.close()
    line_starts = [0] + [m.end() for m in re.finditer("\n", html)]
    for line, column, text in reversed(finder.spans):
        start = line_starts[line - 1] + column
        if text and html.startswith(text, start):
            html = html[:start] + html[start + len(text) :]
    return html


def add_content_security_policy(html: str, skill_dir: Path) -> str | None:
    """Returns the rendered page with a CSP that runs only the kit's script.

    Returns None when the page has no script element that kit/render.mjs
    builds from the kit files in skill_dir, which is the case for a source
    that render.mjs writes as given. Model-written <meta> refresh and CSP
    tags are removed first. The CSP meta goes before every element of the
    page, so the browser applies it to all of them, followed by a charset
    meta that keeps the charset within the bytes browsers scan for it.
    """
    html = _drop_meta(html)
    scripts = [
        text
        for text in _kit_scripts(skill_dir)
        if f"{_KIT_SCRIPT_OPEN}{text}</script>" in html
    ]
    if not scripts:
        return None
    policy = "; ".join(
        (
            # Nothing loads unless a directive below allows it: no fetch,
            # frame, object, media, or worker.
            "default-src 'none'",
            # Only the kit's inline scripts run. With hashes and no
            # 'unsafe-inline', other inline scripts, on* attributes, and
            # javascript: URLs are blocked too.
            "script-src " + " ".join(_script_hash(text) for text in scripts),
            # The kit inlines its CSS in <style data-ve-kit>, Mermaid
            # drawings carry style attributes, and the model writes its own
            # styles. url() in CSS still obeys img-src and font-src.
            "style-src 'unsafe-inline'",
            # The favicon that render.mjs adds is a data: URL. External
            # images, which could carry page content in their URLs, are
            # blocked.
            "img-src data:",
            # The Google Fonts links are stripped, so the page uses local
            # fonts, and only embedded fonts may load.
            "font-src data:",
            # A <base> tag cannot redirect the page's relative URLs.
            "base-uri 'none'",
            # A form cannot submit the page's content anywhere.
            "form-action 'none'",
        )
    )
    meta = (
        f'<meta http-equiv="Content-Security-Policy" content="{policy}">'
        '<meta charset="utf-8">'
    )
    match = _HEAD_START_RE.match(html)
    end = match.end() if match else 0
    return html[:end] + meta + html[end:]


def build_visual_report(
    model: ModelLike,
    data: WeeklyData,
    skill_dir: Path,
    out: Path,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    language: str = DEFAULT_LANGUAGE,
) -> str | None:
    """Writes the visual report to out, returning None or why it could not.

    The reason is the model's when it gives no page source, and
    render_failed when no source renders.

    The model writes a page source in the language of the locale language,
    and visual-explainer renders it. A rendered page without the kit's script
    counts as a render failure, and the page that is kept carries a CSP from
    add_content_security_policy. When rendering fails, the model rewrites
    the source once with the render errors. Leaves no file at out
    when no page renders, including one left by an earlier run. The render
    output is never printed, because it can repeat finding details.
    """
    out.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="continuum-report-") as work:
        src = Path(work) / "report.src.html"
        errors: str | None = None
        failure = "render_failed"
        for _ in range(2):
            source = visual_report_source(model, data, skill_dir, errors, language)
            if source is None:
                failure = model.last_failure or "unknown"
                break
            src.write_text(source, encoding="utf-8")
            errors = _render(runner, skill_dir, src, out)
            if errors is None:
                html = out.read_text(encoding="utf-8")
                html = color_unstyled_svg_text(strip_external_fonts(html))
                html = add_content_security_policy(
                    set_html_lang(html, language), skill_dir
                )
                if html is not None:
                    out.write_text(html, encoding="utf-8")
                    return None
                errors = _NO_KIT_ERRORS
    out.unlink(missing_ok=True)
    return failure
