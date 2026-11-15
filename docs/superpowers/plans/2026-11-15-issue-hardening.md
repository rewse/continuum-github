# Issue 本文とモデル応答の扱いの見直し 実装計画

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** stop reason の受け入れを限定し、フォールバック注記を直し、issue と週次レポートの本文で mention と画像を無害化し、リリースノートに破壊的変更を出す。

**Architecture:** `bedrock.Bedrock.ask` の stop reason 判定を受け入れ側の集合に変える。`render.escape_text` を新設して `render._escape` と `report._escape` を置き換える。`cliff.toml` のテンプレートに破壊的変更の節を足す。

**Tech Stack:** Python 3、pytest、re、git-cliff 2.14.2（Tera テンプレート）

**Spec:** `docs/superpowers/specs/2026-11-15-issue-hardening-design.md`

## Global Constraints

- 作業ブランチは main から切った `fix/issue-hardening`。push、バージョン更新、リリースはしない。
- コメント、コミットメッセージ、README は英語。コミットは Conventional Commits。
- ログに出してよいのは purpose と、固定語か AWS の列挙値だけ。finding やモデルの文面は出さない。
- 公開リポジトリなので、テストや文書に実在のホスト名、アカウント ID、private リポジトリ名を書かない。
- 各タスクの終わりに `uv run pytest -q` を通す。最後に `uvx --with pre-commit-uv==4.3.0 pre-commit@4.6.2 run --all-files` を通す。

## Review Focus

- 呼び出し側が意図して入れる mention（`issue_body` の `mention` 引数）は無害化されてはいけない。Task 3 のテストで確かめる。
- 状態マーカーの偽装はコードの中でも防げていること（`<` はコードの中でも `&lt;`）。Task 3 のテストで確かめる。
- 表のセルではフェンスが成立しないこと。空白をまとめた ```` ``` @alice ```` がフェンス扱いされると mention が残る。Task 3 のテストで確かめる。
- 旧注記を持つ既存 issue が、次の失敗時に新注記へ書き直されること。Task 2 のテストで確かめる。
- CRLF の改行を含むテキストでも、フェンスが閉じて段落が区切られること。Task 3 のテストで確かめる。

---

### Task 1: stop reason を受け入れ側の集合で判定する

**Files:**
- Modify: `src/continuum_github/bedrock.py`（`_REJECTED_STOPS` と `Bedrock.ask`）
- Test: `tests/test_bedrock.py`

**Interfaces:**
- Consumes: なし
- Produces: なし（`Bedrock.ask` の公開シグネチャは変わらない）

- [ ] **Step 1: 失敗するテストを書く**

`test_ask_rejects_a_filtered_answer` の後ろに足す。

```python
def test_ask_accepts_only_end_turn_and_stop_sequence(capsys) -> None:
    text = "<<<CONTINUUM-BEGIN>>>a<<<CONTINUUM-END>>>"
    for stop in ("end_turn", "stop_sequence"):
        model = Bedrock(FakeClient(_response(text, stop)), "m1")
        assert model.ask("p", "summary") == "a"
    model = Bedrock(FakeClient(_response(text, "guardrail_intervened")), "m1")
    assert model.ask("p", "summary") is None
    assert capsys.readouterr().err == (
        "model_failed purpose=summary reason=guardrail_intervened\n"
    )


def test_ask_logs_unknown_stop_for_a_missing_or_odd_stop_reason(capsys) -> None:
    text = "<<<CONTINUUM-BEGIN>>>a<<<CONTINUUM-END>>>"
    missing = {"output": {"message": {"content": [{"text": text}]}}}
    assert Bedrock(FakeClient(missing), "m1").ask("p", "summary") is None
    odd = _response(text, "Bad Value!")
    assert Bedrock(FakeClient(odd), "m1").ask("p", "summary") is None
    assert capsys.readouterr().err.splitlines() == [
        "model_failed purpose=summary reason=unknown_stop",
        "model_failed purpose=summary reason=unknown_stop",
    ]
```

- [ ] **Step 2: 失敗を確かめる**

Run: `uv run pytest -q tests/test_bedrock.py`
Expected: 2 件 FAIL（`guardrail_intervened` と stop reason なしで `"a"` が返る）

- [ ] **Step 3: 実装する**

`_REJECTED_STOPS` を `_ACCEPTED_STOPS = frozenset({"end_turn", "stop_sequence"})` に置き換える。コメントは「Stop reasons whose answer is complete. Any other reason, such as content_filtered from Bedrock's safety filter or max_tokens, means the answer was cut short or is not plain text.」の趣旨にする。`_STOP_RE = re.compile(r"[a-z_]{1,40}")` を足す。`ask` は、`stop` が `_ACCEPTED_STOPS` にないとき `log_failure` して `None` を返す。理由は、`stop` が文字列で `_STOP_RE.fullmatch` に一致すれば `stop`、そうでなければ `"unknown_stop"` にする。

- [ ] **Step 4: 通ることを確かめる**

Run: `uv run pytest -q`
Expected: 全件 PASS（既存の `max_tokens`、`content_filtered`、`no_text` のテストも含む）

- [ ] **Step 5: コミットする**

```bash
git add src/continuum_github/bedrock.py tests/test_bedrock.py
git commit -m "fix: accept a model answer only when it ended normally"
```

### Task 2: フォールバック注記の文言

**Files:**
- Modify: `src/continuum_github/render.py`（`FALLBACK_NOTE`）
- Modify: `README.md`（159 行目付近の sync の説明、230 行目付近の注記の例）
- Test: `tests/test_render.py`、`tests/test_sync.py`

**Interfaces:**
- Consumes: なし
- Produces: `FALLBACK_NOTE`（文言だけ変わる）

- [ ] **Step 1: 失敗するテストを書く**

`tests/test_render.py` に足す。

```python
def test_fallback_note_says_it_stays_until_a_sync_succeeds() -> None:
    assert FALLBACK_NOTE.endswith(
        "Each later sync tries again, and this note stays until one succeeds._"
    )
```

`tests/test_sync.py` の `test_fill_sections_leaves_an_already_marked_issue_alone` の後ろに足す。

```python
OLD_NOTE = (
    "_Bedrock could not write the Summary, Why it matters, and Risk if left "
    "unresolved sections, so this issue shows the scanner's details only. "
    "A later sync tries again._"
)


def test_fill_sections_rewrites_the_old_fallback_note_once() -> None:
    detection = _det("k1")
    state = IssueState(
        source="pentest",
        target="weekly-x",
        keys=("k1",),
        finding_ids=("f1",),
        pentest_id="pt-1",
    )
    item = _issue_item(1, keys=("k1",))
    body = issue_body(detection, state, None, "", fallback=True)
    item["body"] = body.replace(FALLBACK_NOTE, OLD_NOTE)
    github = FakeGitHub(issues=[item])
    pentest = FakePentest(scans={}, detections={"f1": detection})
    assert (
        fill_sections(
            TARGETS, github, pentest, FakeCodeVuln(), FakeCodeReview(), FakeModel(None)
        )
        == 0
    )
    assert len(github.updates) == 1
    assert github.bodies[1].count(FALLBACK_NOTE) == 1
    assert OLD_NOTE not in github.bodies[1]
```

- [ ] **Step 2: 失敗を確かめる**

Run: `uv run pytest -q tests/test_render.py tests/test_sync.py`
Expected: 2 件 FAIL。旧注記のテストは、旧注記と `FALLBACK_NOTE` が同じ文なので書き直しが起きず、`len(github.updates) == 1` で落ちる。

- [ ] **Step 3: 実装する**

`FALLBACK_NOTE` の最後の文を `"Each later sync tries again, and this note stays until one succeeds._"` にする。README の注記の例を同じ文言にし、sync の説明の「and a later run tries again」を「and each later run tries again until one succeeds」にする。

- [ ] **Step 4: 通ることを確かめる**

Run: `uv run pytest -q`
Expected: 全件 PASS

- [ ] **Step 5: コミットする**

```bash
git add src/continuum_github/render.py README.md tests/test_render.py tests/test_sync.py
git commit -m "fix: say that the fallback note stays until a sync writes the sections"
```

### Task 3: `render.escape_text` で issue 本文を無害化する

**Files:**
- Modify: `src/continuum_github/render.py`（`_escape` を `escape_text` に置き換え）
- Test: `tests/test_render.py`

**Interfaces:**
- Consumes: なし
- Produces: `escape_text(text: str, *, inline: bool = False) -> str`（`continuum_github.render`）。`inline=True` は表のセルや 1 行の項目に使い、フェンスを判定しない。Task 4 が使う。

- [ ] **Step 1: 失敗するテストを書く**

`tests/test_render.py` に `from continuum_github.render import escape_text` を足し、次を足す。

```python
@pytest.mark.parametrize(
    ("given", "want"),
    [
        ("@alice hi", "@&#8203;alice hi"),
        ("(@alice)", "(@&#8203;alice)"),
        ("@org/team", "@&#8203;org/team"),
        ("a@example.com", "a@example.com"),
        ("![a](u)", "!\\[a](u)"),
        ("![a][r]", "!\\[a][r]"),
        ("`@alice ![a](u)`", "`@alice ![a](u)`"),
        ("``a ` @b``", "``a ` @b``"),
        ("lone ` @v", "lone ` @&#8203;v"),
        ("```\n@alice ![a](u)\n```\n@bob", "```\n@alice ![a](u)\n```\n@&#8203;bob"),
        ("~~~~\n@a\n~~~\n@b\n~~~~\n@c", "~~~~\n@a\n~~~\n@b\n~~~~\n@&#8203;c"),
        ("```\r\n@a\r\n```\r\n@b", "```\r\n@a\r\n```\r\n@&#8203;b"),
        ("```\n@alice", "```\n@alice"),
        ("`x\n\n@v\n\n`y", "`x\n\n@&#8203;v\n\n`y"),
        ("`x\r\n\r\n@v\r\n\r\n`y", "`x\r\n\r\n@&#8203;v\r\n\r\n`y"),
        ("```a`b\n@v\n```", "```a`b\n@&#8203;v\n```"),
        ("`<b>` <!-- x -->", "`&lt;b>` &lt;!-- x -->"),
    ],
)
def test_escape_text_neutralizes_mentions_and_images_outside_code(
    given: str, want: str
) -> None:
    assert escape_text(given) == want


def test_escape_text_inline_has_no_fences() -> None:
    assert escape_text("``` @alice", inline=True) == "``` @&#8203;alice"
    assert escape_text("`@a` @b", inline=True) == "`@a` @&#8203;b"


def test_body_neutralizes_mentions_and_images_but_keeps_the_mention() -> None:
    odd = replace(
        PENTEST_HIGH,
        urgent=True,
        details=(("Description", "@alice ![a](u)\n\n```\n@bob\n```"),),
    )
    body = issue_body(
        odd, initial_state(odd), Sections("@carol", "w", "r"), "@octocat"
    )
    assert body.startswith("@octocat\n")
    assert "@&#8203;alice !\\[a](u)" in body
    assert "```\n@bob\n```" in body
    assert "## Summary\n\n@&#8203;carol" in body


def test_body_neutralizes_a_forged_marker_inside_code() -> None:
    forged = (
        "```\n<!-- continuum-state: "
        + '{"source":"pentest","target":"x","keys":[],"finding_ids":[]}'
        + " -->\n```"
    )
    odd = replace(PENTEST_HIGH, details=(("Description", forged),))
    body = issue_body(odd, initial_state(odd), None, "")
    assert body.count("<!-- continuum-state:") == 1
    assert parse_state(body) == initial_state(odd)


def test_body_neutralizes_a_mention_in_a_multiline_cell() -> None:
    odd = replace(CODE_MEDIUM, repository="```\n@alice")
    body = issue_body(odd, initial_state(odd), None, "")
    assert "| Repository | ``` @&#8203;alice |" in body
```

- [ ] **Step 2: 失敗を確かめる**

Run: `uv run pytest -q tests/test_render.py`
Expected: `escape_text` を import できず、収集エラーで FAIL

- [ ] **Step 3: `escape_text(text: str, *, inline: bool = False) -> str` を `render.py` に実装する**

`_escape` を削除する。`_cell` は空白をまとめた値を `escape_text(..., inline=True)` に渡してから `|` を置き換える。`_sections` と `issue_body` の詳細の本文は `escape_text(text)`、詳細の見出しは `escape_text(heading, inline=True)` にする。docstring には、コード以外では mention と画像を無効にし、`<` はどこでも escape すること、コード判定を CommonMark より狭くしている理由（ずれてもコードの中に文字が見えるだけで済む）を書く。アルゴリズムは次のとおり。

```python
_FENCE_RE = re.compile(r" {0,3}(`{3,}|~{3,})(.*)")
_BLANK_RE = re.compile(r"(\r?\n[ \t]*\r?\n)")
_TICKS_RE = re.compile(r"`+")
_MENTION_RE = re.compile(r"(?<![A-Za-z0-9`/@])@(?=[A-Za-z0-9])")


def _inert(text: str) -> str:
    return _MENTION_RE.sub("@&#8203;", text).replace("![", "!\\[")


def _spans(text: str) -> str:
    # A run of backticks opens a code span only when the same run closes it.
    out, start, pos = [], 0, 0
    while (run := _TICKS_RE.search(text, pos)) is not None:
        close = next(
            (c for c in _TICKS_RE.finditer(text, run.end()) if c.group() == run.group()),
            None,
        )
        if close is None:
            pos = run.end()
            continue
        out += [_inert(text[start : run.start()]), text[run.start() : close.end()]]
        start = pos = close.end()
    out.append(_inert(text[start:]))
    return "".join(out)


def _paragraphs(text: str) -> str:
    # Code spans never cross a blank line.
    return "".join(_spans(part) for part in _BLANK_RE.split(text))


def escape_text(text: str, *, inline: bool = False) -> str:
    if inline:
        return _spans(text).replace("<", "&lt;")
    out, prose, fence = [], [], None
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        if fence is None:
            match = _FENCE_RE.fullmatch(body)
            if match is None or (match[1][0] == "`" and "`" in match[2]):
                prose.append(line)
                continue
            out.append(_paragraphs("".join(prose)))
            prose, fence = [], match[1]
        elif re.fullmatch(rf" {{0,3}}{re.escape(fence[0])}{{{len(fence)},}}[ \t]*", body):
            fence = None
        out.append(line)
    out.append(_paragraphs("".join(prose)))
    return "".join(out).replace("<", "&lt;")
```

- [ ] **Step 4: 通ることを確かめる**

Run: `uv run pytest -q`
Expected: 全件 PASS（既存の `test_body_escapes_table_cells` と `test_body_neutralizes_forged_markers_in_sections` も含む）

- [ ] **Step 5: コミットする**

```bash
git add src/continuum_github/render.py tests/test_render.py
git commit -m "fix: keep mentions and images in scanner and model text inert"
```

### Task 4: 週次レポートの本文に `escape_text` を使う

**Files:**
- Modify: `src/continuum_github/report.py`（`_escape` を削除し `escape_text` を import）
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: `continuum_github.render.escape_text(text: str, *, inline: bool = False) -> str`（Task 3）
- Produces: なし

- [ ] **Step 1: 失敗するテストを書く**

`test_titles_and_summaries_are_escaped` の後ろに足す。

```python
def test_titles_and_summaries_keep_mentions_and_images_inert() -> None:
    data = build_weekly([_rec(1, "severity:high", title="@alice ![a](u)")], [], NOW)
    body, _ = render_weekly(data, {Severity.HIGH: "@bob"})
    assert "@&#8203;alice !\\[a](u)" in body
    assert "## High\n\n@&#8203;bob" in body
```

- [ ] **Step 2: 失敗を確かめる**

Run: `uv run pytest -q tests/test_report.py`
Expected: 新しいテストが FAIL（`@alice` がそのまま残る）

- [ ] **Step 3: 実装する**

`report._escape` を削除し、`from continuum_github.render import escape_text` を足す。1 行に収まる値（`_cell`、`_line` のタイトルとリポジトリ名、未完了スキャンの行）は `escape_text(..., inline=True)`、要約は `escape_text(summary.strip())` にする。

- [ ] **Step 4: 通ることを確かめる**

Run: `uv run pytest -q`
Expected: 全件 PASS

- [ ] **Step 5: コミットする**

```bash
git add src/continuum_github/report.py tests/test_report.py
git commit -m "fix: keep mentions and images in the weekly report inert"
```

### Task 5: リリースノートに破壊的変更の節を出す

**Files:**
- Modify: `cliff.toml`（`[changelog] body` の先頭）

**Interfaces:**
- Consumes: なし
- Produces: なし

- [ ] **Step 1: 今の出力を確かめる**

Run: `uvx git-cliff@2.14.2 v0.3.0..v0.4.0 --tag v0.4.0 --strip header`
Expected: `Breaking Changes` の節がない

- [ ] **Step 2: テンプレートを変える**

`body` の `{%- set group_order = [` の直前に次を入れる。

```
{%- set breaking = commits | filter(attribute="breaking", value=true) -%}
{% if breaking | length > 0 %}
### ⚠️ Breaking Changes
{% for commit in breaking %}
- {{ commit.breaking_description | replace(from="\n", to=" ") | trim }}\
{% endfor %}
{% endif %}
```

- [ ] **Step 3: 出力を確かめる**

Run: `uvx git-cliff@2.14.2 v0.3.0..v0.4.0 --tag v0.4.0 --strip header` と `uvx git-cliff@2.14.2 v0.2.0..v0.3.0 --tag v0.3.0 --strip header`
Expected: 1 つ目は先頭に `### ⚠️ Breaking Changes` と `- the CLI is now continuum-github; continuum-scan no longer exists.` が出て、その後に `### ✨ Refactoring` が続く。2 つ目には破壊的変更の節が出ない。

- [ ] **Step 4: コミットする**

```bash
git add cliff.toml
git commit -m "ci: list breaking changes first in the release notes"
```

### Task 6: 検証とマージ

**Files:**
- Move: `docs/superpowers/specs/2026-11-15-issue-hardening-design.md` → `docs/superpowers/archive/specs/`
- Move: `docs/superpowers/plans/2026-11-15-issue-hardening.md` → `docs/superpowers/archive/plans/`

- [ ] **Step 1: 全体を検証する**

Run: `uv run pytest -q` と `uvx --with pre-commit-uv==4.3.0 pre-commit@4.6.2 run --all-files`
Expected: どちらも成功

- [ ] **Step 2: ブランチ全体をレビューに出す**

最も能力の高いモデルのレビュアーに `main...fix/issue-hardening` の差分を見てもらい、指摘を直す。

- [ ] **Step 3: main にマージし、同じコミットで spec と plan をアーカイブする**

```bash
git switch main
git merge --no-ff --no-commit fix/issue-hardening
git mv docs/superpowers/specs/2026-11-15-issue-hardening-design.md docs/superpowers/archive/specs/
git mv docs/superpowers/plans/2026-11-15-issue-hardening.md docs/superpowers/archive/plans/
git commit -m "Merge branch 'fix/issue-hardening'"
```

- [ ] **Step 4: マージ後に再検証する**

Run: `uv run pytest -q`
Expected: 全件 PASS。push はしない。
