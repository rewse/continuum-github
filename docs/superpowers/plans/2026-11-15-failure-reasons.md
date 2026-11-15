# モデルが書けなかった理由を注記に出す 実装計画

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** issue の注記と週次レポートの注記に、モデルが書けなかった理由を出す。

**Architecture:** `Bedrock.last_failure` に直前の失敗理由を持たせ、`finding_sections`、`severity_summaries`、`build_visual_report` がそれを呼び出し側へ返す。`render.fallback_note` と `report.unavailable_parts` が理由を検査して注記に入れる。

**Tech Stack:** Python 3、pytest

**Spec:** `docs/superpowers/specs/2026-11-15-failure-reasons-design.md`

## Global Constraints

- 作業ブランチは main から切った `feat/failure-reasons`。push、バージョン更新、リリースはしない。
- コメント、コミットメッセージ、README は英語。コミットは Conventional Commits。
- 注記に入れる理由は `[A-Za-z0-9_]{1,64}` に完全一致する値だけ。一致しなければ `unknown`。
- 各タスクの終わりに `uv run pytest -q` を通す。最後に `uvx --with pre-commit-uv==4.3.0 pre-commit@4.6.2 run --all-files` を通す。

## Review Focus

- 同じ理由で失敗し続ける issue に毎回書き込まないこと。Task 2 のテストで確かめる。
- モデルが答えず `last_failure` も `None` のとき（フェイクや将来の実装）、理由は `unknown` になること。Task 1 と Task 3 のテストで確かめる。
- `ask` が成功したあと `last_failure` が `None` に戻ること。前の失敗理由が次の成功に残ると、検査で落ちた答えに古い理由が付く。Task 1 のテストで確かめる。
- 理由に `` ` `` や改行が入っても本文の Markdown を壊さないこと。検査で `unknown` になる。Task 2 のテストで確かめる。

---

### Task 1: `last_failure` と `Failure`

**Files:**
- Modify: `src/continuum_github/bedrock.py`（`ModelLike`、`Bedrock.ask`、`Failure`、`finding_sections`、`severity_summaries`）
- Modify: `tests/fakes.py`（`FakeModel`、`RecordingModel`）
- Test: `tests/test_bedrock.py`、`tests/test_report.py`

**Interfaces:**
- Produces:
  - `@dataclass(frozen=True) class Failure: reason: str`（`continuum_github.bedrock`）
  - `ModelLike.last_failure: str | None`
  - `finding_sections(model, detection, language=DEFAULT_LANGUAGE) -> Sections | Failure`
  - `severity_summaries(model, data, language=DEFAULT_LANGUAGE) -> tuple[dict[Severity, str], dict[Severity, str]]`（要約、理由）
  - `FakeModel(answer, failure: str | None = None)`、`RecordingModel(answers, failures: Sequence[str | None] = ())`。答えが `None` のとき、与えた理由を `last_failure` に入れる。

- [ ] **Step 1: 失敗するテストを書く**

`tests/test_bedrock.py` に足す。

```python
def test_ask_records_the_last_failure_and_clears_it_on_success() -> None:
    text = "<<<CONTINUUM-BEGIN>>>a<<<CONTINUUM-END>>>"
    filtered = Bedrock(FakeClient(_response(text, "content_filtered")), "m1")
    assert filtered.ask("p", "summary") is None
    assert filtered.last_failure == "content_filtered"
    filtered.client = FakeClient(_response(text))
    assert filtered.ask("p", "summary") == "a"
    assert filtered.last_failure is None
    error = ClientError({"Error": {"Code": "ThrottlingException"}}, "Converse")
    throttled = Bedrock(FakeClient(error=error), "m1")
    throttled.ask("p", "summary")
    assert throttled.last_failure == "ThrottlingException"
    empty = {"output": {"message": {"content": []}}, "stopReason": "end_turn"}
    no_text = Bedrock(FakeClient(empty), "m1")
    no_text.ask("p", "summary")
    assert no_text.last_failure == "no_text"


def test_finding_sections_returns_the_failure_reason() -> None:
    assert finding_sections(
        FakeModel(None, "content_filtered"), DETECTION
    ) == Failure("content_filtered")
    assert finding_sections(FakeModel("not json"), DETECTION) == Failure(
        "invalid_answer"
    )
    assert finding_sections(FakeModel(None), DETECTION) == Failure("unknown")
```

`test_finding_sections_parses_and_validates_json` と `test_finding_sections_logs_an_invalid_answer` の `is None` を `isinstance(..., Failure)` に変える。

`tests/test_report.py` の `test_severity_summaries_asks_once_per_severity` と `test_severity_summaries_drops_bad_answers` を、戻り値の 1 つ目で比べる形に直し、次を足す。

```python
def test_severity_summaries_returns_the_failure_reasons() -> None:
    data = build_weekly([_rec(1, "severity:high"), _rec(2, "severity:medium")], [], NOW)
    model = RecordingModel([None, "  "], failures=["content_filtered", None])
    summaries, failures = severity_summaries(model, data)
    assert summaries == {}
    assert failures == {Severity.HIGH: "content_filtered", Severity.MEDIUM: "invalid_answer"}
```

- [ ] **Step 2: 失敗を確かめる**

Run: `uv run pytest -q tests/test_bedrock.py tests/test_report.py`
Expected: `Failure` を import できず収集エラー

- [ ] **Step 3: 実装する**

`Bedrock.__init__` で `self.last_failure: str | None = None`。`ask` は最初に `None` にし、`log_failure` を呼ぶ 6 か所で同じ理由を入れる（`_fail(purpose, reason)` に集める）。`finding_sections` は答えがなければ `Failure(model.last_failure or "unknown")`、検査で落ちたら `Failure("invalid_answer")` を返す。`severity_summaries` も同じ規則で理由を集める。`FakeModel` と `RecordingModel` は `last_failure` を持ち、答えを返すたびに設定する。

- [ ] **Step 4: 通ることを確かめる**

Run: `uv run pytest -q`
Expected: `sync.py` と `cli.py` が古い戻り値を使うテストが FAIL する場合がある。そのテストは Task 2 と Task 3 で直すので、ここでは `tests/test_bedrock.py` と `tests/test_report.py` の該当テストが PASS すればよい。`sync.fill_sections` は `isinstance(sections, Failure)` で失敗を扱うよう最小限直し、全件 PASS にする。`cli._build_report` は 1 つ目の要素だけを使うよう最小限直す。

- [ ] **Step 5: コミットする**

```bash
git add src/continuum_github/bedrock.py src/continuum_github/sync.py src/continuum_github/cli.py tests/fakes.py tests/test_bedrock.py tests/test_report.py
git commit -m "feat: return why the model could not write a section or summary"
```

### Task 2: issue の注記に理由を出す

**Files:**
- Modify: `src/continuum_github/render.py`（`FALLBACK_NOTE` → `fallback_note`、`issue_body`）
- Modify: `src/continuum_github/sync.py`（`fill_sections`）
- Test: `tests/test_render.py`、`tests/test_sync.py`

**Interfaces:**
- Consumes: `Failure`（Task 1）
- Produces:
  - `fallback_note(reason: str) -> str`
  - `safe_reason(reason: str) -> str`（`[A-Za-z0-9_]{1,64}` なら reason、そうでなければ `"unknown"`）
  - `issue_body(detection, state, sections, mention, failure: str | None = None) -> str`

- [ ] **Step 1: 失敗するテストを書く**

`tests/test_render.py`:

```python
def test_fallback_note_names_the_reason() -> None:
    assert fallback_note("content_filtered") == (
        "_Bedrock could not write the Summary, Why it matters, and Risk if left "
        "unresolved sections (`content_filtered`), so this issue shows the "
        "scanner's details only. Each later sync tries again, and this note "
        "stays until one succeeds._"
    )
    assert "(`unknown`)" in fallback_note("a`b\nc")
    assert "(`unknown`)" in fallback_note("x" * 65)
```

`FALLBACK_NOTE` を使う既存のテストは `fallback_note("content_filtered")` と `failure="content_filtered"` に置き換える。`test_fallback_note_says_it_stays_until_a_sync_succeeds` は `fallback_note("x").endswith(...)` にする。

`tests/test_sync.py` の `test_fill_sections_rewrites_the_old_fallback_note_once` の後ろに足す。

```python
def test_fill_sections_rewrites_the_note_only_when_the_reason_changes() -> None:
    detection = _det("k1")
    state = IssueState(
        source="pentest", target="weekly-x", keys=("k1",), finding_ids=("f1",), pentest_id="pt-1"
    )
    item = _issue_item(1, keys=("k1",))
    item["body"] = issue_body(detection, state, None, "", failure="content_filtered")
    pentest = FakePentest(scans={}, detections={"f1": detection})
    same = FakeGitHub(issues=[item])
    fill_sections(TARGETS, same, pentest, FakeCodeVuln(), FakeCodeReview(), FakeModel(None, "content_filtered"))
    assert same.bodies == {}
    changed = FakeGitHub(issues=[item])
    fill_sections(TARGETS, changed, pentest, FakeCodeVuln(), FakeCodeReview(), FakeModel(None, "ThrottlingException"))
    assert fallback_note("ThrottlingException") in changed.bodies[1]
    assert fallback_note("content_filtered") not in changed.bodies[1]
```

旧注記のテストは `FakeModel(None, "content_filtered")` を使い、書き直された本文に `fallback_note("content_filtered")` が 1 回あることを確かめる形にする。

- [ ] **Step 2: 失敗を確かめる**

Run: `uv run pytest -q tests/test_render.py tests/test_sync.py`
Expected: `fallback_note` を import できず収集エラー

- [ ] **Step 3: 実装する**

`render` に `safe_reason` と `fallback_note` を足し、`FALLBACK_NOTE` を消す。`issue_body` は `failure` が `None` でなければ `fallback_note(failure)` を入れる。`fill_sections` は `Failure` を受けたら `fallback_note(sections.reason)` が本文になければ書き直す。

- [ ] **Step 4: 通ることを確かめる**

Run: `uv run pytest -q`
Expected: 全件 PASS

- [ ] **Step 5: コミットする**

```bash
git add src/continuum_github/render.py src/continuum_github/sync.py tests/test_render.py tests/test_sync.py
git commit -m "feat: name the reason in the note of an issue the model could not fill"
```

### Task 3: 週次レポートの注記に理由を出す

**Files:**
- Modify: `src/continuum_github/report.py`（`build_visual_report`、`unavailable_parts`）
- Modify: `src/continuum_github/cli.py`（`_build_report`、`_report_build`）
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: `severity_summaries`（Task 1）、`safe_reason`（Task 2）
- Produces:
  - `build_visual_report(model, data, skill_dir, out, runner=..., language=...) -> str | None`（書けたら `None`、書けなければ理由）
  - `unavailable_parts(data, summaries, failures: Mapping[Severity, str], html_failure: str | None) -> list[str]`
  - `cli._build_report(settings, targets, model) -> tuple[WeeklyData, dict[Severity, str], dict[Severity, str]]`

- [ ] **Step 1: 失敗するテストを書く**

`build_visual_report` の既存テストの `is True` を `is None` にし、`is False` を理由との比較にする。描画が 2 回とも失敗するテストは `== "render_failed"`、モデルが答えないテストは `RecordingModel([None], failures=["content_filtered"])` で `== "content_filtered"`、node が動かないテストは `== "render_failed"`。

`unavailable_parts` の 2 つのテストを次に置き換える。

```python
def test_unavailable_parts_names_each_part_with_its_reason() -> None:
    parts = unavailable_parts(
        TWO_SEVERITIES,
        {Severity.MEDIUM: "s"},
        {Severity.HIGH: "content_filtered"},
        "render_failed",
    )
    assert parts == ["High summary (`content_filtered`)", "Visual report (`render_failed`)"]
    both = {Severity.HIGH: "h", Severity.MEDIUM: "m"}
    assert unavailable_parts(TWO_SEVERITIES, both, {}, None) == []
    assert unavailable_parts(TWO_SEVERITIES, both, {}, "a`b") == ["Visual report (`unknown`)"]
    assert unavailable_parts(TWO_SEVERITIES, {Severity.MEDIUM: "s"}, {}, None) == ["High summary"]
```

`_build_report` を差し替えるテストは 3 つ組を返す形にし、`build_visual_report` を差し替えるテストは `None`（成功）か理由を返す形にする。理由付きの注記が本文の最後に出ることを確かめる CLI のテストを 1 つ足す（`_build_report` は `(data, {}, {Severity.HIGH: "content_filtered"})`、`build_visual_report` は `"render_failed"` を返す）。

- [ ] **Step 2: 失敗を確かめる**

Run: `uv run pytest -q tests/test_report.py`
Expected: 書き換えたテストが FAIL

- [ ] **Step 3: 実装する**

`build_visual_report` は、モデルが答えなければ `model.last_failure or "unknown"` を返し、描画が 2 回とも失敗したら `"render_failed"` を返す。成功なら `None`。`unavailable_parts` は理由があれば `safe_reason` を通して `` (`reason`) `` を付ける。`cli._report_build` は `html = html_failure is None` として出力の `html=` を保つ。

- [ ] **Step 4: 通ることを確かめる**

Run: `uv run pytest -q`
Expected: 全件 PASS

- [ ] **Step 5: コミットする**

```bash
git add src/continuum_github/report.py src/continuum_github/cli.py tests/test_report.py
git commit -m "feat: name the reason for each part the weekly report lacks"
```

### Task 4: 文書、検証、マージ

**Files:**
- Modify: `README.md`（注記の例）、`docs/setup.md`（`model_failed` の説明）
- Move: spec と plan を `docs/superpowers/archive/` へ

- [ ] **Step 1:** README の issue 注記の例を `fallback_note("content_filtered")` と同じ文にし、setup.md の `model_failed` の説明に「同じ理由が注記にも括弧で出る」ことを足す。
- [ ] **Step 2:** `uv run pytest -q` と pre-commit を通す。Expected: どちらも成功。コミットは `docs: show the failure reason in the note examples`。
- [ ] **Step 3:** 最も能力の高いモデルのレビュアーにブランチ全体を見てもらい、Critical と Important を直す。
- [ ] **Step 4:** main に `--no-ff --no-commit` でマージし、同じコミットで spec と plan をアーカイブに移す。マージ後に `uv run pytest -q` を通す。push はしない。
