# 全体レビューで先送りにした指摘の修正 実装計画

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 切り詰めでコードスパンが割れないようにし、GitHub クライアントの待ち時間の扱いを直す。

**Architecture:** `render` に行の境目で切る `_cut_at_line` を足し、`issue_body` と `fit_body` で使う。`github._retry_delay` に日付形式の `Retry-After` と 1 秒の下限を足す。

**Tech Stack:** Python 3、pytest、httpx、email.utils

**Spec:** `docs/superpowers/specs/2026-11-15-review-minors-design.md`

## Global Constraints

- 作業ブランチは main から切った `fix/review-minors`。push とリリースはしない。
- コメント、コミットメッセージは英語。コミットは Conventional Commits。
- 各タスクの終わりに `uv run pytest -q` を通す。最後に `uvx --with pre-commit-uv==4.3.0 pre-commit@4.6.2 run --all-files` を通す。

## Review Focus

- 切り詰めの後も状態マーカーが読めること。Task 1 のテストで確かめる。
- `fit_body` が既に `… (truncated)` で終わる本文をさらに切っても、印が 1 つだけであること。既存の `test_fit_body_*` が通り続けることで確かめる。
- 日付形式の `Retry-After` が過去なら下限の 1 秒になること。Task 2 のテストで確かめる。
- サーバーエラーの扱いを変えないこと。continuum-github のクライアントはサーバーエラーを再試行しないので、変更はない。

---

### Task 1: 行の境目で切り詰める

**Files:**
- Modify: `src/continuum_github/render.py`（`issue_body`、`fit_body`）
- Test: `tests/test_render.py`

**Interfaces:**
- Produces: `_cut_at_line(text: str, room: int) -> str`（`render` の非公開関数）。`text[:room]` のうち最後の `\n` か `\r` までを返し、なければ空文字列を返す。

- [ ] **Step 1: 失敗するテストを書く**

```python
def test_body_truncation_never_splits_a_code_span() -> None:
    long_span = "`@alice " + "x" * 70000 + "`"
    for text in (long_span, "keep @bob\n" + long_span):
        huge = replace(PENTEST_HIGH, details=(("Description", text),))
        body = issue_body(huge, initial_state(huge), None, "")
        assert len(body) <= 65536
        assert "@alice" not in body
        assert "… (truncated)" in body
        assert parse_state(body) == initial_state(huge)
    body = issue_body(
        replace(PENTEST_HIGH, details=(("Description", "keep @bob\n" + long_span),)),
        initial_state(PENTEST_HIGH),
        None,
        "",
    )
    assert "keep @&#8203;bob\n… (truncated)" in body


def test_fit_body_never_splits_a_code_span() -> None:
    text = "a\n`@alice " + "x" * 100 + "`"
    odd = replace(PENTEST_HIGH, details=(("Description", text),))
    body = issue_body(odd, initial_state(odd), None, "")
    fitted = fit_body(body, limit=len(body) - 50)
    assert len(fitted) <= len(body) - 50
    assert "@alice" not in fitted
    assert "a\n… (truncated)" in fitted
    assert parse_state(fitted) == initial_state(odd)
```

- [ ] **Step 2: 失敗を確かめる**

Run: `uv run pytest -q tests/test_render.py -k never_splits`
Expected: 2 件 FAIL（`@alice` が本文に残る）

- [ ] **Step 3: 実装する**

`_cut_at_line` を足し、`issue_body` の `inner[:room]` と `fit_body` の `inner[:room]` を `_cut_at_line(inner, room)` に置き換える。`fit_body` の docstring に、行の境目で切るのはコードスパンを割らないためだと書く。

- [ ] **Step 4: 通ることを確かめる**

Run: `uv run pytest -q`
Expected: 全件 PASS

- [ ] **Step 5: コミットする**

```bash
git add src/continuum_github/render.py tests/test_render.py
git commit -m "fix: truncate issue details only at a line break"
```

### Task 2: 日付形式の `Retry-After` と待ちの下限

**Files:**
- Modify: `src/continuum_github/github.py`（`_is_rate_limited`、`_retry_delay`）
- Test: `tests/test_github.py`

**Interfaces:**
- Consumes: なし
- Produces: なし

- [ ] **Step 1: 失敗するテストを書く**

`test_wait_is_capped_at_15_minutes` の後ろに足す。既存の `_FakeTime`、`_paced_github` を使う。

```python
def test_retry_after_as_an_http_date_waits_until_that_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeTime()
    # 1994-11-06 08:49:37 UTC
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
```

1 つ目のテストの `784111747.0` は 1994-11-06 08:49:07 UTC で、`Retry-After` の 30 秒前である。

- [ ] **Step 2: 失敗を確かめる**

Run: `uv run pytest -q tests/test_github.py`
Expected: 3 件 FAIL（60.0、60.0、0.0 を待つ）

- [ ] **Step 3: 実装する**

`_MIN_WAIT = 1.0` を足す。`_retry_delay` は、`Retry-After` を `float` で読み、だめなら `email.utils.parsedate_to_datetime(...).timestamp() - time.time()` で読む（`TypeError` と `ValueError` は読めない扱い）。読めなければ `X-RateLimit-Reset` から `time.time()` を引き、それも読めなければ `_DEFAULT_WAIT`。結果を `min(max(delay, _MIN_WAIT), _MAX_WAIT)` に収める。docstring を「Returns seconds to wait: Retry-After as seconds or an HTTP date, else the rate-limit reset, else 60, kept between 1 second and 15 minutes.」の趣旨にする。`_is_rate_limited` に、二次レート制限は `Retry-After` なしの 403 で来ることがあるので本文の message でも判定する、という docstring を付ける。

- [ ] **Step 4: 通ることを確かめる**

Run: `uv run pytest -q`
Expected: 全件 PASS

- [ ] **Step 5: コミットする**

```bash
git add src/continuum_github/github.py tests/test_github.py
git commit -m "fix: read an HTTP-date Retry-After and wait at least a second"
```

### Task 3: 検証とマージ

**Files:**
- Move: `docs/superpowers/specs/2026-11-15-review-minors-design.md` → `docs/superpowers/archive/specs/`
- Move: `docs/superpowers/plans/2026-11-15-review-minors.md` → `docs/superpowers/archive/plans/`

- [ ] **Step 1: 全体を検証する**

Run: `uv run pytest -q` と `uvx --with pre-commit-uv==4.3.0 pre-commit@4.6.2 run --all-files`
Expected: どちらも成功

- [ ] **Step 2: ブランチ全体をレビューに出す**

最も能力の高いモデルのレビュアーに `main...fix/review-minors` の差分を見てもらい、指摘を直す。

- [ ] **Step 3: main にマージし、同じコミットで spec と plan をアーカイブする**

```bash
git switch main
git merge --no-ff --no-commit fix/review-minors
git mv docs/superpowers/specs/2026-11-15-review-minors-design.md docs/superpowers/archive/specs/
git mv docs/superpowers/plans/2026-11-15-review-minors.md docs/superpowers/archive/plans/
git commit -m "Merge branch 'fix/review-minors'"
```

- [ ] **Step 4: マージ後に再検証する**

Run: `uv run pytest -q`
Expected: 全件 PASS。push はしない。
