# `_retry_delay` の後片付け 実装計画

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `_retry_delay` に現在時刻を注入し、有限でない値と tzinfo のない日付を正しく扱い、過去の日付のテストを足す。

**Architecture:** `GitHub.__init__` に `now` を足して `_retry_delay` に渡す。`_seconds_until` と reset の読み取りで `math.isfinite` を確かめ、naive な日付を UTC とみなす。

**Tech Stack:** Python 3、pytest、httpx、email.utils、math

**Spec:** `docs/superpowers/specs/2026-11-15-retry-delay-cleanup-design.md`

## Global Constraints

- 作業ブランチは main から切った `fix/retry-delay-cleanup`。push とリリースはしない。
- コメント、コミットメッセージは英語。コミットは Conventional Commits。
- 最後に `uv run pytest -q` と `uvx --with pre-commit-uv==4.3.0 pre-commit@4.6.2 run --all-files` を通す。

## Review Focus

- `cli.py` の `GitHub(client, repository)` は引数を変えずに動くこと。既存のテストで確かめる。
- 書き込みペースは今までどおり `clock`（monotonic）を使うこと。既存の `test_consecutive_posts_are_paced` で確かめる。

---

### Task 1: `now` の注入と読めない値

**Files:**
- Modify: `src/continuum_github/github.py`（`_seconds_until`、`_retry_delay`、`GitHub.__init__`、`GitHub._request`）
- Test: `tests/test_github.py`

**Interfaces:**
- Produces: `GitHub.__init__(..., now: Callable[[], float] = time.time)`、`_retry_delay(response: httpx.Response, now: Callable[[], float]) -> float`

- [ ] **Step 1: テストのヘルパーを変える**

`_FakeTime` に `wall: float = 0.0` の属性と、`wall + 経過時間` を返す `now(self) -> float` を足す。`_paced_github` は `now=fake.now` を渡す。`time.time` を monkeypatch している 4 つのテストは、`fake.wall` に同じ値を入れる形に書き換える。

- [ ] **Step 2: 失敗するテストを書く**

```python
def _sleeps_after(headers: dict[str, str], wall: float = 5000.0) -> list[float]:
    fake = _FakeTime(wall=wall)
    answers = [httpx.Response(429, headers=headers), httpx.Response(200, json=[])]
    _paced_github(lambda request: answers.pop(0), fake).issues()
    return fake.sleeps


def test_a_past_http_date_still_waits_one_second() -> None:
    # 70 seconds after the date.
    headers = {"Retry-After": "Sun, 06 Nov 1994 08:49:37 GMT"}
    assert _sleeps_after(headers, wall=784111847.0) == [1.0]


@pytest.mark.parametrize(
    "headers",
    [
        {"Retry-After": "nan"},
        {"Retry-After": "inf"},
        {"Retry-After": "-inf"},
        {"X-RateLimit-Reset": "nan"},
    ],
)
def test_a_non_finite_wait_falls_back_to_60_seconds(headers: dict[str, str]) -> None:
    assert _sleeps_after(headers) == [60.0]


def test_an_asctime_retry_after_is_read_as_utc() -> None:
    # 30 seconds before the date, which is GMT like every HTTP date.
    headers = {"Retry-After": "Sun Nov  6 08:49:37 1994"}
    assert _sleeps_after(headers, wall=784111747.0) == [30.0]
```

`_FakeTime` は `__init__(self, wall: float = 0.0)` を持ち、`now()` は `wall` に `sleep` の合計を足した値を返す。

- [ ] **Step 3: 失敗を確かめる**

Run: `uv run pytest -q tests/test_github.py`
Expected: `GitHub` が `now` を受け付けず、`_paced_github` を使うテストが FAIL

- [ ] **Step 4: 実装する**

`GitHub.__init__` に `now` を足して `self._now` に入れ、`_request` は `_retry_delay(response, self._now)` を呼ぶ。`_retry_delay` は `now()` を 1 回だけ読む。`_seconds_until` は有限でない `float` を `None` にし、日付の `tzinfo` が `None` なら `replace(tzinfo=UTC)` してから `.timestamp()` を取る。reset も有限でなければ読めない扱いにする。

- [ ] **Step 5: 通ることを確かめる**

Run: `uv run pytest -q`
Expected: 全件 PASS

- [ ] **Step 6: コミットする**

```bash
git add src/continuum_github/github.py tests/test_github.py
git commit -m "fix: inject the wall clock into retry delays and reject non-finite waits"
```

### Task 2: 検証とマージ

- [ ] **Step 1:** `uv run pytest -q` と pre-commit を通す。
- [ ] **Step 2:** 利用側の `fix/waf-retry-delay-cleanup` と一緒に、最も能力の高いモデルのレビュアーに見てもらう。
- [ ] **Step 3:** main に `--no-ff --no-commit` でマージし、同じコミットで spec と plan を `docs/superpowers/archive/` に移す。
- [ ] **Step 4:** マージ後に `uv run pytest -q` を通す。push はしない。
