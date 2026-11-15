# `_retry_delay` の後片付け

## 目的

`2026-11-15-review-minors` の全体レビューで出た細かい指摘のうち、利用者が直すと決めた 3 つを、v0.4.1 の前に直す。

1. `_retry_delay` が引数の `clock` を受け取るのに使わず、`time.time()` を直接読んでいる。
2. `Retry-After: nan` が `float` として読めてしまい、`min(max(nan, 1.0), 900.0)` が `nan` のまま `time.sleep` に渡って `ValueError` になる。`inf` と `-inf` は今は上限と下限に収まるが、数値として意味をなさない値なので、`nan` と合わせて読めない扱いにする（設計者の判断）。asctime 形式の日付（`Sun Nov  6 08:49:37 1994`）は `parsedate_to_datetime` が tzinfo なしで返すので、`.timestamp()` がローカル時刻として読む。
3. 過去の日付の `Retry-After` が下限の 1 秒になることを確かめるテストがない。

## 方式

### 1. 現在時刻の注入

`GitHub.__init__` に `now: Callable[[], float] = time.time` を足し、`_retry_delay(response, now)` に渡す。`_retry_delay` は `time.time()` を読まない。利用側の WAF クライアントと同じ形になる。テストは `time.time` の monkeypatch をやめ、`_paced_github` から `now` を渡す。

### 2. 読めない値

`_seconds_until` は、`float` で読めた値が有限でなければ（`math.isfinite` が偽）読めない扱いにする。`X-RateLimit-Reset` も同じ扱いにする。日付として読めた値が tzinfo を持たなければ UTC とみなす（HTTP の日付は常に GMT）。

### 3. テスト

過去の日付の `Retry-After` は 1 秒待つテストを足す。`nan`、`inf`、asctime 形式のテストも足す。

## 対象外

- 切り詰めの位置がフェンスの途中になる場合の見た目と、長い 1 行が丸ごと消える件。実害がないので後回しにする。
- 利用側の WAF クライアントには 2 と 3 を同じように入れる（利用側の仕様）。1 は利用側ではすでに `now` を注入している。
