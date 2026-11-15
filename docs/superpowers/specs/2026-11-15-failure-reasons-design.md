# モデルが書けなかった理由を注記に出す

## 目的

モデルが issue のセクションや週次レポートの一部を書けなかったとき、注記には「書けなかった」としか出ない。理由はワークフローのログ（`model_failed purpose=... reason=...`）にしかなく、`content_filtered` のように何度試しても通らない理由と、一時的な理由の区別が issue からはつかない。注記に理由を書き足す。利用者が、issue の注記と週次レポートの注記の両方に入れることを選んだ。v0.4.1 に入れるが、リリースは利用者の指示を待つ。

## 理由の値

ログに出しているのと同じ値を使う。

- stop reason（`content_filtered`、`max_tokens`、`guardrail_intervened` など）と `unknown_stop`
- 応答の形の問題（`no_text`、`no_markers`）
- 答えの中身の検査で落ちたもの（`invalid_answer`）
- AWS のエラーコード（`ThrottlingException` など）と botocore の例外のクラス名（`ReadTimeoutError` など）
- ビジュアルレポートの描画が 2 回とも失敗したとき（`render_failed`）

どれも固定の語か列挙値で、finding の内容を含まない。本文に入れる前に `[A-Za-z0-9_]{1,64}` に完全一致するかを確かめ、一致しなければ `unknown` にする。エラーコードは AWS が返す文字列なので、想定外の形が本文に入らないようにするためである。

## 理由の受け渡し

`Bedrock` は直前の `ask` が失敗した理由を `last_failure: str | None` に持つ。`ask` を呼ぶたびに最初に `None` に戻し、`log_failure` を呼ぶところで同じ値を入れる。`ModelLike` にも `last_failure` を足し、テストの `FakeModel` と `RecordingModel` は `None` 以外を返す手段を持つ。

- `finding_sections` は戻り値を `Sections | Failure` にする。`Failure` は `bedrock` に置く frozen dataclass で、`reason: str` だけを持つ。理由は `model.last_failure`、それが `None`（モデルは答えたが中身が検査で落ちた）なら `invalid_answer` にする。
- `severity_summaries` は `(summaries, failures)` を返す。`failures` は書けなかった severity から理由への dict である。
- `build_visual_report` は、書けたら `None`、書けなかったら理由を返す。モデルが答えなければその理由、描画が 2 回とも失敗したら `render_failed`、2 回目の依頼でモデルが答えなければそのときの理由にする。

## issue の注記

`FALLBACK_NOTE` を `fallback_note(reason: str) -> str` にし、次の形にする。

> _Bedrock could not write the Summary, Why it matters, and Risk if left unresolved sections (`content_filtered`), so this issue shows the scanner's details only. Each later sync tries again, and this note stays until one succeeds._

`issue_body` の `fallback: bool` は `failure: str | None` に変える。`fill_sections` は、本文に今回の理由の注記がそのまま含まれていなければ本文を書き直す。同じ理由で失敗し続ける issue には書き込まない。理由が変わったとき、および理由のない今の注記を持つ issue は、次に失敗したとき 1 回書き直される。

## 週次レポートの注記

`unavailable_parts` は、各部分の名前の後ろに理由を付ける。

> _Written without Bedrock this week: High summary (`content_filtered`), Visual report (`render_failed`)._

引数は `unavailable_parts(data, summaries, failures, html_failure)` にする。`failures` は `severity_summaries` が返したもの、`html_failure` は `build_visual_report` が返したものである。要約のない severity に理由がなければ（呼び出し側の誤り）、理由を付けずに名前だけを出す。

## 文書

README の注記の例を新しい形にし、setup.md の `model_failed` の説明に、同じ理由が注記にも出ることを書き足す。

## テスト

- `Bedrock.ask` が失敗の種類ごとに `last_failure` を設定し、成功すると `None` に戻すこと。
- `finding_sections` が `Failure("content_filtered")` と `Failure("invalid_answer")` を返すこと。
- 理由が `[A-Za-z0-9_]{1,64}` に一致しなければ注記に `unknown` が出ること。
- `fill_sections` が、同じ理由なら書き込まず、理由が変われば書き直すこと。理由のない旧注記も書き直すこと。
- `severity_summaries` と `build_visual_report` が理由を返し、週次レポートの注記にそれが出ること。

## 対象外

- WAF の issue。モデルを呼ばない。
- 理由ごとに再試行をやめる処理。`content_filtered` でも毎回試す今の動きは変えない。
