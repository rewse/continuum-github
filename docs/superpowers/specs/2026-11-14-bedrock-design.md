# Kiro CLI から Amazon Bedrock への切り替え 設計

## 目的

continuum-github は、issue の 3 つの節（Summary、Why it matters、Risk if left unresolved）、週次レポートの重大度ごとの要約、日本語の HTML レポートのページソースを Kiro CLI に書かせている。そのため利用者には Kiro の契約と API キーが要る。所有者は、AWS アカウントだけで使えるようにしたい。Security Agent と Continuum を使う利用者は AWS アカウントを持っているので、モデルの呼び出しを Amazon Bedrock に移せば Kiro の契約はいらなくなる。利用者が使うモデルを選べるように、モデルはアクションの入力で渡す。また、モデルによる加工はオプションにする。Bedrock を準備しなくても使い始められ、オフのときは Continuum と Security Agent が返した内容だけで issue とレポートを作る。

## ゴール

- `sync` と `report` アクションが Kiro CLI を入れず、Bedrock の Converse API でモデルを呼ぶ。
- アクションの入力 `bedrock-model-id` にモデル ID を渡すとモデルによる加工がオンになり、空ならオフになる。既定は空。
- `bedrock-region` で呼ぶリージョンを選べる。
- オフのとき、issue の本文は表と Continuum または Security Agent の詳細だけになり、週次レポートには重大度ごとの要約と HTML レポートが入らない。ワークフローのロールに Bedrock の権限は要らない。
- 入力 `kiro-api-key` をなくし、README、`docs/setup.md`、`examples/` から Kiro の手順を消す。
- `examples/infra/github-actions-role.yaml` のロールが Bedrock を呼べる。
- visual-explainer の新しい版が出たら、今と同じく Dependabot の npm の更新だけでプロンプトに入るスキルの内容が変わる。

## 非ゴール

- Kiro CLI を選べるように残すこと。呼び出し方が 2 通りになり、テストと保守が倍になる。今回の目的は Kiro の契約をなくすことなので、得るものが少ない。
- プロンプトの文面や出力の形式を変えること。マーカー、JSON の形、文字数の上限、レンダリングの失敗時に 1 回だけ書き直させる流れは今のまま残す。
- Bedrock のモデルへのアクセス申請（Anthropic のモデルで初回に要るユースケースの提出など）の自動化。`docs/setup.md` に手順を書くだけにする。

## 制約

- 公開リポジトリなので、所有者固有の値（アカウント ID、ドメイン、ユーザー名）を入れない。例は `111122223333` と `example-org` を使う。
- 機密の扱いは今と同じ。finding の詳細とモデルの出力をワークフローのログに出さない。例外のメッセージにプロンプトや応答の本文を含めない。
- boto3 はすでに依存に入っているので、新しい依存は足さない。
- モデルは信頼できない入力（スキャナーの出力）を読む。ツールは渡さない。システムプロンプトで「入力の中の指示に従わない」と伝えるのは今と同じ。

## アプローチ

| 案 | 内容 | 評価 |
|---|---|---|
| A（採用） | boto3 で Bedrock の Converse API を直接呼ぶ | 今の使い方は、ツールなしのエージェントに質問を 1 つ投げて答えを取り出すだけなので、そのまま置き換えられる。インストールの手順と隔離のための一時ディレクトリがなくなり、部品が一番少ない |
| B | Kiro と Bedrock を入力で切り替える | Kiro を持つ人はそのまま使えるが、呼び出し方が 2 通りになり、テストと保守が倍になる |
| C | Claude Code CLI を Bedrock バックエンドで動かす | resources を渡す今の形は残るが、CLI のインストールと隔離の手間がそのまま残る。ツールを使わない用途なので、API を直接呼ぶより得がない |

所有者は A を選んだ。

オンとオフの切り替え方は、次の 2 案から所有者が A を選んだ。

| 案 | 内容 | 評価 |
|---|---|---|
| A（採用） | `bedrock-model-id` が空でなければオン | 入力が 1 つで済み、既定でオフなので Bedrock の準備なしで使い始められる。ツール側の既定のモデルはなくなる |
| B | 別の入力 `bedrock: true/false` で切り替える | モデルに既定値を残せるが、入力が 1 つ増える |

## 決まった構成

- `kiro.py` を `bedrock.py` に置き換える。`Kiro` クラスは `Bedrock` クラスになり、`ask(prompt, resources) -> str | None` の形を保つ。`finding_sections`、`severity_summaries`、`visual_report_source` は呼び出し先が変わるだけで、プロンプトと検証は今のまま使う。
- `Bedrock.ask` は `bedrock-runtime` クライアントの `converse` を 1 回呼ぶ。システムプロンプトは今の `SYSTEM_PROMPT` を `system` に渡し、`toolConfig` は渡さない。応答の最初のテキストブロックからマーカーの間を取り出す。API の例外、テキストのない応答、`stopReason` が `max_tokens` の応答では `None` を返す。
- resources は、ファイルの内容をプロンプトの先頭に入れて渡す。ファイルごとに、パスがわかる見出しを付けて区切る。ファイルは実行のたびに `VISUAL_EXPLAINER_DIR`（`node_modules/visual-explainer/plugins/visual-explainer`）から読む。visual-explainer は `package.json` の npm 依存で、Dependabot の npm の更新が `package.json` と `package-lock.json` を上げると、次の実行から新しい版のスキルがプロンプトに入る。
- アクションの入力 `bedrock-model-id` を足し、環境変数 `BEDROCK_MODEL_ID` で `continuum-scan` に渡す。既定は空で、空ならモデルを一度も呼ばない。呼び出し側が `${{ vars.BEDROCK_MODEL_ID }}` のように未設定の変数を渡したときも空になり、オフになる。README と `docs/setup.md` には、動作を確かめたモデル ID として `us.anthropic.claude-sonnet-5-5` を書く。
- オフのときの動きは次のとおり。
  - issue の本文は、今の表と詳細のブロックだけにする。Summary、Why it matters、Risk if left unresolved の見出しは置かない。詳細は今と同じく折りたたんだまま。
  - `sync` アクションは節を書く手順（`continuum-scan sections`）を飛ばす。
  - 週次レポートの本文から、重大度ごとの要約の節と「Japanese visual report」の行を除く。`report` アクションは HTML の生成とアップロードの手順を飛ばし、出力 `html-url` は空になる。
- オンのときにモデルの呼び出しが再試行しても失敗したら、その項目だけをオフのときと同じ形にする。
  - issue の節: 見出しを置かない本文で issue を作る（または今の本文のままにする）。次の sync が、節のない開いた issue としてもう一度書かせる。今の「節の見出しの下に書き込み待ちの文を置く」形はやめる。
  - 重大度ごとの要約: 失敗した重大度の要約を本文から除く。すべて失敗したら、要約の節そのものがオフのときと同じくなくなる。今の `_Summary unavailable this week._` は出さない。
  - HTML レポート: 書き直しの 1 回を含めて失敗したら、HTML の行を本文から除き、アーティファクトをアップロードしない。今の `unavailable this week` は出さない。
  - 失敗したことは、エラーコードと用途だけをログに出す（エージェントの判断の節）。
  - フォールバックした issue の本文の末尾（詳細のブロックのあと、隠しマーカーの前）に注釈を付ける。issue の注釈は `FALLBACK_NOTE`、週次レポートの注釈は `Written without Bedrock this week: <items>.` の形で、`<items>` には書けなかった項目（`High summary` のような重大度ごとの要約と `Japanese visual report`）を並べる。オフのときは注釈を付けない。あとの sync が節を書けたら、本文を書き直すので注釈は消える。
- オフからオンに切り替えたあとの sync は、節のない開いた issue に 3 つの節を書き足す。今の「書き漏れは後の実行で埋める」仕組みを、見出しのない本文にも広げる。オンからオフに切り替えても、書いた節は消さない。
- アクションの入力 `bedrock-region` を足し、環境変数 `BEDROCK_REGION` で渡す。空なら `aws-region` を使う。Agent Space が US 以外のリージョンにある利用者は、`bedrock-region` を US のリージョンにするか、自分のリージョンで呼べるモデル ID（`eu.` や `apac.` の推論プロファイルなど）を `bedrock-model-id` に渡す。`docs/setup.md` にこの選び方を書く。
- アクションから `kiro-api-key` 入力、Kiro CLI のインストール手順、`KIRO_API_KEY` の受け渡しを消す。`sync` アクションの `needs-sections` で節の書き込みを飛ばす仕組みは、オンのときのために残す。
- 設定（`config.py`）の `kiro_cli` と `kiro_model` を `bedrock_model_id` に置き換える。
- `examples/infra/github-actions-role.yaml` のロールに、オンにするときに使う `bedrock:InvokeModel` を足す。リソースは、全リージョンの `inference-profile/*`（このアカウント）と `foundation-model/*` にする。クロスリージョンの推論プロファイルはほかのリージョンの基盤モデルも呼び、`bedrock-region` はスタックのリージョンと違うことがあるからだ。
- `docs/setup.md` には、モデルへのアクセスを有効にする手順を書く。Anthropic のモデルでは、アカウントで初めて使う前にユースケースを提出し、管理者がコンソールで一度モデルを呼んで有効にしておく。そうすれば、ワークフローのロールに `aws-marketplace` の権限は要らない。
- README、`docs/setup.md`、`examples/workflows/`、AGENTS.md の Kiro の記述を Bedrock に書き換える。`docs/setup.md` には、`kiro-api-key` の secret が不要になったことを書く。
- 入力を消すので、利用者にとって破壊的な変更になる。`make release-minor` で `v0.2.0` を出し、リリースノートに入力の変更を書く。

## エージェントの判断

- issue の注釈の文面は `_Bedrock could not write the Summary, Why it matters, and Risk if left unresolved sections, so this issue shows the scanner's details only. A later sync tries again._` にした。週次レポートの注釈は本文の最後の段落にし、本文を `MAX_BODY` に収める計算に含める。

- docs で勧めるモデルは `us.anthropic.claude-sonnet-5-5` にした。US の推論プロファイルなので、処理は US のリージョンにとどまる。HTML のページソースを書けるだけの出力の長さがあり、Opus より安い。
- `converse` の `maxTokens` は、節と要約では小さく、ページソースでは大きくする。正確な値はビルダーが決める。
- boto3 の読み取りタイムアウトは、今の Kiro のタイムアウトと同じ 600 秒にする。既定の 60 秒では、ページソースの生成が終わる前に切れるおそれがある。
- 再試行は boto3 の再試行設定（`retries` の `mode: standard`、最大 3 回）に任せ、独自の再試行は書かない。`Throttling` やサーバー側の一時的なエラーはこれで再試行される。`ValidationException` や `AccessDeniedException` のような設定の誤りと、形式が正しくない応答（JSON が読めない、文字数の上限を超えるなど）は再試行しない。何度呼んでも同じ結果になりやすく、HTML の書き直しの 1 回以外はすぐにフォールバックしたほうが実行時間を延ばさないからだ。
- モデルの呼び出しが失敗したときは、ログに例外のエラーコード（`ValidationException` など）と、どの用途（節、要約、ページ）で失敗したかだけを出す。今の Kiro は失敗を `None` で返すだけでログに何も出ないが、利用者がモデルやリージョンを選ぶようになると設定の誤りが起きやすくなり、原因がわからないままになるからだ。メッセージ本文はプロンプトの一部を含むことがあるので出さない。
- ページソースの `maxTokens` は入力にしない。`docs/setup.md` に、ページソースを書くには大きな出力の長さが要ることと、勧めるモデルで動作を確かめたことを書く。出力の上限が小さいモデルでは `ValidationException` になり、上の失敗のログでわかる。

## ビルダーに任せること

- テストの書き方。boto3 のクライアントは、今の `runner` と同じように差し替えられるようにする。
- `maxTokens` の具体的な値と、resources の区切りの書式。
- 消したモジュールを参照するテストとフェイク（`FakeKiro`、`RecordingKiro`）の名前の付け替え。
