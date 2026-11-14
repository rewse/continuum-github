# パッケージ名と CLI 名の統一、global 推論プロファイルへの切り替え

## 目的

配布名は `continuum-github` なのに、import 名は `continuum_scan`、CLI 名は `continuum-scan` のままになっている。これは分割前の `rewse/continuum` の名前を引き継いだだけで、意図した名前ではない。三つを `continuum-github` 系に揃え、名前からリポジトリとツールが対応して見えるようにする。

あわせて、例と推奨のモデル ID を `us.anthropic.claude-sonnet-5-5` から `global.anthropic.claude-sonnet-5-5` に置き換える。所有者は global の推論プロファイルを使いたい。

## ゴール

- import 名を `continuum_github`、CLI 名を `continuum-github` にする。
- 旧 CLI 名 `continuum-scan` は残さない。
- continuum-github と security-findings の文書、例、計画にあるモデル ID を `global.anthropic.claude-sonnet-5-5` に置き換える。

## 非ゴール

- issue の状態マーカー `<!-- continuum-state: ... -->`、ラベル、環境変数（`CONTINUUM_LANGUAGE` など）の名前は変えない。マーカーを変えると、既存の issue を sync が読めなくなる。
- アーカイブ済みの spec と plan、security-findings にある完了済みの spec と plan は書き換えない。
- IAM のリソース指定は変えない。`inference-profile/*` と `bedrock:*::foundation-model/*` は、global のルーティングが認可を求めるリージョンなしの `arn:aws:bedrock:::foundation-model/...` も含む。`iam simulate-custom-policy` で allowed になることを確かめてある。
- 文書に、リージョンごとの推論プロファイルの使い分けの説明は足さない。`us.` についての説明は消し、ID を置き換えるだけにする。

## アプローチ

| 案 | 内容 | トレードオフ |
|---|---|---|
| A（採用） | `continuum-scan` を消し、`continuum-github` だけにする | 古い手順で `continuum-scan` を打つと失敗する。利用者はほぼ所有者だけなので、影響は小さい |
| B | `continuum-scan` を 1 リリースだけ別名として残す | 古い手順でも動くが、エントリポイントが二つになり、あとで消す手間が残る |

所有者は A を選んだ。

## continuum-github の変更

- `src/continuum_scan/` を `src/continuum_github/` に移し、`src` と `tests` の import をすべて書き換える。
- `pyproject.toml` の `[project.scripts]` を `continuum-github = "continuum_github.cli:main"` にし、`packages` と version の path を新しいディレクトリに向ける。`scripts/bump_version.sh` の `VERSION_FILE` も同じく直す。
- `sync/action.yml` と `report/action.yml` で `continuum-scan` を呼んでいるところを `continuum-github` にする。
- `README.md`、`docs/setup.md`、`AGENTS.md`、`examples/infra/*.yaml` のコメントと説明にある CLI 名を書き換える。`examples/infra/github-actions-role.yaml` のインラインポリシー名 `continuum-scan` も `continuum-github` にする。
- `sync/action.yml` と `report/action.yml` の入力の説明、`README.md` の入力の表、`docs/setup.md` の `gh variable set BEDROCK_MODEL_ID` と推奨モデルの文にあるモデル ID を `global.anthropic.claude-sonnet-5-5` にする。`docs/setup.md` の `us.` 推論プロファイルについての文は消す。
- CLI 名が変わるのは破壊的な変更なので、v0.4.0 として出す。発行は所有者の指示を待つ。リリースノートは git-cliff がコミットから作るので、CLI 名を変えるコミットは `refactor!:` にし、`BREAKING CHANGE:` フッターで新しい CLI 名を示す。

## security-findings の変更

security-findings のピンはまだ v0.1.2 で、bedrock-rollout は始まっていない。所有者の判断で、bedrock-rollout は v0.4.0 の発行まで待ち、v0.3.0 を飛ばして v0.4.0 に直接ピンする。切り替えを 1 回で済ませるためである。

- bedrock-rollout の spec と plan を v0.4.0 向けに直す。v0.3.0 と書いてあるところを v0.4.0 にし、モデル ID を `global.anthropic.claude-sonnet-5-5` にする。
- `infra/template.yaml` のインラインポリシー名 `continuum-scan` は、bedrock-rollout の Task 1（`bedrock:InvokeModel` の追加）と同じデプロイで `continuum-github` にする。Task 1 の確認手順の `--policy-name` も `continuum-github` にする。
- v0.4.0 にピンする Dependabot の PR には何も足さずに merge する。そのあとのコミットで、`README.md`、`AGENTS.md`、`docs/setup.md`、`infra/template.yaml` のコメントにある CLI 名を `continuum-github` にし、`tests/test_docs.py` の期待値も合わせる（実装者の判断）。ワークフローは action の中から CLI を呼ぶので、merge からこのコミットまでの間も壊れない。コメントだけの変更なので、テンプレートのデプロイはいらない。このコミットは、bedrock-rollout でワークフローに `bedrock-model-id` と `language` を足すコミットと一緒にしてよい。
- WAF plan にあるモデル ID と、fox の `cloudfront_waf_report_bedrock_model_id` の既定値を `global.anthropic.claude-sonnet-5-5` にする。
- リポジトリ変数 `BEDROCK_MODEL_ID` を `global.anthropic.claude-sonnet-5-5` に変える。外部への書き込みなので、変える前に所有者に確認する。

## 実装者に任せること

- import の書き換えの手段（`git mv` と一括置換など）
- コミットの分け方
