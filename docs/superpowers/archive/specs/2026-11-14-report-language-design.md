# モデルが書く文章の言語の変数化 設計

## 目的

モデルは、issue の 3 つの節と重大度ごとの要約を英語で、ビジュアルレポート（HTML）を日本語で書くよう指示されている。公開ツールとしては、利用者が言語を選べるほうがよい。所有者は、言語を `ja_JP` のような形式の変数で渡し、モデルが書く文章すべてをその言語にしたい。

## ゴール

- `sync` と `report` アクションの入力 `language` で、モデルが書く文章の言語を選べる。値は `ja_JP` や `en_US` のようなロケールの形式で、既定は `en_US`。
- 対象は、issue の 3 つの節、週次レポートの重大度ごとの要約、ビジュアルレポートの 3 つ。
- ファイル名、アーティファクト、レポート本文の行から「Japanese」と `ja` をなくす。

## 非ゴール

- コードが書く文字列の翻訳。issue の見出し（Summary、Why it matters、Risk if left unresolved）、表、状態のコメント、フォールバックの注釈、週次レポートの見出しと一覧は英語のまま。
- ロケールから言語名への対応表。モデルはロケールの形式を理解するので、値をそのままプロンプトに入れる。

## アプローチ

| 案 | 内容 | 評価 |
|---|---|---|
| A | ビジュアルレポートだけを変数の言語で書く | issue と週次レポートの本文は英語の見出しとそろったまま、読みたいまとめを HTML に寄せられる |
| B（採用） | モデルが書く文章すべてを変数の言語で書く | 英語の見出しの下に別の言語の本文が並ぶ |

所有者は最初に A を選び、そのあと B に変えた。英語の見出しの下に別の言語の本文が並ぶことは承知のうえで選んだ。値の形式は `ja_JP` のようなロケールにすると決めた。

## 決まった構成

- `sync` と `report` の両方のアクションに入力 `language`（既定 `en_US`）を足し、環境変数 `CONTINUUM_LANGUAGE` で `continuum-scan` に渡す。`sync` では節を書く手順（`continuum-scan sections`）に、`report` では `report build` の手順に渡す。
- `continuum-scan` は `CONTINUUM_LANGUAGE` が空なら `en_US` を使う。呼び出し側が未設定の変数を渡すと空になるからだ。値は `^[a-z]{2,3}(_[A-Z]{2})?$` に合わなければ設定の読み込みで `ValueError` にする。値はプロンプトに入るので、形式を絞って任意の文を入れられないようにする。
- 3 つのプロンプトの「in English」「in Japanese」「write all prose in Japanese」を、ロケールを示す文に置き換える。例: `in the language of the locale ja_JP`。
- 描画したあとの HTML の `<html>` の `lang` 属性を、コードでロケールの値（`_` を `-` にした値、例 `ja-JP`）にする。visual-explainer の描画が `<html>` を作り直すかどうかによらず確実に付けるため、モデルへの指示ではなく、`color_unstyled_svg_text` と同じ後処理にする。すでに `lang` があれば置き換える。
- 節と要約の文字数の上限（1,500 文字）は言語によらず同じにする。
- ファイル名を `report.ja.html` から `report.html` にする。アップロードの手順のパスも同じく変える。
- レポート本文の行を `Japanese visual report: <url>` から `Visual report: <url>` にし、フォールバックの注釈の項目名も `Visual report` にする。
- README、`docs/setup.md`、アクションの説明から「Japanese visual report」をなくし、`language` を入力の表に足す。例の `sync.yml` と `report.yml` は `language: ${{ vars.LANGUAGE }}` を渡す。
- 言語を変えても、すでに書いた節は書き直さない。新しい issue と、節がまだない issue だけが新しい言語になる。
- 既定のビジュアルレポートの言語が日本語から英語に変わり、ファイル名も変わるので、`v0.3.0` として出す。`docs/setup.md` の移行の注記に、v0.2 以前から上げる利用者でビジュアルレポートを日本語のままにしたいなら `LANGUAGE=ja_JP` を設定する、と足す。リリースは今までと同じく、所有者の確認を取って `make release-minor` で出す。
- security-findings 側（`language: ${{ vars.LANGUAGE }}` を両方の workflow で渡し、リポジトリ変数 `LANGUAGE=ja_JP` を設定し、README と AGENTS.md の「Japanese visual report」を直す）は、security-findings の `2026-11-14-bedrock-rollout.md` の Task 2 と Task 3 に足す。security-findings は `v0.2.0` を経由せず、`v0.3.0` のピンに一度で上げる。Dependabot の `v0.2.0` の PR は merge せず、`v0.3.0` が出たあとに Dependabot が同じ PR を `v0.3.0` に更新するのを待つ。

## エージェントの判断

- 入力名は、レポートだけでなく issue の節にも効くので `language` にした。リポジトリ変数の名前も `LANGUAGE` にそろえる。
- `continuum-scan` に渡す環境変数は `LANGUAGE` ではなく `CONTINUUM_LANGUAGE` にした。`LANGUAGE` は GNU gettext がメッセージの言語に使う変数で、同じ手順で動くほかのコマンドの出力を変えてしまうからだ。
- 本文の行には言語を入れなかった。HTML を開けば言語はわかり、行に入れると `render_weekly` と注釈の関数にロケールを渡す必要が出るからだ。
- 正規表現は、`ja`、`ja_JP`、`zh_TW`、`fil_PH` を許し、`ja-JP` や `Japanese` を拒む。

## ビルダーに任せること

- プロンプトの正確な文面。
- テストの名前。
