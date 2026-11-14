# ビジュアルレポートの言語の変数化 設計

## 目的

`report` アクションは、ビジュアルレポート（HTML）を日本語で書くようにモデルへ指示している。公開ツールとしては、利用者が言語を選べるほうがよい。所有者は、言語を `ja_JP` のような形式の変数で渡したい。

## ゴール

- `report` アクションの入力 `report-language` で、ビジュアルレポートの言語を選べる。値は `ja_JP` や `en_US` のようなロケールの形式で、既定は `en_US`。
- ファイル名、アーティファクト、レポート本文の行から「Japanese」と `ja` をなくす。

## 非ゴール

- issue の 3 つの節と重大度ごとの要約の言語。今のまま英語で書く（所有者が A を選んだ）。
- ロケールから言語名への対応表。モデルはロケールの形式を理解するので、値をそのままプロンプトに入れる。

## アプローチ

| 案 | 内容 | 評価 |
|---|---|---|
| A（採用） | ビジュアルレポートだけを変数の言語で書く | issue と週次レポートの本文は英語の見出しとそろったまま、読みたいまとめを HTML に寄せられる |
| B | モデルが書く文章すべてを変数の言語で書く | 英語の見出しの下に別の言語の本文が並ぶ |

所有者は A を選び、値の形式を `ja_JP` のようなロケールにすると決めた。

## 決まった構成

- `report` アクションに入力 `report-language`（既定 `en_US`）を足し、環境変数 `REPORT_LANGUAGE` で `continuum-scan report build` に渡す。`sync` アクションには足さない。
- `continuum-scan` は `REPORT_LANGUAGE` が空なら `en_US` を使う。呼び出し側が未設定の変数を渡すと空になるからだ。値は `^[a-z]{2,3}(_[A-Z]{2})?$` に合わなければ設定の読み込みで `ValueError` にする。値はプロンプトに入るので、形式を絞って任意の文を入れられないようにする。
- ビジュアルレポートのプロンプトの「in Japanese」と「write all prose in Japanese」を、ロケールを示す文に置き換える。例: `in the language of the locale ja_JP`。あわせて、ページの `<html>` に `lang` 属性（`_` を `-` にした値、例 `ja-JP`）を付けるよう指示する。
- ファイル名を `report.ja.html` から `report.html` にする。アップロードの手順のパスも同じく変える。
- レポート本文の行を `Japanese visual report: <url>` から `Visual report: <url>` にし、フォールバックの注釈の項目名も `Visual report` にする。
- README、`docs/setup.md`、アクションの説明から「Japanese visual report」をなくし、`report-language` を入力の表に足す。例の `report.yml` は `report-language: ${{ vars.REPORT_LANGUAGE }}` を渡す。
- 既定の言語が日本語から英語に変わり、ファイル名も変わるので、`v0.3.0` として出す。`docs/setup.md` の v0.1 からの移行の注記に、v0.2 以前から上げる利用者は日本語を保つなら `REPORT_LANGUAGE=ja_JP` を設定する、と足す。リリースは今までと同じく、所有者の確認を取って `make release-minor` で出す。
- security-findings 側（`report-language: ${{ vars.REPORT_LANGUAGE }}` を渡し、リポジトリ変数 `REPORT_LANGUAGE=ja_JP` を設定し、README と AGENTS.md の「Japanese visual report」を直す）は、security-findings の `2026-11-14-bedrock-rollout.md` の Task 2 と Task 3 に足す。

## エージェントの判断

- 入力名は `report-language` にした。値の形式は所有者が決めた。
- 本文の行には言語を入れなかった。HTML を開けば言語はわかり、行に入れると `render_weekly` と注釈の関数にロケールを渡す必要が出るからだ。
- 正規表現は、`ja`、`ja_JP`、`zh_TW`、`fil_PH` を許し、`ja-JP` や `Japanese` を拒む。

## ビルダーに任せること

- プロンプトの正確な文面。
- テストの名前。
