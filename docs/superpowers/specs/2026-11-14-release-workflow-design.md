# リリースの仕組み 設計

## 目的

continuum-github のリリースはタグを手で打つだけで、GitHub Release もなく、パッケージのバージョン（`pyproject.toml` の `0.1.0`）とタグ（`v0.1.1`）がずれている。所有者は enecoq-data-fetcher と同じリリースの仕組みを入れ、バージョン上げ、タグ、リリースノートを揃えたい。利用者は action を SHA で固定して Dependabot で更新するので、GitHub Release があれば Dependabot の PR にリリースノートが載る。

## ゴール

- `make release-patch|minor|major` 1 回で、バージョンを上げたコミットとタグが origin に届き、GitHub Release が作られる。
- パッケージのバージョンとタグが常に一致する。
- リリースノートは Conventional Commits から git-cliff で作る。

## 非ゴール

- PyPI への公開。配布は composite action だけにする（所有者の判断。分割の設計の非ゴールを引き継ぐ）。
- 自動のタグ付け（rewse/actions の `trufflehog-auto-tag.yml` のようなもの）。

## 制約

- `~/git/AGENTS.md` の GitHub 設定の規則に従う。`uses:` は SHA と `# vX.Y.Z` で固定し、`release.yml` の名前は変えない。`release.yml` を持つリポジトリにはタグのルールセット `Protect release tags` を付ける。
- パッケージをインストールする workflow は、先に Aikido Safe Chain を入れる。`[tool.uv] exclude-newer = "4 days"` が `uv build` の隔離されたビルド環境にも効く。
- 公開リポジトリなので、所有者固有の値を入れない。

## アプローチ

| 案 | 内容 | 評価 |
|---|---|---|
| A（採用） | enecoq-data-fetcher の仕組みから PyPI の公開を除いたもの | composite action だけを配る設計と合う。rewse/actions とも同じ形 |
| B | enecoq-data-fetcher と同じく PyPI にも公開する | 手元の setup が `uvx --from continuum-github` で済むが、Trusted Publishing の登録と `release` 環境が増え、分割の設計の非ゴールを変えることになる |

所有者は A を選んだ。

## 決まった構成

- バージョンは `src/continuum_scan/__init__.py` の `__version__` に置き、`pyproject.toml` は `dynamic = ["version"]` と `[tool.hatch.version] path` で読む。値は最新のタグに合わせて `0.1.1` から始める。
- `scripts/bump_version.sh` と `Makefile` は enecoq-data-fetcher のものを、`VERSION_FILE` のパスだけ変えて使う。main がクリーンで origin と同じときだけ、`chore: bump version to X.Y.Z` のコミットとタグを作り、`--push` で両方を 1 回の atomic push で送る。
- `.github/workflows/release.yml` は `v*` タグの push で動き、checkout（全履歴）、uv、Safe Chain、`uv build`、git-cliff のリリースノート、`gh release create --verify-tag`、`dist/*` の添付を行う。ジョブの権限は `contents: write` だけで、`id-token` と `environment` は持たない。
- `cliff.toml` は enecoq-data-fetcher のものを、比較 URL を `rewse/continuum-github` に変えて使う。
- タグのルールセット `Protect release tags` は `refs/tags/v*` の作成、更新、削除を制限し、リポジトリの admin ロールだけが例外になる。
- AGENTS.md に Releases の節を足し、`make release-*` は頼まれたときだけ実行すると書く。Confidentiality の節に残っている、削除済みの `tests/test_redaction.py` への言及を消す。
- テストは `release.yml` の形（タグのトリガー、権限、SHA の固定、`--verify-tag`）と、パッケージのバージョンが `__version__` から読めることを確かめる。

## エージェントの判断

- 既存のタグ `v0.1.0` と `v0.1.1` にも、git-cliff のリリースノートだけで GitHub Release を後から作る。両方のビルド物の中のバージョンは `0.1.0` なので、成果物は添付しない。
- 導入後の最初のリリースは `make release-patch` で `v0.1.2` を出す。ルールセットの作成と push は所有者の確認を取ってから行う。
- 利用者側（security-findings）のピンは、workflow 2 つと `pyproject.toml` の git 依存を同じ SHA にそろえて上げる。Dependabot の github-actions は workflow のピンしか上げず、3 か所の SHA を比べるテストで落ちるので、その PR は閉じて手で上げる。

## ビルダーに任せること

- テストの書き方とファイル名。
- 後付けの GitHub Release を作る具体的なコマンド。
