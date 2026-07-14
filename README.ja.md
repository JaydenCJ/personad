# personad

[English](README.md) | [中文](README.zh.md) | [日本語](README.ja.md)

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Go ≥1.22](https://img.shields.io/badge/go-%E2%89%A51.22-00ADD8)](go.mod) [![Version 0.1.0](https://img.shields.io/badge/version-0.1.0-informational)](CHANGELOG.md) ![Tests](https://img.shields.io/badge/tests-91%20passed-brightgreen) [![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](CONTRIBUTING.md)

**personad：開発と CI のためのオープンソースな決定論的フェイク OIDC プロバイダ — TOML でペルソナ定義、スナップショットテストできるバイト固定トークン、discovery/JWKS/PKCE 完備。デモ用ではなく、アサーションのために。**

![Demo](docs/assets/demo.svg)

```bash
git clone https://github.com/JaydenCJ/personad && cd personad
go build -o personad ./cmd/personad    # single static binary, stdlib only
```

> プレリリース：v0.1.0 はまだどのパッケージレジストリにも公開していません。上記の通りソースからビルドしてください（Go ≥1.22 なら可）。

## なぜ personad？

OAuth の統合テストはいずれ本物の IdP と戦うことになります：レート制限、期限切れのテストテナント、実行のたびに `iat`/`jti` が変わってスナップショット断言できないトークン、そしてヘッドレス CI ジョブの真ん中に立ちはだかるログイン画面。よくある代替策にはそれぞれ代償があります — mock-oauth2-server は優秀ですが、あらゆる Web プロジェクトの CI イメージに JVM を持ち込みます。Keycloak の dev モードは 600 MB のコンテナで、起動はテストスイートの実行より長い。手書きの JWT スタブは discovery/JWKS/PKCE を飛ばすので、まさにテストしたかったコードパス（issuer 検証、鍵ローテーション、verifier チェック）が未テストのまま残ります。personad は 6 MB の静的バイナリで、標準的なクライアントライブラリが code + PKCE フローを完走できるだけの本物の OIDC を話します — しかも端から端まで決定論的：署名鍵は設定の seed から導出、時計は凍結可能、claim の順序は固定。同じペルソナファイルはどのマシンでも永遠に同じトークンバイトを鋳造します。断言は `assertMatches` ではなく `assertEquals` で書けます。

| | personad | mock-oauth2-server | oauth2-mock-server (npm) | Keycloak dev モード |
|---|---|---|---|---|
| ランタイムの重さ | 6 MB 静的バイナリ | JVM | Node.js | JVM コンテナ |
| バイト固定トークンでスナップショットテスト | ✅ seed + 凍結時計 | ❌ 起動ごとにランダム鍵 | ❌ 起動ごとにランダム鍵 | ❌ |
| ペルソナがレビュー可能な設定 | ✅ TOML をリポジトリに | ⚠️ JSON/コードコールバック | ⚠️ コード | ⚠️ realm エクスポート JSON |
| Discovery + JWKS + PKCE (S256) | ✅ | ✅ | ✅ | ✅ |
| サーバなしでトークン鋳造（CLI） | ✅ `personad mint` | ❌ | ❌ | ❌ |
| refresh ローテーション・introspection・userinfo | ✅ | ✅ | ⚠️ 一部 | ✅ |
| ランタイム依存 | 0（Go 標準ライブラリ） | JVM + ライブラリ | npm パッケージ 4 個 | 数百 |

<sub>サイズは 2026-07-13 に確認：personad のバイナリは strip 済みで約 6 MB（`go build -ldflags "-s -w"`。未 strip では約 9 MB）。mock-oauth2-server は JRE（約 200 MB）か約 180 MB の Docker イメージが必要。Keycloak コンテナはタグにより約 430–600 MB。</sub>

## 特徴

- **TOML のペルソナ** — ユーザーはコードではなくデータ：subject・メール・グループ・任意のカスタム claim をテストの隣のレビュー可能なファイルに置き、キー名の打ち間違いは黙って誤ったトークンを鋳造せず即座に失敗するほど厳格に検証。
- **バイト固定のトークン** — 設定 seed から導出する Ed25519 鍵、固定の claim 順序、凍結された `issued_at`、導出される `jti`：同じファイルはどのマシンでも同じコンパクト JWT を生みます。personad 自身のテストにゴールデントークンが釘付けされ、ドリフトは破壊的変更扱い。
- **玄関一式** — `/.well-known/openid-configuration`、RFC 7638 kid 付き JWKS、HTML ペルソナ選択ページ付き認可コードフロー、PKCE（S256 + plain、パブリッククライアントには必須）、refresh ローテーション、client_credentials、userinfo、RFC 7662 introspection。
- **サーバなしで鋳造** — `personad mint` は ID/アクセストークンを stdout に直接出力、ユニットテストやフィクスチャに。`personad decode` は自分の発行したトークンを検証して整形表示。
- **正直なエラー、本物の拒否** — code の再利用、redirect URI の不一致、誤った verifier、クライアント跨ぎの引き換え、userinfo への id_token 送信 — すべて準拠 IdP と同じ形で失敗し、メッセージは間違いを名指しします。
- **構造からして安全** — ループバック以外へのバインドを拒否、テレメトリなし、ネットワーク呼び出しなし、依存ゼロ。personad が話す相手はあなたのテストスイートだけです。

## クイックスタート

```bash
go build -o personad ./cmd/personad
./personad mint --config examples/personas.toml --persona alice --client web-app
```

実際にキャプチャした出力 — 2 回実行して diff しても、同じバイトです：

```text
eyJhbGciOiJFZERTQSIsImtpZCI6ImZnSkc3TzYzcDRHblZ2bFdEbGc3b3JSNzJTeGFYZWM0UFlZMjNSaEN5ZE0iLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjkxMTEiLCJzdWIiOiJ1c2VyLWFsaWNlLTAwMSIsImF1ZCI6IndlYi1hcHAiLCJleHAiOjE3NjcyMjkyMDAsImlhdCI6MTc2NzIyNTYwMCwiYXV0aF90aW1lIjoxNzY3MjI1NjAwLCJlbWFpbCI6ImFsaWNlQGV4YW1wbGUudGVzdCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJncm91cHMiOlsiYWRtaW4iLCJkZXYiXSwiZGVwYXJ0bWVudCI6ImVuZ2luZWVyaW5nIiwibGV2ZWwiOjV9.eS_CBeCGZ2JR0Mtk1gZ0y3MXuEK4w_M-48mo3X913Q_tbQZtlOCg3N44ZS514RKY60Ovr-NKnh4PpEkdrFlQCw
```

続いて本物のプロバイダを起動し、アプリの OIDC クライアントを向けます：

```bash
./personad serve --config examples/personas.toml
```

```text
personad 127.0.0.1:9111 listening
issuer:    http://127.0.0.1:9111
discovery: http://127.0.0.1:9111/.well-known/openid-configuration
personas:  alice, bob
```

code + PKCE フローを完走し（curl 版は `examples/code-flow.sh`）、userinfo を叩く — 実際にキャプチャした出力：

```text
$ curl -s http://127.0.0.1:9111/userinfo -H "Authorization: Bearer $ACCESS"
{
  "sub": "user-alice-001",
  "email": "alice@example.test",
  "email_verified": true,
  "groups": [
    "admin",
    "dev"
  ],
  "department": "engineering",
  "level": 5
}
```

## ペルソナファイル

ペルソナファイルがトークンの全バイトを決定します。完全なリファレンスは [docs/persona-format.md](docs/persona-format.md)。要となるキー：

| キー | デフォルト | 効果 |
|---|---|---|
| `issuer` | 必須 | `iss` claim と全エンドポイントの基底 URL（末尾スラッシュなし） |
| `seed` | 必須 | Ed25519 署名鍵を導出 — 同じ seed なら、どこでも同じ JWKS |
| `tokens.issued_at` | 実時計 | クォート付き RFC 3339 タイムスタンプ。`iat`/`exp` を凍結しバイトをスナップショット安全に |
| `tokens.ttl` | `"1h"` | トークン寿命（`exp = iat + ttl`） |
| `tokens.algorithm` | `"EdDSA"` | または `"RS256"` + `tokens.rsa_key_file`。EdDSA 非対応のクライアントライブラリ向け |
| `[[clients]]` | 必須 | `client_id`、任意の `client_secret`（省略 → パブリッククライアント、PKCE 強制）、完全一致の `redirect_uris` |
| `[[personas]]` | 必須 | `name`、`subject`、`email`、`groups`、加えて自由形式の `[personas.claims]` |

scope はどこでも（ID トークン・アクセストークン・userinfo）同じ規則で claim を開放します：`email` → メール系 claim、`groups` → groups、`profile` → 全カスタム claim（キー順ソート）。

## CLI リファレンス

| コマンド | 効果 |
|---|---|
| `serve --config F [--addr 127.0.0.1:9111]` | プロバイダを起動（ループバック限定を強制） |
| `mint --config F --persona P --client C` | トークンを出力。`--kind id\|access`、`--scope`、`--nonce`、`--at RFC3339` |
| `decode --config F TOKEN` | 署名検証し、header + claims を整形表示 |
| `personas --config F` | 設定済みペルソナの一覧表 |
| `jwks` / `discovery --config F` | サーバなしで JWKS / discovery 文書を出力 |
| `validate --config F` | ペルソナファイルを検査。失敗時は exit 1 で問題のキーを提示 |

終了コード：`0` 成功、`1` 実行時失敗、`2` 使い方の誤り。

## 検証

このリポジトリは CI を同梱しません。上記の主張はすべてローカル実行で検証します：

```bash
go test ./...            # 91 deterministic tests, no external network, < 5 s
bash scripts/smoke.sh    # builds, checks the golden token, drives the full
                         # code+PKCE flow with curl — prints SMOKE OK
```

## アーキテクチャ

```mermaid
flowchart LR
    F[personas.toml] --> P[toml: subset parser]
    P --> C[config: validate]
    C --> I[issuer: deterministic claims]
    K[seed / PEM] --> J[jose: keys, ordered JSON, JWT]
    J --> I
    I --> M[CLI mint / decode]
    I --> S[oidc server]
    S --> D["discovery + JWKS"]
    S --> A["authorize + PKCE"]
    S --> T["token / refresh / introspect"]
    S --> U[userinfo]
    A --> ST[(grant store)]
    ST --> T
```

## ロードマップ

- [x] v0.1.0 — TOML ペルソナ、seed 導出鍵、凍結時計、code+PKCE フロー、refresh ローテーション、client_credentials、userinfo、introspection、mint/decode CLI、テスト 91 件 + smoke スクリプト
- [ ] レガシークライアント検証用の device-code / implicit グラントのエミュレーション
- [ ] フォールト注入：`--chaos` フラグで期限切れトークン・時計のずれ・誤 kid の JWKS を出し、クライアントのエラーパスをテスト
- [ ] マルチテナントアプリ向けに 1 プロセスで複数 issuer を並走
- [ ] クライアントライブラリが実際に送るリクエストを断言するためのオプトインのリクエストログ（`--log jsonl`）
- [ ] リソースサーバへ公開鍵を事前配布する `personad export-jwks`

全リストは [open issues](https://github.com/JaydenCJ/personad/issues) を参照。

## コントリビュート

issue・議論・PR を歓迎します — ローカルのワークフロー（format、vet、テスト、`SMOKE OK`）と決定論のグラウンドルールは [CONTRIBUTING.md](CONTRIBUTING.md) へ。入門タスクは [good first issue](https://github.com/JaydenCJ/personad/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) のラベル付き、設計の議論は [Discussions](https://github.com/JaydenCJ/personad/discussions) で。

## ライセンス

[MIT](LICENSE)
