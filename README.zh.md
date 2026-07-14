# personad

[English](README.md) | [中文](README.zh.md) | [日本語](README.ja.md)

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Go ≥1.22](https://img.shields.io/badge/go-%E2%89%A51.22-00ADD8)](go.mod) [![Version 0.1.0](https://img.shields.io/badge/version-0.1.0-informational)](CHANGELOG.md) ![Tests](https://img.shields.io/badge/tests-91%20passed-brightgreen) [![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](CONTRIBUTING.md)

**personad：面向开发与 CI 的开源确定性假 OIDC 提供方 —— TOML 定义 persona、字节级稳定的令牌可做快照测试、完整的 discovery/JWKS/PKCE。为断言而生，不是演示品。**

![Demo](docs/assets/demo.svg)

```bash
git clone https://github.com/JaydenCJ/personad && cd personad
go build -o personad ./cmd/personad    # single static binary, stdlib only
```

> 预发布：v0.1.0 尚未发布到任何包注册表；请按上面方式从源码构建（Go ≥1.22 均可）。

## 为什么选 personad？

每个 OAuth 集成测试迟早都要和真实身份提供方搏斗：限流、过期的测试租户、每次运行 `iat`/`jti` 都在变导致无法做快照断言的令牌，以及横在无头 CI 任务中间的登录页。常见的替代方案各有代价 —— mock-oauth2-server 很优秀，但会把一个 JVM 拖进每个 Web 项目的 CI 镜像；Keycloak dev 模式是个 600 MB 的容器，启动时间比你的测试套件还长；手写的 JWT 桩子跳过了 discovery/JWKS/PKCE，于是你本想测试的那些代码路径（issuer 校验、密钥轮换、verifier 检查）恰恰没被测到。personad 是一个 6 MB 的静态二进制，讲的 OIDC 足够真实，标准客户端库可以对它完成完整的 code + PKCE 流程 —— 而且端到端确定：签名密钥由配置里的 seed 推导，时钟可以冻结，claim 顺序固定，所以同一个 persona 文件在任何机器上、永远铸出相同的令牌字节。你的断言可以写 `assertEquals`，而不是 `assertMatches`。

| | personad | mock-oauth2-server | oauth2-mock-server (npm) | Keycloak dev 模式 |
|---|---|---|---|---|
| 运行时体积 | 6 MB 静态二进制 | JVM | Node.js | JVM 容器 |
| 字节级稳定令牌、可快照测试 | ✅ seed + 冻结时钟 | ❌ 每次启动随机密钥 | ❌ 每次启动随机密钥 | ❌ |
| persona 是可评审的配置 | ✅ TOML 放进仓库 | ⚠️ JSON/代码回调 | ⚠️ 代码 | ⚠️ realm 导出 JSON |
| Discovery + JWKS + PKCE (S256) | ✅ | ✅ | ✅ | ✅ |
| 无需服务器直接铸令牌（CLI） | ✅ `personad mint` | ❌ | ❌ | ❌ |
| refresh 轮换、introspection、userinfo | ✅ | ✅ | ⚠️ 部分 | ✅ |
| 运行时依赖 | 0（Go 标准库） | JVM + 库 | 4 个 npm 包 | 数百个 |

<sub>体积核查于 2026-07-13：personad 的二进制 strip 后约 6 MB（`go build -ldflags "-s -w"`；未 strip 约 9 MB）；mock-oauth2-server 需要 JRE（约 200 MB）或其约 180 MB 的 Docker 镜像；Keycloak 容器视 tag 约 430–600 MB。</sub>

## 特性

- **TOML 定义 persona** —— 用户是数据不是代码：subject、邮箱、组和任意自定义 claim 都放在测试旁边一份可评审的文件里，校验严格到写错一个键名就直接失败，而不是悄悄铸出错误的令牌。
- **字节级稳定的令牌** —— 由配置 seed 推导的 Ed25519 密钥、固定的 claim 顺序、冻结的 `issued_at`、推导出的 `jti`：同一个文件在任何机器上产出同一个紧凑 JWT。personad 自己的测试套件里钉着一枚黄金令牌，任何漂移都是破坏性变更。
- **完整的门面** —— `/.well-known/openid-configuration`、带 RFC 7638 kid 的 JWKS、带 HTML persona 选择页的授权码流程、PKCE（S256 + plain，公共客户端强制）、refresh 轮换、client_credentials、userinfo 与 RFC 7662 introspection。
- **不起服务器也能铸币** —— `personad mint` 直接把 ID 或 access 令牌写到 stdout，供单元测试和 fixture 使用；`personad decode` 校验并美化打印它签发的任何令牌。
- **诚实的报错、真实的拒绝** —— 重放的 code、不匹配的 redirect URI、错误的 verifier、跨客户端兑换、把 id_token 发给 userinfo，全都按合规 IdP 的方式失败，并且报错会点名错误本身。
- **构造即安全** —— 拒绝绑定回环以外的任何地址，无遥测、无网络调用、零依赖；personad 唯一交谈的对象就是你的测试套件。

## 快速上手

```bash
go build -o personad ./cmd/personad
./personad mint --config examples/personas.toml --persona alice --client web-app
```

真实捕获的输出 —— 运行两次再 diff，字节一模一样：

```text
eyJhbGciOiJFZERTQSIsImtpZCI6ImZnSkc3TzYzcDRHblZ2bFdEbGc3b3JSNzJTeGFYZWM0UFlZMjNSaEN5ZE0iLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjkxMTEiLCJzdWIiOiJ1c2VyLWFsaWNlLTAwMSIsImF1ZCI6IndlYi1hcHAiLCJleHAiOjE3NjcyMjkyMDAsImlhdCI6MTc2NzIyNTYwMCwiYXV0aF90aW1lIjoxNzY3MjI1NjAwLCJlbWFpbCI6ImFsaWNlQGV4YW1wbGUudGVzdCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJncm91cHMiOlsiYWRtaW4iLCJkZXYiXSwiZGVwYXJ0bWVudCI6ImVuZ2luZWVyaW5nIiwibGV2ZWwiOjV9.eS_CBeCGZ2JR0Mtk1gZ0y3MXuEK4w_M-48mo3X913Q_tbQZtlOCg3N44ZS514RKY60Ovr-NKnh4PpEkdrFlQCw
```

然后启动真正的提供方，把你应用的 OIDC 客户端指过来：

```bash
./personad serve --config examples/personas.toml
```

```text
personad 127.0.0.1:9111 listening
issuer:    http://127.0.0.1:9111
discovery: http://127.0.0.1:9111/.well-known/openid-configuration
personas:  alice, bob
```

完成 code + PKCE 流程（curl 版见 `examples/code-flow.sh`），再请求 userinfo —— 真实捕获的输出：

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

## Persona 文件

一份 persona 文件完全决定每一个令牌字节。完整参考见 [docs/persona-format.md](docs/persona-format.md)；关键的键：

| 键 | 默认值 | 作用 |
|---|---|---|
| `issuer` | 必填 | `iss` claim 以及所有端点的基础 URL（不带尾部斜杠） |
| `seed` | 必填 | 推导 Ed25519 签名密钥 —— 同一 seed，处处同一 JWKS |
| `tokens.issued_at` | 实时时钟 | 加引号的 RFC 3339 时间戳；冻结 `iat`/`exp`，让字节可安全快照 |
| `tokens.ttl` | `"1h"` | 令牌有效期（`exp = iat + ttl`） |
| `tokens.algorithm` | `"EdDSA"` | 或 `"RS256"` 配合 `tokens.rsa_key_file`，服务不支持 EdDSA 的客户端库 |
| `[[clients]]` | 必填 | `client_id`、可选 `client_secret`（省略 → 公共客户端，强制 PKCE）、精确匹配的 `redirect_uris` |
| `[[personas]]` | 必填 | `name`、`subject`、`email`、`groups`，外加自由形式的 `[personas.claims]` |

scope 在所有位置（ID 令牌、access 令牌、userinfo）以同一规则控制 claim 释放：`email` → 邮箱类 claim，`groups` → groups，`profile` → 全部自定义 claim，按键名排序。

## CLI 参考

| 命令 | 作用 |
|---|---|
| `serve --config F [--addr 127.0.0.1:9111]` | 运行提供方（强制仅回环） |
| `mint --config F --persona P --client C` | 打印令牌；`--kind id\|access`、`--scope`、`--nonce`、`--at RFC3339` |
| `decode --config F TOKEN` | 校验签名，美化打印 header + claims |
| `personas --config F` | 已配置 persona 的表格 |
| `jwks` / `discovery --config F` | 不起服务直接打印 JWKS / discovery 文档 |
| `validate --config F` | 检查 persona 文件；失败时 exit 1 并指出出错的键 |

退出码：`0` 成功，`1` 运行失败，`2` 用法错误。

## 验证

本仓库不携带任何 CI；上面的每一条声明都由本地运行验证：

```bash
go test ./...            # 91 deterministic tests, no external network, < 5 s
bash scripts/smoke.sh    # builds, checks the golden token, drives the full
                         # code+PKCE flow with curl — prints SMOKE OK
```

## 架构

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

## 路线图

- [x] v0.1.0 —— TOML persona、seed 推导密钥、冻结时钟、code+PKCE 流程、refresh 轮换、client_credentials、userinfo、introspection、mint/decode CLI、91 个测试 + smoke 脚本
- [ ] device-code 与 implicit 授权模拟，用于测试遗留客户端
- [ ] 故障注入：`--chaos` 参数产出过期令牌、偏移时钟和错误 kid 的 JWKS，测试客户端的错误路径
- [ ] 单进程内多个并存 issuer，服务多租户应用
- [ ] 可选请求日志（`--log jsonl`），断言客户端库实际发出的请求
- [ ] `personad export-jwks`，为资源服务器预先下发公钥

完整列表见 [open issues](https://github.com/JaydenCJ/personad/issues)。

## 参与贡献

欢迎 issue、讨论与 PR —— 本地工作流（format、vet、测试、`SMOKE OK`）和确定性的基本规则见 [CONTRIBUTING.md](CONTRIBUTING.md)。入门任务标注为 [good first issue](https://github.com/JaydenCJ/personad/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)，设计讨论在 [Discussions](https://github.com/JaydenCJ/personad/discussions)。

## 许可证

[MIT](LICENSE)
