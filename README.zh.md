# pi-bitwarden — 已归档，由 ai-vault 取代

> **这个项目已归档。** 它还能装、能跑，但不再更新：没有新功能，也不修 bug。
> 它做过的事情全部活在 **[ai-vault](https://github.com/xiaolikt/ai-vault)** 里，
> 开发也在那边继续。
>
> [English](README.md)

## 迁移到 ai-vault

ai-vault 保留了这个扩展的全部工具——`bw_list`、`bw_run`、`bw_inject`、
`bw_clipboard`、`bw_reveal`、输出擦洗、`/bw`——并增加了全机共享的加密密码库、
Ente Auth，以及可配置的解锁策略。

| 你原来有的 | 现在得到的 |
|---|---|
| `bw_list` / `bw_run` / `bw_inject` / `bw_clipboard` / `bw_reveal` | 同名同行为 |
| 每个会话输一次主密码 | `bitwarden.unlock`：`session` / `time` / `never`——想不再输就把 `bw` 会话落盘 |
| 密码只在 Bitwarden 里 | `vault_get`：先查本地库、Bitwarden 兜底，命中后可导入——你同意的那些就能让 agent 自由用 |
| — | `vault_add`、`vault_list`、`vault_import`、`ente_list`、`ente_code` |
| — | 一个 `~/.ai-vault`，pi、omp 和机器上别的 agent 共用 |

```bash
npm i -g @xiaolikt/ai-vault          # CLI（Linux、Windows、Linux arm64）
pi install npm:pi-ai-vault           # pi
omp plugin install npm:pi-ai-vault   # omp
/vault init                           # 一次
```

**不要两个都装。** pi-bitwarden 和 pi-ai-vault 注册同一批 `bw_*` 工具，都装会重复。
先把这个卸掉：

```bash
pi remove git:github.com/xiaolikt/pi-bitwarden
```

完整文档：[github.com/xiaolikt/ai-vault](https://github.com/xiaolikt/ai-vault) ·
[npm: pi-ai-vault](https://www.npmjs.com/package/pi-ai-vault) ·
[npm: @xiaolikt/ai-vault](https://www.npmjs.com/package/@xiaolikt/ai-vault)

---

## 它原来是什么

一个给 [pi coding agent](https://github.com/earendil-works/pi-coding-agent) **和 OMP**
用的扩展：把 Bitwarden 密码交给**进程，而不是大模型**。

当模型要跑一条需要凭据的命令（API token、`docker login`、`git push`……）时，
密码从你的 Bitwarden 库直接进 bash 子进程。密码**从不出现在对话里**——不发给
模型提供商，也不写进会话文件。

| 工具 | 作用 | 模型看得到密码？ |
|---|---|---|
| `bw_list` | 列条目（名称 / 用户名 / URI / id）；按这些字段搜索，`offset`/`limit` | ❌ |
| `bw_inject` | 把密码注入 bash 环境变量，本会话内有效（**仅 pi**；每次确认） | ❌ 只看到「已注入为 $XXX」 |
| `bw_run` | 用 `$VAULT_SECRET` 跑一条命令（**pi 和 OMP 都能用**） | ❌ 输出被擦洗 |
| `bw_clipboard` | 复制到剪贴板，自动清除（默认 30 秒），锁定/退出时也清 | ❌ |
| `bw_reveal` | 明文返回（每次确认 + 强警告，可关闭） | ✅ 用户当场允许 |
| `/bw status\|unlock\|lock\|clear [ENV]` | 管理解锁状态；撤销注入的变量 | — |

`bw_list`/`bw_inject`/`bw_run`/`bw_clipboard`/`bw_reveal` 共用字段选择器：
`password`（默认）· `totp`（种子）· `code`（动态验证码，`bw get totp`）· `notes` · `field:<自定义字段名>`。

## 安全模型（发布时的）

- **主密码**：Zenity 桌面弹窗（OMP 的 TUI 回退会掩码输入；上游 pi 忽略掩码提示）。只通过环境变量传给 `bw unlock`——绝不进 argv、日志或会话。
- **BW_SESSION 只在 agent 进程内存里**：不落盘，扩展也不会把它放进 bash 环境。如果你启动 `pi`/`omp` 时 shell 里已经 export 了 `BW_SESSION`，模型的 bash 会继承它——先取消。
- **注入的密码**：
  - **pi**：`bw_inject` 用 `createBashTool` 的 `spawnHook`，值只存在于 bash 子进程环境里。
  - **OMP**：OMP 对模型的 bash 调用会丢弃那个 hook。所以 `bw_inject` 在 OMP 上**拒绝运行**，而不是假装成功；用 `bw_run`，它只起一条命令，值在命令结束后就没了。什么都不写盘。
- **输出擦洗**：一个 `tool_result` 钩子把每个注入/运行过的值、它的 base64/base64url/URL 编码/hex 形式、以及 `details`/`structuredContent` 里的同样字符串，都换成 `[BW_SCRUBBED:$VAR]`。`/bw clear` 或锁定后仍然擦洗，所以早先写进文件的值不能被 `cat` 回模型。截断的 bash 输出产物也会擦洗。
- **每次确认**：`bw_inject`、`bw_clipboard`、`bw_reveal` 会弹窗（zenity），显示**实际解析到的**条目和字段；TUI 回退走 pi/OMP 的输入框。拒绝即最终，工具会告诉模型不要重试。
- **审计日志**：`~/.bw/pi-extension/audit.log` 记录解锁、拒绝、注入和明文读取，带会话标签，从不记值。
- **`bw_reveal` 默认关闭**；接受密码会进对话的话，在 `~/.bw/pi-extension/config.json` 里打开。

## 安装（旧版，仍然可用）

需要 Bitwarden CLI（`bw`），并用 `bw login` 登录过。

```bash
pi install npm:pi-bitwarden              # pi
omp plugin install npm:pi-bitwarden      # omp
```

或从源码：

```bash
pi install git:github.com/xiaolikt/pi-bitwarden
omp plugin install git+ssh://git@github.com/xiaolikt/pi-bitwarden.git
```

第一次用会要 Bitwarden 主密码；之后会话密钥留在内存里，直到会话结束（或 `/bw lock`）。

## 许可证

MIT
