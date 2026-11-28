# pi-bitwarden — archived, superseded by ai-vault

> **This project is archived.** It still installs and runs, but it is frozen: no
> new features, no fixes. Everything it did lives on in
> **[ai-vault](https://github.com/xiaolikt/ai-vault)**, which is where the
> development continues.
>
> [中文版](README.zh.md)

## Migrate to ai-vault

ai-vault keeps every tool this extension had — `bw_list`, `bw_run`,
`bw_inject`, `bw_clipboard`, `bw_reveal`, the output scrubber, `/bw` — and adds
a machine-wide encrypted store, Ente Auth, and configurable unlock policies.

| You had | You get |
|---|---|
| `bw_list` / `bw_run` / `bw_inject` / `bw_clipboard` / `bw_reveal` | the same tools, same names, same behaviour |
| master password per session | `bitwarden.unlock`: `session` / `time` / `never` — keep the `bw` session on disk if you want to stop typing it |
| secrets only in Bitwarden | `vault_get`: local store first, Bitwarden as fallback, with an import offer so the agent can freely use the passwords you approve |
| — | `vault_add`, `vault_list`, `vault_import`, `ente_list`, `ente_code` |
| — | a `~/.ai-vault` store shared by pi, omp and anything else on the machine |

```bash
npm i -g @xiaolikt/ai-vault          # the CLI (Linux, Windows, Linux arm64)
pi install npm:pi-ai-vault           # pi
omp plugin install npm:pi-ai-vault   # omp
/vault init                           # once
```

**Do not install both.** pi-bitwarden and pi-ai-vault register the same `bw_*`
tools; having both means duplicates. Remove this one first:

```bash
pi remove git:github.com/xiaolikt/pi-bitwarden
```

Full documentation: [github.com/xiaolikt/ai-vault](https://github.com/xiaolikt/ai-vault) ·
[npm: pi-ai-vault](https://www.npmjs.com/package/pi-ai-vault) ·
[npm: @xiaolikt/ai-vault](https://www.npmjs.com/package/@xiaolikt/ai-vault)

---

## What it was

A [pi coding agent](https://github.com/earendil-works/pi-coding-agent) **and OMP**
extension that delivers Bitwarden secrets to **processes, not the LLM**.

When the model needs to run a command that requires a credential (an API
token, `docker login`, `git push`...), the secret goes from your Bitwarden vault
into the bash child process. The secret **never appears in the conversation** —
it is not sent to the LLM provider and not written to session files.

| Tool | What it does | Model sees the secret? |
|---|---|---|
| `bw_list` | List items (name / username / URI / id); search across those fields, `offset`/`limit` | ❌ |
| `bw_inject` | Fetch a secret into a bash env var for the rest of the session (**pi only**; per-call confirmation) | ❌ only "injected as $XXX" |
| `bw_run` | Run one command with the secret in its env as `$VAULT_SECRET` (**works on pi and OMP**) | ❌ output is scrubbed |
| `bw_clipboard` | Copy to the system clipboard, auto-cleared (default 30s) and on lock/exit | ❌ |
| `bw_reveal` | Plain text (per-call confirmation + strong warning, can be disabled) | ✅ user-approved per call |
| `/bw status\|unlock\|lock\|clear [ENV]` | Manage unlock state; drop one or all injected vars | — |

`bw_list`/`bw_inject`/`bw_run`/`bw_clipboard`/`bw_reveal` share the field selector:
`password` (default) · `totp` (seed) · `code` (rotating TOTP code via `bw get totp`) · `notes` · `field:<customFieldName>`.

## Security model (as shipped)

- **Master password**: Zenity desktop prompt (the TUI fallback masks input on OMP; upstream pi ignores the hint and shows it). Passed to `bw unlock` only via an env var — never argv, logs, or sessions.
- **BW_SESSION lives in the agent process memory only**: never on disk, never placed in the bash environment by the extension. If you launch `pi`/`omp` with `BW_SESSION` already exported, the model's bash inherits it — unset it first.
- **Injected secrets**:
  - **pi**: `bw_inject` uses `createBashTool`'s `spawnHook`, so active values live in the bash child env only.
  - **OMP**: OMP discards that hook for model bash calls. `bw_inject` therefore **refuses to run on OMP** instead of silently reporting success; use `bw_run`, which spawns exactly one command with the value in its environment. Nothing is written to disk and the value does not survive the command.
- **Output scrubber**: a `tool_result` hook replaces every injected/run value, its base64/base64url/URL-encoded/hex forms, and the same strings inside `details`/`structuredContent`, with `[BW_SCRUBBED:$VAR]`. Values stay scrubbed after `/bw clear` or lock, so a file written earlier cannot be `cat`-ed back into the model. Truncated bash output artifacts are scrubbed too.
- **Per-call confirmation**: `bw_inject`, `bw_clipboard` and `bw_reveal` open a window (zenity) naming the *resolved* item and field; the TUI fallback asks through pi/OMP. A denied prompt is final for that call — the tool tells the model not to retry.
- **Audit log**: `~/.bw/pi-extension/audit.log` records unlocks, denials, injections and reveals with the session label, never a value.
- **`bw_reveal` is off by default**; enable it in `~/.bw/pi-extension/config.json` if you accept that a secret will enter the conversation.

## Install (legacy, still works)

Requires the Bitwarden CLI (`bw`), logged in with `bw login`.

```bash
pi install npm:pi-bitwarden              # pi
omp plugin install npm:pi-bitwarden      # omp
```

or from source:

```bash
pi install git:github.com/xiaolikt/pi-bitwarden
omp plugin install git+ssh://git@github.com/xiaolikt/pi-bitwarden.git
```

On first use you are asked for the Bitwarden master password; afterwards the
session key stays in memory for the rest of the session (or `/bw lock`).

## License

MIT
