/**
 * pi Bitwarden extension — deliver vault secrets to processes, not to the LLM.
 *
 * Security model
 * ==============
 * - Master password: prompted via Zenity (desktop) or pi TUI input. Lives in
 *   memory only for the duration of one `bw unlock` call, passed via env var
 *   (never argv). The session key (BW_SESSION) stays in this process's memory:
 *   never on disk, never in the bash environment, never in logs or results.
 * - bw_inject: fetches a secret and injects it as an env var into bash tool
 *   child processes (pi only: createBashTool's spawnHook). The model never
 *   sees the value. A tool_result scrubber replaces every active secret
 *   (raw/base64/base64url/URL/hex, plus details/structuredContent) in ALL tool
 *   results before they reach the model (catches `echo $VAR`).
 * - bw_run: runs one command with the secret in its environment. This is the
 *   OMP path (OMP discards spawnHook env), and also works on pi. Output is
 *   scrubbed; nothing is persisted after the command exits.
 * - bw_clipboard: copies a secret to the system clipboard, auto-cleared after
 *   the configured delay and on lock/exit (only if it still holds our value).
 * - bw_reveal (optional, per-call confirmation): returns a secret in plain
 *   text. The value then transits the LLM provider and the session file —
 *   that is inherent, hence every reveal needs explicit approval.
 * - Auto-lock: configurable idle timeout (config.json, default: session-lifetime,
 *   i.e. unlock once per pi session); always on /bw lock, on /new //fork session
 *   switch, and on pi exit. Locking drops the session key and all injected vars.
 * - Audit log: ~/.bw/pi-extension/audit.log (timestamps, item names, env var
 *   names, allow/deny — never secret values).
 * - Config: ~/.bw/pi-extension/config.json (autoLockMinutes, keepOnResume,
 *   clipboardClearSeconds, allowReveal, maxInjectedEnv).
 *
 * Requires: bitwarden CLI (`bw`), logged in (`bw login`).
 * Replaces mcp__bitwarden (removed); browser filling works via agent-browser:
 *   agent-browser fill @ref "$VAR"   (value never enters the conversation)
 */

import { spawn, spawnSync } from "node:child_process";
import { readFileSync, promises as fs } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import type { ExtensionAPI, ExtensionContext, ToolResultEventResult } from "@earendil-works/pi-coding-agent";
import { createBashTool } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { scrubDeep, scrubText } from "./scrub.ts";

// ---------------------------------------------------------------------------
// Configuration (defaults overridable via ~/.bw/pi-extension/config.json)
// ---------------------------------------------------------------------------
const STATE_DIR = path.join(homedir(), ".bw", "pi-extension");
const CONFIG_PATH = path.join(STATE_DIR, "config.json");

const DEFAULTS = {
	/** Idle minutes before the vault session and injected secrets drop.
	 *  0 = unlock lasts for the whole pi session (lock only on /bw lock or exit). */
	autoLockMinutes: 0,
	/** Keep the unlock state when switching sessions with /resume in the same pi process. */
	keepOnResume: true,
	/** Clipboard auto-clear delay. */
	clipboardClearSeconds: 30,
	/** Allow bw_reveal (plain-text secret to the model, per-call confirmation). */
	allowReveal: true,
	/** Upper bound on concurrently injected env vars. */
	maxInjectedEnv: 12,
};

function loadConfig(): typeof DEFAULTS {
	type Config = typeof DEFAULTS;
	const fail = (key: keyof Config, expected: string, fallback: unknown) =>
		process.stderr.write(
			`pi-bitwarden: invalid ${key} in ${CONFIG_PATH} (expected ${expected}); using ${String(fallback)}\n`,
		);
	const int = (
		raw: Record<string, unknown>,
		key: keyof Config,
		min: number,
		max: number,
		invalidFallback: number = DEFAULTS[key] as number,
	): number => {
		const value = raw[key];
		if (value === undefined) return DEFAULTS[key] as number;
		if (typeof value === "number" && Number.isInteger(value) && value >= min && value <= max) return value;
		fail(key, `integer ${min}..${max}`, invalidFallback);
		return invalidFallback;
	};
	const bool = (raw: Record<string, unknown>, key: keyof Config, invalidValue: boolean): boolean => {
		const fallback = DEFAULTS[key] as boolean;
		const value = raw[key];
		if (value === undefined) return fallback;
		if (typeof value === "boolean") return value;
		// Explicit but wrong type: fail closed for security switches.
		fail(key, "true or false", invalidValue);
		return invalidValue;
	};

	let parsed: unknown;
	try {
		parsed = JSON.parse(readFileSync(CONFIG_PATH, "utf-8"));
	} catch {
		return { ...DEFAULTS };
	}
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return { ...DEFAULTS };
	const raw = parsed as Record<string, unknown>;
	return {
		autoLockMinutes: int(raw, "autoLockMinutes", 0, 10_080, 15),
		keepOnResume: bool(raw, "keepOnResume", false),
		clipboardClearSeconds: int(raw, "clipboardClearSeconds", 0, 3600),
		allowReveal: bool(raw, "allowReveal", false),
		maxInjectedEnv: int(raw, "maxInjectedEnv", 1, 64),
	};
}

const CONFIG = loadConfig();
/** 0 = no idle lock (session-lifetime unlock). */
const autoLockMs = CONFIG.autoLockMinutes > 0 ? CONFIG.autoLockMinutes * 60_000 : 0;
const CLIPBOARD_CLEAR_TEXT =
	CONFIG.clipboardClearSeconds > 0
		? `auto-cleared after ${CONFIG.clipboardClearSeconds}s`
		: "auto-clear disabled (lock/exit still clear)";
const BW_TIMEOUT_MS = 120_000;

/** Env names the model may never claim (shell/loader injection vectors + Bitwarden internals). */
const ENV_BLOCKLIST =
	/^(PATH|HOME|SHELL|USER|LOGNAME|PWD|OLDPWD|IFS|PS1|PS2|PROMPT_COMMAND|BASH_ENV|BASH_FUNC_.+|BASH_LOADABLES_PATH|ENV|SHELLOPTS|BASHOPTS|LD_.+|DYLD_.+|PYTHONPATH|PYTHONSTARTUP|PERL5OPT|RUBYOPT|NODE_OPTIONS|NODE_PATH|GIT_CONFIG|GIT_CONFIG_GLOBAL|GIT_CONFIG_SYSTEM|GIT_SSH|GIT_SSH_COMMAND|GIT_ASKPASS|GIT_EDITOR|GIT_PAGER|GIT_EXTERNAL_DIFF|SSH_AUTH_SOCK|SSH_ASKPASS|SUDO_ASKPASS|LESSOPEN|LESSCLOSE|PAGER|MANPAGER|EDITOR|VISUAL|BROWSER|SSL_CERT_FILE|REQUESTS_CA_BUNDLE|CURL_HOME|CURL_CA_BUNDLE|http_proxy|https_proxy|all_proxy|no_proxy|PI_.+|BW_.+)$/i;

const FIELD_RE = /^(password|totp|code|notes|field:[\w.\- ]{1,64})$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const BW_LOGIN_HINT =
	"Bitwarden CLI is not logged in. Run `bw login` in a terminal first " +
	"(and `bw config --server <url>` if self-hosted), then retry. " +
	"You can check with /bw status.";

// ---------------------------------------------------------------------------
// State (memory only)
// ---------------------------------------------------------------------------
let sessionKey: string | undefined;
let sessionVerifiedAt = 0;
let lastActivity = 0;
/** OMP exposes its package exports as `pi.pi`; upstream pi does not. */
let ompHost = false;
let lockTimer: NodeJS.Timeout | undefined;
let unlockInFlight: Promise<string> | undefined;
type BwItem = {
	id?: string;
	name?: string;
	notes?: string;
	login?: { username?: string; password?: string; totp?: string; uris?: { uri?: string }[] };
	fields?: { name?: string; value?: string }[];
};
/** Only metadata is cached; secrets stay in the vault process until needed. */
type LiteItem = { id: string; name: string; username: string; uri: string };

let itemsCache: { at: number; items: LiteItem[] } | undefined;

/** Injected secrets: ENV -> { value, item, field, at }. Values never reach the model. */
const injected = new Map<string, { value: string; item: string; field: string; at: number }>();

/**
 * Values the output scrubber must keep hiding, even after /bw clear or lock:
 * a command may already have copied $VAR to a file, and a later `cat` would
 * otherwise leak it. Keyed by ENV + value so replacements keep both.
 */
const scrubValues = new Map<string, { env: string; value: string }>();
const MAX_SCRUB_VALUES = 64;

function rememberScrubValue(env: string, value: string): void {
	scrubValues.set(`${env}\u0000${value}`, { env, value });
	while (scrubValues.size > MAX_SCRUB_VALUES) {
		const oldest = scrubValues.keys().next();
		if (oldest.done) break;
		scrubValues.delete(oldest.value);
	}
}

process.once("exit", () => {
	clearClipboardSync();
});

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
function hasDisplay(): boolean {
	return !!(process.env.DISPLAY || process.env.WAYLAND_DISPLAY);
}

function safeStatus(ctx: ExtensionContext | undefined, text: string | undefined): void {
	try {
		ctx?.ui.setStatus("bitwarden", text);
	} catch {
		/* runner may be inactive */
	}
}

function tail(s: string, n = 200): string {
	const t = s.trim();
	if (!t) return "";
	return t.length > n ? t.slice(-n) : t;
}

function exec(
	cmd: string,
	args: string[],
	opts: {
		env?: Record<string, string>;
		timeout?: number;
		input?: string;
		signal?: AbortSignal;
		cwd?: string;
	} = {},
): Promise<{ stdout: string; stderr: string; code: number }> {
	if (opts.signal?.aborted) return Promise.reject(new Error(`${cmd} cancelled`));
	const { promise, resolve, reject } = Promise.withResolvers<{ stdout: string; stderr: string; code: number }>();
	const child = spawn(cmd, args, {
		env: opts.env ? { ...process.env, ...opts.env } : process.env,
		cwd: opts.cwd,
		stdio: ["pipe", "pipe", "pipe"],
	});
	let out = "";
	let err = "";
	let settled = false;
	const cleanup = () => {
		clearTimeout(timer);
		opts.signal?.removeEventListener("abort", onAbort);
	};
	const finish = (fn: () => void) => {
		if (settled) return;
		settled = true;
		cleanup();
		fn();
	};
	const onAbort = () =>
		finish(() => {
			child.kill("SIGKILL");
			reject(new Error(`${cmd} cancelled`));
		});
	const timer = setTimeout(
		() =>
			finish(() => {
				child.kill("SIGKILL");
				reject(new Error(`${cmd} timed out after ${opts.timeout ?? BW_TIMEOUT_MS}ms`));
			}),
		opts.timeout ?? BW_TIMEOUT_MS,
	);
	opts.signal?.addEventListener("abort", onAbort, { once: true });
	if (opts.signal?.aborted) onAbort();
	child.stdout?.on("data", (d) => (out += d));
	child.stderr?.on("data", (d) => (err += d));
	child.on("error", (e) => finish(() => reject(e)));
	child.on("close", (code) => finish(() => resolve({ stdout: out, stderr: err, code: code ?? -1 })));
	child.stdin?.on("error", () => {}); // EPIPE when the child dies before reading input
	if (opts.input !== undefined) child.stdin?.write(opts.input);
	child.stdin?.end();
	return promise;
}

const AUDIT_MAX_BYTES = 1024 * 1024;
let auditModeFixed = false;

async function audit(event: string, detail: string): Promise<void> {
	try {
		await fs.mkdir(STATE_DIR, { recursive: true, mode: 0o700 });
		const log = path.join(STATE_DIR, "audit.log");
		if (!auditModeFixed) {
			auditModeFixed = true;
			await fs.chmod(STATE_DIR, 0o700).catch(() => {});
			await fs.chmod(log, 0o600).catch(() => {});
		}
		try {
			const stat = await fs.stat(log);
			if (stat.size > AUDIT_MAX_BYTES) await fs.rename(log, `${log}.1`);
		} catch {
			/* first entry */
		}
		// Item names are model/vault supplied: keep one entry per line.
		const safeDetail = detail.replace(/[\r\n]+/g, " ").slice(0, 500);
		const line = `${new Date().toISOString()} ${event} ${safeDetail}\n`;
		await fs.appendFile(log, line, { mode: 0o600 });
	} catch {
		/* best-effort */
	}
}

// ---------------------------------------------------------------------------
// Bitwarden CLI plumbing (secrets only ever travel via env vars / pipes)
// ---------------------------------------------------------------------------
let bwBin: string | undefined;

async function resolveBw(): Promise<string> {
	if (bwBin) return bwBin;
	try {
		await exec("bw", ["--version"], { timeout: 20_000 });
		bwBin = "bw";
		return bwBin;
	} catch {
		/* fall through to nvm scan */
	}
	try {
		const nvmDir = path.join(homedir(), ".nvm", "versions", "node");
		const versions = (await fs.readdir(nvmDir).catch(() => [] as string[]))
			.filter((v) => /^\d+\.\d+\.\d+$/.test(v))
			.sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
			.reverse();
		for (const v of versions) {
			const p = path.join(nvmDir, v, "bin", "bw");
			if (await fs.access(p).then(() => true, () => false)) {
				bwBin = p;
				return bwBin;
			}
		}
	} catch {
		/* ignore */
	}
	throw new Error("Bitwarden CLI (`bw`) not found in PATH or ~/.nvm. Install it, `bw login`, and retry.");
}

async function runBw(
	args: string[],
	opts: { session?: string; extraEnv?: Record<string, string>; signal?: AbortSignal } = {},
): Promise<string> {
	const bin = await resolveBw();
	const env: Record<string, string> = { ...opts.extraEnv };
	if (opts.session) env.BW_SESSION = opts.session;
	const r = await exec(bin, [...args, "--nointeraction"], { env, signal: opts.signal });
	if (r.code !== 0) {
		const hint = tail(r.stderr) || `exit ${r.code}`;
		// Never include stdout in errors — some commands print secrets on success-ish paths.
		throw new Error(`bw ${args.slice(0, 2).join(" ")} failed: ${hint}`);
	}
	return r.stdout;
}

async function runBwJson(args: string[], session?: string, signal?: AbortSignal): Promise<any> {
	return JSON.parse(await runBw(args, { session, signal }));
}

let statusCache: { at: number; json: any } | undefined;

async function bwStatus(session?: string, signal?: AbortSignal): Promise<any> {
	// `bw status` with a stale BW_SESSION exits non-zero; strip env session for the probe.
	if (session) {
		const r = await runBw(["status"], { session, signal });
		return JSON.parse(r);
	}
	if (statusCache && Date.now() - statusCache.at < 3000) return statusCache.json;
	const json = await runBwJson(["status"], undefined, signal);
	statusCache = { at: Date.now(), json };
	return json;
}

async function askMasterPassword(
	ctx: ExtensionContext | undefined,
	reason: string,
	signal?: AbortSignal,
): Promise<string> {
	if (signal?.aborted) throw new Error("Cancelled.");
	if (hasDisplay()) {
		try {
			const r = await exec(
				"zenity",
				["--password", `--title=pi · Bitwarden master password — ${reason}`],
				{ timeout: 10 * 60_000, signal },
			);
			if (r.code !== 0) throw new Error("cancelled");
			const pw = r.stdout.replace(/[\r\n]+$/, "");
			if (!pw) throw new Error("cancelled");
			return pw;
		} catch (e: unknown) {
			const message = e instanceof Error ? e.message : String(e);
			if (message === "cancelled" || message === "Master password prompt cancelled.") {
				throw new Error("Master password prompt cancelled.");
			}
			if (signal?.aborted) throw new Error("Cancelled.");
			// zenity missing/broken → fall through to TUI input
		}
	}
	if (ctx?.hasUI) {
		// OMP honors `secret` and masks the input; upstream pi ignores the option.
		const secretHint = { secret: true };
		const pw = await ctx.ui.input(
			"Bitwarden master password (masked where supported — desktop prompt unavailable)",
			reason,
			secretHint,
		);
		if (signal?.aborted) throw new Error("Cancelled.");
		if (!pw) throw new Error("Master password prompt cancelled.");
		return pw;
	}
	throw new Error(
		"No way to prompt for the master password (no TUI, no desktop). Run /bw unlock in an interactive pi session.",
	);
}

async function confirmAction(
	ctx: ExtensionContext | undefined,
	title: string,
	message: string,
	signal?: AbortSignal,
): Promise<boolean> {
	if (signal?.aborted) throw new Error("Cancelled.");
	if (ctx?.hasUI) {
		const ok = await ctx.ui.confirm(title, message);
		if (signal?.aborted) throw new Error("Cancelled.");
		return ok === true;
	}
	if (hasDisplay()) {
		try {
			const r = await exec("zenity", ["--question", `--title=${title}`, "--text", message], {
				timeout: 10 * 60_000,
				signal,
			});
			if (process.env.BW_MOCK_DIR) {
				try { await fs.appendFile(`${process.env.BW_MOCK_DIR}/confirm.log`, `zenity code=${r.code} stderr=${tail(r.stderr, 40)}\n`); } catch {}
			}
			return r.code === 0;
		} catch {
			if (signal?.aborted) throw new Error("Cancelled.");
			return false;
		}
	}
	return false;
}

function startAutoLock(): void {
	lastActivity = Date.now();
	if (lockTimer || !autoLockMs) return;
	lockTimer = setInterval(() => {
		if (sessionKey && autoLockMs && Date.now() - lastActivity > autoLockMs) {
			void lock("auto-idle");
		}
	}, 30_000);
	lockTimer.unref?.();
}

async function lock(reason: string): Promise<void> {
	const hadSession = !!sessionKey;
	sessionKey = undefined;
	sessionVerifiedAt = 0;
	itemsCache = undefined;
	injected.clear();
	await clearClipboardIfOwner();
	if (lockTimer) {
		clearInterval(lockTimer);
		lockTimer = undefined;
	}
	if (hadSession) {
		await audit("lock", `reason=${reason}`);
		try {
			const bin = await resolveBw();
			await exec(bin, ["lock", "--nointeraction"], { timeout: 15_000 });
		} catch {
			/* best-effort; dropping our session key is what matters */
		}
	}
}

function touchActivity(): void {
	lastActivity = Date.now();
}

async function ensureUnlocked(ctx: ExtensionContext | undefined, signal?: AbortSignal): Promise<string> {
	touchActivity();
	if (signal?.aborted) throw new Error("Cancelled.");
	if (sessionKey && Date.now() - sessionVerifiedAt < 30_000) return sessionKey;
	if (sessionKey) {
		try {
			const st = await bwStatus(sessionKey, signal);
			if (st?.status === "unlocked") {
				sessionVerifiedAt = Date.now();
				return sessionKey;
			}
		} catch {
			if (signal?.aborted) throw new Error("Cancelled.");
			/* stale session key */
		}
		sessionKey = undefined;
		sessionVerifiedAt = 0;
	}
	if (unlockInFlight) return unlockInFlight;

	unlockInFlight = (async () => {
		const st = await bwStatus(undefined, signal); // no session env
		if (st?.status === "unauthenticated") throw new Error(BW_LOGIN_HINT);

		const pw = await askMasterPassword(ctx, "unlock vault", signal);
		const bin = await resolveBw();
		const r = await exec(bin, ["unlock", "--passwordenv", "BW_MASTER_PASSWORD", "--raw"], {
			env: { BW_MASTER_PASSWORD: pw },
			timeout: 60_000,
			signal,
		});
		if (r.code !== 0) {
			await audit("unlock", "deny=bad-password");
			throw new Error(`Unlock failed (wrong master password or CLI error). ${tail(r.stderr, 120)}`);
		}
		const key = r.stdout.replace(/[\r\n]+$/, "");
		if (!key) throw new Error("Unlock failed: empty session key.");
		const verify = await bwStatus(key, signal);
		if (verify?.status !== "unlocked") throw new Error("Unlock failed: session key not accepted.");
		sessionKey = key;
		sessionVerifiedAt = Date.now();
		startAutoLock();
		await audit("unlock", "ok");
		// Refresh in the background: a full sync can take seconds on large vaults.
		const lastSync = Date.parse(st?.lastSync ?? "");
		if (!Number.isFinite(lastSync) || Date.now() - lastSync > 15 * 60_000) {
			void runBw(["sync"], { session: key }).catch(() => {
				/* offline ok — cached vault */
			});
		}
		return key;
	})().finally(() => {
		unlockInFlight = undefined;
	});
	return unlockInFlight;
}

function toLite(raw: BwItem): LiteItem {
	return {
		id: raw.id ?? "",
		name: raw.name ?? "",
		username: raw.login?.username ?? "",
		uri: raw.login?.uris?.[0]?.uri ?? "",
	};
}

async function listItems(session: string, signal?: AbortSignal): Promise<LiteItem[]> {
	if (itemsCache && Date.now() - itemsCache.at < 5 * 60_000) return itemsCache.items;
	const raw = (await runBwJson(["list", "items"], session, signal)) as BwItem[];
	const items = raw.map(toLite);
	itemsCache = { at: Date.now(), items };
	return items;
}

async function getItemById(session: string, id: string, signal?: AbortSignal): Promise<BwItem> {
	try {
		return (await runBwJson(["get", "item", id], session, signal)) as BwItem;
	} catch {
		throw new Error(`No Bitwarden item with id ${id}.`);
	}
}

function itemScore(item: LiteItem, query: string): number {
	const haystack = `${item.name} ${item.username} ${item.uri}`.toLowerCase();
	let score = 0;
	for (const token of query.split(/\s+/).filter(Boolean)) {
		if (haystack.includes(token)) score += 10;
		else if (token.length > 3 && haystack.includes(token.slice(0, Math.max(3, token.length - 2)))) score += 3;
	}
	return score;
}

async function resolveItem(session: string, ref: string, signal?: AbortSignal): Promise<BwItem> {
	if (UUID_RE.test(ref)) return getItemById(session, ref, signal);

	const items = await listItems(session, signal);
	const query = ref.trim().toLowerCase();
	if (!query) throw new Error("Item reference is empty; pass an item name or id.");
	const exact = items.filter((i) => i.name.toLowerCase() === query);
	const partial = items.filter((i) =>
		`${i.name}\n${i.username}\n${i.uri}`.toLowerCase().includes(query),
	);
	const hits = exact.length > 0 ? exact : partial;
	if (hits.length === 1) return getItemById(session, hits[0].id, signal);

	const list = (items: LiteItem[]) =>
		items
			.slice(0, 10)
			.map((i) => `- ${i.name || "?"} | user: ${i.username || "-"} | ${i.uri || "-"} | id: ${i.id}`)
			.join("\n");
	if (hits.length > 1) throw new Error(`Multiple Bitwarden items match "${ref}". Specify by id:\n${list(hits)}`);

	const closest = items
		.map((item) => ({ item, score: itemScore(item, query) }))
		.filter((entry) => entry.score > 0)
		.sort((a, b) => b.score - a.score)
		.slice(0, 10)
		.map((entry) => entry.item);
	throw new Error(
		closest.length > 0
			? `No Bitwarden item matches "${ref}". Closest items:\n${list(closest)}`
			: `No Bitwarden item matches "${ref}". Use bw_list to browse item names.`,
	);
}

function extractSecret(item: BwItem, field: string): string {
	let v: string | undefined;
	if (field === "password") v = item.login?.password;
	else if (field === "totp") v = item.login?.totp; // TOTP seed, not the rotating code
	else if (field === "notes") v = item.notes;
	else if (field.startsWith("field:")) {
		const name = field.slice(6);
		v = item.fields?.find((f) => f.name === name)?.value;
	}
	if (typeof v !== "string" || v.length === 0) {
		throw new Error(`Field "${field}" is empty or missing on item "${item.name ?? "?"}".`);
	}
	return v;
}

async function fetchSecret(
	ctx: ExtensionContext | undefined,
	itemRef: string,
	field: string,
	signal?: AbortSignal,
): Promise<{ value: string; itemId: string; itemName: string }> {
	const session = await ensureUnlocked(ctx, signal);
	const item = await resolveItem(session, itemRef, signal);
	if (field === "code") {
		if (!item.id) throw new Error(`Bitwarden item "${item.name ?? "?"}" has no id, so no TOTP code can be generated.`);
		const code = (await runBw(["get", "totp", item.id], { session, signal })).trim();
		if (!code) throw new Error(`No TOTP code available for item "${item.name ?? "?"}".`);
		return { value: code, itemId: item.id, itemName: item.name ?? "?" };
	}
	return {
		value: extractSecret(item, field),
		itemId: item.id ?? "?",
		itemName: item.name ?? "?",
	};
}

function normalizeEnvName(raw: string): string {
	const name = raw.trim().toUpperCase();
	if (!/^[A-Z_][A-Z0-9_]*$/.test(name)) {
		throw new Error(`Invalid env var name "${raw}". Use letters, digits, underscores; must not start with a digit.`);
	}
	if (ENV_BLOCKLIST.test(name)) {
		throw new Error(`Env var name "${name}" is blocked (shell/loader/Bitwarden internals). Pick a specific name like MYAPP_TOKEN.`);
	}
	return name;
}

function injectedListText(): string {
	if (injected.size === 0) return "(none)";
	return [...injected.entries()].map(([env, r]) => `$${env} ← "${r.item}" (${r.field})`).join(", ");
}

// ---------------------------------------------------------------------------
// Clipboard
// ---------------------------------------------------------------------------
type ClipboardBackend = {
	copy: [string, string[]];
	clear: [string, string[]];
	read: [string, string[]];
};

function clipboardBackend(): ClipboardBackend | undefined {
	if (process.platform === "darwin") {
		return { copy: ["pbcopy", []], clear: ["pbcopy", []], read: ["pbpaste", []] };
	}
	if (process.env.WAYLAND_DISPLAY) {
		return {
			copy: ["wl-copy", []],
			clear: ["wl-copy", ["-c"]],
			read: ["wl-paste", ["--no-newline"]],
		};
	}
	if (process.env.DISPLAY) {
		return {
			copy: ["xclip", ["-selection", "clipboard"]],
			clear: ["xclip", ["-selection", "clipboard", "/dev/null"]],
			read: ["xclip", ["-selection", "clipboard", "-o"]],
		};
	}
	return undefined;
}

let clipboardValue: string | undefined;
/** Set while a copy is in flight, so exit cleanup can still clear it. */
let clipboardPending: string | undefined;
let clipboardTimer: NodeJS.Timeout | undefined;

function clipboardMatches(current: string, value: string): boolean {
	return current === value || current.replace(/[\r\n]+$/, "") === value.replace(/[\r\n]+$/, "");
}

async function copyToClipboard(value: string): Promise<void> {
	const backend = clipboardBackend();
	if (!backend) throw new Error("No clipboard available (need Wayland, X11, or macOS).");
	const [cmd, args] = backend.copy;
	const { promise, resolve, reject } = Promise.withResolvers<void>();
	// wl-copy/xclip stay alive to own the selection; a quick clean exit also means success.
	const child = spawn(cmd, args, { stdio: ["pipe", "ignore", "pipe"], detached: true });
	let settled = false;
	let stderr = "";
	const finish = (err?: Error) => {
		if (settled) return;
		settled = true;
		if (err) reject(err);
		else {
			child.unref();
			resolve();
		}
	};
	child.stderr?.on("data", (d) => (stderr += d));
	child.on("error", finish);
	child.on("exit", (code) => {
		if (code === 0) finish();
		else finish(new Error(`${cmd} exited with ${code}${stderr ? `: ${tail(stderr, 120)}` : ""}`));
	});
	child.stdin?.on("error", (e) => finish(e instanceof Error ? e : new Error(String(e))));
	child.stdin?.write(value, (err) => {
		if (err) {
			finish(err);
			return;
		}
		child.stdin?.end();
		setTimeout(() => finish(), 500);
	});
	clipboardPending = value;
	try {
		await promise;
	} catch (e) {
		clipboardPending = undefined;
		throw e;
	}
	clipboardPending = undefined;
	clearTimeout(clipboardTimer);
	clipboardValue = value;
	clipboardTimer = undefined;
	if (CONFIG.clipboardClearSeconds > 0) {
		clipboardTimer = setTimeout(() => void clearClipboardIfOwner(), CONFIG.clipboardClearSeconds * 1000);
		clipboardTimer.unref?.();
	}
}

/** Clear only if the clipboard still holds our value (never wipe a newer user copy). */
async function clearClipboardIfOwner(): Promise<boolean> {
	const value = clipboardValue ?? clipboardPending;
	const backend = clipboardBackend();
	clipboardValue = undefined;
	clipboardPending = undefined;
	if (clipboardTimer) {
		clearTimeout(clipboardTimer);
		clipboardTimer = undefined;
	}
	if (!value || !backend) return false;
	try {
		const r = await exec(backend.read[0], backend.read[1], { timeout: 3000 });
		if (r.code === 0 && r.stdout.length > 0 && !clipboardMatches(r.stdout, value)) return false;
	} catch {
		/* unreadable clipboard: clear anyway (fail-safe) */
	}
	try {
		await exec(backend.clear[0], backend.clear[1], { timeout: 5000, input: "" });
	} catch {
		/* best-effort */
	}
	return true;
}

/** Exit-path cleanup: timers never run after the process exits. */
function clearClipboardSync(): void {
	const value = clipboardValue ?? clipboardPending;
	const backend = clipboardBackend();
	clipboardValue = undefined;
	clipboardPending = undefined;
	if (!value || !backend) return;
	try {
		const r = spawnSync(backend.read[0], backend.read[1], { encoding: "utf8", timeout: 1000 });
		if (r.status === 0 && typeof r.stdout === "string" && r.stdout.length > 0 && !clipboardMatches(r.stdout, value)) return;
	} catch {
		/* clear anyway */
	}
	try {
		spawnSync(backend.clear[0], backend.clear[1], { input: "", timeout: 2000 });
	} catch {
		/* best-effort */
	}
}

/** Bash truncation can leave the full output in a file; scrub that copy too. */
async function scrubArtifact(details: unknown): Promise<void> {
	if (!details || typeof details !== "object" || !("fullOutputPath" in details)) return;
	const file = details.fullOutputPath;
	if (typeof file !== "string" || !file) return;
	try {
		const stat = await fs.stat(file);
		if (stat.size > 8 * 1024 * 1024) {
			await fs.rm(file, { force: true });
			return;
		}
		const raw = await fs.readFile(file, "utf-8");
		const { text, changed } = scrubText(raw, scrubValues.values());
		if (changed) await fs.writeFile(file, text, { mode: 0o600 });
	} catch {
		/* artifact already gone or unreadable */
	}
}

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------
export default function (pi: ExtensionAPI) {
	ompHost = "pi" in pi;

	// --- Override the bash tool: inject active secrets into child env only ---
	const bashTool = createBashTool(process.cwd(), {
		spawnHook: ({ command, cwd, env }) => {
			if (injected.size > 0) {
				for (const [name, rec] of injected) env[name] = rec.value;
			}
			return { command, cwd, env };
		},
	});
	pi.registerTool({ ...bashTool } as any);

	// Bash activity counts toward the idle auto-lock.
	pi.on("tool_call", async (event) => {
		if (event.toolName === "bash") touchActivity();
		return undefined;
	});

	// --- bw_list: vault map without secrets ---
	pi.registerTool({
		name: "bw_list",
		label: "Bitwarden list",
		description:
			"List Bitwarden vault items: name, username, URI, id. NEVER returns passwords, TOTP, notes or field values. " +
			"Search matches item name, username, or URI. Paginated with offset/limit. " +
			"First use in a session prompts for the master password (unlock). Use it to find item names/ids before bw_inject.",
		promptSnippet: "List Bitwarden items (no secrets)",
		promptGuidelines: [
			"Use bw_list to find Bitwarden item names/ids, then bw_inject to pass a credential to a bash command.",
		],
		parameters: Type.Object({
			search: Type.Optional(Type.String({ description: "Substring filter on name, username, or URI" })),
			offset: Type.Optional(Type.Number({ description: "Rows to skip (default 0)" })),
			limit: Type.Optional(Type.Number({ description: "Rows to return (default 60, max 200)" })),
		}),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const session = await ensureUnlocked(ctx, signal);
			const offsetInput = params.offset;
			const limitInput = params.limit;
			const offset =
				typeof offsetInput === "number" && Number.isFinite(offsetInput)
					? Math.max(0, Math.trunc(offsetInput))
					: 0;
			const limit =
				typeof limitInput === "number" && Number.isFinite(limitInput)
					? Math.min(200, Math.max(1, Math.trunc(limitInput)))
					: 60;
			let items = [...(await listItems(session, signal))].sort((a, b) => a.name.localeCompare(b.name));
			const query = (params.search ?? "").trim().toLowerCase();
			if (query) {
				items = items.filter((i) => `${i.name}\n${i.username}\n${i.uri}`.toLowerCase().includes(query));
			}
			const page = items.slice(offset, offset + limit);
			const lines = page.map(
				(i) => `${i.name || "?"} | user: ${i.username || "-"} | uri: ${i.uri || "-"} | id: ${i.id}`,
			);
			const range = page.length > 0 ? `${offset + 1}-${offset + page.length} of ` : "0 of ";
			const more =
				offset + page.length < items.length
					? `\n... ${items.length - offset - page.length} more (use offset=${offset + page.length})`
					: "";
			const text =
				`${range}${items.length} item(s)${query ? ` matching "${params.search}"` : ""}:\n` +
				lines.join("\n") +
				more;
			return { content: [{ type: "text", text }], details: { count: items.length, offset, limit } };
		},
	});

	// --- bw_inject: secret -> bash env, model never sees the value ---
	pi.registerTool({
		name: "bw_inject",
		label: "Bitwarden inject",
		description:
			"pi only (OMP requires bw_run): fetch a Bitwarden secret and inject it as an environment variable into bash tool commands. " +
			"The VALUE IS NEVER SHOWN to you nor stored in the conversation; reference it as $VAR in later bash commands. " +
			"Requires user confirmation per injection. Use when a command needs a credential (API token, docker login, git push, ...). " +
			"Browser filling: agent-browser fill @ref \"$VAR\" types it into a form without the value entering the conversation. " +
			"Prefer this over bw_reveal. field: 'password' (default) | 'totp' (seed) | 'code' (rotating TOTP code) | 'notes' | 'field:<customFieldName>'.",
		promptSnippet: "Pass a Bitwarden secret to bash via env var (value hidden from model)",
		promptGuidelines: [
			"Use bw_inject when a bash command needs a Bitwarden credential; never ask the user to paste secrets into chat.",
			"To fill a browser login with agent-browser: bw_inject the secret, then run agent-browser fill @ref \"$VAR\" — the value stays out of the conversation.",
			"For repeated browser logins, import once with: printenv $VAR | agent-browser auth save <name> --username <user> --password-stdin — afterwards agent-browser auth login <name> needs no secret.",
		],
		parameters: Type.Object({
			item: Type.String({ description: "Item name or id (see bw_list)" }),
			field: Type.Optional(
				Type.String({
					description:
						"password | totp (seed) | code (rotating TOTP) | notes | field:<customFieldName> (default: password)",
				}),
			),
			env: Type.String({ description: "Env var name for bash commands, e.g. MYAPP_TOKEN" }),
		}),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const field = (params.field ?? "password").trim();
			if (!FIELD_RE.test(field)) {
				throw new Error(`Invalid field "${field}". Use password | totp | code | notes | field:<name>.`);
			}
			if (ompHost) {
				throw new Error(
					"bw_inject does not work on OMP: its bash tool discards the spawnHook env. Use bw_run instead " +
						"(command runs with $VAULT_SECRET in its env), or bw_clipboard/bw_reveal.",
				);
			}
			const envName = normalizeEnvName(params.env);
			if (!injected.has(envName) && injected.size >= CONFIG.maxInjectedEnv) {
				throw new Error(`Too many injected vars (max ${CONFIG.maxInjectedEnv}). Run /bw clear to drop some.`);
			}

			const replaced = injected.get(envName);
			const ok = await confirmAction(
				ctx,
				"Bitwarden: inject secret into AI bash environment",
				`Item:   ${params.item}\nField:  ${field}\nEnv:    $${envName}` +
					(replaced ? `\n\nReplaces current injection: "${replaced.item}" (${replaced.field})` : "") +
					`\n\nCommands run by the AI in this pi session will see $${envName}.` +
					`\nThe value itself is never shown to the AI nor stored in the chat.` +
					`\nDropped on ` +
					(autoLockMs ? `idle lock (${Math.round(autoLockMs / 60000)} min) or /bw lock` : `/bw lock or session end`) +
					`.` +
					`\n\nAllow?`,
				signal,
			);
			if (!ok) {
				await audit("inject", `deny env=${envName} item="${params.item}" field=${field}`);
				throw new Error("User declined the injection.");
			}

			const { value, itemId, itemName } = await fetchSecret(ctx, params.item, field, signal);
			injected.set(envName, { value, item: itemName, field, at: Date.now() });
			rememberScrubValue(envName, value);
			await audit("inject", `allow env=${envName} item="${itemName}" (${itemId}) field=${field}`);
			safeStatus(ctx, `🔓 bw: ${injected.size} env var(s)`);
			const weak =
				value.length < 6
					? " WARNING: this value is shorter than 6 characters, so tool output cannot be reliably scrubbed."
					: "";

			return {
				content: [
					{
						type: "text",
						text:
							`Injected $${envName} (item "${itemName}", field ${field}) into the bash environment. ` +
							`Use $${envName} in bash commands. Do NOT try to print, echo, or exfiltrate it — output is scrubbed.${weak} ` +
							`Active injected vars: ${injectedListText()}`,
					},
				],
				details: { env: envName, item: itemName, field },
			};
		},
	});

	// --- bw_run: one command with the secret in its env (works on OMP) ---
	pi.registerTool({
		name: "bw_run",
		label: "Bitwarden run",
		description:
			"Run a shell command with a Bitwarden secret in its environment as $VAULT_SECRET (or a chosen env name). " +
			"The value never enters the conversation; stdout/stderr are scrubbed. Requires confirmation per call. " +
			"Use this on OMP (where bw_inject is unavailable) or when the secret should live for exactly one command. " +
			"field: 'password' (default) | 'totp' (seed) | 'code' (rotating TOTP) | 'notes' | 'field:<customFieldName>'.",
		promptSnippet: "Run one command with a Bitwarden secret in its env (value hidden)",
		promptGuidelines: [
			"Use bw_run for a command that needs a Bitwarden credential; reference it as $VAULT_SECRET.",
			"Never print or echo the value; prefer piping it into the consumer (e.g. --password-stdin).",
		],
		parameters: Type.Object({
			item: Type.String({ description: "Item name or id (see bw_list)" }),
			field: Type.Optional(
				Type.String({ description: "password | totp (seed) | code (rotating TOTP) | notes | field:<name> (default: password)" }),
			),
			env: Type.Optional(
				Type.String({ description: "Env var name available to the command (default VAULT_SECRET)" }),
			),
			command: Type.String({ description: "Shell command; use $VAULT_SECRET for the value" }),
			cwd: Type.Optional(Type.String({ description: "Working directory (default: current session cwd)" })),
			timeout: Type.Optional(Type.Number({ description: "Seconds (default 120, max 600)" })),
		}),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const field = (params.field ?? "password").trim();
			if (!FIELD_RE.test(field)) {
				throw new Error(`Invalid field "${field}". Use password | totp | code | notes | field:<name>.`);
			}
			if (!params.command.trim()) throw new Error("Command is empty.");
			const envName = normalizeEnvName(params.env ?? "VAULT_SECRET");
			const timeoutInput = params.timeout;
			const seconds =
				typeof timeoutInput === "number" && Number.isFinite(timeoutInput)
					? Math.min(600, Math.max(1, Math.trunc(timeoutInput)))
					: 120;
			const cwd = params.cwd?.trim() || ctx.cwd || process.cwd();
			const ok = await confirmAction(
				ctx,
				"Bitwarden: run command with secret",
				`Item:    ${params.item}\nField:   ${field}\nEnv:     $${envName}\nCwd:     ${cwd}\n` +
					`Command:\n${params.command}\n\n` +
					`The command runs once with $${envName} set. The value never enters the chat; output is scrubbed.\n\nAllow?`,
				signal,
			);
			if (!ok) {
				await audit("run", `deny env=${envName} item="${params.item}" field=${field}`);
				throw new Error("User declined the command.");
			}
			const { value, itemName } = await fetchSecret(ctx, params.item, field, signal);
			rememberScrubValue(envName, value);
			const r = await exec("bash", ["-c", params.command], {
				env: { [envName]: value },
				cwd,
				timeout: seconds * 1000,
				signal,
			});
			await audit("run", `allow env=${envName} item="${itemName}" field=${field} exit=${r.code}`);
			const raw = [r.stdout, r.stderr].filter((s) => s.length > 0).join("\n");
			const scrubbed = scrubText(raw, scrubValues.values()).text;
			const output =
				scrubbed.length > 32_000
					? `... (truncated to the last 32000 chars)\n${scrubbed.slice(-32_000)}`
					: scrubbed;
			return {
				content: [
					{
						type: "text",
						text:
							`Ran with $${envName} (item "${itemName}", field ${field}); exit ${r.code}.\n` +
							(output ? `--- output ---\n${output}` : "(no output)"),
					},
				],
				details: { item: itemName, field, env: envName, exit: r.code },
			};
		},
	});

	// --- bw_clipboard: secret -> clipboard, auto-cleared ---
	pi.registerTool({
		name: "bw_clipboard",
		label: "Bitwarden clipboard",
		description:
			"Copy a Bitwarden secret to the system clipboard; " +
			CLIPBOARD_CLEAR_TEXT +
			". The value never enters the conversation. Requires user confirmation. " +
			"field: 'password' (default) | 'totp' (seed) | 'code' (rotating TOTP code) | 'notes' | 'field:<customFieldName>'.",
		promptSnippet: "Copy a Bitwarden secret to clipboard (auto-clear)",
		parameters: Type.Object({
			item: Type.String({ description: "Item name or id (see bw_list)" }),
			field: Type.Optional(
				Type.String({ description: "password | totp (seed) | code (rotating TOTP) | notes | field:<name> (default: password)" }),
			),
		}),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const field = (params.field ?? "password").trim();
			if (!FIELD_RE.test(field)) throw new Error(`Invalid field "${field}".`);
			const ok = await confirmAction(
				ctx,
				"Bitwarden: copy secret to clipboard",
				`Item:   ${params.item}\nField:  ${field}\n\nThe value is copied to the system clipboard; ${CLIPBOARD_CLEAR_TEXT}. It never enters the chat.\n\nAllow?`,
				signal,
			);
			if (!ok) {
				await audit("clipboard", `deny item="${params.item}" field=${field}`);
				throw new Error("User declined.");
			}
			const { value, itemName } = await fetchSecret(ctx, params.item, field, signal);
			await copyToClipboard(value);
			await audit("clipboard", `allow item="${itemName}" field=${field}`);
			const clears =
				CONFIG.clipboardClearSeconds > 0 ? `Clears in ${CONFIG.clipboardClearSeconds}s.` : "Auto-clear disabled.";
			return {
				content: [{ type: "text", text: `Copied "${itemName}" (${field}) to clipboard. ${clears}` }],
				details: { item: itemName, field },
			};
		},
	});

	// --- bw_reveal: plain text to the model, per-call confirmation ---
	pi.registerTool({
		name: "bw_reveal",
		label: "Bitwarden reveal (danger)",
		description:
			"Return a Bitwarden secret in PLAIN TEXT. DANGEROUS: the value will be sent to the LLM provider and stored in the session file. " +
			"Requires explicit user confirmation every single call. Only use when bw_inject / bw_clipboard genuinely cannot do the job. " +
			"field: 'password' (default) | 'totp' (seed) | 'code' (rotating TOTP code) | 'notes' | 'field:<customFieldName>'.",
		promptSnippet: "Reveal a Bitwarden secret in plain text (per-call approval)",
		promptGuidelines: [
			"Use bw_reveal only as a last resort; prefer bw_inject (bash env) or bw_clipboard which keep the value out of the conversation.",
		],
		parameters: Type.Object({
			item: Type.String({ description: "Item name or id (see bw_list)" }),
			field: Type.Optional(
				Type.String({ description: "password | totp (seed) | code (rotating TOTP) | notes | field:<name> (default: password)" }),
			),
			reason: Type.String({ description: "Why the plain-text value is needed (shown to the user)" }),
		}),
		async execute(_id, params, signal, _onUpdate, ctx) {
			if (!CONFIG.allowReveal) throw new Error("bw_reveal is disabled in this installation (CONFIG.allowReveal).");
			const field = (params.field ?? "password").trim();
			if (!FIELD_RE.test(field)) throw new Error(`Invalid field "${field}".`);
			const provider = ctx?.model?.provider ?? "the LLM provider";
			const ok = await confirmAction(
				ctx,
				"⚠️ Bitwarden: reveal secret IN PLAIN TEXT",
				`Item:   ${params.item}\nField:  ${field}\nReason: ${params.reason}\n\n` +
					`The value will be shown to the AI, sent to ${provider}, and stored in the pi session file.\n` +
					`bw_inject (env var) or bw_clipboard usually suffice.\n\nAllow?`,
				signal,
			);
			if (!ok) {
				await audit("reveal", `deny item="${params.item}" field=${field}`);
				throw new Error("User declined the reveal.");
			}
			const { value, itemName } = await fetchSecret(ctx, params.item, field, signal);
			await audit("reveal", `allow item="${itemName}" field=${field}`);
			return {
				content: [{ type: "text", text: `${itemName} (${field}):\n<secret>${value}</secret>` }],
				details: { item: itemName, field },
			};
		},
	});

	// --- Scrubber: active secrets never reach the model via tool results ---
	pi.on("tool_result", async (event) => {
		if (event.toolName === "bw_reveal") return undefined; // intentional
		if (scrubValues.size === 0) return undefined;
		let changed = false;
		const content = event.content.map((block: any) => {
			if (block?.type !== "text" || typeof block.text !== "string") return block;
			const result = scrubText(block.text, scrubValues.values());
			if (result.changed) changed = true;
			return result.changed ? { ...block, text: result.text } : block;
		});
		// Host tool details can carry expanded command/env data; scrub them too.
		const details = scrubDeep(event.details, scrubValues.values());
		const structured = scrubDeep(event.structuredContent, scrubValues.values());
		if (details.changed || structured.changed) changed = true;
		await scrubArtifact(event.details);
		if (!changed) return undefined;
		const result: ToolResultEventResult = { content };
		if (details.changed) result.details = details.value;
		// The scrubbed tree is still JSON-shaped (strings, arrays, plain objects).
		if (structured.changed) result.structuredContent = structured.value as ToolResultEventResult["structuredContent"];
		return result;
	});

	// --- /bw command ---
	pi.registerCommand("bw", {
		description: "Bitwarden: status | unlock | lock | clear [ENV]",
		handler: async (args: string, ctx) => {
			const parts = (args ?? "status").trim().split(/\s+/);
			const sub = parts[0] || "status";
			if (sub === "lock") {
				await lock("user");
				safeStatus(ctx, undefined);
				ctx.ui.notify("Bitwarden: locked (session key + injected env dropped)", "info");
				return;
			}
			if (sub === "clear") {
				const target = parts[1];
				if (target) {
					let envName: string;
					try {
						envName = normalizeEnvName(target);
					} catch (e) {
						ctx.ui.notify(e instanceof Error ? e.message : String(e), "error");
						return;
					}
					const removed = injected.delete(envName);
					safeStatus(ctx, sessionKey ? `🔓 bw: ${injected.size} env var(s)` : undefined);
					ctx.ui.notify(
						removed ? `Bitwarden: dropped $${envName}` : `Bitwarden: $${envName} was not injected`,
						removed ? "info" : "warning",
					);
					return;
				}
				injected.clear();
				safeStatus(ctx, sessionKey ? `🔓 bw: 0 env var(s)` : undefined);
				ctx.ui.notify("Bitwarden: injected env vars cleared", "info");
				return;
			}
			if (sub === "unlock") {
				try {
					await ensureUnlocked(ctx);
					safeStatus(ctx, "🔓 bw: 0 env var(s)");
					ctx.ui.notify("Bitwarden: unlocked", "info");
				} catch (e: unknown) {
					ctx.ui.notify(`Bitwarden unlock failed: ${e instanceof Error ? e.message : String(e)}`, "error");
				}
				return;
			}
			// status
			let cli = "unknown";
			try {
				const st = await bwStatus();
				cli = st?.status ?? "unknown";
			} catch (e: unknown) {
				cli = `error: ${tail(e instanceof Error ? e.message : String(e), 80)}`;
			}
			const ttl = sessionKey && autoLockMs ? Math.max(0, Math.round((autoLockMs - (Date.now() - lastActivity)) / 60000)) : 0;
			ctx.ui.notify(
				`bw CLI: ${cli}\n` +
					`extension: ${sessionKey ? (autoLockMs ? `unlocked (auto-lock in ${ttl} min)` : "unlocked (session-lifetime)") : "locked"}\n` +
					`injected env: ${injectedListText()}\n` +
					`bw_reveal: ${CONFIG.allowReveal ? "enabled" : "disabled"}`,
				"info",
			);
		},
	});

	// --- Lifecycle ---
	pi.on("session_start", async (event, ctx) => {
		if (event.reason === "startup" || event.reason === "reload") return;
		if (event.reason === "resume" && CONFIG.keepOnResume) return; // same process: keep unlock
		// /new //fork: don't inherit secrets into a fresh session
		await lock(`session-${event.reason}`);
		safeStatus(ctx, undefined);
	});

	pi.on("session_shutdown", async (event) => {
		if (event.reason === "resume" && CONFIG.keepOnResume) return; // same process: keep unlock
		await lock(`session-${event.reason}`);
	});
}
