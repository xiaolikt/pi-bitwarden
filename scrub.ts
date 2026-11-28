/** Values the output scrubber must keep hiding. */
export type ScrubValue = { env: string; value: string };

/**
 * Replace a secret and its common encodings (base64, base64url, URL, hex) in
 * text. Short values (< 6 chars) are deliberately skipped: replacing them
 * would corrupt ordinary output more often than it protects anything.
 */
export function scrubText(input: string, values: Iterable<ScrubValue>): { text: string; changed: boolean } {
	let text = input;
	let changed = false;
	const replace = (needle: string, label: string) => {
		if (needle.length < 6 || !text.includes(needle)) return;
		text = text.split(needle).join(label);
		changed = true;
	};
	for (const { env, value } of values) {
		replace(value, `[BW_SCRUBBED:${env}]`);
		if (value.length >= 16) {
			const b64 = Buffer.from(value, "utf-8").toString("base64");
			replace(b64, `[BW_SCRUBBED-B64:${env}]`);
			replace(b64.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_"), `[BW_SCRUBBED-B64URL:${env}]`);
		}
		const url = encodeURIComponent(value);
		if (url !== value) replace(url, `[BW_SCRUBBED-URL:${env}]`);
		replace(Buffer.from(value, "utf-8").toString("hex"), `[BW_SCRUBBED-HEX:${env}]`);
	}
	return { text, changed };
}

/** OMP's bash `details.trace` can echo the sourced env file; scrub nested values. */
export function scrubDeep(
	value: unknown,
	values: Iterable<ScrubValue>,
	depth = 0,
): { value: unknown; changed: boolean } {
	if (depth > 12) return { value, changed: false };
	if (typeof value === "string") {
		const result = scrubText(value, values);
		return { value: result.text, changed: result.changed };
	}
	if (Array.isArray(value)) {
		let changed = false;
		const next = value.map((entry) => {
			const result = scrubDeep(entry, values, depth + 1);
			if (result.changed) changed = true;
			return result.value;
		});
		return { value: changed ? next : value, changed };
	}
	if (value && typeof value === "object") {
		let changed = false;
		const next: Record<string, unknown> = {};
		for (const [key, entry] of Object.entries(value)) {
			const result = scrubDeep(entry, values, depth + 1);
			if (result.changed) changed = true;
			next[key] = result.value;
		}
		return { value: changed ? next : value, changed };
	}
	return { value, changed: false };
}
