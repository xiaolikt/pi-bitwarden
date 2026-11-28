import { describe, expect, test } from "bun:test";
import { scrubDeep, scrubText } from "../scrub.ts";

const SECRET = "supersecret-value-123";
const values = [{ env: "T1", value: SECRET }];

describe("scrubText", () => {
	test("redacts the raw value", () => {
		const result = scrubText(`out: ${SECRET}\n`, values);
		expect(result.changed).toBe(true);
		expect(result.text).toBe("out: [BW_SCRUBBED:T1]\n");
	});

	test("redacts base64 and base64url", () => {
		// 22 bytes → base64 ends with "=", so the url-safe form differs.
		const raw = `${SECRET}x`;
		const b64 = Buffer.from(raw).toString("base64");
		const b64url = b64.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
		const result = scrubText(`${b64} ${b64url}`, [{ env: "T1", value: raw }]);
		expect(result.text).toBe("[BW_SCRUBBED-B64:T1] [BW_SCRUBBED-B64URL:T1]");
	});

	test("redacts URL-encoded and hex forms", () => {
		const raw = "a b&c=d/e";
		const encoded = encodeURIComponent(raw);
		const hex = Buffer.from(raw).toString("hex");
		const result = scrubText(`${encoded} ${hex}`, [{ env: "U", value: raw }]);
		expect(result.text).toBe("[BW_SCRUBBED-URL:U] [BW_SCRUBBED-HEX:U]");
	});

	test("leaves short values alone", () => {
		const result = scrubText("abc abc", [{ env: "S", value: "abc" }]);
		expect(result.changed).toBe(false);
		expect(result.text).toBe("abc abc");
	});

	test("leaves unrelated text alone", () => {
		const result = scrubText("nothing here", values);
		expect(result.changed).toBe(false);
		expect(result.text).toBe("nothing here");
	});
});

describe("scrubDeep", () => {
	test("scrubs nested strings in details/structuredContent", () => {
		const input = {
			trace: { units: [{ source: `export T1='${SECRET}'` }], history: [["argv", SECRET]] },
		};
		const result = scrubDeep(input, values);
		expect(result.changed).toBe(true);
		expect(JSON.stringify(result.value)).not.toContain(SECRET);
		expect(JSON.stringify(result.value)).toContain("[BW_SCRUBBED:T1]");
	});

	test("preserves shapes and unchanged values", () => {
		const input = { ok: true, count: 3, list: [null, "plain"] };
		const result = scrubDeep(input, values);
		expect(result.changed).toBe(false);
		expect(result.value).toBe(input);
	});
});
