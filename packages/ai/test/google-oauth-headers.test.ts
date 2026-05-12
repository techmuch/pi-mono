import { afterEach, describe, expect, it, vi } from "vitest";
import { getModel } from "../src/models.js";
import { streamGoogle } from "../src/providers/google.js";
import type { Context } from "../src/types.js";

describe("Google Gemini OAuth Headers", () => {
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it("injects Bearer token into Authorization header when ya29. token is used", async () => {
		const fetchMock = vi.fn(async () => {
			return new Response(
				JSON.stringify({
					candidates: [{ content: { parts: [{ text: "Hello" }] }, finishReason: "STOP" }],
					usageMetadata: { promptTokenCount: 1, candidatesTokenCount: 1, totalTokenCount: 2 },
				}),
				{
					status: 200,
					headers: { "Content-Type": "application/json" },
				},
			);
		});
		vi.stubGlobal("fetch", fetchMock);

		const model = getModel("google", "gemini-1.5-pro");
		const context: Context = { messages: [{ role: "user", content: "Hi", timestamp: Date.now() }] };
		// ya29. is a typical prefix for Google OAuth access tokens
		const oauthToken = "ya29.test-token";

		const stream = streamGoogle(model, context, { apiKey: oauthToken });

		try {
			// We need to consume the stream to trigger the fetch
			for await (const event of stream) {
				if (event.type === "error") {
					console.error("Stream error:", event.error);
				}
			}
		} catch (e) {
			console.error("Caught error during stream consumption:", e);
		}

		expect(fetchMock).toHaveBeenCalled();
		const lastCall = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
		const requestHeaders = lastCall[1]?.headers as Headers;

		expect(requestHeaders.get("authorization")).toBe(`Bearer ${oauthToken}`);
	});

	it("uses standard key= parameter when a normal API key is used", async () => {
		const fetchMock = vi.fn(async () => {
			return new Response(
				JSON.stringify([
					{
						candidates: [{ content: { parts: [{ text: "Hello" }] }, finishReason: "STOP" }],
						usageMetadata: { promptTokenCount: 1, candidatesTokenCount: 1, totalTokenCount: 2 },
					},
				]),
				{
					status: 200,
					headers: { "Content-Type": "application/json" },
				},
			);
		});
		vi.stubGlobal("fetch", fetchMock);

		const model = getModel("google", "gemini-1.5-pro");
		const context: Context = { messages: [{ role: "user", content: "Hi", timestamp: Date.now() }] };
		const standardKey = "AIza-standard-key";

		const stream = streamGoogle(model, context, { apiKey: standardKey });

		try {
			for await (const event of stream) {
				if (event.type === "error") {
					console.error("Stream error:", event.error);
				}
			}
		} catch (e) {
			console.error("Caught error during stream consumption:", e);
		}

		expect(fetchMock).toHaveBeenCalled();
		const lastCall = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
		const requestHeaders = lastCall[1]?.headers as Headers;

		expect(requestHeaders?.get("authorization")).toBeNull();
		expect(requestHeaders?.get("x-goog-api-key")).toBe(standardKey);
	});
});
