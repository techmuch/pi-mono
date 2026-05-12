/**
 * Google Gemini OAuth flow
 *
 * NOTE: This module uses Node.js http.createServer for the OAuth callback server.
 * It is only intended for CLI use, not browser environments.
 */

import type { Server } from "node:http";
import { oauthErrorHtml, oauthSuccessHtml } from "./oauth-page.js";
import { generatePKCE } from "./pkce.js";
import type { OAuthCredentials, OAuthLoginCallbacks, OAuthPrompt, OAuthProviderInterface } from "./types.js";

type CallbackServerInfo = {
	server: Server;
	redirectUri: string;
	cancelWait: () => void;
	waitForCode: () => Promise<{ code: string; state: string } | null>;
};

type NodeApis = {
	createServer: typeof import("node:http").createServer;
};

let nodeApis: NodeApis | null = null;
let nodeApisPromise: Promise<NodeApis> | null = null;

// Use environment variables for Client ID and Secret, or provide safe defaults for testing if appropriate.
// In a real CLI, users might need to provide their own OAuth Client ID/Secret via config if not hardcoded.
const getClientId = () => process.env.GOOGLE_OAUTH_CLIENT_ID || "";
const getClientSecret = () => process.env.GOOGLE_OAUTH_CLIENT_SECRET || "";

const AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const CALLBACK_HOST = process.env.PI_OAUTH_CALLBACK_HOST || "127.0.0.1";
const CALLBACK_PORT = 53694; // Different port to avoid conflict
const CALLBACK_PATH = "/callback";
const REDIRECT_URI = `http://localhost:${CALLBACK_PORT}${CALLBACK_PATH}`;
const SCOPES = "https://www.googleapis.com/auth/generative-learning";

async function getNodeApis(): Promise<NodeApis> {
	if (nodeApis) return nodeApis;
	if (!nodeApisPromise) {
		if (typeof process === "undefined" || (!process.versions?.node && !process.versions?.bun)) {
			throw new Error("Google OAuth is only available in Node.js environments");
		}
		nodeApisPromise = import("node:http").then((httpModule) => ({
			createServer: httpModule.createServer,
		}));
	}
	nodeApis = await nodeApisPromise;
	return nodeApis;
}

function parseAuthorizationInput(input: string): { code?: string; state?: string } {
	const value = input.trim();
	if (!value) return {};

	try {
		const url = new URL(value);
		return {
			code: url.searchParams.get("code") ?? undefined,
			state: url.searchParams.get("state") ?? undefined,
		};
	} catch {
		// not a URL
	}

	if (value.includes("#")) {
		const [code, state] = value.split("#", 2);
		return { code, state };
	}

	if (value.includes("code=")) {
		const params = new URLSearchParams(value);
		return {
			code: params.get("code") ?? undefined,
			state: params.get("state") ?? undefined,
		};
	}

	return { code: value };
}

function formatErrorDetails(error: unknown): string {
	if (error instanceof Error) {
		const details: string[] = [`${error.name}: ${error.message}`];
		const errorWithCode = error as Error & { code?: string; errno?: number | string; cause?: unknown };
		if (errorWithCode.code) details.push(`code=${errorWithCode.code}`);
		if (typeof errorWithCode.errno !== "undefined") details.push(`errno=${String(errorWithCode.errno)}`);
		if (typeof error.cause !== "undefined") {
			details.push(`cause=${formatErrorDetails(error.cause)}`);
		}
		if (error.stack) {
			details.push(`stack=${error.stack}`);
		}
		return details.join("; ");
	}
	return String(error);
}

async function startCallbackServer(expectedState: string): Promise<CallbackServerInfo> {
	const { createServer } = await getNodeApis();

	return new Promise((resolve, reject) => {
		let settleWait: ((value: { code: string; state: string } | null) => void) | undefined;
		const waitForCodePromise = new Promise<{ code: string; state: string } | null>((resolveWait) => {
			let settled = false;
			settleWait = (value) => {
				if (settled) return;
				settled = true;
				resolveWait(value);
			};
		});

		const server = createServer((req, res) => {
			try {
				const url = new URL(req.url || "", "http://localhost");
				if (url.pathname !== CALLBACK_PATH) {
					res.writeHead(404, { "Content-Type": "text/html; charset=utf-8" });
					res.end(oauthErrorHtml("Callback route not found."));
					return;
				}

				const code = url.searchParams.get("code");
				const state = url.searchParams.get("state");
				const error = url.searchParams.get("error");

				if (error) {
					res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
					res.end(oauthErrorHtml("Google authentication did not complete.", `Error: ${error}`));
					return;
				}

				if (!code || !state) {
					res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
					res.end(oauthErrorHtml("Missing code or state parameter."));
					return;
				}

				if (state !== expectedState) {
					res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
					res.end(oauthErrorHtml("State mismatch."));
					return;
				}

				res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
				res.end(oauthSuccessHtml("Google authentication completed. You can close this window."));
				settleWait?.({ code, state });
			} catch {
				res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
				res.end("Internal error");
			}
		});

		server.on("error", (err) => {
			reject(err);
		});

		server.listen(CALLBACK_PORT, CALLBACK_HOST, () => {
			resolve({
				server,
				redirectUri: REDIRECT_URI,
				cancelWait: () => {
					settleWait?.(null);
				},
				waitForCode: () => waitForCodePromise,
			});
		});
	});
}

async function postForm(url: string, body: URLSearchParams): Promise<string> {
	const response = await fetch(url, {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			Accept: "application/json",
		},
		body: body.toString(),
		signal: AbortSignal.timeout(30_000),
	});

	const responseBody = await response.text();

	if (!response.ok) {
		throw new Error(`HTTP request failed. status=${response.status}; url=${url}; body=${responseBody}`);
	}

	return responseBody;
}

async function exchangeAuthorizationCode(
	code: string,
	verifier: string,
	redirectUri: string,
): Promise<OAuthCredentials> {
	const clientId = getClientId();
	const clientSecret = getClientSecret();

	if (!clientId) {
		throw new Error("GOOGLE_OAUTH_CLIENT_ID environment variable is required.");
	}

	let responseBody: string;
	try {
		const params = new URLSearchParams({
			grant_type: "authorization_code",
			client_id: clientId,
			code,
			redirect_uri: redirectUri,
			code_verifier: verifier,
		});

		if (clientSecret) {
			params.append("client_secret", clientSecret);
		}

		responseBody = await postForm(TOKEN_URL, params);
	} catch (error) {
		throw new Error(
			`Token exchange request failed. url=${TOKEN_URL}; redirect_uri=${redirectUri}; response_type=authorization_code; details=${formatErrorDetails(error)}`,
		);
	}

	let tokenData: { access_token: string; refresh_token: string; expires_in: number };
	try {
		tokenData = JSON.parse(responseBody) as { access_token: string; refresh_token: string; expires_in: number };
	} catch (error) {
		throw new Error(
			`Token exchange returned invalid JSON. url=${TOKEN_URL}; body=${responseBody}; details=${formatErrorDetails(error)}`,
		);
	}

	return {
		refresh: tokenData.refresh_token,
		access: tokenData.access_token,
		expires: Date.now() + tokenData.expires_in * 1000 - 5 * 60 * 1000,
	};
}

/**
 * Login with Google OAuth (authorization code + PKCE)
 */
export async function loginGoogle(options: {
	onAuth: (info: { url: string; instructions?: string }) => void;
	onPrompt: (prompt: OAuthPrompt) => Promise<string>;
	onProgress?: (message: string) => void;
	onManualCodeInput?: () => Promise<string>;
}): Promise<OAuthCredentials> {
	const clientId = getClientId();
	if (!clientId) {
		throw new Error("GOOGLE_OAUTH_CLIENT_ID environment variable is required.");
	}

	const { verifier, challenge } = await generatePKCE();
	const server = await startCallbackServer(verifier);

	let code: string | undefined;
	let state: string | undefined;
	let redirectUriForExchange = REDIRECT_URI;

	try {
		const authParams = new URLSearchParams({
			client_id: clientId,
			response_type: "code",
			redirect_uri: REDIRECT_URI,
			scope: SCOPES,
			code_challenge: challenge,
			code_challenge_method: "S256",
			state: verifier,
			access_type: "offline", // Required to get a refresh token from Google
			prompt: "consent", // Force consent screen to guarantee refresh token is provided
		});

		options.onAuth({
			url: `${AUTHORIZE_URL}?${authParams.toString()}`,
			instructions:
				"Complete login in your browser. If the browser is on another machine, paste the final redirect URL here.",
		});

		if (options.onManualCodeInput) {
			let manualInput: string | undefined;
			let manualError: Error | undefined;
			const manualPromise = options
				.onManualCodeInput()
				.then((input) => {
					manualInput = input;
					server.cancelWait();
				})
				.catch((err) => {
					manualError = err instanceof Error ? err : new Error(String(err));
					server.cancelWait();
				});

			const result = await server.waitForCode();

			if (manualError) {
				throw manualError;
			}

			if (result?.code) {
				code = result.code;
				state = result.state;
				redirectUriForExchange = REDIRECT_URI;
			} else if (manualInput) {
				const parsed = parseAuthorizationInput(manualInput);
				if (parsed.state && parsed.state !== verifier) {
					throw new Error("OAuth state mismatch");
				}
				code = parsed.code;
				state = parsed.state ?? verifier;
			}

			if (!code) {
				await manualPromise;
				if (manualError) {
					throw manualError;
				}
				if (manualInput) {
					const parsed = parseAuthorizationInput(manualInput);
					if (parsed.state && parsed.state !== verifier) {
						throw new Error("OAuth state mismatch");
					}
					code = parsed.code;
					state = parsed.state ?? verifier;
				}
			}
		} else {
			const result = await server.waitForCode();
			if (result?.code) {
				code = result.code;
				state = result.state;
				redirectUriForExchange = REDIRECT_URI;
			}
		}

		if (!code) {
			const input = await options.onPrompt({
				message: "Paste the authorization code or full redirect URL:",
				placeholder: REDIRECT_URI,
			});
			const parsed = parseAuthorizationInput(input);
			if (parsed.state && parsed.state !== verifier) {
				throw new Error("OAuth state mismatch");
			}
			code = parsed.code;
			state = parsed.state ?? verifier;
		}

		if (!code) {
			throw new Error("Missing authorization code");
		}

		if (!state) {
			throw new Error("Missing OAuth state");
		}

		options.onProgress?.("Exchanging authorization code for tokens...");
		return exchangeAuthorizationCode(code, verifier, redirectUriForExchange);
	} finally {
		server.server.close();
	}
}

/**
 * Refresh Google OAuth token
 */
export async function refreshGoogleToken(refreshToken: string): Promise<OAuthCredentials> {
	const clientId = getClientId();
	const clientSecret = getClientSecret();

	if (!clientId) {
		throw new Error("GOOGLE_OAUTH_CLIENT_ID environment variable is required to refresh tokens.");
	}

	let responseBody: string;
	try {
		const params = new URLSearchParams({
			grant_type: "refresh_token",
			client_id: clientId,
			refresh_token: refreshToken,
		});

		if (clientSecret) {
			params.append("client_secret", clientSecret);
		}

		responseBody = await postForm(TOKEN_URL, params);
	} catch (error) {
		throw new Error(`Google token refresh request failed. url=${TOKEN_URL}; details=${formatErrorDetails(error)}`);
	}

	let data: { access_token: string; refresh_token?: string; expires_in: number; scope?: string };
	try {
		data = JSON.parse(responseBody) as {
			access_token: string;
			refresh_token?: string;
			expires_in: number;
			scope?: string;
		};
	} catch (error) {
		throw new Error(
			`Google token refresh returned invalid JSON. url=${TOKEN_URL}; body=${responseBody}; details=${formatErrorDetails(error)}`,
		);
	}

	return {
		// Google sometimes returns a new refresh token, sometimes doesn't. If not, reuse the old one.
		refresh: data.refresh_token || refreshToken,
		access: data.access_token,
		expires: Date.now() + data.expires_in * 1000 - 5 * 60 * 1000,
	};
}

export const googleOAuthProvider: OAuthProviderInterface = {
	id: "google",
	name: "Google Gemini",
	usesCallbackServer: true,

	async login(callbacks: OAuthLoginCallbacks): Promise<OAuthCredentials> {
		return loginGoogle({
			onAuth: callbacks.onAuth,
			onPrompt: callbacks.onPrompt,
			onProgress: callbacks.onProgress,
			onManualCodeInput: callbacks.onManualCodeInput,
		});
	},

	async refreshToken(credentials: OAuthCredentials): Promise<OAuthCredentials> {
		return refreshGoogleToken(credentials.refresh);
	},

	getApiKey(credentials: OAuthCredentials): string {
		return credentials.access;
	},
};
