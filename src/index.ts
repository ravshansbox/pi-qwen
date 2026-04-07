import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { OAuthCredentials, OAuthLoginCallbacks } from "@mariozechner/pi-ai";
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

const QWEN_OAUTH_BASE_URL = "https://chat.qwen.ai";
const QWEN_DEVICE_CODE_ENDPOINT = `${QWEN_OAUTH_BASE_URL}/api/v1/oauth2/device/code`;
const QWEN_TOKEN_ENDPOINT = `${QWEN_OAUTH_BASE_URL}/api/v1/oauth2/token`;
const QWEN_CLIENT_ID = "f0304373b74a44d2b584a3fb70ca9e56";
const QWEN_SCOPE = "openid profile email model.completion";
const QWEN_DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";
const QWEN_DEFAULT_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1";
const DEFAULT_POLL_INTERVAL_MS = 2000;
const EXPIRY_SAFETY_BUFFER_MS = 5 * 60 * 1000;

type ThinkingLevel = "minimal" | "low" | "medium" | "high" | "xhigh";

interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval?: number;
}

interface OAuthErrorResponse {
  error: string;
  error_description?: string;
}

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in: number;
  resource_url?: string;
}

function toFormBody(values: Record<string, string>): string {
  return new URLSearchParams(values).toString();
}

function generatePkce() {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

function getQwenBaseUrl(resourceUrl?: string): string {
  if (!resourceUrl) return QWEN_DEFAULT_BASE_URL;

  const normalized = resourceUrl.startsWith("http")
    ? resourceUrl
    : `https://${resourceUrl}`;

  return normalized.endsWith("/v1") ? normalized : `${normalized}/v1`;
}

function computeExpiry(expiresInSeconds: number): number {
  return Date.now() + expiresInSeconds * 1000 - EXPIRY_SAFETY_BUFFER_MS;
}

function describeOAuthError(error: string, description?: string): string {
  switch (error) {
    case "expired_token":
      return "Qwen device code expired. Start login again.";
    case "access_denied":
      return "Qwen authorization was denied.";
    case "invalid_grant":
      return "Qwen refresh token is invalid or expired. Please log in again.";
    case "invalid_request":
      return description || "Invalid request sent to Qwen OAuth.";
    default:
      return description ? `${error}: ${description}` : error;
  }
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error("Qwen login cancelled"));
      return;
    }

    const timer = setTimeout(() => {
      cleanup();
      resolve();
    }, ms);

    const onAbort = () => {
      clearTimeout(timer);
      cleanup();
      reject(new Error("Qwen login cancelled"));
    };

    const cleanup = () => signal?.removeEventListener("abort", onAbort);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

async function parseJsonResponse<T>(response: Response): Promise<T | null> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

async function startDeviceFlow(): Promise<{ device: DeviceCodeResponse; verifier: string }> {
  const { verifier, challenge } = generatePkce();

  const response = await fetch(QWEN_DEVICE_CODE_ENDPOINT, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
      "x-request-id": randomUUID(),
    },
    body: toFormBody({
      client_id: QWEN_CLIENT_ID,
      scope: QWEN_SCOPE,
      code_challenge: challenge,
      code_challenge_method: "S256",
    }),
  });

  const data = await parseJsonResponse<DeviceCodeResponse & OAuthErrorResponse>(response);

  if (!response.ok || !data?.device_code || !data.verification_uri) {
    throw new Error(
      data?.error
        ? `Qwen device authorization failed: ${describeOAuthError(data.error, data.error_description)}`
        : `Qwen device authorization failed: ${response.status} ${response.statusText}`,
    );
  }

  return { device: data, verifier };
}

async function pollForToken(
  deviceCode: string,
  verifier: string,
  intervalSeconds: number | undefined,
  expiresIn: number,
  signal?: AbortSignal,
): Promise<TokenResponse> {
  const deadline = Date.now() + expiresIn * 1000;
  let intervalMs = Math.max(
    1000,
    Math.floor((intervalSeconds ?? DEFAULT_POLL_INTERVAL_MS / 1000) * 1000),
  );

  while (Date.now() < deadline) {
    if (signal?.aborted) throw new Error("Qwen login cancelled");

    const response = await fetch(QWEN_TOKEN_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: toFormBody({
        grant_type: QWEN_DEVICE_GRANT_TYPE,
        client_id: QWEN_CLIENT_ID,
        device_code: deviceCode,
        code_verifier: verifier,
      }),
      signal,
    });

    const data = await parseJsonResponse<TokenResponse & OAuthErrorResponse>(response);

    if (response.ok && data?.access_token) {
      return data;
    }

    const error = data?.error;
    if (error === "authorization_pending") {
      await sleep(intervalMs, signal);
      continue;
    }
    if (error === "slow_down") {
      intervalMs = Math.min(intervalMs + 3000, 10000);
      await sleep(intervalMs, signal);
      continue;
    }

    if (error) {
      throw new Error(`Qwen token request failed: ${describeOAuthError(error, data?.error_description)}`);
    }

    throw new Error(`Qwen token request failed: ${response.status} ${response.statusText}`);
  }

  throw new Error("Qwen authentication timed out. Please try again.");
}

async function loginQwen(callbacks: OAuthLoginCallbacks): Promise<OAuthCredentials> {
  const { device, verifier } = await startDeviceFlow();
  callbacks.onAuth({
    url: device.verification_uri_complete || device.verification_uri,
    instructions: device.verification_uri_complete
      ? undefined
      : `Enter code: ${device.user_code}`,
  });

  const token = await pollForToken(
    device.device_code,
    verifier,
    device.interval,
    device.expires_in,
    callbacks.signal,
  );

  return {
    refresh: token.refresh_token || "",
    access: token.access_token,
    expires: computeExpiry(token.expires_in),
    enterpriseUrl: token.resource_url,
  };
}

async function refreshQwenToken(credentials: OAuthCredentials): Promise<OAuthCredentials> {
  if (!credentials.refresh) {
    throw new Error("No Qwen refresh token available. Please log in again.");
  }

  const response = await fetch(QWEN_TOKEN_ENDPOINT, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: toFormBody({
      grant_type: "refresh_token",
      refresh_token: credentials.refresh,
      client_id: QWEN_CLIENT_ID,
    }),
  });

  const data = await parseJsonResponse<TokenResponse & OAuthErrorResponse>(response);

  if (!response.ok || !data?.access_token) {
    if (data?.error) {
      throw new Error(`Qwen token refresh failed: ${describeOAuthError(data.error, data.error_description)}`);
    }
    throw new Error(`Qwen token refresh failed: ${response.status} ${response.statusText}`);
  }

  return {
    refresh: data.refresh_token || credentials.refresh,
    access: data.access_token,
    expires: computeExpiry(data.expires_in),
    enterpriseUrl: data.resource_url ?? credentials.enterpriseUrl,
  };
}

function qwenReasoningEffortMap(): Record<ThinkingLevel, string> {
  return {
    minimal: "low",
    low: "low",
    medium: "medium",
    high: "high",
    xhigh: "high",
  };
}

function sanitizeQwenPayload(payload: unknown): unknown {
  if (!payload || typeof payload !== "object") return payload;

  const next = { ...(payload as Record<string, unknown>) };

  delete next.store;
  delete next.parallel_tool_calls;
  delete next.stream_options;
  delete next.service_tier;
  delete next.user;
  delete next.metadata;

  if (Array.isArray(next.tools) && next.tools.length === 0) {
    delete next.tools;
    delete next.tool_choice;
  }

  if (next.tool_choice === "auto" && !Array.isArray(next.tools)) {
    delete next.tool_choice;
  }

  if (next.temperature == null) delete next.temperature;
  if (next.top_p == null) delete next.top_p;
  if (next.reasoning_effort == null) delete next.reasoning_effort;

  if (!("enable_thinking" in next)) {
    next.enable_thinking = false;
  }

  return next;
}

export default function qwenProviderExtension(pi: ExtensionAPI) {
  pi.registerProvider("qwen", {
    baseUrl: QWEN_DEFAULT_BASE_URL,
    apiKey: "DASHSCOPE_API_KEY",
    api: "openai-completions",
    headers: {
      Accept: "application/json",
      "X-DashScope-CacheControl": "enable",
      "X-DashScope-AuthType": "qwen-oauth",
      "X-DashScope-UserAgent": "QwenCode/pi-extension",
      "User-Agent": "QwenCode/pi-extension",
    },
    models: [
      {
        id: "coder-model",
        name: "coder-model",
        reasoning: true,
        input: ["text", "image"],
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
        contextWindow: 1_000_000,
        maxTokens: 65_536,
        compat: {
          supportsDeveloperRole: false,
          supportsReasoningEffort: true,
          reasoningEffortMap: qwenReasoningEffortMap(),
          maxTokensField: "max_tokens",
          thinkingFormat: "qwen",
        },
      },
    ],
    oauth: {
      name: "Qwen",
      login: loginQwen,
      refreshToken: refreshQwenToken,
      getApiKey: (credentials) => credentials.access,
      modifyModels: (models, credentials) => {
        const oauthBaseUrl = getQwenBaseUrl(credentials.enterpriseUrl as string | undefined);
        return models.map((model) => {
          if (model.provider !== "qwen") return model;
          if (model.id === "coder-model") {
            return {
              ...model,
              baseUrl: oauthBaseUrl,
              headers: {
                ...model.headers,
                "X-DashScope-AuthType": "qwen-oauth",
              },
            };
          }
          return model;
        });
      },
    },
  });

  pi.on("before_provider_request", (event) => {
    const payload = event.payload as { model?: unknown } | undefined;
    if (payload?.model !== "coder-model") return;
    return sanitizeQwenPayload(event.payload);
  });

}
