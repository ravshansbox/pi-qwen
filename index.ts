import type { OAuthCredentials, OAuthLoginCallbacks } from '@earendil-works/pi-ai';
import type { ExtensionAPI } from '@earendil-works/pi-coding-agent';

const QWEN_OAUTH_BASE_URL = 'https://auth.qwen.ai/api/oauth';
const QWEN_DEVICE_CODE_ENDPOINT = `${QWEN_OAUTH_BASE_URL}/device/code`;
const QWEN_TOKEN_ENDPOINT = `${QWEN_OAUTH_BASE_URL}/token`;
const QWEN_CLIENT_ID = 'qwen-code-cli';
const QWEN_SCOPE = 'model:invoke profile:read';
const QWEN_DEVICE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';
const QWEN_DEFAULT_BASE_URL = 'https://api.qwen.ai/compatible-mode/v1';
const DEFAULT_POLL_INTERVAL_MS = 2000;
const EXPIRY_SAFETY_BUFFER_MS = 30_000;

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
}

function toFormBody(values: Record<string, string>): string {
  return new URLSearchParams(values).toString();
}

function computeExpiry(expiresInSeconds: number): number {
  return Date.now() + expiresInSeconds * 1000 - EXPIRY_SAFETY_BUFFER_MS;
}

function describeOAuthError(error: string, description?: string): string {
  switch (error) {
    case 'expired_token':
      return 'Qwen device code expired. Start login again.';
    case 'access_denied':
      return 'Qwen authorization was denied.';
    case 'invalid_grant':
      return 'Qwen refresh token is invalid or expired. Please log in again.';
    case 'invalid_request':
      return description || 'Invalid request sent to Qwen OAuth.';
    default:
      return description ? `${error}: ${description}` : error;
  }
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error('Qwen login cancelled'));
      return;
    }

    const timer = setTimeout(() => {
      cleanup();
      resolve();
    }, ms);

    const onAbort = () => {
      clearTimeout(timer);
      cleanup();
      reject(new Error('Qwen login cancelled'));
    };

    const cleanup = () => signal?.removeEventListener('abort', onAbort);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

async function parseJsonResponse<T>(response: Response): Promise<{
  data: T | null;
  text: string;
}> {
  const text = await response.text();
  try {
    return { data: JSON.parse(text) as T, text };
  } catch {
    return { data: null, text };
  }
}

function describeTokenResponse(response: Response, text: string, secrets: string[]): string {
  const url = response.url ? new URL(response.url) : null;
  let details = JSON.stringify({
    url: url ? `${url.origin}${url.pathname}` : QWEN_TOKEN_ENDPOINT,
    redirected: response.redirected,
    contentType: response.headers.get('content-type'),
    allow: response.headers.get('allow'),
    server: response.headers.get('server'),
    requestId: response.headers.get('x-request-id'),
    body: text
      .replace(
        /((?:access_token|refresh_token|id_token|device_code|user_code|code_verifier|code_challenge)["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s&<>,;}]+)/gi,
        '$1[redacted]',
      )
      .replace(/\s+/g, ' ')
      .trim(),
  });
  for (const secret of secrets) {
    if (secret) {
      details = details.replaceAll(secret, '[redacted]');
      details = details.replaceAll(encodeURIComponent(secret), '[redacted]');
    }
  }
  return details.length > 2000 ? `${details.slice(0, 2000)}…` : details;
}

async function startDeviceFlow(signal?: AbortSignal): Promise<DeviceCodeResponse> {
  const response = await fetch(QWEN_DEVICE_CODE_ENDPOINT, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: toFormBody({
      client_id: QWEN_CLIENT_ID,
      scope: QWEN_SCOPE,
    }),
    signal: signal ?? null,
  });

  const { data } = await parseJsonResponse<DeviceCodeResponse & OAuthErrorResponse>(response);

  if (
    !response.ok ||
    !data?.device_code ||
    !data.user_code ||
    !Number.isFinite(data.expires_in) ||
    data.expires_in <= 0 ||
    (data.interval !== undefined && (!Number.isFinite(data.interval) || data.interval <= 0))
  ) {
    throw new Error(
      data?.error
        ? `Qwen device authorization failed: ${describeOAuthError(data.error, data.error_description)}`
        : `Qwen device authorization failed: ${response.status} ${response.statusText}`,
    );
  }

  return data;
}

async function pollForToken(
  deviceCode: string,
  userCode: string,
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
    await sleep(intervalMs, signal);
    if (Date.now() >= deadline) break;

    const response = await fetch(QWEN_TOKEN_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: toFormBody({
        grant_type: QWEN_DEVICE_GRANT_TYPE,
        client_id: QWEN_CLIENT_ID,
        device_code: deviceCode,
      }),
      signal: signal ?? null,
    });

    const { data, text } = await parseJsonResponse<TokenResponse & OAuthErrorResponse>(response);

    if (response.ok && data?.access_token) {
      return data;
    }

    const error = data?.error;
    if (error === 'authorization_pending') continue;
    if (error === 'slow_down') {
      intervalMs += 5000;
      continue;
    }

    if (error) {
      throw new Error(
        `Qwen token request failed: ${describeOAuthError(error, data?.error_description)}`,
      );
    }

    throw new Error(
      `Qwen token request failed: ${response.status} ${response.statusText}. Response: ${describeTokenResponse(response, text, [deviceCode, userCode])}`,
    );
  }

  throw new Error('Qwen authentication timed out. Please try again.');
}

async function loginQwen(callbacks: OAuthLoginCallbacks): Promise<OAuthCredentials> {
  const device = await startDeviceFlow(callbacks.signal);
  const url = new URL('https://chat.qwen.ai/authorize');
  url.searchParams.set('user_code', device.user_code);
  url.searchParams.set('client', 'qwen-code');
  callbacks.onAuth({
    url: url.toString(),
    instructions: `Enter code: ${device.user_code}`,
  });

  const token = await pollForToken(
    device.device_code,
    device.user_code,
    device.interval,
    device.expires_in,
    callbacks.signal,
  );

  return {
    refresh: token.refresh_token || '',
    access: token.access_token,
    expires: computeExpiry(token.expires_in),
  };
}

async function refreshQwenToken(
  credentials: OAuthCredentials,
  signal?: AbortSignal,
): Promise<OAuthCredentials> {
  if (!credentials.refresh) {
    throw new Error('No Qwen refresh token available. Please log in again.');
  }

  const response = await fetch(QWEN_TOKEN_ENDPOINT, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: toFormBody({
      grant_type: 'refresh_token',
      refresh_token: credentials.refresh,
      client_id: QWEN_CLIENT_ID,
    }),
    signal: signal ?? null,
  });

  const { data } = await parseJsonResponse<TokenResponse & OAuthErrorResponse>(response);

  if (!response.ok || !data?.access_token) {
    if (data?.error) {
      throw new Error(
        `Qwen token refresh failed: ${describeOAuthError(data.error, data.error_description)}`,
      );
    }
    throw new Error(`Qwen token refresh failed: ${response.status} ${response.statusText}`);
  }

  return {
    refresh: data.refresh_token || credentials.refresh,
    access: data.access_token,
    expires: computeExpiry(data.expires_in),
  };
}

export default function (pi: ExtensionAPI) {
  pi.registerProvider('qwen', {
    baseUrl: QWEN_DEFAULT_BASE_URL,
    api: 'openai-completions',
    headers: {
      Accept: 'application/json',
    },
    models: [
      {
        id: 'qwen3.8-max',
        name: 'Qwen 3.8 Max',
        reasoning: false,
        input: ['text', 'image'],
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
        contextWindow: 1_000_000,
        maxTokens: 32_000,
        compat: {
          supportsDeveloperRole: false,
          maxTokensField: 'max_tokens',
        },
      },
    ],
    oauth: {
      name: 'Qwen Account',
      login: loginQwen,
      refreshToken: refreshQwenToken,
      getApiKey: (credentials) => credentials.access,
    },
  });
}
