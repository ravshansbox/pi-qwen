import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';
import extension from './index.ts';

type Fetch = typeof fetch;
const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

function loadProvider() {
  let config: any;
  const pi: any = {
    registerProvider: (_name: string, value: unknown) => {
      config = value;
    },
    on: () => {},
  };
  extension(pi);
  return config;
}

function abortableFetch(body: unknown): Fetch {
  return ((_url: string, init?: RequestInit) =>
    new Promise((resolve, reject) => {
      if (init?.signal?.aborted) return reject(new Error('aborted'));
      init?.signal?.addEventListener('abort', () => reject(new Error('aborted')));
      setImmediate(() => resolve(new Response(JSON.stringify(body), { status: 200 })));
    })) as Fetch;
}

test('token refresh stops when the abort signal fires', async () => {
  globalThis.fetch = abortableFetch({ access_token: 'new', expires_in: 3600 });
  const { oauth } = loadProvider();
  const controller = new AbortController();
  controller.abort();

  await assert.rejects(
    oauth.refreshToken({ refresh: 'r', access: 'a', expires: 0 }, controller.signal),
  );
});

test('login stops when cancelled during the device code request', async () => {
  globalThis.fetch = ((_url: string, init?: RequestInit) =>
    new Promise((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new Error('aborted')));
    })) as Fetch;
  const { oauth } = loadProvider();
  const controller = new AbortController();
  const login = oauth.login({ onAuth: () => {}, signal: controller.signal });
  controller.abort();

  const outcome = await Promise.race([
    login.then(
      () => 'resolved',
      () => 'rejected',
    ),
    new Promise((resolve) => setTimeout(() => resolve('pending'), 100)),
  ]);
  assert.equal(outcome, 'rejected');
});

for (const [format, body, contentType] of [
  ['HTML', '<html><h1>Request blocked by gateway</h1></html>', 'text/html'],
  [
    'JSON',
    '{"message":"Request blocked by gateway","access_token":"secret-access"}',
    'application/json',
  ],
  ['long text', `Request blocked by gateway ${'x'.repeat(4000)}`, 'text/plain'],
]) {
  test(`login reports bounded, sanitised diagnostics for a ${format} token error`, async () => {
    globalThis.fetch = (async (url: string, init?: RequestInit) => {
      if (url.endsWith('/device/code')) {
        return Response.json({
          device_code: 'secret-device',
          user_code: 'TEST-CODE',
          verification_uri: 'https://example.com',
          expires_in: 600,
        });
      }
      assert.equal(new URLSearchParams(init?.body as string).has('code_verifier'), false);
      const responseBody =
        contentType === 'application/json'
          ? JSON.stringify({
              ...JSON.parse(body!),
              device_code: 'secret-device',
              user_code: 'TEST-CODE',
            })
          : `device_code=secret-device&user_code=TEST-CODE\n${body}\nEcho: secret-device TEST-CODE`;
      const response = new Response(responseBody, {
        status: 405,
        statusText: 'Not Allowed',
        headers: {
          'content-type': contentType!,
          allow: 'GET',
          server: 'test-gateway',
          'x-request-id': 'request-123',
        },
      });
      Object.defineProperties(response, {
        url: { value: 'https://chat.qwen.ai/blocked?device_code=secret-device#secret-fragment' },
        redirected: { value: true },
      });
      return response;
    }) as Fetch;
    const { oauth } = loadProvider();

    await assert.rejects(oauth.login({ onAuth: () => {} }), (error: Error) => {
      assert.match(error.message, /Qwen token request failed: 405 Not Allowed/);
      assert.match(error.message, /Request blocked by gateway/);
      assert.match(error.message, /"url":"https:\/\/chat.qwen.ai\/blocked"/);
      assert.match(error.message, /"redirected":true/);
      assert.ok(error.message.includes(`"contentType":"${contentType}"`));
      assert.match(error.message, /"allow":"GET"/);
      assert.match(error.message, /"server":"test-gateway"/);
      assert.match(error.message, /"requestId":"request-123"/);
      assert.match(error.message, /\[redacted\]/);
      assert.doesNotMatch(error.message, /secret-device|TEST-CODE|secret-access|secret-fragment/);
      assert.ok(error.message.length < 2100);
      return true;
    });
  });
}

const flush = () => new Promise((resolve) => setImmediate(resolve));

test('subscription login preserves the server code and polls with the new protocol', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 1_000_000 });
  let polls = 0;
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    assert.equal(init?.method, 'POST');
    assert.equal(
      new Headers(init?.headers).get('content-type'),
      'application/x-www-form-urlencoded',
    );
    const body = Object.fromEntries(new URLSearchParams(init?.body as string));
    if (url.endsWith('/device/code')) {
      assert.equal(url, 'https://auth.qwen.ai/api/oauth/device/code');
      assert.deepEqual(body, { client_id: 'qwen-code-cli', scope: 'model:invoke profile:read' });
      return Response.json({
        device_code: 'device-secret',
        user_code: 'ABCD-EFGH',
        verification_uri: 'https://chat.qwen.ai/device',
        verification_uri_complete: 'https://chat.qwen.ai/device?user_code=ABCD-EFGH',
        expires_in: 600,
        interval: 5,
      });
    }
    assert.equal(url, 'https://auth.qwen.ai/api/oauth/token');
    assert.deepEqual(body, {
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      client_id: 'qwen-code-cli',
      device_code: 'device-secret',
    });
    if (++polls === 1) return Response.json({ error: 'authorization_pending' }, { status: 400 });
    return Response.json({
      access_token: 'access-secret',
      refresh_token: 'refresh-secret',
      token_type: 'Bearer',
      expires_in: 3600,
    });
  }) as Fetch;
  const { oauth } = loadProvider();
  let auth: unknown;
  const login = oauth.login({
    onAuth: (value: unknown) => {
      auth = value;
    },
  });
  await flush();
  assert.deepEqual(auth, {
    url: 'https://chat.qwen.ai/authorize?user_code=ABCD-EFGH&client=qwen-code',
    instructions: 'Enter code: ABCD-EFGH',
  });
  assert.equal(polls, 0);
  t.mock.timers.tick(5000);
  await flush();
  assert.equal(polls, 1);
  t.mock.timers.tick(5000);
  const credentials = await login;
  assert.deepEqual(credentials, {
    access: 'access-secret',
    refresh: 'refresh-secret',
    expires: Date.now() + 3_600_000 - 30_000,
  });
  assert.equal(oauth.getApiKey(credentials), 'access-secret');
});

test('subscription refresh rotates tokens using the new endpoint and client', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1_000_000 });
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    assert.equal(url, 'https://auth.qwen.ai/api/oauth/token');
    assert.equal(init?.method, 'POST');
    assert.deepEqual(Object.fromEntries(new URLSearchParams(init?.body as string)), {
      grant_type: 'refresh_token',
      client_id: 'qwen-code-cli',
      refresh_token: 'old-refresh',
    });
    return Response.json({
      access_token: 'new-access',
      refresh_token: 'new-refresh',
      token_type: 'Bearer',
      expires_in: 3600,
    });
  }) as Fetch;
  const { oauth } = loadProvider();
  assert.deepEqual(
    await oauth.refreshToken({ access: 'old', refresh: 'old-refresh', expires: 0 }),
    {
      access: 'new-access',
      refresh: 'new-refresh',
      expires: Date.now() + 3_600_000 - 30_000,
    },
  );
});

test('the registered model uses the subscription inference API', () => {
  const provider = loadProvider();
  assert.equal(provider.baseUrl, 'https://api.qwen.ai/compatible-mode/v1');
  assert.equal(provider.api, 'openai-completions');
  assert.equal(provider.apiKey, undefined);
  assert.deepEqual(provider.headers, { Accept: 'application/json' });
  assert.deepEqual(
    provider.models.map((model: { id: string }) => model.id),
    ['qwen3.8-max'],
  );
  assert.equal(provider.models[0].contextWindow, 1_000_000);
  assert.equal(provider.models[0].maxTokens, 32_000);
  assert.equal(provider.models[0].reasoning, false);
});

test('login increases the poll interval by five seconds for every slow_down', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let polls = 0;
  globalThis.fetch = (async (url: string) => {
    if (url.endsWith('/device/code')) {
      return Response.json({
        device_code: 'd',
        user_code: 'ABCD-EFGH',
        verification_uri: 'https://chat.qwen.ai/device',
        expires_in: 600,
        interval: 15,
      });
    }
    polls++;
    return Response.json({ error: 'slow_down' }, { status: 400 });
  }) as Fetch;
  const { oauth } = loadProvider();
  const controller = new AbortController();
  const login = oauth.login({ onAuth: () => {}, signal: controller.signal });
  const rejection = assert.rejects(login, /cancelled/);

  await flush();
  t.mock.timers.tick(15_000);
  await flush();
  assert.equal(polls, 1);
  t.mock.timers.tick(19_000);
  await flush();
  assert.equal(polls, 1);
  t.mock.timers.tick(1000);
  await flush();
  assert.equal(polls, 2);
  t.mock.timers.tick(24_000);
  await flush();
  assert.equal(polls, 2);
  t.mock.timers.tick(1000);
  await flush();
  assert.equal(polls, 3);
  controller.abort();
  await rejection;
});
