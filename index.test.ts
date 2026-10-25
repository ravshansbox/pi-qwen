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

test('login never polls faster after the server asks it to slow down', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const requests: string[] = [];
  globalThis.fetch = (async (url: string) => {
    requests.push(url);
    if (url.endsWith('/device/code')) {
      return Response.json({
        device_code: 'd',
        user_code: 'u',
        verification_uri: 'https://example.com',
        expires_in: 600,
        interval: 15,
      });
    }
    return Response.json({ error: 'slow_down' }, { status: 400 });
  }) as Fetch;
  const { oauth } = loadProvider();
  const controller = new AbortController();
  const login = oauth.login({ onAuth: () => {}, signal: controller.signal });
  login.catch(() => {});
  const flush = () => new Promise((resolve) => setImmediate(resolve));

  await flush();
  await flush();
  const pollsBefore = requests.length;
  t.mock.timers.tick(14_000);
  await flush();
  await flush();

  assert.equal(requests.length, pollsBefore);
  controller.abort();
});
