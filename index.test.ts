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
