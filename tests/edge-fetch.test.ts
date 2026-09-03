import { afterEach, describe, expect, it, vi } from 'vitest';
import { createDefaultOidcFetch } from '../src/oidc/edge-fetch.js';

/**
 * The default fetch exists for one production-observed reason: Node's bare
 * "node" User-Agent gets Managed-Challenged by the IdP's edge bot protection
 * before the request ever reaches the IdP's own application code, which a
 * server can never solve -- see the module's own doc comment for the full
 * story (first hit, and fixed, in RelyperPrivateCase; folded back in here so
 * every service provider gets it for free instead of reinventing it).
 */
describe('createDefaultOidcFetch', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('sends a descriptive User-Agent identifying the client, not the bare Node default', async () => {
    const calls: RequestInit[] = [];
    vi.stubGlobal('fetch', async (_url: unknown, init: RequestInit) => {
      calls.push(init);
      return new Response('{}', { status: 200 });
    });

    const doFetch = createDefaultOidcFetch('client-relyper-piano-test');
    await doFetch('https://idp.example/token', { method: 'POST' });

    expect(calls).toHaveLength(1);
    const headers = new Headers(calls[0].headers);
    expect(headers.get('user-agent')).toBe('@relyper/sp-auth (client:client-relyper-piano-test)');
  });

  it('does not overwrite a User-Agent the caller already set', async () => {
    const calls: RequestInit[] = [];
    vi.stubGlobal('fetch', async (_url: unknown, init: RequestInit) => {
      calls.push(init);
      return new Response('{}', { status: 200 });
    });

    const doFetch = createDefaultOidcFetch('client-relyper-piano-test');
    await doFetch('https://idp.example/token', { headers: { 'user-agent': 'custom/1.0' } });

    expect(new Headers(calls[0].headers).get('user-agent')).toBe('custom/1.0');
  });

  it('retries once when an edge layer -- not the IdP -- answers 403', async () => {
    let attempt = 0;
    vi.stubGlobal('fetch', async () => {
      attempt += 1;
      if (attempt === 1) return new Response('blocked', { status: 403 });
      return new Response('{"ok":true}', { status: 200 });
    });

    const doFetch = createDefaultOidcFetch('client-x');
    const response = await doFetch('https://idp.example/token', { method: 'POST' });

    expect(attempt).toBe(2);
    expect(response.status).toBe(200);
  });

  it.each([403, 429, 502, 503, 504])('treats %i as an edge rejection worth retrying', async (status) => {
    let attempt = 0;
    vi.stubGlobal('fetch', async () => {
      attempt += 1;
      return new Response('edge', { status: attempt === 1 ? status : 200 });
    });

    const doFetch = createDefaultOidcFetch('client-x');
    await doFetch('https://idp.example/token');

    expect(attempt).toBe(2);
  });

  it('does not retry a genuine application error from the IdP itself', async () => {
    let attempt = 0;
    vi.stubGlobal('fetch', async () => {
      attempt += 1;
      return new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 });
    });

    const doFetch = createDefaultOidcFetch('client-x');
    const response = await doFetch('https://idp.example/token', { method: 'POST' });

    expect(attempt).toBe(1);
    expect(response.status).toBe(400);
  });

  it('reports the edge rejection to onEdgeRejection before retrying', async () => {
    let attempt = 0;
    vi.stubGlobal('fetch', async () => {
      attempt += 1;
      return new Response('blocked', { status: attempt === 1 ? 403 : 200 });
    });

    const seen: unknown[] = [];
    const doFetch = createDefaultOidcFetch('client-x', (rejection) => seen.push(rejection));
    await doFetch('https://idp.example/token');

    expect(seen).toEqual([{ url: 'https://idp.example/token', status: 403, retried: true }]);
  });

  it('does not retry a non-replayable streamed body, and reports retried: false', async () => {
    let attempt = 0;
    vi.stubGlobal('fetch', async () => {
      attempt += 1;
      return new Response('blocked', { status: 403 });
    });

    const seen: unknown[] = [];
    const doFetch = createDefaultOidcFetch('client-x', (rejection) => seen.push(rejection));
    const stream = new ReadableStream();
    const response = await doFetch('https://idp.example/token', { method: 'POST', body: stream, duplex: 'half' } as RequestInit);

    expect(attempt).toBe(1);
    expect(response.status).toBe(403);
    expect(seen).toEqual([{ url: 'https://idp.example/token', status: 403, retried: false }]);
  });
});
