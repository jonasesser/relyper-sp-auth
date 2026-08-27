import { describe, expect, it, vi } from 'vitest';
import { fetchRelyperSession, hasAnyRole } from '../src/client.js';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

describe('fetchRelyperSession', () => {
  it('returns the user from a /me response', async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ user: { id: 'db-1', email: 'jonas@relyper.test' } }));
    const session = await fetchRelyperSession<{ id: string }>({ fetch: fetchMock });

    expect(session.status).toBe('authenticated');
    if (session.status !== 'authenticated') return;
    expect(session.user.id).toBe('db-1');
    expect(fetchMock).toHaveBeenCalledWith('/api/me', expect.objectContaining({ method: 'GET' }));
  });

  it('also accepts a response without a user wrapper', async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ id: 'db-2' }));
    const session = await fetchRelyperSession<{ id: string }>({ fetch: fetchMock });

    expect(session.status).toBe('authenticated');
    if (session.status !== 'authenticated') return;
    expect(session.user.id).toBe('db-2');
  });

  it('distinguishes unauthenticated from forbidden', async () => {
    const unauthenticated = await fetchRelyperSession({ fetch: async () => jsonResponse({}, 401) });
    const forbidden = await fetchRelyperSession({ fetch: async () => jsonResponse({}, 403) });

    expect(unauthenticated.status).toBe('unauthenticated');
    expect(forbidden.status).toBe('forbidden');
  });

  it('reports other errors as error instead of throwing', async () => {
    const session = await fetchRelyperSession({ fetch: async () => jsonResponse({}, 500) });
    expect(session.status).toBe('error');
  });

  it('allows a custom path', async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ user: {} }));
    await fetchRelyperSession({ fetch: fetchMock, path: '/api/session' });
    expect(fetchMock).toHaveBeenCalledWith('/api/session', expect.anything());
  });
});

describe('hasAnyRole', () => {
  it('checks roles without contacting the server', () => {
    expect(hasAnyRole({ roles: ['a', 'b'] }, ['b'])).toBe(true);
    expect(hasAnyRole({ roles: ['a'] }, ['b', 'c'])).toBe(false);
  });
});
