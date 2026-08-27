import { describe, expect, it, vi } from 'vitest';
import { fetchRelyperSession, hasAnyRole } from '../src/client.js';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

describe('fetchRelyperSession', () => {
  it('liefert den Nutzer aus einer /me-Antwort', async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ user: { id: 'db-1', email: 'jonas@relyper.test' } }));
    const session = await fetchRelyperSession<{ id: string }>({ fetch: fetchMock });

    expect(session.status).toBe('authenticated');
    if (session.status !== 'authenticated') return;
    expect(session.user.id).toBe('db-1');
    expect(fetchMock).toHaveBeenCalledWith('/api/me', expect.objectContaining({ method: 'GET' }));
  });

  it('akzeptiert auch eine Antwort ohne user-Huelle', async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ id: 'db-2' }));
    const session = await fetchRelyperSession<{ id: string }>({ fetch: fetchMock });

    expect(session.status).toBe('authenticated');
    if (session.status !== 'authenticated') return;
    expect(session.user.id).toBe('db-2');
  });

  it('unterscheidet nicht angemeldet von keine Berechtigung', async () => {
    const unauthenticated = await fetchRelyperSession({ fetch: async () => jsonResponse({}, 401) });
    const forbidden = await fetchRelyperSession({ fetch: async () => jsonResponse({}, 403) });

    expect(unauthenticated.status).toBe('unauthenticated');
    expect(forbidden.status).toBe('forbidden');
  });

  it('meldet andere Fehler als error statt zu werfen', async () => {
    const session = await fetchRelyperSession({ fetch: async () => jsonResponse({}, 500) });
    expect(session.status).toBe('error');
  });

  it('erlaubt einen eigenen Pfad', async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ user: {} }));
    await fetchRelyperSession({ fetch: fetchMock, path: '/api/session' });
    expect(fetchMock).toHaveBeenCalledWith('/api/session', expect.anything());
  });
});

describe('hasAnyRole', () => {
  it('prueft Rollen ohne Serverkontakt', () => {
    expect(hasAnyRole({ roles: ['a', 'b'] }, ['b'])).toBe(true);
    expect(hasAnyRole({ roles: ['a'] }, ['b', 'c'])).toBe(false);
  });
});
