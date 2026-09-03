import { beforeEach, describe, expect, it, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { relyperOidcAuth, type RelyperOidcFastifyOptions } from '../src/oidc-fastify.js';
import { createSessionCodec } from '../src/oidc/session.js';
import type { RelyperIdentity } from '../src/types.js';
import {
  CLIENT_ID,
  CLIENT_SECRET,
  ISSUER,
  REDIRECT_URI,
  createFakeIdp,
  discoveryDocument,
  pendingNonce,
  type FakeIdp
} from './fake-idp.js';

/**
 * End-to-end exercise of the adapter: a browser walks through the login, comes
 * back with a code, and the session cookie it receives is what unlocks the
 * application. Every step is checked with the HTTP artefacts a browser would see.
 */

const SESSION_SECRET = 'test-session-secret-long-enough-0000';

let idp: FakeIdp;

async function buildApp(overrides: Partial<RelyperOidcFastifyOptions> = {}): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  await app.register(relyperOidcAuth, {
    issuer: ISSUER,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: REDIRECT_URI,
    sessionSecret: SESSION_SECRET,
    requiredRole: 'relyper_private_case_user',
    fetch: idp.fetch,
    cookieSecure: false,
    meRoute: '/api/me',
    ...overrides
  } as RelyperOidcFastifyOptions);

  app.get('/api/cases', async (request) => ({ subject: request.relyperIdentity.subject }));
  return app;
}

/** Reads one Set-Cookie value by name out of a reply. */
function cookieFrom(headers: Record<string, unknown>, name: string): string | null {
  const raw = headers['set-cookie'];
  const list = Array.isArray(raw) ? raw : raw ? [String(raw)] : [];
  for (const entry of list) {
    if (entry.startsWith(name + '=')) return entry;
  }
  return null;
}

function valueOf(cookie: string | null): string {
  if (!cookie) return '';
  return decodeURIComponent(cookie.slice(cookie.indexOf('=') + 1).split(';')[0]);
}

/** Drives the full login and returns the session cookie a browser would hold. */
async function performLogin(app: FastifyInstance): Promise<string> {
  const start = await app.inject({ method: 'GET', url: '/auth/login?returnTo=/cases/7' });
  const loginCookie = cookieFrom(start.headers as Record<string, unknown>, 'relyper_login');
  const state = new URL(start.headers.location as string).searchParams.get('state') ?? '';
  const nonce = new URL(start.headers.location as string).searchParams.get('nonce') ?? '';
  pendingNonce.set('code-1', nonce);

  const callback = await app.inject({
    method: 'GET',
    url: '/auth/callback?code=code-1&state=' + encodeURIComponent(state),
    headers: { cookie: 'relyper_login=' + encodeURIComponent(valueOf(loginCookie)) }
  });

  const sessionCookie = cookieFrom(callback.headers as Record<string, unknown>, 'relyper_session');
  return 'relyper_session=' + encodeURIComponent(valueOf(sessionCookie));
}

beforeEach(async () => {
  idp = await createFakeIdp();
  pendingNonce.clear();
});

describe('login route', () => {
  it('redirects to the identity provider and remembers the handshake', async () => {
    const app = await buildApp();
    const response = await app.inject({ method: 'GET', url: '/auth/login?returnTo=/cases/7' });

    expect(response.statusCode).toBe(302);
    const target = new URL(response.headers.location as string);
    expect(target.origin + target.pathname).toBe(discoveryDocument.authorization_endpoint);
    expect(target.searchParams.get('code_challenge_method')).toBe('S256');

    const cookie = cookieFrom(response.headers as Record<string, unknown>, 'relyper_login');
    expect(cookie).toContain('HttpOnly');
    // Lax, because the callback arrives as a top-level navigation from the IdP;
    // Strict would withhold the cookie exactly then and break every login.
    expect(cookie).toContain('SameSite=Lax');
    expect(response.headers['cache-control']).toBe('no-store');
  });
});

describe('callback route', () => {
  it('establishes a session and returns the user to where they started', async () => {
    const app = await buildApp();
    const start = await app.inject({ method: 'GET', url: '/auth/login?returnTo=/cases/7' });
    const loginCookie = valueOf(cookieFrom(start.headers as Record<string, unknown>, 'relyper_login'));
    const target = new URL(start.headers.location as string);
    pendingNonce.set('code-1', target.searchParams.get('nonce') ?? '');

    const response = await app.inject({
      method: 'GET',
      url: '/auth/callback?code=code-1&state=' + encodeURIComponent(target.searchParams.get('state') ?? ''),
      headers: { cookie: 'relyper_login=' + encodeURIComponent(loginCookie) }
    });

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe('/cases/7');

    const session = cookieFrom(response.headers as Record<string, unknown>, 'relyper_session');
    expect(session).toContain('HttpOnly');

    // The handshake cookie is single-use and must be gone afterwards.
    const cleared = cookieFrom(response.headers as Record<string, unknown>, 'relyper_login');
    expect(cleared).toContain('Max-Age=0');

    const payload = await createSessionCodec(SESSION_SECRET).open(valueOf(session));
    expect(payload?.identity.subject).toBe('user-1');
  });

  it('refuses a callback that no login started', async () => {
    const app = await buildApp();
    const response = await app.inject({ method: 'GET', url: '/auth/callback?code=c&state=s' });
    expect(response.statusCode).toBe(400);
    expect(response.json().code).toBe('missing_transaction');
    expect(cookieFrom(response.headers as Record<string, unknown>, 'relyper_session')).toBeNull();
  });

  it('refuses a callback whose state does not match the handshake', async () => {
    const app = await buildApp();
    const start = await app.inject({ method: 'GET', url: '/auth/login' });
    const loginCookie = valueOf(cookieFrom(start.headers as Record<string, unknown>, 'relyper_login'));

    const response = await app.inject({
      method: 'GET',
      url: '/auth/callback?code=c&state=forged-state',
      headers: { cookie: 'relyper_login=' + encodeURIComponent(loginCookie) }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().code).toBe('invalid_state');
    expect(cookieFrom(response.headers as Record<string, unknown>, 'relyper_session')).toBeNull();
  });

  it('grants no session to a user without the required role', async () => {
    idp.claims.roles = ['factory_viewer'];
    const app = await buildApp();
    const start = await app.inject({ method: 'GET', url: '/auth/login' });
    const loginCookie = valueOf(cookieFrom(start.headers as Record<string, unknown>, 'relyper_login'));
    const target = new URL(start.headers.location as string);
    pendingNonce.set('code-1', target.searchParams.get('nonce') ?? '');

    const response = await app.inject({
      method: 'GET',
      url: '/auth/callback?code=code-1&state=' + encodeURIComponent(target.searchParams.get('state') ?? ''),
      headers: { cookie: 'relyper_login=' + encodeURIComponent(loginCookie) }
    });

    expect(response.statusCode).toBe(403);
    expect(response.json().code).toBe('missing_role');
    expect(cookieFrom(response.headers as Record<string, unknown>, 'relyper_session')).toBeNull();
  });

  it('can send a failed login to an error page instead of a JSON body', async () => {
    const app = await buildApp({ loginErrorRedirect: '/login-failed' });
    const response = await app.inject({ method: 'GET', url: '/auth/callback?code=c&state=s' });
    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe('/login-failed?error=missing_transaction');
  });

  it('answers a refused code exchange with 401, not 502 (a reverse proxy replaces an origin 502 with its own generic error page, hiding this response body entirely)', async () => {
    idp.setTokenResponse({ status: 401, body: { error: 'invalid_client', error_description: 'client authentication failed' } });
    const app = await buildApp();
    const start = await app.inject({ method: 'GET', url: '/auth/login' });
    const loginCookie = valueOf(cookieFrom(start.headers as Record<string, unknown>, 'relyper_login'));
    const target = new URL(start.headers.location as string);

    const response = await app.inject({
      method: 'GET',
      url: '/auth/callback?code=code-1&state=' + encodeURIComponent(target.searchParams.get('state') ?? ''),
      headers: { cookie: 'relyper_login=' + encodeURIComponent(loginCookie) }
    });

    expect(response.statusCode).toBe(401);
    expect(response.json().code).toBe('token_exchange_failed');
    expect(cookieFrom(response.headers as Record<string, unknown>, 'relyper_session')).toBeNull();
  });
});

describe('session guard', () => {
  it('answers an unauthenticated API request with 401 and the login route', async () => {
    const app = await buildApp();
    const response = await app.inject({ method: 'GET', url: '/api/cases' });
    expect(response.statusCode).toBe(401);
    expect(response.json()).toMatchObject({ code: 'unauthenticated', loginUrl: '/auth/login' });
  });

  it('redirects a browser navigation to the login and remembers the target', async () => {
    const app = await buildApp();
    const response = await app.inject({
      method: 'GET',
      url: '/cases/7',
      headers: { accept: 'text/html,application/xhtml+xml', 'sec-fetch-mode': 'navigate' }
    });
    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe('/auth/login?returnTo=%2Fcases%2F7');
  });

  it('lets a valid session through', async () => {
    const app = await buildApp();
    const cookie = await performLogin(app);
    const response = await app.inject({ method: 'GET', url: '/api/cases', headers: { cookie } });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ subject: 'user-1' });
  });

  it('rejects a tampered session cookie', async () => {
    const app = await buildApp();
    const cookie = await performLogin(app);
    const broken = cookie.slice(0, -6) + 'AAAAAA';
    const response = await app.inject({ method: 'GET', url: '/api/cases', headers: { cookie: broken } });
    expect(response.statusCode).toBe(401);
  });

  it('rejects a session cookie sealed by another application', async () => {
    // Two service providers behind the same domain must not share sessions.
    const foreign = await createSessionCodec('a-different-application-secret-00000').seal(
      {
        identity: { subject: 'x', email: 'x@y.z', displayName: 'X', roles: ['relyper_private_case_user'] },
        authenticatedAt: Math.floor(Date.now() / 1000),
        sessionId: 'sid-foreign'
      },
      600
    );
    const app = await buildApp();
    const response = await app.inject({
      method: 'GET',
      url: '/api/cases',
      headers: { cookie: 'relyper_session=' + encodeURIComponent(foreign) }
    });
    expect(response.statusCode).toBe(401);
  });

  it('ends a session that has passed its absolute lifetime', async () => {
    const app = await buildApp();
    const stale = await createSessionCodec(SESSION_SECRET).seal(
      {
        identity: { subject: 'user-1', email: 'a@b.c', displayName: 'A', roles: ['relyper_private_case_user'] },
        // Sealed recently, but the login it represents happened two days ago.
        authenticatedAt: Math.floor(Date.now() / 1000) - 2 * 24 * 60 * 60,
        sessionId: 'sid-stale'
      },
      600
    );
    const response = await app.inject({
      method: 'GET',
      url: '/api/cases',
      headers: { cookie: 'relyper_session=' + encodeURIComponent(stale) }
    });
    expect(response.statusCode).toBe(401);
    expect(response.json().code).toBe('session_expired');
  });

  it('re-checks the required role on every request, not just at login', async () => {
    const app = await buildApp();
    const cookie = await performLogin(app);

    // Same session, but an application that has since tightened its requirement.
    const stricter = await buildApp({ requiredRole: 'relyper_private_case_admin' });
    const response = await stricter.inject({ method: 'GET', url: '/api/cases', headers: { cookie } });
    expect(response.statusCode).toBe(403);
    expect(response.json().code).toBe('missing_role');
  });

  it('leaves the auth routes themselves unguarded', async () => {
    const app = await buildApp();
    const response = await app.inject({ method: 'GET', url: '/auth/login' });
    expect(response.statusCode).toBe(302);
  });

  it('maps the identity onto the application user via resolveUser', async () => {
    const resolveUser = vi.fn(async (identity: RelyperIdentity) => ({ id: 'local-1', idpSubject: identity.subject }));
    const app = await buildApp({ resolveUser });
    const cookie = await performLogin(app);

    const response = await app.inject({ method: 'GET', url: '/api/me', headers: { cookie } });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ user: { id: 'local-1', idpSubject: 'user-1' } });
    expect(resolveUser).toHaveBeenCalled();
  });

  it('renews a rolling session on activity', async () => {
    const app = await buildApp();
    const cookie = await performLogin(app);
    const response = await app.inject({ method: 'GET', url: '/api/cases', headers: { cookie } });
    expect(cookieFrom(response.headers as Record<string, unknown>, 'relyper_session')).toBeTruthy();
  });

  it('does not renew when rolling sessions are off', async () => {
    const app = await buildApp({ rollingSession: false });
    const cookie = await performLogin(app);
    const response = await app.inject({ method: 'GET', url: '/api/cases', headers: { cookie } });
    expect(cookieFrom(response.headers as Record<string, unknown>, 'relyper_session')).toBeNull();
  });
});

describe('logout route', () => {
  it('clears both cookies and sends the browser on', async () => {
    const app = await buildApp();
    const cookie = await performLogin(app);
    const response = await app.inject({ method: 'POST', url: '/auth/logout', headers: { cookie } });

    expect(response.statusCode).toBe(302);
    expect(cookieFrom(response.headers as Record<string, unknown>, 'relyper_session')).toContain('Max-Age=0');
    expect(cookieFrom(response.headers as Record<string, unknown>, 'relyper_login')).toContain('Max-Age=0');
  });

  it('keeps a stateless session usable until it expires', async () => {
    const app = await buildApp();
    const cookie = await performLogin(app);
    await app.inject({ method: 'POST', url: '/auth/logout', headers: { cookie } });

    // Without a revocation list the logout only affects the browser that asked:
    // a cookie copied beforehand keeps working until it expires. That is the
    // trade-off of a stateless session, and the reason for the next test.
    const response = await app.inject({ method: 'GET', url: '/api/cases', headers: { cookie } });
    expect(response.statusCode).toBe(200);
  });

  it('makes logout binding when the application keeps a revocation list', async () => {
    const revoked = new Set<string>();
    const app = await buildApp({
      onLogout: (sessionId) => {
        revoked.add(sessionId);
      },
      isSessionRevoked: (sessionId) => revoked.has(sessionId)
    });

    const cookie = await performLogin(app);
    expect((await app.inject({ method: 'GET', url: '/api/cases', headers: { cookie } })).statusCode).toBe(200);

    await app.inject({ method: 'POST', url: '/auth/logout', headers: { cookie } });
    expect(revoked.size).toBe(1);

    // Now even the copied cookie is dead.
    const response = await app.inject({ method: 'GET', url: '/api/cases', headers: { cookie } });
    expect(response.statusCode).toBe(401);
    expect(response.json().code).toBe('session_revoked');
  });

  it('hands the session id to onLogin so it can be recorded', async () => {
    const seen: string[] = [];
    const app = await buildApp({ onLogin: (_result, _request, sessionId) => { seen.push(sessionId); } });
    await performLogin(app);
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatch(/^[A-Za-z0-9_-]{20,}$/);
  });
});
