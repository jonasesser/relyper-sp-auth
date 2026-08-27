import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { relyperAuth } from '../src/fastify.js';
import type { RelyperIdentity } from '../src/types.js';

const ROLE = 'relyper_private_case_user';

const headers = {
  'x-relyper-subject': 'idp-subject-1',
  'x-relyper-email': 'jonas@relyper.test',
  'x-relyper-name': 'Jonas',
  'x-relyper-roles': ROLE
};

let app: FastifyInstance | null = null;

afterEach(async () => {
  await app?.close();
  app = null;
});

async function buildApp(options: Parameters<typeof relyperAuth>[1] = {}): Promise<FastifyInstance> {
  const instance = Fastify({ logger: false });
  await instance.register(relyperAuth, { requiredRole: ROLE, ...options });
  instance.get('/api/secret', async (request) => ({
    identity: request.relyperIdentity,
    principal: (request as unknown as Record<string, unknown>).principal
  }));
  instance.get('/public', async () => ({ ok: true }));
  await instance.ready();
  app = instance;
  return instance;
}

describe('Fastify adapter', () => {
  it('lets a valid identity through and attaches it to the request', async () => {
    const instance = await buildApp();
    const response = await instance.inject({ method: 'GET', url: '/api/secret', headers });

    expect(response.statusCode).toBe(200);
    expect(response.json().identity).toMatchObject({ subject: 'idp-subject-1', roles: [ROLE] });
  });

  it('blocks requests without an identity with 401', async () => {
    const instance = await buildApp();
    const response = await instance.inject({ method: 'GET', url: '/api/secret' });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({ error: 'Authentication required.' });
  });

  it('blocks requests with the wrong role with 403', async () => {
    const instance = await buildApp();
    const response = await instance.inject({
      method: 'GET',
      url: '/api/secret',
      headers: { ...headers, 'x-relyper-roles': 'other_role' }
    });

    expect(response.statusCode).toBe(403);
  });

  it('protects only the paths selected by protect', async () => {
    const instance = await buildApp({ protect: (request) => request.url.startsWith('/api/') });

    expect((await instance.inject({ method: 'GET', url: '/public' })).statusCode).toBe(200);
    expect((await instance.inject({ method: 'GET', url: '/api/secret' })).statusCode).toBe(401);
  });

  it('translates the identity into the application user object via resolveUser', async () => {
    const resolveUser = vi.fn(async (identity: RelyperIdentity) => ({
      id: `db-${identity.subject}`,
      email: identity.email
    }));
    const instance = await buildApp({ resolveUser });
    const response = await instance.inject({ method: 'GET', url: '/api/secret', headers });

    expect(response.statusCode).toBe(200);
    expect(response.json().principal).toEqual({ id: 'db-idp-subject-1', email: 'jonas@relyper.test' });
    expect(resolveUser).toHaveBeenCalledTimes(1);
  });

  it('does not call resolveUser for rejected requests', async () => {
    const resolveUser = vi.fn(async () => ({ id: 'should-not-happen' }));
    const instance = await buildApp({ resolveUser });
    const response = await instance.inject({ method: 'GET', url: '/api/secret' });

    expect(response.statusCode).toBe(401);
    expect(resolveUser).not.toHaveBeenCalled();
  });

  it('registers the /me route only on request', async () => {
    const withoutRoute = await buildApp();
    expect((await withoutRoute.inject({ method: 'GET', url: '/api/me', headers })).statusCode).toBe(404);
    await withoutRoute.close();

    const withRoute = await buildApp({
      meRoute: '/api/me',
      resolveUser: async (identity) => ({ id: `db-${identity.subject}` })
    });
    const response = await withRoute.inject({ method: 'GET', url: '/api/me', headers });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ user: { id: 'db-idp-subject-1' } });
  });

  it('reports failed attempts to onAuthFailure, e.g. for an audit log', async () => {
    const onAuthFailure = vi.fn();
    const instance = await buildApp({ onAuthFailure });
    await instance.inject({ method: 'GET', url: '/api/secret', headers: { ...headers, 'x-relyper-roles': 'wrong' } });

    expect(onAuthFailure).toHaveBeenCalledTimes(1);
    expect(onAuthFailure.mock.calls[0][0]).toMatchObject({ code: 'missing_role', status: 403 });
  });

  it('allows a custom error body', async () => {
    const instance = await buildApp({ errorBody: (failure) => ({ code: failure.code, hint: 'Please sign in.' }) });
    const response = await instance.inject({ method: 'GET', url: '/api/secret' });

    expect(response.json()).toEqual({ code: 'missing_subject', hint: 'Please sign in.' });
  });

  it('exposes the role check as a decorator', async () => {
    const instance = await buildApp();
    expect(instance.relyperAuth.hasRole({ subject: 's', email: 'e', displayName: 'd', roles: [ROLE] }, ROLE)).toBe(true);
    expect(instance.relyperAuth.hasRole({ subject: 's', email: 'e', displayName: 'd', roles: [] }, ROLE)).toBe(false);
  });
});
