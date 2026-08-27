import fp from 'fastify-plugin';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { createRelyperAuth, type RelyperAuth } from './core.js';
import type { RelyperAuthFailure, RelyperAuthOptions, RelyperIdentity } from './types.js';

declare module 'fastify' {
  interface FastifyRequest {
    /** Identity from the Relyper IdP. Set by the plugin once the request is protected. */
    relyperIdentity: RelyperIdentity;
  }
  interface FastifyInstance {
    relyperAuth: RelyperAuth;
  }
}

export type RelyperFastifyOptions = RelyperAuthOptions & {
  /**
   * Decides which requests are protected. Default: all.
   * Typical: `(request) => request.url.startsWith('/api/')`.
   */
  protect?: (request: FastifyRequest) => boolean;
  /** Hook the check runs in. Default: onRequest, i.e. before the body is parsed. */
  hook?: 'onRequest' | 'preHandler';
  /**
   * Translates the IdP identity into the application's own user object,
   * typically an upsert into its own database.
   * Without this hook, the IdP identity lands on the request unchanged.
   */
  resolveUser?: (identity: RelyperIdentity, request: FastifyRequest) => unknown | Promise<unknown>;
  /** Property on the request that holds the result. Default: 'principal'. */
  principalKey?: string;
  /** Path for a /me route. Default: false, the plugin does not register a route on its own. */
  meRoute?: string | false;
  /** Response of the /me route. Default: `{ user: request[principalKey] }`. */
  meResponse?: (request: FastifyRequest) => unknown;
  /** Error body. Default: `{ error: failure.message }`. */
  errorBody?: (failure: RelyperAuthFailure, request: FastifyRequest) => unknown;
  /** Hook for audit-logging failed access attempts. */
  onAuthFailure?: (failure: RelyperAuthFailure, request: FastifyRequest) => void | Promise<void>;
  /** Warns once in the log when dev auth kicks in. Default: true. */
  warnOnDevAuth?: boolean;
};

async function plugin(app: FastifyInstance, options: RelyperFastifyOptions): Promise<void> {
  const auth = createRelyperAuth(options);
  const principalKey = options.principalKey ?? 'principal';
  const hook = options.hook ?? 'onRequest';
  const protect = options.protect ?? (() => true);
  const errorBody = options.errorBody ?? ((failure: RelyperAuthFailure) => ({ error: failure.message }));
  const warnOnDevAuth = options.warnOnDevAuth ?? true;
  let devAuthWarned = false;

  if (!app.hasRequestDecorator('relyperIdentity')) {
    // Fastify recommends reserving the slot on the request upfront. The value stays
    // empty until the hook runs; the declared type is deliberately non-nullable
    // because a protected route always has an identity by the time it runs.
    app.decorateRequest('relyperIdentity', null as unknown as RelyperIdentity);
  }
  if (!app.hasRequestDecorator(principalKey)) {
    app.decorateRequest(principalKey, null);
  }
  if (!app.hasDecorator('relyperAuth')) {
    app.decorate('relyperAuth', auth);
  }

  app.addHook(hook, async (request: FastifyRequest, reply: FastifyReply) => {
    if (!protect(request)) return;

    const result = auth.authenticate(request.headers);

    if (!result.ok) {
      if (options.onAuthFailure) await options.onAuthFailure(result, request);
      return reply.code(result.status).send(errorBody(result, request));
    }

    if (result.viaDevAuth && warnOnDevAuth && !devAuthWarned) {
      devAuthWarned = true;
      app.log.warn(
        '@relyper/sp-auth: dev auth is active, requests without gateway headers are treated as an authenticated user. Never enable this in production.'
      );
    }

    request.relyperIdentity = result.identity;
    const principal = options.resolveUser ? await options.resolveUser(result.identity, request) : result.identity;
    (request as unknown as Record<string, unknown>)[principalKey] = principal;
  });

  if (options.meRoute) {
    const meResponse = options.meResponse
      ?? ((request: FastifyRequest) => ({ user: (request as unknown as Record<string, unknown>)[principalKey] }));
    app.get(options.meRoute, async (request: FastifyRequest) => meResponse(request));
  }
}

export const relyperAuth = fp(plugin, {
  name: '@relyper/sp-auth',
  fastify: '5.x'
});

export default relyperAuth;
