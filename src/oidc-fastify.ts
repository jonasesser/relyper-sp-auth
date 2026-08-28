import fp from 'fastify-plugin';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { createRelyperOidcClient, safeReturnTo, type RelyperOidcClient } from './oidc/client.js';
import {
  clearCookie,
  createLoginCodec,
  createSessionCodec,
  createSessionId,
  parseCookies,
  serializeCookie,
  type CookieOptions,
  type SessionPayload
} from './oidc/session.js';
import { RelyperOidcError, type RelyperLoginResult, type RelyperOidcOptions } from './oidc/types.js';
import type { RelyperIdentity } from './types.js';

/**
 * Fastify adapter for the OIDC login against the Relyper IdP.
 *
 * Registers the three routes a browser-facing service provider needs -- start
 * the login, receive the callback, end the session -- and guards the rest of the
 * application with the resulting session cookie.
 */

declare module 'fastify' {
  interface FastifyRequest {
    /** Identity from the verified ID token. Set once a protected route has passed the guard. */
    relyperIdentity: RelyperIdentity;
    /** Raw session as it was sealed into the cookie. */
    relyperSession: SessionPayload | null;
  }
  interface FastifyInstance {
    relyperOidc: RelyperOidcClient;
  }
}

export type RelyperOidcFastifyOptions = RelyperOidcOptions & {
  /**
   * Secret this application seals its cookies with, at least 32 characters.
   * Unrelated to the client secret and never shared with the IdP. Rotating it
   * invalidates every open session.
   */
  sessionSecret: string;

  /** Default: 'relyper_session'. */
  sessionCookieName?: string;
  /** Default: 'relyper_login'. */
  loginCookieName?: string;
  cookieDomain?: string;
  cookiePath?: string;
  /**
   * `Secure` flag. Default: on, unless NODE_ENV is 'development' or 'test'.
   * Leaving this on over plain HTTP means the browser silently drops the cookie.
   */
  cookieSecure?: boolean;
  /** Lifetime of a session in seconds. Default: 28800 (8 hours). */
  sessionTtlSeconds?: number;
  /** Lifetime of the login handshake in seconds. Default: 600 (10 minutes). */
  loginTtlSeconds?: number;
  /**
   * Re-issue the session cookie on activity so an active user is not logged out
   * mid-session. Default: true. The IdP login time is preserved either way.
   */
  rollingSession?: boolean;
  /** Absolute lifetime in seconds a session can reach through rolling renewal. Default: 86400 (24h). */
  sessionAbsoluteTtlSeconds?: number;
  /** Keep the ID token in the session so RP-initiated logout can pass it. Default: false. */
  keepIdToken?: boolean;

  /** Default: '/auth/login'. */
  loginPath?: string;
  /** Default: '/auth/callback'. Must match the redirect URI registered at the IdP. */
  callbackPath?: string;
  /** Default: '/auth/logout'. Registered for both GET and POST. */
  logoutPath?: string;
  /** Local path to land on after logout. Default: '/'. */
  postLogoutRedirect?: string;
  /** Local path the callback redirects to when the login fails. Default: none, a JSON error is sent. */
  loginErrorRedirect?: string;

  /**
   * Decides which requests the session guard covers. Default: everything except
   * the login, callback and logout routes.
   */
  protect?: (request: FastifyRequest) => boolean;
  /** Hook the guard runs in. Default: 'onRequest'. */
  hook?: 'onRequest' | 'preHandler';
  /**
   * Translates the IdP identity into the application's own user object, usually
   * an upsert into its database. Runs on every guarded request.
   */
  resolveUser?: (identity: RelyperIdentity, request: FastifyRequest) => unknown | Promise<unknown>;
  /** Request property holding the result of `resolveUser`. Default: 'principal'. */
  principalKey?: string;
  /** Path for a /me route. Default: false. */
  meRoute?: string | false;
  /** Response of the /me route. Default: `{ user: request[principalKey] }`. */
  meResponse?: (request: FastifyRequest) => unknown;

  /**
   * Whether an unauthenticated request is answered with a redirect to the login
   * instead of a 401. Default: redirect for top-level HTML navigation, 401 for
   * everything else, which is what a single-page app wants.
   */
  redirectUnauthenticated?: boolean | ((request: FastifyRequest) => boolean);
  /** Body of a 401/403. Default: `{ error, code, loginUrl }`. */
  errorBody?: (failure: RelyperAuthFailureInfo, request: FastifyRequest) => unknown;
  /** Audit hook for rejected requests and failed logins. */
  onAuthFailure?: (failure: RelyperAuthFailureInfo, request: FastifyRequest) => void | Promise<void>;
  /**
   * Called after a successful login, before the redirect. Receives the session id
   * that identifies this login, so an application keeping a revocation list can
   * record it here.
   */
  onLogin?: (result: RelyperLoginResult, request: FastifyRequest, sessionId: string) => void | Promise<void>;
  /**
   * Called when a session ends, with the id from {@link RelyperOidcFastifyOptions.onLogin}.
   * Implement this together with `isSessionRevoked` to make logout binding: the
   * session cookie itself is stateless, so clearing it only affects the browser
   * that asked. Recording the id here and rejecting it afterwards also stops a
   * cookie that was copied before the logout.
   */
  onLogout?: (sessionId: string, session: SessionPayload, request: FastifyRequest) => void | Promise<void>;
  /**
   * Consulted on every guarded request. Return true to refuse a session whose id
   * has been revoked. Default: no revocation list, sessions live until they expire.
   */
  isSessionRevoked?: (sessionId: string, request: FastifyRequest) => boolean | Promise<boolean>;
};

export type RelyperAuthFailureInfo = {
  status: number;
  code: string;
  message: string;
  /** Safe to log; never contains tokens or secrets. */
  detail?: string;
};

const DEFAULTS = {
  sessionCookieName: 'relyper_session',
  loginCookieName: 'relyper_login',
  cookiePath: '/',
  sessionTtlSeconds: 8 * 60 * 60,
  sessionAbsoluteTtlSeconds: 24 * 60 * 60,
  loginTtlSeconds: 10 * 60,
  loginPath: '/auth/login',
  callbackPath: '/auth/callback',
  logoutPath: '/auth/logout',
  postLogoutRedirect: '/'
};

async function plugin(app: FastifyInstance, options: RelyperOidcFastifyOptions): Promise<void> {
  const client = createRelyperOidcClient(options);
  const sessions = createSessionCodec(options.sessionSecret);
  const logins = createLoginCodec(options.sessionSecret);

  const sessionCookieName = options.sessionCookieName ?? DEFAULTS.sessionCookieName;
  const loginCookieName = options.loginCookieName ?? DEFAULTS.loginCookieName;
  const sessionTtl = options.sessionTtlSeconds ?? DEFAULTS.sessionTtlSeconds;
  const absoluteTtl = options.sessionAbsoluteTtlSeconds ?? DEFAULTS.sessionAbsoluteTtlSeconds;
  const loginTtl = options.loginTtlSeconds ?? DEFAULTS.loginTtlSeconds;
  const rolling = options.rollingSession ?? true;
  const keepIdToken = options.keepIdToken ?? false;
  const principalKey = options.principalKey ?? 'principal';
  const hook = options.hook ?? 'onRequest';

  const loginPath = options.loginPath ?? DEFAULTS.loginPath;
  const callbackPath = options.callbackPath ?? DEFAULTS.callbackPath;
  const logoutPath = options.logoutPath ?? DEFAULTS.logoutPath;
  const postLogoutRedirect = safeReturnTo(options.postLogoutRedirect ?? DEFAULTS.postLogoutRedirect);
  const authRoutes = new Set([loginPath, callbackPath, logoutPath]);

  const nodeEnv = process.env.NODE_ENV ?? 'development';
  const cookieBase: CookieOptions = {
    path: options.cookiePath ?? DEFAULTS.cookiePath,
    domain: options.cookieDomain,
    httpOnly: true,
    // Lax, not Strict: the callback arrives as a top-level navigation from the
    // IdP, and Strict would withhold the login cookie exactly then.
    sameSite: 'Lax',
    secure: options.cookieSecure ?? (nodeEnv !== 'development' && nodeEnv !== 'test')
  };

  const errorBody = options.errorBody
    ?? ((failure: RelyperAuthFailureInfo) => ({
      error: failure.message,
      code: failure.code,
      loginUrl: loginPath
    }));

  if (!app.hasRequestDecorator('relyperIdentity')) {
    app.decorateRequest('relyperIdentity', null as unknown as RelyperIdentity);
  }
  if (!app.hasRequestDecorator('relyperSession')) {
    app.decorateRequest('relyperSession', null);
  }
  if (!app.hasRequestDecorator(principalKey)) {
    app.decorateRequest(principalKey, null);
  }
  if (!app.hasDecorator('relyperOidc')) {
    app.decorate('relyperOidc', client);
  }

  function pathOf(request: FastifyRequest): string {
    const url = request.url ?? '/';
    const index = url.indexOf('?');
    return index === -1 ? url : url.slice(0, index);
  }

  const protect = options.protect ?? ((request: FastifyRequest) => !authRoutes.has(pathOf(request)));

  function wantsRedirect(request: FastifyRequest): boolean {
    if (typeof options.redirectUnauthenticated === 'function') return options.redirectUnauthenticated(request);
    if (typeof options.redirectUnauthenticated === 'boolean') return options.redirectUnauthenticated;
    // A browser navigating to a page accepts HTML and is best served a redirect;
    // an XHR from a single-page app wants a status code it can act on.
    if (request.method !== 'GET') return false;
    const accept = String(request.headers.accept ?? '');
    const fetchMode = String(request.headers['sec-fetch-mode'] ?? '');
    if (fetchMode && fetchMode !== 'navigate') return false;
    return accept.includes('text/html');
  }

  async function reject(
    request: FastifyRequest,
    reply: FastifyReply,
    failure: RelyperAuthFailureInfo
  ): Promise<FastifyReply> {
    if (options.onAuthFailure) await options.onAuthFailure(failure, request);
    if (failure.status === 401 && wantsRedirect(request)) {
      const target = loginPath + '?returnTo=' + encodeURIComponent(pathOf(request));
      return reply.redirect(target, 302);
    }
    return reply.code(failure.status).send(errorBody(failure, request));
  }

  function setSessionCookie(reply: FastifyReply, payload: SessionPayload, ttl: number): Promise<void> {
    return sessions.seal(payload, ttl).then((token) => {
      reply.header(
        'set-cookie',
        serializeCookie(sessionCookieName, token, { ...cookieBase, maxAgeSeconds: ttl })
      );
    });
  }

  // ------------------------------------------------------------- login ---

  app.get(loginPath, async (request: FastifyRequest, reply: FastifyReply) => {
    const query = (request.query ?? {}) as Record<string, string | undefined>;
    const { url, transaction } = await client.createAuthorizationRequest({
      returnTo: query.returnTo,
      prompt: query.prompt
    });

    const sealed = await logins.seal(transaction, loginTtl);
    reply.header(
      'set-cookie',
      serializeCookie(loginCookieName, sealed, { ...cookieBase, maxAgeSeconds: loginTtl })
    );
    // The IdP decides what to show here; caching that decision would be wrong.
    reply.header('cache-control', 'no-store');
    return reply.redirect(url, 302);
  });

  // ---------------------------------------------------------- callback ---

  app.get(callbackPath, async (request: FastifyRequest, reply: FastifyReply) => {
    reply.header('cache-control', 'no-store');

    const cookies = parseCookies(request.headers.cookie);
    const transaction = await logins.open(cookies[loginCookieName]);
    // The handshake cookie is single-use, whatever the outcome.
    const cleared = clearCookie(loginCookieName, cookieBase);

    if (!transaction) {
      reply.header('set-cookie', cleared);
      return failLogin(request, reply, new RelyperOidcError(
        'missing_transaction',
        'The login has expired. Please sign in again.',
        { status: 400 }
      ));
    }

    let result: RelyperLoginResult;
    try {
      result = await client.completeLogin({
        query: (request.query ?? {}) as Record<string, string | string[] | undefined>,
        transaction
      });
    } catch (error) {
      reply.header('set-cookie', cleared);
      return failLogin(request, reply, error);
    }

    const now = Math.floor(Date.now() / 1000);
    const sessionId = createSessionId();
    const payload: SessionPayload = {
      identity: result.identity,
      authenticatedAt: now,
      sessionId,
      ...(keepIdToken ? { idToken: result.tokens.idToken } : {})
    };

    if (options.onLogin) await options.onLogin(result, request, sessionId);

    const sealed = await sessions.seal(payload, sessionTtl);
    reply.header('set-cookie', [
      cleared,
      serializeCookie(sessionCookieName, sealed, { ...cookieBase, maxAgeSeconds: sessionTtl })
    ]);

    return reply.redirect(transaction.returnTo, 302);
  });

  async function failLogin(request: FastifyRequest, reply: FastifyReply, error: unknown): Promise<FastifyReply> {
    const oidcError = error instanceof RelyperOidcError
      ? error
      : new RelyperOidcError('idp_error', 'The login could not be completed.', {
          cause: error,
          detail: error instanceof Error ? error.message : undefined
        });

    const failure: RelyperAuthFailureInfo = {
      status: oidcError.status,
      code: oidcError.code,
      message: oidcError.message,
      detail: oidcError.detail
    };

    // Logged at warn with the detail, because a login that keeps failing is an
    // operational problem someone has to be able to diagnose.
    request.log.warn(
      { relyperOidc: failure.code, detail: failure.detail },
      '@relyper/sp-auth: OIDC login failed'
    );
    if (options.onAuthFailure) await options.onAuthFailure(failure, request);

    if (options.loginErrorRedirect) {
      const target = safeReturnTo(options.loginErrorRedirect)
        + (options.loginErrorRedirect.includes('?') ? '&' : '?')
        + 'error=' + encodeURIComponent(failure.code);
      return reply.redirect(target, 302);
    }

    return reply.code(failure.status).send(errorBody(failure, request));
  }

  // ------------------------------------------------------------ logout ---

  async function handleLogout(request: FastifyRequest, reply: FastifyReply): Promise<FastifyReply> {
    const cookies = parseCookies(request.headers.cookie);
    const session = await sessions.open(cookies[sessionCookieName]);

    reply.header('cache-control', 'no-store');
    reply.header('set-cookie', [
      clearCookie(sessionCookieName, cookieBase),
      clearCookie(loginCookieName, cookieBase)
    ]);

    // Clearing the cookie only affects the browser that asked. An application
    // that also wants a copied cookie to stop working records the id here.
    if (session?.sessionId && options.onLogout) {
      await options.onLogout(session.sessionId, session, request);
    }

    // If the IdP supports RP-initiated logout, end its session too -- otherwise
    // the next login would silently sign the same user straight back in.
    const endSession = await client.endSessionUrl({
      idTokenHint: session?.idToken,
      postLogoutRedirectUri: undefined
    });
    return reply.redirect(endSession ?? postLogoutRedirect, 302);
  }

  app.get(logoutPath, handleLogout);
  app.post(logoutPath, handleLogout);

  // ------------------------------------------------------------- guard ---

  app.addHook(hook, async (request: FastifyRequest, reply: FastifyReply) => {
    if (!protect(request)) return;

    const cookies = parseCookies(request.headers.cookie);
    const session = await sessions.open(cookies[sessionCookieName]);

    if (!session?.identity?.subject) {
      return reject(request, reply, {
        status: 401,
        code: 'unauthenticated',
        message: 'Authentication required.'
      });
    }

    // An absolute cap on top of the rolling window, so a session cannot be kept
    // alive indefinitely by activity alone.
    const age = Math.floor(Date.now() / 1000) - (session.authenticatedAt ?? 0);
    if (age > absoluteTtl) {
      reply.header('set-cookie', clearCookie(sessionCookieName, cookieBase));
      return reject(request, reply, {
        status: 401,
        code: 'session_expired',
        message: 'Your session has expired. Please sign in again.'
      });
    }

    if (options.isSessionRevoked && session.sessionId
      && await options.isSessionRevoked(session.sessionId, request)) {
      reply.header('set-cookie', clearCookie(sessionCookieName, cookieBase));
      return reject(request, reply, {
        status: 401,
        code: 'session_revoked',
        message: 'Your session has ended. Please sign in again.'
      });
    }

    // Re-checked on every request, not just at login: if the required role is
    // tightened in configuration, sessions issued before that must not survive.
    const requiredRoles = client.options.requiredRoles;
    if (requiredRoles.length && !client.hasRole(session.identity, requiredRoles, client.options.roleMatch)) {
      return reject(request, reply, {
        status: 403,
        code: 'missing_role',
        message: 'Your account does not have access to this application.',
        detail: 'presented roles: ' + (session.identity.roles.join(', ') || '(none)')
      });
    }

    request.relyperSession = session;
    request.relyperIdentity = session.identity;

    const principal = options.resolveUser
      ? await options.resolveUser(session.identity, request)
      : session.identity;
    (request as unknown as Record<string, unknown>)[principalKey] = principal;

    if (rolling) await setSessionCookie(reply, session, sessionTtl);
  });

  if (options.meRoute) {
    const meResponse = options.meResponse
      ?? ((request: FastifyRequest) => ({ user: (request as unknown as Record<string, unknown>)[principalKey] }));
    app.get(options.meRoute, async (request: FastifyRequest) => meResponse(request));
  }
}

export const relyperOidcAuth = fp(plugin, {
  name: '@relyper/sp-auth/oidc-fastify',
  fastify: '5.x'
});

export default relyperOidcAuth;
