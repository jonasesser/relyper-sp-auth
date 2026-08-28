import type { RelyperIdentity } from './types.js';

/**
 * Framework-free browser client for a service provider's /me route.
 * Deliberately without a Vue/React dependency: a composable or hook wrapping
 * it is a ten-liner in the application.
 */

export type RelyperSession<TUser = RelyperIdentity> =
  | { status: 'authenticated'; user: TUser }
  /**
   * Nobody is signed in. With the OIDC integration the server also names the
   * route that starts a login; {@link startRelyperLogin} sends the browser there.
   */
  | { status: 'unauthenticated'; response: Response; loginUrl: string }
  /** Signed in, but without the role required for this service provider. */
  | { status: 'forbidden'; response: Response; message?: string }
  | { status: 'error'; response: Response };

export type FetchSessionOptions = {
  /** Default: '/api/me'. */
  path?: string;
  /** Custom fetch implementation, e.g. for tests or SSR. */
  fetch?: typeof globalThis.fetch;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  /** Default: 'same-origin'. */
  credentials?: RequestCredentials;
  /** Fallback when the server names no login route. Default: '/auth/login'. */
  loginPath?: string;
};

const DEFAULT_LOGIN_PATH = '/auth/login';

export async function fetchRelyperSession<TUser = RelyperIdentity>(
  options: FetchSessionOptions = {}
): Promise<RelyperSession<TUser>> {
  const doFetch = options.fetch ?? globalThis.fetch;
  if (!doFetch) throw new Error('@relyper/sp-auth/client: no fetch implementation available.');

  const response = await doFetch(options.path ?? '/api/me', {
    method: 'GET',
    credentials: options.credentials ?? 'same-origin',
    // Without this the browser would follow a redirect to the identity provider
    // inside the request, and the caller would see an opaque cross-origin
    // failure instead of the status it can act on.
    redirect: 'manual',
    headers: { accept: 'application/json', ...(options.headers ?? {}) },
    signal: options.signal
  });

  if (response.status === 401 || response.type === 'opaqueredirect') {
    const body = await readJsonBody(response);
    const loginUrl = typeof body?.loginUrl === 'string' && body.loginUrl
      ? body.loginUrl
      : options.loginPath ?? DEFAULT_LOGIN_PATH;
    return { status: 'unauthenticated', response, loginUrl };
  }

  if (response.status === 403) {
    const body = await readJsonBody(response);
    const message = typeof body?.error === 'string' ? body.error : undefined;
    return { status: 'forbidden', response, message };
  }

  if (!response.ok) return { status: 'error', response };

  const body = (await response.json()) as { user?: TUser } | TUser;
  const user = (body as { user?: TUser }).user ?? (body as TUser);
  return { status: 'authenticated', user };
}

export type StartLoginOptions = {
  /** Route that starts the login. Default: '/auth/login'. */
  loginUrl?: string;
  /**
   * Where to land after the login. Default: the current path including query
   * and hash, so the user resumes exactly where the session ran out.
   */
  returnTo?: string;
};

/**
 * Sends the browser into the OIDC login.
 *
 * A full navigation, not a fetch: the identity provider has to be able to show
 * its own login page and set its own session cookie, which an XHR cannot do.
 * `location.replace` keeps the expired page out of the back-button history.
 */
export function startRelyperLogin(options: StartLoginOptions = {}): void {
  if (typeof window === 'undefined') {
    throw new Error('@relyper/sp-auth/client: startRelyperLogin needs a browser environment.');
  }
  const base = options.loginUrl ?? DEFAULT_LOGIN_PATH;
  const returnTo = options.returnTo
    ?? window.location.pathname + window.location.search + window.location.hash;
  const separator = base.includes('?') ? '&' : '?';
  window.location.replace(base + separator + 'returnTo=' + encodeURIComponent(returnTo));
}

/**
 * Ends the session. A form POST rather than fetch, so the browser follows the
 * server's redirect and, where the identity provider supports it, the logout
 * continues on to end the session there too.
 */
export function startRelyperLogout(options: { logoutUrl?: string } = {}): void {
  if (typeof window === 'undefined') {
    throw new Error('@relyper/sp-auth/client: startRelyperLogout needs a browser environment.');
  }
  const form = window.document.createElement('form');
  form.method = 'POST';
  form.action = options.logoutUrl ?? '/auth/logout';
  window.document.body.appendChild(form);
  form.submit();
}

/** true if the identity has at least one of the given roles. */
export function hasAnyRole(identity: Pick<RelyperIdentity, 'roles'>, roles: string[]): boolean {
  return roles.some((role) => identity.roles.includes(role));
}

async function readJsonBody(response: Response): Promise<Record<string, unknown> | null> {
  try {
    return (await response.clone().json()) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export type { RelyperIdentity };
