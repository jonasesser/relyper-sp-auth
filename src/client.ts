import type { RelyperIdentity } from './types.js';

/**
 * Framework-free browser client for a service provider's /me route.
 * Deliberately without a Vue/React dependency: a composable or hook wrapping
 * it is a ten-liner in the application.
 */

export type RelyperSession<TUser = RelyperIdentity> =
  | { status: 'authenticated'; user: TUser }
  /** No identity passed through the gateway. Typically: login required. */
  | { status: 'unauthenticated'; response: Response }
  /** Signed in, but without the role required for this service provider. */
  | { status: 'forbidden'; response: Response }
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
};

export async function fetchRelyperSession<TUser = RelyperIdentity>(
  options: FetchSessionOptions = {}
): Promise<RelyperSession<TUser>> {
  const doFetch = options.fetch ?? globalThis.fetch;
  if (!doFetch) throw new Error('@relyper/sp-auth/client: no fetch implementation available.');

  const response = await doFetch(options.path ?? '/api/me', {
    method: 'GET',
    credentials: options.credentials ?? 'same-origin',
    headers: { accept: 'application/json', ...(options.headers ?? {}) },
    signal: options.signal
  });

  if (response.status === 401) return { status: 'unauthenticated', response };
  if (response.status === 403) return { status: 'forbidden', response };
  if (!response.ok) return { status: 'error', response };

  const body = (await response.json()) as { user?: TUser } | TUser;
  const user = (body as { user?: TUser }).user ?? (body as TUser);
  return { status: 'authenticated', user };
}

/** true if the identity has at least one of the given roles. */
export function hasAnyRole(identity: Pick<RelyperIdentity, 'roles'>, roles: string[]): boolean {
  return roles.some((role) => identity.roles.includes(role));
}

export type { RelyperIdentity };
