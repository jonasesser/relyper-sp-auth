import type { RelyperIdentity } from './types.js';

/**
 * Framework-freier Browser-Client fuer die /me-Route eines Service Providers.
 * Bewusst ohne Vue/React-Abhaengigkeit: ein Composable oder Hook darum herum
 * ist in der Anwendung ein Zehnzeiler.
 */

export type RelyperSession<TUser = RelyperIdentity> =
  | { status: 'authenticated'; user: TUser }
  /** Keine Identitaet am Gateway vorbei. Typisch: Login noetig. */
  | { status: 'unauthenticated'; response: Response }
  /** Angemeldet, aber ohne die Rolle fuer diesen Service Provider. */
  | { status: 'forbidden'; response: Response }
  | { status: 'error'; response: Response };

export type FetchSessionOptions = {
  /** Standard: '/api/me'. */
  path?: string;
  /** Eigene fetch-Implementierung, etwa fuer Tests oder SSR. */
  fetch?: typeof globalThis.fetch;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  /** Standard: 'same-origin'. */
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

/** true, wenn die Identitaet mindestens eine der Rollen besitzt. */
export function hasAnyRole(identity: Pick<RelyperIdentity, 'roles'>, roles: string[]): boolean {
  return roles.some((role) => identity.roles.includes(role));
}

export type { RelyperIdentity };
