import type {
  RelyperAuthFailure,
  RelyperAuthOptions,
  RelyperAuthResult,
  RelyperHeaderNames,
  RelyperHeaderSource,
  RelyperIdentity,
  ResolvedRelyperAuthOptions
} from './types.js';

export const DEFAULT_HEADER_NAMES: RelyperHeaderNames = {
  subject: 'x-relyper-subject',
  email: 'x-relyper-email',
  displayName: 'x-relyper-name',
  roles: 'x-relyper-roles'
};

/** Common headers of a generic auth proxy, only active on explicit request. */
export const FORWARDED_HEADER_NAMES: RelyperHeaderNames = {
  subject: 'x-forwarded-user',
  email: 'x-forwarded-email',
  displayName: 'x-forwarded-preferred-username',
  roles: 'x-forwarded-groups'
};

const DEV_AUTH_DEFAULTS = {
  subject: 'dev-user',
  email: 'dev@relyper.local',
  displayName: 'Relyper Dev User'
};

export function parseRoleList(raw: string): string[] {
  return raw
    .split(',')
    .map((role) => role.trim())
    .filter(Boolean);
}

export function readHeader(source: RelyperHeaderSource, name: string): string {
  if (typeof (source as { get?: unknown }).get === 'function') {
    const value = (source as { get(key: string): string | null | undefined }).get(name);
    return typeof value === 'string' ? value.trim() : '';
  }
  const record = source as Record<string, string | string[] | undefined>;
  const value = record[name] ?? record[name.toLowerCase()];
  if (Array.isArray(value)) return (value[0] ?? '').trim();
  return typeof value === 'string' ? value.trim() : '';
}

function resolveOptions(options: RelyperAuthOptions): ResolvedRelyperAuthOptions {
  const requiredRoles = options.requiredRole === undefined
    ? []
    : (Array.isArray(options.requiredRole) ? options.requiredRole : [options.requiredRole]).filter(Boolean);

  const forwarded = options.acceptForwardedHeaders;
  const forwardedHeaderNames = forwarded
    ? { ...FORWARDED_HEADER_NAMES, ...(typeof forwarded === 'object' ? forwarded : {}) }
    : null;

  const devAuthOption = options.devAuth;
  const devAuthEnabled = Boolean(devAuthOption) && (devAuthOption as { enabled?: boolean }).enabled !== false;

  return {
    requiredRoles,
    roleMatch: options.roleMatch ?? 'any',
    requireEmail: options.requireEmail ?? true,
    headerNames: { ...DEFAULT_HEADER_NAMES, ...(options.headerNames ?? {}) },
    forwardedHeaderNames,
    devAuth: devAuthEnabled
      ? {
          subject: (devAuthOption as { subject?: string }).subject ?? DEV_AUTH_DEFAULTS.subject,
          email: (devAuthOption as { email?: string }).email ?? DEV_AUTH_DEFAULTS.email,
          displayName: (devAuthOption as { displayName?: string }).displayName ?? DEV_AUTH_DEFAULTS.displayName,
          roles: (devAuthOption as { roles?: string[] }).roles ?? requiredRoles
        }
      : null,
    unauthenticatedStatus: options.unauthenticatedStatus ?? 401,
    forbiddenStatus: options.forbiddenStatus ?? 403
  };
}

export type RelyperAuth = {
  readonly options: ResolvedRelyperAuthOptions;
  /** Checks headers and returns either an identity or a failure with an HTTP status. */
  authenticate(headers: RelyperHeaderSource): RelyperAuthResult;
  /** Role check for additional gates inside the application. */
  hasRole(identity: RelyperIdentity, role: string | string[], match?: 'any' | 'all'): boolean;
};

export function createRelyperAuth(options: RelyperAuthOptions = {}): RelyperAuth {
  const resolved = resolveOptions(options);
  const parseRoles = options.parseRoles ?? parseRoleList;

  function fail(code: RelyperAuthFailure['code'], status: number, presentedRoles: string[]): RelyperAuthFailure {
    const base = { ok: false as const, status, code, presentedRoles };
    const message = typeof options.message === 'function'
      ? options.message(base)
      : options.message ?? defaultMessage(code);
    return { ...base, message };
  }

  return {
    options: resolved,

    authenticate(headers: RelyperHeaderSource): RelyperAuthResult {
      const pick = (key: keyof RelyperHeaderNames): string => {
        const primary = readHeader(headers, resolved.headerNames[key]);
        if (primary) return primary;
        if (!resolved.forwardedHeaderNames) return '';
        return readHeader(headers, resolved.forwardedHeaderNames[key]);
      };

      const presentedRoles = parseRoles(pick('roles'));
      const dev = resolved.devAuth;

      const subject = pick('subject') || (dev ? dev.subject : '');
      const email = pick('email') || (dev ? dev.email : '');
      const roles = presentedRoles.length ? presentedRoles : dev ? [...dev.roles] : [];
      const displayName = pick('displayName') || email || (dev ? dev.displayName : '') || 'Relyper User';

      if (!subject) return fail('missing_subject', resolved.unauthenticatedStatus, presentedRoles);
      if (resolved.requireEmail && !email) return fail('missing_email', resolved.unauthenticatedStatus, presentedRoles);

      if (resolved.requiredRoles.length && !matchesRoles(roles, resolved.requiredRoles, resolved.roleMatch)) {
        return fail('missing_role', resolved.forbiddenStatus, presentedRoles);
      }

      const identity: RelyperIdentity = { subject, email, displayName, roles };
      const viaDevAuth = Boolean(dev) && !readHeader(headers, resolved.headerNames.subject);
      return { ok: true, identity, viaDevAuth };
    },

    hasRole(identity: RelyperIdentity, role: string | string[], match: 'any' | 'all' = 'any'): boolean {
      const wanted = Array.isArray(role) ? role : [role];
      return matchesRoles(identity.roles, wanted, match);
    }
  };
}

function matchesRoles(actual: string[], required: string[], match: 'any' | 'all'): boolean {
  return match === 'all'
    ? required.every((role) => actual.includes(role))
    : required.some((role) => actual.includes(role));
}

function defaultMessage(code: RelyperAuthFailure['code']): string {
  switch (code) {
    case 'missing_subject':
      return 'Authentication required.';
    case 'missing_email':
      return 'Authentication required: the identity provider did not supply an e-mail address.';
    case 'missing_role':
      return 'Access requires an authenticated user with the required role.';
  }
}
