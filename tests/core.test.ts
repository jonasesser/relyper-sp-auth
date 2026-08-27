import { describe, expect, it } from 'vitest';
import { createRelyperAuth, parseRoleList, readHeader } from '../src/core.js';

const ROLE = 'relyper_private_case_user';

function gatewayHeaders(overrides: Record<string, string | string[] | undefined> = {}) {
  return {
    'x-relyper-subject': 'idp-subject-1',
    'x-relyper-email': 'jonas@relyper.test',
    'x-relyper-name': 'Jonas',
    'x-relyper-roles': `${ROLE},relyper_beta`,
    ...overrides
  };
}

describe('createRelyperAuth', () => {
  it('accepts a complete identity from the gateway', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE });
    const result = auth.authenticate(gatewayHeaders());

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.identity).toEqual({
      subject: 'idp-subject-1',
      email: 'jonas@relyper.test',
      displayName: 'Jonas',
      roles: [ROLE, 'relyper_beta']
    });
    expect(result.viaDevAuth).toBe(false);
  });

  it('responds with 401 when there is no identity', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE });
    const result = auth.authenticate({});

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(401);
    expect(result.code).toBe('missing_subject');
  });

  it('distinguishes a missing role (403) from a missing identity (401)', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE });
    const result = auth.authenticate(gatewayHeaders({ 'x-relyper-roles': 'some_other_role' }));

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(403);
    expect(result.code).toBe('missing_role');
    expect(result.presentedRoles).toEqual(['some_other_role']);
  });

  it('allows custom status codes for applications that do not distinguish 401 from 403', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE, unauthenticatedStatus: 403 });
    const result = auth.authenticate({});

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(403);
  });

  it('requires an email address by default, but can be relaxed', () => {
    const strict = createRelyperAuth({ requiredRole: ROLE });
    const relaxed = createRelyperAuth({ requiredRole: ROLE, requireEmail: false });
    const headers = gatewayHeaders({ 'x-relyper-email': undefined });

    expect(strict.authenticate(headers).ok).toBe(false);
    expect(relaxed.authenticate(headers).ok).toBe(true);
  });

  it('checks every required role when roleMatch is "all"', () => {
    const auth = createRelyperAuth({ requiredRole: [ROLE, 'relyper_admin'], roleMatch: 'all' });

    expect(auth.authenticate(gatewayHeaders()).ok).toBe(false);
    expect(auth.authenticate(gatewayHeaders({ 'x-relyper-roles': `${ROLE},relyper_admin` })).ok).toBe(true);
  });

  it('checks only the identity when requiredRole is not set', () => {
    const auth = createRelyperAuth();
    expect(auth.authenticate(gatewayHeaders({ 'x-relyper-roles': '' })).ok).toBe(true);
  });
});

describe('x-forwarded headers', () => {
  const forwarded = {
    'x-forwarded-user': 'proxy-subject',
    'x-forwarded-email': 'proxy@relyper.test',
    'x-forwarded-groups': ROLE
  };

  it('ignores them by default', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE });
    expect(auth.authenticate(forwarded).ok).toBe(false);
  });

  it('accepts them only on explicit request', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE, acceptForwardedHeaders: true });
    const result = auth.authenticate(forwarded);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.identity.subject).toBe('proxy-subject');
  });

  it('lets the Relyper header take precedence', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE, acceptForwardedHeaders: true });
    const result = auth.authenticate({ ...forwarded, ...gatewayHeaders() });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.identity.subject).toBe('idp-subject-1');
  });
});

describe('dev auth', () => {
  it('is off by default', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE });
    expect(auth.authenticate({}).ok).toBe(false);
  });

  it('when enabled, produces a local identity with the required role', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE, devAuth: {} });
    const result = auth.authenticate({});

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.identity.subject).toBe('dev-user');
    expect(result.identity.roles).toEqual([ROLE]);
    expect(result.viaDevAuth).toBe(true);
  });

  it('lets real gateway headers take precedence and then reports no dev auth', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE, devAuth: {} });
    const result = auth.authenticate(gatewayHeaders());

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.identity.subject).toBe('idp-subject-1');
    expect(result.viaDevAuth).toBe(false);
  });

  it('stays off with enabled: false', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE, devAuth: { enabled: false } });
    expect(auth.authenticate({}).ok).toBe(false);
  });
});

describe('header sources and roles', () => {
  it('reads headers from a Fetch API Headers object', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE });
    const headers = new Headers(gatewayHeaders() as Record<string, string>);
    const result = auth.authenticate(headers);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.identity.email).toBe('jonas@relyper.test');
  });

  it('takes the first value when a header is set multiple times', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE });
    const result = auth.authenticate(gatewayHeaders({ 'x-relyper-subject': ['first', 'second'] }));

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.identity.subject).toBe('first');
  });

  it('parses role lists robustly', () => {
    expect(parseRoleList(' a , b ,, c ')).toEqual(['a', 'b', 'c']);
    expect(parseRoleList('')).toEqual([]);
  });

  it('allows a custom role parser', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE, parseRoles: (raw) => raw.split(' ').filter(Boolean) });
    const result = auth.authenticate(gatewayHeaders({ 'x-relyper-roles': `other ${ROLE}` }));
    expect(result.ok).toBe(true);
  });

  it('reads headers case-insensitively', () => {
    expect(readHeader({ 'x-relyper-subject': ' abc ' }, 'X-Relyper-Subject')).toBe('abc');
  });

  it('accepts a fixed error message', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE, message: 'Access denied.' });
    const result = auth.authenticate({});
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.message).toBe('Access denied.');
  });
});
