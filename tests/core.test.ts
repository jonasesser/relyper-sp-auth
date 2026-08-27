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
  it('nimmt eine vollstaendige Identitaet vom Gateway an', () => {
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

  it('antwortet ohne Identitaet mit 401', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE });
    const result = auth.authenticate({});

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(401);
    expect(result.code).toBe('missing_subject');
  });

  it('unterscheidet fehlende Rolle (403) von fehlender Identitaet (401)', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE });
    const result = auth.authenticate(gatewayHeaders({ 'x-relyper-roles': 'irgendeine_andere_rolle' }));

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(403);
    expect(result.code).toBe('missing_role');
    expect(result.presentedRoles).toEqual(['irgendeine_andere_rolle']);
  });

  it('erlaubt eigene Statuscodes fuer Anwendungen, die nicht zwischen 401 und 403 trennen', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE, unauthenticatedStatus: 403 });
    const result = auth.authenticate({});

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(403);
  });

  it('verlangt standardmaessig eine Mailadresse, laesst sich aber abschalten', () => {
    const strict = createRelyperAuth({ requiredRole: ROLE });
    const relaxed = createRelyperAuth({ requiredRole: ROLE, requireEmail: false });
    const headers = gatewayHeaders({ 'x-relyper-email': undefined });

    expect(strict.authenticate(headers).ok).toBe(false);
    expect(relaxed.authenticate(headers).ok).toBe(true);
  });

  it('prueft bei roleMatch "all" jede geforderte Rolle', () => {
    const auth = createRelyperAuth({ requiredRole: [ROLE, 'relyper_admin'], roleMatch: 'all' });

    expect(auth.authenticate(gatewayHeaders()).ok).toBe(false);
    expect(auth.authenticate(gatewayHeaders({ 'x-relyper-roles': `${ROLE},relyper_admin` })).ok).toBe(true);
  });

  it('prueft ohne requiredRole nur die Identitaet', () => {
    const auth = createRelyperAuth();
    expect(auth.authenticate(gatewayHeaders({ 'x-relyper-roles': '' })).ok).toBe(true);
  });
});

describe('x-forwarded-Header', () => {
  const forwarded = {
    'x-forwarded-user': 'proxy-subject',
    'x-forwarded-email': 'proxy@relyper.test',
    'x-forwarded-groups': ROLE
  };

  it('ignoriert sie standardmaessig', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE });
    expect(auth.authenticate(forwarded).ok).toBe(false);
  });

  it('akzeptiert sie nur auf ausdruecklichen Wunsch', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE, acceptForwardedHeaders: true });
    const result = auth.authenticate(forwarded);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.identity.subject).toBe('proxy-subject');
  });

  it('laesst den Relyper-Header vorgehen', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE, acceptForwardedHeaders: true });
    const result = auth.authenticate({ ...forwarded, ...gatewayHeaders() });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.identity.subject).toBe('idp-subject-1');
  });
});

describe('Dev-Auth', () => {
  it('ist standardmaessig aus', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE });
    expect(auth.authenticate({}).ok).toBe(false);
  });

  it('erzeugt eingeschaltet eine lokale Identitaet mit der Pflichtrolle', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE, devAuth: {} });
    const result = auth.authenticate({});

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.identity.subject).toBe('dev-user');
    expect(result.identity.roles).toEqual([ROLE]);
    expect(result.viaDevAuth).toBe(true);
  });

  it('laesst echte Gateway-Header vorgehen und meldet dann keine Dev-Auth', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE, devAuth: {} });
    const result = auth.authenticate(gatewayHeaders());

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.identity.subject).toBe('idp-subject-1');
    expect(result.viaDevAuth).toBe(false);
  });

  it('bleibt bei enabled: false aus', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE, devAuth: { enabled: false } });
    expect(auth.authenticate({}).ok).toBe(false);
  });
});

describe('Header-Quellen und Rollen', () => {
  it('liest Header aus einem Headers-Objekt der Fetch-API', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE });
    const headers = new Headers(gatewayHeaders() as Record<string, string>);
    const result = auth.authenticate(headers);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.identity.email).toBe('jonas@relyper.test');
  });

  it('nimmt bei mehrfach gesetzten Headern den ersten Wert', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE });
    const result = auth.authenticate(gatewayHeaders({ 'x-relyper-subject': ['erster', 'zweiter'] }));

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.identity.subject).toBe('erster');
  });

  it('zerlegt Rollenlisten robust', () => {
    expect(parseRoleList(' a , b ,, c ')).toEqual(['a', 'b', 'c']);
    expect(parseRoleList('')).toEqual([]);
  });

  it('erlaubt eine eigene Rollen-Zerlegung', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE, parseRoles: (raw) => raw.split(' ').filter(Boolean) });
    const result = auth.authenticate(gatewayHeaders({ 'x-relyper-roles': `andere ${ROLE}` }));
    expect(result.ok).toBe(true);
  });

  it('liest Header unabhaengig von der Schreibweise', () => {
    expect(readHeader({ 'x-relyper-subject': ' abc ' }, 'X-Relyper-Subject')).toBe('abc');
  });

  it('uebernimmt eine feste Fehlermeldung', () => {
    const auth = createRelyperAuth({ requiredRole: ROLE, message: 'Kein Zutritt.' });
    const result = auth.authenticate({});
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.message).toBe('Kein Zutritt.');
  });
});
