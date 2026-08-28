import { describe, expect, it, beforeEach } from 'vitest';
import { SignJWT, generateKeyPair } from 'jose';
import { createRelyperOidcClient, safeReturnTo } from '../src/oidc/client.js';
import { RelyperOidcError } from '../src/oidc/types.js';
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
 * These tests exercise the checks that stand between an attacker and a session.
 * Each one first proves the happy path still works, then removes exactly one
 * guarantee and asserts the login is refused.
 */

let idp: FakeIdp;

function makeClient(overrides: Record<string, unknown> = {}) {
  return createRelyperOidcClient({
    issuer: ISSUER,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: REDIRECT_URI,
    requiredRole: 'relyper_private_case_user',
    fetch: idp.fetch,
    ...overrides
  });
}

/** Runs a full login and returns what the client made of it. */
async function login(client: ReturnType<typeof makeClient>, options: { code?: string } = {}) {
  const { transaction } = await client.createAuthorizationRequest();
  const code = options.code ?? 'code-' + transaction.state;
  pendingNonce.set(code, transaction.nonce);
  return client.completeLogin({
    query: { code, state: transaction.state },
    transaction
  });
}

beforeEach(async () => {
  idp = await createFakeIdp();
  pendingNonce.clear();
});

describe('authorization request', () => {
  it('sends PKCE, state and nonce to the authorization endpoint', async () => {
    const client = makeClient();
    const { url, transaction } = await client.createAuthorizationRequest({ returnTo: '/cases/7' });
    const parsed = new URL(url);

    expect(parsed.origin + parsed.pathname).toBe(discoveryDocument.authorization_endpoint);
    expect(parsed.searchParams.get('response_type')).toBe('code');
    expect(parsed.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(parsed.searchParams.get('redirect_uri')).toBe(REDIRECT_URI);
    expect(parsed.searchParams.get('code_challenge_method')).toBe('S256');
    expect(parsed.searchParams.get('code_challenge')).toBeTruthy();
    // The verifier itself must never appear in a URL the browser can see.
    expect(url).not.toContain(transaction.codeVerifier);
    expect(parsed.searchParams.get('state')).toBe(transaction.state);
    expect(parsed.searchParams.get('nonce')).toBe(transaction.nonce);
    expect(transaction.returnTo).toBe('/cases/7');
  });

  it('never carries the client secret into the browser redirect', async () => {
    const client = makeClient();
    const { url } = await client.createAuthorizationRequest();
    expect(url).not.toContain(CLIENT_SECRET);
  });

  it('refuses to be constructed without a client secret', () => {
    expect(() => makeClient({ clientSecret: '' })).toThrow(TypeError);
  });

  it('rejects a discovery document that names a different issuer', async () => {
    const client = createRelyperOidcClient({
      issuer: 'https://evil.example',
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectUri: REDIRECT_URI,
      fetch: (async () =>
        new Response(JSON.stringify(discoveryDocument), {
          status: 200,
          headers: { 'content-type': 'application/json' }
        })) as unknown as typeof globalThis.fetch
    });
    await expect(client.discover()).rejects.toMatchObject({ code: 'discovery_failed' });
  });
});

describe('successful login', () => {
  it('returns the identity from the verified ID token', async () => {
    const result = await login(makeClient());
    expect(result.identity).toMatchObject({
      subject: 'user-1',
      email: 'anna@relyper.test',
      displayName: 'Anna Example',
      roles: ['relyper_private_case_user'],
      tenantId: 'tenant-a',
      tenantName: 'Tenant A',
      teams: ['legal']
    });
    expect(result.identity.tenantIds).toEqual(['tenant-a', 'tenant-b']);
  });

  it('authenticates at the token endpoint with client_secret_basic', async () => {
    await login(makeClient());
    const tokenRequest = idp.requests.find((r) => r.url === discoveryDocument.token_endpoint);
    expect(tokenRequest?.method).toBe('POST');

    const header = tokenRequest?.headers.authorization ?? '';
    expect(header.startsWith('Basic ')).toBe(true);
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
    // RFC 6749 section 2.3.1: both halves are form-urlencoded before the base64,
    // which matters because this secret contains '/' and ':'.
    expect(decoded).toBe(encodeURIComponent(CLIENT_ID) + ':' + encodeURIComponent(CLIENT_SECRET));

    // The secret must not additionally appear in the body.
    expect(tokenRequest?.body).not.toContain(CLIENT_SECRET);
  });

  it('sends the PKCE verifier, not the challenge, to the token endpoint', async () => {
    const client = makeClient();
    const { transaction } = await client.createAuthorizationRequest();
    pendingNonce.set('code-1', transaction.nonce);
    await client.completeLogin({ query: { code: 'code-1', state: transaction.state }, transaction });

    const tokenRequest = idp.requests.find((r) => r.url === discoveryDocument.token_endpoint);
    const params = new URLSearchParams(tokenRequest?.body ?? '');
    expect(params.get('code_verifier')).toBe(transaction.codeVerifier);
    expect(params.get('grant_type')).toBe('authorization_code');
    expect(params.get('redirect_uri')).toBe(REDIRECT_URI);
  });

  it('can authenticate with client_secret_post when configured', async () => {
    await login(makeClient({ tokenEndpointAuthMethod: 'client_secret_post' }));
    const tokenRequest = idp.requests.find((r) => r.url === discoveryDocument.token_endpoint);
    expect(tokenRequest?.headers.authorization).toBeUndefined();
    const params = new URLSearchParams(tokenRequest?.body ?? '');
    expect(params.get('client_secret')).toBe(CLIENT_SECRET);
  });

  it('fetches the discovery document once and reuses it', async () => {
    const client = makeClient();
    await login(client);
    await login(client);
    const discoveryCalls = idp.requests.filter((r) => r.url.includes('.well-known'));
    expect(discoveryCalls).toHaveLength(1);
  });
});

describe('callback validation', () => {
  it('rejects a state that does not match the login transaction', async () => {
    const client = makeClient();
    const { transaction } = await client.createAuthorizationRequest();
    await expect(
      client.completeLogin({ query: { code: 'x', state: 'someone-elses-state' }, transaction })
    ).rejects.toMatchObject({ code: 'invalid_state', status: 400 });
  });

  it('rejects a callback with no state at all', async () => {
    const client = makeClient();
    const { transaction } = await client.createAuthorizationRequest();
    await expect(
      client.completeLogin({ query: { code: 'x' }, transaction })
    ).rejects.toMatchObject({ code: 'invalid_state' });
  });

  it('surfaces an error the identity provider redirected back with', async () => {
    const client = makeClient();
    const { transaction } = await client.createAuthorizationRequest();
    await expect(
      client.completeLogin({
        query: { error: 'access_denied', error_description: 'tenant claim missing', state: transaction.state },
        transaction
      })
    ).rejects.toMatchObject({ code: 'idp_error', status: 401 });
  });

  it('reports a refused code exchange without leaking the response body', async () => {
    const client = makeClient();
    idp.setTokenResponse({ status: 401, body: { error: 'invalid_client', error_description: 'client authentication failed' } });
    const { transaction } = await client.createAuthorizationRequest();
    const failure = await client
      .completeLogin({ query: { code: 'c', state: transaction.state }, transaction })
      .catch((error) => error as RelyperOidcError);

    expect(failure).toBeInstanceOf(RelyperOidcError);
    expect((failure as RelyperOidcError).code).toBe('token_exchange_failed');
    expect((failure as RelyperOidcError).message).not.toContain('invalid_client');
    expect((failure as RelyperOidcError).detail).toContain('invalid_client');
  });

  it('rejects a token response without an ID token', async () => {
    const client = makeClient();
    idp.setTokenResponse({ status: 200, body: { access_token: 'a', token_type: 'Bearer' } });
    const { transaction } = await client.createAuthorizationRequest();
    await expect(
      client.completeLogin({ query: { code: 'c', state: transaction.state }, transaction })
    ).rejects.toMatchObject({ code: 'token_exchange_failed' });
  });
});

describe('ID token verification', () => {
  it('rejects an ID token whose nonce is not the one this login sent', async () => {
    const client = makeClient();
    const { transaction } = await client.createAuthorizationRequest();
    const token = await idp.issueIdToken({ nonce: 'a-nonce-from-another-login' });
    idp.setTokenResponse({ status: 200, body: { id_token: token, access_token: 'a', token_type: 'Bearer' } });

    await expect(
      client.completeLogin({ query: { code: 'c', state: transaction.state }, transaction })
    ).rejects.toMatchObject({ code: 'invalid_id_token' });
  });

  it('rejects an ID token for a different audience', async () => {
    const client = makeClient();
    const { transaction } = await client.createAuthorizationRequest();
    const token = await idp.issueIdToken({ aud: 'some-other-service-provider', nonce: transaction.nonce });
    idp.setTokenResponse({ status: 200, body: { id_token: token, access_token: 'a', token_type: 'Bearer' } });

    await expect(
      client.completeLogin({ query: { code: 'c', state: transaction.state }, transaction })
    ).rejects.toMatchObject({ code: 'invalid_id_token' });
  });

  it('rejects an ID token from a different issuer', async () => {
    const client = makeClient();
    const { transaction } = await client.createAuthorizationRequest();
    const token = await idp.issueIdToken({ iss: 'https://evil.example', nonce: transaction.nonce });
    idp.setTokenResponse({ status: 200, body: { id_token: token, access_token: 'a', token_type: 'Bearer' } });

    await expect(
      client.completeLogin({ query: { code: 'c', state: transaction.state }, transaction })
    ).rejects.toMatchObject({ code: 'invalid_id_token' });
  });

  it('rejects an expired ID token', async () => {
    const client = makeClient();
    const { transaction } = await client.createAuthorizationRequest();
    const past = Math.floor(Date.now() / 1000) - 4000;
    const token = await idp.issueIdToken({ iat: past, exp: past + 300, nonce: transaction.nonce });
    idp.setTokenResponse({ status: 200, body: { id_token: token, access_token: 'a', token_type: 'Bearer' } });

    await expect(
      client.completeLogin({ query: { code: 'c', state: transaction.state }, transaction })
    ).rejects.toMatchObject({ code: 'invalid_id_token' });
  });

  it('rejects an ID token signed by a key the provider does not publish', async () => {
    const client = makeClient();
    const { transaction } = await client.createAuthorizationRequest();
    const attacker = await generateKeyPair('RS256', { extractable: true });
    const token = await idp.issueIdToken({ nonce: transaction.nonce }, { key: attacker.privateKey });
    idp.setTokenResponse({ status: 200, body: { id_token: token, access_token: 'a', token_type: 'Bearer' } });

    await expect(
      client.completeLogin({ query: { code: 'c', state: transaction.state }, transaction })
    ).rejects.toMatchObject({ code: 'invalid_id_token' });
  });

  it('rejects an unsigned ID token', async () => {
    const client = makeClient();
    const { transaction } = await client.createAuthorizationRequest();
    const now = Math.floor(Date.now() / 1000);
    // alg "none": the classic downgrade an unpinned verifier accepts.
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iss: ISSUER, aud: CLIENT_ID, sub: 'user-1', iat: now, exp: now + 300, nonce: transaction.nonce
    })).toString('base64url');
    idp.setTokenResponse({
      status: 200,
      body: { id_token: header + '.' + payload + '.', access_token: 'a', token_type: 'Bearer' }
    });

    await expect(
      client.completeLogin({ query: { code: 'c', state: transaction.state }, transaction })
    ).rejects.toMatchObject({ code: 'invalid_id_token' });
  });

  it('rejects an HMAC-signed ID token', async () => {
    const client = makeClient();
    const { transaction } = await client.createAuthorizationRequest();
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({
      iss: ISSUER, aud: CLIENT_ID, sub: 'user-1', iat: now, exp: now + 300, nonce: transaction.nonce
    })
      .setProtectedHeader({ alg: 'HS256' })
      .sign(new TextEncoder().encode('a'.repeat(32)));
    idp.setTokenResponse({ status: 200, body: { id_token: token, access_token: 'a', token_type: 'Bearer' } });

    await expect(
      client.completeLogin({ query: { code: 'c', state: transaction.state }, transaction })
    ).rejects.toMatchObject({ code: 'invalid_id_token' });
  });

  it('rejects an ID token without a subject', async () => {
    const client = makeClient();
    const { transaction } = await client.createAuthorizationRequest();
    const token = await idp.issueIdToken({ sub: undefined, nonce: transaction.nonce });
    idp.setTokenResponse({ status: 200, body: { id_token: token, access_token: 'a', token_type: 'Bearer' } });

    await expect(
      client.completeLogin({ query: { code: 'c', state: transaction.state }, transaction })
    ).rejects.toMatchObject({ code: 'invalid_id_token' });
  });
});

describe('authorization', () => {
  it('refuses a user without the required role', async () => {
    idp.claims.roles = ['factory_viewer'];
    await expect(login(makeClient())).rejects.toMatchObject({ code: 'missing_role', status: 403 });
  });

  it('accepts any one of several required roles by default', async () => {
    idp.claims.roles = ['tenant_admin'];
    const result = await login(makeClient({ requiredRole: ['relyper_private_case_user', 'tenant_admin'] }));
    expect(result.identity.roles).toEqual(['tenant_admin']);
  });

  it('requires every role when roleMatch is "all"', async () => {
    idp.claims.roles = ['tenant_admin'];
    await expect(
      login(makeClient({ requiredRole: ['relyper_private_case_user', 'tenant_admin'], roleMatch: 'all' }))
    ).rejects.toMatchObject({ code: 'missing_role' });
  });

  it('skips the role check when no role is required', async () => {
    idp.claims.roles = [];
    const result = await login(makeClient({ requiredRole: undefined }));
    expect(result.identity.roles).toEqual([]);
  });

  it('refuses a login without an e-mail address', async () => {
    idp.claims.email = '';
    await expect(login(makeClient())).rejects.toMatchObject({ code: 'missing_email', status: 403 });
  });
});

describe('safeReturnTo', () => {
  it('keeps local paths', () => {
    expect(safeReturnTo('/cases/7?tab=docs')).toBe('/cases/7?tab=docs');
  });

  it('refuses anything that could leave the application', () => {
    // Each of these is a way to smuggle an off-site target past a naive check.
    expect(safeReturnTo('https://evil.example')).toBe('/');
    expect(safeReturnTo('//evil.example')).toBe('/');
    expect(safeReturnTo('/\\evil.example')).toBe('/');
    expect(safeReturnTo('javascript:alert(1)')).toBe('/');
    expect(safeReturnTo('')).toBe('/');
    expect(safeReturnTo(undefined)).toBe('/');
    expect(safeReturnTo(42)).toBe('/');
  });
});
