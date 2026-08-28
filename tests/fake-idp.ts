import { SignJWT, exportJWK, generateKeyPair, type CryptoKey, type JWK } from 'jose';

/**
 * A minimal but real OpenID provider for the tests: actual RSA keys, an actual
 * JWKS, actual signatures. Nothing about the verification is stubbed out, so a
 * test that passes here would also pass against the real Relyper IdP.
 */

export const ISSUER = 'https://idp.relyper.test';
export const CLIENT_ID = 'client-private-case-test';
export const CLIENT_SECRET = 'super-secret-value-with-/-and-:-chars';
export const REDIRECT_URI = 'https://case.relyper.test/auth/callback';

export type FakeIdp = {
  fetch: typeof globalThis.fetch;
  /** Every request the client made, for asserting on what was actually sent. */
  requests: { url: string; method: string; headers: Record<string, string>; body: string }[];
  /** Issues an ID token; override any claim to build a malicious one. */
  issueIdToken(overrides?: Record<string, unknown>, options?: { key?: CryptoKey; alg?: string; kid?: string }): Promise<string>;
  /** Replaces the next token-endpoint response. */
  setTokenResponse(response: { status: number; body: unknown }): void;
  /** Claims the token endpoint puts into the ID token it hands out. */
  claims: Record<string, unknown>;
  privateKey: CryptoKey;
  publicJwk: JWK;
};

export async function createFakeIdp(): Promise<FakeIdp> {
  const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  publicJwk.kid = 'test-key-1';
  publicJwk.alg = 'RS256';
  publicJwk.use = 'sig';

  const idp: FakeIdp = {
    requests: [],
    privateKey,
    publicJwk,
    claims: {
      sub: 'user-1',
      email: 'anna@relyper.test',
      email_verified: true,
      name: 'Anna Example',
      roles: ['relyper_private_case_user'],
      tenant: 'tenant-a',
      tenant_id: 'tenant-a',
      tenant_ids: ['tenant-a', 'tenant-b'],
      tenant_name: 'Tenant A',
      teams: ['legal']
    },

    async issueIdToken(overrides = {}, options = {}) {
      const now = Math.floor(Date.now() / 1000);
      const payload: Record<string, unknown> = {
        iss: ISSUER,
        aud: CLIENT_ID,
        iat: now,
        exp: now + 300,
        ...idp.claims,
        ...overrides
      };
      return new SignJWT(payload)
        .setProtectedHeader({ alg: options.alg ?? 'RS256', kid: options.kid ?? 'test-key-1' })
        .sign(options.key ?? privateKey);
    },

    setTokenResponse(response) {
      tokenResponse = response;
    },

    fetch: (async (input: any, init: any = {}) => {
      const url = typeof input === 'string' ? input : String(input?.url ?? input);
      const headers: Record<string, string> = {};
      for (const [key, value] of Object.entries((init.headers ?? {}) as Record<string, string>)) {
        headers[key.toLowerCase()] = value;
      }
      const body = typeof init.body === 'string' ? init.body : '';
      idp.requests.push({ url, method: init.method ?? 'GET', headers, body });

      if (url === ISSUER + '/.well-known/openid-configuration') {
        return json(200, discoveryDocument);
      }
      if (url === discoveryDocument.jwks_uri) {
        return json(200, { keys: [publicJwk] });
      }
      if (url === discoveryDocument.token_endpoint) {
        if (tokenResponse) {
          const response = tokenResponse;
          tokenResponse = null;
          return json(response.status, response.body);
        }
        const params = new URLSearchParams(body);
        const nonce = pendingNonce.get(params.get('code') ?? '') ?? '';
        return json(200, {
          access_token: 'access-token-value',
          id_token: await idp.issueIdToken(nonce ? { nonce } : {}),
          token_type: 'Bearer',
          expires_in: 300
        });
      }
      if (url === discoveryDocument.userinfo_endpoint) {
        return json(200, { sub: idp.claims.sub, ...userInfoExtra });
      }
      return json(404, { error: 'not_found' });
    }) as unknown as typeof globalThis.fetch
  };

  let tokenResponse: { status: number; body: unknown } | null = null;
  const userInfoExtra: Record<string, unknown> = {};

  return idp;
}

export const discoveryDocument = {
  issuer: ISSUER,
  authorization_endpoint: ISSUER + '/auth/oauth/relyper/authorize',
  token_endpoint: ISSUER + '/auth/oauth/relyper/token',
  userinfo_endpoint: ISSUER + '/auth/oauth/relyper/userinfo',
  jwks_uri: ISSUER + '/auth/oauth/relyper/jwks',
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code'],
  id_token_signing_alg_values_supported: ['RS256'],
  code_challenge_methods_supported: ['S256', 'plain'],
  token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post']
};

/**
 * The IdP has to echo the login's nonce back in the ID token. The real one reads
 * it from the stored authorization code; here it is remembered per code.
 */
export const pendingNonce = new Map<string, string>();

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' }
  });
}
