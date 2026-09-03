import { createRemoteJWKSet, customFetch, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from 'jose';
import type { RelyperIdentity } from '../types.js';
import { createDiscoveryLoader, type DiscoveryLoader } from './discovery.js';
import { defaultClaimsToIdentity } from './claims.js';
import { codeChallengeFor, createCodeVerifier, createNonce, createState } from './pkce.js';
import { createDefaultOidcFetch } from './edge-fetch.js';
import {
  RelyperOidcError,
  type OidcDiscoveryDocument,
  type RelyperAuthorizationRequest,
  type RelyperLoginResult,
  type RelyperLoginTransaction,
  type RelyperOidcOptions,
  type RelyperTokenSet,
  type ResolvedRelyperOidcOptions,
  type TokenEndpointAuthMethod
} from './types.js';

/**
 * OIDC client for a Relyper service provider.
 *
 * Authorization Code Flow with PKCE and a confidential client: the client secret
 * only ever travels from this server to the IdP's token endpoint, never through
 * the browser. Every ID token is verified against the IdP's JWKS before a single
 * claim in it is believed.
 */

const DEFAULT_SCOPE = 'openid email profile roles tenant teams';

export type AuthorizationRequestOptions = {
  /** Local path to return to after the login. Anything else falls back to '/'. */
  returnTo?: string;
  /** OIDC `prompt`, e.g. 'login' to force re-authentication. */
  prompt?: string;
  /** OIDC `login_hint`, usually an e-mail address. */
  loginHint?: string;
};

export type RelyperOidcClient = {
  readonly options: ResolvedRelyperOidcOptions;
  /** Discovery document, fetched on first use and cached afterwards. */
  discover(): Promise<OidcDiscoveryDocument>;
  /**
   * Starts a login. Returns the IdP URL to redirect to plus the transaction the
   * caller has to hand back to {@link RelyperOidcClient.completeLogin}.
   */
  createAuthorizationRequest(options?: AuthorizationRequestOptions): Promise<RelyperAuthorizationRequest>;
  /**
   * Completes a login: checks `state`, exchanges the code, verifies the ID token
   * and returns the identity. Throws {@link RelyperOidcError} on every failure.
   */
  completeLogin(params: {
    query: Record<string, string | string[] | undefined>;
    transaction: RelyperLoginTransaction;
  }): Promise<RelyperLoginResult>;
  /** Role check, identical in semantics to the header-based variant. */
  hasRole(identity: RelyperIdentity, role: string | string[], match?: 'any' | 'all'): boolean;
  /** URL that ends the IdP session, or null if the IdP advertises none. */
  endSessionUrl(options?: { idTokenHint?: string; postLogoutRedirectUri?: string }): Promise<string | null>;
};

function resolveOptions(options: RelyperOidcOptions): ResolvedRelyperOidcOptions {
  const required = ['issuer', 'clientId', 'clientSecret', 'redirectUri'] as const;
  for (const key of required) {
    if (!options[key] || typeof options[key] !== 'string') {
      throw new TypeError('@relyper/sp-auth/oidc: ' + key + ' is required.');
    }
  }

  const requiredRoles = options.requiredRole === undefined
    ? []
    : (Array.isArray(options.requiredRole) ? options.requiredRole : [options.requiredRole]).filter(Boolean);

  return {
    issuer: trimTrailingSlashes(options.issuer),
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    redirectUri: options.redirectUri,
    scope: options.scope ?? DEFAULT_SCOPE,
    tokenEndpointAuthMethod: options.tokenEndpointAuthMethod ?? null,
    requiredRoles,
    roleMatch: options.roleMatch ?? 'any',
    requireEmail: options.requireEmail ?? true,
    useUserInfo: options.useUserInfo ?? false,
    clockToleranceSeconds: options.clockToleranceSeconds ?? 60,
    discoveryTtlMs: options.discoveryTtlMs ?? 3_600_000,
    requestTimeoutMs: options.requestTimeoutMs ?? 10_000
  };
}

export function createRelyperOidcClient(options: RelyperOidcOptions): RelyperOidcClient {
  const resolved = resolveOptions(options);
  // An app that hands us its own fetch owns this decision entirely -- e.g. a
  // fake for tests, or a proxy-aware agent -- and is trusted to have already
  // thought about what its host's edge protection needs, so it is used as-is.
  // Left unset, every call here goes through this library's own default,
  // which exists specifically because the bare global fetch does not survive
  // a production IdP's bot protection -- see RelyperOidcOptions.fetch's doc.
  const doFetch = options.fetch ?? createDefaultOidcFetch(resolved.clientId, options.onEdgeRejection);
  if (typeof doFetch !== 'function') {
    throw new TypeError('@relyper/sp-auth/oidc: no fetch implementation available.');
  }
  const mapClaims = options.mapClaims ?? defaultClaimsToIdentity;

  const discovery: DiscoveryLoader = createDiscoveryLoader({
    issuer: resolved.issuer,
    ttlMs: resolved.discoveryTtlMs,
    requestTimeoutMs: resolved.requestTimeoutMs,
    fetch: doFetch
  });

  // One JWKS per jwks_uri. jose caches the keys, refetches on an unknown `kid`
  // and rate-limits those refetches, which is exactly the key-rotation behaviour
  // we would otherwise have to build by hand.
  const jwksCache = new Map<string, JWTVerifyGetKey>();
  function jwksFor(uri: string): JWTVerifyGetKey {
    let jwks = jwksCache.get(uri);
    if (!jwks) {
      jwks = createRemoteJWKSet(new URL(uri), {
        timeoutDuration: resolved.requestTimeoutMs,
        cooldownDuration: 30_000,
        // The JWKS has to travel the same path as every other call to the IdP,
        // so a proxy-aware or test fetch covers key retrieval as well.
        [customFetch]: doFetch
      });
      jwksCache.set(uri, jwks);
    }
    return jwks;
  }

  function authMethod(document: OidcDiscoveryDocument): TokenEndpointAuthMethod {
    if (resolved.tokenEndpointAuthMethod) return resolved.tokenEndpointAuthMethod;
    const supported = document.token_endpoint_auth_methods_supported ?? [];
    if (supported.includes('client_secret_basic')) return 'client_secret_basic';
    if (supported.includes('client_secret_post')) return 'client_secret_post';
    // The OIDC default for a confidential client when the document says nothing.
    return 'client_secret_basic';
  }

  async function exchangeCode(
    document: OidcDiscoveryDocument,
    code: string,
    codeVerifier: string
  ): Promise<RelyperTokenSet> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: resolved.redirectUri,
      code_verifier: codeVerifier
    });

    const headers: Record<string, string> = {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json'
    };

    if (authMethod(document) === 'client_secret_basic') {
      // RFC 6749 section 2.3.1: both halves are form-urlencoded before the
      // base64. Skipping that breaks any secret holding a reserved character.
      const credentials = encodeURIComponent(resolved.clientId) + ':' + encodeURIComponent(resolved.clientSecret);
      headers.authorization = 'Basic ' + Buffer.from(credentials, 'utf8').toString('base64');
    } else {
      body.set('client_id', resolved.clientId);
      body.set('client_secret', resolved.clientSecret);
    }

    let response: Response;
    try {
      response = await doFetch(document.token_endpoint, {
        method: 'POST',
        headers,
        body: body.toString(),
        signal: AbortSignal.timeout(resolved.requestTimeoutMs)
      });
    } catch (cause) {
      throw new RelyperOidcError('token_exchange_failed', 'The identity provider could not be reached.', { cause });
    }

    const payload = await readJson(response);

    if (!response.ok) {
      // The IdP's own error code is safe to log; the body may hold more, so only
      // the two documented fields are carried over.
      const error = typeof payload?.error === 'string' ? payload.error : 'HTTP ' + response.status;
      const description = typeof payload?.error_description === 'string' ? payload.error_description : '';
      throw new RelyperOidcError('token_exchange_failed', 'The login could not be completed.', {
        detail: description ? error + ': ' + description : error
      });
    }

    const idToken = typeof payload?.id_token === 'string' ? payload.id_token : '';
    if (!idToken) {
      throw new RelyperOidcError('token_exchange_failed', 'The identity provider returned no ID token.', {
        detail: 'token response without id_token'
      });
    }

    return {
      idToken,
      accessToken: typeof payload?.access_token === 'string' ? payload.access_token : '',
      tokenType: typeof payload?.token_type === 'string' ? payload.token_type : 'Bearer',
      expiresIn: typeof payload?.expires_in === 'number' ? payload.expires_in : null,
      refreshToken: typeof payload?.refresh_token === 'string' ? payload.refresh_token : null,
      scope: typeof payload?.scope === 'string' ? payload.scope : null
    };
  }

  async function verifyIdToken(
    document: OidcDiscoveryDocument,
    idToken: string,
    nonce: string
  ): Promise<JWTPayload> {
    let payload: JWTPayload;
    try {
      const result = await jwtVerify(idToken, jwksFor(document.jwks_uri), {
        issuer: document.issuer,
        audience: resolved.clientId,
        clockTolerance: resolved.clockToleranceSeconds,
        // Pinning the algorithms is what stops a token downgraded to `none`, or
        // to an HMAC signed with the provider's public key, from being accepted.
        algorithms: ['RS256', 'RS384', 'RS512', 'PS256', 'ES256', 'ES384']
      });
      payload = result.payload;
    } catch (cause) {
      throw new RelyperOidcError('invalid_id_token', 'The identity provider returned an invalid token.', {
        cause,
        detail: cause instanceof Error ? cause.message : undefined
      });
    }

    // OpenID Connect Core 3.1.3.7 step 11: the nonce ties this token to the login
    // this browser started. Without the check a token captured elsewhere replays.
    if (payload.nonce !== nonce) {
      throw new RelyperOidcError('invalid_id_token', 'The identity provider returned an invalid token.', {
        detail: 'nonce mismatch'
      });
    }

    // Step 12: with several audiences, `azp` has to name this client.
    if (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== resolved.clientId) {
      throw new RelyperOidcError('invalid_id_token', 'The identity provider returned an invalid token.', {
        detail: 'azp does not match the client id'
      });
    }

    if (typeof payload.sub !== 'string' || !payload.sub) {
      throw new RelyperOidcError('invalid_id_token', 'The identity provider returned an invalid token.', {
        detail: 'missing sub claim'
      });
    }

    return payload;
  }

  async function fetchUserInfo(document: OidcDiscoveryDocument, accessToken: string): Promise<Record<string, unknown>> {
    if (!document.userinfo_endpoint || !accessToken) return {};
    let response: Response;
    try {
      response = await doFetch(document.userinfo_endpoint, {
        method: 'GET',
        headers: { authorization: 'Bearer ' + accessToken, accept: 'application/json' },
        signal: AbortSignal.timeout(resolved.requestTimeoutMs)
      });
    } catch (cause) {
      throw new RelyperOidcError('userinfo_failed', 'The identity provider could not be reached.', { cause });
    }
    if (!response.ok) {
      throw new RelyperOidcError('userinfo_failed', 'The user profile could not be read.', {
        detail: 'HTTP ' + response.status
      });
    }
    return (await readJson(response)) ?? {};
  }

  return {
    options: resolved,

    discover: () => discovery.load(),

    async createAuthorizationRequest(requestOptions: AuthorizationRequestOptions = {}): Promise<RelyperAuthorizationRequest> {
      const document = await discovery.load();
      const transaction: RelyperLoginTransaction = {
        state: createState(),
        nonce: createNonce(),
        codeVerifier: createCodeVerifier(),
        returnTo: safeReturnTo(requestOptions.returnTo)
      };

      const url = new URL(document.authorization_endpoint);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('client_id', resolved.clientId);
      url.searchParams.set('redirect_uri', resolved.redirectUri);
      url.searchParams.set('scope', resolved.scope);
      url.searchParams.set('state', transaction.state);
      url.searchParams.set('nonce', transaction.nonce);
      url.searchParams.set('code_challenge', codeChallengeFor(transaction.codeVerifier));
      url.searchParams.set('code_challenge_method', 'S256');
      if (requestOptions.prompt) url.searchParams.set('prompt', requestOptions.prompt);
      if (requestOptions.loginHint) url.searchParams.set('login_hint', requestOptions.loginHint);

      return { url: url.toString(), transaction };
    },

    async completeLogin({ query, transaction }): Promise<RelyperLoginResult> {
      const idpError = firstValue(query.error);
      if (idpError) {
        throw new RelyperOidcError('idp_error', 'The identity provider refused the login.', {
          status: 401,
          detail: [idpError, firstValue(query.error_description)].filter(Boolean).join(': ')
        });
      }

      const state = firstValue(query.state);
      // A constant-time comparison would buy nothing here: whoever can measure
      // the response already holds the cookie this is compared against.
      if (!state || state !== transaction.state) {
        throw new RelyperOidcError('invalid_state', 'The login could not be verified. Please try again.', {
          status: 400,
          detail: state ? 'state does not match the login transaction' : 'state parameter missing'
        });
      }

      const code = firstValue(query.code);
      if (!code) {
        throw new RelyperOidcError('idp_error', 'The identity provider returned no authorization code.', {
          status: 400
        });
      }

      const document = await discovery.load();
      const tokens = await exchangeCode(document, code, transaction.codeVerifier);
      const idClaims = await verifyIdToken(document, tokens.idToken, transaction.nonce);

      let claims: Record<string, unknown> = { ...idClaims };
      if (resolved.useUserInfo) {
        const userInfo = await fetchUserInfo(document, tokens.accessToken);
        // OpenID Connect Core 5.3.2: a UserInfo response whose `sub` differs from
        // the ID token's must be discarded outright.
        if (userInfo.sub && userInfo.sub !== idClaims.sub) {
          throw new RelyperOidcError('userinfo_failed', 'The user profile could not be read.', {
            detail: 'userinfo sub does not match the id token'
          });
        }
        claims = { ...claims, ...userInfo };
      }

      const identity = mapClaims(claims);

      if (resolved.requireEmail && !identity.email) {
        throw new RelyperOidcError('missing_email', 'The identity provider supplied no e-mail address.', {
          status: 403
        });
      }

      if (resolved.requiredRoles.length && !matchesRoles(identity.roles, resolved.requiredRoles, resolved.roleMatch)) {
        throw new RelyperOidcError('missing_role', 'Your account does not have access to this application.', {
          status: 403,
          detail: 'presented roles: ' + (identity.roles.join(', ') || '(none)')
        });
      }

      return { identity, claims, tokens };
    },

    hasRole(identity, role, match = 'any') {
      const wanted = Array.isArray(role) ? role : [role];
      return matchesRoles(identity.roles, wanted, match);
    },

    async endSessionUrl(endSessionOptions = {}): Promise<string | null> {
      const document = await discovery.load();
      if (!document.end_session_endpoint) return null;
      const url = new URL(document.end_session_endpoint);
      if (endSessionOptions.idTokenHint) url.searchParams.set('id_token_hint', endSessionOptions.idTokenHint);
      if (endSessionOptions.postLogoutRedirectUri) {
        url.searchParams.set('post_logout_redirect_uri', endSessionOptions.postLogoutRedirectUri);
      }
      url.searchParams.set('client_id', resolved.clientId);
      return url.toString();
    }
  };
}

function matchesRoles(actual: string[], required: string[], match: 'any' | 'all'): boolean {
  return match === 'all'
    ? required.every((role) => actual.includes(role))
    : required.some((role) => actual.includes(role));
}

function firstValue(value: string | string[] | undefined): string {
  if (Array.isArray(value)) return typeof value[0] === 'string' ? value[0] : '';
  return typeof value === 'string' ? value : '';
}

async function readJson(response: Response): Promise<Record<string, any> | null> {
  try {
    return (await response.json()) as Record<string, any>;
  } catch {
    return null;
  }
}

function trimTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value[end - 1] === '/') end -= 1;
  return value.slice(0, end);
}

/**
 * Only a local path is ever used as a post-login target. An absolute URL, or a
 * protocol-relative one starting with two slashes, would turn the login route
 * into an open redirect. Backslashes are rejected too, because some browsers
 * normalise them to forward slashes and would follow "/\\evil.example".
 */
export function safeReturnTo(value: unknown, fallback = '/'): string {
  const candidate = typeof value === 'string' ? value.trim() : '';
  if (!candidate) return fallback;
  if (!candidate.startsWith('/')) return fallback;
  if (candidate.startsWith('//')) return fallback;
  if (candidate.includes('\\')) return fallback;
  return candidate;
}
