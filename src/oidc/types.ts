import type { RelyperIdentity } from '../types.js';

/** Subset of the OIDC discovery document this client relies on. */
export type OidcDiscoveryDocument = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint?: string;
  end_session_endpoint?: string;
  code_challenge_methods_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
  scopes_supported?: string[];
};

export type TokenEndpointAuthMethod = 'client_secret_basic' | 'client_secret_post';

export type RelyperOidcOptions = {
  /**
   * Base URL of the Relyper IdP, exactly as it appears in the `iss` claim.
   * Discovery is read from `<issuer>/.well-known/openid-configuration`.
   */
  issuer: string;
  /** Client ID registered at the IdP for this service provider. */
  clientId: string;
  /** Client secret generated at the IdP. Never ships to the browser. */
  clientSecret: string;
  /** Must match one of the redirect URIs registered for this client, byte for byte. */
  redirectUri: string;

  /** Default: `openid email profile roles tenant teams`. */
  scope?: string;
  /**
   * How this client authenticates at the token endpoint. Default: whichever of
   * the two the discovery document advertises, preferring `client_secret_basic`.
   */
  tokenEndpointAuthMethod?: TokenEndpointAuthMethod;

  /** Role(s) required for this service provider. Empty means: no role check. */
  requiredRole?: string | string[];
  /** With several required roles: one suffices ('any', default) or all are needed ('all'). */
  roleMatch?: 'any' | 'all';
  /** Default: true. Set to false if the IdP does not supply an e-mail address. */
  requireEmail?: boolean;

  /**
   * Also call the UserInfo endpoint after the token exchange. Default: false,
   * because the Relyper IdP already puts every claim into the ID token. Turn it
   * on if you need claims the ID token does not carry.
   */
  useUserInfo?: boolean;

  /** Leeway for `exp`/`iat`/`nbf` in seconds. Default: 60. */
  clockToleranceSeconds?: number;
  /** How long a discovery document is reused, in milliseconds. Default: 3600000 (1h). */
  discoveryTtlMs?: number;
  /** Timeout for every call to the IdP, in milliseconds. Default: 10000. */
  requestTimeoutMs?: number;
  /** Custom fetch implementation, e.g. for tests or a proxy-aware agent. */
  fetch?: typeof globalThis.fetch;
  /** Maps IdP claims onto the identity. Default: {@link defaultClaimsToIdentity}. */
  mapClaims?: (claims: Record<string, unknown>) => RelyperIdentity;
};

export type ResolvedRelyperOidcOptions = {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scope: string;
  tokenEndpointAuthMethod: TokenEndpointAuthMethod | null;
  requiredRoles: string[];
  roleMatch: 'any' | 'all';
  requireEmail: boolean;
  useUserInfo: boolean;
  clockToleranceSeconds: number;
  discoveryTtlMs: number;
  requestTimeoutMs: number;
};

/** State this client must remember between the redirect out and the callback. */
export type RelyperLoginTransaction = {
  state: string;
  nonce: string;
  codeVerifier: string;
  /** Application path to return to after the login. Always a local path. */
  returnTo: string;
};

export type RelyperAuthorizationRequest = {
  /** The IdP URL the browser has to be redirected to. */
  url: string;
  transaction: RelyperLoginTransaction;
};

export type RelyperTokenSet = {
  accessToken: string;
  idToken: string;
  tokenType: string;
  expiresIn: number | null;
  refreshToken: string | null;
  scope: string | null;
};

export type RelyperLoginResult = {
  identity: RelyperIdentity;
  claims: Record<string, unknown>;
  tokens: RelyperTokenSet;
};

export type RelyperOidcErrorCode =
  /** The IdP redirected back with an `error` parameter. */
  | 'idp_error'
  /** `state` missing, unknown, or not the one this browser started with. */
  | 'invalid_state'
  /** No login transaction cookie -- expired, or a callback nobody started. */
  | 'missing_transaction'
  /** The IdP refused the code exchange. */
  | 'token_exchange_failed'
  /** The ID token failed signature, issuer, audience, nonce, or expiry checks. */
  | 'invalid_id_token'
  /** UserInfo could not be read. */
  | 'userinfo_failed'
  /** Discovery document or JWKS unreachable or malformed. */
  | 'discovery_failed'
  /** Authenticated, but without the role this service provider requires. */
  | 'missing_role'
  /** The IdP supplied no e-mail address although one is required. */
  | 'missing_email';

export class RelyperOidcError extends Error {
  readonly code: RelyperOidcErrorCode;
  /** HTTP status an adapter should answer with. */
  readonly status: number;
  readonly cause?: unknown;
  /** Safe to log: never contains tokens or the client secret. */
  readonly detail?: string;

  constructor(
    code: RelyperOidcErrorCode,
    message: string,
    options: { status?: number; cause?: unknown; detail?: string } = {}
  ) {
    super(message);
    this.name = 'RelyperOidcError';
    this.code = code;
    this.status = options.status ?? 502;
    this.cause = options.cause;
    this.detail = options.detail;
  }
}
