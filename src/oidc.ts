/**
 * OIDC entry point: the Relyper IdP as a real identity provider.
 *
 * The service provider is registered at the IdP as a confidential client and
 * authenticates with its client secret, so no part of the trust chain depends on
 * headers a proxy may or may not have set.
 */

export {
  createRelyperOidcClient,
  safeReturnTo,
  type AuthorizationRequestOptions,
  type RelyperOidcClient
} from './oidc/client.js';

export { defaultClaimsToIdentity } from './oidc/claims.js';

export {
  createCodeVerifier,
  createNonce,
  createState,
  codeChallengeFor
} from './oidc/pkce.js';

export {
  createDiscoveryLoader,
  discoveryUrl,
  type DiscoveryLoader,
  type DiscoveryLoaderOptions
} from './oidc/discovery.js';

export {
  clearCookie,
  createLoginCodec,
  createSessionCodec,
  createSessionId,
  parseCookies,
  safeEqual,
  serializeCookie,
  type CookieOptions,
  type SealedCodec,
  type SessionPayload
} from './oidc/session.js';

export {
  RelyperOidcError,
  type OidcDiscoveryDocument,
  type RelyperAuthorizationRequest,
  type RelyperLoginResult,
  type RelyperLoginTransaction,
  type RelyperOidcErrorCode,
  type RelyperOidcOptions,
  type RelyperTokenSet,
  type ResolvedRelyperOidcOptions,
  type TokenEndpointAuthMethod
} from './oidc/types.js';

export type { RelyperIdentity } from './types.js';
