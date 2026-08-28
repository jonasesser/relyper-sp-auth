import { RelyperOidcError, type OidcDiscoveryDocument } from './types.js';

/**
 * Reads and caches the IdP's discovery document.
 *
 * The endpoints are never hardcoded: an IdP is free to move them, and the
 * document is the contract. Concurrent callers share one in-flight request so a
 * burst of logins does not turn into a burst of requests against the IdP.
 */

const REQUIRED_FIELDS = ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'] as const;

export type DiscoveryLoaderOptions = {
  issuer: string;
  ttlMs: number;
  requestTimeoutMs: number;
  fetch: typeof globalThis.fetch;
};

export type DiscoveryLoader = {
  load(): Promise<OidcDiscoveryDocument>;
  /** Drops the cache, e.g. after a JWKS lookup failed against a rotated IdP. */
  invalidate(): void;
};

export function discoveryUrl(issuer: string): string {
  const base = issuer.replace(/\/+$/, '');
  return base + '/.well-known/openid-configuration';
}

export function createDiscoveryLoader(options: DiscoveryLoaderOptions): DiscoveryLoader {
  let cached: { document: OidcDiscoveryDocument; expiresAt: number } | null = null;
  let inFlight: Promise<OidcDiscoveryDocument> | null = null;

  async function fetchDocument(): Promise<OidcDiscoveryDocument> {
    const url = discoveryUrl(options.issuer);
    let response: Response;
    try {
      response = await options.fetch(url, {
        method: 'GET',
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(options.requestTimeoutMs)
      });
    } catch (cause) {
      throw new RelyperOidcError('discovery_failed', 'The identity provider could not be reached.', {
        cause,
        detail: 'GET ' + url
      });
    }

    if (!response.ok) {
      throw new RelyperOidcError('discovery_failed', 'The identity provider could not be reached.', {
        detail: 'GET ' + url + ' returned HTTP ' + response.status
      });
    }

    let document: OidcDiscoveryDocument;
    try {
      document = (await response.json()) as OidcDiscoveryDocument;
    } catch (cause) {
      throw new RelyperOidcError('discovery_failed', 'The identity provider returned a malformed discovery document.', {
        cause,
        detail: 'GET ' + url
      });
    }

    for (const field of REQUIRED_FIELDS) {
      if (typeof document?.[field] !== 'string' || !document[field]) {
        throw new RelyperOidcError('discovery_failed', 'The discovery document is incomplete.', {
          detail: 'missing field: ' + field
        });
      }
    }

    // The issuer is the identity of the IdP and is compared against the `iss`
    // claim later. A document that names a different issuer than the one we
    // configured means we are talking to the wrong party.
    if (trimSlash(document.issuer) !== trimSlash(options.issuer)) {
      throw new RelyperOidcError('discovery_failed', 'The identity provider reports a different issuer.', {
        detail: 'configured ' + options.issuer + ', document ' + document.issuer
      });
    }

    return document;
  }

  return {
    async load(): Promise<OidcDiscoveryDocument> {
      const now = Date.now();
      if (cached && cached.expiresAt > now) return cached.document;
      if (inFlight) return inFlight;

      inFlight = fetchDocument()
        .then((document) => {
          cached = { document, expiresAt: Date.now() + options.ttlMs };
          return document;
        })
        .finally(() => {
          inFlight = null;
        });

      return inFlight;
    },

    invalidate(): void {
      cached = null;
    }
  };
}

function trimSlash(value: string): string {
  return value.replace(/\/+$/, '');
}
