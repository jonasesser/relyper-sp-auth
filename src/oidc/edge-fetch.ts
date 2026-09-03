/**
 * The default `fetch` this OIDC client uses for every server-to-server call to
 * the IdP (discovery, token exchange, JWKS, UserInfo) when the host application
 * does not supply its own.
 *
 * Two things happen here that plain `fetch` does not do, both learned the hard
 * way in a sibling Relyper application (RelyperPrivateCase) before being folded
 * back into this library so every service provider gets them for free:
 *
 * **A descriptive User-Agent.** Node's bare default ("node") reads to the IdP's
 * edge bot protection (Cloudflare Bot Fight Mode, in production) as an obvious
 * non-browser signature and gets a Managed Challenge instead of a response --
 * a challenge a server can never solve, so every login fails outright with a
 * 403 that never reached the IdP's own application code at all.
 *
 * **One retry when the answer came from that edge layer, not from the IdP.**
 * Observed in production: a token exchange came back 403 in under 50ms with no
 * OAuth error body, while the identical call under a second later succeeded --
 * the edge's bot score is not a hard, permanent verdict on every request from
 * a given host. A user should not have to click "sign in" a second time to
 * work around that.
 */
import type { OidcEdgeRejection } from './types.js';

/**
 * Statuses that mean "something in front of the IdP said no", not "the IdP
 * said no".
 *
 * The distinction decides whether retrying is honest. A token endpoint that
 * rejects a grant answers 400 with an OAuth error body, and repeating that
 * request would only ask the same question twice -- and could double-spend a
 * single-use authorization code if it had, in fact, been accepted. A 403 with
 * no OAuth error in it never reached the token endpoint's own handler -- it
 * came from a WAF, a bot filter or a rate limiter, which means the code (or
 * discovery/JWKS/UserInfo request) was never seen by the IdP and is still
 * unused. 429 and the 5xx gateway codes are the same kind of answer from the
 * same kind of layer.
 */
const EDGE_REJECTION_STATUS = new Set([403, 429, 502, 503, 504]);

/** How long a failed call waits before its one retry. */
const EDGE_RETRY_DELAY_MS = 400;

function isEdgeRejection(response: Response): boolean {
  return !response.ok && EDGE_REJECTION_STATUS.has(response.status);
}

/**
 * Builds the default fetch used when {@link RelyperOidcOptions.fetch} is not
 * given. `clientIdForUserAgent` identifies which service provider is calling
 * in the IdP's own access logs, the same way a browser's User-Agent identifies
 * a browser -- the library has no app name or URL to advertise on its host's
 * behalf, so the registered OIDC client id is what it has.
 */
export function createDefaultOidcFetch(
  clientIdForUserAgent: string,
  onEdgeRejection?: (rejection: OidcEdgeRejection) => void
): typeof globalThis.fetch {
  const userAgent = `@relyper/sp-auth (client:${clientIdForUserAgent})`;

  return async function relyperDefaultFetch(input: Parameters<typeof fetch>[0], init: Parameters<typeof fetch>[1] = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    if (!headers.has('user-agent')) {
      headers.set('user-agent', userAgent);
    }
    const request: Parameters<typeof fetch>[1] = { ...init, headers };
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;

    const response = await fetch(input, request);
    if (!isEdgeRejection(response)) return response;

    // A streamed body cannot be sent twice, so a call like that is left alone
    // rather than retried with nothing left to send.
    const replayable = !(request.body instanceof ReadableStream);
    onEdgeRejection?.({ url, status: response.status, retried: replayable });
    if (!replayable) return response;

    await new Promise((resolve) => setTimeout(resolve, EDGE_RETRY_DELAY_MS));
    return fetch(input, request);
  };
}
