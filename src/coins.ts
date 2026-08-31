/**
 * Client for the Relyper Coins integration API.
 *
 * Relyper Coins are held centrally: the wallet at the identity provider is the
 * single source of truth for what a user can spend across every Relyper product.
 * A service provider therefore never keeps its own balance -- it asks, and it
 * debits, and anything it stores locally is a mirror for its own reporting.
 *
 * The service provider authenticates with the same client ID and secret it uses
 * for the OIDC login, so every debit is attributable to one registered client
 * and an operator can allow or refuse coin spending per app.
 */

export type RelyperCoinWallet = {
  ownerKind: 'user' | 'tenant';
  ownerId: string;
  balanceRc: number;
  lifetimeEarnedRc: number;
  lifetimeSpentRc: number;
  reputationPoints: number;
  convertibleRc: number;
  planTier: string | null;
  planMonthlyAllowanceRc: number;
};

export type RelyperCoinLedgerEntry = {
  direction: 'credit' | 'debit';
  amountRc: number;
  balanceAfterRc: number;
  reason: string;
  product: string | null;
  provider: string | null;
  model: string | null;
  clientId: string | null;
  createdAt: string;
};

export type RelyperCoinDebit = {
  /** IdP subject of the user, i.e. `identity.subject` from the login. */
  subject: string;
  amountRc: number;
  /** Short machine-readable reason, e.g. 'assistant.question'. */
  reason: string;
  /**
   * Makes the debit repeatable without double-charging. Strongly recommended:
   * a retry after a timeout would otherwise bill the user twice.
   */
  idempotencyKey?: string;
  /** Product label shown in the identity provider's reporting. */
  product?: string;
  provider?: string;
  model?: string;
  tenantId?: string;
  meta?: Record<string, unknown>;
};

export type RelyperCoinDebitResult = {
  wallet: RelyperCoinWallet;
  entry: RelyperCoinLedgerEntry | null;
  /** True when this idempotency key had already been booked; nothing was charged again. */
  deduplicated: boolean;
};

export type RelyperCoinsErrorCode =
  /** The wallet does not hold enough coins. */
  | 'insufficient_funds'
  /** This client is registered but not permitted to spend coins. */
  | 'coins_not_enabled'
  /** Client credentials rejected. */
  | 'unauthorized'
  /**
   * Refused with 403 without saying it was the coin permission. Usually the
   * request never reached the coins service: a wrong base URL, a gateway or a
   * WAF. Read `url` and `responseBody` on the error.
   */
  | 'forbidden'
  /** The request was malformed. */
  | 'invalid_request'
  /** The identity provider was unreachable or answered unexpectedly. */
  | 'unavailable';

export class RelyperCoinsError extends Error {
  readonly code: RelyperCoinsErrorCode;
  readonly status: number;
  /** Present on insufficient_funds. */
  readonly balanceRc?: number;
  readonly requestedRc?: number;
  readonly cause?: unknown;
  /**
   * What the service actually answered, and where it was asked.
   *
   * Kept because a status code alone does not identify a cause: a 403 from the
   * coins service and a 403 from a proxy in front of it are the same number and
   * mean entirely different things. Without the body, an operator holding a
   * correctly configured client has nothing to go on but a message this library
   * guessed. `responseError` is the service's own error code when it sent one.
   */
  readonly url?: string;
  readonly responseError?: string;
  readonly responseBody?: string;

  constructor(
    code: RelyperCoinsErrorCode,
    message: string,
    options: {
      status?: number;
      balanceRc?: number;
      requestedRc?: number;
      cause?: unknown;
      url?: string;
      responseError?: string;
      responseBody?: string;
    } = {}
  ) {
    super(message);
    this.name = 'RelyperCoinsError';
    this.code = code;
    this.status = options.status ?? 502;
    this.balanceRc = options.balanceRc;
    this.requestedRc = options.requestedRc;
    this.cause = options.cause;
    this.url = options.url;
    this.responseError = options.responseError;
    this.responseBody = options.responseBody;
  }
}

export type RelyperCoinsOptions = {
  /**
   * Base URL of the identity provider's API, including the path prefix its
   * routes are mounted under. For Relyper that is the issuer plus `/api`, e.g.
   * `https://api.relyper.de/api` for issuer `https://api.relyper.de`.
   */
  baseUrl: string;
  /** Same credentials as the OIDC login. */
  clientId: string;
  clientSecret: string;
  /** Default: 10000. */
  requestTimeoutMs?: number;
  fetch?: typeof globalThis.fetch;
};

export type RelyperCoinsClient = {
  /** Balance and plan allowance of one user's wallet. */
  getWallet(subject: string): Promise<RelyperCoinWallet>;
  /** Recent ledger entries for one user. */
  getLedger(subject: string, limit?: number): Promise<RelyperCoinLedgerEntry[]>;
  /**
   * Spends coins. Throws {@link RelyperCoinsError} with code `insufficient_funds`
   * when the wallet cannot cover the amount -- the debit is refused, not
   * overdrawn.
   */
  debit(input: RelyperCoinDebit): Promise<RelyperCoinDebitResult>;
};

/**
 * Derives the coins API base URL from an OIDC issuer.
 *
 * The Relyper IdP publishes OIDC at the issuer root but mounts its regular API
 * under `/api`, so the two differ by exactly that segment.
 */
export function coinsBaseUrlFromIssuer(issuer: string): string {
  const trimmed = trimTrailingSlashes(issuer);
  return trimmed.endsWith('/api') ? trimmed : trimmed + '/api';
}

export function createRelyperCoinsClient(options: RelyperCoinsOptions): RelyperCoinsClient {
  for (const key of ['baseUrl', 'clientId', 'clientSecret'] as const) {
    if (!options[key] || typeof options[key] !== 'string') {
      throw new TypeError('@relyper/sp-auth/coins: ' + key + ' is required.');
    }
  }
  const doFetch = options.fetch ?? globalThis.fetch;
  if (typeof doFetch !== 'function') {
    throw new TypeError('@relyper/sp-auth/coins: no fetch implementation available.');
  }

  const baseUrl = trimTrailingSlashes(options.baseUrl);
  const timeout = options.requestTimeoutMs ?? 10_000;
  // RFC 6749 section 2.3.1: both halves are form-urlencoded before the base64.
  const authorization = 'Basic ' + Buffer.from(
    encodeURIComponent(options.clientId) + ':' + encodeURIComponent(options.clientSecret),
    'utf8'
  ).toString('base64');

  async function call(path: string, init: { method: string; body?: unknown }): Promise<any> {
    const url = baseUrl + path;
    let response: Response;
    try {
      response = await doFetch(url, {
        method: init.method,
        headers: {
          authorization,
          accept: 'application/json',
          ...(init.body === undefined ? {} : { 'content-type': 'application/json' })
        },
        body: init.body === undefined ? undefined : JSON.stringify(init.body),
        signal: AbortSignal.timeout(timeout)
      });
    } catch (cause) {
      throw new RelyperCoinsError('unavailable', 'The Relyper coin service could not be reached.', { cause });
    }

    const { payload, raw } = await readBody(response);
    if (response.ok) return payload ?? {};

    const error = typeof payload?.error === 'string' ? payload.error : '';
    // Passed to every throw below so the caller can log what was actually
    // answered instead of only what this library concluded from it.
    const evidence = { url, responseError: error || undefined, responseBody: raw || undefined };

    if (response.status === 402 || error === 'insufficient_funds') {
      throw new RelyperCoinsError('insufficient_funds', 'Not enough Relyper Coins.', {
        status: 402,
        balanceRc: numberOrUndefined(payload?.balanceRc),
        requestedRc: numberOrUndefined(payload?.requestedRc),
        ...evidence
      });
    }
    // Only the service's own error code identifies this cause. A bare 403 is
    // not evidence of it: an unmatched route, a gateway or a WAF in front of
    // the service answers with the same status, and reporting those as a
    // permission the operator has already granted sends them looking in the
    // wrong place.
    if (error === 'coins_not_enabled_for_client') {
      throw new RelyperCoinsError('coins_not_enabled', 'This application is not allowed to spend Relyper Coins.', {
        status: response.status,
        ...evidence
      });
    }
    if (response.status === 401) {
      throw new RelyperCoinsError('unauthorized', 'The Relyper coin service rejected this application.', {
        status: 401,
        ...evidence
      });
    }
    if (response.status === 403) {
      throw new RelyperCoinsError('forbidden', 'The Relyper coin service refused this request with 403.', {
        status: 403,
        ...evidence
      });
    }
    if (response.status === 400) {
      throw new RelyperCoinsError('invalid_request', 'The coin request was rejected as invalid.', {
        status: 400,
        ...evidence
      });
    }
    throw new RelyperCoinsError('unavailable', 'The Relyper coin service answered unexpectedly.', {
      ...evidence,
      status: response.status
    });
  }

  function walletPath(subject: string): string {
    if (!subject) throw new TypeError('@relyper/sp-auth/coins: subject is required.');
    return '/integrations/coins/user/' + encodeURIComponent(subject);
  }

  return {
    async getWallet(subject: string): Promise<RelyperCoinWallet> {
      return (await call(walletPath(subject), { method: 'GET' })) as RelyperCoinWallet;
    },

    async getLedger(subject: string, limit = 50): Promise<RelyperCoinLedgerEntry[]> {
      const payload = await call(walletPath(subject) + '/ledger?limit=' + encodeURIComponent(String(limit)), {
        method: 'GET'
      });
      return Array.isArray(payload?.items) ? payload.items : [];
    },

    async debit(input: RelyperCoinDebit): Promise<RelyperCoinDebitResult> {
      if (!(input.amountRc > 0)) {
        throw new TypeError('@relyper/sp-auth/coins: amountRc must be greater than zero.');
      }
      const payload = await call(walletPath(input.subject) + '/debit', {
        method: 'POST',
        body: {
          amountRc: input.amountRc,
          reason: input.reason,
          idempotencyKey: input.idempotencyKey,
          product: input.product,
          provider: input.provider,
          model: input.model,
          tenantId: input.tenantId,
          meta: input.meta ?? {}
        }
      });
      const { ledgerEntry, dedup, ...wallet } = payload ?? {};
      return {
        wallet: wallet as RelyperCoinWallet,
        entry: (ledgerEntry as RelyperCoinLedgerEntry) ?? null,
        deduplicated: dedup === true
      };
    }
  };
}

function trimTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value[end - 1] === '/') end -= 1;
  return value.slice(0, end);
}

function numberOrUndefined(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

/**
 * Reads the body once, as text, and parses JSON from that text.
 *
 * `response.json()` consumes the stream, so a body that is not JSON -- an HTML
 * error page from a gateway, most importantly -- would be lost before anyone
 * could look at it. The raw text is what makes those cases diagnosable, so it
 * is kept and truncated rather than discarded.
 */
async function readBody(response: Response): Promise<{ payload: Record<string, any> | null; raw: string }> {
  let raw = '';
  try {
    raw = await response.text();
  } catch {
    return { payload: null, raw: '' };
  }
  const trimmed = raw.length > 500 ? raw.slice(0, 500) + '...' : raw;
  try {
    return { payload: JSON.parse(raw) as Record<string, any>, raw: trimmed };
  } catch {
    return { payload: null, raw: trimmed };
  }
}
