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

  constructor(
    code: RelyperCoinsErrorCode,
    message: string,
    options: { status?: number; balanceRc?: number; requestedRc?: number; cause?: unknown } = {}
  ) {
    super(message);
    this.name = 'RelyperCoinsError';
    this.code = code;
    this.status = options.status ?? 502;
    this.balanceRc = options.balanceRc;
    this.requestedRc = options.requestedRc;
    this.cause = options.cause;
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

    const payload = await readJson(response);
    if (response.ok) return payload ?? {};

    const error = typeof payload?.error === 'string' ? payload.error : '';
    if (response.status === 402 || error === 'insufficient_funds') {
      throw new RelyperCoinsError('insufficient_funds', 'Not enough Relyper Coins.', {
        status: 402,
        balanceRc: numberOrUndefined(payload?.balanceRc),
        requestedRc: numberOrUndefined(payload?.requestedRc)
      });
    }
    if (response.status === 403 || error === 'coins_not_enabled_for_client') {
      throw new RelyperCoinsError('coins_not_enabled', 'This application is not allowed to spend Relyper Coins.', {
        status: 403
      });
    }
    if (response.status === 401) {
      throw new RelyperCoinsError('unauthorized', 'The Relyper coin service rejected this application.', {
        status: 401
      });
    }
    if (response.status === 400) {
      throw new RelyperCoinsError('invalid_request', 'The coin request was rejected as invalid.', { status: 400 });
    }
    throw new RelyperCoinsError('unavailable', 'The Relyper coin service answered unexpectedly.', {
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

async function readJson(response: Response): Promise<Record<string, any> | null> {
  try {
    return (await response.json()) as Record<string, any>;
  } catch {
    return null;
  }
}
