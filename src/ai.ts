/**
 * Client for the Relyper AI proxy.
 *
 * A service provider that uses this holds no provider keys of its own. It
 * describes the call, Relyper runs it with its own credentials, measures what
 * was consumed and debits the user's wallet before answering. The application
 * never sees an OpenAI or Anthropic key, and the ledger records what was
 * actually used rather than what the application said it used.
 *
 * Authenticated with the same client ID and secret as the OIDC login, exactly
 * like the coins client -- and gated by the same `May consume Relyper Coins`
 * flag, because spending a model here is spending coins.
 */

export type RelyperAiErrorCode =
  /** The wallet cannot cover the call. Nothing was run. */
  | 'insufficient_funds'
  /** This client is registered but not permitted to spend coins. */
  | 'coins_not_enabled'
  /** Client credentials rejected. */
  | 'unauthorized'
  /** Refused with 403 without saying it was the coin permission. */
  | 'forbidden'
  /** The model is not offered, or the request was malformed. */
  | 'invalid_request'
  /** The upstream provider failed. Nothing was billed. */
  | 'upstream_failed'
  /** Relyper was unreachable or answered unexpectedly. */
  | 'unavailable';

export class RelyperAiError extends Error {
  readonly code: RelyperAiErrorCode;
  readonly status: number;
  readonly balanceRc?: number;
  readonly requestedRc?: number;
  readonly url?: string;
  readonly responseError?: string;
  readonly responseBody?: string;
  readonly cause?: unknown;

  constructor(
    code: RelyperAiErrorCode,
    message: string,
    options: {
      status?: number;
      balanceRc?: number;
      requestedRc?: number;
      url?: string;
      responseError?: string;
      responseBody?: string;
      cause?: unknown;
    } = {}
  ) {
    super(message);
    this.name = 'RelyperAiError';
    this.code = code;
    this.status = options.status ?? 502;
    this.balanceRc = options.balanceRc;
    this.requestedRc = options.requestedRc;
    this.url = options.url;
    this.responseError = options.responseError;
    this.responseBody = options.responseBody;
    this.cause = options.cause;
  }
}

export type RelyperAiMessage = {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
  /** On a tool result: the call it answers. */
  toolCallId?: string;
  /** On an assistant turn that asked for tools. */
  toolCalls?: RelyperAiToolCall[];
};

export type RelyperAiTool = {
  name: string;
  description?: string;
  /** JSON Schema for the arguments, passed through unchanged. */
  inputSchema: Record<string, unknown>;
};

export type RelyperAiToolCall = { id: string; name: string; arguments: string };

export type RelyperAiRequest = {
  provider: 'openai' | 'anthropic';
  model: string;
  messages: RelyperAiMessage[];
  tools?: RelyperAiTool[];
  maxOutputTokens?: number;
  temperature?: number;
  /** What the debit is labelled as in the user's consumption report. */
  reason?: string;
  product?: string;
  /** A retry with the same key settles onto the same ledger entry. */
  idempotencyKey?: string;
  meta?: Record<string, unknown>;
  /**
   * The ID token Relyper issued this user for this application.
   *
   * Required by default, and the reason a service provider cannot spend a
   * stranger's coins: Relyper checks that the token is its own, that it was
   * issued for the calling client, and that its subject is the wallet being
   * charged. Forward the token from the user's session -- never mint or cache
   * one per application.
   */
  userToken?: string;
};

export type RelyperAiUsage = { inputTokens: number; outputTokens: number };

export type RelyperAiResult = {
  text: string;
  toolCalls: RelyperAiToolCall[];
  stopReason: string | null;
  usage: RelyperAiUsage;
  /** What this call cost, as measured and billed by Relyper. */
  coins: { amountRc: number; dedup: boolean };
  /** The wallet after the debit, when the proxy reported it. */
  wallet?: { balanceRc: number } & Record<string, unknown>;
};

export type RelyperAiModel = {
  provider: 'openai' | 'anthropic';
  model: string;
  label: string;
  inputPerMTok: number;
  outputPerMTok: number;
};

/** Emitted while a call is streaming. `done` always arrives last. */
export type RelyperAiEvent =
  | { type: 'text'; delta: string }
  | { type: 'tool_call'; call: RelyperAiToolCall }
  | { type: 'done'; result: RelyperAiResult };

export type RelyperAiOptions = {
  /** The IdP's API base, e.g. `https://api.relyper.de/api`. */
  baseUrl: string;
  /** Same credentials as the OIDC login. */
  clientId: string;
  clientSecret: string;
  /** Default: 300000. Model calls are slow; this is not a page load. */
  requestTimeoutMs?: number;
  fetch?: typeof globalThis.fetch;
};

export type RelyperAiClient = {
  /** What this deployment will run, with prices. */
  listModels(): Promise<RelyperAiModel[]>;
  /** One call, answered when it is finished. */
  complete(subject: string, request: RelyperAiRequest): Promise<RelyperAiResult>;
  /** The same call, delivered as it is produced. Resolves with the finished result. */
  stream(
    subject: string,
    request: RelyperAiRequest,
    onEvent: (event: RelyperAiEvent) => void
  ): Promise<RelyperAiResult>;
};

/** Derives the AI base URL from an OIDC issuer, as the coins client does. */
export function aiBaseUrlFromIssuer(issuer: string): string {
  const trimmed = trimTrailingSlashes(issuer);
  return trimmed.endsWith('/api') ? trimmed : trimmed + '/api';
}

export function createRelyperAiClient(options: RelyperAiOptions): RelyperAiClient {
  for (const key of ['baseUrl', 'clientId', 'clientSecret'] as const) {
    if (!options[key] || typeof options[key] !== 'string') {
      throw new TypeError('@relyper/sp-auth/ai: ' + key + ' is required.');
    }
  }
  const doFetch = options.fetch ?? globalThis.fetch;
  if (typeof doFetch !== 'function') {
    throw new TypeError('@relyper/sp-auth/ai: no fetch implementation available.');
  }

  const baseUrl = trimTrailingSlashes(options.baseUrl);
  const timeout = options.requestTimeoutMs ?? 300_000;
  // RFC 6749 section 2.3.1: both halves are form-urlencoded before the base64.
  const authorization = 'Basic ' + Buffer.from(
    encodeURIComponent(options.clientId) + ':' + encodeURIComponent(options.clientSecret),
    'utf8'
  ).toString('base64');

  function path(subject: string, suffix: string): string {
    if (!subject) throw new TypeError('@relyper/sp-auth/ai: subject is required.');
    return baseUrl + '/integrations/ai/user/' + encodeURIComponent(subject) + suffix;
  }

  /** Turns a non-OK response into the error that says what actually happened. */
  async function fail(url: string, response: Response): Promise<never> {
    const raw = await response.text().catch(() => '');
    let payload: any = null;
    try {
      payload = JSON.parse(raw);
    } catch {
      payload = null;
    }
    const error = typeof payload?.error === 'string' ? payload.error : '';
    const evidence = {
      status: response.status,
      url,
      responseError: error || undefined,
      responseBody: raw ? raw.slice(0, 500) : undefined
    };

    if (response.status === 402 || error === 'insufficient_funds') {
      throw new RelyperAiError('insufficient_funds', 'Not enough Relyper Coins for this call.', {
        ...evidence,
        balanceRc: numberOrUndefined(payload?.balanceRc),
        requestedRc: numberOrUndefined(payload?.requestedRc)
      });
    }
    if (error === 'coins_not_enabled_for_client') {
      throw new RelyperAiError('coins_not_enabled', 'This application is not allowed to spend Relyper Coins.', evidence);
    }
    if (response.status === 401) {
      throw new RelyperAiError('unauthorized', 'Relyper rejected this application.', evidence);
    }
    if (response.status === 403) {
      throw new RelyperAiError('forbidden', 'Relyper refused this request with 403.', evidence);
    }
    if (response.status === 400) {
      throw new RelyperAiError('invalid_request', 'The AI request was rejected as invalid.', evidence);
    }
    if (response.status === 502 || error === 'upstream_failed') {
      throw new RelyperAiError('upstream_failed', 'The model provider failed. Nothing was billed.', evidence);
    }
    throw new RelyperAiError('unavailable', 'The Relyper AI service answered unexpectedly.', evidence);
  }

  async function send(url: string, body: unknown, accept: string): Promise<Response> {
    let response: Response;
    try {
      response = await doFetch(url, {
        method: 'POST',
        headers: { authorization, accept, 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(timeout)
      });
    } catch (cause) {
      throw new RelyperAiError('unavailable', 'The Relyper AI service could not be reached.', { url, cause });
    }
    if (!response.ok) await fail(url, response);
    return response;
  }

  return {
    async listModels() {
      const url = baseUrl + '/integrations/ai/models';
      let response: Response;
      try {
        response = await doFetch(url, {
          method: 'GET',
          headers: { authorization, accept: 'application/json' },
          signal: AbortSignal.timeout(timeout)
        });
      } catch (cause) {
        throw new RelyperAiError('unavailable', 'The Relyper AI service could not be reached.', { url, cause });
      }
      if (!response.ok) await fail(url, response);
      const payload: any = await response.json().catch(() => null);
      return Array.isArray(payload?.models) ? payload.models : [];
    },

    async complete(subject, request) {
      const url = path(subject, '/completions');
      const response = await send(url, request, 'application/json');
      const payload: any = await response.json();
      return {
        text: String(payload?.text ?? ''),
        toolCalls: Array.isArray(payload?.toolCalls) ? payload.toolCalls : [],
        stopReason: payload?.stopReason ?? null,
        usage: {
          inputTokens: Number(payload?.usage?.inputTokens ?? 0),
          outputTokens: Number(payload?.usage?.outputTokens ?? 0)
        },
        coins: {
          amountRc: Number(payload?.coins?.amountRc ?? 0),
          dedup: payload?.coins?.dedup === true
        },
        wallet: payload?.wallet ?? undefined
      };
    },

    async stream(subject, request, onEvent) {
      const url = path(subject, '/completions/stream');
      const response = await send(url, request, 'text/event-stream');

      const reader = response.body?.getReader();
      if (!reader) {
        throw new RelyperAiError('unavailable', 'The Relyper AI service returned no stream.', { url });
      }

      const decoder = new TextDecoder();
      let buffer = '';
      let finished: RelyperAiResult | null = null;

      const handle = (frame: string) => {
        const data = frame
          .split('\n')
          .filter((line) => line.startsWith('data:'))
          .map((line) => line.slice(5).trim())
          .join('');
        if (!data) return;

        let event: any;
        try {
          event = JSON.parse(data);
        } catch {
          return;
        }

        if (event?.type === 'error') {
          throw new RelyperAiError(
            event.error === 'upstream_failed' ? 'upstream_failed' : 'unavailable',
            String(event.error_description || event.error || 'the stream failed'),
            { url, responseError: String(event.error || '') }
          );
        }
        if (event?.type === 'done') {
          const result = event.result ?? {};
          finished = {
            text: String(result.text ?? ''),
            toolCalls: Array.isArray(result.toolCalls) ? result.toolCalls : [],
            stopReason: result.stopReason ?? null,
            usage: {
              inputTokens: Number(result.usage?.inputTokens ?? 0),
              outputTokens: Number(result.usage?.outputTokens ?? 0)
            },
            coins: { amountRc: Number(event.coins?.amountRc ?? 0), dedup: event.coins?.dedup === true },
            wallet: event.wallet ?? undefined
          };
          onEvent({ type: 'done', result: finished });
          return;
        }
        onEvent(event as RelyperAiEvent);
      };

      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let separator = buffer.indexOf('\n\n');
        while (separator >= 0) {
          const frame = buffer.slice(0, separator);
          buffer = buffer.slice(separator + 2);
          handle(frame);
          separator = buffer.indexOf('\n\n');
        }
      }

      if (!finished) {
        // The stream ended without a final event: the answer may be complete
        // upstream, but nothing here knows what it cost, and reporting a call
        // as free is worse than reporting it as failed.
        throw new RelyperAiError('unavailable', 'The stream ended before the call was accounted for.', { url });
      }
      return finished;
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
