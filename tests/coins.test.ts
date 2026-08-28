import { beforeEach, describe, expect, it } from 'vitest';
import {
  coinsBaseUrlFromIssuer,
  createRelyperCoinsClient,
  RelyperCoinsError
} from '../src/coins.js';

const BASE_URL = 'https://api.relyper.test/api';
const CLIENT_ID = 'client-private-case-test';
const CLIENT_SECRET = 'secret-with-/-and-:-chars';
const SUBJECT = '507f1f77bcf86cd799439011';

type Recorded = { url: string; method: string; headers: Record<string, string>; body: string };

let requests: Recorded[];
let responder: (url: string, init: any) => { status: number; body: unknown };

function fakeFetch(): typeof globalThis.fetch {
  return (async (input: any, init: any = {}) => {
    const url = typeof input === 'string' ? input : String(input?.url ?? input);
    const headers: Record<string, string> = {};
    for (const [key, value] of Object.entries((init.headers ?? {}) as Record<string, string>)) {
      headers[key.toLowerCase()] = String(value);
    }
    requests.push({ url, method: init.method ?? 'GET', headers, body: init.body ?? '' });
    const { status, body } = responder(url, init);
    return new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' }
    });
  }) as unknown as typeof globalThis.fetch;
}

function makeClient() {
  return createRelyperCoinsClient({
    baseUrl: BASE_URL,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    fetch: fakeFetch()
  });
}

const WALLET = {
  ownerKind: 'user',
  ownerId: SUBJECT,
  balanceRc: 120,
  lifetimeEarnedRc: 500,
  lifetimeSpentRc: 380,
  reputationPoints: 12,
  convertibleRc: 12,
  planTier: 'pro',
  planMonthlyAllowanceRc: 100
};

beforeEach(() => {
  requests = [];
  responder = () => ({ status: 200, body: WALLET });
});

describe('base url', () => {
  it('derives the coins API from an OIDC issuer', () => {
    // The IdP publishes OIDC at the issuer root but mounts its API under /api.
    expect(coinsBaseUrlFromIssuer('https://api.relyper.de')).toBe('https://api.relyper.de/api');
    expect(coinsBaseUrlFromIssuer('https://api.relyper.de/')).toBe('https://api.relyper.de/api');
    expect(coinsBaseUrlFromIssuer('https://api.relyper.de/api')).toBe('https://api.relyper.de/api');
  });

  it('refuses to be constructed without credentials', () => {
    expect(() => createRelyperCoinsClient({ baseUrl: BASE_URL, clientId: '', clientSecret: 'x' }))
      .toThrow(TypeError);
  });
});

describe('wallet', () => {
  it('reads a wallet with the client credentials', async () => {
    const wallet = await makeClient().getWallet(SUBJECT);
    expect(wallet.balanceRc).toBe(120);

    const request = requests[0];
    expect(request.url).toBe(BASE_URL + '/integrations/coins/user/' + SUBJECT);
    expect(request.method).toBe('GET');

    const decoded = Buffer.from(request.headers.authorization.slice(6), 'base64').toString('utf8');
    // Both halves form-urlencoded before the base64, or a secret containing
    // ':' would split in the wrong place at the other end.
    expect(decoded).toBe(encodeURIComponent(CLIENT_ID) + ':' + encodeURIComponent(CLIENT_SECRET));
  });

  it('escapes the subject into the path', async () => {
    await makeClient().getWallet('sub/../admin');
    expect(requests[0].url).toBe(BASE_URL + '/integrations/coins/user/sub%2F..%2Fadmin');
  });

  it('reads the ledger', async () => {
    responder = () => ({ status: 200, body: { items: [{ direction: 'debit', amountRc: 3 }] } });
    const entries = await makeClient().getLedger(SUBJECT, 10);
    expect(entries).toHaveLength(1);
    expect(requests[0].url).toContain('/ledger?limit=10');
  });
});

describe('debit', () => {
  it('spends coins and reports the new balance', async () => {
    responder = () => ({
      status: 200,
      body: { ...WALLET, balanceRc: 115, ledgerEntry: { amountRc: 5, direction: 'debit' }, dedup: false }
    });

    const result = await makeClient().debit({
      subject: SUBJECT,
      amountRc: 5,
      reason: 'assistant.question',
      idempotencyKey: 'case-7:abc',
      product: 'private-case',
      provider: 'openai',
      model: 'gpt-x'
    });

    expect(result.wallet.balanceRc).toBe(115);
    expect(result.deduplicated).toBe(false);
    expect(result.entry?.amountRc).toBe(5);

    const body = JSON.parse(requests[0].body);
    expect(body).toMatchObject({
      amountRc: 5,
      reason: 'assistant.question',
      idempotencyKey: 'case-7:abc',
      product: 'private-case'
    });
    // Attribution is the identity provider's job, derived from the credentials.
    // Sending a client id in the body would let an app bill another one.
    expect(body.clientId).toBeUndefined();
  });

  it('reports a repeated idempotency key as deduplicated', async () => {
    responder = () => ({ status: 200, body: { ...WALLET, ledgerEntry: { amountRc: 5 }, dedup: true } });
    const result = await makeClient().debit({ subject: SUBJECT, amountRc: 5, reason: 'r', idempotencyKey: 'k' });
    expect(result.deduplicated).toBe(true);
  });

  it('refuses a non-positive amount before contacting the service', async () => {
    await expect(makeClient().debit({ subject: SUBJECT, amountRc: 0, reason: 'r' })).rejects.toThrow(TypeError);
    expect(requests).toHaveLength(0);
  });

  it('surfaces an empty wallet as insufficient_funds with the balance', async () => {
    responder = () => ({ status: 402, body: { error: 'insufficient_funds', balanceRc: 2, requestedRc: 5 } });
    const failure = await makeClient()
      .debit({ subject: SUBJECT, amountRc: 5, reason: 'r' })
      .catch((error) => error as RelyperCoinsError);

    expect(failure).toBeInstanceOf(RelyperCoinsError);
    expect((failure as RelyperCoinsError).code).toBe('insufficient_funds');
    expect((failure as RelyperCoinsError).balanceRc).toBe(2);
    expect((failure as RelyperCoinsError).requestedRc).toBe(5);
  });

  it('distinguishes an app that may not spend coins from bad credentials', async () => {
    responder = () => ({ status: 403, body: { error: 'coins_not_enabled_for_client' } });
    await expect(makeClient().debit({ subject: SUBJECT, amountRc: 1, reason: 'r' }))
      .rejects.toMatchObject({ code: 'coins_not_enabled', status: 403 });

    responder = () => ({ status: 401, body: { error: 'invalid_client' } });
    await expect(makeClient().debit({ subject: SUBJECT, amountRc: 1, reason: 'r' }))
      .rejects.toMatchObject({ code: 'unauthorized', status: 401 });
  });

  it('reports an unreachable service as unavailable', async () => {
    const client = createRelyperCoinsClient({
      baseUrl: BASE_URL,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      fetch: (async () => { throw new Error('ECONNREFUSED'); }) as unknown as typeof globalThis.fetch
    });
    await expect(client.debit({ subject: SUBJECT, amountRc: 1, reason: 'r' }))
      .rejects.toMatchObject({ code: 'unavailable' });
  });

  it('never puts the client secret into a request body', async () => {
    responder = () => ({ status: 200, body: WALLET });
    await makeClient().debit({ subject: SUBJECT, amountRc: 1, reason: 'r' });
    expect(requests[0].body).not.toContain(CLIENT_SECRET);
  });
});
