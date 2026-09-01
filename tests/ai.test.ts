import { beforeEach, describe, expect, it } from 'vitest';
import { aiBaseUrlFromIssuer, createRelyperAiClient, RelyperAiError } from '../src/ai.js';

/**
 * The proxy client, against a fake Relyper.
 *
 * Two things are worth guarding here. The billing figures must survive the
 * round trip intact -- an application that cannot see what a call cost cannot
 * show it to anyone. And a stream that ends without its final event must fail
 * rather than resolve, because a call reported as free is worse than a call
 * reported as broken.
 */

const BASE_URL = 'https://api.relyper.test/api';
const CLIENT_ID = 'client-aifactory-test';
const CLIENT_SECRET = 'secret-with-/-and-:-chars';
const SUBJECT = 'user-42';

let requests: { url: string; method: string; headers: Record<string, string>; body: any }[];
let responder: (url: string) => { status: number; body?: unknown; sse?: string[] };

function fakeFetch(): typeof globalThis.fetch {
  return (async (input: any, init: any = {}) => {
    const url = String(input);
    const headers: Record<string, string> = {};
    for (const [key, value] of Object.entries((init.headers ?? {}) as Record<string, string>)) {
      headers[key.toLowerCase()] = String(value);
    }
    requests.push({ url, method: init.method ?? 'GET', headers, body: init.body ? JSON.parse(init.body) : null });

    const { status, body, sse } = responder(url);
    if (sse) {
      const stream = new ReadableStream({
        start(controller) {
          const encoder = new TextEncoder();
          for (const frame of sse) controller.enqueue(encoder.encode(`data: ${frame}\n\n`));
          controller.close();
        }
      });
      return new Response(stream, { status, headers: { 'content-type': 'text/event-stream' } });
    }
    return new Response(JSON.stringify(body ?? {}), { status, headers: { 'content-type': 'application/json' } });
  }) as unknown as typeof globalThis.fetch;
}

function makeClient() {
  return createRelyperAiClient({ baseUrl: BASE_URL, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, fetch: fakeFetch() });
}

const REQUEST = {
  provider: 'anthropic' as const,
  model: 'claude-sonnet-4-5',
  messages: [{ role: 'user' as const, content: 'Was steht im Vertrag?' }]
};

beforeEach(() => {
  requests = [];
  responder = () => ({
    status: 200,
    body: {
      text: 'Im Vertrag steht ...',
      toolCalls: [],
      stopReason: 'end_turn',
      usage: { inputTokens: 1200, outputTokens: 300 },
      coins: { amountRc: 2, dedup: false },
      wallet: { balanceRc: 118 }
    }
  });
});

describe('Aufbau', () => {
  it('leitet die Basis-URL wie der Coins-Client ab', () => {
    expect(aiBaseUrlFromIssuer('https://api.relyper.de')).toBe('https://api.relyper.de/api');
    expect(aiBaseUrlFromIssuer('https://api.relyper.de/api/')).toBe('https://api.relyper.de/api');
  });

  it('verlangt Credentials', () => {
    expect(() => createRelyperAiClient({ baseUrl: BASE_URL, clientId: '', clientSecret: 'x' })).toThrow(TypeError);
  });
});

describe('complete', () => {
  it('ruft den Endpunkt des Subjects mit Client-Credentials auf', async () => {
    await makeClient().complete(SUBJECT, REQUEST);
    const request = requests[0];
    expect(request.url).toBe(`${BASE_URL}/integrations/ai/user/${SUBJECT}/completions`);
    const decoded = Buffer.from(request.headers.authorization.slice(6), 'base64').toString('utf8');
    expect(decoded).toBe(encodeURIComponent(CLIENT_ID) + ':' + encodeURIComponent(CLIENT_SECRET));
  });

  it('gibt Verbrauch und Kosten unveraendert zurueck', async () => {
    const result = await makeClient().complete(SUBJECT, REQUEST);
    expect(result.text).toBe('Im Vertrag steht ...');
    expect(result.usage).toEqual({ inputTokens: 1200, outputTokens: 300 });
    expect(result.coins).toEqual({ amountRc: 2, dedup: false });
    expect(result.wallet?.balanceRc).toBe(118);
  });

  it('meldet ein leeres Wallet als insufficient_funds', async () => {
    responder = () => ({ status: 402, body: { error: 'insufficient_funds', balanceRc: 1, requestedRc: 40 } });
    const failure = await makeClient().complete(SUBJECT, REQUEST).catch((error) => error);
    expect(failure).toBeInstanceOf(RelyperAiError);
    expect((failure as RelyperAiError).code).toBe('insufficient_funds');
    expect((failure as RelyperAiError).balanceRc).toBe(1);
    expect((failure as RelyperAiError).requestedRc).toBe(40);
  });

  it('unterscheidet die fehlende Coin-Berechtigung von einem blanken 403', async () => {
    responder = () => ({ status: 403, body: { error: 'coins_not_enabled_for_client' } });
    const denied = await makeClient().complete(SUBJECT, REQUEST).catch((error) => error);
    expect((denied as RelyperAiError).code).toBe('coins_not_enabled');

    responder = () => ({ status: 403, body: { message: 'Forbidden' } });
    const gateway = await makeClient().complete(SUBJECT, REQUEST).catch((error) => error);
    expect((gateway as RelyperAiError).code).toBe('forbidden');
    expect((gateway as RelyperAiError).responseBody).toContain('Forbidden');
  });

  it('meldet einen Anbieterausfall als upstream_failed', async () => {
    responder = () => ({ status: 502, body: { error: 'upstream_failed' } });
    const failure = await makeClient().complete(SUBJECT, REQUEST).catch((error) => error);
    expect((failure as RelyperAiError).code).toBe('upstream_failed');
  });
});

describe('stream', () => {
  it('reicht Teilstuecke durch und liefert am Ende die Abrechnung', async () => {
    responder = () => ({
      status: 200,
      sse: [
        JSON.stringify({ type: 'text', delta: 'Im ' }),
        JSON.stringify({ type: 'text', delta: 'Vertrag' }),
        JSON.stringify({
          type: 'done',
          result: { text: 'Im Vertrag', toolCalls: [], stopReason: 'end_turn', usage: { inputTokens: 10, outputTokens: 4 } },
          coins: { amountRc: 1, dedup: false },
          wallet: { balanceRc: 99 }
        })
      ]
    });

    const seen: string[] = [];
    const result = await makeClient().stream(SUBJECT, REQUEST, (event) => {
      if (event.type === 'text') seen.push(event.delta);
    });

    expect(seen).toEqual(['Im ', 'Vertrag']);
    expect(result.text).toBe('Im Vertrag');
    expect(result.coins.amountRc).toBe(1);
    expect(result.wallet?.balanceRc).toBe(99);
  });

  it('reicht Tool-Aufrufe durch', async () => {
    responder = () => ({
      status: 200,
      sse: [
        JSON.stringify({ type: 'tool_call', call: { id: 'call_1', name: 'search_documents', arguments: '{"q":"Vertrag"}' } }),
        JSON.stringify({
          type: 'done',
          result: { text: '', toolCalls: [{ id: 'call_1', name: 'search_documents', arguments: '{"q":"Vertrag"}' }], stopReason: 'tool_use', usage: { inputTokens: 5, outputTokens: 2 } },
          coins: { amountRc: 1, dedup: false }
        })
      ]
    });

    const calls: string[] = [];
    const result = await makeClient().stream(SUBJECT, REQUEST, (event) => {
      if (event.type === 'tool_call') calls.push(event.call.name);
    });

    expect(calls).toEqual(['search_documents']);
    expect(result.toolCalls[0].arguments).toBe('{"q":"Vertrag"}');
  });

  it('scheitert, wenn der Stream ohne Abrechnung endet', async () => {
    // Ein abgerissener Stream darf nicht als kostenloser Aufruf durchgehen.
    responder = () => ({ status: 200, sse: [JSON.stringify({ type: 'text', delta: 'halb' })] });
    const failure = await makeClient().stream(SUBJECT, REQUEST, () => undefined).catch((error) => error);
    expect(failure).toBeInstanceOf(RelyperAiError);
    expect((failure as RelyperAiError).code).toBe('unavailable');
  });
});
