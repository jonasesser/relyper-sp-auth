import { describe, expect, it } from 'vitest';
import {
  clearCookie,
  createLoginCodec,
  createSessionCodec,
  parseCookies,
  safeEqual,
  serializeCookie
} from '../src/oidc/session.js';
import type { RelyperIdentity } from '../src/types.js';

const SECRET = 'a-test-secret-that-is-long-enough-000';

const IDENTITY: RelyperIdentity = {
  subject: 'user-1',
  email: 'anna@relyper.test',
  displayName: 'Anna Example',
  roles: ['relyper_private_case_user'],
  tenantId: 'tenant-a'
};

describe('sealed cookies', () => {
  it('round-trips a session', async () => {
    const codec = createSessionCodec(SECRET);
    const token = await codec.seal({ identity: IDENTITY, authenticatedAt: 1000, sessionId: 'sid-1' }, 60);
    const opened = await codec.open(token);
    expect(opened?.identity).toEqual(IDENTITY);
    expect(opened?.authenticatedAt).toBe(1000);
  });

  it('encrypts rather than merely signs, so the browser cannot read the claims', async () => {
    const codec = createSessionCodec(SECRET);
    const token = await codec.seal({ identity: IDENTITY, authenticatedAt: 1000, sessionId: 'sid-1' }, 60);
    // A signed JWT would carry the payload in plain base64url; an encrypted one
    // must not reveal the e-mail address or the roles anywhere in the string.
    const decoded = token.split('.').map((part) => Buffer.from(part, 'base64url').toString('utf8')).join('');
    expect(decoded).not.toContain('anna@relyper.test');
    expect(decoded).not.toContain('relyper_private_case_user');
  });

  it('refuses a tampered token', async () => {
    const codec = createSessionCodec(SECRET);
    const token = await codec.seal({ identity: IDENTITY, authenticatedAt: 1000, sessionId: 'sid-1' }, 60);
    const parts = token.split('.');
    // Flip a byte in the ciphertext; A256GCM authentication has to catch it.
    const ciphertext = Buffer.from(parts[3], 'base64url');
    ciphertext[0] = ciphertext[0] ^ 0xff;
    parts[3] = ciphertext.toString('base64url');
    expect(await codec.open(parts.join('.'))).toBeNull();
  });

  it('refuses a token sealed with a different secret', async () => {
    const token = await createSessionCodec(SECRET).seal({ identity: IDENTITY, authenticatedAt: 1, sessionId: 'sid-1' }, 60);
    const other = createSessionCodec('a-completely-different-secret-000000');
    expect(await other.open(token)).toBeNull();
  });

  it('refuses an expired token', async () => {
    const codec = createSessionCodec(SECRET);
    // Negative TTL puts the expiry well outside the codec's 5 second tolerance.
    const token = await codec.seal({ identity: IDENTITY, authenticatedAt: 1, sessionId: 'sid-1' }, -60);
    expect(await codec.open(token)).toBeNull();
  });

  it('keeps the login and session cookies cryptographically separate', async () => {
    const sessions = createSessionCodec(SECRET);
    const logins = createLoginCodec(SECRET);
    const loginToken = await logins.seal(
      { state: 's', nonce: 'n', codeVerifier: 'v', returnTo: '/' },
      60
    );
    // Same application secret, different derived key: a login cookie replayed as
    // a session cookie must not open, or a half-finished login would be a session.
    expect(await sessions.open(loginToken)).toBeNull();
  });

  it('treats missing input as no session', async () => {
    const codec = createSessionCodec(SECRET);
    expect(await codec.open(undefined)).toBeNull();
    expect(await codec.open('')).toBeNull();
    expect(await codec.open('not-a-token')).toBeNull();
  });

  it('rejects a secret that is too short to be worth having', () => {
    expect(() => createSessionCodec('short')).toThrow(TypeError);
  });
});

describe('cookie helpers', () => {
  it('sets the flags a session cookie needs', () => {
    const header = serializeCookie('relyper_session', 'value', {
      maxAgeSeconds: 3600,
      secure: true,
      sameSite: 'Lax'
    });
    expect(header).toContain('relyper_session=value');
    expect(header).toContain('Path=/');
    expect(header).toContain('HttpOnly');
    expect(header).toContain('Secure');
    expect(header).toContain('SameSite=Lax');
    expect(header).toContain('Max-Age=3600');
  });

  it('encodes values that would otherwise break the header', () => {
    const header = serializeCookie('n', 'a;b c');
    expect(header.startsWith('n=a%3Bb%20c;')).toBe(true);
  });

  it('expires a cookie when clearing it', () => {
    expect(clearCookie('relyper_session')).toContain('Max-Age=0');
  });

  it('parses a cookie header', () => {
    const parsed = parseCookies('relyper_session=abc; other=1; encoded=a%20b');
    expect(parsed.relyper_session).toBe('abc');
    expect(parsed.other).toBe('1');
    expect(parsed.encoded).toBe('a b');
  });

  it('keeps the first value when a name appears twice', () => {
    // A second cookie of the same name, injected on a sibling path, must not
    // shadow the real one.
    expect(parseCookies('a=first; a=second').a).toBe('first');
  });

  it('survives a malformed header', () => {
    expect(parseCookies('')).toEqual({});
    expect(parseCookies(undefined)).toEqual({});
    expect(parseCookies('=novalue; ;justname')).toEqual({});
  });
});

describe('safeEqual', () => {
  it('compares without leaking length-independent timing', () => {
    expect(safeEqual('abc', 'abc')).toBe(true);
    expect(safeEqual('abc', 'abd')).toBe(false);
    expect(safeEqual('abc', 'abcd')).toBe(false);
    expect(safeEqual('', '')).toBe(true);
  });
});
