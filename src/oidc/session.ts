import { hkdfSync, randomBytes, timingSafeEqual } from 'node:crypto';
import { EncryptJWT, jwtDecrypt } from 'jose';
import type { RelyperIdentity } from '../types.js';
import type { RelyperLoginTransaction } from './types.js';

/**
 * Cookie-backed state for the OIDC flow, with no server-side store.
 *
 * Two cookies are involved and both are encrypted, not merely signed:
 *
 *   - the login cookie, which lives for the seconds between the redirect out and
 *     the callback and carries `state`, `nonce` and the PKCE `code_verifier`;
 *   - the session cookie, which carries the identity after a successful login.
 *
 * Encryption (JWE, direct A256GCM) rather than a signature means the browser
 * never sees the verifier or the user's claims, and A256GCM authenticates the
 * ciphertext, so tampering fails to decrypt instead of yielding a forged value.
 *
 * Both keys are derived from one application secret through HKDF with distinct
 * info labels, so the two cookies can never be swapped for one another.
 */

const MIN_SECRET_LENGTH = 32;
const HKDF_SALT = 'relyper-sp-auth/v1';
const SESSION_LABEL = 'session';
const LOGIN_LABEL = 'login-transaction';

export type SessionPayload = {
  identity: RelyperIdentity;
  /** Seconds since the epoch at which the IdP login happened. */
  authenticatedAt: number;
  /**
   * Identifier of this login. The session itself is stateless, so this exists
   * for the application: recording it at logout and rejecting it afterwards is
   * what turns "the browser dropped its cookie" into a revocation that also
   * stops a cookie someone copied beforehand.
   */
  sessionId: string;
  /**
   * ID token, kept only when `keepIdToken` is on -- it is needed as the
   * `id_token_hint` of an RP-initiated logout and for nothing else.
   */
  idToken?: string;
};

/** Opaque, unguessable identifier for one login. */
export function createSessionId(): string {
  return randomBytes(16).toString('base64url');
}

export type SealedCodec<T> = {
  seal(value: T, ttlSeconds: number): Promise<string>;
  /** Returns null for anything that is not a valid, unexpired token of this codec. */
  open(token: string | undefined | null): Promise<T | null>;
};

function deriveKey(secret: string, label: string): Uint8Array {
  if (typeof secret !== 'string' || secret.length < MIN_SECRET_LENGTH) {
    throw new TypeError(
      '@relyper/sp-auth/oidc: the session secret must be at least ' + MIN_SECRET_LENGTH + ' characters.'
    );
  }
  return new Uint8Array(hkdfSync('sha256', Buffer.from(secret, 'utf8'), HKDF_SALT, label, 32));
}

function createCodec<T extends Record<string, unknown>>(secret: string, label: string): SealedCodec<T> {
  const key = deriveKey(secret, label);

  return {
    async seal(value: T, ttlSeconds: number): Promise<string> {
      return new EncryptJWT(value)
        .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
        .setIssuedAt()
        .setExpirationTime(Math.floor(Date.now() / 1000) + ttlSeconds)
        .encrypt(key);
    },

    async open(token: string | undefined | null): Promise<T | null> {
      if (!token) return null;
      try {
        const { payload } = await jwtDecrypt(token, key, { clockTolerance: 5 });
        return payload as unknown as T;
      } catch {
        // Expired, tampered with, or sealed by an older secret. All of these mean
        // the same thing to the caller: there is no usable state here.
        return null;
      }
    }
  };
}

export function createSessionCodec(secret: string): SealedCodec<SessionPayload> {
  return createCodec<SessionPayload>(secret, SESSION_LABEL);
}

export function createLoginCodec(secret: string): SealedCodec<RelyperLoginTransaction> {
  return createCodec<RelyperLoginTransaction>(secret, LOGIN_LABEL);
}

/** Constant-time string comparison for CSRF-style tokens of equal expected length. */
export function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(String(a), 'utf8');
  const right = Buffer.from(String(b), 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

// ------------------------------------------------------------------ cookies ---

export type CookieOptions = {
  path?: string;
  domain?: string;
  maxAgeSeconds?: number;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'Lax' | 'Strict' | 'None';
};

/**
 * Minimal cookie serialisation, so consumers are not forced to install a cookie
 * plugin just to use this package.
 */
export function serializeCookie(name: string, value: string, options: CookieOptions = {}): string {
  const parts = [name + '=' + encodeURIComponent(value)];
  parts.push('Path=' + (options.path ?? '/'));
  if (options.domain) parts.push('Domain=' + options.domain);
  if (typeof options.maxAgeSeconds === 'number') {
    parts.push('Max-Age=' + Math.max(0, Math.floor(options.maxAgeSeconds)));
    // Expires alongside Max-Age for the benefit of clients that ignore the latter.
    const expires = new Date(Date.now() + Math.max(0, options.maxAgeSeconds) * 1000);
    parts.push('Expires=' + expires.toUTCString());
  }
  if (options.httpOnly !== false) parts.push('HttpOnly');
  if (options.secure) parts.push('Secure');
  parts.push('SameSite=' + (options.sameSite ?? 'Lax'));
  return parts.join('; ');
}

/** Cookie header that deletes `name`. */
export function clearCookie(name: string, options: CookieOptions = {}): string {
  return serializeCookie(name, '', { ...options, maxAgeSeconds: 0 });
}

export function parseCookies(header: string | undefined | null): Record<string, string> {
  const result: Record<string, string> = {};
  if (!header) return result;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index < 1) continue;
    const name = part.slice(0, index).trim();
    if (!name || name in result) continue;
    const raw = part.slice(index + 1).trim();
    try {
      result[name] = decodeURIComponent(raw);
    } catch {
      result[name] = raw;
    }
  }
  return result;
}
