import { randomBytes, createHash } from 'node:crypto';

/**
 * Client side of Proof Key for Code Exchange (RFC 7636) plus the random values
 * that protect the authorization request: `state` against CSRF on the callback,
 * `nonce` against a replayed ID token.
 *
 * All three are 256 bits of CSPRNG output rendered as base64url, which lands in
 * the 43 characters RFC 7636 asks for as a minimum.
 */

function randomUrlSafe(byteLength = 32): string {
  return randomBytes(byteLength).toString('base64url');
}

export function createCodeVerifier(): string {
  return randomUrlSafe(32);
}

export function createState(): string {
  return randomUrlSafe(32);
}

export function createNonce(): string {
  return randomUrlSafe(32);
}

/** S256 challenge for a verifier. `plain` is deliberately not offered. */
export function codeChallengeFor(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}
