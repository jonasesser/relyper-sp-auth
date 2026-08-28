# @relyper/sp-auth

Relyper identity for a service provider. Register your app at the Relyper IdP,
authenticate it with its client secret, and get a typed principal with role
gating — without writing an OIDC client yourself.

```bash
npm install @relyper/sp-auth
```

Requires Node 20+. ESM only.

Two ways to establish who the user is, and they are not alternatives of equal
standing:

- **[OIDC login](#oidc-login)** — the app is a registered, confidential OIDC
  client. Authorization Code Flow with PKCE, ID tokens verified against the
  IdP's JWKS, sessions in encrypted cookies. **This is the one to use.**
- **[Gateway headers](#gateway-headers)** — the app trusts identity headers set
  by a trusted proxy. No secret, no signature, no verification. Only defensible
  when the app is unreachable except through that gateway.

On top of that, **[Relyper Coins](#relyper-coins)** lets an app spend from the
central wallets, authenticating with the same client credentials as the login.

## OIDC login

### 1. Register the service provider

In the Relyper IdP's admin UI under **OIDC Settings**: generate a client ID and
a client secret, set the redirect URI to `https://your-app.example/auth/callback`,
and list the application roles your app gates on under **Application Roles**.

The IdP stores only an Argon2id hash of the secret, so it cannot be read back
later. Copy it when it is generated.

### 2. Register the plugin

```ts
import Fastify from 'fastify';
import { relyperOidcAuth } from '@relyper/sp-auth/oidc/fastify';

const app = Fastify();

await app.register(relyperOidcAuth, {
  issuer: process.env.RELYPER_OIDC_ISSUER,          // https://api.relyper.de
  clientId: process.env.RELYPER_OIDC_CLIENT_ID,
  clientSecret: process.env.RELYPER_OIDC_CLIENT_SECRET,
  redirectUri: process.env.RELYPER_OIDC_REDIRECT_URI,
  sessionSecret: process.env.SESSION_SECRET,        // 32+ chars, yours alone

  requiredRole: 'my_service_user',
  protect: (request) => request.url.startsWith('/api/'),
  meRoute: '/api/me',

  // Turn the IdP identity into your own user record.
  resolveUser: async (identity) => prisma.user.upsert({
    where: { idpSubject: identity.subject },
    create: { idpSubject: identity.subject, email: identity.email, displayName: identity.displayName, roles: identity.roles },
    update: { email: identity.email, displayName: identity.displayName, roles: identity.roles, lastSeenAt: new Date() }
  })
});

app.get('/api/cases', async (request) => {
  request.relyperIdentity; // { subject, email, displayName, roles, tenantId, teams }
  request.principal;       // whatever resolveUser returned
});
```

That registers three routes — `/auth/login`, `/auth/callback`, `/auth/logout` —
and guards everything `protect` selects.

`sessionSecret` is **not** the client secret. It is the key this app seals its
own cookies with, it never leaves the process, and rotating it logs everyone out.

### 3. Drive it from the browser

```ts
import { fetchRelyperSession, startRelyperLogin, startRelyperLogout } from '@relyper/sp-auth/client';

const session = await fetchRelyperSession<{ id: string; email: string }>();

switch (session.status) {
  case 'authenticated': return session.user;
  case 'unauthenticated': return startRelyperLogin({ loginUrl: session.loginUrl });
  case 'forbidden': return showNoAccessScreen(session.message);
  case 'error': return showError();
}
```

`startRelyperLogin` is a full navigation, not a fetch: the IdP has to be able to
show its own login page and set its own cookie, which an XHR cannot do. It
remembers the current path and returns the user there afterwards.

### What the flow guarantees

| Step | What is checked |
| --- | --- |
| `/auth/login` | Fresh `state`, `nonce` and PKCE verifier, sealed into a short-lived encrypted cookie |
| `/auth/callback` | `state` matches this browser's login; no cookie means no callback |
| Token exchange | `client_secret_basic` (or `_post`), with the PKCE verifier |
| ID token | RS256 signature against the IdP's JWKS, plus `iss`, `aud`, `exp`, `nonce`, `azp`, `sub` |
| Algorithms | Pinned, so `alg: none` and HMAC-with-public-key are refused |
| UserInfo (optional) | `sub` must match the ID token's, or the response is discarded |
| Role | Checked at login **and** on every request afterwards |
| `returnTo` | Local paths only, so the login cannot become an open redirect |

The client secret only ever travels from your server to the IdP's token
endpoint. It never reaches the browser.

### Sessions

The session is a cookie sealed with `sessionSecret` — encrypted (JWE, direct
A256GCM), not merely signed, so the browser cannot read the user's claims and
tampering fails to decrypt rather than yielding a forged value. The login cookie
and the session cookie use separate keys derived from that one secret, so
neither can be replayed as the other.

Sessions are stateless by default. That has one consequence worth knowing: a
logout clears the cookie in the browser that asked, but a cookie copied
beforehand keeps working until it expires. When that matters, keep a revocation
list:

```ts
await app.register(relyperOidcAuth, {
  // ...
  onLogin: (result, request, sessionId) => revocations.remember(sessionId),
  onLogout: (sessionId) => revocations.revoke(sessionId),
  isSessionRevoked: (sessionId) => revocations.isRevoked(sessionId)
});
```

### Without Fastify

The client is framework-free:

```ts
import { createRelyperOidcClient } from '@relyper/sp-auth/oidc';

const client = createRelyperOidcClient({ issuer, clientId, clientSecret, redirectUri });

// Start
const { url, transaction } = await client.createAuthorizationRequest({ returnTo: '/cases/7' });
// Persist `transaction` for this browser, then redirect to `url`.

// Finish
const { identity, claims, tokens } = await client.completeLogin({ query, transaction });
```

Every failure is a `RelyperOidcError` with a `code`, an HTTP `status`, a message
safe to show a user, and a `detail` safe to log.

### OIDC options

| Option | Default | Purpose |
| --- | --- | --- |
| `issuer` | – | Base URL of the IdP, as it appears in `iss`. Required. |
| `clientId` / `clientSecret` | – | This app's registration. Required. |
| `redirectUri` | – | Must match the registered URI byte for byte. Required. |
| `sessionSecret` | – | Key for this app's own cookies, 32+ chars. Fastify adapter only. |
| `scope` | `openid email profile roles tenant teams` | Requested scopes. |
| `tokenEndpointAuthMethod` | from discovery | `client_secret_basic` or `client_secret_post`. |
| `requiredRole` / `roleMatch` | – / `'any'` | Role gate. |
| `requireEmail` | `true` | Refuse a login with no address. |
| `useUserInfo` | `false` | Also call UserInfo; the Relyper IdP puts everything in the ID token. |
| `clockToleranceSeconds` | `60` | Leeway for `exp` / `iat`. |
| `discoveryTtlMs` | `3600000` | How long the discovery document is reused. |
| `requestTimeoutMs` | `10000` | Timeout for every call to the IdP. |
| `mapClaims` | `defaultClaimsToIdentity` | Custom claim mapping. |
| `fetch` | global | Custom fetch, used for discovery, tokens, UserInfo and JWKS alike. |

Fastify adapter additions: `sessionCookieName`, `loginCookieName`, `cookieDomain`,
`cookiePath`, `cookieSecure`, `sessionTtlSeconds`, `sessionAbsoluteTtlSeconds`,
`loginTtlSeconds`, `rollingSession`, `keepIdToken`, `loginPath`, `callbackPath`,
`logoutPath`, `postLogoutRedirect`, `loginErrorRedirect`, `protect`, `hook`,
`resolveUser`, `principalKey`, `meRoute`, `meResponse`,
`redirectUnauthenticated`, `errorBody`, `onAuthFailure`, `onLogin`, `onLogout`,
`isSessionRevoked`.

## Gateway headers

The original integration, for services behind a gateway that authenticates on
their behalf.

```ts
import { relyperAuth } from '@relyper/sp-auth/fastify';

await app.register(relyperAuth, {
  requiredRole: 'my_service_user',
  protect: (request) => request.url.startsWith('/api/'),
  meRoute: '/api/me',
  resolveUser
});
```

| Header | Meaning |
| --- | --- |
| `x-relyper-subject` | Stable user ID at the IdP |
| `x-relyper-email` | E-mail address |
| `x-relyper-name` | Display name |
| `x-relyper-roles` | Comma-separated roles |

Fallbacks when `acceptForwardedHeaders` is on: `x-forwarded-user`,
`x-forwarded-email`, `x-forwarded-preferred-username`, `x-forwarded-groups`.

Options: `requiredRole`, `roleMatch`, `requireEmail`, `headerNames`,
`acceptForwardedHeaders`, `devAuth`, `unauthenticatedStatus`, `forbiddenStatus`,
`message`, `parseRoles`. Fastify additions: `protect`, `hook`, `resolveUser`,
`principalKey`, `meRoute`, `meResponse`, `errorBody`, `onAuthFailure`,
`warnOnDevAuth`.

The core is a pure function over headers — no framework, no I/O, never throws:

```ts
import { createRelyperAuth } from '@relyper/sp-auth';

const auth = createRelyperAuth({ requiredRole: 'my_service_user' });
const result = auth.authenticate(request.headers);
if (!result.ok) return reply.code(result.status).send({ error: result.message });
result.identity.subject;
```

### Security model — read this

This path trusts headers. It verifies no token and no signature. It is only safe
when the service is unreachable except through a gateway that **overwrites**
client-supplied `x-relyper-*` headers rather than passing them through.

If the service can be reached directly, anyone can send
`x-relyper-roles: my_service_user` and be admitted. `acceptForwardedHeaders`
widens that surface further, because `x-forwarded-*` is what any generic proxy
sets — which is why it is off by default.

Prefer the OIDC login. It needs no such assumption about the network.

## Relyper Coins

Relyper Coins are held centrally: the wallet at the identity provider is the
single source of truth for what a user can spend across every Relyper product.
A service provider never keeps its own balance.

```ts
import { createRelyperCoinsClient, coinsBaseUrlFromIssuer, RelyperCoinsError } from '@relyper/sp-auth/coins';

const coins = createRelyperCoinsClient({
  // The IdP publishes OIDC at the issuer root but mounts its API under /api.
  baseUrl: coinsBaseUrlFromIssuer(process.env.RELYPER_OIDC_ISSUER),
  clientId: process.env.RELYPER_OIDC_CLIENT_ID,
  clientSecret: process.env.RELYPER_OIDC_CLIENT_SECRET
});

const wallet = await coins.getWallet(identity.subject);

try {
  await coins.debit({
    subject: identity.subject,
    amountRc: 5,
    reason: 'assistant.question',
    idempotencyKey: 'my-app:' + requestHash,   // a retry must not charge twice
    product: 'my-app',
    provider: 'openai',
    model: 'gpt-x'
  });
} catch (error) {
  if (error instanceof RelyperCoinsError && error.code === 'insufficient_funds') {
    // error.balanceRc / error.requestedRc
  }
}
```

The same client ID and secret as the OIDC login, so the IdP can attribute every
debit to one registered app and an operator can allow or revoke coin spending
per app. The app has to be ticked as **May consume Relyper Coins** in the IdP
admin UI, or `debit` throws with code `coins_not_enabled`.

`debit` refuses to overdraw a wallet. Because the exact cost of a request is
usually only known after the work is done, check the balance against an estimate
first and debit the real amount afterwards.

## Design

- The OIDC client does no I/O you did not ask for: discovery and JWKS are
  fetched lazily, cached, and go through your `fetch` if you supply one.
- Identity and application user stay separate. The package hands you a
  `RelyperIdentity`; `resolveUser` maps it to your own record. That boundary is
  what makes the package reusable across service providers.
- `subject` is the IdP's ID and never the primary key of your database.
- Errors carry a user-safe `message` and a separate `detail` for logs, so an
  IdP's diagnostics never leak into a response.

## License

MIT
