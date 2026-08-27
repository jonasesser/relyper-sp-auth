# @relyper/sp-auth

Service-provider side of Relyper identity: turn gateway headers into a typed
principal, gate access by role, and keep the identity layer out of your
application code.

Built for services that sit behind the Relyper auth gateway. The package covers
the parts every service provider repeats — header parsing, role gating, the
`/me` contract, dev login — and leaves persistence to you.

```bash
npm install @relyper/sp-auth
```

Requires Node 20+. ESM only.

## Quick start (Fastify)

```ts
import Fastify from 'fastify';
import { relyperAuth } from '@relyper/sp-auth/fastify';

const app = Fastify();

await app.register(relyperAuth, {
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
  request.relyperIdentity; // { subject, email, displayName, roles }
  request.principal;       // whatever resolveUser returned
});
```

Declare the type of your own principal once:

```ts
declare module 'fastify' {
  interface FastifyRequest {
    principal: { id: string; email: string };
  }
}
```

## Without Fastify

The core is a pure function over headers — no framework, no I/O:

```ts
import { createRelyperAuth } from '@relyper/sp-auth';

const auth = createRelyperAuth({ requiredRole: 'my_service_user' });
const result = auth.authenticate(request.headers); // Node headers or a fetch Headers object

if (!result.ok) {
  return new Response(JSON.stringify({ error: result.message }), { status: result.status });
}
result.identity.subject;
```

`authenticate` never throws and never does I/O, which makes it easy to unit test
and safe to call on every request.

## Browser client

```ts
import { fetchRelyperSession } from '@relyper/sp-auth/client';

const session = await fetchRelyperSession<{ id: string; email: string }>();

switch (session.status) {
  case 'authenticated': return session.user;
  case 'unauthenticated': return redirectToLogin();
  case 'forbidden': return showNoAccessScreen();
  case 'error': return showError();
}
```

No framework dependency. A Vue composable or React hook around it is a few lines.

## Options

| Option | Default | Purpose |
| --- | --- | --- |
| `requiredRole` | – | Role(s) required for this service. Omit to only require an identity. |
| `roleMatch` | `'any'` | With several required roles: one is enough, or all are needed. |
| `requireEmail` | `true` | Set to `false` if your IdP does not send an address. |
| `headerNames` | Relyper headers | Override individual header names for another gateway. |
| `acceptForwardedHeaders` | `false` | Also accept `x-forwarded-*`. Off by default on purpose. |
| `devAuth` | `false` | Local login without a gateway. Never enable in production. |
| `unauthenticatedStatus` | `401` | Status when no identity arrives. |
| `forbiddenStatus` | `403` | Status when the role is missing. |
| `message` | per code | Fixed string or a function for the error message. |
| `parseRoles` | comma-separated | Custom splitting of the roles header. |

Fastify adapter additions: `protect`, `hook`, `resolveUser`, `principalKey`,
`meRoute`, `meResponse`, `errorBody`, `onAuthFailure`, `warnOnDevAuth`.

## Headers

| Header | Meaning |
| --- | --- |
| `x-relyper-subject` | Stable user ID at the IdP |
| `x-relyper-email` | E-mail address |
| `x-relyper-name` | Display name |
| `x-relyper-roles` | Comma-separated roles |

Fallbacks when `acceptForwardedHeaders` is on: `x-forwarded-user`,
`x-forwarded-email`, `x-forwarded-preferred-username`, `x-forwarded-groups`.

## Security model — read this

This package trusts headers. It does **not** verify a token or a signature. That
is only safe when your service is unreachable except through a gateway that
strips client-supplied `x-relyper-*` headers and sets them itself.

If your service can be reached directly, anyone can send
`x-relyper-roles: my_service_user` and be admitted. Two rules follow:

- Never expose the service port publicly without the gateway in front of it.
- Never enable `devAuth` in production. It is off by default, and the Fastify
  adapter logs a warning the first time it is used.

Token verification against the Relyper IdP (JWT/JWKS) is planned for a later
version behind the same API, so switching should not require changes in calling
code.

## Design

- `authenticate` is pure: headers in, result out. No database, no fetch, no throw.
- Identity and application user stay separate. The package hands you a
  `RelyperIdentity`; `resolveUser` maps it to your own record. That boundary is
  what makes the package reusable across service providers.
- `subject` is the IdP ID and never the primary key of your database.

## License

MIT
