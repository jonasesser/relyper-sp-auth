import fp from 'fastify-plugin';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { createRelyperAuth, type RelyperAuth } from './core.js';
import type { RelyperAuthFailure, RelyperAuthOptions, RelyperIdentity } from './types.js';

declare module 'fastify' {
  interface FastifyRequest {
    /** Identitaet aus dem Relyper-IdP. Vom Plugin gesetzt, sobald die Anfrage geschuetzt ist. */
    relyperIdentity: RelyperIdentity;
  }
  interface FastifyInstance {
    relyperAuth: RelyperAuth;
  }
}

export type RelyperFastifyOptions = RelyperAuthOptions & {
  /**
   * Entscheidet, welche Anfragen geschuetzt sind. Standard: alle.
   * Typisch: `(request) => request.url.startsWith('/api/')`.
   */
  protect?: (request: FastifyRequest) => boolean;
  /** Hook, in dem geprueft wird. Standard: onRequest, also vor dem Parsen des Bodys. */
  hook?: 'onRequest' | 'preHandler';
  /**
   * Uebersetzt die IdP-Identitaet in das anwendungseigene Nutzerobjekt,
   * typischerweise ein Upsert in der eigenen Datenbank.
   * Ohne diesen Hook landet die IdP-Identitaet unveraendert am Request.
   */
  resolveUser?: (identity: RelyperIdentity, request: FastifyRequest) => unknown | Promise<unknown>;
  /** Eigenschaft am Request, unter der das Ergebnis liegt. Standard: 'principal'. */
  principalKey?: string;
  /** Pfad fuer eine /me-Route. Standard: false, das Plugin registriert von sich aus keine Route. */
  meRoute?: string | false;
  /** Antwort der /me-Route. Standard: `{ user: request[principalKey] }`. */
  meResponse?: (request: FastifyRequest) => unknown;
  /** Fehlerkoerper. Standard: `{ error: failure.message }`. */
  errorBody?: (failure: RelyperAuthFailure, request: FastifyRequest) => unknown;
  /** Haken fuer Audit-Logging fehlgeschlagener Zugriffe. */
  onAuthFailure?: (failure: RelyperAuthFailure, request: FastifyRequest) => void | Promise<void>;
  /** Warnt einmalig im Log, wenn die Dev-Auth greift. Standard: true. */
  warnOnDevAuth?: boolean;
};

async function plugin(app: FastifyInstance, options: RelyperFastifyOptions): Promise<void> {
  const auth = createRelyperAuth(options);
  const principalKey = options.principalKey ?? 'principal';
  const hook = options.hook ?? 'onRequest';
  const protect = options.protect ?? (() => true);
  const errorBody = options.errorBody ?? ((failure: RelyperAuthFailure) => ({ error: failure.message }));
  const warnOnDevAuth = options.warnOnDevAuth ?? true;
  let devAuthWarned = false;

  if (!app.hasRequestDecorator('relyperIdentity')) {
    // Fastify empfiehlt, den Platz am Request vorab zu reservieren. Der Wert ist
    // bis zum Hook leer; der deklarierte Typ bleibt bewusst nicht-nullable,
    // weil in geschuetzten Routen immer eine Identitaet vorliegt.
    app.decorateRequest('relyperIdentity', null as unknown as RelyperIdentity);
  }
  if (!app.hasRequestDecorator(principalKey)) {
    app.decorateRequest(principalKey, null);
  }
  if (!app.hasDecorator('relyperAuth')) {
    app.decorate('relyperAuth', auth);
  }

  app.addHook(hook, async (request: FastifyRequest, reply: FastifyReply) => {
    if (!protect(request)) return;

    const result = auth.authenticate(request.headers);

    if (!result.ok) {
      if (options.onAuthFailure) await options.onAuthFailure(result, request);
      return reply.code(result.status).send(errorBody(result, request));
    }

    if (result.viaDevAuth && warnOnDevAuth && !devAuthWarned) {
      devAuthWarned = true;
      app.log.warn(
        '@relyper/sp-auth: dev auth is active, requests without gateway headers are treated as an authenticated user. Never enable this in production.'
      );
    }

    request.relyperIdentity = result.identity;
    const principal = options.resolveUser ? await options.resolveUser(result.identity, request) : result.identity;
    (request as unknown as Record<string, unknown>)[principalKey] = principal;
  });

  if (options.meRoute) {
    const meResponse = options.meResponse
      ?? ((request: FastifyRequest) => ({ user: (request as unknown as Record<string, unknown>)[principalKey] }));
    app.get(options.meRoute, async (request: FastifyRequest) => meResponse(request));
  }
}

export const relyperAuth = fp(plugin, {
  name: '@relyper/sp-auth',
  fastify: '5.x'
});

export default relyperAuth;
