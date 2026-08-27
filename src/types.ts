/** Identity that the Relyper IdP passes to a service provider via the gateway. */
export type RelyperIdentity = {
  /** Stable, unique identifier of the user at the IdP. Never the local database ID. */
  subject: string;
  email: string;
  displayName: string;
  roles: string[];
};

export type RelyperAuthFailureCode = 'missing_subject' | 'missing_email' | 'missing_role';

export type RelyperAuthFailure = {
  ok: false;
  /** HTTP status the adapter should send. */
  status: number;
  code: RelyperAuthFailureCode;
  message: string;
  /**
   * Roles the gateway sent along. Intended solely for logging and
   * debugging, never as a basis for authorization.
   */
  presentedRoles: string[];
};

export type RelyperAuthSuccess = {
  ok: true;
  identity: RelyperIdentity;
  /** true if the identity came from dev auth rather than the gateway. */
  viaDevAuth: boolean;
};

export type RelyperAuthResult = RelyperAuthSuccess | RelyperAuthFailure;

export type RelyperHeaderNames = {
  subject: string;
  email: string;
  displayName: string;
  roles: string;
};

/**
 * Header source. Supports both the plain object from Node/Fastify and
 * anything with a `get` method, such as the Fetch API's Headers.
 */
export type RelyperHeaderSource =
  | Record<string, string | string[] | undefined>
  | { get(name: string): string | null | undefined };

export type RelyperDevAuthOptions = {
  /** Default: true, as soon as an object is passed. */
  enabled?: boolean;
  subject?: string;
  email?: string;
  displayName?: string;
  roles?: string[];
};

export type RelyperAuthOptions = {
  /** Role(s) the user needs for this service provider. Empty means: no role check. */
  requiredRole?: string | string[];
  /** With multiple required roles: one is enough ('any', default) or all are needed ('all'). */
  roleMatch?: 'any' | 'all';
  /** Default: true. Set to false if the IdP does not supply an email address. */
  requireEmail?: boolean;
  /** Custom header names, e.g. for a different gateway prefix. */
  headerNames?: Partial<RelyperHeaderNames>;
  /**
   * Accept `x-forwarded-*` as a fallback. Default: false.
   * Deliberately off because these headers can come from generic proxies.
   */
  acceptForwardedHeaders?: boolean | Partial<RelyperHeaderNames>;
  /**
   * Development login without a gateway. Default: off.
   * Must stay off in production, otherwise any caller authenticates itself.
   */
  devAuth?: RelyperDevAuthOptions | false;
  /** Status when no identity arrives at all. Default: 401. */
  unauthenticatedStatus?: number;
  /** Status when the identity is valid but the role is missing. Default: 403. */
  forbiddenStatus?: number;
  /** Fixed text or function for the error message. */
  message?: string | ((failure: Omit<RelyperAuthFailure, 'message'>) => string);
  /** Custom parsing of the roles header, in case the gateway does not use a comma. */
  parseRoles?: (raw: string) => string[];
};

export type ResolvedRelyperAuthOptions = {
  requiredRoles: string[];
  roleMatch: 'any' | 'all';
  requireEmail: boolean;
  headerNames: RelyperHeaderNames;
  forwardedHeaderNames: RelyperHeaderNames | null;
  devAuth: Required<Omit<RelyperDevAuthOptions, 'enabled'>> | null;
  unauthenticatedStatus: number;
  forbiddenStatus: number;
};
