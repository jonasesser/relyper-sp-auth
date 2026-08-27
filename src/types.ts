/** Identitaet, die der Relyper-IdP ueber das Gateway an einen Service Provider weiterreicht. */
export type RelyperIdentity = {
  /** Stabile, eindeutige Kennung des Nutzers beim IdP. Niemals die lokale Datenbank-ID. */
  subject: string;
  email: string;
  displayName: string;
  roles: string[];
};

export type RelyperAuthFailureCode = 'missing_subject' | 'missing_email' | 'missing_role';

export type RelyperAuthFailure = {
  ok: false;
  /** HTTP-Status, den der Adapter senden soll. */
  status: number;
  code: RelyperAuthFailureCode;
  message: string;
  /**
   * Rollen, die das Gateway mitgeschickt hat. Ausschliesslich fuer Logging und
   * Fehlersuche gedacht, niemals als Autorisierungsgrundlage.
   */
  presentedRoles: string[];
};

export type RelyperAuthSuccess = {
  ok: true;
  identity: RelyperIdentity;
  /** true, wenn die Identitaet aus der Dev-Auth stammt und nicht vom Gateway. */
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
 * Header-Quelle. Unterstuetzt sowohl das einfache Objekt aus Node/Fastify als
 * auch alles mit einer `get`-Methode, etwa die Headers der Fetch-API.
 */
export type RelyperHeaderSource =
  | Record<string, string | string[] | undefined>
  | { get(name: string): string | null | undefined };

export type RelyperDevAuthOptions = {
  /** Standard: true, sobald ein Objekt uebergeben wird. */
  enabled?: boolean;
  subject?: string;
  email?: string;
  displayName?: string;
  roles?: string[];
};

export type RelyperAuthOptions = {
  /** Rolle(n), die der Nutzer fuer diesen Service Provider braucht. Leer heisst: keine Rollenpruefung. */
  requiredRole?: string | string[];
  /** Bei mehreren Pflichtrollen: eine genuegt ('any', Standard) oder alle noetig ('all'). */
  roleMatch?: 'any' | 'all';
  /** Standard: true. Auf false setzen, wenn der IdP keine Mailadresse liefert. */
  requireEmail?: boolean;
  /** Abweichende Header-Namen, etwa bei einem anderen Gateway-Praefix. */
  headerNames?: Partial<RelyperHeaderNames>;
  /**
   * `x-forwarded-*` als Rueckfallebene akzeptieren. Standard: false.
   * Bewusst aus, weil diese Header von generischen Proxies stammen koennen.
   */
  acceptForwardedHeaders?: boolean | Partial<RelyperHeaderNames>;
  /**
   * Entwicklungs-Login ohne Gateway. Standard: aus.
   * Muss in Produktion aus bleiben, sonst authentifiziert sich jeder Aufrufer selbst.
   */
  devAuth?: RelyperDevAuthOptions | false;
  /** Status, wenn gar keine Identitaet ankommt. Standard: 401. */
  unauthenticatedStatus?: number;
  /** Status, wenn die Identitaet stimmt, aber die Rolle fehlt. Standard: 403. */
  forbiddenStatus?: number;
  /** Fester Text oder Funktion fuer die Fehlermeldung. */
  message?: string | ((failure: Omit<RelyperAuthFailure, 'message'>) => string);
  /** Eigene Zerlegung des Rollen-Headers, falls das Gateway kein Komma benutzt. */
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
