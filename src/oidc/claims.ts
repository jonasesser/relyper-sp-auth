import type { RelyperIdentity } from '../types.js';

/**
 * Maps the claims of a Relyper ID token onto the identity the application sees.
 *
 * The IdP sends tenant information under several names for backwards
 * compatibility (`tenant`, `tenant_id`, `tenant_ids`, `tenants`); this collapses
 * them into one shape so service providers do not each reinvent the reading.
 */

function asString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

export function asStringList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map((item) => asString(item)).filter(Boolean);
  }
  const single = asString(value);
  if (!single) return [];
  // Some providers send space- or comma-separated lists in a single claim.
  return single.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean);
}

function tenantIdsFrom(claims: Record<string, unknown>): string[] {
  const explicit = asStringList(claims.tenant_ids);
  if (explicit.length) return explicit;

  const tenants = claims.tenants;
  if (Array.isArray(tenants)) {
    const ids = tenants
      .map((entry) => (entry && typeof entry === 'object' ? asString((entry as Record<string, unknown>).tenantId) : ''))
      .filter(Boolean);
    if (ids.length) return ids;
  }

  const single = asString(claims.tenant_id) || asString(claims.tenant);
  return single ? [single] : [];
}

export function defaultClaimsToIdentity(claims: Record<string, unknown>): RelyperIdentity {
  const email = asString(claims.email);
  const tenantIds = tenantIdsFrom(claims);

  return {
    subject: asString(claims.sub),
    email,
    displayName: asString(claims.name) || asString(claims.preferred_username) || email || 'Relyper User',
    roles: asStringList(claims.roles),
    tenantId: tenantIds[0] ?? null,
    tenantIds,
    tenantName: asString(claims.tenant_name) || null,
    teams: asStringList(claims.teams)
  };
}
