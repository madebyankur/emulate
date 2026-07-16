import { SignJWT } from "jose";
import type { Context } from "@emulators/core";
import type { AppEnv, AuthUser, ContentfulStatusCode, Store, TokenMap } from "@emulators/core";
import type {
  Auth0User,
  Auth0Client,
  Auth0Connection,
  Auth0Role,
  Auth0Organization,
  Auth0ResourceServer,
} from "./entities.js";
import type { Auth0Store } from "./store.js";
import { issuerFromBaseUrl, userDisplayName } from "./helpers.js";
import { keyPairPromise, KID } from "./keys.js";

// Auth0 returns errors in two shapes: the Authentication API uses
// { error, error_description } (OAuth-style); the Management API uses
// { statusCode, error, message, errorCode }. These helpers cover both.
export function oauthError(c: Context<AppEnv>, status: number, error: string, description: string): Response {
  return c.json({ error, error_description: description }, status as ContentfulStatusCode);
}

export function mgmtError(
  c: Context<AppEnv>,
  status: number,
  error: string,
  message: string,
  errorCode?: string,
): Response {
  return c.json(
    { statusCode: status, error, message, errorCode: errorCode ?? "operation_error" },
    status as ContentfulStatusCode,
  );
}

// Management API auth: the caller must present a Bearer access token that was
// minted for the Management API audience (`{baseUrl}/api/v2/`). We accept any
// token the auth middleware resolved, mirroring how the other emulators treat
// the tokenMap as the source of truth.
export function requireManagementAuth(c: Context<AppEnv>, _tokenMap?: TokenMap): AuthUser | Response {
  const authUser = c.get("authUser");
  if (!authUser) {
    return mgmtError(c, 401, "Unauthorized", "Invalid token", "unauthorized");
  }
  return authUser;
}

export async function readJsonBody(c: Context<AppEnv>): Promise<Record<string, unknown>> {
  try {
    const body = await c.req.json();
    if (body && typeof body === "object") return body as Record<string, unknown>;
    return {};
  } catch {
    return {};
  }
}

export function parsePage(c: Context<AppEnv>): { page: number; perPage: number; includeTotals: boolean } {
  const page = Math.max(Number.parseInt(c.req.query("page") ?? "0", 10) || 0, 0);
  const perPage = Math.min(Math.max(Number.parseInt(c.req.query("per_page") ?? "50", 10) || 50, 1), 100);
  const includeTotals = c.req.query("include_totals") === "true";
  return { page, perPage, includeTotals };
}

// Wrap a page of results in Auth0's list envelope. When include_totals=true,
// Auth0 returns an object keyed by the resource name; otherwise a bare array.
export function listEnvelope<T>(key: string, all: T[], page: number, perPage: number, includeTotals: boolean): unknown {
  const start = page * perPage;
  const slice = all.slice(start, start + perPage);
  if (!includeTotals) return slice;
  return {
    [key]: slice,
    start,
    limit: perPage,
    length: slice.length,
    total: all.length,
  };
}

export function userResponse(user: Auth0User): Record<string, unknown> {
  return {
    user_id: user.user_id,
    email: user.email,
    email_verified: user.email_verified,
    username: user.username ?? undefined,
    phone_number: user.phone_number ?? undefined,
    phone_verified: user.phone_verified,
    name: user.name,
    nickname: user.nickname ?? user.email,
    given_name: user.given_name ?? undefined,
    family_name: user.family_name ?? undefined,
    picture: user.picture ?? `https://s.gravatar.com/avatar/${encodeURIComponent(user.email)}`,
    blocked: user.blocked,
    identities: [
      {
        connection: user.connection,
        user_id: user.user_id.includes("|") ? user.user_id.split("|")[1] : user.user_id,
        provider: user.user_id.includes("|") ? user.user_id.split("|")[0] : "auth0",
        isSocial: false,
      },
    ],
    user_metadata: user.user_metadata,
    app_metadata: user.app_metadata,
    last_login: user.last_login ?? undefined,
    logins_count: user.logins_count,
    created_at: new Date(user.created_at_unix * 1000).toISOString(),
    updated_at: new Date(user.updated_at_unix * 1000).toISOString(),
  };
}

export function clientResponse(client: Auth0Client): Record<string, unknown> {
  return {
    client_id: client.client_id,
    client_secret: client.client_secret,
    name: client.name,
    description: client.description ?? undefined,
    app_type: client.app_type,
    token_endpoint_auth_method: client.token_endpoint_auth_method,
    callbacks: client.callbacks,
    allowed_logout_urls: client.allowed_logout_urls,
    web_origins: client.web_origins,
    grant_types: client.grant_types,
  };
}

export function connectionResponse(connection: Auth0Connection): Record<string, unknown> {
  return {
    id: connection.connection_id,
    name: connection.name,
    strategy: connection.strategy,
    enabled_clients: connection.enabled_clients,
  };
}

export function roleResponse(role: Auth0Role): Record<string, unknown> {
  return {
    id: role.role_id,
    name: role.name,
    description: role.description ?? undefined,
  };
}

export function organizationResponse(org: Auth0Organization): Record<string, unknown> {
  return {
    id: org.org_id,
    name: org.name,
    display_name: org.display_name ?? undefined,
    metadata: org.metadata,
    enabled_connections: org.enabled_connections.map((connectionId) => ({ connection_id: connectionId })),
  };
}

export function resourceServerResponse(rs: Auth0ResourceServer): Record<string, unknown> {
  return {
    id: rs.resource_server_id,
    name: rs.name,
    identifier: rs.identifier,
    scopes: rs.scopes.map((value) => ({ value, description: value })),
    signing_alg: rs.signing_alg,
    enforce_policies: rs.enforce_policies,
    token_dialect: rs.token_dialect,
  };
}

export function findUserByRef(as: Auth0Store, ref: string): Auth0User | undefined {
  const decoded = decodeURIComponent(ref);
  return as.users.findOneBy("user_id", decoded);
}

// Resolve the roles assigned to a user as role names (for id_token claims).
export function userRoleNames(as: Auth0Store, userId: string): string[] {
  return as.roleAssignments
    .findBy("user_id", userId)
    .map((assignment) => as.roles.findOneBy("role_id", assignment.role_id)?.name)
    .filter((name): name is string => Boolean(name));
}

// Resolve a user's effective permissions for a given API (resource server
// identifier): the union of permissions from all assigned roles plus any
// permissions granted directly to the user, scoped to that audience.
export function userPermissionsForAudience(as: Auth0Store, userId: string, audience: string): string[] {
  const perms = new Set<string>();
  const roleIds = as.roleAssignments.findBy("user_id", userId).map((a) => a.role_id);
  for (const roleId of roleIds) {
    for (const rp of as.rolePermissions.findBy("role_id", roleId)) {
      if (rp.resource_server_identifier === audience) perms.add(rp.permission_name);
    }
  }
  for (const up of as.userPermissions.findBy("user_id", userId)) {
    if (up.resource_server_identifier === audience) perms.add(up.permission_name);
  }
  return [...perms];
}

// --- OAuth ephemeral token stores (kept in Store.getData, like okta) ---

export interface StoredAccessToken {
  clientId: string;
  audience: string;
  scope: string;
  userId: string | null;
  orgId: string | null;
  issuedAt: number;
  expiresAt: number;
}

export interface StoredRefreshToken {
  clientId: string;
  audience: string;
  scope: string;
  userId: string;
  orgId: string | null;
}

export interface PendingCode {
  userId: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  audience: string;
  nonce: string | null;
  orgId: string | null;
  codeChallenge: string | null;
  codeChallengeMethod: string | null;
  createdAt: number;
}

export interface PendingDeviceCode {
  deviceCode: string;
  clientId: string;
  scope: string;
  audience: string;
  approvedUserId: string | null;
  expiresAt: number;
}

function getMap<V>(store: Store, key: string): Map<string, V> {
  let map = store.getData<Map<string, V>>(key);
  if (!map) {
    map = new Map<string, V>();
    store.setData(key, map);
  }
  return map;
}

export const getPendingCodes = (store: Store) => getMap<PendingCode>(store, "auth0.oauth.pendingCodes");
export const getAccessTokens = (store: Store) => getMap<StoredAccessToken>(store, "auth0.oauth.accessTokens");
export const getRefreshTokens = (store: Store) => getMap<StoredRefreshToken>(store, "auth0.oauth.refreshTokens");
export const getDeviceCodes = (store: Store) => getMap<PendingDeviceCode>(store, "auth0.oauth.deviceCodes");

// Sign an Auth0-style id_token (OIDC). Audience is the client_id.
export async function signIdToken(
  baseUrl: string,
  user: Auth0User,
  clientId: string,
  nonce: string | null,
  extraClaims: Record<string, unknown> = {},
): Promise<string> {
  const { privateKey } = await keyPairPromise;
  const now = Math.floor(Date.now() / 1000);
  const claims: Record<string, unknown> = {
    nickname: user.nickname ?? user.email,
    name: userDisplayName(user),
    email: user.email,
    email_verified: user.email_verified,
    picture: user.picture ?? undefined,
    ...extraClaims,
  };
  if (nonce) claims.nonce = nonce;
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: KID, typ: "JWT" })
    .setIssuer(issuerFromBaseUrl(baseUrl))
    .setSubject(user.user_id)
    .setAudience(clientId)
    .setIssuedAt(now)
    .setExpirationTime("1h")
    .sign(privateKey);
}

// Sign an Auth0-style access token (JWT). Audience is the API identifier.
// Auth0 access tokens carry azp (client), scope, and (for users) the subject.
export interface AccessTokenOptions {
  subject: string | null;
  orgId?: string | null;
  orgName?: string | null;
  // Emitted only when the target API has RBAC enabled (enforce_policies).
  permissions?: string[];
  // Extra claims contributed by Actions (custom-claim namespacing).
  extraClaims?: Record<string, unknown>;
  gty?: string;
}

export async function signAccessToken(
  baseUrl: string,
  audience: string,
  clientId: string,
  scope: string,
  opts: AccessTokenOptions,
): Promise<string> {
  const { privateKey } = await keyPairPromise;
  const now = Math.floor(Date.now() / 1000);
  const claims: Record<string, unknown> = {
    azp: clientId,
    scope,
    gty: opts.gty ?? (opts.subject ? "password" : "client-credentials"),
  };
  if (opts.orgId) claims.org_id = opts.orgId;
  if (opts.orgName) claims.org_name = opts.orgName;
  if (opts.permissions && opts.permissions.length > 0) claims.permissions = opts.permissions;
  if (opts.extraClaims) Object.assign(claims, opts.extraClaims);
  const builder = new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: KID, typ: "JWT" })
    .setIssuer(issuerFromBaseUrl(baseUrl))
    .setAudience(audience)
    .setIssuedAt(now)
    .setExpirationTime("1d");
  if (opts.subject) builder.setSubject(opts.subject);
  else builder.setSubject(`${clientId}@clients`);
  return builder.sign(privateKey);
}
