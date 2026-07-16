import type { Hono } from "@emulators/core";
import type { AppEnv, RouteContext, ServicePlugin, Store, TokenMap, WebhookDispatcher } from "@emulators/core";
import { getAuth0Store } from "./store.js";
import type { Auth0ActionConfig } from "./entities.js";
import { DEFAULT_DB_CONNECTION, generateAuth0Id, generateUserId, nowUnix } from "./helpers.js";
import { oidcDiscoveryRoutes } from "./routes/oidc-discovery.js";
import { authorizeRoutes } from "./routes/authorize.js";
import { tokenRoutes } from "./routes/token.js";
import { dbConnectionRoutes } from "./routes/dbconnections.js";
import { userinfoRoutes } from "./routes/userinfo.js";
import { logoutRoutes } from "./routes/logout.js";
import { userRoutes } from "./routes/users.js";
import { managementRoutes } from "./routes/management.js";
import { tenantRoutes } from "./routes/tenant.js";
import { streamRoutes } from "./routes/streams.js";
import { attackProtectionRoutes } from "./routes/attack-protection-routes.js";
import { logRoutes } from "./routes/logs.js";
import { inspectorRoutes } from "./routes/inspector.js";
import { permissionRoutes } from "./routes/permissions.js";
import { actionRoutes } from "./routes/actions.js";
import { mfaRoutes } from "./routes/mfa.js";
import { passwordlessRoutes } from "./routes/passwordless.js";
import { managementExtraRoutes } from "./routes/management-extras.js";
import { protocolRoutes } from "./routes/protocols.js";
import { samlRoutes } from "./routes/saml.js";
import { wsfedRoutes } from "./routes/wsfed.js";
import { cibaRoutes } from "./routes/ciba.js";

export { getAuth0Store, type Auth0Store } from "./store.js";
export * from "./entities.js";

export interface Auth0SeedConfig {
  users?: Array<{
    user_id?: string;
    email: string;
    email_verified?: boolean;
    password?: string;
    connection?: string;
    username?: string;
    name?: string;
    nickname?: string;
    given_name?: string;
    family_name?: string;
    picture?: string;
    app_metadata?: Record<string, unknown>;
    user_metadata?: Record<string, unknown>;
    roles?: string[];
  }>;
  clients?: Array<{
    client_id: string;
    client_secret?: string;
    name: string;
    app_type?: "spa" | "native" | "regular_web" | "non_interactive";
    callbacks?: string[];
    allowed_logout_urls?: string[];
    web_origins?: string[];
    grant_types?: string[];
  }>;
  connections?: Array<{
    name: string;
    strategy?: string;
    enabled_clients?: string[];
  }>;
  resource_servers?: Array<{
    name?: string;
    identifier: string;
    scopes?: string[];
    enforce_policies?: boolean;
  }>;
  client_grants?: Array<{
    client_id: string;
    audience: string;
    scopes?: string[];
  }>;
  roles?: Array<{
    name: string;
    description?: string;
    // Permissions granted by this role, as "identifier:permission" or objects.
    permissions?: Array<{ resource_server_identifier: string; permission_name: string }>;
  }>;
  organizations?: Array<{
    name: string;
    display_name?: string;
    enabled_connections?: string[];
    members?: string[];
  }>;
  // Direct user permissions (independent of roles).
  user_permissions?: Array<{
    user: string; // email or user_id
    resource_server_identifier: string;
    permission_name: string;
  }>;
  // Extensibility: Actions (config-driven or with real JS code).
  actions?: Array<{
    name: string;
    trigger?: string;
    code?: string;
    config?: Auth0ActionConfig;
    order?: number;
  }>;
  // Legacy Rules (executed JS on login).
  rules?: Array<{
    name: string;
    script: string;
    order?: number;
    enabled?: boolean;
  }>;
  // MFA enforcement policy.
  mfa?: {
    always_on?: boolean;
    required_connections?: string[];
    required_users?: string[];
  };
  breached_passwords?: string[];
}

export function seedFromConfig(store: Store, _baseUrl: string, config: unknown): void {
  const cfg = (config ?? {}) as Auth0SeedConfig;
  const as = getAuth0Store(store);
  const now = nowUnix();

  // Always seed a default database connection so password-realm has a realm.
  if (!as.connections.findOneBy("name", DEFAULT_DB_CONNECTION)) {
    as.connections.insert({
      connection_id: `con_${generateAuth0Id().slice(0, 20)}`,
      name: DEFAULT_DB_CONNECTION,
      strategy: "auth0",
      enabled_clients: [],
      created_at_unix: now,
      updated_at_unix: now,
    });
  }

  for (const cn of cfg.connections ?? []) {
    if (as.connections.findOneBy("name", cn.name)) continue;
    as.connections.insert({
      connection_id: `con_${generateAuth0Id().slice(0, 20)}`,
      name: cn.name,
      strategy: cn.strategy ?? "auth0",
      enabled_clients: cn.enabled_clients ?? [],
      created_at_unix: now,
      updated_at_unix: now,
    });
  }

  for (const cl of cfg.clients ?? []) {
    if (as.clients.findOneBy("client_id", cl.client_id)) continue;
    const appType = cl.app_type ?? "regular_web";
    const isPublic = appType === "spa" || appType === "native";
    as.clients.insert({
      client_id: cl.client_id,
      client_secret: cl.client_secret ?? generateAuth0Id() + generateAuth0Id(),
      name: cl.name,
      description: null,
      app_type: appType,
      token_endpoint_auth_method: isPublic ? "none" : "client_secret_post",
      callbacks: cl.callbacks ?? [],
      allowed_logout_urls: cl.allowed_logout_urls ?? [],
      web_origins: cl.web_origins ?? [],
      grant_types: cl.grant_types ?? ["authorization_code", "refresh_token", "client_credentials"],
      created_at_unix: now,
      updated_at_unix: now,
    });
  }

  for (const rs of cfg.resource_servers ?? []) {
    if (as.resourceServers.findOneBy("identifier", rs.identifier)) continue;
    as.resourceServers.insert({
      resource_server_id: generateAuth0Id(),
      name: rs.name ?? rs.identifier,
      identifier: rs.identifier,
      scopes: rs.scopes ?? [],
      signing_alg: "RS256",
      enforce_policies: rs.enforce_policies ?? false,
      token_dialect: rs.enforce_policies ? "access_token_authz" : "access_token",
      created_at_unix: now,
      updated_at_unix: now,
    });
  }

  for (const grant of cfg.client_grants ?? []) {
    as.clientGrants.insert({
      grant_id: `cgr_${generateAuth0Id().slice(0, 20)}`,
      client_id: grant.client_id,
      audience: grant.audience,
      scopes: grant.scopes ?? [],
      created_at_unix: now,
      updated_at_unix: now,
    });
  }

  const roleIdByName = new Map<string, string>();
  for (const role of cfg.roles ?? []) {
    const existing = as.roles.findOneBy("name", role.name);
    let roleId: string;
    if (existing) {
      roleId = existing.role_id;
    } else {
      roleId = `rol_${generateAuth0Id().slice(0, 20)}`;
      as.roles.insert({
        role_id: roleId,
        name: role.name,
        description: role.description ?? null,
        created_at_unix: now,
        updated_at_unix: now,
      });
    }
    roleIdByName.set(role.name, roleId);
    for (const perm of role.permissions ?? []) {
      const dup = as.rolePermissions
        .findBy("role_id", roleId)
        .some(
          (rp) =>
            rp.resource_server_identifier === perm.resource_server_identifier &&
            rp.permission_name === perm.permission_name,
        );
      if (!dup) {
        as.rolePermissions.insert({
          role_id: roleId,
          resource_server_identifier: perm.resource_server_identifier,
          permission_name: perm.permission_name,
        });
      }
    }
  }

  for (const u of cfg.users ?? []) {
    const connection = u.connection ?? DEFAULT_DB_CONNECTION;
    if (as.users.all().some((existing) => existing.email === u.email && existing.connection === connection)) continue;
    const userId = u.user_id
      ? `${connection === DEFAULT_DB_CONNECTION ? "auth0" : connection}|${u.user_id}`
      : generateUserId(connection);
    as.users.insert({
      user_id: userId,
      email: u.email,
      email_verified: u.email_verified ?? false,
      password: u.password ?? null,
      connection,
      username: u.username ?? null,
      name: u.name ?? u.email,
      nickname: u.nickname ?? null,
      given_name: u.given_name ?? null,
      family_name: u.family_name ?? null,
      picture: u.picture ?? null,
      phone_number: null,
      phone_verified: false,
      blocked: false,
      user_metadata: u.user_metadata ?? {},
      app_metadata: u.app_metadata ?? {},
      last_login: null,
      logins_count: 0,
      created_at_unix: now,
      updated_at_unix: now,
    });
    for (const roleName of u.roles ?? []) {
      const roleId = roleIdByName.get(roleName);
      if (roleId) as.roleAssignments.insert({ role_id: roleId, user_id: userId });
    }
  }

  for (const org of cfg.organizations ?? []) {
    if (as.organizations.findOneBy("name", org.name)) continue;
    const orgId = `org_${generateAuth0Id().slice(0, 20)}`;
    as.organizations.insert({
      org_id: orgId,
      name: org.name,
      display_name: org.display_name ?? null,
      metadata: {},
      enabled_connections: org.enabled_connections ?? [],
      created_at_unix: now,
      updated_at_unix: now,
    });
    for (const memberEmail of org.members ?? []) {
      const user = as.users.findOneBy("email", memberEmail);
      if (user) as.orgMembers.insert({ org_id: orgId, user_id: user.user_id, roles: [] });
    }
  }

  for (const up of cfg.user_permissions ?? []) {
    const user = as.users.findOneBy("email", up.user) ?? as.users.findOneBy("user_id", up.user);
    if (!user) continue;
    const dup = as.userPermissions
      .findBy("user_id", user.user_id)
      .some(
        (p) =>
          p.resource_server_identifier === up.resource_server_identifier && p.permission_name === up.permission_name,
      );
    if (!dup) {
      as.userPermissions.insert({
        user_id: user.user_id,
        resource_server_identifier: up.resource_server_identifier,
        permission_name: up.permission_name,
      });
    }
  }

  for (const [index, action] of (cfg.actions ?? []).entries()) {
    const trigger = action.trigger ?? "post-login";
    const actionId = `act_${generateAuth0Id().slice(0, 20)}`;
    as.actions.insert({
      action_id: actionId,
      name: action.name,
      trigger,
      code: action.code ?? "",
      config: action.config ?? null,
      dependencies: [],
      secrets: [],
      deployed: true,
      created_at_unix: now,
      updated_at_unix: now,
    });
    as.actionBindings.insert({
      trigger,
      action_id: actionId,
      display_name: action.name,
      order: action.order ?? index,
    });
  }

  for (const [index, rule] of (cfg.rules ?? []).entries()) {
    as.rules.insert({
      rule_id: `rul_${generateAuth0Id().slice(0, 20)}`,
      name: rule.name,
      script: rule.script,
      order: rule.order ?? index,
      enabled: rule.enabled ?? true,
      created_at_unix: now,
      updated_at_unix: now,
    });
  }

  if (cfg.mfa) {
    store.setData("auth0.mfa.config", {
      alwaysOn: cfg.mfa.always_on ?? false,
      requiredConnections: cfg.mfa.required_connections ?? [],
      requiredUsers: cfg.mfa.required_users ?? [],
    });
  }

  if (cfg.breached_passwords && cfg.breached_passwords.length > 0) {
    const apCfg = store.getData<{ breachedPassword: { enabled: boolean; passwords: string[] } }>(
      "auth0.attackProtection.config",
    );
    if (apCfg) {
      apCfg.breachedPassword.passwords = cfg.breached_passwords;
      store.setData("auth0.attackProtection.config", apCfg);
    } else {
      store.setData("auth0.seed.breachedPasswords", cfg.breached_passwords);
    }
  }
}

function seedDefaults(store: Store, baseUrl: string): void {
  const as = getAuth0Store(store);
  if (as.users.all().length > 0) return;
  seedFromConfig(store, baseUrl, {
    users: [
      {
        email: "user@example.com",
        email_verified: true,
        password: "Password123!",
        name: "Test User",
      },
    ],
    clients: [
      {
        client_id: "auth0_emulate_client",
        client_secret: "auth0_emulate_secret",
        name: "My Auth0 App",
        app_type: "regular_web",
        callbacks: ["http://localhost:3000/api/auth/callback"],
        allowed_logout_urls: ["http://localhost:3000"],
        grant_types: ["authorization_code", "refresh_token", "client_credentials", "password"],
      },
    ],
    resource_servers: [
      {
        name: "My API",
        identifier: "https://api.example.com",
        scopes: ["read:items", "write:items"],
      },
    ],
  });
}

export const auth0Plugin: ServicePlugin = {
  name: "auth0",
  register(app: Hono<AppEnv>, store: Store, webhooks: WebhookDispatcher, baseUrl: string, tokenMap?: TokenMap): void {
    const ctx: RouteContext = { app, store, webhooks, baseUrl, tokenMap };
    // OIDC + Authentication API
    oidcDiscoveryRoutes(ctx);
    authorizeRoutes(ctx);
    tokenRoutes(ctx);
    dbConnectionRoutes(ctx);
    userinfoRoutes(ctx);
    logoutRoutes(ctx);
    passwordlessRoutes(ctx);
    mfaRoutes(ctx);
    cibaRoutes(ctx);
    // Auth protocols (PAR, dynamic registration, passkeys, SAML, WS-Fed, legacy)
    protocolRoutes(ctx);
    samlRoutes(ctx);
    wsfedRoutes(ctx);
    // Management API v2
    userRoutes(ctx);
    managementRoutes(ctx);
    permissionRoutes(ctx);
    actionRoutes(ctx);
    managementExtraRoutes(ctx);
    tenantRoutes(ctx);
    logRoutes(ctx);
    // Platform features
    streamRoutes(ctx);
    attackProtectionRoutes(ctx);
    // Inspector UI (mounted at "/")
    inspectorRoutes(ctx);
  },
  seed(store: Store, baseUrl: string): void {
    seedDefaults(store, baseUrl);
  },
};

export default auth0Plugin;
