import type { RouteContext } from "@emulators/core";
import { getAuth0Store } from "../store.js";
import {
  clientResponse,
  connectionResponse,
  findUserByRef,
  listEnvelope,
  mgmtError,
  organizationResponse,
  parsePage,
  readJsonBody,
  requireManagementAuth,
  resourceServerResponse,
  roleResponse,
  userResponse,
} from "../route-helpers.js";
import { generateAuth0Id, nowUnix } from "../helpers.js";
import type { Auth0AppType } from "../entities.js";

// Management API v2 — clients, connections, roles, organizations, resource
// servers, client grants, and email-verification tickets.
export function managementRoutes(ctx: RouteContext): void {
  clientRoutes(ctx);
  connectionRoutes(ctx);
  roleRoutes(ctx);
  organizationRoutes(ctx);
  resourceServerRoutes(ctx);
  clientGrantRoutes(ctx);
  ticketRoutes(ctx);
}

function clientRoutes({ app, store, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  app.get("/api/v2/clients", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const { page, perPage, includeTotals } = parsePage(c);
    return c.json(listEnvelope("clients", as.clients.all().map(clientResponse), page, perPage, includeTotals));
  });

  app.post("/api/v2/clients", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonBody(c);
    const name = typeof body.name === "string" ? body.name : "";
    if (!name) return mgmtError(c, 400, "Bad Request", "The 'name' field is required.", "invalid_body");

    const appType = (typeof body.app_type === "string" ? body.app_type : "regular_web") as Auth0AppType;
    const isPublic = appType === "spa" || appType === "native";
    const now = nowUnix();
    const created = as.clients.insert({
      client_id: typeof body.client_id === "string" ? body.client_id : generateAuth0Id(),
      client_secret:
        typeof body.client_secret === "string" ? body.client_secret : generateAuth0Id() + generateAuth0Id(),
      name,
      description: typeof body.description === "string" ? body.description : null,
      app_type: appType,
      token_endpoint_auth_method: isPublic ? "none" : "client_secret_post",
      callbacks: toStringArray(body.callbacks),
      allowed_logout_urls: toStringArray(body.allowed_logout_urls),
      web_origins: toStringArray(body.web_origins),
      grant_types: toStringArray(body.grant_types).length
        ? toStringArray(body.grant_types)
        : ["authorization_code", "refresh_token"],
      created_at_unix: now,
      updated_at_unix: now,
    });
    return c.json(clientResponse(created), 201);
  });

  app.get("/api/v2/clients/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const client = as.clients.findOneBy("client_id", c.req.param("id"));
    if (!client) return mgmtError(c, 404, "Not Found", "The client does not exist.", "inexistent_client");
    return c.json(clientResponse(client));
  });

  app.patch("/api/v2/clients/:id", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const client = as.clients.findOneBy("client_id", c.req.param("id"));
    if (!client) return mgmtError(c, 404, "Not Found", "The client does not exist.", "inexistent_client");
    const body = await readJsonBody(c);
    const updates: Record<string, unknown> = { updated_at_unix: nowUnix() };
    if (typeof body.name === "string") updates.name = body.name;
    if (typeof body.description === "string") updates.description = body.description;
    if ("callbacks" in body) updates.callbacks = toStringArray(body.callbacks);
    if ("allowed_logout_urls" in body) updates.allowed_logout_urls = toStringArray(body.allowed_logout_urls);
    if ("web_origins" in body) updates.web_origins = toStringArray(body.web_origins);
    const updated = as.clients.update(client.id, updates);
    return c.json(clientResponse(updated ?? client));
  });

  app.delete("/api/v2/clients/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const client = as.clients.findOneBy("client_id", c.req.param("id"));
    if (client) as.clients.delete(client.id);
    return new Response(null, { status: 204 });
  });
}

function connectionRoutes({ app, store, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  app.get("/api/v2/connections", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const { page, perPage, includeTotals } = parsePage(c);
    return c.json(
      listEnvelope("connections", as.connections.all().map(connectionResponse), page, perPage, includeTotals),
    );
  });

  app.post("/api/v2/connections", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonBody(c);
    const name = typeof body.name === "string" ? body.name : "";
    if (!name) return mgmtError(c, 400, "Bad Request", "The 'name' field is required.", "invalid_body");
    const now = nowUnix();
    const created = as.connections.insert({
      connection_id: `con_${generateAuth0Id().slice(0, 20)}`,
      name,
      strategy: typeof body.strategy === "string" ? body.strategy : "auth0",
      enabled_clients: toStringArray(body.enabled_clients),
      created_at_unix: now,
      updated_at_unix: now,
    });
    return c.json(connectionResponse(created), 201);
  });

  app.get("/api/v2/connections/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const connection = as.connections.findOneBy("connection_id", c.req.param("id"));
    if (!connection) return mgmtError(c, 404, "Not Found", "The connection does not exist.", "inexistent_connection");
    return c.json(connectionResponse(connection));
  });

  app.patch("/api/v2/connections/:id", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const connection = as.connections.findOneBy("connection_id", c.req.param("id"));
    if (!connection) return mgmtError(c, 404, "Not Found", "The connection does not exist.", "inexistent_connection");
    const body = await readJsonBody(c);
    const updates: Record<string, unknown> = { updated_at_unix: nowUnix() };
    if (typeof body.name === "string") updates.name = body.name;
    if ("enabled_clients" in body) updates.enabled_clients = toStringArray(body.enabled_clients);
    const updated = as.connections.update(connection.id, updates);
    return c.json(connectionResponse(updated ?? connection));
  });

  app.delete("/api/v2/connections/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const connection = as.connections.findOneBy("connection_id", c.req.param("id"));
    if (connection) as.connections.delete(connection.id);
    return new Response(null, { status: 204 });
  });
}

function roleRoutes({ app, store, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  app.get("/api/v2/roles", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const { page, perPage, includeTotals } = parsePage(c);
    return c.json(listEnvelope("roles", as.roles.all().map(roleResponse), page, perPage, includeTotals));
  });

  app.post("/api/v2/roles", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonBody(c);
    const name = typeof body.name === "string" ? body.name : "";
    if (!name) return mgmtError(c, 400, "Bad Request", "The 'name' field is required.", "invalid_body");
    const now = nowUnix();
    const created = as.roles.insert({
      role_id: `rol_${generateAuth0Id().slice(0, 20)}`,
      name,
      description: typeof body.description === "string" ? body.description : null,
      created_at_unix: now,
      updated_at_unix: now,
    });
    return c.json(roleResponse(created), 201);
  });

  app.get("/api/v2/roles/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const role = as.roles.findOneBy("role_id", c.req.param("id"));
    if (!role) return mgmtError(c, 404, "Not Found", "The role does not exist.", "inexistent_role");
    return c.json(roleResponse(role));
  });

  app.delete("/api/v2/roles/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const role = as.roles.findOneBy("role_id", c.req.param("id"));
    if (role) {
      for (const assignment of as.roleAssignments.findBy("role_id", role.role_id)) {
        as.roleAssignments.delete(assignment.id);
      }
      as.roles.delete(role.id);
    }
    return new Response(null, { status: 204 });
  });

  // Users assigned to a role.
  app.get("/api/v2/roles/:id/users", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const role = as.roles.findOneBy("role_id", c.req.param("id"));
    if (!role) return mgmtError(c, 404, "Not Found", "The role does not exist.", "inexistent_role");
    const users = as.roleAssignments
      .findBy("role_id", role.role_id)
      .map((a) => as.users.findOneBy("user_id", a.user_id))
      .filter((u): u is NonNullable<typeof u> => Boolean(u));
    const { page, perPage, includeTotals } = parsePage(c);
    return c.json(listEnvelope("users", users.map(userResponse), page, perPage, includeTotals));
  });
}

function organizationRoutes({ app, store, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  app.get("/api/v2/organizations", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const { page, perPage, includeTotals } = parsePage(c);
    return c.json(
      listEnvelope("organizations", as.organizations.all().map(organizationResponse), page, perPage, includeTotals),
    );
  });

  app.post("/api/v2/organizations", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonBody(c);
    const name = typeof body.name === "string" ? body.name : "";
    if (!name) return mgmtError(c, 400, "Bad Request", "The 'name' field is required.", "invalid_body");
    if (as.organizations.findOneBy("name", name)) {
      return mgmtError(c, 409, "Conflict", "An organization with this name already exists.", "duplicate_organization");
    }
    const now = nowUnix();
    const created = as.organizations.insert({
      org_id: `org_${generateAuth0Id().slice(0, 20)}`,
      name,
      display_name: typeof body.display_name === "string" ? body.display_name : null,
      metadata: (body.metadata as Record<string, unknown>) ?? {},
      enabled_connections: toStringArray(body.enabled_connections),
      created_at_unix: now,
      updated_at_unix: now,
    });
    return c.json(organizationResponse(created), 201);
  });

  app.get("/api/v2/organizations/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const org = resolveOrg(as, c.req.param("id"));
    if (!org) return mgmtError(c, 404, "Not Found", "The organization does not exist.", "inexistent_organization");
    return c.json(organizationResponse(org));
  });

  app.delete("/api/v2/organizations/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const org = resolveOrg(as, c.req.param("id"));
    if (org) {
      for (const member of as.orgMembers.findBy("org_id", org.org_id)) as.orgMembers.delete(member.id);
      as.organizations.delete(org.id);
    }
    return new Response(null, { status: 204 });
  });

  // Organization members.
  app.get("/api/v2/organizations/:id/members", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const org = resolveOrg(as, c.req.param("id"));
    if (!org) return mgmtError(c, 404, "Not Found", "The organization does not exist.", "inexistent_organization");
    const members = as.orgMembers
      .findBy("org_id", org.org_id)
      .map((m) => as.users.findOneBy("user_id", m.user_id))
      .filter((u): u is NonNullable<typeof u> => Boolean(u));
    const { page, perPage, includeTotals } = parsePage(c);
    return c.json(listEnvelope("members", members.map(userResponse), page, perPage, includeTotals));
  });

  app.post("/api/v2/organizations/:id/members", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const org = resolveOrg(as, c.req.param("id"));
    if (!org) return mgmtError(c, 404, "Not Found", "The organization does not exist.", "inexistent_organization");
    const body = await readJsonBody(c);
    const members = Array.isArray(body.members)
      ? (body.members as unknown[]).filter((m): m is string => typeof m === "string")
      : [];
    for (const userId of members) {
      if (!as.users.findOneBy("user_id", userId)) continue;
      const exists = as.orgMembers.findBy("org_id", org.org_id).some((m) => m.user_id === userId);
      if (!exists) as.orgMembers.insert({ org_id: org.org_id, user_id: userId, roles: [] });
    }
    return new Response(null, { status: 204 });
  });

  app.delete("/api/v2/organizations/:id/members", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const org = resolveOrg(as, c.req.param("id"));
    if (!org) return mgmtError(c, 404, "Not Found", "The organization does not exist.", "inexistent_organization");
    const body = await readJsonBody(c);
    const members = Array.isArray(body.members)
      ? (body.members as unknown[]).filter((m): m is string => typeof m === "string")
      : [];
    for (const userId of members) {
      const membership = as.orgMembers.findBy("org_id", org.org_id).find((m) => m.user_id === userId);
      if (membership) as.orgMembers.delete(membership.id);
    }
    return new Response(null, { status: 204 });
  });

  // Member roles within an organization.
  app.get("/api/v2/organizations/:id/members/:uid/roles", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const org = resolveOrg(as, c.req.param("id"));
    if (!org) return mgmtError(c, 404, "Not Found", "The organization does not exist.", "inexistent_organization");
    const membership = as.orgMembers.findBy("org_id", org.org_id).find((m) => m.user_id === c.req.param("uid"));
    const roles = (membership?.roles ?? [])
      .map((roleId) => as.roles.findOneBy("role_id", roleId))
      .filter((r): r is NonNullable<typeof r> => Boolean(r))
      .map(roleResponse);
    return c.json(roles);
  });

  app.post("/api/v2/organizations/:id/members/:uid/roles", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const org = resolveOrg(as, c.req.param("id"));
    if (!org) return mgmtError(c, 404, "Not Found", "The organization does not exist.", "inexistent_organization");
    const membership = as.orgMembers.findBy("org_id", org.org_id).find((m) => m.user_id === c.req.param("uid"));
    if (!membership) return mgmtError(c, 404, "Not Found", "The member does not exist.", "inexistent_member");
    const body = await readJsonBody(c);
    const roleIds = toStringArray(body.roles);
    const next = new Set([...membership.roles, ...roleIds]);
    as.orgMembers.update(membership.id, { roles: [...next] });
    return new Response(null, { status: 204 });
  });

  app.delete("/api/v2/organizations/:id/members/:uid/roles", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const org = resolveOrg(as, c.req.param("id"));
    if (!org) return mgmtError(c, 404, "Not Found", "The organization does not exist.", "inexistent_organization");
    const membership = as.orgMembers.findBy("org_id", org.org_id).find((m) => m.user_id === c.req.param("uid"));
    if (!membership) return new Response(null, { status: 204 });
    const body = await readJsonBody(c);
    const roleIds = new Set(toStringArray(body.roles));
    as.orgMembers.update(membership.id, { roles: membership.roles.filter((r) => !roleIds.has(r)) });
    return new Response(null, { status: 204 });
  });

  // Enabled connections for an organization.
  app.get("/api/v2/organizations/:id/enabled_connections", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const org = resolveOrg(as, c.req.param("id"));
    if (!org) return mgmtError(c, 404, "Not Found", "The organization does not exist.", "inexistent_organization");
    return c.json(
      org.enabled_connections.map((connectionId) => ({
        connection_id: connectionId,
        assign_membership_on_login: false,
        connection: { name: as.connections.findOneBy("connection_id", connectionId)?.name ?? connectionId },
      })),
    );
  });

  app.post("/api/v2/organizations/:id/enabled_connections", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const org = resolveOrg(as, c.req.param("id"));
    if (!org) return mgmtError(c, 404, "Not Found", "The organization does not exist.", "inexistent_organization");
    const body = await readJsonBody(c);
    const connectionId = typeof body.connection_id === "string" ? body.connection_id : "";
    if (connectionId && !org.enabled_connections.includes(connectionId)) {
      as.organizations.update(org.id, { enabled_connections: [...org.enabled_connections, connectionId] });
    }
    return c.json({ connection_id: connectionId }, 201);
  });

  app.delete("/api/v2/organizations/:id/enabled_connections/:cid", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const org = resolveOrg(as, c.req.param("id"));
    if (!org) return new Response(null, { status: 204 });
    as.organizations.update(org.id, {
      enabled_connections: org.enabled_connections.filter((cid) => cid !== c.req.param("cid")),
    });
    return new Response(null, { status: 204 });
  });

  // Organization invitations (stored as a config blob list per org).
  app.get("/api/v2/organizations/:id/invitations", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const org = resolveOrg(as, c.req.param("id"));
    if (!org) return mgmtError(c, 404, "Not Found", "The organization does not exist.", "inexistent_organization");
    return c.json(store.getData<unknown[]>(`auth0.org_invitations.${org.org_id}`) ?? []);
  });

  app.post("/api/v2/organizations/:id/invitations", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const org = resolveOrg(as, c.req.param("id"));
    if (!org) return mgmtError(c, 404, "Not Found", "The organization does not exist.", "inexistent_organization");
    const body = await readJsonBody(c);
    const key = `auth0.org_invitations.${org.org_id}`;
    const list = store.getData<Record<string, unknown>[]>(key) ?? [];
    const invitation = {
      id: `uinv_${generateAuth0Id().slice(0, 20)}`,
      organization_id: org.org_id,
      inviter: body.inviter ?? { name: "Emulator" },
      invitee: body.invitee ?? {},
      roles: toStringArray(body.roles),
      created_at: new Date(nowUnix() * 1000).toISOString(),
    };
    list.push(invitation);
    store.setData(key, list);
    return c.json(invitation, 201);
  });

  // Organization-scoped client grants.
  app.get("/api/v2/organizations/:id/client-grants", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const org = resolveOrg(as, c.req.param("id"));
    if (!org) return mgmtError(c, 404, "Not Found", "The organization does not exist.", "inexistent_organization");
    return c.json(store.getData<unknown[]>(`auth0.org_client_grants.${org.org_id}`) ?? []);
  });

  app.post("/api/v2/organizations/:id/client-grants", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const org = resolveOrg(as, c.req.param("id"));
    if (!org) return mgmtError(c, 404, "Not Found", "The organization does not exist.", "inexistent_organization");
    const body = await readJsonBody(c);
    const key = `auth0.org_client_grants.${org.org_id}`;
    const list = store.getData<Record<string, unknown>[]>(key) ?? [];
    const grant = { grant_id: typeof body.grant_id === "string" ? body.grant_id : generateAuth0Id() };
    list.push(grant);
    store.setData(key, list);
    return c.json(grant, 201);
  });
}

function resourceServerRoutes({ app, store, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  app.get("/api/v2/resource-servers", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const { page, perPage, includeTotals } = parsePage(c);
    return c.json(
      listEnvelope(
        "resource_servers",
        as.resourceServers.all().map(resourceServerResponse),
        page,
        perPage,
        includeTotals,
      ),
    );
  });

  app.post("/api/v2/resource-servers", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonBody(c);
    const identifier = typeof body.identifier === "string" ? body.identifier : "";
    if (!identifier) return mgmtError(c, 400, "Bad Request", "The 'identifier' field is required.", "invalid_body");
    if (as.resourceServers.findOneBy("identifier", identifier)) {
      return mgmtError(
        c,
        409,
        "Conflict",
        "A resource server with this identifier already exists.",
        "duplicate_resource_server",
      );
    }
    const scopes = Array.isArray(body.scopes)
      ? (body.scopes as unknown[]).map((s) =>
          s && typeof s === "object" && "value" in s ? String((s as { value: unknown }).value) : String(s),
        )
      : [];
    const now = nowUnix();
    const dialect = body.token_dialect === "access_token_authz" ? "access_token_authz" : "access_token";
    const created = as.resourceServers.insert({
      resource_server_id: generateAuth0Id(),
      name: typeof body.name === "string" ? body.name : identifier,
      identifier,
      scopes,
      signing_alg: "RS256",
      enforce_policies: body.enforce_policies === true,
      token_dialect: dialect,
      created_at_unix: now,
      updated_at_unix: now,
    });
    return c.json(resourceServerResponse(created), 201);
  });

  app.patch("/api/v2/resource-servers/:id", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const id = decodeURIComponent(c.req.param("id"));
    const rs = as.resourceServers.findOneBy("resource_server_id", id) ?? as.resourceServers.findOneBy("identifier", id);
    if (!rs) return mgmtError(c, 404, "Not Found", "The resource server does not exist.", "inexistent_resource_server");
    const body = await readJsonBody(c);
    const updates: Record<string, unknown> = { updated_at_unix: nowUnix() };
    if (typeof body.name === "string") updates.name = body.name;
    if (Array.isArray(body.scopes)) {
      updates.scopes = (body.scopes as unknown[]).map((s) =>
        s && typeof s === "object" && "value" in s ? String((s as { value: unknown }).value) : String(s),
      );
    }
    if (typeof body.enforce_policies === "boolean") updates.enforce_policies = body.enforce_policies;
    if (body.token_dialect === "access_token" || body.token_dialect === "access_token_authz") {
      updates.token_dialect = body.token_dialect;
    }
    const updated = as.resourceServers.update(rs.id, updates);
    return c.json(resourceServerResponse(updated ?? rs));
  });

  app.get("/api/v2/resource-servers/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const id = decodeURIComponent(c.req.param("id"));
    const rs = as.resourceServers.findOneBy("resource_server_id", id) ?? as.resourceServers.findOneBy("identifier", id);
    if (!rs) return mgmtError(c, 404, "Not Found", "The resource server does not exist.", "inexistent_resource_server");
    return c.json(resourceServerResponse(rs));
  });

  app.delete("/api/v2/resource-servers/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const id = decodeURIComponent(c.req.param("id"));
    const rs = as.resourceServers.findOneBy("resource_server_id", id) ?? as.resourceServers.findOneBy("identifier", id);
    if (rs) as.resourceServers.delete(rs.id);
    return new Response(null, { status: 204 });
  });
}

function clientGrantRoutes({ app, store, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  app.get("/api/v2/client-grants", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const { page, perPage, includeTotals } = parsePage(c);
    const grants = as.clientGrants.all().map((g) => ({
      id: g.grant_id,
      client_id: g.client_id,
      audience: g.audience,
      scope: g.scopes,
    }));
    return c.json(listEnvelope("client_grants", grants, page, perPage, includeTotals));
  });

  app.post("/api/v2/client-grants", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonBody(c);
    const clientId = typeof body.client_id === "string" ? body.client_id : "";
    const audience = typeof body.audience === "string" ? body.audience : "";
    if (!clientId || !audience) {
      return mgmtError(c, 400, "Bad Request", "The 'client_id' and 'audience' fields are required.", "invalid_body");
    }
    const now = nowUnix();
    const created = as.clientGrants.insert({
      grant_id: `cgr_${generateAuth0Id().slice(0, 20)}`,
      client_id: clientId,
      audience,
      scopes: toStringArray(body.scope),
      created_at_unix: now,
      updated_at_unix: now,
    });
    return c.json({ id: created.grant_id, client_id: clientId, audience, scope: created.scopes }, 201);
  });

  app.delete("/api/v2/client-grants/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const grant = as.clientGrants.findOneBy("grant_id", c.req.param("id"));
    if (grant) as.clientGrants.delete(grant.id);
    return new Response(null, { status: 204 });
  });
}

function ticketRoutes({ app, store, baseUrl, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  // Create an email-verification ticket. Returns a consumable URL.
  app.post("/api/v2/tickets/email-verification", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonBody(c);
    const userId = typeof body.user_id === "string" ? body.user_id : "";
    const user = findUserByRef(as, userId);
    if (!user) return mgmtError(c, 400, "Bad Request", "The user does not exist.", "inexistent_user");

    const ticketId = generateAuth0Id();
    as.tickets.insert({
      ticket_id: ticketId,
      user_id: user.user_id,
      kind: "email_verification",
      consumed: false,
      created_at_unix: nowUnix(),
    });
    return c.json({ ticket: `${baseUrl}/u/email-verification?ticket=${ticketId}` }, 201);
  });

  app.post("/api/v2/tickets/password-change", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonBody(c);
    const userId = typeof body.user_id === "string" ? body.user_id : "";
    const user = findUserByRef(as, userId);
    if (!user) return mgmtError(c, 400, "Bad Request", "The user does not exist.", "inexistent_user");
    const ticketId = generateAuth0Id();
    as.tickets.insert({
      ticket_id: ticketId,
      user_id: user.user_id,
      kind: "password_change",
      consumed: false,
      created_at_unix: nowUnix(),
    });
    return c.json({ ticket: `${baseUrl}/u/reset-password?ticket=${ticketId}` }, 201);
  });

  // Consume an email-verification ticket (marks the user verified).
  app.get("/u/email-verification", (c) => {
    const ticketId = c.req.query("ticket") ?? "";
    const ticket = as.tickets.findOneBy("ticket_id", ticketId);
    if (!ticket || ticket.consumed || ticket.kind !== "email_verification") {
      return c.text("This ticket is invalid or has already been used.", 400);
    }
    const user = as.users.findOneBy("user_id", ticket.user_id);
    if (user) as.users.update(user.id, { email_verified: true, updated_at_unix: nowUnix() });
    as.tickets.update(ticket.id, { consumed: true });
    return c.text("Your email has been verified.");
  });

  // Consume a password-change ticket. Accepts ?ticket= and optional
  // ?password= to set the new password (emulator convenience).
  app.get("/u/reset-password", (c) => {
    const ticketId = c.req.query("ticket") ?? "";
    const newPassword = c.req.query("password");
    const ticket = as.tickets.findOneBy("ticket_id", ticketId);
    if (!ticket || ticket.consumed || ticket.kind !== "password_change") {
      return c.text("This ticket is invalid or has already been used.", 400);
    }
    const user = as.users.findOneBy("user_id", ticket.user_id);
    if (user && typeof newPassword === "string" && newPassword.length > 0) {
      as.users.update(user.id, { password: newPassword, updated_at_unix: nowUnix() });
    }
    as.tickets.update(ticket.id, { consumed: true });
    return c.text("Your password has been reset.");
  });
}

function resolveOrg(as: ReturnType<typeof getAuth0Store>, ref: string) {
  return as.organizations.findOneBy("org_id", ref) ?? as.organizations.findOneBy("name", ref);
}

function toStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is string => typeof v === "string");
}
