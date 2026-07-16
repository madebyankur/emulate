import type { RouteContext } from "@emulators/core";
import { getAuth0Store } from "../store.js";
import { findUserByRef, mgmtError, readJsonBody, requireManagementAuth } from "../route-helpers.js";

// RBAC permission sub-resources, identity linking, and MFA enrollment listing
// for the Management API. These complete the RBAC + account picture that the
// token layer (issueUserTokens) reads from.
export function permissionRoutes(ctx: RouteContext): void {
  userPermissionRoutes(ctx);
  rolePermissionRoutes(ctx);
  identityRoutes(ctx);
  enrollmentRoutes(ctx);
}

interface PermissionInput {
  resource_server_identifier: string;
  permission_name: string;
}

function parsePermissions(body: Record<string, unknown>): PermissionInput[] {
  if (!Array.isArray(body.permissions)) return [];
  return (body.permissions as unknown[])
    .map((p) => {
      if (!p || typeof p !== "object") return null;
      const obj = p as Record<string, unknown>;
      const id = obj.resource_server_identifier;
      const name = obj.permission_name;
      if (typeof id !== "string" || typeof name !== "string") return null;
      return { resource_server_identifier: id, permission_name: name };
    })
    .filter((p): p is PermissionInput => p !== null);
}

function permissionResponse(as: ReturnType<typeof getAuth0Store>, identifier: string, name: string) {
  const rs = as.resourceServers.findOneBy("identifier", identifier);
  return {
    resource_server_identifier: identifier,
    resource_server_name: rs?.name ?? identifier,
    permission_name: name,
    description: name,
  };
}

function userPermissionRoutes({ app, store, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  app.get("/api/v2/users/:id/permissions", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(as, c.req.param("id"));
    if (!user) return mgmtError(c, 404, "Not Found", "The user does not exist.", "inexistent_user");
    return c.json(
      as.userPermissions
        .findBy("user_id", user.user_id)
        .map((p) => permissionResponse(as, p.resource_server_identifier, p.permission_name)),
    );
  });

  app.post("/api/v2/users/:id/permissions", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(as, c.req.param("id"));
    if (!user) return mgmtError(c, 404, "Not Found", "The user does not exist.", "inexistent_user");
    const body = await readJsonBody(c);
    for (const perm of parsePermissions(body)) {
      const dup = as.userPermissions
        .findBy("user_id", user.user_id)
        .some(
          (p) =>
            p.resource_server_identifier === perm.resource_server_identifier &&
            p.permission_name === perm.permission_name,
        );
      if (!dup) {
        as.userPermissions.insert({
          user_id: user.user_id,
          resource_server_identifier: perm.resource_server_identifier,
          permission_name: perm.permission_name,
        });
      }
    }
    return new Response(null, { status: 201 });
  });

  app.delete("/api/v2/users/:id/permissions", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(as, c.req.param("id"));
    if (!user) return mgmtError(c, 404, "Not Found", "The user does not exist.", "inexistent_user");
    const body = await readJsonBody(c);
    for (const perm of parsePermissions(body)) {
      const match = as.userPermissions
        .findBy("user_id", user.user_id)
        .find(
          (p) =>
            p.resource_server_identifier === perm.resource_server_identifier &&
            p.permission_name === perm.permission_name,
        );
      if (match) as.userPermissions.delete(match.id);
    }
    return new Response(null, { status: 204 });
  });
}

function rolePermissionRoutes({ app, store, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  app.get("/api/v2/roles/:id/permissions", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const role = as.roles.findOneBy("role_id", c.req.param("id"));
    if (!role) return mgmtError(c, 404, "Not Found", "The role does not exist.", "inexistent_role");
    return c.json(
      as.rolePermissions
        .findBy("role_id", role.role_id)
        .map((p) => permissionResponse(as, p.resource_server_identifier, p.permission_name)),
    );
  });

  app.post("/api/v2/roles/:id/permissions", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const role = as.roles.findOneBy("role_id", c.req.param("id"));
    if (!role) return mgmtError(c, 404, "Not Found", "The role does not exist.", "inexistent_role");
    const body = await readJsonBody(c);
    for (const perm of parsePermissions(body)) {
      const dup = as.rolePermissions
        .findBy("role_id", role.role_id)
        .some(
          (p) =>
            p.resource_server_identifier === perm.resource_server_identifier &&
            p.permission_name === perm.permission_name,
        );
      if (!dup) {
        as.rolePermissions.insert({
          role_id: role.role_id,
          resource_server_identifier: perm.resource_server_identifier,
          permission_name: perm.permission_name,
        });
      }
    }
    return new Response(null, { status: 201 });
  });

  app.delete("/api/v2/roles/:id/permissions", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const role = as.roles.findOneBy("role_id", c.req.param("id"));
    if (!role) return mgmtError(c, 404, "Not Found", "The role does not exist.", "inexistent_role");
    const body = await readJsonBody(c);
    for (const perm of parsePermissions(body)) {
      const match = as.rolePermissions
        .findBy("role_id", role.role_id)
        .find(
          (p) =>
            p.resource_server_identifier === perm.resource_server_identifier &&
            p.permission_name === perm.permission_name,
        );
      if (match) as.rolePermissions.delete(match.id);
    }
    return new Response(null, { status: 204 });
  });
}

function identityRoutes({ app, store, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  // Link a secondary identity onto the primary user.
  app.post("/api/v2/users/:id/identities", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(as, c.req.param("id"));
    if (!user) return mgmtError(c, 404, "Not Found", "The user does not exist.", "inexistent_user");
    const body = await readJsonBody(c);

    // Auth0 accepts either a secondary user's link_with token / user_id, or an
    // explicit provider + connection + user_id. We model the explicit form and
    // also support linking an existing secondary user by user_id.
    let provider = typeof body.provider === "string" ? body.provider : "";
    let connection = typeof body.connection === "string" ? body.connection : "";
    let identityUserId = "";
    const secondaryRef = typeof body.link_with === "string" ? body.link_with : (body.user_id as string | undefined);
    if (typeof secondaryRef === "string" && secondaryRef.includes("|")) {
      provider = provider || secondaryRef.split("|")[0];
      identityUserId = secondaryRef.split("|")[1] ?? secondaryRef;
      const secondary = as.users.findOneBy("user_id", secondaryRef);
      if (secondary) {
        connection = connection || secondary.connection;
        // Auth0 deletes the secondary user when linking.
        as.users.delete(secondary.id);
      }
    }
    if (!provider) return mgmtError(c, 400, "Bad Request", "A provider or link_with is required.", "invalid_body");

    as.userIdentities.insert({
      user_id: user.user_id,
      provider,
      connection: connection || provider,
      identity_user_id: identityUserId || provider,
      is_social: body.isSocial === true,
      profile_data: {},
    });
    return c.json(identitiesArray(as, user.user_id, user.connection, user.user_id));
  });

  app.delete("/api/v2/users/:id/identities/:provider/:user_id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(as, c.req.param("id"));
    if (!user) return mgmtError(c, 404, "Not Found", "The user does not exist.", "inexistent_user");
    const provider = c.req.param("provider");
    const secondaryId = c.req.param("user_id");
    const match = as.userIdentities
      .findBy("user_id", user.user_id)
      .find((i) => i.provider === provider && i.identity_user_id === secondaryId);
    if (match) as.userIdentities.delete(match.id);
    return c.json(identitiesArray(as, user.user_id, user.connection, user.user_id));
  });

  // List the organizations a user belongs to.
  app.get("/api/v2/users/:id/organizations", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(as, c.req.param("id"));
    if (!user) return mgmtError(c, 404, "Not Found", "The user does not exist.", "inexistent_user");
    const orgs = as.orgMembers
      .findBy("user_id", user.user_id)
      .map((m) => as.organizations.findOneBy("org_id", m.org_id))
      .filter((o): o is NonNullable<typeof o> => Boolean(o))
      .map((o) => ({ id: o.org_id, name: o.name, display_name: o.display_name ?? undefined }));
    return c.json(orgs);
  });
}

// Build the full identities array (primary + linked) for a user.
function identitiesArray(
  as: ReturnType<typeof getAuth0Store>,
  userId: string,
  primaryConnection: string,
  primaryUserId: string,
) {
  const primary = {
    connection: primaryConnection,
    user_id: primaryUserId.includes("|") ? primaryUserId.split("|")[1] : primaryUserId,
    provider: primaryUserId.includes("|") ? primaryUserId.split("|")[0] : "auth0",
    isSocial: false,
  };
  const linked = as.userIdentities.findBy("user_id", userId).map((i) => ({
    connection: i.connection,
    user_id: i.identity_user_id,
    provider: i.provider,
    isSocial: i.is_social,
    profileData: i.profile_data,
  }));
  return [primary, ...linked];
}

function enrollmentRoutes({ app, store, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  // List a user's MFA enrollments (Management API view).
  app.get("/api/v2/users/:id/enrollments", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(as, c.req.param("id"));
    if (!user) return mgmtError(c, 404, "Not Found", "The user does not exist.", "inexistent_user");
    return c.json(
      as.userEnrollments.findBy("user_id", user.user_id).map((e) => ({
        id: e.enrollment_id,
        status: e.status,
        type: e.type,
        name: e.name ?? undefined,
        enrolled_at: new Date(e.created_at_unix * 1000).toISOString(),
        auth_method: e.type === "otp" ? "authenticator" : (e.oob_channel ?? e.type),
      })),
    );
  });

  // Delete all of a user's MFA enrollments (the multifactor endpoint).
  app.delete("/api/v2/users/:id/multifactor/:provider", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(as, c.req.param("id"));
    if (!user) return new Response(null, { status: 204 });
    for (const e of as.userEnrollments.findBy("user_id", user.user_id)) as.userEnrollments.delete(e.id);
    return new Response(null, { status: 204 });
  });

  // Guardian enrollment endpoints.
  app.get("/api/v2/guardian/enrollments/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const enrollment = as.userEnrollments.findOneBy("enrollment_id", c.req.param("id"));
    if (!enrollment) return mgmtError(c, 404, "Not Found", "Enrollment not found.", "enrollment_not_found");
    return c.json({
      id: enrollment.enrollment_id,
      status: enrollment.status,
      type: enrollment.type,
      enrolled_at: new Date(enrollment.created_at_unix * 1000).toISOString(),
    });
  });

  app.delete("/api/v2/guardian/enrollments/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const enrollment = as.userEnrollments.findOneBy("enrollment_id", c.req.param("id"));
    if (enrollment) as.userEnrollments.delete(enrollment.id);
    return new Response(null, { status: 204 });
  });
}
