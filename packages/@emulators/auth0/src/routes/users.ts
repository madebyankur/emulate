import type { RouteContext } from "@emulators/core";
import { getAuth0Store } from "../store.js";
import {
  findUserByRef,
  listEnvelope,
  mgmtError,
  parsePage,
  readJsonBody,
  requireManagementAuth,
  roleResponse,
  userResponse,
} from "../route-helpers.js";
import { DEFAULT_DB_CONNECTION, generateUserId, nowUnix } from "../helpers.js";
import { dispatchEvent, recordLog } from "../events.js";

// Management API v2 — /api/v2/users and role assignment endpoints.
export function userRoutes({ app, store, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  app.get("/api/v2/users", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;

    const q = (c.req.query("q") ?? "").toLowerCase();
    let users = as.users.all();
    if (q) {
      // Support the common "email:foo@bar" Lucene-style query plus free text.
      const emailMatch = q.match(/email:"?([^"\s]+)"?/);
      if (emailMatch?.[1]) {
        users = users.filter((u) => u.email.toLowerCase() === emailMatch[1]);
      } else {
        users = users.filter((u) => [u.email, u.name, u.username].join(" ").toLowerCase().includes(q));
      }
    }

    const { page, perPage, includeTotals } = parsePage(c);
    return c.json(listEnvelope("users", users.map(userResponse), page, perPage, includeTotals));
  });

  app.get("/api/v2/users-by-email", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const email = (c.req.query("email") ?? "").toLowerCase();
    const matches = as.users.all().filter((u) => u.email.toLowerCase() === email);
    return c.json(matches.map(userResponse));
  });

  app.post("/api/v2/users", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;

    const body = await readJsonBody(c);
    const email = typeof body.email === "string" ? body.email.trim() : "";
    const connection = typeof body.connection === "string" ? body.connection : DEFAULT_DB_CONNECTION;
    if (!email) return mgmtError(c, 400, "Bad Request", "The 'email' field is required.", "invalid_body");
    if (as.users.all().some((u) => u.email.toLowerCase() === email.toLowerCase() && u.connection === connection)) {
      return mgmtError(c, 409, "Conflict", "The user already exists.", "auth0_idp_error");
    }

    const now = nowUnix();
    const userId =
      typeof body.user_id === "string"
        ? `${connection === DEFAULT_DB_CONNECTION ? "auth0" : connection}|${body.user_id}`
        : generateUserId(connection);
    const created = as.users.insert({
      user_id: userId,
      email,
      email_verified: body.email_verified === true,
      password: typeof body.password === "string" ? body.password : null,
      connection,
      username: typeof body.username === "string" ? body.username : null,
      name: typeof body.name === "string" ? body.name : email,
      nickname: typeof body.nickname === "string" ? body.nickname : null,
      given_name: typeof body.given_name === "string" ? body.given_name : null,
      family_name: typeof body.family_name === "string" ? body.family_name : null,
      picture: typeof body.picture === "string" ? body.picture : null,
      phone_number: typeof body.phone_number === "string" ? body.phone_number : null,
      phone_verified: body.phone_verified === true,
      blocked: false,
      user_metadata: (body.user_metadata as Record<string, unknown>) ?? {},
      app_metadata: (body.app_metadata as Record<string, unknown>) ?? {},
      last_login: null,
      logins_count: 0,
      created_at_unix: now,
      updated_at_unix: now,
    });

    await recordLog(store, { type: "sapi", description: "Create a user", userId: created.user_id });
    await dispatchEvent(store, { type: "user.created", data: { user_id: created.user_id, email: created.email } });
    return c.json(userResponse(created), 201);
  });

  app.get("/api/v2/users/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(as, c.req.param("id"));
    if (!user) return mgmtError(c, 404, "Not Found", "The user does not exist.", "inexistent_user");
    return c.json(userResponse(user));
  });

  app.patch("/api/v2/users/:id", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(as, c.req.param("id"));
    if (!user) return mgmtError(c, 404, "Not Found", "The user does not exist.", "inexistent_user");

    const body = await readJsonBody(c);
    const updates: Record<string, unknown> = { updated_at_unix: nowUnix() };
    for (const field of [
      "email",
      "name",
      "nickname",
      "given_name",
      "family_name",
      "picture",
      "username",
      "phone_number",
      "password",
    ] as const) {
      if (typeof body[field] === "string") updates[field] = body[field];
    }
    if (typeof body.email_verified === "boolean") updates.email_verified = body.email_verified;
    if (typeof body.blocked === "boolean") updates.blocked = body.blocked;
    // Auth0 merges metadata objects shallowly.
    if (body.user_metadata && typeof body.user_metadata === "object") {
      updates.user_metadata = { ...user.user_metadata, ...(body.user_metadata as Record<string, unknown>) };
    }
    if (body.app_metadata && typeof body.app_metadata === "object") {
      updates.app_metadata = { ...user.app_metadata, ...(body.app_metadata as Record<string, unknown>) };
    }

    const updated = as.users.update(user.id, updates);
    await dispatchEvent(store, { type: "user.updated", data: { user_id: user.user_id } });
    return c.json(userResponse(updated ?? user));
  });

  app.delete("/api/v2/users/:id", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(as, c.req.param("id"));
    if (!user) return new Response(null, { status: 204 });

    for (const assignment of as.roleAssignments.findBy("user_id", user.user_id)) {
      as.roleAssignments.delete(assignment.id);
    }
    for (const membership of as.orgMembers.findBy("user_id", user.user_id)) {
      as.orgMembers.delete(membership.id);
    }
    as.users.delete(user.id);
    await dispatchEvent(store, { type: "user.deleted", data: { user_id: user.user_id } });
    return new Response(null, { status: 204 });
  });

  // --- per-user role assignment ---
  app.get("/api/v2/users/:id/roles", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(as, c.req.param("id"));
    if (!user) return mgmtError(c, 404, "Not Found", "The user does not exist.", "inexistent_user");
    const roles = as.roleAssignments
      .findBy("user_id", user.user_id)
      .map((a) => as.roles.findOneBy("role_id", a.role_id))
      .filter((r): r is NonNullable<typeof r> => Boolean(r));
    return c.json(roles.map(roleResponse));
  });

  app.post("/api/v2/users/:id/roles", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(as, c.req.param("id"));
    if (!user) return mgmtError(c, 404, "Not Found", "The user does not exist.", "inexistent_user");

    const body = await readJsonBody(c);
    const roleIds = Array.isArray(body.roles)
      ? (body.roles as unknown[]).filter((r): r is string => typeof r === "string")
      : [];
    for (const roleId of roleIds) {
      if (!as.roles.findOneBy("role_id", roleId)) continue;
      const exists = as.roleAssignments.findBy("user_id", user.user_id).some((a) => a.role_id === roleId);
      if (!exists) as.roleAssignments.insert({ role_id: roleId, user_id: user.user_id });
    }
    return new Response(null, { status: 204 });
  });

  app.delete("/api/v2/users/:id/roles", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(as, c.req.param("id"));
    if (!user) return mgmtError(c, 404, "Not Found", "The user does not exist.", "inexistent_user");
    const body = await readJsonBody(c);
    const roleIds = Array.isArray(body.roles)
      ? (body.roles as unknown[]).filter((r): r is string => typeof r === "string")
      : [];
    for (const roleId of roleIds) {
      const assignment = as.roleAssignments.findBy("user_id", user.user_id).find((a) => a.role_id === roleId);
      if (assignment) as.roleAssignments.delete(assignment.id);
    }
    return new Response(null, { status: 204 });
  });
}
