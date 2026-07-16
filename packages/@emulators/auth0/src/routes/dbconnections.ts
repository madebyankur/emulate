import type { Context } from "@emulators/core";
import type { AppEnv, RouteContext } from "@emulators/core";
import { getAuth0Store } from "../store.js";
import { oauthError } from "../route-helpers.js";
import { DEFAULT_DB_CONNECTION, generateAuth0Id, generateUserId, nowUnix } from "../helpers.js";
import { dispatchEvent, recordLog } from "../events.js";
import { isBreachedPassword } from "../attack-protection.js";

async function parseBody(c: Context<AppEnv>): Promise<Record<string, string>> {
  const contentType = c.req.header("Content-Type") ?? "";
  if (contentType.includes("application/json")) {
    try {
      const parsed = (await c.req.json()) as Record<string, unknown>;
      const out: Record<string, string> = {};
      for (const [k, v] of Object.entries(parsed)) {
        if (typeof v === "string") out[k] = v;
      }
      return out;
    } catch {
      return {};
    }
  }
  return Object.fromEntries(new URLSearchParams(await c.req.text()));
}

// Authentication API database-connection endpoints: public signup and the
// change-password trigger. These are unauthenticated (client_id only) — the
// surface embedded-login apps depend on and thin mocks skip.
export function dbConnectionRoutes({ app, store, baseUrl }: RouteContext): void {
  const as = getAuth0Store(store);

  // POST /dbconnections/signup — register a new user in a database connection.
  app.post("/dbconnections/signup", async (c) => {
    const body = await parseBody(c);
    const email = body.email ?? "";
    const password = body.password ?? "";
    const connection = body.connection || DEFAULT_DB_CONNECTION;

    if (!email || !password) {
      return oauthError(c, 400, "invalid_signup", "Email and password are required.");
    }
    if (!as.connections.findOneBy("name", connection)) {
      return oauthError(c, 400, "invalid_signup", `Unknown connection '${connection}'.`);
    }
    if (isBreachedPassword(store, password)) {
      return c.json(
        {
          name: "PasswordStrengthError",
          code: "invalid_password",
          description: "Password is too weak (found in a breach).",
        },
        400,
      );
    }
    if (as.users.all().some((u) => u.email.toLowerCase() === email.toLowerCase() && u.connection === connection)) {
      return c.json(
        { code: "user_exists", description: "The user already exists.", name: "BadRequestError", statusCode: 400 },
        400,
      );
    }

    const now = nowUnix();
    const userId = generateUserId(connection);
    const created = as.users.insert({
      user_id: userId,
      email,
      email_verified: false,
      password,
      connection,
      username: body.username ?? null,
      name: body.name ?? email,
      nickname: body.nickname ?? null,
      given_name: body.given_name ?? null,
      family_name: body.family_name ?? null,
      picture: null,
      phone_number: null,
      phone_verified: false,
      blocked: false,
      user_metadata: {},
      app_metadata: {},
      last_login: null,
      logins_count: 0,
      created_at_unix: now,
      updated_at_unix: now,
    });

    await recordLog(store, { type: "ss", description: "Successful signup", clientId: body.client_id ?? null, userId });
    await dispatchEvent(store, { type: "user.created", data: { user_id: userId, email, connection } });

    // Auth0 returns a trimmed signup response (no tokens; the app logs in next).
    return c.json({
      _id: created.user_id.includes("|") ? created.user_id.split("|")[1] : created.user_id,
      email,
      email_verified: false,
      username: created.username ?? undefined,
    });
  });

  // POST /dbconnections/change_password — issue a password-change ticket. Auth0
  // returns a plain-text confirmation; we also mint a consumable ticket.
  app.post("/dbconnections/change_password", async (c) => {
    const body = await parseBody(c);
    const email = body.email ?? "";
    const connection = body.connection || DEFAULT_DB_CONNECTION;
    const user = as.users
      .all()
      .find((u) => u.email.toLowerCase() === email.toLowerCase() && u.connection === connection);

    // Auth0 always responds 200 with the same message to avoid user enumeration.
    if (user) {
      const ticketId = generateAuth0Id();
      as.tickets.insert({
        ticket_id: ticketId,
        user_id: user.user_id,
        kind: "password_change",
        consumed: false,
        created_at_unix: nowUnix(),
      });
      await recordLog(store, { type: "scp", description: "Password change request", userId: user.user_id });
      // Surface the ticket URL via header for tests; real Auth0 emails it.
      c.header("X-Emulate-Reset-Ticket", `${baseUrl}/u/reset-password?ticket=${ticketId}`);
    }
    return c.text("We've just sent you an email to reset your password.");
  });
}
