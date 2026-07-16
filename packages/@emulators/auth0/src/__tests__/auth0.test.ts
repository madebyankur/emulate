import { createHash, randomBytes } from "node:crypto";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import { Hono, Store, WebhookDispatcher, authMiddleware, type TokenMap } from "@emulators/core";
import { getAuth0Store, auth0Plugin, seedFromConfig } from "../index.js";

const base = "http://localhost:4300";
const CLIENT_ID = "test-client";
const CLIENT_SECRET = "test-secret";
const DB = "Username-Password-Authentication";
const REDIRECT = "http://localhost:3000/callback";
const API_AUDIENCE = "https://api.example.com";

function createApp() {
  const store = new Store();
  const webhooks = new WebhookDispatcher();
  const tokenMap: TokenMap = new Map();
  const app = new Hono();
  app.use("*", authMiddleware(tokenMap));
  auth0Plugin.register(app as never, store, webhooks, base, tokenMap);
  seedFromConfig(store, base, {
    users: [
      { email: "alice@example.com", password: "alice-pw", email_verified: true, name: "Alice", roles: ["admin"] },
      { email: "bob@example.com", password: "bob-pw", name: "Bob" },
    ],
    clients: [
      {
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        name: "Test App",
        app_type: "regular_web",
        callbacks: [REDIRECT],
        allowed_logout_urls: ["http://localhost:3000"],
        grant_types: ["authorization_code", "refresh_token", "client_credentials", "password"],
      },
      { client_id: "spa-client", name: "SPA", app_type: "spa", callbacks: [REDIRECT] },
    ],
    resource_servers: [{ name: "My API", identifier: API_AUDIENCE, scopes: ["read:items", "write:items"] }],
    client_grants: [{ client_id: CLIENT_ID, audience: API_AUDIENCE, scopes: ["read:items", "write:items"] }],
    roles: [{ name: "admin", description: "Admin" }],
    organizations: [{ name: "acme", display_name: "Acme", members: ["alice@example.com"] }],
  });
  return { app, store, tokenMap };
}

function json(body: unknown): RequestInit {
  return { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
}

// Response.json() is typed as Promise<unknown> under strict mode; this keeps
// assertions ergonomic in the test file.
async function readJson(res: Response): Promise<any> {
  return res.json();
}

async function mgmtToken(app: Hono): Promise<string> {
  const res = await app.request(
    `${base}/oauth/token`,
    json({
      grant_type: "client_credentials",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      audience: `${base}/api/v2/`,
    }),
  );
  return (await readJson(res)).access_token as string;
}

function authHeaders(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}

describe("OIDC discovery", () => {
  it("advertises a trailing-slash issuer and the expected endpoints", async () => {
    const { app } = createApp();
    const res = await app.request(`${base}/.well-known/openid-configuration`);
    expect(res.status).toBe(200);
    const doc = await readJson(res);
    expect(doc.issuer).toBe(`${base}/`);
    expect(doc.token_endpoint).toBe(`${base}/oauth/token`);
    expect(doc.grant_types_supported).toContain("http://auth0.com/oauth/grant-type/password-realm");
    expect(doc.code_challenge_methods_supported).toContain("S256");
  });

  it("exposes a matching RS256 JWKS key", async () => {
    const { app } = createApp();
    const res = await app.request(`${base}/.well-known/jwks.json`);
    const jwks = await readJson(res);
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0].alg).toBe("RS256");
    expect(jwks.keys[0].kid).toBe("emulate-auth0-1");
    expect(jwks.keys[0].kty).toBe("RSA");
  });
});

describe("authorization code + PKCE", () => {
  async function authorize(app: Hono, store: Store, challenge: string | null) {
    const as = getAuth0Store(store);
    const user = as.users.findOneBy("email", "alice@example.com")!;
    const form = new URLSearchParams({
      user_ref: user.user_id,
      redirect_uri: REDIRECT,
      scope: "openid profile email offline_access",
      state: "xyz",
      client_id: CLIENT_ID,
      audience: API_AUDIENCE,
    });
    if (challenge) {
      form.set("code_challenge", challenge);
      form.set("code_challenge_method", "S256");
    }
    const res = await app.request(`${base}/u/login/callback`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
      redirect: "manual",
    });
    const location = res.headers.get("location")!;
    return new URL(location).searchParams.get("code")!;
  }

  it("completes a PKCE S256 round trip and returns id + access + refresh tokens", async () => {
    const { app, store } = createApp();
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const code = await authorize(app, store, challenge);

    const res = await app.request(
      `${base}/oauth/token`,
      json({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code_verifier: verifier,
      }),
    );
    expect(res.status).toBe(200);
    const body = await readJson(res);
    expect(body.access_token).toBeTruthy();
    expect(body.id_token).toBeTruthy();
    expect(body.refresh_token).toBeTruthy();

    const access = decodeJwt(body.access_token);
    expect(access.iss).toBe(`${base}/`);
    expect(access.aud).toBe(API_AUDIENCE);
    expect(decodeProtectedHeader(body.access_token).alg).toBe("RS256");

    const id = decodeJwt(body.id_token);
    expect(id.aud).toBe(CLIENT_ID);
    expect(id.email).toBe("alice@example.com");
    // Roles are injected as a namespaced claim.
    expect(id[`${base}/roles`]).toContain("admin");
  });

  it("rejects a wrong PKCE verifier", async () => {
    const { app, store } = createApp();
    const challenge = createHash("sha256").update("right").digest("base64url");
    const code = await authorize(app, store, challenge);
    const res = await app.request(
      `${base}/oauth/token`,
      json({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code_verifier: "wrong",
      }),
    );
    expect(res.status).toBe(403);
    expect((await readJson(res)).error).toBe("invalid_grant");
  });

  it("rejects a reused authorization code", async () => {
    const { app, store } = createApp();
    const code = await authorize(app, store, null);
    const first = await app.request(
      `${base}/oauth/token`,
      json({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      }),
    );
    expect(first.status).toBe(200);
    const second = await app.request(
      `${base}/oauth/token`,
      json({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      }),
    );
    expect(second.status).toBe(403);
  });
});

describe("password-realm grant", () => {
  it("logs in a user and returns the full token set", async () => {
    const { app } = createApp();
    const res = await app.request(
      `${base}/oauth/token`,
      json({
        grant_type: "http://auth0.com/oauth/grant-type/password-realm",
        username: "alice@example.com",
        password: "alice-pw",
        realm: DB,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        scope: "openid profile email offline_access",
        audience: API_AUDIENCE,
      }),
    );
    expect(res.status).toBe(200);
    const body = await readJson(res);
    expect(body.access_token).toBeTruthy();
    expect(body.refresh_token).toBeTruthy();
    expect(decodeJwt(body.access_token).aud).toBe(API_AUDIENCE);
  });

  it("rejects wrong credentials", async () => {
    const { app } = createApp();
    const res = await app.request(
      `${base}/oauth/token`,
      json({
        grant_type: "http://auth0.com/oauth/grant-type/password-realm",
        username: "alice@example.com",
        password: "nope",
        realm: DB,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      }),
    );
    expect(res.status).toBe(403);
    expect((await readJson(res)).error).toBe("invalid_grant");
  });

  it("does not issue a refresh token without offline_access", async () => {
    const { app } = createApp();
    const res = await app.request(
      `${base}/oauth/token`,
      json({
        grant_type: "http://auth0.com/oauth/grant-type/password-realm",
        username: "alice@example.com",
        password: "alice-pw",
        realm: DB,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        scope: "openid",
      }),
    );
    const body = await readJson(res);
    expect(body.access_token).toBeTruthy();
    expect(body.refresh_token).toBeUndefined();
  });
});

describe("refresh token rotation", () => {
  it("rotates the refresh token and invalidates the old one", async () => {
    const { app } = createApp();
    const login = await readJson(
      await app.request(
        `${base}/oauth/token`,
        json({
          grant_type: "http://auth0.com/oauth/grant-type/password-realm",
          username: "alice@example.com",
          password: "alice-pw",
          realm: DB,
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          scope: "openid offline_access",
        }),
      ),
    );
    const oldRefresh = login.refresh_token;

    const refreshed = await app.request(
      `${base}/oauth/token`,
      json({ grant_type: "refresh_token", refresh_token: oldRefresh, client_id: CLIENT_ID }),
    );
    expect(refreshed.status).toBe(200);
    const body = await readJson(refreshed);
    expect(body.refresh_token).toBeTruthy();
    expect(body.refresh_token).not.toBe(oldRefresh);

    const reuse = await app.request(
      `${base}/oauth/token`,
      json({ grant_type: "refresh_token", refresh_token: oldRefresh, client_id: CLIENT_ID }),
    );
    expect(reuse.status).toBe(403);
  });
});

describe("client credentials", () => {
  it("mints an access token constrained to the client grant scopes", async () => {
    const { app } = createApp();
    const res = await app.request(
      `${base}/oauth/token`,
      json({
        grant_type: "client_credentials",
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        audience: API_AUDIENCE,
      }),
    );
    expect(res.status).toBe(200);
    const body = await readJson(res);
    expect(body.access_token).toBeTruthy();
    expect(body.refresh_token).toBeUndefined();
    expect(body.scope).toContain("read:items");
    expect(decodeJwt(body.access_token).aud).toBe(API_AUDIENCE);
  });

  it("rejects an invalid client secret", async () => {
    const { app } = createApp();
    const res = await app.request(
      `${base}/oauth/token`,
      json({ grant_type: "client_credentials", client_id: CLIENT_ID, client_secret: "wrong", audience: API_AUDIENCE }),
    );
    expect(res.status).toBe(401);
  });
});

describe("userinfo", () => {
  it("returns claims for a valid bearer access token", async () => {
    const { app } = createApp();
    const login = await readJson(
      await app.request(
        `${base}/oauth/token`,
        json({
          grant_type: "http://auth0.com/oauth/grant-type/password-realm",
          username: "alice@example.com",
          password: "alice-pw",
          realm: DB,
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          scope: "openid profile email",
        }),
      ),
    );
    const res = await app.request(`${base}/userinfo`, { headers: { Authorization: `Bearer ${login.access_token}` } });
    expect(res.status).toBe(200);
    const body = await readJson(res);
    expect(body.email).toBe("alice@example.com");
    expect(body.sub).toBeTruthy();
  });

  it("rejects an unknown token", async () => {
    const { app } = createApp();
    const res = await app.request(`${base}/userinfo`, { headers: { Authorization: "Bearer nope" } });
    expect(res.status).toBe(401);
  });
});

describe("Management API", () => {
  it("requires authentication", async () => {
    const { app } = createApp();
    const res = await app.request(`${base}/api/v2/users`);
    expect(res.status).toBe(401);
  });

  it("creates, fetches, patches, and deletes a user", async () => {
    const { app } = createApp();
    const token = await mgmtToken(app);

    const created = await app.request(`${base}/api/v2/users`, {
      ...json({ email: "carol@example.com", password: "x", connection: DB, email_verified: true }),
      headers: authHeaders(token),
    });
    expect(created.status).toBe(201);
    const user = await readJson(created);
    expect(user.user_id).toMatch(/^auth0\|/);

    const fetched = await app.request(`${base}/api/v2/users/${encodeURIComponent(user.user_id)}`, {
      headers: authHeaders(token),
    });
    expect(fetched.status).toBe(200);

    const patched = await app.request(`${base}/api/v2/users/${encodeURIComponent(user.user_id)}`, {
      method: "PATCH",
      headers: authHeaders(token),
      body: JSON.stringify({ app_metadata: { plan: "pro" } }),
    });
    expect((await readJson(patched)).app_metadata.plan).toBe("pro");

    const deleted = await app.request(`${base}/api/v2/users/${encodeURIComponent(user.user_id)}`, {
      method: "DELETE",
      headers: authHeaders(token),
    });
    expect(deleted.status).toBe(204);
  });

  it("finds users by email", async () => {
    const { app } = createApp();
    const token = await mgmtToken(app);
    const res = await app.request(`${base}/api/v2/users-by-email?email=alice@example.com`, {
      headers: authHeaders(token),
    });
    const list = await readJson(res);
    expect(list).toHaveLength(1);
    expect(list[0].email).toBe("alice@example.com");
  });

  it("returns a paged envelope when include_totals=true", async () => {
    const { app } = createApp();
    const token = await mgmtToken(app);
    const res = await app.request(`${base}/api/v2/users?include_totals=true`, { headers: authHeaders(token) });
    const body = await readJson(res);
    expect(Array.isArray(body.users)).toBe(true);
    expect(typeof body.total).toBe("number");
  });

  it("manages resource servers and rejects duplicates", async () => {
    const { app } = createApp();
    const token = await mgmtToken(app);
    const dup = await app.request(`${base}/api/v2/resource-servers`, {
      ...json({ identifier: API_AUDIENCE, name: "dup" }),
      headers: authHeaders(token),
    });
    expect(dup.status).toBe(409);
  });
});

describe("self-service signup and password reset", () => {
  it("signs up a user who can then log in", async () => {
    const { app } = createApp();
    const signup = await app.request(
      `${base}/dbconnections/signup`,
      json({ client_id: CLIENT_ID, email: "new@example.com", password: "New123!", connection: DB }),
    );
    expect(signup.status).toBe(200);

    const login = await app.request(
      `${base}/oauth/token`,
      json({
        grant_type: "http://auth0.com/oauth/grant-type/password-realm",
        username: "new@example.com",
        password: "New123!",
        realm: DB,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        scope: "openid",
      }),
    );
    expect(login.status).toBe(200);
  });

  it("rejects a duplicate signup", async () => {
    const { app } = createApp();
    const res = await app.request(
      `${base}/dbconnections/signup`,
      json({ client_id: CLIENT_ID, email: "alice@example.com", password: "x", connection: DB }),
    );
    expect(res.status).toBe(400);
    expect((await readJson(res)).code).toBe("user_exists");
  });
});

describe("email verification tickets", () => {
  it("creates and consumes a verification ticket", async () => {
    const { app, store } = createApp();
    const token = await mgmtToken(app);
    const as = getAuth0Store(store);
    const bob = as.users.findOneBy("email", "bob@example.com")!;
    expect(bob.email_verified).toBe(false);

    const ticketRes = await app.request(`${base}/api/v2/tickets/email-verification`, {
      ...json({ user_id: bob.user_id }),
      headers: authHeaders(token),
    });
    const ticketUrl = (await readJson(ticketRes)).ticket as string;
    const consume = await app.request(ticketUrl);
    expect(consume.status).toBe(200);
    expect(as.users.findOneBy("email", "bob@example.com")!.email_verified).toBe(true);
  });
});

describe("log streams vs event streams", () => {
  it("delivers a typed event to event streams and a log record to log streams", async () => {
    const { app, store } = createApp();
    const token = await mgmtToken(app);
    await app.request(`${base}/api/v2/event-streams`, {
      ...json({ name: "evt", subscriptions: [{ event_type: "user.created" }] }),
      headers: authHeaders(token),
    });
    await app.request(`${base}/api/v2/log-streams`, { ...json({ name: "logs" }), headers: authHeaders(token) });

    await app.request(`${base}/api/v2/users`, {
      ...json({ email: "streamed@example.com", password: "x", connection: DB }),
      headers: authHeaders(token),
    });

    const as = getAuth0Store(store);
    const deliveries = as.streamDeliveries.all();
    const events = deliveries.filter((d) => d.kind === "event");
    const logs = deliveries.filter((d) => d.kind === "log");
    expect(events.some((d) => d.event_type === "user.created")).toBe(true);
    expect(logs.length).toBeGreaterThan(0);
    // The two subsystems are distinct: the log stream did not receive the typed event.
    expect(logs.some((d) => d.event_type === "user.created")).toBe(false);
  });

  it("only delivers subscribed event types", async () => {
    const { app, store } = createApp();
    const token = await mgmtToken(app);
    await app.request(`${base}/api/v2/event-streams`, {
      ...json({ name: "evt", subscriptions: [{ event_type: "login.succeeded" }] }),
      headers: authHeaders(token),
    });
    // Creating a user emits user.created, which this stream is NOT subscribed to.
    await app.request(`${base}/api/v2/users`, {
      ...json({ email: "x@example.com", password: "x", connection: DB }),
      headers: authHeaders(token),
    });
    const as = getAuth0Store(store);
    expect(as.streamDeliveries.findBy("kind", "event").length).toBe(0);
  });
});

describe("attack protection", () => {
  it("blocks an account after the brute-force threshold and unblocks it", async () => {
    const { app } = createApp();
    const token = await mgmtToken(app);
    await app.request(`${base}/api/v2/attack-protection/brute-force-protection`, {
      method: "PATCH",
      headers: authHeaders(token),
      body: JSON.stringify({ max_attempts: 3 }),
    });

    const fail = () =>
      app.request(`${base}/oauth/token`, {
        ...json({
          grant_type: "http://auth0.com/oauth/grant-type/password-realm",
          username: "alice@example.com",
          password: "wrong",
          realm: DB,
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
        }),
        headers: { "Content-Type": "application/json", "X-Forwarded-For": "5.5.5.5" },
      });
    for (let i = 0; i < 3; i++) await fail();

    // Correct password is now rejected with too_many_attempts.
    const blocked = await app.request(`${base}/oauth/token`, {
      ...json({
        grant_type: "http://auth0.com/oauth/grant-type/password-realm",
        username: "alice@example.com",
        password: "alice-pw",
        realm: DB,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      }),
      headers: { "Content-Type": "application/json", "X-Forwarded-For": "5.5.5.5" },
    });
    expect(blocked.status).toBe(429);
    expect((await readJson(blocked)).error).toBe("too_many_attempts");

    await app.request(`${base}/api/v2/user-blocks?identifier=alice@example.com`, {
      method: "DELETE",
      headers: authHeaders(token),
    });
    const ok = await app.request(`${base}/oauth/token`, {
      ...json({
        grant_type: "http://auth0.com/oauth/grant-type/password-realm",
        username: "alice@example.com",
        password: "alice-pw",
        realm: DB,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      }),
      headers: { "Content-Type": "application/json", "X-Forwarded-For": "5.5.5.5" },
    });
    expect(ok.status).toBe(200);
  });

  it("rejects breached passwords", async () => {
    const { app } = createApp();
    const token = await mgmtToken(app);
    await app.request(`${base}/api/v2/attack-protection/breached-password-detection`, {
      method: "PATCH",
      headers: authHeaders(token),
      body: JSON.stringify({ enabled: true, passwords: ["hunter2"] }),
    });
    // Seed a user whose password is the breached one.
    await app.request(`${base}/api/v2/users`, {
      ...json({ email: "weak@example.com", password: "hunter2", connection: DB }),
      headers: authHeaders(token),
    });
    const res = await app.request(
      `${base}/oauth/token`,
      json({
        grant_type: "http://auth0.com/oauth/grant-type/password-realm",
        username: "weak@example.com",
        password: "hunter2",
        realm: DB,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      }),
    );
    expect(res.status).toBe(401);
    expect((await readJson(res)).error).toBe("password_leaked");
  });
});

describe("device authorization flow", () => {
  it("completes a device-code round trip after approval", async () => {
    const { app, store } = createApp();
    const start = await app.request(
      `${base}/oauth/device/code`,
      json({ client_id: CLIENT_ID, scope: "openid", audience: API_AUDIENCE }),
    );
    const { device_code } = await readJson(start);

    // Before approval, polling is pending.
    const pending = await app.request(
      `${base}/oauth/token`,
      json({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code, client_id: CLIENT_ID }),
    );
    expect(pending.status).toBe(403);
    expect((await readJson(pending)).error).toBe("authorization_pending");

    const as = getAuth0Store(store);
    const alice = as.users.findOneBy("email", "alice@example.com")!;
    await app.request(`${base}/_emulate/device/approve`, json({ device_code, user_id: alice.user_id }));

    const done = await app.request(
      `${base}/oauth/token`,
      json({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code, client_id: CLIENT_ID }),
    );
    expect(done.status).toBe(200);
    expect((await readJson(done)).access_token).toBeTruthy();
  });
});

describe("logout", () => {
  it("redirects to an allowed returnTo URL", async () => {
    const { app } = createApp();
    const res = await app.request(`${base}/v2/logout?client_id=${CLIENT_ID}&returnTo=http://localhost:3000`, {
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("http://localhost:3000");
  });

  it("rejects a returnTo not in allowed_logout_urls", async () => {
    const { app } = createApp();
    const res = await app.request(`${base}/v2/logout?client_id=${CLIENT_ID}&returnTo=http://evil.example.com`);
    expect(res.status).toBe(400);
  });
});

describe("inspector", () => {
  let app: Hono;
  beforeEach(() => {
    app = createApp().app;
  });
  it("renders the users tab", async () => {
    const res = await app.request(`${base}/`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Auth0 Inspector");
    expect(html).toContain("alice@example.com");
  });
});
