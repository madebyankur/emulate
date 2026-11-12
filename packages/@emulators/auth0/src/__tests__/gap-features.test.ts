import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { Hono, Store, WebhookDispatcher, authMiddleware, type TokenMap } from "@emulators/core";
import { auth0Plugin, getAuth0Store, seedFromConfig } from "../index.js";

const base = "http://localhost:4321";
const CLIENT_ID = "test-client";
const CLIENT_SECRET = "test-secret";
const REDIRECT = "http://localhost:3000/callback";
const API_AUDIENCE = "https://api.example.com";
const MGMT = `${base}/api/v2/`;

function json(body: unknown): RequestInit {
  return { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
}

function patch(body: unknown): RequestInit {
  return { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
}

async function readJson(res: Response): Promise<any> {
  return res.json();
}

function authHeaders(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}

interface SetupOptions {
  seed?: Parameters<typeof seedFromConfig>[2];
}

function createApp(opts: SetupOptions = {}) {
  const store = new Store();
  const webhooks = new WebhookDispatcher();
  const tokenMap: TokenMap = new Map();
  const app = new Hono();
  app.use("*", authMiddleware(tokenMap));
  auth0Plugin.register(app, store, webhooks, base, tokenMap);
  seedFromConfig(store, base, {
    users: [
      { email: "alice@example.com", password: "alice-pw", email_verified: true, name: "Alice", roles: ["admin"] },
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
    ],
    resource_servers: [
      { name: "My API", identifier: API_AUDIENCE, scopes: ["read:items", "write:items"], enforce_policies: true },
    ],
    roles: [
      {
        name: "admin",
        description: "Admin",
        permissions: [{ resource_server_identifier: API_AUDIENCE, permission_name: "read:items" }],
      },
    ],
    organizations: [{ name: "acme", display_name: "Acme", members: ["alice@example.com"] }],
    ...(opts.seed ?? {}),
  });
  return { app, store, tokenMap };
}

async function mgmtToken(app: Hono): Promise<string> {
  const res = await app.request(
    `${base}/oauth/token`,
    json({ grant_type: "client_credentials", client_id: CLIENT_ID, client_secret: CLIENT_SECRET, audience: MGMT }),
  );
  return (await readJson(res)).access_token as string;
}

async function passwordLogin(app: Hono, extra: Record<string, unknown> = {}) {
  return app.request(
    `${base}/oauth/token`,
    json({
      grant_type: "password",
      username: "alice@example.com",
      password: "alice-pw",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      audience: API_AUDIENCE,
      scope: "openid profile email",
      ...extra,
    }),
  );
}

describe("RBAC + token fidelity", () => {
  it("emits the permissions claim when the API enforces policies", async () => {
    const { app } = createApp();
    const res = await passwordLogin(app);
    expect(res.status).toBe(200);
    const body = await readJson(res);
    const claims = decodeJwt(body.access_token);
    expect(claims.permissions).toEqual(["read:items"]);
  });

  it("omits permissions when the API does not enforce policies", async () => {
    const { app } = createApp({
      seed: {
        resource_servers: [{ name: "Open API", identifier: "https://open.example.com", scopes: ["x"] }],
      },
    });
    const res = await passwordLogin(app, { audience: "https://open.example.com" });
    const body = await readJson(res);
    const claims = decodeJwt(body.access_token);
    expect(claims.permissions).toBeUndefined();
  });

  it("supports user permission management endpoints", async () => {
    const { app } = createApp();
    const token = await mgmtToken(app);
    const users = await readJson(await app.request(`${MGMT}users`, { headers: authHeaders(token) }));
    const userId = users[0].user_id;
    const post = await app.request(`${MGMT}users/${encodeURIComponent(userId)}/permissions`, {
      ...json({ permissions: [{ resource_server_identifier: API_AUDIENCE, permission_name: "write:items" }] }),
      headers: authHeaders(token),
    });
    expect(post.status).toBe(201);
    const list = await readJson(
      await app.request(`${MGMT}users/${encodeURIComponent(userId)}/permissions`, { headers: authHeaders(token) }),
    );
    expect(list.map((p: { permission_name: string }) => p.permission_name)).toContain("write:items");
  });
});

describe("Actions and Rules", () => {
  it("runs a config-driven action that injects an id_token claim", async () => {
    const { app } = createApp({
      seed: {
        actions: [
          { name: "add-dept", trigger: "post-login", config: { addClaims: { idToken: { "https://x/dept": "eng" } } } },
        ],
      },
    });
    const res = await passwordLogin(app, { scope: "openid" });
    const body = await readJson(res);
    const claims = decodeJwt(body.id_token);
    expect(claims["https://x/dept"]).toBe("eng");
  });

  it("runs real JS action code in the sandbox", async () => {
    const { app } = createApp({
      seed: {
        actions: [
          {
            name: "js-claim",
            trigger: "post-login",
            code: "exports.onExecutePostLogin = async (event, api) => { api.idToken.setCustomClaim('https://x/js', 'yes'); };",
          },
        ],
      },
    });
    const res = await passwordLogin(app, { scope: "openid" });
    const body = await readJson(res);
    const claims = decodeJwt(body.id_token);
    expect(claims["https://x/js"]).toBe("yes");
  });

  it("denies login when an action calls api.access.deny", async () => {
    const { app } = createApp({
      seed: {
        actions: [
          {
            name: "deny",
            trigger: "post-login",
            code: "exports.onExecutePostLogin = async (event, api) => { api.access.deny('nope'); };",
          },
        ],
      },
    });
    const res = await passwordLogin(app);
    expect(res.status).toBe(403);
    expect((await readJson(res)).error).toBe("access_denied");
  });

  it("forces MFA when an action enables multifactor", async () => {
    const { app } = createApp({
      seed: {
        actions: [
          {
            name: "mfa",
            trigger: "post-login",
            code: "exports.onExecutePostLogin = async (event, api) => { api.multifactor.enable('any'); };",
          },
        ],
      },
    });
    const res = await passwordLogin(app);
    expect(res.status).toBe(403);
    expect((await readJson(res)).error).toBe("mfa_required");
  });
});

describe("Passwordless", () => {
  it("starts and completes an email OTP login", async () => {
    const { app } = createApp();
    const start = await app.request(
      `${base}/passwordless/start`,
      json({ connection: "email", email: "new@example.com" }),
    );
    expect(start.status).toBe(200);
    const codeRes = await readJson(await app.request(`${base}/_emulate/passwordless/code?identifier=new@example.com`));
    const res = await app.request(
      `${base}/oauth/token`,
      json({
        grant_type: "http://auth0.com/oauth/grant-type/passwordless/otp",
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        username: "new@example.com",
        otp: codeRes.code,
        realm: "email",
        scope: "openid email",
      }),
    );
    expect(res.status).toBe(200);
    const body = await readJson(res);
    expect(decodeJwt(body.id_token).email).toBe("new@example.com");
  });
});

describe("MFA", () => {
  it("challenges an enrolled-policy user and completes via the mfa-otp grant", async () => {
    const { app } = createApp({ seed: { mfa: { always_on: true } } });
    const res = await passwordLogin(app);
    expect(res.status).toBe(403);
    const challenge = await readJson(res);
    expect(challenge.error).toBe("mfa_required");
    expect(challenge.mfa_token).toBeTruthy();

    const assoc = await app.request(`${base}/mfa/associate`, {
      ...json({ authenticator_types: ["otp"] }),
      headers: { Authorization: `Bearer ${challenge.mfa_token}`, "Content-Type": "application/json" },
    });
    expect(assoc.status).toBe(200);

    const complete = await app.request(
      `${base}/oauth/token`,
      json({
        grant_type: "http://auth0.com/oauth/grant-type/mfa-otp",
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        mfa_token: challenge.mfa_token,
        otp: "000000",
      }),
    );
    expect(complete.status).toBe(200);
    expect((await readJson(complete)).access_token).toBeTruthy();
  });
});

describe("Management API breadth", () => {
  it("creates a verification-email job that returns a ticket", async () => {
    const { app } = createApp();
    const token = await mgmtToken(app);
    const users = await readJson(await app.request(`${MGMT}users`, { headers: authHeaders(token) }));
    const userId = users[0].user_id;
    const res = await app.request(`${MGMT}jobs/verification-email`, {
      ...json({ user_id: userId }),
      headers: authHeaders(token),
    });
    expect(res.status).toBe(201);
    const body = await readJson(res);
    expect(body.status).toBe("completed");
    expect(typeof body.ticket).toBe("string");
  });

  it("manages actions through the Management API", async () => {
    const { app } = createApp();
    const token = await mgmtToken(app);
    const create = await app.request(`${MGMT}actions/actions`, {
      ...json({ name: "my-action", supported_triggers: [{ id: "post-login", version: "v3" }], code: "//noop" }),
      headers: authHeaders(token),
    });
    expect(create.status).toBe(201);
    const action = await readJson(create);
    const deploy = await app.request(`${MGMT}actions/actions/${action.id}/deploy`, {
      method: "POST",
      headers: authHeaders(token),
    });
    expect(deploy.status).toBe(200);
    expect((await readJson(deploy)).deployed).toBe(true);
  });

  it("returns the live signing key", async () => {
    const { app } = createApp();
    const token = await mgmtToken(app);
    const res = await app.request(`${MGMT}keys/signing`, { headers: authHeaders(token) });
    expect(res.status).toBe(200);
    const keys = await readJson(res);
    expect(keys[0].kid).toBe("emulate-auth0-1");
  });

  it("toggles RBAC on a resource server via PATCH", async () => {
    const { app } = createApp();
    const token = await mgmtToken(app);
    const res = await app.request(`${MGMT}resource-servers/${encodeURIComponent(API_AUDIENCE)}`, {
      ...patch({ enforce_policies: false }),
      headers: authHeaders(token),
    });
    expect(res.status).toBe(200);
    expect((await readJson(res)).enforce_policies).toBe(false);
  });
});

describe("Auth protocols", () => {
  it("registers a client dynamically", async () => {
    const { app } = createApp();
    const res = await app.request(
      `${base}/oidc/register`,
      json({ client_name: "Dyn", redirect_uris: ["http://localhost:9999/cb"] }),
    );
    expect(res.status).toBe(201);
    const body = await readJson(res);
    expect(body.client_id).toBeTruthy();
    expect(body.client_secret).toBeTruthy();
  });

  it("accepts a PAR request_uri and drives /authorize", async () => {
    const { app } = createApp();
    const par = await app.request(`${base}/oauth/par`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT,
        response_type: "code",
        scope: "openid",
      }).toString(),
    });
    expect(par.status).toBe(201);
    const { request_uri } = await readJson(par);
    expect(request_uri).toMatch(/^urn:ietf:params:oauth:request_uri:/);
    const authorize = await app.request(`${base}/authorize?request_uri=${encodeURIComponent(request_uri)}`);
    expect(authorize.status).toBe(200);
    expect(await authorize.text()).toContain("alice@example.com");
  });

  it("does not 500 on a SAML callback with a malformed user_ref", async () => {
    const { app } = createApp();
    const res = await app.request(`${base}/samlp/${CLIENT_ID}/callback`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ user_ref: "auth0|", redirect_uri: REDIRECT, state: "rs" }).toString(),
    });
    expect([200, 400]).toContain(res.status);
  });

  it("completes a CIBA poll after approval", async () => {
    const { app, store } = createApp();
    const start = await app.request(
      `${base}/bc-authorize`,
      json({ client_id: CLIENT_ID, scope: "openid", binding_message: "go" }),
    );
    const { auth_req_id } = await readJson(start);
    const pending = await app.request(
      `${base}/oauth/token`,
      json({ grant_type: "urn:openid:params:grant-type:ciba", auth_req_id, client_id: CLIENT_ID }),
    );
    expect((await readJson(pending)).error).toBe("authorization_pending");
    const userId = getAuth0Store(store).users.all()[0].user_id;
    await app.request(`${base}/_emulate/ciba/approve`, json({ auth_req_id, user_id: userId }));
    const done = await app.request(
      `${base}/oauth/token`,
      json({ grant_type: "urn:openid:params:grant-type:ciba", auth_req_id, client_id: CLIENT_ID }),
    );
    expect(done.status).toBe(200);
    expect((await readJson(done)).access_token).toBeTruthy();
  });

  it("serves the legacy /tokeninfo deprecation error", async () => {
    const { app } = createApp();
    const res = await app.request(`${base}/tokeninfo`);
    expect(res.status).toBe(403);
  });
});
