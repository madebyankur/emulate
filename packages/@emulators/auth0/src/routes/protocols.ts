import { randomBytes } from "node:crypto";
import type { Context } from "@emulators/core";
import type { AppEnv, RouteContext, Store } from "@emulators/core";
import { getAuth0Store } from "../store.js";
import { generateAuth0Id, nowUnix } from "../helpers.js";
import { oauthError } from "../route-helpers.js";

// Smaller OAuth/OIDC protocol surfaces: Pushed Authorization Requests (PAR),
// Dynamic Client Registration, a minimal passkey ceremony, and shaped stubs
// for deprecated endpoints so SDKs do not 404.

// --- PAR (RFC 9126) ---
export interface PushedRequest {
  params: Record<string, string>;
  expiresAt: number;
}

export function getPushedRequests(store: Store): Map<string, PushedRequest> {
  let map = store.getData<Map<string, PushedRequest>>("auth0.par.requests");
  if (!map) {
    map = new Map();
    store.setData("auth0.par.requests", map);
  }
  return map;
}

export function protocolRoutes(ctx: RouteContext): void {
  parRoutes(ctx);
  registrationRoutes(ctx);
  passkeyRoutes(ctx);
  legacyStubRoutes(ctx);
}

function parRoutes({ app, store }: RouteContext): void {
  // POST /oauth/par — store the pushed authorization params, return request_uri.
  app.post("/oauth/par", async (c) => {
    const body = await readForm(c);
    if (!body.client_id) return oauthError(c, 400, "invalid_request", "client_id is required.");
    const id = randomBytes(16).toString("hex");
    const requestUri = `urn:ietf:params:oauth:request_uri:${id}`;
    const expiresIn = 90;
    getPushedRequests(store).set(requestUri, {
      params: body,
      expiresAt: Math.floor(Date.now() / 1000) + expiresIn,
    });
    return c.json({ request_uri: requestUri, expires_in: expiresIn }, 201);
  });
}

function registrationRoutes({ app, store, baseUrl }: RouteContext): void {
  const as = getAuth0Store(store);

  // POST /oidc/register — Dynamic Client Registration (RFC 7591).
  app.post("/oidc/register", async (c) => {
    const body = (await readJson(c)) as Record<string, unknown>;
    const redirectUris = Array.isArray(body.redirect_uris)
      ? (body.redirect_uris as unknown[]).filter((u): u is string => typeof u === "string")
      : [];
    const name = typeof body.client_name === "string" ? body.client_name : "Dynamic Client";
    const now = nowUnix();
    const clientId = generateAuth0Id();
    const clientSecret = generateAuth0Id() + generateAuth0Id();
    as.clients.insert({
      client_id: clientId,
      client_secret: clientSecret,
      name,
      description: null,
      app_type: "regular_web",
      token_endpoint_auth_method: "client_secret_post",
      callbacks: redirectUris,
      allowed_logout_urls: [],
      web_origins: [],
      grant_types: ["authorization_code", "refresh_token"],
      created_at_unix: now,
      updated_at_unix: now,
    });
    return c.json(
      {
        client_id: clientId,
        client_secret: clientSecret,
        client_name: name,
        redirect_uris: redirectUris,
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        client_id_issued_at: now,
        registration_client_uri: `${baseUrl}/oidc/register/${clientId}`,
      },
      201,
    );
  });
}

// Minimal passkey (WebAuthn) ceremony. We do not perform real attestation; the
// challenge round-trips and registration records a webauthn enrollment so the
// shape is correct for SDK exercising.
function passkeyRoutes({ app, store }: RouteContext): void {
  const as = getAuth0Store(store);

  app.post("/passkey/challenge", async (c) => {
    await readJson(c);
    const challenge = randomBytes(32).toString("base64url");
    return c.json({
      auth_session: randomBytes(16).toString("hex"),
      authn_params_public_key: {
        challenge,
        rpId: "localhost",
        userVerification: "preferred",
        timeout: 60000,
      },
    });
  });

  app.post("/passkey/register", async (c) => {
    const body = (await readJson(c)) as Record<string, unknown>;
    const email = typeof body.email === "string" ? body.email : "";
    const user = email ? as.users.findOneBy("email", email) : as.users.all()[0];
    if (user) {
      as.userEnrollments.insert({
        enrollment_id: `pk_${generateAuth0Id().slice(0, 16)}`,
        user_id: user.user_id,
        type: "webauthn-roaming",
        oob_channel: null,
        secret: null,
        name: "Passkey",
        status: "confirmed",
        created_at_unix: nowUnix(),
      });
    }
    return c.json({ registered: true });
  });
}

// Deprecated endpoints — return correctly shaped responses / deprecation errors.
function legacyStubRoutes({ app, store, baseUrl }: RouteContext): void {
  const as = getAuth0Store(store);

  // GET /tokeninfo — legacy id_token introspection (deprecated). Auth0 disabled
  // this for new tenants; return the deprecation error shape.
  app.get("/tokeninfo", (c) =>
    c.json({ error: "access_denied", error_description: "The /tokeninfo endpoint is disabled for this tenant." }, 403),
  );
  app.post("/tokeninfo", (c) =>
    c.json({ error: "access_denied", error_description: "The /tokeninfo endpoint is disabled for this tenant." }, 403),
  );

  // POST /oauth/ro — legacy resource-owner password (superseded by password
  // grant on /oauth/token). Return the deprecation error.
  app.post("/oauth/ro", (c) =>
    oauthError(
      c,
      403,
      "unauthorized_client",
      "The /oauth/ro endpoint is deprecated. Use the password grant on /oauth/token.",
    ),
  );

  // POST /co/authenticate — legacy cross-origin authentication first step.
  // Returns a login_ticket the way the real endpoint does.
  app.post("/co/authenticate", async (c) => {
    const body = (await readJson(c)) as Record<string, unknown>;
    const username = typeof body.username === "string" ? body.username : "";
    const user = as.users.findOneBy("email", username) ?? as.users.findOneBy("username", username);
    if (!user || (typeof body.password === "string" && user.password !== body.password)) {
      return oauthError(c, 401, "invalid_grant", "Wrong email or password.");
    }
    return c.json({
      login_ticket: randomBytes(16).toString("hex"),
      co_verifier: randomBytes(8).toString("hex"),
      co_id: randomBytes(4).toString("hex"),
    });
  });

  void baseUrl;
}

async function readForm(c: Context<AppEnv>): Promise<Record<string, string>> {
  try {
    const contentType = c.req.header("Content-Type") ?? "";
    if (contentType.includes("application/json")) {
      const json = (await c.req.json()) as Record<string, unknown>;
      const out: Record<string, string> = {};
      for (const [k, v] of Object.entries(json)) if (typeof v === "string") out[k] = v;
      return out;
    }
    return Object.fromEntries(new URLSearchParams(await c.req.text()));
  } catch {
    return {};
  }
}

async function readJson(c: Context<AppEnv>): Promise<unknown> {
  try {
    return await c.req.json();
  } catch {
    return {};
  }
}
