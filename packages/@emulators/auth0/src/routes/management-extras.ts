import type { RouteContext, Store } from "@emulators/core";
import { getAuth0Store } from "../store.js";
import {
  findUserByRef,
  getAccessTokens,
  getRefreshTokens,
  listEnvelope,
  mgmtError,
  parsePage,
  readJsonBody,
  requireManagementAuth,
} from "../route-helpers.js";
import { generateAuth0Id, nowUnix } from "../helpers.js";
import { publicJwk, KID } from "../keys.js";
import { recordLog } from "../events.js";
import { getAttackConfig } from "../attack-protection.js";

// The breadth of remaining Management API families. Config-style resources are
// backed by Store.getData key/value blobs; entity-style resources (jobs,
// sessions) use collections. Everything is guarded by requireManagementAuth.
export function managementExtraRoutes(ctx: RouteContext): void {
  grantsApi(ctx);
  deviceCredentialsApi(ctx);
  jobsApi(ctx);
  emailApi(ctx);
  brandingPromptsApi(ctx);
  keysApi(ctx);
  sessionsApi(ctx);
  anomalyBlacklistApi(ctx);
  statsApi(ctx);
  configEchoApi(ctx);
}

// A small helper for config-blob resources: GET returns the stored value (or a
// default), PATCH/PUT shallow-merges.
function configResource<T extends Record<string, unknown>>(
  ctx: RouteContext,
  path: string,
  key: string,
  fallback: () => T,
  methods: { read?: boolean; patch?: boolean; put?: boolean } = { read: true, patch: true },
): void {
  const { app, store, tokenMap } = ctx;
  const get = (): T => store.getData<T>(key) ?? fallback();

  if (methods.read !== false) {
    app.get(path, (c) => {
      const auth = requireManagementAuth(c, tokenMap);
      if (auth instanceof Response) return auth;
      return c.json(get());
    });
  }
  if (methods.patch) {
    app.patch(path, async (c) => {
      const auth = requireManagementAuth(c, tokenMap);
      if (auth instanceof Response) return auth;
      const body = await readJsonBody(c);
      const next = { ...get(), ...body } as T;
      store.setData(key, next);
      return c.json(next);
    });
  }
  if (methods.put) {
    app.put(path, async (c) => {
      const auth = requireManagementAuth(c, tokenMap);
      if (auth instanceof Response) return auth;
      const body = await readJsonBody(c);
      store.setData(key, body as T);
      return c.json(body);
    });
  }
}

// --- Grants (user authorizations) ---
function grantsApi({ app, store, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);
  // We model grants as the (user, client, audience, scopes) authorizations
  // derived from issued tokens; a dedicated collection is overkill, so we
  // surface client grants joined with sessions as a reasonable approximation.
  app.get("/api/v2/grants", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const userId = c.req.query("user_id");
    const grants = getGrants(store).filter((g) => !userId || g.user_id === userId);
    const { page, perPage, includeTotals } = parsePage(c);
    return c.json(listEnvelope("grants", grants, page, perPage, includeTotals));
  });

  app.delete("/api/v2/grants/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    deleteGrant(store, c.req.param("id"));
    return new Response(null, { status: 204 });
  });

  // user_id-scoped bulk delete (revoke all of a user's grants).
  app.delete("/api/v2/grants", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const userId = c.req.query("user_id");
    if (userId) {
      for (const g of getGrants(store).filter((g) => g.user_id === userId)) deleteGrant(store, g.id);
    }
    return new Response(null, { status: 204 });
  });

  void as;
}

interface GrantRecord {
  id: string;
  user_id: string;
  clientID: string;
  audience: string;
  scope: string[];
}

function getGrants(store: Store): GrantRecord[] {
  return store.getData<GrantRecord[]>("auth0.grants") ?? [];
}

function deleteGrant(store: Store, id: string): void {
  const grants = getGrants(store).filter((g) => g.id !== id);
  store.setData("auth0.grants", grants);
}

// --- Device credentials (public-key / refresh-token credentials) ---
function deviceCredentialsApi({ app, store, tokenMap }: RouteContext): void {
  app.get("/api/v2/device-credentials", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const creds = store.getData<unknown[]>("auth0.device_credentials") ?? [];
    return c.json(creds);
  });

  app.post("/api/v2/device-credentials", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonBody(c);
    const creds = store.getData<Record<string, unknown>[]>("auth0.device_credentials") ?? [];
    const created = { id: `dcr_${generateAuth0Id().slice(0, 20)}`, ...body };
    creds.push(created);
    store.setData("auth0.device_credentials", creds);
    return c.json(created, 201);
  });

  app.delete("/api/v2/device-credentials/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const id = c.req.param("id");
    const creds = (store.getData<Record<string, unknown>[]>("auth0.device_credentials") ?? []).filter(
      (cr) => cr.id !== id,
    );
    store.setData("auth0.device_credentials", creds);
    return new Response(null, { status: 204 });
  });
}

// --- Jobs (verification email, users import/export) ---
function jobsApi({ app, store, baseUrl, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  app.post("/api/v2/jobs/verification-email", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonBody(c);
    const user = findUserByRef(as, typeof body.user_id === "string" ? body.user_id : "");
    if (!user) return mgmtError(c, 400, "Bad Request", "The user does not exist.", "inexistent_user");
    // Create a verification ticket as a side effect, like the real job does.
    const ticketId = generateAuth0Id();
    as.tickets.insert({
      ticket_id: ticketId,
      user_id: user.user_id,
      kind: "email_verification",
      consumed: false,
      created_at_unix: nowUnix(),
    });
    await recordLog(store, { type: "sv", description: "Verification email job", userId: user.user_id });
    const job = as.jobs.insert({
      job_id: `job_${generateAuth0Id().slice(0, 20)}`,
      type: "verification_email",
      status: "completed",
      connection_id: null,
      created_at_unix: nowUnix(),
    });
    return c.json(jobResponse(job, baseUrl, ticketId), 201);
  });

  app.post("/api/v2/jobs/users-imports", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const job = as.jobs.insert({
      job_id: `job_${generateAuth0Id().slice(0, 20)}`,
      type: "users_import",
      status: "completed",
      connection_id: null,
      created_at_unix: nowUnix(),
    });
    return c.json(jobResponse(job, baseUrl), 201);
  });

  app.post("/api/v2/jobs/users-exports", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const job = as.jobs.insert({
      job_id: `job_${generateAuth0Id().slice(0, 20)}`,
      type: "users_export",
      status: "completed",
      connection_id: null,
      created_at_unix: nowUnix(),
    });
    return c.json(jobResponse(job, baseUrl), 201);
  });

  app.get("/api/v2/jobs/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const job = as.jobs.findOneBy("job_id", c.req.param("id"));
    if (!job) return mgmtError(c, 404, "Not Found", "The job does not exist.", "inexistent_job");
    return c.json(jobResponse(job, baseUrl));
  });
}

function jobResponse(
  job: { job_id: string; type: string; status: string; created_at_unix: number },
  baseUrl: string,
  ticketId?: string,
): Record<string, unknown> {
  const resp: Record<string, unknown> = {
    id: job.job_id,
    type: job.type,
    status: job.status,
    created_at: new Date(job.created_at_unix * 1000).toISOString(),
  };
  if (job.type === "users_export") resp.location = `${baseUrl}/_emulate/jobs/${job.job_id}/export.json`;
  if (ticketId) resp.ticket = `${baseUrl}/u/email-verification?ticket=${ticketId}`;
  return resp;
}

// --- Email templates and provider ---
function emailApi({ app, store, tokenMap }: RouteContext): void {
  app.get("/api/v2/email-templates/:name", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const name = c.req.param("name");
    const templates = store.getData<Record<string, unknown>>("auth0.email_templates") ?? {};
    const tpl = templates[name] ?? {
      template: name,
      enabled: true,
      from: "",
      subject: "",
      body: "",
      syntax: "liquid",
    };
    return c.json(tpl);
  });

  app.patch("/api/v2/email-templates/:name", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const name = c.req.param("name");
    const body = await readJsonBody(c);
    const templates = store.getData<Record<string, unknown>>("auth0.email_templates") ?? {};
    const next = { ...(templates[name] as Record<string, unknown>), ...body, template: name };
    templates[name] = next;
    store.setData("auth0.email_templates", templates);
    return c.json(next);
  });

  app.put("/api/v2/email-templates/:name", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const name = c.req.param("name");
    const body = await readJsonBody(c);
    const templates = store.getData<Record<string, unknown>>("auth0.email_templates") ?? {};
    templates[name] = { ...body, template: name };
    store.setData("auth0.email_templates", templates);
    return c.json(templates[name], 201);
  });

  configResource(
    { app, store, tokenMap } as RouteContext,
    "/api/v2/emails/provider",
    "auth0.email_provider",
    () => ({ name: "smtp", enabled: true, credentials: {}, settings: {} }),
    { read: true, patch: true },
  );
}

// --- Branding and prompts ---
function brandingPromptsApi(ctx: RouteContext): void {
  configResource(ctx, "/api/v2/branding", "auth0.branding", () => ({
    colors: { primary: "#635dff", page_background: "#000000" },
    favicon_url: "",
    logo_url: "",
    font: { url: "" },
  }));

  configResource(ctx, "/api/v2/branding/themes/default", "auth0.branding_theme", () => ({
    themeId: "default",
    displayName: "Default",
    colors: { primary_button: "#635dff" },
  }));

  configResource(ctx, "/api/v2/prompts", "auth0.prompts", () => ({
    universal_login_experience: "new",
    identifier_first: true,
    webauthn_platform_first_factor: false,
  }));

  // Prompt custom text is keyed by prompt + language.
  const { app, store, tokenMap } = ctx;
  app.get("/api/v2/prompts/:prompt/custom-text/:lang", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const key = `auth0.prompt_text.${c.req.param("prompt")}.${c.req.param("lang")}`;
    return c.json(store.getData<Record<string, unknown>>(key) ?? {});
  });

  app.put("/api/v2/prompts/:prompt/custom-text/:lang", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const key = `auth0.prompt_text.${c.req.param("prompt")}.${c.req.param("lang")}`;
    const body = await readJsonBody(c);
    store.setData(key, body);
    return c.json(body);
  });
}

// --- Signing / encryption keys ---
function keysApi({ app, store, tokenMap }: RouteContext): void {
  app.get("/api/v2/keys/signing", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const jwk = await publicJwk();
    return c.json([
      {
        kid: KID,
        cert: "",
        current: true,
        next: false,
        previous: false,
        current_since: new Date(0).toISOString(),
        fingerprint: KID,
        thumbprint: KID,
        revoked: false,
        jwk,
      },
    ]);
  });

  app.get("/api/v2/keys/signing/:kid", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    if (c.req.param("kid") !== KID) {
      return mgmtError(c, 404, "Not Found", "Signing key not found.", "key_not_found");
    }
    return c.json({ kid: KID, current: true, revoked: false, jwk: await publicJwk() });
  });

  // Rotation/revocation are no-ops in the emulator (single static key) but
  // return the Auth0-shaped acknowledgement so tooling does not error.
  app.post("/api/v2/keys/signing/rotate", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    return c.json({ message: "Rotation is a no-op in the emulator.", kid: KID });
  });

  app.put("/api/v2/keys/signing/:kid/revoke", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    return c.json({ message: "Revocation is a no-op in the emulator.", kid: c.req.param("kid") });
  });

  void store;
}

// --- Sessions and refresh tokens ---
function sessionsApi({ app, store, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  const sessionResponse = (s: {
    session_id: string;
    user_id: string;
    client_id: string | null;
    created_at_unix: number;
    last_interacted_unix: number;
  }) => ({
    id: s.session_id,
    user_id: s.user_id,
    created_at: new Date(s.created_at_unix * 1000).toISOString(),
    updated_at: new Date(s.last_interacted_unix * 1000).toISOString(),
    clients: s.client_id ? [{ client_id: s.client_id }] : [],
  });

  app.get("/api/v2/sessions/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const session = as.sessions.findOneBy("session_id", c.req.param("id"));
    if (!session) return mgmtError(c, 404, "Not Found", "The session does not exist.", "inexistent_session");
    return c.json(sessionResponse(session));
  });

  app.delete("/api/v2/sessions/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const session = as.sessions.findOneBy("session_id", c.req.param("id"));
    if (session) as.sessions.delete(session.id);
    return new Response(null, { status: 204 });
  });

  app.get("/api/v2/users/:id/sessions", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(as, c.req.param("id"));
    if (!user) return mgmtError(c, 404, "Not Found", "The user does not exist.", "inexistent_user");
    return c.json({ sessions: as.sessions.findBy("user_id", user.user_id).map(sessionResponse) });
  });

  app.delete("/api/v2/users/:id/sessions", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(as, c.req.param("id"));
    if (user) for (const s of as.sessions.findBy("user_id", user.user_id)) as.sessions.delete(s.id);
    return new Response(null, { status: 204 });
  });

  // Refresh tokens are kept in the OAuth token map; expose revoke + per-user.
  app.delete("/api/v2/refresh-tokens/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    getRefreshTokens(store).delete(c.req.param("id"));
    return new Response(null, { status: 204 });
  });

  app.delete("/api/v2/users/:id/refresh-tokens", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const user = findUserByRef(as, c.req.param("id"));
    if (user) {
      const map = getRefreshTokens(store);
      for (const [token, rec] of map.entries()) {
        if (rec.userId === user.user_id) map.delete(token);
      }
    }
    return new Response(null, { status: 204 });
  });

  void getAccessTokens;
}

// --- Anomaly blocks and blacklists ---
function anomalyBlacklistApi({ app, store, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  // Clearing an IP block removes any suspicious-ip user blocks for that IP and
  // resets the suspicious-ip counter (wiring into attack protection state).
  app.delete("/api/v2/anomaly/blocks/ips/:ip", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const ip = c.req.param("ip");
    for (const block of as.userBlocks.all().filter((b) => b.ip === ip)) as.userBlocks.delete(block.id);
    const counters = store.getData<Map<string, unknown>>("auth0.attackProtection.suspiciousIp");
    if (counters) counters.delete(ip);
    return new Response(null, { status: 204 });
  });

  app.get("/api/v2/anomaly/blocks/ips/:ip", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const ip = c.req.param("ip");
    const blocked = as.userBlocks.all().some((b) => b.ip === ip);
    return c.json({ blocked });
  });

  app.get("/api/v2/blacklists/tokens", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    return c.json(store.getData<unknown[]>("auth0.blacklisted_tokens") ?? []);
  });

  app.post("/api/v2/blacklists/tokens", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonBody(c);
    const list = store.getData<Record<string, unknown>[]>("auth0.blacklisted_tokens") ?? [];
    list.push(body);
    store.setData("auth0.blacklisted_tokens", list);
    return new Response(null, { status: 204 });
  });

  void getAttackConfig;
}

// --- Stats (derived from log events) ---
function statsApi({ app, store, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  app.get("/api/v2/stats/active-users", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const active = new Set(
      as.users
        .all()
        .filter((u) => u.last_login)
        .map((u) => u.user_id),
    );
    return c.json(active.size);
  });

  app.get("/api/v2/stats/daily", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const logins = as.logEvents.all().filter((l) => l.type.startsWith("s")).length;
    const signups = as.logEvents.all().filter((l) => l.type === "ss").length;
    const today = new Date(nowUnix() * 1000).toISOString().slice(0, 10).replace(/-/g, "");
    return c.json([{ date: `${today}T00:00:00.000Z`, logins, signups, leaked_passwords: 0 }]);
  });
}

// --- Config-echo families (custom domains, flows, forms, network ACLs, etc.) ---
function configEchoApi(ctx: RouteContext): void {
  const { app, store, tokenMap } = ctx;

  // Custom domains: list/create/get/delete with a verified status.
  app.get("/api/v2/custom-domains", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    return c.json(store.getData<unknown[]>("auth0.custom_domains") ?? []);
  });

  app.post("/api/v2/custom-domains", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonBody(c);
    const list = store.getData<Record<string, unknown>[]>("auth0.custom_domains") ?? [];
    const created = {
      custom_domain_id: `cd_${generateAuth0Id().slice(0, 20)}`,
      domain: body.domain ?? "",
      primary: list.length === 0,
      status: "ready",
      type: body.type ?? "auth0_managed_certs",
      verification: { methods: [] },
    };
    list.push(created);
    store.setData("auth0.custom_domains", list);
    return c.json(created, 201);
  });

  app.get("/api/v2/custom-domains/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const list = store.getData<Record<string, unknown>[]>("auth0.custom_domains") ?? [];
    const found = list.find((d) => d.custom_domain_id === c.req.param("id"));
    if (!found) return mgmtError(c, 404, "Not Found", "Custom domain not found.", "not_found");
    return c.json(found);
  });

  app.delete("/api/v2/custom-domains/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const list = (store.getData<Record<string, unknown>[]>("auth0.custom_domains") ?? []).filter(
      (d) => d.custom_domain_id !== c.req.param("id"),
    );
    store.setData("auth0.custom_domains", list);
    return new Response(null, { status: 204 });
  });

  // Generic list-backed collections for flows, forms, self-service-profiles.
  for (const [path, key] of [
    ["/api/v2/flows", "auth0.flows"],
    ["/api/v2/forms", "auth0.forms"],
    ["/api/v2/self-service-profiles", "auth0.self_service_profiles"],
  ] as const) {
    app.get(path, (c) => {
      const auth = requireManagementAuth(c, tokenMap);
      if (auth instanceof Response) return auth;
      return c.json(store.getData<unknown[]>(key) ?? []);
    });
    app.post(path, async (c) => {
      const auth = requireManagementAuth(c, tokenMap);
      if (auth instanceof Response) return auth;
      const body = await readJsonBody(c);
      const list = store.getData<Record<string, unknown>[]>(key) ?? [];
      const created = { id: generateAuth0Id(), ...body };
      list.push(created);
      store.setData(key, list);
      return c.json(created, 201);
    });
  }

  // Network ACLs as a config blob list.
  configResource(ctx, "/api/v2/network-acls", "auth0.network_acls", () => ({ rules: [] }));

  // Encryption keys (informational).
  configResource(
    ctx,
    "/api/v2/keys/encryption",
    "auth0.encryption_keys",
    () => ({ keys: [{ kid: "enc-1", type: "environment-root-key", state: "active" }] }),
    { read: true },
  );
}
