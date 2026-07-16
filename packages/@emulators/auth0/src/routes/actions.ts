import type { RouteContext } from "@emulators/core";
import type { Auth0Action, Auth0Hook, Auth0Rule } from "../entities.js";
import { getAuth0Store } from "../store.js";
import { generateAuth0Id, nowUnix } from "../helpers.js";
import { listEnvelope, mgmtError, parsePage, readJsonBody, requireManagementAuth } from "../route-helpers.js";
import { testAction, type ActionRunContext } from "../actions-runtime.js";

// Management API for Actions, their trigger bindings, and the legacy Rules and
// Hooks. The execution side lives in actions-runtime.ts; this module is CRUD +
// deploy/test plumbing.
export function actionRoutes(ctx: RouteContext): void {
  actionsApi(ctx);
  triggerApi(ctx);
  rulesApi(ctx);
  hooksApi(ctx);
}

function actionResponse(action: Auth0Action): Record<string, unknown> {
  return {
    id: action.action_id,
    name: action.name,
    supported_triggers: [{ id: action.trigger, version: "v3" }],
    code: action.code,
    dependencies: action.dependencies,
    secrets: action.secrets.map((s) => ({ name: s.name })),
    deployed: action.deployed,
    status: action.deployed ? "built" : "pending",
    created_at: new Date(action.created_at_unix * 1000).toISOString(),
    updated_at: new Date(action.updated_at_unix * 1000).toISOString(),
  };
}

function actionsApi({ app, store, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  app.get("/api/v2/actions/actions", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const triggerId = c.req.query("triggerId");
    let actions = as.actions.all();
    if (triggerId) actions = actions.filter((a) => a.trigger === triggerId);
    const { page, perPage, includeTotals } = parsePage(c);
    return c.json(listEnvelope("actions", actions.map(actionResponse), page, perPage, includeTotals));
  });

  app.post("/api/v2/actions/actions", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonBody(c);
    const name = typeof body.name === "string" ? body.name : "";
    if (!name) return mgmtError(c, 400, "Bad Request", "The 'name' field is required.", "invalid_body");
    const triggers = Array.isArray(body.supported_triggers) ? (body.supported_triggers as unknown[]) : [];
    const trigger =
      triggers[0] && typeof triggers[0] === "object" && "id" in (triggers[0] as object)
        ? String((triggers[0] as { id: unknown }).id)
        : "post-login";
    const now = nowUnix();
    const created = as.actions.insert({
      action_id: `act_${generateAuth0Id().slice(0, 20)}`,
      name,
      trigger,
      code: typeof body.code === "string" ? body.code : "",
      config: null,
      dependencies: Array.isArray(body.dependencies) ? (body.dependencies as Auth0Action["dependencies"]) : [],
      secrets: Array.isArray(body.secrets) ? (body.secrets as Auth0Action["secrets"]) : [],
      deployed: false,
      created_at_unix: now,
      updated_at_unix: now,
    });
    return c.json(actionResponse(created), 201);
  });

  app.get("/api/v2/actions/actions/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const action = as.actions.findOneBy("action_id", c.req.param("id"));
    if (!action) return mgmtError(c, 404, "Not Found", "The action does not exist.", "inexistent_action");
    return c.json(actionResponse(action));
  });

  app.patch("/api/v2/actions/actions/:id", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const action = as.actions.findOneBy("action_id", c.req.param("id"));
    if (!action) return mgmtError(c, 404, "Not Found", "The action does not exist.", "inexistent_action");
    const body = await readJsonBody(c);
    const updates: Record<string, unknown> = { updated_at_unix: nowUnix() };
    if (typeof body.name === "string") updates.name = body.name;
    if (typeof body.code === "string") updates.code = body.code;
    if (Array.isArray(body.dependencies)) updates.dependencies = body.dependencies;
    if (Array.isArray(body.secrets)) updates.secrets = body.secrets;
    const updated = as.actions.update(action.id, updates);
    return c.json(actionResponse(updated ?? action));
  });

  app.delete("/api/v2/actions/actions/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const action = as.actions.findOneBy("action_id", c.req.param("id"));
    if (action) {
      for (const binding of as.actionBindings.findBy("action_id", action.action_id)) {
        as.actionBindings.delete(binding.id);
      }
      as.actions.delete(action.id);
    }
    return new Response(null, { status: 204 });
  });

  // Deploy an action (marks it executable in the pipeline).
  app.post("/api/v2/actions/actions/:id/deploy", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const action = as.actions.findOneBy("action_id", c.req.param("id"));
    if (!action) return mgmtError(c, 404, "Not Found", "The action does not exist.", "inexistent_action");
    const updated = as.actions.update(action.id, { deployed: true, updated_at_unix: nowUnix() });
    return c.json(actionResponse(updated ?? action));
  });

  // Test an action against a synthetic event.
  app.post("/api/v2/actions/actions/:id/test", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const action = as.actions.findOneBy("action_id", c.req.param("id"));
    if (!action) return mgmtError(c, 404, "Not Found", "The action does not exist.", "inexistent_action");
    const sampleUser = as.users.all()[0];
    if (!sampleUser) return c.json({ payload: {} });
    const runCtx: ActionRunContext = {
      trigger: action.trigger,
      user: sampleUser,
      clientId: "test",
      clientName: "Test",
      ip: "127.0.0.1",
      scope: "openid profile email",
      audience: "",
      orgId: null,
      orgName: null,
      requestQuery: {},
    };
    const result = await testAction(store, action, runCtx);
    return c.json({
      payload: {
        idToken: result.idTokenClaims,
        accessToken: result.accessTokenClaims,
        denied: result.denied,
        mfaRequired: result.mfaRequired,
      },
    });
  });
}

function triggerApi({ app, store, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  const TRIGGERS = [
    "post-login",
    "credentials-exchange",
    "pre-user-registration",
    "post-user-registration",
    "post-change-password",
    "send-phone-message",
  ];

  app.get("/api/v2/actions/triggers", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    return c.json({ triggers: TRIGGERS.map((id) => ({ id, version: "v3", status: "CURRENT" })) });
  });

  app.get("/api/v2/actions/triggers/:trigger/bindings", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const trigger = c.req.param("trigger");
    const bindings = as.actionBindings
      .findBy("trigger", trigger)
      .slice()
      .sort((a, b) => a.order - b.order)
      .map((b) => ({
        id: `bnd_${b.action_id}`,
        trigger_id: b.trigger,
        display_name: b.display_name,
        action: { id: b.action_id, name: as.actions.findOneBy("action_id", b.action_id)?.name ?? "" },
      }));
    return c.json({ bindings });
  });

  // PATCH bindings — replace the ordered binding set for a trigger.
  app.patch("/api/v2/actions/triggers/:trigger/bindings", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const trigger = c.req.param("trigger");
    const body = await readJsonBody(c);
    const incoming = Array.isArray(body.bindings) ? (body.bindings as unknown[]) : [];
    // Clear existing bindings for the trigger.
    for (const existing of as.actionBindings.findBy("trigger", trigger)) as.actionBindings.delete(existing.id);
    let order = 0;
    for (const entry of incoming) {
      if (!entry || typeof entry !== "object") continue;
      const ref = (entry as { ref?: { value?: string }; display_name?: string }).ref;
      const displayName = (entry as { display_name?: string }).display_name ?? "";
      const actionRef = ref?.value ?? "";
      // ref.value may be an action id or name.
      const action = as.actions.findOneBy("action_id", actionRef) ?? as.actions.findOneBy("name", actionRef);
      if (!action) continue;
      as.actionBindings.insert({
        trigger,
        action_id: action.action_id,
        display_name: displayName || action.name,
        order: order++,
      });
    }
    return c.json({ bindings: as.actionBindings.findBy("trigger", trigger).map((b) => ({ id: b.action_id })) });
  });
}

function rulesApi({ app, store, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  const ruleResponse = (r: Auth0Rule) => ({
    id: r.rule_id,
    name: r.name,
    script: r.script,
    order: r.order,
    enabled: r.enabled,
    stage: "login_success",
  });

  app.get("/api/v2/rules", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const { page, perPage, includeTotals } = parsePage(c);
    const rules = as.rules
      .all()
      .slice()
      .sort((a, b) => a.order - b.order)
      .map(ruleResponse);
    return c.json(listEnvelope("rules", rules, page, perPage, includeTotals));
  });

  app.post("/api/v2/rules", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonBody(c);
    const name = typeof body.name === "string" ? body.name : "";
    if (!name) return mgmtError(c, 400, "Bad Request", "The 'name' field is required.", "invalid_body");
    const now = nowUnix();
    const created = as.rules.insert({
      rule_id: `rul_${generateAuth0Id().slice(0, 20)}`,
      name,
      script: typeof body.script === "string" ? body.script : "",
      order: typeof body.order === "number" ? body.order : as.rules.all().length,
      enabled: body.enabled !== false,
      created_at_unix: now,
      updated_at_unix: now,
    });
    return c.json(ruleResponse(created), 201);
  });

  app.patch("/api/v2/rules/:id", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const rule = as.rules.findOneBy("rule_id", c.req.param("id"));
    if (!rule) return mgmtError(c, 404, "Not Found", "The rule does not exist.", "inexistent_rule");
    const body = await readJsonBody(c);
    const updates: Record<string, unknown> = { updated_at_unix: nowUnix() };
    if (typeof body.name === "string") updates.name = body.name;
    if (typeof body.script === "string") updates.script = body.script;
    if (typeof body.order === "number") updates.order = body.order;
    if (typeof body.enabled === "boolean") updates.enabled = body.enabled;
    const updated = as.rules.update(rule.id, updates);
    return c.json(ruleResponse(updated ?? rule));
  });

  app.delete("/api/v2/rules/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const rule = as.rules.findOneBy("rule_id", c.req.param("id"));
    if (rule) as.rules.delete(rule.id);
    return new Response(null, { status: 204 });
  });
}

function hooksApi({ app, store, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  const hookResponse = (h: Auth0Hook) => ({
    id: h.hook_id,
    name: h.name,
    triggerId: h.triggerId,
    script: h.script,
    enabled: h.enabled,
  });

  app.get("/api/v2/hooks", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const { page, perPage, includeTotals } = parsePage(c);
    return c.json(listEnvelope("hooks", as.hooks.all().map(hookResponse), page, perPage, includeTotals));
  });

  app.post("/api/v2/hooks", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonBody(c);
    const name = typeof body.name === "string" ? body.name : "";
    if (!name) return mgmtError(c, 400, "Bad Request", "The 'name' field is required.", "invalid_body");
    const now = nowUnix();
    const created = as.hooks.insert({
      hook_id: `hook_${generateAuth0Id().slice(0, 20)}`,
      name,
      triggerId: typeof body.triggerId === "string" ? body.triggerId : "credentials-exchange",
      script: typeof body.script === "string" ? body.script : "",
      enabled: body.enabled !== false,
      created_at_unix: now,
      updated_at_unix: now,
    });
    return c.json(hookResponse(created), 201);
  });

  app.patch("/api/v2/hooks/:id", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const hook = as.hooks.findOneBy("hook_id", c.req.param("id"));
    if (!hook) return mgmtError(c, 404, "Not Found", "The hook does not exist.", "inexistent_hook");
    const body = await readJsonBody(c);
    const updates: Record<string, unknown> = { updated_at_unix: nowUnix() };
    if (typeof body.name === "string") updates.name = body.name;
    if (typeof body.script === "string") updates.script = body.script;
    if (typeof body.enabled === "boolean") updates.enabled = body.enabled;
    const updated = as.hooks.update(hook.id, updates);
    return c.json(hookResponse(updated ?? hook));
  });

  app.delete("/api/v2/hooks/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const hook = as.hooks.findOneBy("hook_id", c.req.param("id"));
    if (hook) as.hooks.delete(hook.id);
    return new Response(null, { status: 204 });
  });
}
