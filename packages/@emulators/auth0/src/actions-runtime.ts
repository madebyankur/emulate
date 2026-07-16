import { createContext, Script } from "node:vm";
import type { Store } from "@emulators/core";
import type { Auth0Action, Auth0ActionConfig, Auth0Hook, Auth0Rule, Auth0User } from "./entities.js";
import { getAuth0Store } from "./store.js";
import { userRoleNames } from "./route-helpers.js";
import { recordLog } from "./events.js";

// The execution engine for Auth0 extensibility: Actions (post-login,
// credentials-exchange, ...), legacy Rules, and legacy Hooks. Each mechanism is
// normalized into a single ActionResult accumulator so the token layer never
// needs to know which one produced a claim.
//
// Two execution paths are supported, matching the user's requirement:
//   1. Config-driven (declarative): an action with a `config` object and no
//      `code` mutates the result deterministically. Safe and test-friendly.
//   2. Real JS: an action with `code` runs in a node:vm sandbox with the Auth0
//      `event`/`api` objects. NOT a security boundary, but bounded by a 1s
//      timeout and a sandbox without require/process/globalThis escape hatches.

const SCRIPT_TIMEOUT_MS = 1000;

export interface ActionRunContext {
  trigger: string;
  user: Auth0User;
  clientId: string;
  clientName: string;
  ip: string | null;
  scope: string;
  audience: string;
  orgId: string | null;
  orgName: string | null;
  requestQuery: Record<string, string>;
}

export interface ActionResult {
  idTokenClaims: Record<string, unknown>;
  accessTokenClaims: Record<string, unknown>;
  // Non-null when an action denied the transaction; the value is the reason.
  denied: string | null;
  // True when an action enabled MFA for the transaction.
  mfaRequired: boolean;
  // Metadata mutations to merge back onto the user.
  appMetadata: Record<string, unknown>;
  userMetadata: Record<string, unknown>;
}

function emptyResult(): ActionResult {
  return {
    idTokenClaims: {},
    accessTokenClaims: {},
    denied: null,
    mfaRequired: false,
    appMetadata: {},
    userMetadata: {},
  };
}

// Build the Auth0 `event` object exposed to action/rule code (read-only view).
function buildEvent(ctx: ActionRunContext, roles: string[]): Record<string, unknown> {
  return {
    user: {
      user_id: ctx.user.user_id,
      email: ctx.user.email,
      email_verified: ctx.user.email_verified,
      name: ctx.user.name,
      nickname: ctx.user.nickname,
      username: ctx.user.username,
      app_metadata: { ...ctx.user.app_metadata },
      user_metadata: { ...ctx.user.user_metadata },
    },
    client: { client_id: ctx.clientId, name: ctx.clientName },
    request: { ip: ctx.ip, query: ctx.requestQuery, hostname: "localhost" },
    authorization: { roles },
    organization: ctx.orgId ? { id: ctx.orgId, name: ctx.orgName } : undefined,
    transaction: { requested_scopes: ctx.scope.split(/\s+/).filter(Boolean) },
    secrets: {},
  };
}

// Build the Auth0 `api` object: every method mutates the shared result.
function buildApi(result: ActionResult): Record<string, unknown> {
  return {
    idToken: {
      setCustomClaim: (name: string, value: unknown) => {
        result.idTokenClaims[name] = value;
      },
    },
    accessToken: {
      setCustomClaim: (name: string, value: unknown) => {
        result.accessTokenClaims[name] = value;
      },
    },
    access: {
      deny: (reason: string) => {
        result.denied = reason || "access_denied";
      },
    },
    multifactor: {
      enable: (_provider?: string, _options?: unknown) => {
        result.mfaRequired = true;
      },
    },
    user: {
      setAppMetadata: (key: string, value: unknown) => {
        result.appMetadata[key] = value;
      },
      setUserMetadata: (key: string, value: unknown) => {
        result.userMetadata[key] = value;
      },
    },
  };
}

// Apply a declarative, code-free action config to the result.
function applyConfig(config: Auth0ActionConfig, result: ActionResult): void {
  if (config.addClaims?.idToken) Object.assign(result.idTokenClaims, config.addClaims.idToken);
  if (config.addClaims?.accessToken) Object.assign(result.accessTokenClaims, config.addClaims.accessToken);
  if (config.setAppMetadata) Object.assign(result.appMetadata, config.setAppMetadata);
  if (config.setUserMetadata) Object.assign(result.userMetadata, config.setUserMetadata);
  if (config.requireMfa) result.mfaRequired = true;
  if (config.denyWith) result.denied = config.denyWith;
}

// Run a single piece of action code in the sandbox. The code is expected to
// define `exports.onExecutePostLogin` (or the trigger-appropriate handler).
async function runActionCode(
  code: string,
  handlerName: string,
  event: Record<string, unknown>,
  api: Record<string, unknown>,
): Promise<void> {
  const moduleObj = { exports: {} as Record<string, unknown> };
  const sandbox = {
    module: moduleObj,
    exports: moduleObj.exports,
    console: { log: () => {}, error: () => {}, warn: () => {} },
  };
  const context = createContext(sandbox);
  new Script(code).runInContext(context, { timeout: SCRIPT_TIMEOUT_MS });
  const handler = (moduleObj.exports[handlerName] ?? sandbox.exports[handlerName]) as
    | ((event: unknown, api: unknown) => unknown)
    | undefined;
  if (typeof handler === "function") {
    await handler(event, api);
  }
}

// Map an Action trigger to the handler name Auth0 expects the code to export.
function handlerForTrigger(trigger: string): string {
  switch (trigger) {
    case "credentials-exchange":
      return "onExecuteCredentialsExchange";
    case "pre-user-registration":
      return "onExecutePreUserRegistration";
    case "post-user-registration":
      return "onExecutePostUserRegistration";
    default:
      return "onExecutePostLogin";
  }
}

// Run all Actions bound to a trigger (in binding order), then legacy Rules /
// Hooks where applicable, accumulating into a single result.
export async function runActionPipeline(store: Store, ctx: ActionRunContext): Promise<ActionResult> {
  const as = getAuth0Store(store);
  const result = emptyResult();
  const roles = userRoleNames(as, ctx.user.user_id);

  const bindings = as.actionBindings
    .findBy("trigger", ctx.trigger)
    .slice()
    .sort((a, b) => a.order - b.order);

  for (const binding of bindings) {
    const action = as.actions.findOneBy("action_id", binding.action_id);
    if (!action || !action.deployed) continue;
    await runOne(action, ctx, roles, result, store);
    if (result.denied) break;
  }

  // Legacy Rules run on the login (post-login-equivalent) trigger, in order.
  if (ctx.trigger === "post-login") {
    const rules = as.rules
      .all()
      .filter((r) => r.enabled)
      .sort((a, b) => a.order - b.order);
    for (const rule of rules) {
      await runRule(rule, ctx, roles, result, store);
      if (result.denied) break;
    }
  }

  return result;
}

async function runOne(
  action: Auth0Action,
  ctx: ActionRunContext,
  roles: string[],
  result: ActionResult,
  store: Store,
): Promise<void> {
  if (action.config) applyConfig(action.config, result);
  if (action.code && action.code.trim().length > 0) {
    try {
      await runActionCode(action.code, handlerForTrigger(action.trigger), buildEvent(ctx, roles), buildApi(result));
    } catch (err) {
      // Auth0 aborts the transaction when an action throws.
      result.denied = err instanceof Error ? err.message : "Action execution failed.";
      await recordLog(store, {
        type: "f",
        description: `Action '${action.name}' threw: ${result.denied}`,
        userId: ctx.user.user_id,
      });
    }
  }
}

// Legacy Rule signature: function (user, context, callback). We expose a
// context with idToken/accessToken accumulators and complete via callback.
async function runRule(
  rule: Auth0Rule,
  ctx: ActionRunContext,
  roles: string[],
  result: ActionResult,
  store: Store,
): Promise<void> {
  const ruleContext = {
    clientID: ctx.clientId,
    clientName: ctx.clientName,
    idToken: {} as Record<string, unknown>,
    accessToken: {} as Record<string, unknown>,
    authorization: { roles },
  };
  const ruleUser = {
    user_id: ctx.user.user_id,
    email: ctx.user.email,
    app_metadata: { ...ctx.user.app_metadata },
    user_metadata: { ...ctx.user.user_metadata },
  };

  await new Promise<void>((resolve) => {
    let settled = false;
    const callback = (err: unknown) => {
      if (settled) return;
      settled = true;
      if (err) result.denied = err instanceof Error ? err.message : String(err);
      Object.assign(result.idTokenClaims, ruleContext.idToken);
      Object.assign(result.accessTokenClaims, ruleContext.accessToken);
      resolve();
    };
    try {
      const sandbox = {
        module: { exports: {} },
        exports: {},
        console: { log: () => {}, error: () => {}, warn: () => {} },
        UnauthorizedError: class UnauthorizedError extends Error {},
      };
      const context = createContext(sandbox);
      // Wrap the rule body so we can invoke it with our arguments.
      const wrapped = `(${rule.script})`;
      const fn = new Script(wrapped).runInContext(context, { timeout: SCRIPT_TIMEOUT_MS }) as (
        user: unknown,
        context: unknown,
        callback: (err: unknown, user?: unknown, context?: unknown) => void,
      ) => void;
      if (typeof fn === "function") {
        fn(ruleUser, ruleContext, callback);
      } else {
        callback(null);
      }
    } catch (err) {
      void recordLog(store, {
        type: "f",
        description: `Rule '${rule.name}' threw: ${err instanceof Error ? err.message : String(err)}`,
        userId: ctx.user.user_id,
      });
      callback(err);
    }
  });
}

// Run the credentials-exchange trigger (client_credentials / M2M). There is no
// user; actions can only inject access-token claims. Returns the access-token
// claims to merge.
export async function runCredentialsExchange(
  store: Store,
  clientId: string,
  clientName: string,
  audience: string,
  scope: string,
): Promise<Record<string, unknown>> {
  const as = getAuth0Store(store);
  const result = emptyResult();
  const bindings = as.actionBindings
    .findBy("trigger", "credentials-exchange")
    .slice()
    .sort((a, b) => a.order - b.order);

  const event: Record<string, unknown> = {
    client: { client_id: clientId, name: clientName },
    transaction: { requested_scopes: scope.split(/\s+/).filter(Boolean) },
    request: { ip: null, hostname: "localhost" },
    resource_server: { identifier: audience },
    secrets: {},
  };

  for (const binding of bindings) {
    const action = as.actions.findOneBy("action_id", binding.action_id);
    if (!action || !action.deployed) continue;
    if (action.config) applyConfig(action.config, result);
    if (action.code && action.code.trim().length > 0) {
      try {
        await runActionCode(action.code, "onExecuteCredentialsExchange", event, buildApi(result));
      } catch {
        // M2M action failures are non-fatal in the emulator.
      }
    }
  }
  return result.accessTokenClaims;
}

// Expose for the actions/:id/test endpoint: run a single action's code/config
// against a synthetic event and return the resulting mutations.
export async function testAction(store: Store, action: Auth0Action, ctx: ActionRunContext): Promise<ActionResult> {
  const as = getAuth0Store(store);
  const roles = userRoleNames(as, ctx.user.user_id);
  const result = emptyResult();
  await runOne(action, ctx, roles, result, store);
  return result;
}

export type { Auth0Hook };
