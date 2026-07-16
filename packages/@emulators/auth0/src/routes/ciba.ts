import { randomBytes } from "node:crypto";
import type { Context } from "@emulators/core";
import type { AppEnv, RouteContext, Store } from "@emulators/core";
import { getAuth0Store } from "../store.js";
import { oauthError } from "../route-helpers.js";

// CIBA (Client-Initiated Backchannel Authentication). A client starts a login
// out-of-band; the end-user approves on another channel; the client polls the
// token endpoint with the auth_req_id. This reuses the device-code poll shape.

export interface CibaRequest {
  authReqId: string;
  clientId: string;
  scope: string;
  audience: string;
  bindingMessage: string | null;
  approvedUserId: string | null;
  expiresAt: number;
}

export function getCibaRequests(store: Store): Map<string, CibaRequest> {
  let map = store.getData<Map<string, CibaRequest>>("auth0.ciba.requests");
  if (!map) {
    map = new Map();
    store.setData("auth0.ciba.requests", map);
  }
  return map;
}

export function cibaRoutes({ app, store }: RouteContext): void {
  const as = getAuth0Store(store);

  // POST /bc-authorize — start a backchannel authentication request.
  app.post("/bc-authorize", async (c) => {
    const body = await readBody(c);
    const clientId = str(body.client_id);
    const scope = str(body.scope) || "openid";
    const audience = str(body.audience);
    const bindingMessage = str(body.binding_message) || null;
    const expiresIn = 300;
    const authReqId = randomBytes(24).toString("hex");
    getCibaRequests(store).set(authReqId, {
      authReqId,
      clientId,
      scope,
      audience,
      bindingMessage,
      approvedUserId: null,
      expiresAt: Math.floor(Date.now() / 1000) + expiresIn,
    });
    return c.json({ auth_req_id: authReqId, expires_in: expiresIn, interval: 5 });
  });

  // POST /_emulate/ciba/approve — test helper to approve a pending request.
  app.post("/_emulate/ciba/approve", async (c) => {
    const body = await readBody(c);
    const authReqId = str(body.auth_req_id);
    const userId = str(body.user_id);
    const pending = getCibaRequests(store).get(authReqId);
    if (!pending) return oauthError(c, 404, "not_found", "Unknown auth_req_id.");
    if (!as.users.findOneBy("user_id", userId)) return oauthError(c, 404, "not_found", "Unknown user.");
    pending.approvedUserId = userId;
    getCibaRequests(store).set(authReqId, pending);
    return c.json({ approved: true });
  });
}

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}

async function readBody(c: Context<AppEnv>): Promise<Record<string, unknown>> {
  const contentType = c.req.header("Content-Type") ?? "";
  try {
    if (contentType.includes("application/json")) return (await c.req.json()) as Record<string, unknown>;
    return Object.fromEntries(new URLSearchParams(await c.req.text()));
  } catch {
    return {};
  }
}
