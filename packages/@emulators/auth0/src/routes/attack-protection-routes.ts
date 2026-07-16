import type { RouteContext } from "@emulators/core";
import { getAttackConfig, setAttackConfig, unblock } from "../attack-protection.js";
import { getAuth0Store } from "../store.js";
import { readJsonBody, requireManagementAuth } from "../route-helpers.js";

// Management API v2 attack-protection config endpoints + user-blocks. Config is
// stateful and consumed by the enforcement logic in token.ts / authorize.ts.
export function attackProtectionRoutes({ app, store, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  app.get("/api/v2/attack-protection/brute-force-protection", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const cfg = getAttackConfig(store);
    return c.json({
      enabled: cfg.bruteForce.enabled,
      max_attempts: cfg.bruteForce.max_attempts,
      mode: cfg.bruteForce.mode,
      shields: ["block", "user_notification"],
    });
  });

  app.patch("/api/v2/attack-protection/brute-force-protection", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonBody(c);
    const cfg = getAttackConfig(store);
    if (typeof body.enabled === "boolean") cfg.bruteForce.enabled = body.enabled;
    if (typeof body.max_attempts === "number") cfg.bruteForce.max_attempts = body.max_attempts;
    if (body.mode === "count_per_identifier_and_ip" || body.mode === "count_per_identifier")
      cfg.bruteForce.mode = body.mode;
    setAttackConfig(store, cfg);
    return c.json({
      enabled: cfg.bruteForce.enabled,
      max_attempts: cfg.bruteForce.max_attempts,
      mode: cfg.bruteForce.mode,
    });
  });

  app.get("/api/v2/attack-protection/suspicious-ip-throttling", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const cfg = getAttackConfig(store);
    return c.json({
      enabled: cfg.suspiciousIp.enabled,
      shields: ["block", "admin_notification"],
      stage: { "pre-login": { max_attempts: cfg.suspiciousIp.max_attempts, rate: cfg.suspiciousIp.window_seconds } },
    });
  });

  app.patch("/api/v2/attack-protection/suspicious-ip-throttling", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonBody(c);
    const cfg = getAttackConfig(store);
    if (typeof body.enabled === "boolean") cfg.suspiciousIp.enabled = body.enabled;
    const stage = (body.stage as Record<string, unknown> | undefined)?.["pre-login"] as
      | Record<string, unknown>
      | undefined;
    if (stage && typeof stage.max_attempts === "number") cfg.suspiciousIp.max_attempts = stage.max_attempts;
    setAttackConfig(store, cfg);
    return c.json({ enabled: cfg.suspiciousIp.enabled });
  });

  app.get("/api/v2/attack-protection/breached-password-detection", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const cfg = getAttackConfig(store);
    return c.json({ enabled: cfg.breachedPassword.enabled, shields: ["block"], method: "standard" });
  });

  app.patch("/api/v2/attack-protection/breached-password-detection", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonBody(c);
    const cfg = getAttackConfig(store);
    if (typeof body.enabled === "boolean") cfg.breachedPassword.enabled = body.enabled;
    // Emulator extension: allow seeding the breached-password list directly.
    if (Array.isArray(body.passwords)) {
      cfg.breachedPassword.passwords = (body.passwords as unknown[]).filter((p): p is string => typeof p === "string");
    }
    setAttackConfig(store, cfg);
    return c.json({ enabled: cfg.breachedPassword.enabled });
  });

  app.get("/api/v2/attack-protection/bot-detection", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const cfg = getAttackConfig(store);
    return c.json({ enabled: cfg.botDetection.enabled });
  });

  app.patch("/api/v2/attack-protection/bot-detection", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonBody(c);
    const cfg = getAttackConfig(store);
    if (typeof body.enabled === "boolean") cfg.botDetection.enabled = body.enabled;
    setAttackConfig(store, cfg);
    return c.json({ enabled: cfg.botDetection.enabled });
  });

  // --- user-blocks: inspect and clear blocks raised by attack protection ---
  app.get("/api/v2/user-blocks", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const identifier = c.req.query("identifier") ?? "";
    const blocks = identifier ? as.userBlocks.findBy("identifier", identifier) : as.userBlocks.all();
    return c.json({ blocked_for: blocks.map((b) => ({ identifier: b.identifier, ip: b.ip })) });
  });

  app.delete("/api/v2/user-blocks", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const identifier = c.req.query("identifier") ?? "";
    if (identifier) unblock(store, identifier);
    return new Response(null, { status: 204 });
  });

  app.get("/api/v2/user-blocks/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const id = decodeURIComponent(c.req.param("id"));
    const user = as.users.findOneBy("user_id", id);
    const identifier = user?.email ?? id;
    const blocks = as.userBlocks.findBy("identifier", identifier);
    return c.json({ blocked_for: blocks.map((b) => ({ identifier: b.identifier, ip: b.ip })) });
  });

  app.delete("/api/v2/user-blocks/:id", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const id = decodeURIComponent(c.req.param("id"));
    const user = as.users.findOneBy("user_id", id);
    unblock(store, user?.email ?? id);
    return new Response(null, { status: 204 });
  });
}
