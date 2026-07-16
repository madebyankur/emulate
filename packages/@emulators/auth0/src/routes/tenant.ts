import type { RouteContext } from "@emulators/core";
import type { Store } from "@emulators/core";
import { requireManagementAuth, readJsonBody } from "../route-helpers.js";

// Tenant settings and Guardian (MFA) factors — stateful config read/write.
interface TenantSettings {
  friendly_name: string;
  support_email: string;
  support_url: string;
  default_audience: string;
  default_directory: string;
  enabled_locales: string[];
  flags: Record<string, boolean>;
}

function getTenant(store: Store): TenantSettings {
  let t = store.getData<TenantSettings>("auth0.tenant.settings");
  if (!t) {
    t = {
      friendly_name: "Emulated Tenant",
      support_email: "support@example.com",
      support_url: "https://example.com/support",
      default_audience: "",
      default_directory: "Username-Password-Authentication",
      enabled_locales: ["en"],
      flags: {},
    };
    store.setData("auth0.tenant.settings", t);
  }
  return t;
}

interface GuardianFactor {
  name: string;
  enabled: boolean;
}

function getFactors(store: Store): GuardianFactor[] {
  let f = store.getData<GuardianFactor[]>("auth0.guardian.factors");
  if (!f) {
    f = [
      { name: "sms", enabled: false },
      { name: "push-notification", enabled: false },
      { name: "otp", enabled: false },
      { name: "email", enabled: false },
      { name: "webauthn-roaming", enabled: false },
      { name: "recovery-code", enabled: false },
    ];
    store.setData("auth0.guardian.factors", f);
  }
  return f;
}

export function tenantRoutes({ app, store, tokenMap }: RouteContext): void {
  app.get("/api/v2/tenants/settings", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    return c.json(getTenant(store));
  });

  app.patch("/api/v2/tenants/settings", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonBody(c);
    const current = getTenant(store);
    const next: TenantSettings = { ...current };
    for (const key of [
      "friendly_name",
      "support_email",
      "support_url",
      "default_audience",
      "default_directory",
    ] as const) {
      if (typeof body[key] === "string") next[key] = body[key] as string;
    }
    if (Array.isArray(body.enabled_locales)) {
      next.enabled_locales = (body.enabled_locales as unknown[]).filter((v): v is string => typeof v === "string");
    }
    if (body.flags && typeof body.flags === "object") {
      next.flags = { ...current.flags, ...(body.flags as Record<string, boolean>) };
    }
    store.setData("auth0.tenant.settings", next);
    return c.json(next);
  });

  app.get("/api/v2/guardian/factors", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    return c.json(getFactors(store));
  });

  app.put("/api/v2/guardian/factors/:name", async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const name = c.req.param("name");
    const body = await readJsonBody(c);
    const enabled = body.enabled === true;
    const factors = getFactors(store);
    const factor = factors.find((f) => f.name === name);
    if (!factor) return c.json({ statusCode: 404, error: "Not Found", message: "Unknown factor" }, 404);
    factor.enabled = enabled;
    store.setData("auth0.guardian.factors", factors);
    return c.json({ name, enabled });
  });
}
