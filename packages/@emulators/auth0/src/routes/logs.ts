import type { RouteContext } from "@emulators/core";
import { getAuth0Store } from "../store.js";
import { listEnvelope, parsePage, requireManagementAuth } from "../route-helpers.js";

// Management API v2 — /api/v2/logs (tenant log events).
export function logRoutes({ app, store, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  app.get("/api/v2/logs", (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const logs = as.logEvents
      .all()
      .sort((a, b) => b.date.localeCompare(a.date))
      .map((log) => ({
        log_id: log.log_id,
        _id: log.log_id,
        type: log.type,
        description: log.description,
        client_id: log.client_id ?? undefined,
        user_id: log.user_id ?? undefined,
        ip: log.ip ?? undefined,
        date: log.date,
      }));
    const { page, perPage, includeTotals } = parsePage(c);
    return c.json(listEnvelope("logs", logs, page, perPage, includeTotals));
  });
}
