import type { RouteContext } from "@emulators/core";
import type { Auth0Stream, Auth0StreamKind } from "../entities.js";
import { generateAuth0Id, nowUnix } from "../helpers.js";
import { getAuth0Store } from "../store.js";
import { mgmtError, readJsonBody, requireManagementAuth } from "../route-helpers.js";

// Log Streams (raw log records) and Event Streams (typed domain events).
// Both share the Auth0Stream entity, differentiated by `kind`.
function streamResponse(stream: Auth0Stream): Record<string, unknown> {
  return {
    id: stream.stream_id,
    name: stream.name,
    status: stream.status,
    type: "http",
    sink: { httpEndpoint: stream.sink_url },
    ...(stream.kind === "event" ? { subscriptions: stream.subscriptions.map((event_type) => ({ event_type })) } : {}),
  };
}

function streamsApi(ctx: RouteContext, kind: Auth0StreamKind, basePath: string, key: string): void {
  const { app, store, tokenMap } = ctx;
  const as = getAuth0Store(store);

  app.get(basePath, (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    return c.json(as.streams.findBy("kind", kind).map(streamResponse));
  });

  app.post(basePath, async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const body = await readJsonBody(c);
    const sink = (body.sink && typeof body.sink === "object" ? body.sink : {}) as Record<string, unknown>;
    const sinkUrl = typeof sink.httpEndpoint === "string" ? sink.httpEndpoint : null;
    const subscriptions = Array.isArray(body.subscriptions)
      ? (body.subscriptions as unknown[]).map((s) =>
          s && typeof s === "object" && "event_type" in s
            ? String((s as { event_type: unknown }).event_type)
            : String(s),
        )
      : ["*"];
    const now = nowUnix();
    const created = as.streams.insert({
      stream_id: generateAuth0Id(),
      kind,
      name: typeof body.name === "string" ? body.name : `${key}-stream`,
      status: "active",
      sink_url: sinkUrl,
      subscriptions: kind === "event" ? subscriptions : [],
      created_at_unix: now,
      updated_at_unix: now,
    });
    return c.json(streamResponse(created), 201);
  });

  app.patch(`${basePath}/:id`, async (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const stream = as.streams.findOneBy("stream_id", c.req.param("id"));
    if (!stream || stream.kind !== kind)
      return mgmtError(c, 404, "Not Found", "The stream does not exist.", "inexistent_stream");
    const body = await readJsonBody(c);
    const updates: Record<string, unknown> = { updated_at_unix: nowUnix() };
    if (typeof body.name === "string") updates.name = body.name;
    if (body.status === "active" || body.status === "paused") updates.status = body.status;
    if (
      body.sink &&
      typeof body.sink === "object" &&
      typeof (body.sink as Record<string, unknown>).httpEndpoint === "string"
    ) {
      updates.sink_url = (body.sink as Record<string, unknown>).httpEndpoint;
    }
    const updated = as.streams.update(stream.id, updates);
    return c.json(streamResponse(updated ?? stream));
  });

  app.delete(`${basePath}/:id`, (c) => {
    const auth = requireManagementAuth(c, tokenMap);
    if (auth instanceof Response) return auth;
    const stream = as.streams.findOneBy("stream_id", c.req.param("id"));
    if (stream && stream.kind === kind) as.streams.delete(stream.id);
    return new Response(null, { status: 204 });
  });
}

export function streamRoutes(ctx: RouteContext): void {
  streamsApi(ctx, "log", "/api/v2/log-streams", "log");
  streamsApi(ctx, "event", "/api/v2/event-streams", "event");

  // Test helper: inspect recorded deliveries without an external sink.
  const as = getAuth0Store(ctx.store);
  ctx.app.get("/_emulate/stream-deliveries", (c) => {
    return c.json(
      as.streamDeliveries.all().map((d) => ({
        stream_id: d.stream_id,
        kind: d.kind,
        event_type: d.event_type,
        payload: d.payload,
        status: d.status,
        error: d.error,
        delivered_at: d.delivered_at,
      })),
    );
  });
}
