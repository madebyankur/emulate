import type { Store } from "@emulators/core";
import { generateAuth0Id, nowIso } from "./helpers.js";
import { getAuth0Store } from "./store.js";

const MAX_DELIVERIES = 1000;
const MAX_LOG_EVENTS = 1000;

// Record a tenant log event and fan it out to log streams. Auth0 log event
// `type` codes are short (e.g. "s" success login, "f" failed login, "ss"
// signup, "sapi" success api operation) — we keep them realistic.
export interface LogInput {
  type: string;
  description: string;
  clientId?: string | null;
  userId?: string | null;
  ip?: string | null;
}

// A typed domain event for event streams (e.g. "user.created",
// "login.succeeded"). These are distinct from raw log records.
export interface DomainEventInput {
  type: string;
  data: Record<string, unknown>;
}

async function deliver(
  store: Store,
  streamId: string,
  kind: "log" | "event",
  eventType: string,
  sinkUrl: string | null,
  payload: unknown,
): Promise<void> {
  const as = getAuth0Store(store);
  let status: number | null = null;
  let error: string | null = null;

  if (sinkUrl) {
    try {
      const res = await fetch(sinkUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(10000),
      });
      status = res.status;
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
    }
  }

  as.streamDeliveries.insert({
    stream_id: streamId,
    kind,
    event_type: eventType,
    payload,
    status,
    error,
    delivered_at: nowIso(),
  });

  const deliveries = as.streamDeliveries.all();
  if (deliveries.length > MAX_DELIVERIES) {
    for (const old of deliveries.slice(0, deliveries.length - MAX_DELIVERIES)) {
      as.streamDeliveries.delete(old.id);
    }
  }
}

// Record a log event in the store (always) and dispatch it to every active
// log stream.
export async function recordLog(store: Store, input: LogInput): Promise<void> {
  const as = getAuth0Store(store);
  const log = as.logEvents.insert({
    log_id: generateAuth0Id(),
    type: input.type,
    description: input.description,
    client_id: input.clientId ?? null,
    user_id: input.userId ?? null,
    ip: input.ip ?? null,
    date: nowIso(),
  });

  const events = as.logEvents.all();
  if (events.length > MAX_LOG_EVENTS) {
    for (const old of events.slice(0, events.length - MAX_LOG_EVENTS)) {
      as.logEvents.delete(old.id);
    }
  }

  const logStreams = as.streams.findBy("kind", "log").filter((s) => s.status === "active");
  await Promise.all(
    logStreams.map((stream) =>
      deliver(store, stream.stream_id, "log", input.type, stream.sink_url, {
        log_id: log.log_id,
        type: log.type,
        description: log.description,
        client_id: log.client_id,
        user_id: log.user_id,
        ip: log.ip,
        date: log.date,
      }),
    ),
  );
}

// Dispatch a typed domain event to every active event stream subscribed to
// the event type (or "*").
export async function dispatchEvent(store: Store, input: DomainEventInput): Promise<void> {
  const as = getAuth0Store(store);
  const eventStreams = as.streams
    .findBy("kind", "event")
    .filter((s) => s.status === "active")
    .filter((s) => s.subscriptions.includes("*") || s.subscriptions.includes(input.type));

  await Promise.all(
    eventStreams.map((stream) =>
      deliver(store, stream.stream_id, "event", input.type, stream.sink_url, {
        id: generateAuth0Id(),
        type: input.type,
        time: nowIso(),
        data: input.data,
      }),
    ),
  );
}
