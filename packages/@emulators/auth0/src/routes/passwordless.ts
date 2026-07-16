import type { Context } from "@emulators/core";
import type { AppEnv, RouteContext, Store } from "@emulators/core";
import { getAuth0Store } from "../store.js";
import { generateUserId, nowUnix } from "../helpers.js";
import { oauthError } from "../route-helpers.js";
import { recordLog } from "../events.js";

// Passwordless connections: an emailed/texted one-time code logs the user in.
// Codes are deterministic in the emulator (last-issued is retrievable via the
// inspector / test helper) so flows are testable without a real mail/SMS sink.

export interface PasswordlessCode {
  identifier: string; // email or phone_number
  connection: string; // "email" | "sms"
  code: string;
  createdAt: number;
}

const CODE_TTL_MS = 10 * 60 * 1000;

function getCodes(store: Store): Map<string, PasswordlessCode> {
  let map = store.getData<Map<string, PasswordlessCode>>("auth0.passwordless.codes");
  if (!map) {
    map = new Map();
    store.setData("auth0.passwordless.codes", map);
  }
  return map;
}

// Generate a 6-digit numeric code.
function generateCode(): string {
  // Deterministic-friendly: 6 digits derived from crypto bytes.
  const n = (Math.abs(hashNow()) % 900000) + 100000;
  return String(n);
}

// Avoid Date.now-only entropy collisions across rapid calls by mixing a
// per-call counter held in module scope.
let counter = 0;
function hashNow(): number {
  counter = (counter + 1) % 1_000_000;
  return nowUnix() * 1_000_000 + counter;
}

// Look up the pending code for an identifier (used by the OTP grant).
export function findPasswordlessCode(store: Store, identifier: string): PasswordlessCode | undefined {
  const code = getCodes(store).get(identifier);
  if (!code) return undefined;
  if (Date.now() - code.createdAt > CODE_TTL_MS) {
    getCodes(store).delete(identifier);
    return undefined;
  }
  return code;
}

export function consumePasswordlessCode(store: Store, identifier: string): void {
  getCodes(store).delete(identifier);
}

// Ensure a user exists for a passwordless identifier, creating one if needed
// (Auth0 auto-provisions users for the email/sms connections).
export function ensurePasswordlessUser(store: Store, identifier: string, connection: string) {
  const as = getAuth0Store(store);
  const byEmail = connection === "email" ? as.users.findOneBy("email", identifier) : undefined;
  const byPhone = connection === "sms" ? as.users.all().find((u) => u.phone_number === identifier) : undefined;
  const existing = byEmail ?? byPhone;
  if (existing) return existing;
  const now = nowUnix();
  return as.users.insert({
    user_id: generateUserId(connection),
    email: connection === "email" ? identifier : "",
    email_verified: connection === "email",
    password: null,
    connection,
    username: null,
    name: identifier,
    nickname: null,
    given_name: null,
    family_name: null,
    picture: null,
    phone_number: connection === "sms" ? identifier : null,
    phone_verified: connection === "sms",
    blocked: false,
    user_metadata: {},
    app_metadata: {},
    last_login: null,
    logins_count: 0,
    created_at_unix: now,
    updated_at_unix: now,
  });
}

export function passwordlessRoutes({ app, store }: RouteContext): void {
  // POST /passwordless/start — issue a code to email or sms.
  app.post("/passwordless/start", async (c) => {
    const body = await readBody(c);
    const connection = typeof body.connection === "string" ? body.connection : "email";
    const identifier =
      connection === "sms"
        ? typeof body.phone_number === "string"
          ? body.phone_number
          : ""
        : typeof body.email === "string"
          ? body.email
          : "";
    if (!identifier) {
      return oauthError(c, 400, "bad.request", "An email or phone_number is required.");
    }
    const code = generateCode();
    getCodes(store).set(identifier, { identifier, connection, code, createdAt: Date.now() });
    await recordLog(store, {
      type: "cls",
      description: `Passwordless code sent via ${connection}`,
    });
    // Auth0 returns the contact info, never the code. The emulator surfaces the
    // code through the test helper below.
    return c.json({ _id: identifier, [connection === "sms" ? "phone_number" : "email"]: identifier, sent: true });
  });

  // POST /passwordless/verify — verify a code and mark the identifier verified
  // (the legacy verify endpoint; the OTP grant on /oauth/token is preferred).
  app.post("/passwordless/verify", async (c) => {
    const body = await readBody(c);
    const connection = typeof body.connection === "string" ? body.connection : "email";
    const identifier =
      connection === "sms"
        ? typeof body.phone_number === "string"
          ? body.phone_number
          : ""
        : typeof body.email === "string"
          ? body.email
          : "";
    const code = typeof body.verification_code === "string" ? body.verification_code : "";
    const pending = findPasswordlessCode(store, identifier);
    if (!pending || pending.code !== code) {
      return oauthError(c, 400, "invalid_grant", "Wrong email or verification code.");
    }
    return c.json({ verified: true });
  });

  // GET /_emulate/passwordless/code — test helper to read the last code.
  app.get("/_emulate/passwordless/code", (c) => {
    const identifier = c.req.query("identifier") ?? "";
    const pending = findPasswordlessCode(store, identifier);
    if (!pending) return c.json({ error: "not_found" }, 404);
    return c.json({ identifier: pending.identifier, connection: pending.connection, code: pending.code });
  });
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
