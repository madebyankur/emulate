import { randomBytes } from "node:crypto";
import type { Context } from "@emulators/core";
import type { AppEnv, RouteContext, Store } from "@emulators/core";
import type { Auth0User } from "../entities.js";
import { getAuth0Store } from "../store.js";
import { generateAuth0Id, nowUnix } from "../helpers.js";
import { oauthError } from "../route-helpers.js";

// --- MFA configuration (whether a login must satisfy MFA) ---
export interface MfaConfig {
  // Require MFA for every user.
  alwaysOn: boolean;
  // Require MFA for users in these connections.
  requiredConnections: string[];
  // Require MFA for these specific user_ids.
  requiredUsers: string[];
}

function defaultMfaConfig(): MfaConfig {
  return { alwaysOn: false, requiredConnections: [], requiredUsers: [] };
}

export function getMfaConfig(store: Store): MfaConfig {
  let cfg = store.getData<MfaConfig>("auth0.mfa.config");
  if (!cfg) {
    cfg = defaultMfaConfig();
    const seeded = store.getData<Partial<MfaConfig>>("auth0.seed.mfa");
    if (seeded) cfg = { ...cfg, ...seeded };
    store.setData("auth0.mfa.config", cfg);
  }
  return cfg;
}

// Is MFA required for this user on login? True when policy demands it OR the
// user already has a confirmed enrollment (Auth0 challenges enrolled users).
export function isMfaRequired(store: Store, user: Auth0User): boolean {
  const cfg = getMfaConfig(store);
  if (cfg.alwaysOn) return true;
  if (cfg.requiredUsers.includes(user.user_id)) return true;
  if (cfg.requiredConnections.includes(user.connection)) return true;
  const as = getAuth0Store(store);
  return as.userEnrollments.findBy("user_id", user.user_id).some((e) => e.status === "confirmed");
}

// --- MFA challenge tokens (mfa_token issued with the mfa_required error) ---
export interface MfaChallenge {
  userId: string;
  clientId: string;
  audience: string;
  scope: string;
  nonce: string | null;
  orgId: string | null;
  // The OOB code (when an oob challenge has been started) for verification.
  oobCode: string | null;
  oobValue: string | null;
  createdAt: number;
}

function getChallenges(store: Store): Map<string, MfaChallenge> {
  let map = store.getData<Map<string, MfaChallenge>>("auth0.mfa.challenges");
  if (!map) {
    map = new Map();
    store.setData("auth0.mfa.challenges", map);
  }
  return map;
}

export function createMfaChallengeToken(
  store: Store,
  args: {
    userId: string;
    clientId: string;
    audience: string;
    scope: string;
    nonce: string | null;
    orgId: string | null;
  },
): string {
  const token = randomBytes(24).toString("base64url");
  getChallenges(store).set(token, { ...args, oobCode: null, oobValue: null, createdAt: Date.now() });
  return token;
}

export function getMfaChallenge(store: Store, token: string): MfaChallenge | undefined {
  return getChallenges(store).get(token);
}

export function consumeMfaChallenge(store: Store, token: string): void {
  getChallenges(store).delete(token);
}

// For the emulator, OTP/recovery verification accepts the enrollment secret or
// a deterministic test code so tests do not need a real TOTP implementation.
export const EMULATOR_MFA_OTP = "000000";

export function verifyOtp(store: Store, userId: string, code: string): boolean {
  if (code === EMULATOR_MFA_OTP) return true;
  const as = getAuth0Store(store);
  return as.userEnrollments
    .findBy("user_id", userId)
    .some((e) => e.type === "otp" && e.status === "confirmed" && e.secret === code);
}

export function verifyRecoveryCode(store: Store, userId: string, code: string): boolean {
  const as = getAuth0Store(store);
  const match = as.userEnrollments
    .findBy("user_id", userId)
    .find((e) => e.type === "recovery-code" && e.secret === code);
  if (match) {
    as.userEnrollments.delete(match.id);
    return true;
  }
  return false;
}

// --- MFA Authentication API routes (/mfa/*) ---
export function mfaRoutes({ app, store }: RouteContext): void {
  const as = getAuth0Store(store);

  // List the caller's enrolled authenticators. The Bearer token here is the
  // mfa_token; we resolve the user from the challenge.
  app.get("/mfa/authenticators", (c) => {
    const challenge = challengeFromAuth(c, store);
    if (!challenge) return oauthError(c, 401, "invalid_token", "A valid mfa_token is required.");
    const authenticators = as.userEnrollments.findBy("user_id", challenge.userId).map((e) => ({
      id: e.enrollment_id,
      authenticator_type: e.type === "otp" ? "otp" : e.type === "recovery-code" ? "recovery-code" : "oob",
      active: e.status === "confirmed",
      oob_channel: e.oob_channel ?? undefined,
      name: e.name ?? undefined,
    }));
    return c.json(authenticators);
  });

  // Associate (enroll) a new authenticator.
  app.post("/mfa/associate", async (c) => {
    const challenge = challengeFromAuth(c, store);
    if (!challenge) return oauthError(c, 401, "invalid_token", "A valid mfa_token is required.");
    const body = await readBody(c);
    const types = Array.isArray(body.authenticator_types) ? (body.authenticator_types as string[]) : ["otp"];
    const type = types[0] ?? "otp";
    const oobChannels = Array.isArray(body.oob_channels) ? (body.oob_channels as string[]) : [];
    const secret = randomBytes(10).toString("hex").toUpperCase();
    const enrollment = as.userEnrollments.insert({
      enrollment_id: `dev_${generateAuth0Id().slice(0, 16)}`,
      user_id: challenge.userId,
      type: type === "oob" ? "oob" : type,
      oob_channel: type === "oob" ? (oobChannels[0] ?? "sms") : null,
      secret,
      name: typeof body.name === "string" ? body.name : null,
      status: "confirmed",
      created_at_unix: nowUnix(),
    });
    const resp: Record<string, unknown> = {
      authenticator_type: enrollment.type,
      secret,
      barcode_uri: `otpauth://totp/Emulate:${challenge.userId}?secret=${secret}`,
      recovery_codes: [randomBytes(12).toString("hex")],
    };
    if (enrollment.oob_channel) resp.oob_channel = enrollment.oob_channel;
    return c.json(resp, 200);
  });

  // Start a challenge against an authenticator (issues/sends a code).
  app.post("/mfa/challenge", async (c) => {
    const body = await readBody(c);
    const mfaToken = typeof body.mfa_token === "string" ? body.mfa_token : "";
    const challenge = getMfaChallenge(store, mfaToken);
    if (!challenge) return oauthError(c, 401, "invalid_token", "A valid mfa_token is required.");
    const enrollment = as.userEnrollments.findBy("user_id", challenge.userId).find((e) => e.status === "confirmed");
    const challengeType = enrollment && enrollment.type === "oob" ? "oob" : "otp";
    if (challengeType === "oob") {
      const oobCode = `oob_${generateAuth0Id().slice(0, 16)}`;
      challenge.oobCode = oobCode;
      challenge.oobValue = EMULATOR_MFA_OTP;
      getChallengesUpdate(store, mfaToken, challenge);
      return c.json({ challenge_type: "oob", oob_code: oobCode, binding_method: "prompt" });
    }
    return c.json({ challenge_type: "otp" });
  });
}

function getChallengesUpdate(store: Store, token: string, challenge: MfaChallenge): void {
  const map = store.getData<Map<string, MfaChallenge>>("auth0.mfa.challenges");
  if (map) map.set(token, challenge);
}

// Resolve an active challenge from a Bearer mfa_token header.
function challengeFromAuth(c: Context<AppEnv>, store: Store): MfaChallenge | undefined {
  const header = c.req.header("Authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return undefined;
  return getMfaChallenge(store, token);
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
