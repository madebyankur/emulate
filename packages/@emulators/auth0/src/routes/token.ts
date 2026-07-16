import { createHash, randomBytes } from "node:crypto";
import type { Context } from "@emulators/core";
import type { AppEnv, RouteContext, Store, TokenMap } from "@emulators/core";
import { constantTimeSecretEqual } from "@emulators/core";
import type { Auth0Client } from "../entities.js";
import {
  PASSWORD_GRANT,
  PASSWORD_REALM_GRANT,
  DEVICE_CODE_GRANT,
  DEFAULT_DB_CONNECTION,
  PASSWORDLESS_OTP_GRANT,
  MFA_OTP_GRANT,
  MFA_OOB_GRANT,
  MFA_RECOVERY_GRANT,
  CIBA_GRANT,
  parseScope,
} from "../helpers.js";
import {
  getAccessTokens,
  getDeviceCodes,
  getPendingCodes,
  getRefreshTokens,
  oauthError,
  signAccessToken,
  signIdToken,
  userRoleNames,
  userPermissionsForAudience,
  type StoredAccessToken,
  type StoredRefreshToken,
} from "../route-helpers.js";
import { getAuth0Store } from "../store.js";
import { clearAttempts, clientIp, isBlocked, isBreachedPassword, recordFailedAttempt } from "../attack-protection.js";
import { dispatchEvent, recordLog } from "../events.js";
import { runActionPipeline, runCredentialsExchange, type ActionRunContext } from "../actions-runtime.js";
import {
  isMfaRequired,
  createMfaChallengeToken,
  getMfaChallenge,
  consumeMfaChallenge,
  verifyOtp,
  verifyRecoveryCode,
} from "./mfa.js";
import { findPasswordlessCode, consumePasswordlessCode, ensurePasswordlessUser } from "./passwordless.js";
import { getCibaRequests } from "./ciba.js";
import { generateAuth0Id, nowUnix } from "../helpers.js";

const CODE_TTL_MS = 10 * 60 * 1000;

function mgmtAudience(baseUrl: string): string {
  return `${baseUrl}/api/v2/`;
}

async function parseBody(c: Context<AppEnv>): Promise<Record<string, string>> {
  const contentType = c.req.header("Content-Type") ?? "";
  if (contentType.includes("application/json")) {
    try {
      const parsed = (await c.req.json()) as Record<string, unknown>;
      const out: Record<string, string> = {};
      for (const [k, v] of Object.entries(parsed)) {
        if (typeof v === "string") out[k] = v;
        else if (typeof v === "number" || typeof v === "boolean") out[k] = String(v);
      }
      return out;
    } catch {
      return {};
    }
  }
  return Object.fromEntries(new URLSearchParams(await c.req.text()));
}

function parseClientCreds(
  c: Context<AppEnv>,
  body: Record<string, string>,
): { clientId: string; clientSecret: string } {
  let clientId = body.client_id ?? "";
  let clientSecret = body.client_secret ?? "";
  const authHeader = c.req.header("Authorization") ?? "";
  if (authHeader.startsWith("Basic ")) {
    const decoded = Buffer.from(authHeader.slice(6), "base64").toString("utf8");
    const sep = decoded.indexOf(":");
    if (sep !== -1) {
      if (!clientId) clientId = decodeURIComponent(decoded.slice(0, sep));
      if (!clientSecret) clientSecret = decodeURIComponent(decoded.slice(sep + 1));
    }
  }
  return { clientId, clientSecret };
}

// Validate client credentials when clients are registered. Public clients
// (token_endpoint_auth_method "none") need no secret. Returns the client (or
// null when none are registered) or an error Response.
function resolveClient(
  c: Context<AppEnv>,
  clients: Auth0Client[],
  clientId: string,
  clientSecret: string,
  requireSecret: boolean,
): Auth0Client | null | Response {
  if (clients.length === 0) return null;
  const client = clients.find((entry) => entry.client_id === clientId);
  if (!client) return oauthError(c, 401, "invalid_client", "Unknown client.");
  if (requireSecret && client.token_endpoint_auth_method !== "none") {
    if (!constantTimeSecretEqual(client.client_secret, clientSecret)) {
      return oauthError(c, 401, "invalid_client", "Invalid client credentials.");
    }
  }
  return client;
}

function verifyPkce(challenge: string | null, method: string | null, verifier: string | undefined): boolean {
  if (challenge === null) return true;
  if (!verifier) return false;
  if ((method ?? "plain").toLowerCase() === "s256") {
    return createHash("sha256").update(verifier).digest("base64url") === challenge;
  }
  return verifier === challenge;
}

interface IssueArgs {
  userId: string;
  clientId: string;
  audience: string;
  scope: string;
  nonce: string | null;
  orgId: string | null;
  includeRefresh: boolean;
  ip?: string | null;
  // The extensibility trigger to run (post-login by default). Pass null to
  // skip the Action/Rule pipeline entirely (e.g. refresh_token silent auth).
  trigger?: string | null;
  // When true, do not re-evaluate MFA (the caller already satisfied it).
  mfaSatisfied?: boolean;
}

// The shared token-minting routine for every user-facing grant. It runs the
// Actions/Rules pipeline (which can inject claims, deny, or force MFA),
// enforces MFA, resolves RBAC permissions + org name, signs the tokens, and
// records a session.
async function issueUserTokens(
  c: Context<AppEnv>,
  store: Store,
  baseUrl: string,
  tokenMap: TokenMap | undefined,
  args: IssueArgs,
): Promise<Response> {
  const as = getAuth0Store(store);
  const user = as.users.findOneBy("user_id", args.userId);
  if (!user) return oauthError(c, 400, "invalid_grant", "Unknown user.");

  const audience = args.audience || mgmtAudience(baseUrl);
  const scopes = parseScope(args.scope);

  // Resolve organization name (if any) for the org_name claim.
  const org = args.orgId ? as.organizations.findOneBy("org_id", args.orgId) : null;
  const orgName = org?.name ?? null;

  // --- Extensibility pipeline (Actions + legacy Rules) ---
  const trigger = args.trigger === undefined ? "post-login" : args.trigger;
  let extraIdClaims: Record<string, unknown> = {};
  let extraAccessClaims: Record<string, unknown> = {};
  let pipelineMfa = false;
  if (trigger) {
    const runCtx: ActionRunContext = {
      trigger,
      user,
      clientId: args.clientId,
      clientName: as.clients.findOneBy("client_id", args.clientId)?.name ?? args.clientId,
      ip: args.ip ?? null,
      scope: args.scope,
      audience,
      orgId: args.orgId,
      orgName,
      requestQuery: {},
    };
    const pipeline = await runActionPipeline(store, runCtx);
    if (pipeline.denied) {
      await recordLog(store, {
        type: "f",
        description: `Login denied by extensibility: ${pipeline.denied}`,
        clientId: args.clientId || null,
        userId: user.user_id,
        ip: args.ip ?? null,
      });
      return oauthError(c, 403, "access_denied", pipeline.denied);
    }
    extraIdClaims = pipeline.idTokenClaims;
    extraAccessClaims = pipeline.accessTokenClaims;
    pipelineMfa = pipeline.mfaRequired;
    // Persist metadata mutations from the pipeline.
    if (Object.keys(pipeline.appMetadata).length > 0 || Object.keys(pipeline.userMetadata).length > 0) {
      as.users.update(user.id, {
        app_metadata: { ...user.app_metadata, ...pipeline.appMetadata },
        user_metadata: { ...user.user_metadata, ...pipeline.userMetadata },
        updated_at_unix: nowUnix(),
      });
    }
  }

  // --- MFA enforcement ---
  if (!args.mfaSatisfied && (pipelineMfa || isMfaRequired(store, user))) {
    const mfaToken = createMfaChallengeToken(store, {
      userId: user.user_id,
      clientId: args.clientId,
      audience,
      scope: args.scope,
      nonce: args.nonce,
      orgId: args.orgId,
    });
    await recordLog(store, {
      type: "mfar",
      description: "Multi-factor authentication required",
      clientId: args.clientId || null,
      userId: user.user_id,
      ip: args.ip ?? null,
    });
    return c.json(
      {
        error: "mfa_required",
        error_description: "Multifactor authentication required",
        mfa_token: mfaToken,
      },
      403,
    );
  }

  // --- RBAC permissions claim (only when the target API enables it) ---
  const rs = as.resourceServers.findOneBy("identifier", audience);
  const permissions = rs && rs.enforce_policies ? userPermissionsForAudience(as, user.user_id, audience) : [];

  const accessToken = await signAccessToken(baseUrl, audience, args.clientId, args.scope, {
    subject: user.user_id,
    orgId: args.orgId,
    orgName,
    permissions,
    extraClaims: extraAccessClaims,
  });

  const now = Math.floor(Date.now() / 1000);
  getAccessTokens(store).set(accessToken, {
    clientId: args.clientId,
    audience,
    scope: args.scope,
    userId: user.user_id,
    orgId: args.orgId,
    issuedAt: now,
    expiresAt: now + 86400,
  } satisfies StoredAccessToken);

  // Mirror into the shared tokenMap so /userinfo and the Management API
  // recognize this Bearer token.
  tokenMap?.set(accessToken, { login: user.email, id: user.id, scopes });

  const response: Record<string, unknown> = {
    access_token: accessToken,
    scope: args.scope,
    expires_in: 86400,
    token_type: "Bearer",
  };

  if (args.includeRefresh && scopes.includes("offline_access")) {
    const refreshToken = randomBytes(24).toString("base64url");
    getRefreshTokens(store).set(refreshToken, {
      clientId: args.clientId,
      audience,
      scope: args.scope,
      userId: user.user_id,
      orgId: args.orgId,
    } satisfies StoredRefreshToken);
    response.refresh_token = refreshToken;
  }

  if (scopes.includes("openid")) {
    const roleClaim = userRoleNames(as, user.user_id);
    const extra: Record<string, unknown> = { ...extraIdClaims };
    if (args.orgId) {
      extra.org_id = args.orgId;
      if (orgName) extra.org_name = orgName;
    }
    if (roleClaim.length > 0) extra[`${baseUrl}/roles`] = roleClaim;
    response.id_token = await signIdToken(baseUrl, user, args.clientId, args.nonce, extra);
  }

  // Record a session and update login bookkeeping.
  as.sessions.insert({
    session_id: generateAuth0Id(),
    user_id: user.user_id,
    client_id: args.clientId || null,
    created_at_unix: now,
    last_interacted_unix: now,
  });
  as.users.update(user.id, { last_login: new Date().toISOString(), logins_count: user.logins_count + 1 });

  return c.json(response);
}

export function tokenRoutes({ app, store, baseUrl, tokenMap }: RouteContext): void {
  const as = getAuth0Store(store);

  // POST /oauth/token — the multiplexed grant endpoint.
  app.post("/oauth/token", async (c) => {
    const body = await parseBody(c);
    const grantType = body.grant_type ?? "";
    const creds = parseClientCreds(c, body);
    const ip = clientIp(c.req.header("X-Forwarded-For"));

    // --- authorization_code (+ PKCE) ---
    if (grantType === "authorization_code") {
      const code = body.code ?? "";
      const pending = getPendingCodes(store).get(code);
      if (!pending || Date.now() - pending.createdAt > CODE_TTL_MS) {
        if (pending) getPendingCodes(store).delete(code);
        return oauthError(c, 403, "invalid_grant", "Invalid authorization code");
      }

      const clientResult = resolveClient(c, as.clients.all(), creds.clientId, creds.clientSecret, false);
      if (clientResult instanceof Response) return clientResult;
      const isPublic = clientResult?.token_endpoint_auth_method === "none";
      // Confidential clients must present a valid secret; public clients use PKCE.
      if (clientResult && !isPublic && !constantTimeSecretEqual(clientResult.client_secret, creds.clientSecret)) {
        return oauthError(c, 401, "invalid_client", "Invalid client credentials.");
      }
      if (!verifyPkce(pending.codeChallenge, pending.codeChallengeMethod, body.code_verifier)) {
        return oauthError(c, 403, "invalid_grant", "Failed to verify code verifier");
      }
      if (body.redirect_uri && body.redirect_uri !== pending.redirectUri) {
        return oauthError(c, 403, "invalid_grant", "redirect_uri does not match.");
      }
      getPendingCodes(store).delete(code);

      const resp = await issueUserTokens(c, store, baseUrl, tokenMap, {
        userId: pending.userId,
        clientId: pending.clientId || creds.clientId,
        audience: pending.audience,
        scope: pending.scope,
        nonce: pending.nonce,
        orgId: pending.orgId,
        includeRefresh: true,
        ip,
      });
      await recordLog(store, {
        type: "seacft",
        description: "Success Exchange (Authorization Code)",
        clientId: pending.clientId,
        userId: pending.userId,
        ip,
      });
      await dispatchEvent(store, {
        type: "login.succeeded",
        data: { user_id: pending.userId, client_id: pending.clientId },
      });
      return resp;
    }

    // --- refresh_token (with rotation) ---
    if (grantType === "refresh_token") {
      const refreshToken = body.refresh_token ?? "";
      const existing = getRefreshTokens(store).get(refreshToken);
      if (!existing) return oauthError(c, 403, "invalid_grant", "Unknown or expired refresh token.");

      const clientResult = resolveClient(c, as.clients.all(), creds.clientId, creds.clientSecret, false);
      if (clientResult instanceof Response) return clientResult;

      getRefreshTokens(store).delete(refreshToken);
      const scope = body.scope || existing.scope;
      const resp = await issueUserTokens(c, store, baseUrl, tokenMap, {
        userId: existing.userId,
        clientId: existing.clientId,
        audience: existing.audience,
        scope,
        nonce: null,
        orgId: existing.orgId,
        includeRefresh: true,
        ip,
        // Silent auth: do not re-prompt MFA or re-run the login pipeline.
        trigger: null,
        mfaSatisfied: true,
      });
      await recordLog(store, {
        type: "ssrt",
        description: "Success Silent Auth (Refresh Token)",
        clientId: existing.clientId,
        userId: existing.userId,
        ip,
      });
      return resp;
    }

    // --- client_credentials (machine to machine) ---
    if (grantType === "client_credentials") {
      const clientResult = resolveClient(c, as.clients.all(), creds.clientId, creds.clientSecret, true);
      if (clientResult instanceof Response) return clientResult;
      const clientId = clientResult?.client_id ?? creds.clientId;
      if (!clientId) return oauthError(c, 401, "invalid_client", "client_id is required.");

      const audience = body.audience ?? mgmtAudience(baseUrl);
      // If a client grant exists, constrain scope to its grant; otherwise allow requested.
      const grant = as.clientGrants.findBy("client_id", clientId).find((g) => g.audience === audience);
      const requested = parseScope(body.scope);
      const scope = grant
        ? grant.scopes.filter((s) => requested.length === 0 || requested.includes(s)).join(" ")
        : (body.scope ?? "");

      // credentials-exchange Actions can inject custom access-token claims.
      const clientName = clientResult?.name ?? clientId;
      const m2mClaims = await runCredentialsExchange(store, clientId, clientName, audience, scope);
      const accessToken = await signAccessToken(baseUrl, audience, clientId, scope, {
        subject: null,
        extraClaims: m2mClaims,
      });
      const now = Math.floor(Date.now() / 1000);
      getAccessTokens(store).set(accessToken, {
        clientId,
        audience,
        scope,
        userId: null,
        orgId: null,
        issuedAt: now,
        expiresAt: now + 86400,
      });
      tokenMap?.set(accessToken, { login: `${clientId}@clients`, id: 0, scopes: parseScope(scope) });

      await recordLog(store, { type: "scoa", description: "Success Client Credentials Exchange", clientId, ip });
      return c.json({ access_token: accessToken, scope, expires_in: 86400, token_type: "Bearer" });
    }

    // --- password / password-realm (resource owner) ---
    if (grantType === PASSWORD_GRANT || grantType === PASSWORD_REALM_GRANT) {
      const username = body.username ?? "";
      const password = body.password ?? "";
      const realm = body.realm || DEFAULT_DB_CONNECTION;

      if (isBlocked(store, username, ip)) {
        await recordLog(store, {
          type: "limit_wc",
          description: "Blocked account",
          clientId: creds.clientId || null,
          ip,
        });
        return oauthError(
          c,
          429,
          "too_many_attempts",
          "Your account has been blocked after multiple consecutive login attempts.",
        );
      }
      if (isBreachedPassword(store, password)) {
        await recordLog(store, {
          type: "pwd_leak",
          description: "Breached password detected",
          clientId: creds.clientId || null,
          ip,
        });
        return oauthError(
          c,
          401,
          "password_leaked",
          "This login attempt has been blocked because the password you're using was previously disclosed through a data breach.",
        );
      }

      const user = as.users.findOneBy("email", username) ?? as.users.findOneBy("username", username);
      const realmMatch = user && (grantType === PASSWORD_GRANT || user.connection === realm);
      if (!user || !realmMatch || user.password !== password || user.blocked) {
        await recordFailedAttempt(store, username, ip, creds.clientId || null);
        await recordLog(store, {
          type: "fp",
          description: "Failed login (wrong credentials)",
          clientId: creds.clientId || null,
          ip,
        });
        await dispatchEvent(store, { type: "login.failed", data: { username, connection: realm } });
        return oauthError(c, 403, "invalid_grant", "Wrong email or password.");
      }

      clearAttempts(store, username, ip);
      const clientResult = resolveClient(c, as.clients.all(), creds.clientId, creds.clientSecret, false);
      if (clientResult instanceof Response) return clientResult;

      const resp = await issueUserTokens(c, store, baseUrl, tokenMap, {
        userId: user.user_id,
        clientId: creds.clientId,
        audience: body.audience ?? "",
        scope: body.scope || "openid profile email",
        nonce: null,
        orgId: null,
        includeRefresh: true,
        ip,
      });
      await recordLog(store, {
        type: "sepft",
        description: "Success Exchange (Password Realm)",
        clientId: creds.clientId || null,
        userId: user.user_id,
        ip,
      });
      await dispatchEvent(store, { type: "login.succeeded", data: { user_id: user.user_id, connection: realm } });
      return resp;
    }

    // --- device_code ---
    if (grantType === DEVICE_CODE_GRANT) {
      const deviceCode = body.device_code ?? "";
      const pending = getDeviceCodes(store).get(deviceCode);
      if (!pending || Date.now() / 1000 > pending.expiresAt) {
        if (pending) getDeviceCodes(store).delete(deviceCode);
        return oauthError(c, 400, "expired_token", "The device code has expired.");
      }
      if (!pending.approvedUserId) {
        return oauthError(c, 403, "authorization_pending", "User has not yet approved the device.");
      }
      getDeviceCodes(store).delete(deviceCode);
      const resp = await issueUserTokens(c, store, baseUrl, tokenMap, {
        userId: pending.approvedUserId,
        clientId: pending.clientId,
        audience: pending.audience,
        scope: pending.scope,
        nonce: null,
        orgId: null,
        includeRefresh: true,
        ip,
      });
      return resp;
    }

    // --- passwordless OTP (email/sms one-time code) ---
    if (grantType === PASSWORDLESS_OTP_GRANT) {
      const realm = body.realm || "email";
      const identifier = body.username ?? "";
      const otp = body.otp ?? "";
      const pending = findPasswordlessCode(store, identifier);
      if (!pending || pending.code !== otp) {
        await dispatchEvent(store, { type: "login.failed", data: { username: identifier, connection: realm } });
        return oauthError(c, 403, "invalid_grant", "Wrong email or verification code.");
      }
      consumePasswordlessCode(store, identifier);
      const user = ensurePasswordlessUser(store, identifier, realm);
      const resp = await issueUserTokens(c, store, baseUrl, tokenMap, {
        userId: user.user_id,
        clientId: creds.clientId,
        audience: body.audience ?? "",
        scope: body.scope || "openid profile email",
        nonce: null,
        orgId: null,
        includeRefresh: true,
        ip,
      });
      await recordLog(store, {
        type: "seacft",
        description: "Success Exchange (Passwordless OTP)",
        clientId: creds.clientId || null,
        userId: user.user_id,
        ip,
      });
      await dispatchEvent(store, { type: "login.succeeded", data: { user_id: user.user_id, connection: realm } });
      return resp;
    }

    // --- MFA completion grants (consume an mfa_token + code) ---
    if (grantType === MFA_OTP_GRANT || grantType === MFA_OOB_GRANT || grantType === MFA_RECOVERY_GRANT) {
      const mfaToken = body.mfa_token ?? "";
      const challenge = getMfaChallenge(store, mfaToken);
      if (!challenge) return oauthError(c, 401, "invalid_grant", "Malformed or expired mfa_token.");

      let ok = false;
      if (grantType === MFA_OTP_GRANT) {
        ok = verifyOtp(store, challenge.userId, body.otp ?? "");
      } else if (grantType === MFA_OOB_GRANT) {
        const bindingCode = body.binding_code ?? body.otp ?? "";
        ok = challenge.oobValue !== null && bindingCode === challenge.oobValue;
      } else {
        ok = verifyRecoveryCode(store, challenge.userId, body.recovery_code ?? "");
      }
      if (!ok) return oauthError(c, 403, "invalid_grant", "Invalid MFA code.");

      consumeMfaChallenge(store, mfaToken);
      const resp = await issueUserTokens(c, store, baseUrl, tokenMap, {
        userId: challenge.userId,
        clientId: challenge.clientId,
        audience: challenge.audience,
        scope: challenge.scope,
        nonce: challenge.nonce,
        orgId: challenge.orgId,
        includeRefresh: true,
        ip,
        mfaSatisfied: true,
      });
      await recordLog(store, {
        type: "seacft",
        description: "Success Exchange (MFA)",
        clientId: challenge.clientId || null,
        userId: challenge.userId,
        ip,
      });
      return resp;
    }

    // --- CIBA (backchannel) — poll an auth_req_id ---
    if (grantType === CIBA_GRANT) {
      const authReqId = body.auth_req_id ?? "";
      const pending = getCibaRequests(store).get(authReqId);
      if (!pending || Date.now() / 1000 > pending.expiresAt) {
        if (pending) getCibaRequests(store).delete(authReqId);
        return oauthError(c, 400, "expired_token", "The auth_req_id has expired.");
      }
      if (!pending.approvedUserId) {
        return oauthError(c, 400, "authorization_pending", "The end-user has not yet approved the request.");
      }
      getCibaRequests(store).delete(authReqId);
      return issueUserTokens(c, store, baseUrl, tokenMap, {
        userId: pending.approvedUserId,
        clientId: pending.clientId,
        audience: pending.audience,
        scope: pending.scope,
        nonce: null,
        orgId: null,
        includeRefresh: true,
        ip,
      });
    }

    return oauthError(c, 400, "unsupported_grant_type", `Grant type '${grantType}' not supported.`);
  });

  // POST /oauth/revoke — revoke a refresh token.
  app.post("/oauth/revoke", async (c) => {
    const body = await parseBody(c);
    const token = body.token ?? "";
    getRefreshTokens(store).delete(token);
    getAccessTokens(store).delete(token);
    tokenMap?.delete(token);
    return c.body(null, 200);
  });

  // POST /oauth/device/code — start the device authorization flow.
  app.post("/oauth/device/code", async (c) => {
    const body = await parseBody(c);
    const clientId = body.client_id ?? "";
    const scope = body.scope ?? "openid profile";
    const audience = body.audience ?? "";
    const deviceCode = randomBytes(20).toString("hex");
    const userCode = randomBytes(4).toString("hex").toUpperCase().slice(0, 8);
    const expiresIn = 900;
    getDeviceCodes(store).set(deviceCode, {
      deviceCode,
      clientId,
      scope,
      audience,
      approvedUserId: null,
      expiresAt: Math.floor(Date.now() / 1000) + expiresIn,
    });
    return c.json({
      device_code: deviceCode,
      user_code: userCode,
      verification_uri: `${baseUrl}/activate`,
      verification_uri_complete: `${baseUrl}/activate?user_code=${userCode}`,
      expires_in: expiresIn,
      interval: 5,
    });
  });

  // POST /_emulate/device/approve — test helper to approve a pending device code.
  app.post("/_emulate/device/approve", async (c) => {
    const body = await parseBody(c);
    const deviceCode = body.device_code ?? "";
    const userId = body.user_id ?? "";
    const pending = getDeviceCodes(store).get(deviceCode);
    if (!pending) return oauthError(c, 404, "not_found", "Unknown device code.");
    if (!as.users.findOneBy("user_id", userId)) return oauthError(c, 404, "not_found", "Unknown user.");
    pending.approvedUserId = userId;
    getDeviceCodes(store).set(deviceCode, pending);
    return c.json({ approved: true });
  });
}
