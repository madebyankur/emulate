import { randomUUID } from "node:crypto";
import type { Auth0User } from "./entities.js";

// Auth0 issuers always carry a trailing slash (https://tenant.auth0.com/).
// SDKs verify the `iss` claim against this exact value, so normalize here.
export function issuerFromBaseUrl(baseUrl: string): string {
  return baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
}

export function generateAuth0Id(): string {
  return randomUUID().replace(/-/g, "");
}

// Auth0 user ids are "{strategy}|{opaque}". The default DB connection uses the
// "auth0" strategy prefix.
export function generateUserId(connection: string): string {
  const strategy = connection === "Username-Password-Authentication" ? "auth0" : connection;
  return `${strategy}|${generateAuth0Id().slice(0, 24)}`;
}

export function nowUnix(): number {
  return Math.floor(Date.now() / 1000);
}

export function nowIso(): string {
  return new Date().toISOString();
}

export function userDisplayName(user: Pick<Auth0User, "name" | "nickname" | "email">): string {
  return user.name || user.nickname || user.email || "User";
}

export function parseScope(scope: string | undefined | null): string[] {
  return (scope ?? "")
    .split(/\s+/)
    .map((part) => part.trim())
    .filter(Boolean);
}

export const DEFAULT_DB_CONNECTION = "Username-Password-Authentication";

// The password-realm grant uses this fully-qualified Auth0 grant_type URN.
export const PASSWORD_REALM_GRANT = "http://auth0.com/oauth/grant-type/password-realm";
export const PASSWORD_GRANT = "password";
export const DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
export const PASSWORDLESS_OTP_GRANT = "http://auth0.com/oauth/grant-type/passwordless/otp";
export const MFA_OTP_GRANT = "http://auth0.com/oauth/grant-type/mfa-otp";
export const MFA_OOB_GRANT = "http://auth0.com/oauth/grant-type/mfa-oob";
export const MFA_RECOVERY_GRANT = "http://auth0.com/oauth/grant-type/mfa-recovery-code";
export const CIBA_GRANT = "urn:openid:params:grant-type:ciba";
