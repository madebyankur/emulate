import type { Entity } from "@emulators/core";

// A user in an Auth0 tenant. `user_id` is the Auth0 identifier, conventionally
// "{connection-strategy}|{id}" (e.g. "auth0|abc123").
export interface Auth0User extends Entity {
  user_id: string;
  email: string;
  email_verified: boolean;
  // Plaintext here on purpose: this is an emulator, not a real IdP.
  password: string | null;
  connection: string;
  username: string | null;
  name: string;
  nickname: string | null;
  given_name: string | null;
  family_name: string | null;
  picture: string | null;
  phone_number: string | null;
  phone_verified: boolean;
  blocked: boolean;
  user_metadata: Record<string, unknown>;
  app_metadata: Record<string, unknown>;
  last_login: string | null;
  logins_count: number;
  created_at_unix: number;
  updated_at_unix: number;
}

// An Auth0 Application (a.k.a. client).
export type Auth0AppType = "spa" | "native" | "regular_web" | "non_interactive";

export interface Auth0Client extends Entity {
  client_id: string;
  client_secret: string;
  name: string;
  description: string | null;
  app_type: Auth0AppType;
  // Public clients (spa/native) use PKCE and do not present a secret.
  token_endpoint_auth_method: "client_secret_post" | "client_secret_basic" | "none";
  callbacks: string[];
  allowed_logout_urls: string[];
  web_origins: string[];
  grant_types: string[];
  created_at_unix: number;
  updated_at_unix: number;
}

// A Connection is an identity source (database, social, enterprise). The
// `name` doubles as the Auth0 "realm" used by the password-realm grant.
export interface Auth0Connection extends Entity {
  connection_id: string;
  name: string;
  strategy: string;
  enabled_clients: string[];
  created_at_unix: number;
  updated_at_unix: number;
}

export interface Auth0Role extends Entity {
  role_id: string;
  name: string;
  description: string | null;
  created_at_unix: number;
  updated_at_unix: number;
}

export interface Auth0RoleAssignment extends Entity {
  role_id: string;
  user_id: string;
}

export interface Auth0Organization extends Entity {
  org_id: string;
  name: string;
  display_name: string | null;
  metadata: Record<string, unknown>;
  enabled_connections: string[];
  created_at_unix: number;
  updated_at_unix: number;
}

export interface Auth0OrganizationMember extends Entity {
  org_id: string;
  user_id: string;
  roles: string[];
}

// A Resource Server is an Auth0 API: its `identifier` is the audience that
// access tokens are minted for, and `scopes` are the permissions it defines.
// `enforce_policies` + `token_dialect: "access_token_authz"` opt the API into
// RBAC, which is what makes the `permissions` claim appear in access tokens.
export interface Auth0ResourceServer extends Entity {
  resource_server_id: string;
  name: string;
  identifier: string;
  scopes: string[];
  signing_alg: "RS256";
  enforce_policies: boolean;
  token_dialect: "access_token" | "access_token_authz";
  created_at_unix: number;
  updated_at_unix: number;
}

// A permission (scope) on a resource server granted to a role. A role's
// permissions are resolved through its assignees at token time.
export interface Auth0RolePermission extends Entity {
  role_id: string;
  resource_server_identifier: string;
  permission_name: string;
}

// A permission granted directly to a user (independent of any role).
export interface Auth0UserPermission extends Entity {
  user_id: string;
  resource_server_identifier: string;
  permission_name: string;
}

// A linked identity on a user (the Auth0 account-linking model). The primary
// identity is derived from the user's own connection; secondary identities are
// stored here and surfaced in the `identities` array.
export interface Auth0UserIdentity extends Entity {
  user_id: string;
  provider: string;
  connection: string;
  identity_user_id: string;
  is_social: boolean;
  profile_data: Record<string, unknown>;
}

// An MFA enrollment (authenticator) for a user.
export interface Auth0UserEnrollment extends Entity {
  enrollment_id: string;
  user_id: string;
  // "otp" | "oob" (sms/email/push) | "recovery-code" | "webauthn-roaming"
  type: string;
  // For oob: the channel ("sms", "email", "voice"). Null otherwise.
  oob_channel: string | null;
  // The shared secret (otp) or recovery code, kept in plaintext (emulator).
  secret: string | null;
  name: string | null;
  status: "pending" | "confirmed";
  created_at_unix: number;
}

// A Client Grant authorizes a client (machine-to-machine) for an API audience
// with a fixed set of scopes — the backing store for client_credentials.
export interface Auth0ClientGrant extends Entity {
  grant_id: string;
  client_id: string;
  audience: string;
  scopes: string[];
  created_at_unix: number;
  updated_at_unix: number;
}

// A Log Stream sends raw log records; an Event Stream sends typed domain
// events. Both are modeled with the same entity, differentiated by `kind`.
export type Auth0StreamKind = "log" | "event";

export interface Auth0Stream extends Entity {
  stream_id: string;
  kind: Auth0StreamKind;
  name: string;
  status: "active" | "paused";
  sink_url: string | null;
  // For event streams: the set of subscribed event types ("*" = all).
  subscriptions: string[];
  created_at_unix: number;
  updated_at_unix: number;
}

// A delivery attempt to a stream sink, retained for the inspector.
export interface Auth0StreamDelivery extends Entity {
  stream_id: string;
  kind: Auth0StreamKind;
  event_type: string;
  payload: unknown;
  status: number | null;
  error: string | null;
  delivered_at: string;
}

// A tenant log event (the Auth0 "log" object), also surfaced in the inspector.
export interface Auth0LogEvent extends Entity {
  log_id: string;
  type: string;
  description: string;
  client_id: string | null;
  user_id: string | null;
  ip: string | null;
  date: string;
}

// An email-verification (or password-change) ticket.
export interface Auth0Ticket extends Entity {
  ticket_id: string;
  user_id: string;
  kind: "email_verification" | "password_change";
  consumed: boolean;
  created_at_unix: number;
}

// A user block raised by attack protection, cleared via the user-blocks API.
export interface Auth0UserBlock extends Entity {
  identifier: string;
  ip: string;
  reason: "brute_force" | "suspicious_ip";
  created_at_unix: number;
}

// --- Extensibility (Theme C) ---

// An Auth0 Action. `trigger` binds it to a flow (e.g. "post-login",
// "credentials-exchange"). When `code` is present it is executed in a sandbox;
// otherwise the declarative `config` (from seed) drives behavior.
export interface Auth0Action extends Entity {
  action_id: string;
  name: string;
  trigger: string;
  code: string;
  // Declarative behavior used when there is no executable code (or alongside).
  config: Auth0ActionConfig | null;
  dependencies: Array<{ name: string; version: string }>;
  secrets: Array<{ name: string; value: string }>;
  deployed: boolean;
  created_at_unix: number;
  updated_at_unix: number;
}

// Declarative, code-free action behavior (the config-driven path).
export interface Auth0ActionConfig {
  addClaims?: { idToken?: Record<string, unknown>; accessToken?: Record<string, unknown> };
  denyWith?: string;
  requireMfa?: boolean;
  setAppMetadata?: Record<string, unknown>;
  setUserMetadata?: Record<string, unknown>;
}

// Ordered binding of actions to a trigger.
export interface Auth0ActionBinding extends Entity {
  trigger: string;
  action_id: string;
  display_name: string;
  order: number;
}

// A legacy Rule (executes JS on login; ordered globally).
export interface Auth0Rule extends Entity {
  rule_id: string;
  name: string;
  script: string;
  order: number;
  enabled: boolean;
  created_at_unix: number;
  updated_at_unix: number;
}

// A legacy Hook (extensibility point keyed by triggerId).
export interface Auth0Hook extends Entity {
  hook_id: string;
  name: string;
  triggerId: string;
  script: string;
  enabled: boolean;
  created_at_unix: number;
  updated_at_unix: number;
}

// --- Sessions & jobs (Theme D) ---

// A user authentication session, created on successful token issuance.
export interface Auth0Session extends Entity {
  session_id: string;
  user_id: string;
  client_id: string | null;
  created_at_unix: number;
  last_interacted_unix: number;
}

// An async job (verification email, users import/export). Synchronously
// "completed" in the emulator but shaped like the real job object.
export interface Auth0Job extends Entity {
  job_id: string;
  type: "verification_email" | "users_import" | "users_export";
  status: "pending" | "completed" | "failed";
  connection_id: string | null;
  created_at_unix: number;
}
