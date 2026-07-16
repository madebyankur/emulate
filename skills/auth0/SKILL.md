---
name: auth0
description: Emulated Auth0 identity platform (OAuth 2.0 / OIDC, Management API v2, log streams, event streams, attack protection) for local development and testing. Use when the user needs to test Auth0 login locally, emulate Auth0 OIDC discovery, exchange tokens, use the password-realm grant, manage users/clients/roles/organizations via the Management API, test refresh-token rotation, audience-scoped access tokens, log or event streams, or attack protection without hitting a real Auth0 tenant. Triggers include "Auth0", "emulate Auth0", "mock Auth0 login", "test Auth0 sign-in", "password-realm", "Auth0 Management API", "Auth0 Universal Login", "Auth0 organizations", "Auth0 event streams", "Auth0 attack protection", or any task requiring a local Auth0 provider.
allowed-tools: Bash(npx emulate:*), Bash(emulate:*), Bash(curl:*)
---

# Auth0 Emulator

Auth0 identity platform emulation: OAuth 2.0 / OIDC (authorization code + PKCE, refresh token rotation, client credentials, password-realm, device code), Management API v2 (users, clients, connections, roles, organizations, resource servers, client grants, tickets, tenant settings, Guardian), and the platform features thin mocks skip — log streams, event streams, and stateful attack protection.

Access tokens are RS256 JWTs minted for the requested API `audience`. The issuer carries Auth0's trailing slash (`http://localhost:4013/`), so SDK token verification passes.

## Start

```bash
# Auth0 only
npx emulate --service auth0

# Default port (when run alone)
# http://localhost:4000
```

Or programmatically:

```typescript
import { createEmulator } from 'emulate'

const auth0 = await createEmulator({ service: 'auth0', port: 4013 })
// auth0.url === 'http://localhost:4013'
```

## Pointing Your App at the Emulator

### Environment Variable

```bash
AUTH0_EMULATOR_URL=http://localhost:4013
```

### URL Mapping

| Real Auth0 URL | Emulator URL |
|----------------|--------------|
| `https://{tenant}.auth0.com/.well-known/openid-configuration` | `$AUTH0_EMULATOR_URL/.well-known/openid-configuration` |
| `https://{tenant}.auth0.com/.well-known/jwks.json` | `$AUTH0_EMULATOR_URL/.well-known/jwks.json` |
| `https://{tenant}.auth0.com/authorize` | `$AUTH0_EMULATOR_URL/authorize` |
| `https://{tenant}.auth0.com/oauth/token` | `$AUTH0_EMULATOR_URL/oauth/token` |
| `https://{tenant}.auth0.com/userinfo` | `$AUTH0_EMULATOR_URL/userinfo` |
| `https://{tenant}.auth0.com/v2/logout` | `$AUTH0_EMULATOR_URL/v2/logout` |
| `https://{tenant}.auth0.com/api/v2/...` | `$AUTH0_EMULATOR_URL/api/v2/...` |

### @auth0/nextjs-auth0

```bash
AUTH0_ISSUER_BASE_URL=http://localhost:4013
AUTH0_BASE_URL=http://localhost:3000
AUTH0_CLIENT_ID=auth0_emulate_client
AUTH0_CLIENT_SECRET=auth0_emulate_secret
AUTH0_SECRET=a-long-random-string
```

### Auth.js / NextAuth.js

```typescript
import Auth0 from '@auth/core/providers/auth0'

Auth0({
  clientId: process.env.AUTH0_CLIENT_ID,
  clientSecret: process.env.AUTH0_CLIENT_SECRET,
  issuer: process.env.AUTH0_EMULATOR_URL, // http://localhost:4013
})
```

## Seed Config

```yaml
auth0:
  users:
    - email: user@example.com
      email_verified: true
      password: Password123!
      name: Test User
      connection: Username-Password-Authentication
      roles: [admin]
  clients:
    - client_id: auth0_emulate_client
      client_secret: auth0_emulate_secret
      name: My Auth0 App
      app_type: regular_web
      callbacks:
        - http://localhost:3000/api/auth/callback
      allowed_logout_urls:
        - http://localhost:3000
      grant_types: [authorization_code, refresh_token, client_credentials, password]
  resource_servers:
    - name: My API
      identifier: https://api.example.com
      scopes: [read:items, write:items]
  client_grants:
    - client_id: auth0_emulate_client
      audience: https://api.example.com
      scopes: [read:items, write:items]
  roles:
    - name: admin
      description: Administrator
  organizations:
    - name: acme
      display_name: Acme Inc
      members: [user@example.com]
  breached_passwords: [password, 123456, qwerty]
```

`app_type: spa` and `native` create public clients (PKCE, no secret). When no clients are configured the emulator accepts any `client_id`; with clients configured, `client_id`, `client_secret` (for confidential clients), and `redirect_uri` are validated.

## API Endpoints

### OIDC Discovery

```bash
curl http://localhost:4013/.well-known/openid-configuration
curl http://localhost:4013/.well-known/jwks.json
```

The issuer is `http://localhost:4013/` (trailing slash). JWKS exposes an RSA key (`kid`: `emulate-auth0-1`).

### Authorization Code + PKCE

```bash
# Browser flow: renders Universal Login with a seeded-user picker
curl -v "http://localhost:4013/authorize?\
client_id=auth0_emulate_client&\
redirect_uri=http://localhost:3000/api/auth/callback&\
scope=openid+profile+email&\
response_type=code&\
state=abc&\
audience=https://api.example.com&\
code_challenge=<challenge>&code_challenge_method=S256"
```

After the user picks an account the emulator posts to `/u/login/callback` and redirects to `redirect_uri?code=...&state=...`. Exchange the code:

```bash
curl -X POST http://localhost:4013/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"authorization_code","code":"<code>","redirect_uri":"http://localhost:3000/api/auth/callback","client_id":"auth0_emulate_client","client_secret":"auth0_emulate_secret","code_verifier":"<verifier>"}'
```

### Password Realm (resource owner)

```bash
curl -X POST http://localhost:4013/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"http://auth0.com/oauth/grant-type/password-realm","username":"user@example.com","password":"Password123!","realm":"Username-Password-Authentication","client_id":"auth0_emulate_client","client_secret":"auth0_emulate_secret","scope":"openid profile email offline_access","audience":"https://api.example.com"}'
```

Returns `access_token` (JWT, `aud` = the API identifier), `id_token`, `refresh_token` (when `offline_access` is requested), `scope`, `expires_in`, `token_type`.

### Client Credentials (machine to machine)

```bash
curl -X POST http://localhost:4013/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"client_credentials","client_id":"auth0_emulate_client","client_secret":"auth0_emulate_secret","audience":"https://api.example.com"}'
```

When a client grant exists for the (client, audience) pair, the granted scopes are applied. Use the `{baseUrl}/api/v2/` audience to mint a Management API token.

### Refresh Token (with rotation)

```bash
curl -X POST http://localhost:4013/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"refresh_token","refresh_token":"<token>","client_id":"auth0_emulate_client"}'
```

The old refresh token is invalidated and a new one is returned.

### User Info

```bash
curl http://localhost:4013/userinfo -H "Authorization: Bearer <access_token>"
```

### Self-service signup and password reset

```bash
# Public signup
curl -X POST http://localhost:4013/dbconnections/signup \
  -H "Content-Type: application/json" \
  -d '{"client_id":"auth0_emulate_client","email":"new@example.com","password":"NewPass123!","connection":"Username-Password-Authentication"}'

# Request a password-change ticket (URL returned in X-Emulate-Reset-Ticket header)
curl -i -X POST http://localhost:4013/dbconnections/change_password \
  -H "Content-Type: application/json" \
  -d '{"client_id":"auth0_emulate_client","email":"new@example.com","connection":"Username-Password-Authentication"}'
```

### Management API v2

Authenticate with a Bearer token minted via `client_credentials` for the `{baseUrl}/api/v2/` audience.

```bash
TOKEN=$(curl -s -X POST http://localhost:4013/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"client_credentials","client_id":"auth0_emulate_client","client_secret":"auth0_emulate_secret","audience":"http://localhost:4013/api/v2/"}' \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['access_token'])")

# Create a user
curl -X POST http://localhost:4013/api/v2/users \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"email":"new@example.com","password":"secret","connection":"Username-Password-Authentication","email_verified":true}'

# List users (use include_totals=true for the paged envelope)
curl "http://localhost:4013/api/v2/users?include_totals=true" -H "Authorization: Bearer $TOKEN"

# Find by email
curl "http://localhost:4013/api/v2/users-by-email?email=new@example.com" -H "Authorization: Bearer $TOKEN"
```

Other resources follow the same pattern: `/api/v2/clients`, `/api/v2/connections`, `/api/v2/roles` (+ `/:id/users`), `/api/v2/organizations` (+ `/:id/members`), `/api/v2/resource-servers`, `/api/v2/client-grants`, `/api/v2/tickets/email-verification`, `/api/v2/tenants/settings`, `/api/v2/guardian/factors`, `/api/v2/logs`.

### Log Streams vs Event Streams

These are separate subsystems. Log streams receive raw log records; event streams receive typed domain events filtered by subscription.

```bash
# Event stream: subscribe to user.created and login events
curl -X POST http://localhost:4013/api/v2/event-streams \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"events","subscriptions":[{"event_type":"user.created"},{"event_type":"login.succeeded"}],"sink":{"httpEndpoint":"https://example.com/hook"}}'

# Log stream: receives raw log records
curl -X POST http://localhost:4013/api/v2/log-streams \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"logs","sink":{"httpEndpoint":"https://example.com/logs"}}'

# Inspect recorded deliveries (no external sink needed)
curl http://localhost:4013/_emulate/stream-deliveries
```

Domain event types include `user.created`, `user.updated`, `user.deleted`, `login.succeeded`, `login.failed`, and `user.blocked`.

### Attack Protection

Stateful enforcement, configurable and clearable for tests.

```bash
# Lower the brute-force threshold
curl -X PATCH http://localhost:4013/api/v2/attack-protection/brute-force-protection \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"max_attempts":3}'

# After 3 failed password-realm attempts the account is blocked (429 too_many_attempts).
# Inspect and clear blocks:
curl "http://localhost:4013/api/v2/user-blocks?identifier=user@example.com" -H "Authorization: Bearer $TOKEN"
curl -X DELETE "http://localhost:4013/api/v2/user-blocks?identifier=user@example.com" -H "Authorization: Bearer $TOKEN"

# Seed breached passwords (rejected with password_leaked)
curl -X PATCH http://localhost:4013/api/v2/attack-protection/breached-password-detection \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"enabled":true,"passwords":["password","hunter2"]}'
```

### Device Authorization Flow

```bash
# 1. Request a device code
curl -X POST http://localhost:4013/oauth/device/code \
  -H "Content-Type: application/json" \
  -d '{"client_id":"auth0_emulate_client","scope":"openid profile","audience":"https://api.example.com"}'

# 2. Approve it (emulator test helper, in place of the activation page)
curl -X POST http://localhost:4013/_emulate/device/approve \
  -H "Content-Type: application/json" \
  -d '{"device_code":"<device_code>","user_id":"<user_id>"}'

# 3. Poll for tokens
curl -X POST http://localhost:4013/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":"<device_code>","client_id":"auth0_emulate_client"}'
```

### Logout

```bash
curl "http://localhost:4013/v2/logout?client_id=auth0_emulate_client&returnTo=http://localhost:3000"
# OIDC RP-initiated logout is also supported:
curl "http://localhost:4013/oidc/logout?post_logout_redirect_uri=http://localhost:3000"
```

### RBAC (permissions claim)

Set `enforce_policies: true` on a resource server and grant permissions to roles
(or users) — access tokens for that API audience then carry a `permissions`
claim. Manage them via `POST /api/v2/users/:id/permissions` and
`POST /api/v2/roles/:id/permissions`. Org logins also emit `org_name` alongside
`org_id`.

### Actions, Rules, Hooks

Seed Actions either declaratively (`config`) or with real JS (`code`, run in a
`node:vm` sandbox with the Auth0 `event`/`api` objects). The post-login pipeline
can inject custom claims (`api.idToken.setCustomClaim`), deny a login
(`api.access.deny`), or force MFA (`api.multifactor.enable`). Legacy Rules and
Hooks are supported for older tenants. Manage at `/api/v2/actions/actions`,
`/api/v2/rules`, `/api/v2/hooks`.

### Passwordless

```bash
# Start an email/SMS code
curl http://localhost:4013/passwordless/start -H 'Content-Type: application/json' \
  -d '{"connection":"email","email":"new@example.com"}'
# Read the issued code (emulator test helper, in place of the inbox)
curl "http://localhost:4013/_emulate/passwordless/code?identifier=new@example.com"
# Exchange the code for tokens (auto-creates the user)
curl http://localhost:4013/oauth/token -H 'Content-Type: application/json' -d '{
  "grant_type":"http://auth0.com/oauth/grant-type/passwordless/otp",
  "client_id":"auth0_emulate_client","client_secret":"auth0_emulate_secret",
  "username":"new@example.com","otp":"<code>","realm":"email","scope":"openid email"}'
```

### MFA

When MFA is required (seed `mfa.always_on`, a per-user/connection policy, an
enrolled authenticator, or an Action), login returns `403 mfa_required` with an
`mfa_token`. Associate an authenticator (`POST /mfa/associate` with the
`mfa_token` as Bearer), then complete with an MFA grant
(`http://auth0.com/oauth/grant-type/mfa-otp`, the emulator OTP is `000000`).

### Other protocols

- **PAR**: `POST /oauth/par` returns a `request_uri` accepted by `/authorize`.
- **Dynamic registration**: `POST /oidc/register` creates a client (RFC 7591).
- **SAML**: `GET /samlp/:clientId` (signed `<samlp:Response>` to the ACS) and
  `GET /samlp/metadata/:clientId`.
- **WS-Fed**: `GET /wsfed/:clientId` (signed SAML 1.1 assertion via wresult) and
  `/wsfed/FederationMetadata/2007-06/FederationMetadata.xml`.
- **CIBA**: `POST /bc-authorize` + the `urn:openid:params:grant-type:ciba` grant
  (approve out-of-band via `POST /_emulate/ciba/approve`).
- **Passkeys**: `POST /passkey/challenge` and `/passkey/register` (minimal
  ceremony, no real attestation crypto).

### Inspector

Open `http://localhost:4013/` for a tabbed dashboard of users, applications, connections, organizations, roles, APIs, Actions/Rules, MFA enrollments, sessions, streams, attack-protection blocks, and logs.

## Notes

- Access tokens are JWTs scoped to the requested `audience`; register APIs as resource servers to make audience/scope meaningful, and set `enforce_policies` to surface the `permissions` claim.
- Refresh tokens are only issued when `offline_access` is in scope.
- Action/Rule/Hook code runs in a `node:vm` sandbox with a 1s timeout; this is a fidelity convenience, not a security boundary (the emulator runs trusted local config).
- SAML/WS-Fed assertions are genuinely RS256-signed with the tenant key but use a minimal canonicalization — sufficient for SDK signature verification, not a full SAML IdP (no encryption, single NameID format).
- Not implemented: HS256 token signing, real TOTP/WebAuthn cryptographic verification (the emulator accepts a deterministic OTP), custom database action scripts, and exact production rate limiting.
