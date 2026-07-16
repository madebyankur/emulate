# @emulators/auth0

Auth0 identity platform emulation with OAuth 2.0 / OIDC, Management API v2, log streams, event streams, and attack protection.

Part of [emulate](https://github.com/vercel-labs/emulate), local drop-in replacement services for CI and no-network sandboxes.

## Install

```bash
npm install @emulators/auth0
```

## Endpoints

### OIDC / Authentication API

- `GET /.well-known/openid-configuration` - OIDC discovery (issuer carries Auth0's trailing slash)
- `GET /.well-known/jwks.json` - JSON Web Key Set (RS256)
- `GET /authorize` - Universal Login with seeded-user picker and PKCE
- `POST /oauth/token` - `authorization_code`, `refresh_token`, `client_credentials`, `password`, `password-realm`, `device_code`
- `POST /oauth/device/code` - device authorization flow
- `POST /oauth/revoke` - revoke a refresh token
- `GET /userinfo` - OIDC user info
- `GET /v2/logout` - logout with `returnTo` validation
- `POST /dbconnections/signup` - public user self-registration
- `POST /dbconnections/change_password` - issue a password-change ticket

### Management API v2

Users, clients (applications), connections, roles, organizations, resource servers, client grants, email-verification and password-change tickets, tenant settings, Guardian factors, and logs under `/api/v2/*`. Authenticate with a Bearer access token minted via the `client_credentials` grant for the `{baseUrl}/api/v2/` audience.

### Platform features

- **Log streams** (`/api/v2/log-streams`) - raw tenant log records
- **Event streams** (`/api/v2/event-streams`) - typed domain events (`user.created`, `login.succeeded`, …) filtered by subscription
- **Attack protection** (`/api/v2/attack-protection/*`, `/api/v2/user-blocks`) - stateful brute-force, suspicious-IP, and breached-password enforcement
- **Inspector** (`GET /`) - tabbed dashboard for all resources, streams, blocks, and logs

## Access tokens

Access tokens are RS256 JWTs minted for the requested API `audience`. Register APIs as resource servers (`/api/v2/resource-servers`) and authorize machine-to-machine clients with client grants (`/api/v2/client-grants`).

## Notes

Log streams and event streams are separate subsystems, as in production Auth0: a single action (e.g. creating a user) emits a log record to log streams and a distinct typed event to subscribed event streams. Stream deliveries are observable at `GET /_emulate/stream-deliveries`.

Not implemented: HS256 token signing, live MFA challenge/enrollment, Actions/Rules/Hooks, custom database scripts, enterprise connection brokering, and exact production rate limiting.
