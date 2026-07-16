import type { RouteContext } from "@emulators/core";
import {
  issuerFromBaseUrl,
  PASSWORD_REALM_GRANT,
  DEVICE_CODE_GRANT,
  PASSWORDLESS_OTP_GRANT,
  MFA_OTP_GRANT,
  MFA_OOB_GRANT,
  MFA_RECOVERY_GRANT,
  CIBA_GRANT,
} from "../helpers.js";
import { publicJwk } from "../keys.js";

export function oidcDiscoveryRoutes({ app, baseUrl }: RouteContext): void {
  app.get("/.well-known/openid-configuration", (c) => {
    const issuer = issuerFromBaseUrl(baseUrl);
    return c.json({
      issuer,
      authorization_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/oauth/token`,
      device_authorization_endpoint: `${baseUrl}/oauth/device/code`,
      userinfo_endpoint: `${baseUrl}/userinfo`,
      mfa_challenge_endpoint: `${baseUrl}/mfa/challenge`,
      jwks_uri: `${baseUrl}/.well-known/jwks.json`,
      registration_endpoint: `${baseUrl}/oidc/register`,
      revocation_endpoint: `${baseUrl}/oauth/revoke`,
      end_session_endpoint: `${baseUrl}/v2/logout`,
      pushed_authorization_request_endpoint: `${baseUrl}/oauth/par`,
      backchannel_authentication_endpoint: `${baseUrl}/bc-authorize`,
      scopes_supported: ["openid", "profile", "offline_access", "name", "email", "email_verified"],
      response_types_supported: ["code", "token", "id_token", "code token", "code id_token", "token id_token"],
      response_modes_supported: ["query", "fragment", "form_post"],
      subject_types_supported: ["public"],
      grant_types_supported: [
        "authorization_code",
        "implicit",
        "refresh_token",
        "client_credentials",
        "password",
        PASSWORD_REALM_GRANT,
        DEVICE_CODE_GRANT,
        PASSWORDLESS_OTP_GRANT,
        MFA_OTP_GRANT,
        MFA_OOB_GRANT,
        MFA_RECOVERY_GRANT,
        CIBA_GRANT,
      ],
      request_uri_parameter_supported: true,
      id_token_signing_alg_values_supported: ["HS256", "RS256"],
      token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
      claims_supported: [
        "aud",
        "auth_time",
        "exp",
        "iat",
        "iss",
        "name",
        "nickname",
        "email",
        "email_verified",
        "sub",
        "org_id",
        "org_name",
        "permissions",
      ],
      code_challenge_methods_supported: ["S256", "plain"],
    });
  });

  app.get("/.well-known/jwks.json", async (c) => {
    return c.json({ keys: [await publicJwk()] });
  });
}
