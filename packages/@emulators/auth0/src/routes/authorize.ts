import { randomBytes } from "node:crypto";
import type { Context } from "@emulators/core";
import type { AppEnv, RouteContext } from "@emulators/core";
import { bodyStr, matchesRedirectUri, renderErrorPage, renderFormPostPage } from "@emulators/core";
import { getAuth0Store } from "../store.js";
import { getPendingCodes, type PendingCode } from "../route-helpers.js";
import { clientIp, isBlocked } from "../attack-protection.js";
import { recordLog } from "../events.js";
import { getPushedRequests } from "./protocols.js";
import { renderUniversalLogin, SERVICE_LABEL } from "./ui.js";

// GET /authorize — Universal Login. Validates the client and redirect_uri, then
// renders the seeded-user picker. PKCE params are carried through hidden fields.
export function authorizeRoutes({ app, store }: RouteContext): void {
  const as = getAuth0Store(store);

  app.get("/authorize", (c) => {
    // Resolve PAR request_uri (RFC 9126): pushed params override the query.
    const requestUri = c.req.query("request_uri") ?? "";
    const pushed = requestUri ? getPushedRequests(store).get(requestUri) : undefined;
    const q = (name: string): string => pushed?.params[name] ?? c.req.query(name) ?? "";
    if (requestUri && pushed && Date.now() / 1000 > pushed.expiresAt) {
      getPushedRequests(store).delete(requestUri);
    }

    const clientId = q("client_id");
    const redirectUri = q("redirect_uri");
    const scope = q("scope") || "openid profile email";
    const state = q("state");
    const nonce = q("nonce");
    const audience = q("audience");
    const organization = q("organization");
    const responseType = q("response_type") || "code";
    const responseMode = q("response_mode") || "query";
    const codeChallenge = q("code_challenge");
    const codeChallengeMethod = q("code_challenge_method");

    if (responseType !== "code") {
      return c.html(
        renderErrorPage("Unsupported response_type", "Only response_type=code is supported.", SERVICE_LABEL),
        400,
      );
    }
    if (!redirectUri) {
      return c.html(
        renderErrorPage("Missing redirect URI", "The redirect_uri parameter is required.", SERVICE_LABEL),
        400,
      );
    }

    const clients = as.clients.all();
    let appName = "";
    if (clients.length > 0) {
      const client = clients.find((entry) => entry.client_id === clientId);
      if (!client) {
        return c.html(
          renderErrorPage("Application not found", `The client_id '${clientId}' is not registered.`, SERVICE_LABEL),
          400,
        );
      }
      if (!matchesRedirectUri(redirectUri, client.callbacks)) {
        return c.html(
          renderErrorPage(
            "Callback URL mismatch",
            "The redirect_uri is not registered for this client.",
            SERVICE_LABEL,
          ),
          400,
        );
      }
      appName = client.name;
    }

    return c.html(
      renderUniversalLogin(as.users.all(), appName, {
        redirect_uri: redirectUri,
        scope,
        state,
        nonce,
        audience,
        organization,
        client_id: clientId,
        response_mode: responseMode,
        code_challenge: codeChallenge,
        code_challenge_method: codeChallengeMethod,
      }),
    );
  });

  const handleCallback = async (c: Context<AppEnv>): Promise<Response> => {
    const body = await c.req.parseBody();
    const userRef = bodyStr(body.user_ref);
    const redirectUri = bodyStr(body.redirect_uri);
    const scope = bodyStr(body.scope) || "openid profile email";
    const state = bodyStr(body.state);
    const nonce = bodyStr(body.nonce);
    const audience = bodyStr(body.audience);
    const organization = bodyStr(body.organization);
    const clientId = bodyStr(body.client_id);
    const responseMode = bodyStr(body.response_mode) || "query";
    const codeChallenge = bodyStr(body.code_challenge);
    const codeChallengeMethod = bodyStr(body.code_challenge_method);

    if (!redirectUri) {
      return c.html(
        renderErrorPage("Missing redirect URI", "The redirect_uri parameter is required.", SERVICE_LABEL),
        400,
      );
    }

    const user = as.users.findOneBy("user_id", userRef);
    if (!user) {
      return c.html(renderErrorPage("Unknown user", "The selected user is not available.", SERVICE_LABEL), 400);
    }

    const ip = clientIp(c.req.header("X-Forwarded-For"));
    if (isBlocked(store, user.email, ip)) {
      return c.html(
        renderErrorPage(
          "Account blocked",
          "This account is temporarily blocked due to suspicious activity.",
          SERVICE_LABEL,
        ),
        429,
      );
    }

    const clients = as.clients.all();
    if (clients.length > 0) {
      const client = clients.find((entry) => entry.client_id === clientId);
      if (!client || !matchesRedirectUri(redirectUri, client.callbacks)) {
        return c.html(
          renderErrorPage(
            "Callback URL mismatch",
            "The redirect_uri is not registered for this client.",
            SERVICE_LABEL,
          ),
          400,
        );
      }
    }

    // Resolve organization reference (id "org_..." or name) if supplied.
    let orgId: string | null = null;
    if (organization) {
      const org =
        as.organizations.findOneBy("org_id", organization) ?? as.organizations.findOneBy("name", organization);
      orgId = org?.org_id ?? null;
    }

    const code = randomBytes(24).toString("hex");
    const pending: PendingCode = {
      userId: user.user_id,
      clientId,
      redirectUri,
      scope,
      audience,
      nonce: nonce || null,
      orgId,
      codeChallenge: codeChallenge || null,
      codeChallengeMethod: codeChallengeMethod || null,
      createdAt: Date.now(),
    };
    getPendingCodes(store).set(code, pending);

    await recordLog(store, {
      type: "slo",
      description: "Login via Universal Login",
      clientId: clientId || null,
      userId: user.user_id,
      ip,
    });

    if (responseMode === "form_post") {
      return c.html(renderFormPostPage(redirectUri, { code, state }, SERVICE_LABEL));
    }
    const url = new URL(redirectUri);
    url.searchParams.set("code", code);
    if (state) url.searchParams.set("state", state);
    return c.redirect(url.toString(), 302);
  };

  app.post("/u/login/callback", handleCallback);
  // Auth0 SDKs sometimes post the consent/login form to /login/callback.
  app.post("/login/callback", handleCallback);
}
