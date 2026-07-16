import type { RouteContext } from "@emulators/core";
import { matchesRedirectUri } from "@emulators/core";
import { getAuth0Store } from "../store.js";

// GET /v2/logout — Auth0 logout. Redirects to returnTo when provided and
// allowed by a registered client's allowed_logout_urls.
export function logoutRoutes({ app, store }: RouteContext): void {
  const as = getAuth0Store(store);

  app.get("/v2/logout", (c) => {
    const returnTo = c.req.query("returnTo");
    const clientId = c.req.query("client_id") ?? "";
    if (!returnTo) return c.text("Logged out");

    const clients = as.clients.all();
    if (clients.length > 0) {
      const client = clientId ? clients.find((entry) => entry.client_id === clientId) : undefined;
      const allowed = client
        ? matchesRedirectUri(returnTo, client.allowed_logout_urls)
        : clients.some((entry) => matchesRedirectUri(returnTo, entry.allowed_logout_urls));
      if (!allowed) return c.text("Invalid returnTo URL", 400);
    }

    return c.redirect(returnTo, 302);
  });

  // GET /oidc/logout — OIDC RP-Initiated Logout (spec-compliant alias). Honors
  // post_logout_redirect_uri + id_token_hint instead of returnTo + client_id.
  app.get("/oidc/logout", (c) => {
    const redirectUri = c.req.query("post_logout_redirect_uri");
    if (!redirectUri) return c.text("Logged out");

    const clients = as.clients.all();
    if (clients.length > 0) {
      const allowed = clients.some((entry) => matchesRedirectUri(redirectUri, entry.allowed_logout_urls));
      if (!allowed) return c.text("Invalid post_logout_redirect_uri", 400);
    }

    const state = c.req.query("state");
    const url = new URL(redirectUri);
    if (state) url.searchParams.set("state", state);
    return c.redirect(url.toString(), 302);
  });
}
