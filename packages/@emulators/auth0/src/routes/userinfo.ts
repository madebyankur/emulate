import type { RouteContext } from "@emulators/core";
import { getAuth0Store } from "../store.js";
import { getAccessTokens } from "../route-helpers.js";
import { userDisplayName } from "../helpers.js";

// GET /userinfo — OIDC user info for the bearer access token. We resolve the
// user from the OAuth access-token store (set at token issuance).
export function userinfoRoutes({ app, store }: RouteContext): void {
  const as = getAuth0Store(store);

  app.get("/userinfo", (c) => {
    const authHeader = c.req.header("Authorization") ?? "";
    const token = authHeader.replace(/^Bearer\s+/i, "").trim();
    const access = getAccessTokens(store).get(token);
    if (!access || !access.userId) {
      return c.json({ error: "invalid_token", error_description: "The access token is invalid." }, 401);
    }

    const user = as.users.findOneBy("user_id", access.userId);
    if (!user) {
      return c.json({ error: "invalid_token", error_description: "User not found." }, 401);
    }

    return c.json({
      sub: user.user_id,
      name: userDisplayName(user),
      nickname: user.nickname ?? user.email,
      given_name: user.given_name ?? undefined,
      family_name: user.family_name ?? undefined,
      picture: user.picture ?? `https://s.gravatar.com/avatar/${encodeURIComponent(user.email)}`,
      email: user.email,
      email_verified: user.email_verified,
      updated_at: new Date(user.updated_at_unix * 1000).toISOString(),
    });
  });
}
