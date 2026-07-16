import { escapeHtml, renderCardPage, renderUserButton } from "@emulators/core";
import type { Auth0User } from "../entities.js";
import { userDisplayName } from "../helpers.js";

export const SERVICE_LABEL = "Auth0";

// Render the Universal Login page: a list of seeded users to pick from, posting
// to the authorize callback with the full set of OAuth parameters preserved.
// `formAction` defaults to the OIDC callback; SAML/WS-Fed pass their own.
export function renderUniversalLogin(
  users: Auth0User[],
  appName: string,
  hiddenBase: Record<string, string>,
  formAction = "/u/login/callback",
): string {
  const buttons = users
    .map((user) =>
      renderUserButton({
        letter: (user.name?.[0] ?? user.email?.[0] ?? "?").toUpperCase(),
        login: user.email,
        name: userDisplayName(user),
        email: user.email,
        formAction,
        hiddenFields: { ...hiddenBase, user_ref: user.user_id },
      }),
    )
    .join("\n");

  const subtitle = appName
    ? `Log in to <strong>${escapeHtml(appName)}</strong> to continue.`
    : "Choose a seeded user to continue.";

  return renderCardPage(
    "Welcome",
    subtitle,
    users.length > 0 ? buttons : '<p class="empty">No users in the emulator store.</p>',
    SERVICE_LABEL,
  );
}
