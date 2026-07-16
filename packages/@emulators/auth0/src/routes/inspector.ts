import type { InspectorTab, RouteContext } from "@emulators/core";
import { escapeHtml, renderInspectorPage } from "@emulators/core";
import { getAuth0Store } from "../store.js";
import { SERVICE_LABEL } from "./ui.js";

const TABS: InspectorTab[] = [
  { id: "users", label: "Users", href: "/?tab=users" },
  { id: "clients", label: "Applications", href: "/?tab=clients" },
  { id: "connections", label: "Connections", href: "/?tab=connections" },
  { id: "orgs", label: "Organizations", href: "/?tab=orgs" },
  { id: "roles", label: "Roles", href: "/?tab=roles" },
  { id: "apis", label: "APIs", href: "/?tab=apis" },
  { id: "actions", label: "Actions", href: "/?tab=actions" },
  { id: "mfa", label: "MFA", href: "/?tab=mfa" },
  { id: "sessions", label: "Sessions", href: "/?tab=sessions" },
  { id: "streams", label: "Streams", href: "/?tab=streams" },
  { id: "protection", label: "Attack Protection", href: "/?tab=protection" },
  { id: "logs", label: "Logs", href: "/?tab=logs" },
];

type TabId = (typeof TABS)[number]["id"];

export function inspectorRoutes({ app, store }: RouteContext): void {
  const as = () => getAuth0Store(store);

  app.get("/", (c) => {
    const requested = c.req.query("tab") ?? "users";
    const active = (TABS.some((t) => t.id === requested) ? requested : "users") as TabId;
    let body: string;
    switch (active) {
      case "clients":
        body = clientsView();
        break;
      case "connections":
        body = connectionsView();
        break;
      case "orgs":
        body = orgsView();
        break;
      case "roles":
        body = rolesView();
        break;
      case "apis":
        body = apisView();
        break;
      case "actions":
        body = actionsView();
        break;
      case "mfa":
        body = mfaView();
        break;
      case "sessions":
        body = sessionsView();
        break;
      case "streams":
        body = streamsView();
        break;
      case "protection":
        body = protectionView();
        break;
      case "logs":
        body = logsView();
        break;
      default:
        body = usersView();
    }
    return c.html(renderInspectorPage("Auth0 Inspector", TABS, active, body, SERVICE_LABEL));
  });

  function usersView(): string {
    const rows = as()
      .users.all()
      .map((u) => [
        escapeHtml(u.user_id),
        escapeHtml(u.email),
        escapeHtml(u.email_verified ? "yes" : "no"),
        escapeHtml(u.connection),
        escapeHtml(u.blocked ? "blocked" : "active"),
        escapeHtml(String(u.logins_count)),
      ]);
    return section(
      "Users",
      table(["User ID", "Email", "Verified", "Connection", "Status", "Logins"], rows, "No users."),
    );
  }

  function clientsView(): string {
    const rows = as()
      .clients.all()
      .map((cl) => [
        escapeHtml(cl.name),
        escapeHtml(cl.client_id),
        escapeHtml(cl.app_type),
        escapeHtml(cl.token_endpoint_auth_method),
        escapeHtml(cl.callbacks.join(", ")),
      ]);
    return section(
      "Applications",
      table(["Name", "Client ID", "Type", "Auth Method", "Callbacks"], rows, "No applications."),
    );
  }

  function connectionsView(): string {
    const rows = as()
      .connections.all()
      .map((cn) => [escapeHtml(cn.name), escapeHtml(cn.strategy), escapeHtml(cn.enabled_clients.join(", "))]);
    return section("Connections", table(["Name", "Strategy", "Enabled Clients"], rows, "No connections."));
  }

  function orgsView(): string {
    const rows = as()
      .organizations.all()
      .map((o) => [
        escapeHtml(o.name),
        escapeHtml(o.display_name ?? ""),
        escapeHtml(String(as().orgMembers.findBy("org_id", o.org_id).length)),
        escapeHtml(o.enabled_connections.join(", ")),
      ]);
    return section(
      "Organizations",
      table(["Name", "Display Name", "Members", "Connections"], rows, "No organizations."),
    );
  }

  function rolesView(): string {
    const rows = as()
      .roles.all()
      .map((r) => [
        escapeHtml(r.name),
        escapeHtml(r.description ?? ""),
        escapeHtml(String(as().roleAssignments.findBy("role_id", r.role_id).length)),
      ]);
    return section("Roles", table(["Name", "Description", "Assignees"], rows, "No roles."));
  }

  function apisView(): string {
    const rows = as()
      .resourceServers.all()
      .map((rs) => [escapeHtml(rs.name), escapeHtml(rs.identifier), escapeHtml(rs.scopes.join(", "))]);
    const grantRows = as()
      .clientGrants.all()
      .map((g) => [escapeHtml(g.client_id), escapeHtml(g.audience), escapeHtml(g.scopes.join(", "))]);
    return (
      section("Resource Servers (APIs)", table(["Name", "Identifier (Audience)", "Scopes"], rows, "No APIs.")) +
      section("Client Grants", table(["Client ID", "Audience", "Scopes"], grantRows, "No client grants."))
    );
  }

  function actionsView(): string {
    const actionRows = as()
      .actions.all()
      .map((a) => [
        escapeHtml(a.name),
        escapeHtml(a.trigger),
        escapeHtml(a.code ? "code" : "config"),
        escapeHtml(a.deployed ? "deployed" : "draft"),
      ]);
    const ruleRows = as()
      .rules.all()
      .map((r) => [escapeHtml(r.name), escapeHtml(String(r.order)), escapeHtml(r.enabled ? "enabled" : "disabled")]);
    return (
      section("Actions", table(["Name", "Trigger", "Kind", "Status"], actionRows, "No actions.")) +
      section("Rules (legacy)", table(["Name", "Order", "Status"], ruleRows, "No rules."))
    );
  }

  function mfaView(): string {
    const rows = as()
      .userEnrollments.all()
      .map((e) => [escapeHtml(e.user_id), escapeHtml(e.type), escapeHtml(e.oob_channel ?? ""), escapeHtml(e.status)]);
    return section("MFA Enrollments", table(["User", "Type", "Channel", "Status"], rows, "No enrollments."));
  }

  function sessionsView(): string {
    const rows = as()
      .sessions.all()
      .slice(-50)
      .reverse()
      .map((s) => [
        escapeHtml(s.session_id),
        escapeHtml(s.user_id),
        escapeHtml(s.client_id ?? ""),
        escapeHtml(new Date(s.created_at_unix * 1000).toISOString()),
      ]);
    return section("Sessions", table(["Session ID", "User", "Client", "Created"], rows, "No sessions."));
  }

  function streamsView(): string {
    const streamRows = as()
      .streams.all()
      .map((s) => [
        escapeHtml(s.name),
        escapeHtml(s.kind),
        escapeHtml(s.status),
        escapeHtml(s.sink_url ?? ""),
        escapeHtml(s.kind === "event" ? s.subscriptions.join(", ") : "all logs"),
      ]);
    const deliveryRows = as()
      .streamDeliveries.all()
      .slice(-30)
      .reverse()
      .map((d) => [
        escapeHtml(d.kind),
        escapeHtml(d.event_type),
        escapeHtml(d.status === null ? "" : String(d.status)),
        escapeHtml(d.error ?? ""),
        escapeHtml(d.delivered_at),
      ]);
    return (
      section("Streams", table(["Name", "Kind", "Status", "Sink", "Subscriptions"], streamRows, "No streams.")) +
      section(
        "Recent Deliveries",
        table(["Kind", "Event", "Status", "Error", "Delivered"], deliveryRows, "No deliveries."),
      )
    );
  }

  function protectionView(): string {
    const blockRows = as()
      .userBlocks.all()
      .map((b) => [
        escapeHtml(b.identifier),
        escapeHtml(b.ip),
        escapeHtml(b.reason),
        escapeHtml(new Date(b.created_at_unix * 1000).toISOString()),
      ]);
    return section(
      "Active User Blocks",
      table(["Identifier", "IP", "Reason", "Since"], blockRows, "No active blocks."),
    );
  }

  function logsView(): string {
    const rows = as()
      .logEvents.all()
      .slice(-50)
      .reverse()
      .map((l) => [
        escapeHtml(l.type),
        escapeHtml(l.description),
        escapeHtml(l.user_id ?? ""),
        escapeHtml(l.ip ?? ""),
        escapeHtml(l.date),
      ]);
    return section("Log Events", table(["Type", "Description", "User", "IP", "Date"], rows, "No log events."));
  }
}

function section(title: string, body: string): string {
  return `<section class="inspector-section">
  <h2>${escapeHtml(title)}</h2>
  ${body}
</section>`;
}

function table(headers: string[], rows: string[][], empty: string): string {
  if (rows.length === 0) return `<p class="inspector-empty">${escapeHtml(empty)}</p>`;
  const headerHtml = headers.map((h) => `<th>${escapeHtml(h)}</th>`).join("");
  const rowHtml = rows.map((row) => `<tr>${row.map((cell) => `<td>${cell}</td>`).join("")}</tr>`).join("\n");
  return `<table class="inspector-table">
  <thead><tr>${headerHtml}</tr></thead>
  <tbody>
${rowHtml}
  </tbody>
</table>`;
}
