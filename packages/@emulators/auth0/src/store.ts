import type { Collection, Store } from "@emulators/core";
import type {
  Auth0User,
  Auth0Client,
  Auth0Connection,
  Auth0Role,
  Auth0RoleAssignment,
  Auth0Organization,
  Auth0OrganizationMember,
  Auth0ResourceServer,
  Auth0ClientGrant,
  Auth0Stream,
  Auth0StreamDelivery,
  Auth0LogEvent,
  Auth0Ticket,
  Auth0UserBlock,
  Auth0RolePermission,
  Auth0UserPermission,
  Auth0UserIdentity,
  Auth0UserEnrollment,
  Auth0Action,
  Auth0ActionBinding,
  Auth0Rule,
  Auth0Hook,
  Auth0Session,
  Auth0Job,
} from "./entities.js";

export interface Auth0Store {
  users: Collection<Auth0User>;
  clients: Collection<Auth0Client>;
  connections: Collection<Auth0Connection>;
  roles: Collection<Auth0Role>;
  roleAssignments: Collection<Auth0RoleAssignment>;
  organizations: Collection<Auth0Organization>;
  orgMembers: Collection<Auth0OrganizationMember>;
  resourceServers: Collection<Auth0ResourceServer>;
  clientGrants: Collection<Auth0ClientGrant>;
  streams: Collection<Auth0Stream>;
  streamDeliveries: Collection<Auth0StreamDelivery>;
  logEvents: Collection<Auth0LogEvent>;
  tickets: Collection<Auth0Ticket>;
  userBlocks: Collection<Auth0UserBlock>;
  rolePermissions: Collection<Auth0RolePermission>;
  userPermissions: Collection<Auth0UserPermission>;
  userIdentities: Collection<Auth0UserIdentity>;
  userEnrollments: Collection<Auth0UserEnrollment>;
  actions: Collection<Auth0Action>;
  actionBindings: Collection<Auth0ActionBinding>;
  rules: Collection<Auth0Rule>;
  hooks: Collection<Auth0Hook>;
  sessions: Collection<Auth0Session>;
  jobs: Collection<Auth0Job>;
}

export function getAuth0Store(store: Store): Auth0Store {
  return {
    users: store.collection<Auth0User>("auth0.users", ["user_id", "email", "connection"]),
    clients: store.collection<Auth0Client>("auth0.clients", ["client_id"]),
    connections: store.collection<Auth0Connection>("auth0.connections", ["connection_id", "name"]),
    roles: store.collection<Auth0Role>("auth0.roles", ["role_id", "name"]),
    roleAssignments: store.collection<Auth0RoleAssignment>("auth0.role_assignments", ["role_id", "user_id"]),
    organizations: store.collection<Auth0Organization>("auth0.orgs", ["org_id", "name"]),
    orgMembers: store.collection<Auth0OrganizationMember>("auth0.org_members", ["org_id", "user_id"]),
    resourceServers: store.collection<Auth0ResourceServer>("auth0.resource_servers", [
      "resource_server_id",
      "identifier",
    ]),
    clientGrants: store.collection<Auth0ClientGrant>("auth0.client_grants", ["grant_id", "client_id", "audience"]),
    streams: store.collection<Auth0Stream>("auth0.streams", ["stream_id", "kind"]),
    streamDeliveries: store.collection<Auth0StreamDelivery>("auth0.stream_deliveries", ["stream_id"]),
    logEvents: store.collection<Auth0LogEvent>("auth0.log_events", ["log_id"]),
    tickets: store.collection<Auth0Ticket>("auth0.tickets", ["ticket_id", "user_id"]),
    userBlocks: store.collection<Auth0UserBlock>("auth0.user_blocks", ["identifier", "ip"]),
    rolePermissions: store.collection<Auth0RolePermission>("auth0.role_permissions", [
      "role_id",
      "resource_server_identifier",
    ]),
    userPermissions: store.collection<Auth0UserPermission>("auth0.user_permissions", [
      "user_id",
      "resource_server_identifier",
    ]),
    userIdentities: store.collection<Auth0UserIdentity>("auth0.user_identities", ["user_id", "provider"]),
    userEnrollments: store.collection<Auth0UserEnrollment>("auth0.user_enrollments", ["enrollment_id", "user_id"]),
    actions: store.collection<Auth0Action>("auth0.actions", ["action_id", "trigger", "name"]),
    actionBindings: store.collection<Auth0ActionBinding>("auth0.action_bindings", ["trigger", "action_id"]),
    rules: store.collection<Auth0Rule>("auth0.rules", ["rule_id"]),
    hooks: store.collection<Auth0Hook>("auth0.hooks", ["hook_id", "triggerId"]),
    sessions: store.collection<Auth0Session>("auth0.sessions", ["session_id", "user_id"]),
    jobs: store.collection<Auth0Job>("auth0.jobs", ["job_id"]),
  };
}
