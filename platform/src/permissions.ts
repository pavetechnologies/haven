import type { HumanRole } from "./types.ts"

export const PERMISSIONS = [
  "org.members.read",
  "org.members.manage",
  "org.permissions.read",
  "org.permissions.manage",
  "projects.list",
  "projects.create",
  "projects.manage",
  "keys.list",
  "keys.create",
  "keys.update",
  "keys.reveal",
  "keys.delete",
  "policies.org.read",
  "policies.org.manage",
  "policies.project.read",
  "policies.project.manage",
  "policies.key.read",
  "policies.key.manage",
  "approvals.read",
  "approvals.normal",
  "approvals.elevated",
  "approvals.breakglass",
  "approvals.escalate",
  "agents.read",
  "agents.manage",
  "grants.read",
  "grants.manage",
  "api_keys.read",
  "api_keys.manage",
  "audit.read",
] as const

export type Permission = (typeof PERMISSIONS)[number]

export type PermissionScope = "org" | "project" | "key"

const ORG_ONLY: readonly PermissionScope[] = ["org"]
const ORG_PROJECT: readonly PermissionScope[] = ["org", "project"]
const ORG_PROJECT_KEY: readonly PermissionScope[] = ["org", "project", "key"]

export const PERMISSION_SCOPES: Record<Permission, readonly PermissionScope[]> = {
  "org.members.read": ORG_ONLY,
  "org.members.manage": ORG_ONLY,
  "org.permissions.read": ORG_ONLY,
  "org.permissions.manage": ORG_ONLY,
  "projects.list": ORG_PROJECT,
  "projects.create": ORG_ONLY,
  "projects.manage": ORG_PROJECT,
  "keys.list": ORG_PROJECT_KEY,
  "keys.create": ORG_PROJECT_KEY,
  "keys.update": ORG_PROJECT_KEY,
  "keys.reveal": ORG_PROJECT_KEY,
  "keys.delete": ORG_PROJECT_KEY,
  "policies.org.read": ORG_ONLY,
  "policies.org.manage": ORG_ONLY,
  "policies.project.read": ORG_PROJECT,
  "policies.project.manage": ORG_PROJECT,
  "policies.key.read": ORG_PROJECT_KEY,
  "policies.key.manage": ORG_PROJECT_KEY,
  "approvals.read": ORG_PROJECT_KEY,
  "approvals.normal": ORG_PROJECT_KEY,
  "approvals.elevated": ORG_PROJECT_KEY,
  "approvals.breakglass": ORG_PROJECT_KEY,
  "approvals.escalate": ORG_PROJECT_KEY,
  "agents.read": ORG_PROJECT,
  "agents.manage": ORG_PROJECT,
  "grants.read": ORG_PROJECT_KEY,
  "grants.manage": ORG_PROJECT_KEY,
  "api_keys.read": ORG_ONLY,
  "api_keys.manage": ORG_ONLY,
  "audit.read": ORG_PROJECT,
}

const USER_TEMPLATE = [
  "projects.list",
  "keys.list",
  "approvals.read",
  "approvals.normal",
] as const satisfies readonly Permission[]

const ADMIN_TEMPLATE = [
  ...USER_TEMPLATE,
  "projects.create",
  "projects.manage",
  "keys.create",
  "keys.update",
  "policies.project.read",
  "policies.project.manage",
  "policies.key.read",
  "policies.key.manage",
  "agents.read",
  "agents.manage",
  "grants.read",
  "grants.manage",
  "approvals.elevated",
  "approvals.escalate",
  "audit.read",
] as const satisfies readonly Permission[]

const SUPERADMIN_TEMPLATE = [
  ...ADMIN_TEMPLATE,
  "org.members.read",
  "org.members.manage",
  "org.permissions.read",
  "org.permissions.manage",
  "policies.org.read",
  "policies.org.manage",
  "keys.reveal",
  "keys.delete",
  "approvals.breakglass",
  "api_keys.read",
  "api_keys.manage",
] as const satisfies readonly Permission[]

export const ROLE_TEMPLATES: Record<HumanRole, readonly Permission[]> = {
  user: USER_TEMPLATE,
  admin: ADMIN_TEMPLATE,
  superadmin: SUPERADMIN_TEMPLATE,
}

export function permissionAllowsScope(permission: Permission, scope: PermissionScope): boolean {
  const scopes = PERMISSION_SCOPES[permission]
  if (!scopes) return false
  return scopes.includes(scope)
}

export function templateAllows(role: HumanRole, permission: Permission): boolean {
  return ROLE_TEMPLATES[role].includes(permission)
}

export function isPermission(value: string): value is Permission {
  return (PERMISSIONS as readonly string[]).includes(value)
}
