import {
  isPermission,
  permissionAllowsScope,
  templateAllows,
  type Permission,
  type PermissionScope,
} from "./permissions.ts"
import type { HumanRole } from "./types.ts"

export type AccessAssignmentEffect = "allow" | "deny"

export interface AccessAssignment {
  id: string
  user_id: string
  org_id: string
  project_id: string | null
  key_id: string | null
  permission: Permission
  effect: AccessAssignmentEffect
  reason: string
  grantor_id: string
  created_at: string
  expires_at: string | null
  revoked_at: string | null
  revoked_by: string | null
}

export interface ResourceLocator {
  orgId: string
  projectId?: string | null
  keyId?: string | null
}

export interface MatchedAccessAssignment {
  id: string
  org_id: string
  project_id: string | null
  key_id: string | null
  permission: string
  effect: string
}

export interface AuthorizationDecision {
  allow: boolean
  decision_id: string
  permission: string
  reason:
    | "unknown_permission"
    | "invalid_resource"
    | "malformed_assignment"
    | "explicit_deny"
    | "role_template"
    | "explicit_allow"
    | "missing_permission"
  matched: {
    role_template: HumanRole | null
    grants: MatchedAccessAssignment[]
    denies: MatchedAccessAssignment[]
    expired: MatchedAccessAssignment[]
    revoked: MatchedAccessAssignment[]
    malformed: MatchedAccessAssignment[]
  }
}

export interface EvaluateHumanAuthorizationInput {
  decisionId: string
  permission: string
  resource: ResourceLocator
  role: HumanRole | null
  assignments: AccessAssignment[]
  at?: Date
}

export function assignmentScope(assignment: Pick<AccessAssignment, "project_id" | "key_id">): PermissionScope | null {
  if (assignment.key_id) return assignment.project_id ? "key" : null
  return assignment.project_id ? "project" : "org"
}

function safeAssignmentMetadata(assignment: AccessAssignment): MatchedAccessAssignment {
  return {
    id: typeof assignment.id === "string" ? assignment.id : "",
    org_id: typeof assignment.org_id === "string" ? assignment.org_id : "",
    project_id: typeof assignment.project_id === "string" ? assignment.project_id : null,
    key_id: typeof assignment.key_id === "string" ? assignment.key_id : null,
    permission: typeof assignment.permission === "string" ? assignment.permission : "",
    effect: typeof assignment.effect === "string" ? assignment.effect : "",
  }
}

function validNullableId(value: unknown): value is string | null {
  return value === null || (typeof value === "string" && value.length > 0)
}

function validDate(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && !Number.isNaN(Date.parse(value))
}

function validRequiredId(value: unknown): value is string {
  return typeof value === "string" && value.length > 0
}

function isWellFormedAssignment(assignment: AccessAssignment): boolean {
  const expiryValid = assignment.expires_at === null || validDate(assignment.expires_at)
  const revocationDateValid = assignment.revoked_at === null || validDate(assignment.revoked_at)
  const revokerValid = validNullableId(assignment.revoked_by)
  const revocationConsistent = (assignment.revoked_at === null) === (assignment.revoked_by === null)
  return (
    validRequiredId(assignment.id) &&
    validRequiredId(assignment.user_id) &&
    validRequiredId(assignment.org_id) &&
    isPermission(assignment.permission) &&
    (assignment.effect === "allow" || assignment.effect === "deny") &&
    validRequiredId(assignment.reason) &&
    validRequiredId(assignment.grantor_id) &&
    validDate(assignment.created_at) &&
    validNullableId(assignment.project_id) &&
    validNullableId(assignment.key_id) &&
    expiryValid &&
    revocationDateValid &&
    revokerValid &&
    revocationConsistent
  )
}

export function evaluateHumanAuthorization(input: EvaluateHumanAuthorizationInput): AuthorizationDecision {
  const matched: AuthorizationDecision["matched"] = {
    role_template: null,
    grants: [],
    denies: [],
    expired: [],
    revoked: [],
    malformed: [],
  }
  const base = {
    decision_id: input.decisionId,
    permission: input.permission,
    matched,
  }
  if (!isPermission(input.permission)) {
    return { ...base, allow: false, reason: "unknown_permission" }
  }
  const projectPresent = input.resource.projectId !== undefined && input.resource.projectId !== null
  const keyPresent = input.resource.keyId !== undefined && input.resource.keyId !== null
  if (
    !input.resource.orgId ||
    (projectPresent && input.resource.projectId === "") ||
    (keyPresent && input.resource.keyId === "") ||
    (keyPresent && !projectPresent)
  ) {
    return { ...base, allow: false, reason: "invalid_resource" }
  }

  const at = (input.at ?? new Date()).getTime()
  for (const assignment of input.assignments) {
    if (assignment.permission !== input.permission || assignment.org_id !== input.resource.orgId) continue
    const metadata = safeAssignmentMetadata(assignment)
    if (!validNullableId(assignment.project_id) || !validNullableId(assignment.key_id)) {
      matched.malformed.push(metadata)
      continue
    }
    const scope = assignmentScope(assignment)
    if (!scope || !permissionAllowsScope(input.permission, scope)) {
      matched.malformed.push(metadata)
      continue
    }
    if (scope === "project" && assignment.project_id !== input.resource.projectId) continue
    if (
      scope === "key" &&
      (assignment.project_id !== input.resource.projectId || assignment.key_id !== input.resource.keyId)
    ) {
      continue
    }
    if (!isWellFormedAssignment(assignment)) {
      matched.malformed.push(metadata)
      continue
    }
    if (assignment.revoked_at) {
      matched.revoked.push(metadata)
      continue
    }
    if (assignment.expires_at && Date.parse(assignment.expires_at) <= at) {
      matched.expired.push(metadata)
      continue
    }
    if (assignment.effect === "deny") matched.denies.push(metadata)
    else if (assignment.effect === "allow") matched.grants.push(metadata)
  }

  if (matched.malformed.length) return { ...base, allow: false, reason: "malformed_assignment" }
  if (matched.denies.length) return { ...base, allow: false, reason: "explicit_deny" }
  const validRole = input.role === "user" || input.role === "admin" || input.role === "superadmin"
  if (validRole && templateAllows(input.role, input.permission)) {
    matched.role_template = input.role
    return { ...base, allow: true, reason: "role_template" }
  }
  if (matched.grants.length) return { ...base, allow: true, reason: "explicit_allow" }
  return { ...base, allow: false, reason: "missing_permission" }
}
