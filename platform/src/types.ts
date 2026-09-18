export type { Permission, PermissionScope } from "./permissions.ts"
export type {
  AccessAssignment,
  AccessAssignmentEffect,
  AuthorizationDecision,
  ResourceLocator,
} from "./authorization.ts"

export type RiskTier = "low" | "medium" | "high" | "critical"
export type AgentStatus = "active" | "revoked"
export type HumanRole = "superadmin" | "admin" | "user"
export type KnockStatus = "pending" | "approved" | "denied" | "auto_allow" | "auto_deny"
export type PolicyDefault = "deny" | "allow" | "approve"
export type KnockDecision = "allow" | "deny" | "approve"
export type OnExposure = "block" | "queue" | "observe"
export type PolicyActorType = "human" | "agent"
export type ApprovalTier = "normal" | "elevated" | "breakglass"
export type PolicyMinimum = "auto" | ApprovalTier | "deny"
export type ApprovalMode = "threshold" | "sequential"
export type AccessRequestStatus =
  | "pending"
  | "approved"
  | "denied"
  | "auto_approved"
  | "auto_denied"
  | "cancelled"
  | "expired"
export type AccessRequestEventType = "approved_stage" | "denied" | "escalated" | "cancelled" | "expired"

export interface ActionPolicyMatch {
  action: string
  actor_type: PolicyActorType
  environment?: string
  agent_id?: string
}

export interface ActionPolicyDefault extends ActionPolicyMatch {
  outcome: "deny" | "auto_approve" | "approval_required"
  mode?: ApprovalMode
  tiers?: ApprovalTier[]
  reason_required?: boolean
  expires_in_seconds?: number
  max_token_ttl_seconds?: number
}

export interface ActionPolicyMinimumRule extends ActionPolicyMatch {
  min: PolicyMinimum
  mode?: ApprovalMode
  tiers?: ApprovalTier[]
  reason_required?: boolean
  expires_in_seconds?: number
  max_token_ttl_seconds?: number
}

export interface ActionPolicyDocument {
  defaults: ActionPolicyDefault[]
  minimums: ActionPolicyMinimumRule[]
}

export interface ActionPolicyRecord {
  scope_type: "org" | "project" | "key"
  scope_id: string
  version: number
  document: ActionPolicyDocument
  created_at: string
  created_by: string
}

export interface AccessRequestPolicySnapshot {
  org: ActionPolicyDocument | null
  project: ActionPolicyDocument | null
  key: ActionPolicyDocument | null
}

export interface AccessRequestEvent {
  id: string
  request_id: string
  type: AccessRequestEventType
  actor_human_id: string
  tier: ApprovalTier | null
  reason: string | null
  created_at: string
}

export interface AccessRequest {
  id: string
  org_id: string
  project_id: string | null
  key_id: string | null
  action: string
  actor_type: PolicyActorType
  actor_id: string
  requester_human_id: string | null
  agent_owner_human_id: string | null
  mode: ApprovalMode
  tiers: ApprovalTier[]
  stage_index: number
  status: AccessRequestStatus
  policy_version: number
  policy_snapshot: AccessRequestPolicySnapshot
  policy_reason: string
  reason_required: boolean
  max_token_ttl_seconds: number | null
  reason: string | null
  created_at: string
  expires_at: string | null
  resolved_at: string | null
  events: AccessRequestEvent[]
}

export type PolicyDecision =
  | { outcome: "deny"; reason: string }
  | { outcome: "auto_approve"; reason: string; max_token_ttl_seconds?: number }
  | {
      outcome: "approval_required"
      reason: string
      mode: ApprovalMode
      tiers: ApprovalTier[]
      reason_required: boolean
      expires_in_seconds?: number
      max_token_ttl_seconds?: number
    }

export interface Guardrail {
  default: PolicyDefault
  allow_agents: string[]
  allow_actions: string[]
  max_ttl_seconds: number
  require_approval: boolean
  on_exposure: OnExposure
}

export const DEFAULT_GUARDRAIL: Guardrail = {
  default: "deny",
  allow_agents: [],
  allow_actions: ["secrets:read"],
  max_ttl_seconds: 900,
  require_approval: false,
  on_exposure: "queue",
}

export interface Org {
  id: string
  slug: string
  name: string
  guardrail: Guardrail
  created_at: string
}

export interface Project {
  id: string
  org_id: string
  slug: string
  name: string
  guardrail: Guardrail
  created_at: string
}

export interface KeyMeta {
  id: string
  project_id: string
  env: string
  name: string
  version: number
  updated_at: string
  ref: string
  guardrail: Guardrail | null
}

export interface Human {
  id: string
  username: string
  created_at: string
}

export interface Membership {
  user_id: string
  org_id: string
  role: HumanRole
}

export interface Agent {
  id: string
  name: string
  owner: string
  purpose: string
  org_id: string | null
  project_id: string | null
  risk_tier: RiskTier
  scopes: string[]
  status: AgentStatus
  created_at: string
  updated_at: string
  revoked_at: string | null
  first_seen_at: string
}

export interface LedgerEvent {
  id: string
  ts: string
  type: string
  agent_id: string | null
  actor: string
  resource: string | null
  action: string | null
  outcome: "success" | "denied" | "error" | "info"
  detail: Record<string, unknown>
  prev_hash: string | null
  hash: string
}

export interface KnockNeed {
  action: string
  key_ref?: string
  scope?: string
}

export interface Knock {
  id: string
  access_request_id: string | null
  org_slug: string
  project_slug: string
  agent_name: string
  purpose: string
  need: KnockNeed[]
  status: KnockStatus
  decision_reason: string
  agent_id: string | null
  created_at: string
  resolved_at: string | null
}
