import type { EvaluatedPolicyDecision } from "./action_policy.ts"
import type { ResourceLocator } from "./authorization.ts"
import type {
  AccessRequest,
  AccessRequestEvent,
  AccessRequestEventType,
  AccessRequestStatus,
  ApprovalTier,
  PolicyActorType,
} from "./types.ts"

const TIER_ORDER: ApprovalTier[] = ["normal", "elevated", "breakglass"]

export type CreateAccessRequestInput = {
  org_id: string
  project_id?: string | null
  key_id?: string | null
  action: string
  actor_type: PolicyActorType
  actor_id: string
  requester_human_id?: string | null
  agent_owner_human_id?: string | null
  policy_decision: EvaluatedPolicyDecision
  reason?: string | null
}

export type AccessRequestFilter = {
  org_id?: string
  project_id?: string | null
  key_id?: string | null
  status?: AccessRequestStatus
}

export interface AccessRequestWorkflowStore {
  now(): string
  id(prefix: string): string
  transaction<T>(operation: () => T): T
  insertRequest(request: AccessRequest): void
  updateRequest(request: AccessRequest, expectedStatus: AccessRequestStatus, expectedStage: number): void
  getRequest(requestId: string): AccessRequest | null
  listRequests(filter?: AccessRequestFilter): AccessRequest[]
  insertEvent(event: AccessRequestEvent): void
  authorizeHuman(
    actorHumanId: string,
    permission: string,
    resource: ResourceLocator,
  ): { allow: boolean }
  ledger(
    type: string,
    request: AccessRequest,
    actorHumanId?: string,
    reason?: string | null,
    tier?: ApprovalTier | null,
  ): void
}

function requiredText(value: string | null | undefined, error: string): string {
  const result = value?.trim() ?? ""
  if (!result) throw new Error(error)
  return result
}

function resourceFor(request: AccessRequest): ResourceLocator {
  return {
    orgId: request.org_id,
    ...(request.project_id ? { projectId: request.project_id } : {}),
    ...(request.key_id ? { keyId: request.key_id } : {}),
  }
}

function requirePermission(store: AccessRequestWorkflowStore, request: AccessRequest, actorId: string, permission: string) {
  const resource = resourceFor(request)
  if (
    !store.authorizeHuman(actorId, "approvals.read", resource).allow ||
    !store.authorizeHuman(actorId, permission, resource).allow
  ) {
    throw new Error("forbidden")
  }
}

function currentTier(request: AccessRequest): ApprovalTier {
  const tier = request.tiers[request.stage_index]
  if (!tier || !TIER_ORDER.includes(tier)) throw new Error("invalid_request")
  return tier
}

function event(
  store: AccessRequestWorkflowStore,
  request: AccessRequest,
  type: AccessRequestEventType,
  actorHumanId: string,
  tier: ApprovalTier | null,
  reason: string | null,
): AccessRequestEvent {
  const created: AccessRequestEvent = {
    id: store.id("are"),
    request_id: request.id,
    type,
    actor_human_id: actorHumanId,
    tier,
    reason,
    created_at: store.now(),
  }
  store.insertEvent(created)
  request.events.push(created)
  return created
}

function assertPending(request: AccessRequest) {
  if (request.status !== "pending") throw new Error("request_not_pending")
}

function expireIfNeeded(store: AccessRequestWorkflowStore, request: AccessRequest): boolean {
  if (!request.expires_at || Date.parse(request.expires_at) > Date.parse(store.now())) return false
  const expectedStage = request.stage_index
  request.status = "expired"
  request.resolved_at = store.now()
  event(store, request, "expired", "system", null, null)
  store.updateRequest(request, "pending", expectedStage)
  store.ledger("access_request.expired", request)
  return true
}

function loadPending(store: AccessRequestWorkflowStore, requestId: string): AccessRequest {
  const request = store.getRequest(requestId)
  if (!request) throw new Error("request_not_found")
  if (request.status === "expired") throw new Error("request_expired")
  assertPending(request)
  return request
}

export function createAccessRequest(
  store: AccessRequestWorkflowStore,
  input: CreateAccessRequestInput,
): AccessRequest {
  return store.transaction(() => {
    const action = requiredText(input.action, "invalid_request")
    const actorId = requiredText(input.actor_id, "invalid_request")
    const orgId = requiredText(input.org_id, "invalid_request")
    if (input.actor_type !== "human" && input.actor_type !== "agent") throw new Error("invalid_request")
    const requesterHumanId = input.requester_human_id?.trim() || null
    const agentOwnerHumanId = input.agent_owner_human_id?.trim() || null
    if (
      input.actor_type === "human" &&
      (!requesterHumanId || requesterHumanId !== actorId || agentOwnerHumanId)
    ) {
      throw new Error("invalid_request")
    }
    if (input.actor_type === "agent" && requesterHumanId) throw new Error("invalid_request")

    const decision = input.policy_decision
    let status: AccessRequestStatus
    let tiers: ApprovalTier[]
    let mode: AccessRequest["mode"]
    if (decision.outcome === "approval_required") {
      if (!decision.tiers.length || decision.tiers.some((tier) => !TIER_ORDER.includes(tier))) {
        throw new Error("invalid_policy_decision")
      }
      status = "pending"
      tiers = [...decision.tiers]
      mode = decision.mode
    } else {
      status = decision.outcome === "auto_approve" ? "auto_approved" : "auto_denied"
      tiers = []
      mode = "threshold"
    }
    const createdAt = store.now()
    const expiresAt =
      decision.outcome === "approval_required" && decision.expires_in_seconds
        ? new Date(Date.parse(createdAt) + decision.expires_in_seconds * 1000).toISOString()
        : null
    const request: AccessRequest = {
      id: store.id("arq"),
      org_id: orgId,
      project_id: input.project_id ?? null,
      key_id: input.key_id ?? null,
      action,
      actor_type: input.actor_type,
      actor_id: actorId,
      requester_human_id: requesterHumanId,
      agent_owner_human_id: agentOwnerHumanId,
      mode,
      tiers,
      stage_index: 0,
      status,
      policy_version: decision.policy_version,
      policy_snapshot: structuredClone(decision.snapshot),
      policy_reason: decision.reason,
      reason_required: decision.outcome === "approval_required" && decision.reason_required,
      max_token_ttl_seconds:
        decision.outcome === "deny" ? null : decision.max_token_ttl_seconds ?? null,
      reason: input.reason?.trim() || decision.reason,
      created_at: createdAt,
      expires_at: expiresAt,
      resolved_at: status === "pending" ? null : createdAt,
      events: [],
    }
    store.insertRequest(request)
    const ledgerType =
      status === "auto_approved"
        ? "access_request.auto_approved"
        : status === "auto_denied"
          ? "access_request.auto_denied"
          : "access_request.created"
    store.ledger(ledgerType, request)
    return structuredClone(request)
  })
}

export function approveAccessRequest(
  store: AccessRequestWorkflowStore,
  requestId: string,
  input: { actor_human_id: string; reason?: string | null },
): AccessRequest {
  let expired = false
  const result = store.transaction(() => {
    const request = loadPending(store, requestId)
    if (expireIfNeeded(store, request)) {
      expired = true
      return request
    }
    const actorId = requiredText(input.actor_human_id, "invalid_actor")
    if (request.actor_type === "human" && request.requester_human_id === actorId) {
      throw new Error("self_approval")
    }
    if (request.mode === "sequential" && request.events.some(
      (item) => item.type === "approved_stage" && item.actor_human_id === actorId,
    )) {
      throw new Error("same_approver")
    }
    const tier = currentTier(request)
    requirePermission(store, request, actorId, `approvals.${tier}`)
    const reason = input.reason?.trim() || null
    if ((request.reason_required || tier !== "normal") && !reason) throw new Error("reason_required")

    const expectedStage = request.stage_index
    event(store, request, "approved_stage", actorId, tier, reason)
    if (request.mode === "sequential" && request.stage_index < request.tiers.length - 1) {
      request.stage_index += 1
    } else {
      request.status = "approved"
      request.resolved_at = store.now()
    }
    store.updateRequest(request, "pending", expectedStage)
    store.ledger("access_request.approved", request, actorId, reason, tier)
    return request
  })
  if (expired) throw new Error("request_expired")
  return structuredClone(result)
}

export function denyAccessRequest(
  store: AccessRequestWorkflowStore,
  requestId: string,
  input: { actor_human_id: string; reason?: string | null },
): AccessRequest {
  let expired = false
  const result = store.transaction(() => {
    const request = loadPending(store, requestId)
    if (expireIfNeeded(store, request)) {
      expired = true
      return request
    }
    const actorId = requiredText(input.actor_human_id, "invalid_actor")
    const tier = currentTier(request)
    requirePermission(store, request, actorId, `approvals.${tier}`)
    const reason = input.reason?.trim() || null
    if ((request.reason_required || tier !== "normal") && !reason) throw new Error("reason_required")
    const expectedStage = request.stage_index
    request.status = "denied"
    request.resolved_at = store.now()
    event(store, request, "denied", actorId, tier, reason)
    store.updateRequest(request, "pending", expectedStage)
    store.ledger("access_request.denied", request, actorId, reason, tier)
    return request
  })
  if (expired) throw new Error("request_expired")
  return structuredClone(result)
}

export function escalateAccessRequest(
  store: AccessRequestWorkflowStore,
  requestId: string,
  input: { actor_human_id: string; tier: ApprovalTier; reason: string },
): AccessRequest {
  let expired = false
  const result = store.transaction(() => {
    const request = loadPending(store, requestId)
    if (expireIfNeeded(store, request)) {
      expired = true
      return request
    }
    const actorId = requiredText(input.actor_human_id, "invalid_actor")
    const reason = requiredText(input.reason, "reason_required")
    requirePermission(store, request, actorId, "approvals.escalate")
    if (!TIER_ORDER.includes(input.tier)) throw new Error("invalid_tier")
    const strongest = request.tiers.reduce(
      (highest, tier) => Math.max(highest, TIER_ORDER.indexOf(tier)),
      -1,
    )
    const target = TIER_ORDER.indexOf(input.tier)
    if (target <= strongest) throw new Error("escalation_not_upward")

    const expectedStage = request.stage_index
    if (request.mode === "threshold") request.tiers[request.stage_index] = input.tier
    else request.tiers.push(input.tier)
    event(store, request, "escalated", actorId, input.tier, reason)
    store.updateRequest(request, "pending", expectedStage)
    store.ledger("access_request.escalated", request, actorId, reason, input.tier)
    return request
  })
  if (expired) throw new Error("request_expired")
  return structuredClone(result)
}

export function cancelAccessRequest(
  store: AccessRequestWorkflowStore,
  requestId: string,
  input: { actor_human_id: string; reason: string },
): AccessRequest {
  let expired = false
  const result = store.transaction(() => {
    const request = loadPending(store, requestId)
    if (expireIfNeeded(store, request)) {
      expired = true
      return request
    }
    const actorId = requiredText(input.actor_human_id, "invalid_actor")
    const reason = requiredText(input.reason, "reason_required")
    requirePermission(store, request, actorId, "approvals.escalate")
    const expectedStage = request.stage_index
    request.status = "cancelled"
    request.resolved_at = store.now()
    event(store, request, "cancelled", actorId, currentTier(request), reason)
    store.updateRequest(request, "pending", expectedStage)
    store.ledger("access_request.cancelled", request, actorId, reason)
    return request
  })
  if (expired) throw new Error("request_expired")
  return structuredClone(result)
}

export function listAccessRequests(
  store: AccessRequestWorkflowStore,
  filter?: AccessRequestFilter,
): AccessRequest[] {
  const rows = store.listRequests(filter?.status === undefined ? filter : { ...filter, status: undefined })
  for (const row of rows) {
    if (row.status !== "pending") continue
    store.transaction(() => {
      const current = store.getRequest(row.id)
      if (current?.status === "pending") expireIfNeeded(store, current)
    })
  }
  return store
    .listRequests(filter)
    .map((request) => structuredClone(request))
}
