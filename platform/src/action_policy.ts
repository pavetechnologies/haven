import type {
  ActionPolicyDefault,
  ActionPolicyDocument,
  ActionPolicyMatch,
  ActionPolicyMinimumRule,
  ApprovalMode,
  ApprovalTier,
  Guardrail,
  PolicyActorType,
  PolicyDecision,
  PolicyMinimum,
} from "./types.ts"

export type EvaluatePolicyInput = {
  orgPolicy?: ActionPolicyDocument
  projectPolicy?: ActionPolicyDocument
  keyPolicy?: ActionPolicyDocument
  action: string
  actor_type: PolicyActorType
  environment?: string
  agent_id?: string
  policy_version?: number
}

export type EvaluatedPolicyDecision = PolicyDecision & {
  policy_version: number
  snapshot: {
    org: ActionPolicyDocument | null
    project: ActionPolicyDocument | null
    key: ActionPolicyDocument | null
  }
}

const STRENGTH: Record<PolicyMinimum, number> = {
  auto: 0,
  normal: 1,
  elevated: 2,
  breakglass: 3,
  deny: 4,
}

export function policyStrength(a: PolicyMinimum, b: PolicyMinimum): number {
  return STRENGTH[a] - STRENGTH[b]
}

const DOCUMENT_FIELDS = new Set(["defaults", "minimums"])
const MATCH_FIELDS = ["action", "actor_type", "environment", "agent_id"] as const
const DEFAULT_FIELDS = new Set([
  ...MATCH_FIELDS,
  "outcome",
  "mode",
  "tiers",
  "reason_required",
  "expires_in_seconds",
  "max_token_ttl_seconds",
])
const MINIMUM_FIELDS = new Set([
  ...MATCH_FIELDS,
  "min",
  "mode",
  "tiers",
  "reason_required",
  "expires_in_seconds",
  "max_token_ttl_seconds",
])
const ACTOR_TYPES = new Set<PolicyActorType>(["human", "agent"])
const OUTCOMES = new Set(["deny", "auto_approve", "approval_required"])
const MINIMUMS = new Set<PolicyMinimum>(["auto", "normal", "elevated", "breakglass", "deny"])
const MODES = new Set<ApprovalMode>(["threshold", "sequential"])
const TIERS = new Set<ApprovalTier>(["normal", "elevated", "breakglass"])
const TIER_ORDER: ApprovalTier[] = ["normal", "elevated", "breakglass"]

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value)
}

function hasOnlyFields(value: Record<string, unknown>, fields: Set<string>) {
  return Object.keys(value).every((field) => fields.has(field))
}

function positiveInteger(value: unknown): boolean {
  return value === undefined || (Number.isInteger(value) && Number(value) > 0)
}

function validTiers(value: unknown): value is ApprovalTier[] {
  return (
    value === undefined ||
    (Array.isArray(value) &&
      value.length > 0 &&
      new Set(value).size === value.length &&
      value.every((tier) => TIERS.has(tier)))
  )
}

function validMatch(rule: Record<string, unknown>): boolean {
  return (
    typeof rule.action === "string" &&
    rule.action.trim().length > 0 &&
    ACTOR_TYPES.has(rule.actor_type as PolicyActorType) &&
    (rule.environment === undefined || (typeof rule.environment === "string" && rule.environment.length > 0)) &&
    (rule.agent_id === undefined || (typeof rule.agent_id === "string" && rule.agent_id.length > 0)) &&
    !(rule.actor_type === "human" && rule.agent_id !== undefined)
  )
}

function validOptions(rule: Record<string, unknown>): boolean {
  return (
    (rule.mode === undefined || MODES.has(rule.mode as ApprovalMode)) &&
    validTiers(rule.tiers) &&
    (rule.reason_required === undefined || typeof rule.reason_required === "boolean") &&
    positiveInteger(rule.expires_in_seconds) &&
    positiveInteger(rule.max_token_ttl_seconds)
  )
}

function matcherKey(rule: ActionPolicyMatch): string {
  return [rule.action, rule.actor_type, rule.environment ?? "", rule.agent_id ?? ""].join("\u0000")
}

export function validatePolicyDocument(value: unknown): value is ActionPolicyDocument {
  if (!isObject(value) || !hasOnlyFields(value, DOCUMENT_FIELDS)) return false
  if (!Array.isArray(value.defaults) || !Array.isArray(value.minimums)) return false
  const defaultsValid = value.defaults.every(
    (rule) =>
      isObject(rule) &&
      hasOnlyFields(rule, DEFAULT_FIELDS) &&
      validMatch(rule) &&
      validOptions(rule) &&
      OUTCOMES.has(rule.outcome as string) &&
      (rule.outcome === "approval_required" || (rule.mode === undefined && rule.tiers === undefined)),
  )
  const minimumsValid = value.minimums.every(
    (rule) =>
      isObject(rule) &&
      hasOnlyFields(rule, MINIMUM_FIELDS) &&
      validMatch(rule) &&
      validOptions(rule) &&
      MINIMUMS.has(rule.min as PolicyMinimum) &&
      ((rule.min !== "auto" && rule.min !== "deny") || (rule.mode === undefined && rule.tiers === undefined)),
  )
  if (!defaultsValid || !minimumsValid) return false
  const defaultKeys = value.defaults.map((rule) => matcherKey(rule as ActionPolicyDefault))
  const minimumKeys = value.minimums.map((rule) => matcherKey(rule as ActionPolicyMinimumRule))
  return new Set(defaultKeys).size === defaultKeys.length && new Set(minimumKeys).size === minimumKeys.length
}

function matches(rule: ActionPolicyMatch, input: EvaluatePolicyInput): boolean {
  return (
    rule.action === input.action &&
    rule.actor_type === input.actor_type &&
    (rule.environment === undefined || rule.environment === input.environment) &&
    (rule.agent_id === undefined || rule.agent_id === input.agent_id)
  )
}

function specificity(rule: ActionPolicyMatch): number {
  return Number(rule.environment !== undefined) + Number(rule.agent_id !== undefined)
}

function matchingDefault(document: ActionPolicyDocument, input: EvaluatePolicyInput): ActionPolicyDefault | undefined {
  return document.defaults
    .filter((rule) => matches(rule, input))
    .sort((left, right) => {
      const specificityDifference = specificity(right) - specificity(left)
      if (specificityDifference !== 0) return specificityDifference
      // Equal-specificity conflicts fail closed toward the stronger outcome, never array order.
      return policyStrength(defaultStrength(right), defaultStrength(left))
    })[0]
}

function defaultStrength(rule: ActionPolicyDefault): PolicyMinimum {
  if (rule.outcome === "deny") return "deny"
  if (rule.outcome === "auto_approve") return "auto"
  return rule.tiers?.reduce<ApprovalTier>(
    (strongest, tier) => (TIER_ORDER.indexOf(tier) > TIER_ORDER.indexOf(strongest) ? tier : strongest),
    "normal",
  ) ?? "normal"
}

function orderedTiers(tiers: Iterable<ApprovalTier>): ApprovalTier[] {
  const selected = new Set(tiers)
  return TIER_ORDER.filter((tier) => selected.has(tier))
}

function cloneDocument(document: ActionPolicyDocument | undefined): ActionPolicyDocument | null {
  return document ? structuredClone(document) : null
}

export function guardrailToActionPolicy(guardrail: Guardrail): ActionPolicyDocument {
  const actionAllowed = guardrail.allow_actions.includes("*") || guardrail.allow_actions.includes("secrets:read")
  const outcome = !actionAllowed || guardrail.default === "deny"
    ? "deny"
    : guardrail.require_approval || guardrail.default === "approve"
      ? "approval_required"
      : "auto_approve"
  const common = {
    action: "keys.resolve",
    actor_type: "agent" as const,
    outcome,
    ...(outcome === "approval_required" ? { mode: "threshold" as const, tiers: ["normal" as const] } : {}),
    max_token_ttl_seconds: guardrail.max_ttl_seconds,
  }
  if (!guardrail.allow_agents.length || guardrail.allow_agents.includes("*")) {
    return { defaults: [common], minimums: [] }
  }
  return {
    defaults: guardrail.allow_agents.map((agent_id) => ({ ...common, agent_id })),
    minimums: [],
  }
}

export function evaluatePolicy(input: EvaluatePolicyInput): EvaluatedPolicyDecision {
  const policy_version = input.policy_version ?? 0
  const invalidPolicy = (): EvaluatedPolicyDecision => ({
    outcome: "deny",
    reason: "invalid_policy",
    policy_version,
    snapshot: { org: null, project: null, key: null },
  })
  const sourceDocuments = [input.orgPolicy, input.projectPolicy, input.keyPolicy].filter(
    (document): document is ActionPolicyDocument => document !== undefined,
  )
  try {
    if (sourceDocuments.some((document) => !validatePolicyDocument(document))) return invalidPolicy()
  } catch {
    return invalidPolicy()
  }

  let snapshot: EvaluatedPolicyDecision["snapshot"]
  try {
    snapshot = {
      org: cloneDocument(input.orgPolicy),
      project: cloneDocument(input.projectPolicy),
      key: cloneDocument(input.keyPolicy),
    }
  } catch {
    return invalidPolicy()
  }
  const documents = [snapshot.org, snapshot.project, snapshot.key].filter(
    (document): document is ActionPolicyDocument => document !== null,
  )

  const selectedDefault =
    (snapshot.key && matchingDefault(snapshot.key, input)) ||
    (snapshot.project && matchingDefault(snapshot.project, input)) ||
    (snapshot.org && matchingDefault(snapshot.org, input))
  if (!selectedDefault) {
    return { outcome: "deny", reason: "no_matching_default", policy_version, snapshot }
  }

  const minimums = documents.flatMap((document) => document.minimums.filter((rule) => matches(rule, input)))
  let strength = defaultStrength(selectedDefault)
  for (const minimum of minimums) {
    if (policyStrength(minimum.min, strength) > 0) strength = minimum.min
  }
  if (strength === "deny") {
    return { outcome: "deny", reason: "policy_deny", policy_version, snapshot }
  }

  const maxTokenTtls = [selectedDefault.max_token_ttl_seconds, ...minimums.map((rule) => rule.max_token_ttl_seconds)]
    .filter((value): value is number => value !== undefined)
  const max_token_ttl_seconds = maxTokenTtls.length ? Math.min(...maxTokenTtls) : undefined
  if (strength === "auto") {
    return {
      outcome: "auto_approve",
      reason: "default_auto_approve",
      ...(max_token_ttl_seconds === undefined ? {} : { max_token_ttl_seconds }),
      policy_version,
      snapshot,
    }
  }

  const mode: ApprovalMode =
    selectedDefault.mode === "sequential" || minimums.some((rule) => rule.mode === "sequential")
      ? "sequential"
      : "threshold"
  const requiredTier = strength as ApprovalTier
  const configuredTiers = [
    ...(selectedDefault.tiers ?? []),
    ...minimums.flatMap((minimum) => minimum.tiers ?? []),
    requiredTier,
  ].filter((tier) => TIER_ORDER.indexOf(tier) <= TIER_ORDER.indexOf(requiredTier))
  const tiers = mode === "sequential" ? orderedTiers(configuredTiers) : [requiredTier]
  const expiries = [selectedDefault.expires_in_seconds, ...minimums.map((rule) => rule.expires_in_seconds)].filter(
    (value): value is number => value !== undefined,
  )
  return {
    outcome: "approval_required",
    reason: minimums.length ? "minimum_constraint" : "default_approval",
    mode,
    tiers,
    reason_required:
      requiredTier !== "normal" ||
      Boolean(selectedDefault.reason_required) ||
      minimums.some((rule) => rule.reason_required),
    ...(expiries.length ? { expires_in_seconds: Math.min(...expiries) } : {}),
    ...(max_token_ttl_seconds === undefined ? {} : { max_token_ttl_seconds }),
    policy_version,
    snapshot,
  }
}
