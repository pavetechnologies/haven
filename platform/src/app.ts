/**
 * Haven HTTP handler — identity · broker · PEP · ledger · secrets · knock · operator UI
 */
import { existsSync } from "node:fs"
import { join, normalize, resolve } from "node:path"
import { parseKeyRef, type Haven } from "./haven.ts"
import {
  isPermission,
  PERMISSIONS,
  PERMISSION_SCOPES,
  permissionAllowsScope,
  ROLE_TEMPLATES,
  type Permission,
  type PermissionScope,
} from "./permissions.ts"
import type { AccessRequest, ActionPolicyDocument, Guardrail, HumanRole, KeyMeta, RiskTier } from "./types.ts"

export const VERSION = "0.3.0"
const TIERS = new Set(["low", "medium", "high", "critical"])
const ROLES = new Set(["superadmin", "admin", "user"])
const BUOY_KINDS = new Set(["harbor", "custom"])
const WATCH_AUDIENCES = new Set([...BUOY_KINDS, "all"])
const CANARY_MODES = new Set(["decoy_key", "sibling"])
const REMEDIATION_STATUSES = new Set(["open", "rotated", "dismissed"])

function json(data: unknown, status = 200, extra: HeadersInit = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "x-haven-version": VERSION,
      ...extra,
    },
  })
}

function err(status: number, code: string, message: string, detail: Record<string, unknown> = {}) {
  return json({ error: code, message, ...detail }, status)
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(value, (_key, nested) => {
    if (!nested || typeof nested !== "object" || Array.isArray(nested)) return nested
    return Object.fromEntries(
      Object.entries(nested as Record<string, unknown>).sort(([left], [right]) =>
        left < right ? -1 : left > right ? 1 : 0,
      ),
    )
  })
}

async function readBody(req: Request) {
  try {
    return await req.json()
  } catch {
    return null
  }
}

function isOpenRoute(method: string, path: string) {
  if (path === "/health") return true
  if (method === "POST" && path === "/v1/session") return true
  if (method === "POST" && path === "/v1/knock") return true
  if (method === "GET" && path === "/v1/activity") return true
  if (method === "POST" && path === "/v1/activity") return true
  if (
    method === "POST" &&
    (path === "/v1/authorize" ||
      path === "/v1/tokens/introspect" ||
      path === "/v1/tokens/revoke" ||
      path === "/v1/secrets/resolve")
  )
    return true
  if (method === "GET" && !path.startsWith("/v1")) return true
  return false
}

function isBuoyRoute(method: string, path: string) {
  return (method === "GET" && path === "/v1/watch-packages/current") || (method === "POST" && path === "/v1/sightings")
}

export function createApp(haven: Haven) {
  const UI_DIST = resolve(haven.uiDist || join(import.meta.dir, "../../ui/dist"))

  function keyById(keyId: string): { org: string; project: string; key: KeyMeta } | null {
    for (const org of haven.listOrgs()) {
      for (const project of haven.listProjects(org.slug)) {
        for (const env of ["dev", "prod"]) {
          const key = haven.listKeys(org.slug, project.slug, env).find((item) => item.id === keyId)
          if (key) return { org: org.slug, project: project.slug, key }
        }
      }
    }
    return null
  }

  function policyFailure(error: unknown) {
    const code = String((error as any)?.message || error)
    if (code === "policy_version_conflict") return err(409, code, "policy changed; reload before saving")
    if (
      code === "invalid_policy" ||
      code === "invalid_expected_version" ||
      code === "created_by_required" ||
      code === "invalid_preview" ||
      code === "policy_scope_mismatch" ||
      code === "bad_resource_uri"
    ) {
      return err(400, code, code)
    }
    if (code === "org_not_found" || code === "project_not_found" || code === "key_not_found") {
      return err(404, "not_found", code)
    }
    throw error
  }

  function previewWarnings(input: any, decision: any) {
    if (
      decision?.reason !== "minimum_constraint" ||
      (input?.candidate_scope !== "project" && input?.candidate_scope !== "key")
    ) {
      return []
    }
    const matches = (rule: any) =>
      rule?.action === input.action &&
      rule?.actor_type === input.actor_type &&
      (rule.environment === undefined || rule.environment === input.environment) &&
      (rule.agent_id === undefined || rule.agent_id === input.agent_id)
    const parentDocuments =
      input.candidate_scope === "project"
        ? [decision.snapshot?.org]
        : [decision.snapshot?.org, decision.snapshot?.project]
    if (!parentDocuments.some((document) => document?.minimums?.some(matches))) return []
    return [
      {
        code: "parent_minimum_neutralizes_candidate",
        message: "A parent minimum raises this candidate outcome and cannot be weakened here.",
      },
    ]
  }

  function uiFile(rel: string) {
    const cleaned = normalize(rel).replace(/^(\.\.(\/|\\|$))+/, "")
    const full = resolve(UI_DIST, cleaned)
    if (!full.startsWith(UI_DIST)) return null
    if (!existsSync(full)) return null
    return full
  }

  function serveUi(path: string) {
    const rel = path === "/" || path.startsWith("/app") ? "index.html" : path.replace(/^\//, "")
    const file = uiFile(rel) || uiFile("index.html")
    if (!file) {
      return new Response("Haven operator UI is not built. Run the ui/ build.", {
        status: 503,
        headers: { "content-type": "text/plain; charset=utf-8" },
      })
    }
    const bunFile = Bun.file(file)
    const type = file.endsWith(".html") ? "text/html; charset=utf-8" : bunFile.type
    return new Response(bunFile, { headers: { "content-type": type } })
  }

  function actor(req: Request) {
    const userId = haven.sessionUserId(req)
    if (!userId) return null
    const human = haven.getHuman(userId)
    if (!human) return null
    return { ...human, orgs: haven.membershipsFor(userId) }
  }

  function requireOrgRole(req: Request, orgSlug: string, allowed: HumanRole[]) {
    const a = actor(req)
    if (!a) return { error: err(401, "unauthorized", "sign in required") }
    const org = haven.getOrgBySlug(orgSlug)
    if (!org) return { error: err(404, "not_found", "org not found") }
    const role = haven.roleFor(a.id, org.id)
    if (!role || !allowed.includes(role)) return { error: err(403, "forbidden", "insufficient role") }
    return { actor: a, org, role }
  }

  function requirePermission(
    req: Request,
    orgSlug: string,
    permission: Permission,
    resource: { projectId?: string | null; keyId?: string | null } = {},
  ) {
    const a = actor(req)
    if (!a) return { error: err(401, "unauthorized", "sign in required") }
    const org = haven.getOrgBySlug(orgSlug)
    if (!org) return { error: err(404, "not_found", "org not found") }
    const decision = haven.authorizeHuman(a.id, permission, { orgId: org.id, ...resource })
    if (!decision.allow) {
      return {
        error: err(403, "forbidden", decision.reason, {
          decision_id: decision.decision_id,
        }),
      }
    }
    return { actor: a, org, decision }
  }

  function requireHumanKeyPolicy(input: {
    humanId: string
    orgId: string
    projectId: string
    keyId: string
    action: "keys.reveal" | "keys.delete" | "keys.update"
    ref: string
    reason?: string | null
  }): Response | null {
    const decision = haven.evaluateHumanKeyAction({
      human_id: input.humanId,
      action: input.action,
      resource: input.ref,
    })
    if (decision.outcome === "deny") {
      return err(403, "policy_denied", decision.reason)
    }
    if (decision.outcome === "approval_required") {
      const existing = haven.listAccessRequests({
        org_id: input.orgId,
        project_id: input.projectId,
        key_id: input.keyId,
        status: "pending",
      }).find(
        (request) =>
          request.actor_type === "human" &&
          request.actor_id === input.humanId &&
          request.action === input.action &&
          request.policy_version === decision.policy_version &&
          canonicalJson(request.policy_snapshot) === canonicalJson(decision.snapshot),
      )
      const request =
        existing ??
        haven.createAccessRequest({
          org_id: input.orgId,
          project_id: input.projectId,
          key_id: input.keyId,
          action: input.action,
          actor_type: "human",
          actor_id: input.humanId,
          requester_human_id: input.humanId,
          policy_decision: decision,
          reason: input.reason,
        })
      return json({ access_request_id: request.id, status: request.status }, 202)
    }
    return null
  }

  function accessRequestOrgSlug(orgId: string) {
    return haven.listOrgs().find((org) => org.id === orgId)?.slug || null
  }

  function canReviewAccessRequest(request: AccessRequest, actorId: string) {
    if (request.status !== "pending") return false
    if (request.actor_type === "human" && request.requester_human_id === actorId) return false
    if (
      request.mode === "sequential" &&
      request.events.some((event) => event.type === "approved_stage" && event.actor_human_id === actorId)
    ) {
      return false
    }
    const tier = request.tiers[request.stage_index]
    if (!tier) return false
    const resource = {
      orgId: request.org_id,
      projectId: request.project_id,
      keyId: request.key_id,
    }
    if (!haven.authorizeHuman(actorId, "approvals.read", resource).allow) return false
    return (
      haven.authorizeHuman(actorId, `approvals.${tier}`, resource).allow ||
      haven.authorizeHuman(actorId, "approvals.escalate", resource).allow
    )
  }

  function accessRequestFailure(error: unknown) {
    const code = String((error as any)?.message || error)
    if (code === "request_not_found") return err(404, "not_found", code)
    if (code === "request_expired") return err(410, code, code)
    if (code === "request_not_pending") return err(409, code, code)
    if (code === "forbidden" || code === "self_approval" || code === "same_approver") {
      return err(403, code, code)
    }
    if (
      code === "reason_required" ||
      code === "invalid_actor" ||
      code === "invalid_tier" ||
      code === "escalation_not_upward"
    ) {
      return err(400, code, code)
    }
    throw error
  }

  return async function handleRequest(req: Request): Promise<Response> {
    const url = new URL(req.url)
    const path = url.pathname.replace(/\/+$/, "") || "/"
    const method = req.method.toUpperCase()

    if (method === "GET" && path === "/health") {
      return json({
        ok: true,
        service: "haven",
        version: VERSION,
        planes: ["identity", "broker", "pep", "ledger", "secrets", "knock", "activity", "buoys"],
        data: { dataDir: haven.dataDir },
      })
    }

    if (method === "GET" && !path.startsWith("/v1")) {
      return serveUi(path)
    }

    const buoyRoute = isBuoyRoute(method, path)
    if (buoyRoute && !req.headers.get("x-haven-buoy-id")?.trim()) {
      return err(401, "unauthorized", "X-Haven-Buoy-Id header required")
    }
    const buoy = buoyRoute ? haven.authenticateBuoy(req) : null
    if (
      path.startsWith("/v1") &&
      !isOpenRoute(method, path) &&
      !actor(req) &&
      !haven.authenticateApiKey(req) &&
      !buoy
    ) {
      return err(401, "unauthorized", "sign in required")
    }

    try {
      if (method === "POST" && path === "/v1/session") {
        const body = await readBody(req)
        const username = String(body?.username || "")
        const password = String(body?.password || "")
        const user = await haven.verifyPassword(username, password)
        if (!user) return err(401, "unauthorized", "invalid username or password")
        return json({ ok: true, username: user.username }, 200, { "set-cookie": haven.mintSessionCookie(user.id) })
      }

      if (method === "POST" && path === "/v1/session/logout") {
        return json({ ok: true }, 200, { "set-cookie": haven.clearSessionCookie() })
      }

      if (method === "GET" && path === "/v1/me") {
        const a = actor(req)
        if (!a) return err(401, "unauthorized", "sign in required")
        return json({ id: a.id, username: a.username, orgs: a.orgs })
      }

      if (method === "POST" && path === "/v1/me/password") {
        const a = actor(req)
        if (!a) return err(401, "unauthorized", "sign in required")
        const body = await readBody(req)
        try {
          await haven.changePassword(a.id, String(body?.current || ""), String(body?.next || ""))
          return json({ ok: true })
        } catch (e: any) {
          const msg = String(e.message || e)
          if (msg === "invalid_password") return err(401, "unauthorized", "current password is wrong")
          if (msg === "invalid_human") return err(400, "invalid_human", "new password must be 12+ characters")
          throw e
        }
      }

      if (method === "POST" && path === "/v1/knock") {
        const body = await readBody(req)
        try {
          const result = haven.knock({
            org: String(body?.org || ""),
            project: String(body?.project || ""),
            agent_name: String(body?.agent_name || ""),
            purpose: String(body?.purpose || ""),
            need: Array.isArray(body?.need) ? body.need : [],
            ttl_seconds: body?.ttl_seconds ? Number(body.ttl_seconds) : undefined,
          })
          const status = result.status === "auto_deny" ? 403 : result.status === "pending" ? 202 : 200
          return json(result, status)
        } catch (e: any) {
          const msg = String(e.message || e)
          if (msg === "org_not_found" || msg === "project_not_found") return err(404, msg, msg)
          if (msg === "invalid_knock") return err(400, "invalid_body", "org, project, agent_name, purpose, need required")
          if (msg === "agent_scope_mismatch" || msg === "resource_scope_mismatch") {
            return err(403, "forbidden", msg)
          }
          throw e
        }
      }

      const knockDecide = path.match(/^\/v1\/knocks\/([^/]+)\/(approve|deny)$/)
      if (method === "POST" && knockDecide) {
        const sessionActor = actor(req)
        if (!sessionActor) return err(401, "unauthorized", "sign in required")
        const knock = haven.getKnock(knockDecide[1])
        if (!knock) return err(404, "not_found", "knock_not_found")
        const request = knock.access_request_id
          ? haven.listAccessRequests().find((item) => item.id === knock.access_request_id)
          : null
        if (!request || request.status !== "pending") return err(409, "already_resolved", "access request is not pending")
        const tier = request.tiers[request.stage_index]
        if (!tier) return err(409, "invalid_request", "access request has no current approval tier")
        const project = haven.getProject(knock.org_slug, knock.project_slug)
        const gate = requirePermission(req, knock.org_slug, `approvals.${tier}`, {
          projectId: request.project_id ?? project?.id,
          keyId: request.key_id,
        })
        if ("error" in gate && gate.error) return gate.error
        try {
          const body = await readBody(req)
          const result = haven.decideKnock(knockDecide[1], {
            actorId: gate.actor.id,
            decision: knockDecide[2] as "approve" | "deny",
            reason: body?.reason ? String(body.reason) : null,
          })
          return json(result)
        } catch (e: any) {
          const msg = String(e.message || e)
          if (msg === "knock_not_found") return err(404, "not_found", msg)
          if (msg === "already_resolved") return err(409, "already_resolved", msg)
          if (msg === "forbidden") return err(403, "forbidden", msg)
          if (msg === "reason_required") return err(400, "reason_required", msg)
          throw e
        }
      }

      if (method === "GET" && path === "/v1/knocks") {
        const org = String(url.searchParams.get("org") || "").trim()
        if (!org) return err(400, "invalid_query", "org required")
        const gate = requirePermission(req, org, "approvals.read")
        if ("error" in gate && gate.error) return gate.error
        const status = url.searchParams.get("status") || undefined
        return json({ knocks: haven.listKnocks(status).filter((knock) => knock.org_slug === org) })
      }

      if (method === "GET" && path === "/v1/access-requests") {
        const orgSlug = String(url.searchParams.get("org") || "").trim()
        if (!orgSlug) return err(400, "invalid_query", "org required")
        const gate = requireOrgRole(req, orgSlug, ["superadmin", "admin", "user"])
        if ("error" in gate && gate.error) return gate.error
        const status = String(url.searchParams.get("status") || "").trim()
        if (status && !["pending", "approved", "denied", "auto_approved", "auto_denied", "cancelled", "expired"].includes(status)) {
          return err(400, "invalid_query", "invalid access request status")
        }
        return json({
          access_requests: haven.listAccessRequests({
            org_id: gate.org.id,
            ...(status ? { status: status as any } : {}),
          }).filter((request) => canReviewAccessRequest(request, gate.actor.id)),
        })
      }

      const accessRequestGet = path.match(/^\/v1\/access-requests\/([^/]+)$/)
      if (method === "GET" && accessRequestGet) {
        const request = haven.listAccessRequests().find((item) => item.id === accessRequestGet[1])
        if (!request) return err(404, "not_found", "request_not_found")
        const orgSlug = accessRequestOrgSlug(request.org_id)
        if (!orgSlug) return err(404, "not_found", "request_not_found")
        const gate = requirePermission(req, orgSlug, "approvals.read", {
          projectId: request.project_id,
          keyId: request.key_id,
        })
        if ("error" in gate && gate.error) return gate.error
        return json(request)
      }

      const accessRequestTransition = path.match(
        /^\/v1\/access-requests\/([^/]+)\/(approve|deny|escalate|cancel)$/,
      )
      if (method === "POST" && accessRequestTransition) {
        const sessionActor = actor(req)
        if (!sessionActor) return err(401, "unauthorized", "sign in required")
        const request = haven.listAccessRequests().find((item) => item.id === accessRequestTransition[1])
        if (!request) return err(404, "not_found", "request_not_found")
        const body = await readBody(req)
        try {
          if (accessRequestTransition[2] === "approve") {
            return json(haven.approveAccessRequest(request.id, {
              actor_human_id: sessionActor.id,
              reason: body?.reason ? String(body.reason) : null,
            }))
          }
          if (accessRequestTransition[2] === "deny") {
            return json(haven.denyAccessRequest(request.id, {
              actor_human_id: sessionActor.id,
              reason: body?.reason ? String(body.reason) : null,
            }))
          }
          if (accessRequestTransition[2] === "escalate") {
            return json(haven.escalateAccessRequest(request.id, {
              actor_human_id: sessionActor.id,
              tier: String(body?.tier || "") as "normal" | "elevated" | "breakglass",
              reason: String(body?.reason || ""),
            }))
          }
          return json(haven.cancelAccessRequest(request.id, {
            actor_human_id: sessionActor.id,
            reason: String(body?.reason || ""),
          }))
        } catch (error) {
          return accessRequestFailure(error)
        }
      }

      if (method === "GET" && path === "/v1/orgs") {
        const a = actor(req)
        if (!a) return err(401, "unauthorized", "sign in required")
        return json({ orgs: a.orgs.map((m) => ({ ...haven.getOrgBySlug(m.slug), role: m.role })) })
      }

      if (method === "GET" && path === "/v1/permissions") {
        const a = actor(req)
        if (!a) return err(401, "unauthorized", "sign in required")
        return json({
          version: 1,
          permissions: PERMISSIONS.map((permission) => ({
            permission,
            scopes: PERMISSION_SCOPES[permission],
          })),
        })
      }

      const userAccess = path.match(/^\/v1\/orgs\/([^/]+)\/users\/([^/]+)\/access$/)
      if (method === "GET" && userAccess) {
        const gate = requirePermission(req, userAccess[1], "org.permissions.read")
        if ("error" in gate && gate.error) return gate.error
        const user = haven.getHuman(userAccess[2])
        const role = haven.roleFor(userAccess[2], gate.org.id)
        if (!user || !role) return err(404, "not_found", "member not found")
        return json({
          user: { ...user, role },
          assigned: haven.listAccessAssignments(user.id, gate.org.id),
          inherited: [...ROLE_TEMPLATES[role]],
          effective: PERMISSIONS.map((permission) =>
            haven.explainAccess(user.id, permission, { orgId: gate.org.id }),
          ),
        })
      }

      const accessAssignments = path.match(/^\/v1\/orgs\/([^/]+)\/access-assignments$/)
      if (method === "POST" && accessAssignments) {
        const gate = requirePermission(req, accessAssignments[1], "org.permissions.manage")
        if ("error" in gate && gate.error) return gate.error
        const body = await readBody(req)
        const reason = String(body?.reason || "").trim()
        if (!reason) return err(400, "reason_required", "reason required")
        const permission = String(body?.permission || "")
        if (!isPermission(permission)) return err(400, "invalid_permission", "known permission required")
        const projectId = body?.project_id ? String(body.project_id) : null
        const keyId = body?.key_id ? String(body.key_id) : null
        const scope: PermissionScope | null = keyId ? (projectId ? "key" : null) : projectId ? "project" : "org"
        if (!scope || !permissionAllowsScope(permission, scope)) {
          return err(400, "invalid_assignment_scope", "permission cannot be assigned at requested scope")
        }
        try {
          return json(
            haven.grantAccessAssignment({
              user_id: String(body?.user_id || ""),
              org_id: gate.org.id,
              project_id: projectId,
              key_id: keyId,
              permission,
              effect: String(body?.effect || "") as "allow" | "deny",
              reason,
              grantor_id: gate.actor.id,
              expires_at: body?.expires_at ? String(body.expires_at) : null,
            }),
            201,
          )
        } catch (e: any) {
          const code = String(e.message || e)
          if (
            code === "invalid_permission" ||
            code === "invalid_effect" ||
            code === "reason_required" ||
            code === "invalid_assignment_scope" ||
            code === "invalid_expiry"
          ) {
            return err(400, code, code)
          }
          if (code === "member_not_found" || code === "project_not_found" || code === "key_not_found") {
            return err(404, "not_found", code)
          }
          if (code === "lockout_prevented") return err(409, code, code)
          throw e
        }
      }

      const revokeAssignment = path.match(/^\/v1\/orgs\/([^/]+)\/access-assignments\/([^/]+)\/revoke$/)
      if (method === "POST" && revokeAssignment) {
        const gate = requirePermission(req, revokeAssignment[1], "org.permissions.manage")
        if ("error" in gate && gate.error) return gate.error
        const body = await readBody(req)
        const reason = String(body?.reason || "").trim()
        if (!reason) return err(400, "reason_required", "reason required")
        const assignment = haven
          .listAccessAssignments()
          .find((item) => item.org_id === gate.org.id && item.id === revokeAssignment[2])
        if (!assignment) return err(404, "not_found", "assignment not found")
        try {
          return json(
            haven.revokeAccessAssignment(assignment.id, {
              revoked_by: gate.actor.id,
              reason,
            }),
          )
        } catch (e: any) {
          const code = String(e.message || e)
          if (code === "reason_required") return err(400, code, code)
          if (code === "assignment_not_found") return err(404, "not_found", code)
          if (code === "lockout_prevented") return err(409, code, code)
          throw e
        }
      }

      if (method === "POST" && path === "/v1/authorization/explain") {
        const body = await readBody(req)
        const orgSlug = String(body?.org || body?.org_slug || "").trim()
        if (!orgSlug) return err(400, "invalid_body", "org required")
        const gate = requirePermission(req, orgSlug, "org.permissions.read")
        if ("error" in gate && gate.error) return gate.error
        const userId = String(body?.user_id || "")
        if (!haven.getHuman(userId) || !haven.roleFor(userId, gate.org.id)) {
          return err(404, "not_found", "member not found")
        }
        const permission = String(body?.permission || "")
        if (!isPermission(permission)) return err(400, "invalid_permission", "known permission required")
        const projectId = body?.project_id ? String(body.project_id) : null
        const keyId = body?.key_id ? String(body.key_id) : null
        if (keyId && !projectId) return err(400, "invalid_resource", "key scope requires project_id")
        return json(
          haven.explainAccess(userId, permission, {
            orgId: gate.org.id,
            projectId,
            keyId,
          }),
        )
      }

      if (method === "GET" && path === "/v1/buoys") {
        const org = String(url.searchParams.get("org") || "").trim()
        if (!org) return err(400, "invalid_query", "org required")
        const gate = requirePermission(req, org, "agents.read")
        if ("error" in gate && gate.error) return gate.error
        return json({ buoys: haven.listBuoys(org) })
      }

      if (method === "POST" && path === "/v1/buoys") {
        const body = await readBody(req)
        const org = String(body?.org || body?.org_slug || "").trim()
        const kind = String(body?.kind || "")
        const name = String(body?.name || "").trim()
        if (!org || !BUOY_KINDS.has(kind) || !name) {
          return err(400, "invalid_body", "org, kind (harbor|custom), and name required")
        }
        const gate = requirePermission(req, org, "agents.manage")
        if ("error" in gate && gate.error) return gate.error
        try {
          return json(
            await haven.registerBuoy({
              orgSlug: org,
              kind: kind as "harbor" | "custom",
              name,
            }),
            201,
          )
        } catch (e: any) {
          const msg = String(e.message || e)
          if (msg === "invalid_buoy") return err(400, "invalid_body", msg)
          if (msg === "org_not_found") return err(404, "not_found", msg)
          if (msg === "canary_pepper_not_configured") return err(503, msg, msg)
          throw e
        }
      }

      const buoyCredential = path.match(/^\/v1\/buoys\/([^/]+)\/rotate-credential$/)
      if (method === "POST" && buoyCredential) {
        const body = await readBody(req)
        const org = String(body?.org || body?.org_slug || url.searchParams.get("org") || "").trim()
        if (!org) return err(400, "invalid_body", "org required")
        const gate = requirePermission(req, org, "agents.manage")
        if ("error" in gate && gate.error) return gate.error
        if (!haven.listBuoys(org).some((item) => item.id === buoyCredential[1])) {
          return err(404, "not_found", "buoy not found")
        }
        try {
          return json(await haven.rotateBuoyCredential(buoyCredential[1]))
        } catch (e: any) {
          const msg = String(e.message || e)
          if (msg === "buoy_not_found") return err(404, "not_found", msg)
          if (msg === "buoy_revoked") return err(409, msg, msg)
          if (msg === "canary_pepper_not_configured") return err(503, msg, msg)
          throw e
        }
      }

      const buoyRevoke = path.match(/^\/v1\/buoys\/([^/]+)\/revoke$/)
      if (method === "POST" && buoyRevoke) {
        const body = await readBody(req)
        const org = String(body?.org || body?.org_slug || url.searchParams.get("org") || "").trim()
        if (!org) return err(400, "invalid_body", "org required")
        const gate = requirePermission(req, org, "agents.manage")
        if ("error" in gate && gate.error) return gate.error
        if (!haven.listBuoys(org).some((item) => item.id === buoyRevoke[1])) {
          return err(404, "not_found", "buoy not found")
        }
        return json(haven.revokeBuoy(buoyRevoke[1]))
      }

      if (method === "GET" && path === "/v1/canaries") {
        const org = String(url.searchParams.get("org") || "").trim()
        if (!org) return err(400, "invalid_query", "org required")
        const gate = requireOrgRole(req, org, ["superadmin", "admin"])
        if ("error" in gate && gate.error) return gate.error
        return json({ canaries: haven.listCanaries(org) })
      }

      if (method === "POST" && path === "/v1/canaries") {
        const body = await readBody(req)
        const org = String(body?.org || body?.org_slug || "").trim()
        const project = String(body?.project || body?.project_slug || "").trim()
        const mode = String(body?.mode || "")
        if (!org || !project || !CANARY_MODES.has(mode)) {
          return err(400, "invalid_body", "org, project, and mode (decoy_key|sibling) required")
        }
        const gate = requireOrgRole(req, org, ["superadmin", "admin"])
        if ("error" in gate && gate.error) return gate.error
        try {
          return json(
            haven.plantCanary({
              orgSlug: org,
              projectSlug: project,
              mode: mode as "decoy_key" | "sibling",
              keyRef: body?.key_ref ? String(body.key_ref) : undefined,
              decoy: body?.decoy ? String(body.decoy) : undefined,
            }),
            201,
          )
        } catch (e: any) {
          const msg = String(e.message || e)
          if (msg === "org_not_found" || msg === "project_not_found" || msg === "key_not_found") {
            return err(404, "not_found", msg)
          }
          if (
            msg === "invalid_canary_mode" ||
            msg === "key_ref_required" ||
            msg === "key_ref_not_allowed"
          ) {
            return err(400, "invalid_body", msg)
          }
          if (msg === "canary_pepper_not_configured") return err(503, msg, msg)
          throw e
        }
      }

      const canaryRevoke = path.match(/^\/v1\/canaries\/([^/]+)\/revoke$/)
      if (method === "POST" && canaryRevoke) {
        const body = await readBody(req)
        const org = String(body?.org || body?.org_slug || url.searchParams.get("org") || "").trim()
        if (!org) return err(400, "invalid_body", "org required")
        const gate = requireOrgRole(req, org, ["superadmin", "admin"])
        if ("error" in gate && gate.error) return gate.error
        if (!haven.listCanaries(org).some((item) => item.id === canaryRevoke[1])) {
          return err(404, "not_found", "canary not found")
        }
        return json(haven.revokeCanary(canaryRevoke[1]))
      }

      if (method === "GET" && path === "/v1/watch-packages/current") {
        if (!buoy) return err(401, "unauthorized", "missing or invalid buoy credential")
        const audience = String(url.searchParams.get("audience") || buoy.kind).trim()
        if (!WATCH_AUDIENCES.has(audience)) {
          return err(400, "invalid_query", "audience must be harbor|custom|all")
        }
        if (audience !== "all" && audience !== buoy.kind) {
          return err(400, "invalid_query", "audience must match buoy kind or be all")
        }
        return json(haven.currentWatchPackage(buoy.org_id, audience), 200, {
          "x-haven-buoy-id": buoy.id,
        })
      }

      if (method === "POST" && path === "/v1/sightings") {
        if (!buoy) return err(401, "unauthorized", "missing or invalid buoy credential")
        const body = await readBody(req)
        if (!body?.buoy_id || !body?.canary_id || !body?.digest || !body?.observed_at) {
          return err(400, "invalid_body", "buoy_id, canary_id, digest, and observed_at required")
        }
        try {
          return json(haven.ingestSighting(buoy, body), 201)
        } catch (e: any) {
          const msg = String(e.message || e)
          if (msg === "invalid_buoy") return err(403, msg, msg)
          if (msg === "canary_not_found") return err(404, "not_found", msg)
          if (msg === "canary_revoked") return err(409, msg, msg)
          if (msg === "digest_mismatch" || msg === "invalid_observed_at") return err(400, "invalid_body", msg)
          throw e
        }
      }

      if (method === "GET" && path === "/v1/remediations") {
        const org = String(url.searchParams.get("org") || "").trim()
        const status = String(url.searchParams.get("status") || "").trim()
        if (!org) return err(400, "invalid_query", "org required")
        if (status && !REMEDIATION_STATUSES.has(status)) {
          return err(400, "invalid_query", "status must be open|rotated|dismissed")
        }
        const gate = requireOrgRole(req, org, ["superadmin", "admin"])
        if ("error" in gate && gate.error) return gate.error
        return json({
          remediations: haven.listRemediations(
            org,
            status ? (status as "open" | "rotated" | "dismissed") : undefined,
          ),
        })
      }

      const remediationAction = path.match(/^\/v1\/remediations\/([^/]+)\/(rotate|dismiss)$/)
      if (method === "POST" && remediationAction) {
        const body = await readBody(req)
        const org = String(body?.org || body?.org_slug || url.searchParams.get("org") || "").trim()
        if (!org) return err(400, "invalid_body", "org required")
        const gate = requireOrgRole(req, org, ["superadmin", "admin"])
        if ("error" in gate && gate.error) return gate.error
        if (!haven.listRemediations(org).some((item) => item.id === remediationAction[1])) {
          return err(404, "not_found", "remediation not found")
        }
        try {
          if (remediationAction[2] === "dismiss") {
            return json(haven.dismissRemediation(remediationAction[1]))
          }
          return json(haven.rotateRemediation(remediationAction[1], body?.revoke_canary !== false))
        } catch (e: any) {
          const msg = String(e.message || e)
          if (msg === "remediation_not_found") return err(404, "not_found", msg)
          if (msg === "remediation_already_rotated") return err(409, msg, msg)
          throw e
        }
      }

      if (method === "POST" && path === "/v1/orgs") {
        const a = actor(req)
        if (!a) return err(401, "unauthorized", "sign in required")
        const superadmin = a.orgs.some((o) => o.role === "superadmin")
        if (!superadmin) return err(403, "forbidden", "superadmin required")
        const body = await readBody(req)
        const slug = String(body?.slug || "").trim()
        const name = String(body?.name || slug).trim()
        if (!slug) return err(400, "invalid_body", "slug required")
        try {
          const org = haven.createOrg(slug, name)
          haven.createProject(org.id, "default", "default")
          await haven.createHuman({ username: a.username, password: "", orgId: org.id, role: "superadmin" })
          return json(org, 201)
        } catch (e: any) {
          if (String(e).includes("UNIQUE")) return err(409, "slug_taken", "org slug already exists")
          throw e
        }
      }

      const orgPolicy = path.match(/^\/v1\/orgs\/([^/]+)\/policy$/)
      if (orgPolicy && (method === "GET" || method === "PUT")) {
        const permission = method === "GET" ? "policies.org.read" : "policies.org.manage"
        const gate = requirePermission(req, orgPolicy[1], permission)
        if ("error" in gate && gate.error) return gate.error
        try {
          if (method === "GET") return json(haven.getOrgPolicy(orgPolicy[1]))
          const body = await readBody(req)
          return json(
            haven.setOrgPolicy(
              orgPolicy[1],
              body?.document as ActionPolicyDocument,
              body?.expected_version,
              gate.actor.username,
            ),
          )
        } catch (error) {
          return policyFailure(error)
        }
      }

      const orgPolicyHistory = path.match(/^\/v1\/orgs\/([^/]+)\/policy\/history$/)
      if (method === "GET" && orgPolicyHistory) {
        const gate = requirePermission(req, orgPolicyHistory[1], "policies.org.read")
        if ("error" in gate && gate.error) return gate.error
        const current = haven.getOrgPolicy(orgPolicyHistory[1])
        return json({ history: haven.listPolicyHistory("org", current.scope_id) })
      }

      const projectPolicy = path.match(/^\/v1\/orgs\/([^/]+)\/projects\/([^/]+)\/policy$/)
      if (projectPolicy && (method === "GET" || method === "PUT")) {
        const project = haven.getProject(projectPolicy[1], projectPolicy[2])
        const permission = method === "GET" ? "policies.project.read" : "policies.project.manage"
        const gate = requirePermission(req, projectPolicy[1], permission, { projectId: project?.id })
        if ("error" in gate && gate.error) return gate.error
        try {
          if (method === "GET") return json(haven.getProjectPolicy(projectPolicy[1], projectPolicy[2]))
          const body = await readBody(req)
          return json(
            haven.setProjectPolicy(
              projectPolicy[1],
              projectPolicy[2],
              body?.document as ActionPolicyDocument,
              body?.expected_version,
              gate.actor.username,
            ),
          )
        } catch (error) {
          return policyFailure(error)
        }
      }

      const projectPolicyHistory = path.match(
        /^\/v1\/orgs\/([^/]+)\/projects\/([^/]+)\/policy\/history$/,
      )
      if (method === "GET" && projectPolicyHistory) {
        const project = haven.getProject(projectPolicyHistory[1], projectPolicyHistory[2])
        const gate = requirePermission(req, projectPolicyHistory[1], "policies.project.read", {
          projectId: project?.id,
        })
        if ("error" in gate && gate.error) return gate.error
        try {
          const current = haven.getProjectPolicy(projectPolicyHistory[1], projectPolicyHistory[2])
          return json({ history: haven.listPolicyHistory("project", current.scope_id) })
        } catch (error) {
          return policyFailure(error)
        }
      }

      const keyPolicy = path.match(/^\/v1\/keys\/([^/]+)\/policy$/)
      if (keyPolicy && (method === "GET" || method === "PUT")) {
        const located = keyById(keyPolicy[1])
        if (!located) return err(404, "not_found", "key not found")
        const project = haven.getProject(located.org, located.project)
        const permission = method === "GET" ? "policies.key.read" : "policies.key.manage"
        const gate = requirePermission(req, located.org, permission, {
          projectId: project?.id,
          keyId: located.key.id,
        })
        if ("error" in gate && gate.error) return gate.error
        try {
          if (method === "GET") return json(haven.getKeyPolicy(located.key.ref))
          const body = await readBody(req)
          return json(
            haven.setKeyPolicy(
              located.key.ref,
              body?.document as ActionPolicyDocument,
              body?.expected_version,
              gate.actor.username,
            ),
          )
        } catch (error) {
          return policyFailure(error)
        }
      }

      const keyPolicyHistory = path.match(/^\/v1\/keys\/([^/]+)\/policy\/history$/)
      if (method === "GET" && keyPolicyHistory) {
        const located = keyById(keyPolicyHistory[1])
        if (!located) return err(404, "not_found", "key not found")
        const project = haven.getProject(located.org, located.project)
        const gate = requirePermission(req, located.org, "policies.key.read", {
          projectId: project?.id,
          keyId: located.key.id,
        })
        if ("error" in gate && gate.error) return gate.error
        return json({ history: haven.listPolicyHistory("key", located.key.id) })
      }

      if (method === "POST" && path === "/v1/policies/preview") {
        const body = await readBody(req)
        const orgSlug = String(body?.org || "").trim()
        if (!orgSlug) return err(400, "invalid_body", "org required")
        const parsedKey = body?.key_ref ? parseKeyRef(String(body.key_ref)) : null
        const previewBody = {
          ...body,
          ...(parsedKey && !body?.project ? { project: parsedKey.project } : {}),
        }
        const project = previewBody.project ? haven.getProject(orgSlug, String(previewBody.project)) : null
        const located = parsedKey
          ? {
              org: parsedKey.org,
              project: parsedKey.project,
              key: haven
                .listKeys(parsedKey.org, parsedKey.project, parsedKey.env)
                .find((item) => item.ref === String(body.key_ref)),
            }
          : null
        const scope =
          previewBody.candidate_scope || (previewBody.key_ref ? "key" : previewBody.project ? "project" : "org")
        if (parsedKey && !located?.key) return err(404, "not_found", "key not found")
        const permission =
          scope === "key" ? "policies.key.read" : scope === "project" ? "policies.project.read" : "policies.org.read"
        const gate = requirePermission(req, orgSlug, permission, {
          projectId: project?.id,
          keyId: located?.key?.id,
        })
        if ("error" in gate && gate.error) return gate.error
        try {
          const decision = haven.previewPolicy(previewBody)
          return json({ ...decision, warnings: previewWarnings(previewBody, decision) })
        } catch (error) {
          return policyFailure(error)
        }
      }

      const orgGuard = path.match(/^\/v1\/orgs\/([^/]+)\/guardrails$/)
      if (method === "PUT" && orgGuard) {
        const gate = requirePermission(req, orgGuard[1], "policies.org.manage")
        if ("error" in gate && gate.error) return gate.error
        const body = await readBody(req)
        return json(haven.setOrgGuardrail(orgGuard[1], body as Guardrail))
      }

      const orgMembers = path.match(/^\/v1\/orgs\/([^/]+)\/members$/)
      if (method === "GET" && orgMembers) {
        const gate = requirePermission(req, orgMembers[1], "org.members.read")
        if ("error" in gate && gate.error) return gate.error
        return json({ members: haven.listMembers(orgMembers[1]) })
      }
      if (method === "POST" && orgMembers) {
        const gate = requirePermission(req, orgMembers[1], "org.members.manage")
        if ("error" in gate && gate.error) return gate.error
        const body = await readBody(req)
        const role = String(body?.role || "user") as HumanRole
        if (!ROLES.has(role)) return err(400, "invalid_role", "superadmin|admin|user")
        if (role === "superadmin") {
          const elevated = requirePermission(req, orgMembers[1], "org.permissions.manage")
          if ("error" in elevated && elevated.error) return elevated.error
        }
        try {
          const member = await haven.createHuman({
            username: String(body?.username || ""),
            password: String(body?.password || ""),
            orgId: gate.org!.id,
            role,
          })
          return json({ ...member, role }, 201)
        } catch (e: any) {
          if (String(e.message) === "invalid_human") return err(400, "invalid_human", "username and password (12+) required")
          throw e
        }
      }

      const orgProjects = path.match(/^\/v1\/orgs\/([^/]+)\/projects$/)
      if (method === "GET" && orgProjects) {
        const gate = requirePermission(req, orgProjects[1], "projects.list")
        if ("error" in gate && gate.error) return gate.error
        return json({ projects: haven.listProjects(orgProjects[1]) })
      }
      if (method === "POST" && orgProjects) {
        const gate = requirePermission(req, orgProjects[1], "projects.create")
        if ("error" in gate && gate.error) return gate.error
        const body = await readBody(req)
        const slug = String(body?.slug || "").trim().toLowerCase()
        if (!slug || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(slug)) {
          return err(400, "invalid_body", "slug required (a-z, 0-9, _, -)")
        }
        try {
          return json(haven.createProject(gate.org!.id, slug, String(body?.name || slug)), 201)
        } catch (e: any) {
          if (String(e).includes("UNIQUE")) return err(409, "slug_taken", "project slug already exists")
          throw e
        }
      }

      const projGuard = path.match(/^\/v1\/orgs\/([^/]+)\/projects\/([^/]+)\/guardrails$/)
      if (method === "PUT" && projGuard) {
        const project = haven.getProject(projGuard[1], projGuard[2])
        const gate = requirePermission(req, projGuard[1], "policies.project.manage", {
          projectId: project?.id,
        })
        if ("error" in gate && gate.error) return gate.error
        const body = await readBody(req)
        try {
          return json(haven.setProjectGuardrail(projGuard[1], projGuard[2], body as Guardrail))
        } catch (e: any) {
          if (String(e.message) === "project_not_found") return err(404, "not_found", "project not found")
          throw e
        }
      }

      if (method === "POST" && path === "/v1/agents") {
        const body = await readBody(req)
        const org = String(body?.org || body?.org_slug || "").trim()
        if (!org) return err(400, "invalid_body", "org required")
        const gate = requirePermission(req, org, "agents.manage")
        if ("error" in gate && gate.error) return gate.error
        if (!body?.name || !body?.owner || !body?.purpose)
          return err(400, "invalid_body", "name, owner, purpose required")
        const risk = (body.risk_tier || "medium") as RiskTier
        if (!TIERS.has(risk)) return err(400, "invalid_risk_tier", "low|medium|high|critical")
        const scopes = Array.isArray(body.scopes) ? body.scopes.map(String) : ["secrets:read"]
        try {
          const agent = haven.createAgent({
            name: String(body.name),
            owner: String(body.owner),
            purpose: String(body.purpose),
            org_id: gate.org.id,
            risk_tier: risk,
            scopes,
          })
          return json(agent, 201)
        } catch (e: any) {
          if (String(e).includes("UNIQUE")) return err(409, "name_taken", "agent name already exists")
          throw e
        }
      }

      if (method === "GET" && path === "/v1/agents") {
        const org = String(url.searchParams.get("org") || "").trim()
        if (!org) return err(400, "invalid_query", "org required")
        const gate = requirePermission(req, org, "agents.read")
        if ("error" in gate && gate.error) return gate.error
        return json({ agents: haven.listAgents().filter((agent) => agent.org_id === gate.org.id) })
      }

      const agentMatch = path.match(/^\/v1\/agents\/([^/]+)$/)
      if (method === "GET" && agentMatch) {
        const org = String(url.searchParams.get("org") || "").trim()
        if (!org) return err(400, "invalid_query", "org required")
        const gate = requirePermission(req, org, "agents.read")
        if ("error" in gate && gate.error) return gate.error
        const a = haven.getAgent(agentMatch[1])
        if (!a || a.org_id !== gate.org.id) return err(404, "not_found", "agent not found")
        return json(a)
      }

      const revokeMatch = path.match(/^\/v1\/agents\/([^/]+)\/revoke$/)
      if (method === "POST" && revokeMatch) {
        const body = await readBody(req)
        const org = String(body?.org || body?.org_slug || url.searchParams.get("org") || "").trim()
        if (!org) return err(400, "invalid_body", "org required")
        const gate = requirePermission(req, org, "agents.manage")
        if ("error" in gate && gate.error) return gate.error
        const existing = haven.getAgent(revokeMatch[1])
        if (!existing || existing.org_id !== gate.org.id) return err(404, "not_found", "agent not found")
        const a = haven.revokeAgent(revokeMatch[1])
        if (!a) return err(404, "not_found", "agent not found")
        return json(a)
      }

      if (method === "POST" && path === "/v1/tokens") {
        const body = await readBody(req)
        if (!body?.agent_id) return err(400, "invalid_body", "agent_id required")
        const agent = haven.getAgent(String(body.agent_id))
        if (!agent || !agent.org_id) return err(404, "not_found", "agent_not_found")
        const org = haven.getOrg(agent.org_id)
        if (!org) return err(404, "not_found", "agent_not_found")
        const gate = requirePermission(req, org.slug, "agents.manage", {
          projectId: agent.project_id,
        })
        if ("error" in gate && gate.error) return gate.error
        try {
          const t = haven.mintToken(
            String(body.agent_id),
            Number(body.ttl_seconds || 900),
            body.scopes,
            undefined,
            gate.org.id,
          )
          return json(t, 201)
        } catch (e: any) {
          const msg = String(e.message || e)
          if (msg === "agent_not_found") return err(404, "not_found", msg)
          if (msg === "agent_revoked") return err(403, "agent_revoked", msg)
          if (msg === "agent_scope_mismatch") return err(403, "forbidden", msg)
          if (msg.startsWith("scope_not_granted")) return err(403, "scope_not_granted", msg)
          throw e
        }
      }

      if (method === "POST" && path === "/v1/tokens/introspect") {
        const body = await readBody(req)
        if (!body?.token) return err(400, "invalid_body", "token required")
        return json(haven.introspectToken(String(body.token)))
      }

      if (method === "POST" && path === "/v1/tokens/revoke") {
        const body = await readBody(req)
        if (!body?.token) return err(400, "invalid_body", "token required")
        const r = haven.revokeToken(String(body.token))
        if (!r) return err(404, "not_found", "token not found")
        return json(r)
      }

      if (method === "POST" && path === "/v1/authorize") {
        const body = await readBody(req)
        if (!body?.token || !body?.action) return err(400, "invalid_body", "token and action required")
        const decision = haven.authorize(String(body.token), String(body.action), String(body.resource || ""))
        return json(decision, decision.allow ? 200 : 403)
      }

      if (method === "POST" && path === "/v1/resources/grant") {
        const body = await readBody(req)
        const org = String(body?.org || body?.org_slug || "").trim()
        if (!org) return err(400, "invalid_body", "org required")
        const gate = requirePermission(req, org, "grants.manage")
        if ("error" in gate && gate.error) return gate.error
        if (!body?.agent_id || !body?.resource) return err(400, "invalid_body", "agent_id and resource required")
        const agent = haven.getAgent(String(body.agent_id))
        if (!agent || agent.org_id !== gate.org.id) return err(404, "not_found", "agent_not_found")
        const resource = String(body.resource)
        const parsed = parseKeyRef(resource)
        if (!parsed || parsed.org !== org) return err(400, "invalid_resource", "resource must belong to authorized org")
        try {
          return json(haven.grantResource(agent.id, resource), 201)
        } catch (e: any) {
          const msg = String(e.message || e)
          if (msg === "agent_not_found") return err(404, "not_found", msg)
          if (msg === "resource_must_use_haven_uri") return err(400, "invalid_resource", msg)
          throw e
        }
      }
      if (method === "GET" && path === "/v1/resources") {
        const org = String(url.searchParams.get("org") || "").trim()
        if (!org) return err(400, "invalid_query", "org required")
        const gate = requirePermission(req, org, "grants.read")
        if ("error" in gate && gate.error) return gate.error
        const agent_id = url.searchParams.get("agent_id") || undefined
        const orgAgentIds = new Set(
          haven
            .listAgents()
            .filter((agent) => agent.org_id === gate.org.id)
            .map((agent) => agent.id),
        )
        return json({
          grants: haven.listResourceGrants(agent_id).filter((grant) => orgAgentIds.has(grant.agent_id)),
        })
      }
      if (method === "POST" && path === "/v1/resources/revoke") {
        const body = await readBody(req)
        const org = String(body?.org || body?.org_slug || "").trim()
        if (!org) return err(400, "invalid_body", "org required")
        const gate = requirePermission(req, org, "grants.manage")
        if ("error" in gate && gate.error) return gate.error
        if (!body?.agent_id || !body?.resource) return err(400, "invalid_body", "agent_id and resource required")
        const agent = haven.getAgent(String(body.agent_id))
        if (!agent || agent.org_id !== gate.org.id) return err(404, "not_found", "agent_not_found")
        const resource = String(body.resource)
        const parsed = parseKeyRef(resource)
        if (!parsed || parsed.org !== org) return err(400, "invalid_resource", "resource must belong to authorized org")
        return json(haven.revokeResource(agent.id, resource))
      }

      if (method === "POST" && path === "/v1/secrets/reveal") {
        const body = await readBody(req)
        const ref = String(body?.ref || "").trim()
        const parsed = parseKeyRef(ref)
        if (!parsed) return err(400, "invalid_body", "valid key ref required")
        const project = haven.getProject(parsed.org, parsed.project)
        const key = haven.listKeys(parsed.org, parsed.project, parsed.env).find((item) => item.name === parsed.name)
        const gate = requirePermission(req, parsed.org, "keys.reveal", {
          projectId: project?.id,
          keyId: key?.id,
        })
        if ("error" in gate && gate.error) return gate.error
        if (!project || !key) return err(404, "not_found", "key not found")
        try {
          const policyGate = requireHumanKeyPolicy({
            humanId: gate.actor.id,
            orgId: gate.org.id,
            projectId: project.id,
            keyId: key.id,
            action: "keys.reveal",
            ref,
            reason: body?.reason ? String(body.reason) : null,
          })
          if (policyGate) return policyGate
          return json(haven.revealKey(ref, gate.actor.username))
        } catch (e: any) {
          const msg = String(e.message || e)
          if (msg === "key_not_found" || msg === "project_not_found") return err(404, "not_found", "key not found")
          throw e
        }
      }

      if (method === "POST" && path === "/v1/secrets/delete") {
        const body = await readBody(req)
        const ref = String(body?.ref || "").trim()
        const confirmName = String(body?.confirm_name || "").trim()
        const parsed = parseKeyRef(ref)
        if (!parsed) return err(400, "invalid_body", "valid key ref required")
        if (!confirmName) return err(400, "invalid_body", "confirm_name required")
        const project = haven.getProject(parsed.org, parsed.project)
        const key = haven.listKeys(parsed.org, parsed.project, parsed.env).find((item) => item.name === parsed.name)
        const gate = requirePermission(req, parsed.org, "keys.delete", {
          projectId: project?.id,
          keyId: key?.id,
        })
        if ("error" in gate && gate.error) return gate.error
        if (!project || !key) return err(404, "not_found", "key not found")
        if (confirmName !== key.name) return err(400, "invalid_body", "confirmation_name_mismatch")
        try {
          const policyGate = requireHumanKeyPolicy({
            humanId: gate.actor.id,
            orgId: gate.org.id,
            projectId: project.id,
            keyId: key.id,
            action: "keys.delete",
            ref,
            reason: body?.reason ? String(body.reason) : null,
          })
          if (policyGate) return policyGate
          return json(haven.deleteKey(ref, confirmName, gate.actor.username))
        } catch (e: any) {
          const msg = String(e.message || e)
          if (msg === "key_not_found") return err(404, "not_found", "key not found")
          if (msg === "confirmation_name_mismatch") return err(400, "invalid_body", msg)
          throw e
        }
      }

      if (method === "GET" && path === "/v1/secrets") {
        const org = url.searchParams.get("org") || "demo"
        const project = url.searchParams.get("project") || "default"
        const env = url.searchParams.get("env") || "dev"
        const projectRecord = haven.getProject(org, project)
        const gate = requirePermission(req, org, "keys.list", { projectId: projectRecord?.id })
        if ("error" in gate && gate.error) return gate.error
        return json({ secrets: haven.listKeys(org, project, env) })
      }

      if (method === "POST" && path === "/v1/secrets") {
        const body = await readBody(req)
        const org = String(body?.org || "demo")
        const project = String(body?.project || "default")
        const env = String(body?.env || "dev") === "prod" ? "prod" : "dev"
        const name = String(body?.name || "").trim()
        const value = String(body?.value || "")
        const projectRecord = haven.getProject(org, project)
        const existingKey = projectRecord
          ? haven.listKeys(org, project, env).find((item) => item.name === name)
          : undefined
        const gate = requirePermission(req, org, existingKey ? "keys.update" : "keys.create", {
          projectId: projectRecord?.id,
          keyId: existingKey?.id,
        })
        if ("error" in gate && gate.error) return gate.error
        if (!name || !value) return err(400, "invalid_body", "name, value required")
        try {
          if (existingKey && projectRecord) {
            const ref = existingKey.ref
            const policyGate = requireHumanKeyPolicy({
              humanId: gate.actor.id,
              orgId: gate.org.id,
              projectId: projectRecord.id,
              keyId: existingKey.id,
              action: "keys.update",
              ref,
              reason: body?.reason ? String(body.reason) : null,
            })
            if (policyGate) return policyGate
          }
          return json(haven.putKey({ org, project, env, name, value }))
        } catch (e: any) {
          const msg = String(e.message || e)
          if (msg === "org_not_found") return err(404, "not_found", msg)
          throw e
        }
      }

      if (method === "POST" && path === "/v1/secrets/resolve") {
        const body = await readBody(req)
        if (!body?.token || !body?.resource) return err(400, "invalid_body", "token and resource required")
        const result = haven.resolveSecret(String(body.token), String(body.resource))
        if (!result.allow) {
          const status = result.reason === "resource_not_granted" || result.reason === "scope_missing" ? 403 : 400
          return json(
            {
              allow: false,
              reason: result.reason,
              decision_id: result.decision_id,
              agent_id: result.agent_id,
              resource: body.resource,
            },
            status,
          )
        }
        return json({
          allow: true,
          resource: result.resource,
          value: result.value,
          decision_id: result.decision_id,
          agent_id: result.agent_id,
        })
      }

      if (method === "POST" && path === "/v1/api-keys") {
        const body = await readBody(req)
        const org = String(body?.org || body?.org_slug || "").trim()
        if (!org) return err(400, "invalid_body", "org required")
        const gate = requirePermission(req, org, "api_keys.manage")
        if ("error" in gate && gate.error) return gate.error
        if (!body?.name) return err(400, "invalid_body", "name required")
        try {
          return json(haven.mintApiKey(String(body.name), gate.org.id), 201)
        } catch (e: any) {
          if (String(e.message) === "name_required") return err(400, "invalid_body", "name required")
          throw e
        }
      }

      if (method === "GET" && path === "/v1/api-keys") {
        const org = String(url.searchParams.get("org") || "").trim()
        if (!org) return err(400, "invalid_query", "org required")
        const gate = requirePermission(req, org, "api_keys.read")
        if ("error" in gate && gate.error) return gate.error
        return json({ keys: haven.listApiKeys(gate.org.id) })
      }

      const apiKeyRevoke = path.match(/^\/v1\/api-keys\/([^/]+)\/revoke$/)
      if (method === "POST" && apiKeyRevoke) {
        const body = await readBody(req)
        const org = String(body?.org || body?.org_slug || url.searchParams.get("org") || "").trim()
        if (!org) return err(400, "invalid_body", "org required")
        const gate = requirePermission(req, org, "api_keys.manage")
        if ("error" in gate && gate.error) return gate.error
        const k = haven.revokeApiKey(apiKeyRevoke[1], gate.org.id)
        if (!k) return err(404, "not_found", "api key not found")
        return json(k)
      }

      if (method === "POST" && path === "/v1/activity") {
        const key = haven.authenticateApiKey(req)
        if (!key) return err(401, "unauthorized", "missing or invalid activity API key")
        const body = await readBody(req)
        try {
          const event = haven.ingestActivity(key, body || {})
          return json({ ok: true, event }, 201)
        } catch (e: any) {
          const msg = String(e.message || e)
          if (msg === "invalid_activity_type")
            return err(400, "invalid_activity_type", "type must be activity.* or log.*")
          if (msg === "invalid_outcome") return err(400, "invalid_outcome", "success|denied|error|info")
          if (msg === "scope_missing") return err(403, "scope_missing", msg)
          throw e
        }
      }

      if (method === "GET" && path === "/v1/activity") {
        const key = haven.authenticateApiKey(req)
        if (!key) return err(401, "unauthorized", "missing or invalid activity API key")
        if (!key.scopes.includes("activity:read")) return err(403, "scope_missing", "activity:read required")
        if (!key.org_id) return err(401, "unauthorized", "activity API key has no organization")
        const limit = Math.min(Number(url.searchParams.get("limit") || 50), 500)
        return json({ events: haven.listActivityForOrg(key.org_id, limit) })
      }

      if (method === "GET" && path === "/v1/ledger") {
        const org = String(url.searchParams.get("org") || "").trim()
        if (!org) return err(400, "invalid_query", "org required")
        const gate = requirePermission(req, org, "audit.read")
        if ("error" in gate && gate.error) return gate.error
        const limit = Math.min(Number(url.searchParams.get("limit") || 50), 500)
        const agent_id = url.searchParams.get("agent_id") || undefined
        return json({ events: haven.ledgerListForOrg(gate.org.id, limit, agent_id) })
      }

      if (method === "GET" && path === "/v1/ledger/verify") {
        const org = String(url.searchParams.get("org") || "").trim()
        if (!org) return err(400, "invalid_query", "org required")
        const gate = requirePermission(req, org, "audit.read")
        if ("error" in gate && gate.error) return gate.error
        return json(haven.verifyLedger())
      }

      return err(404, "not_found", `no route ${method} ${path}`)
    } catch (e: any) {
      console.error(e)
      return err(500, "internal", String(e.message || e))
    }
  }
}
