export const ACCESS_SECTIONS = ["assigned", "inherited", "effective"] as const

export const ORG_SWITCHER = { id: "active-org", label: "Organization" } as const

export const ASSIGNMENT_FORM_CONTROLS = [
  "effect",
  "scope",
  "permission",
  "project",
  "key",
  "expires",
  "reason",
  "grant",
  "revoke",
] as const

export const APPROVAL_INBOX_COLUMNS = [
  "Origin",
  "Owner",
  "Resource",
  "Stage",
  "Policy explanation",
  "Requester reason",
  "Actions",
] as const

export const APPROVAL_INBOX_ACTIONS = ["Approve", "Deny", "Escalate"] as const

export function orgScopedScreenKey(org: string, screen: string) {
  return `${org}:${screen}`
}

export function projectKeysForPicker(
  keys: Array<{ id: string; name: string; ref: string }>,
) {
  return keys.map((key) => {
    const segments = key.ref.split("/")
    return {
      value: key.id,
      label: `${key.name} · ${segments.at(-2) || "unknown"}`,
      ref: key.ref,
    }
  })
}
