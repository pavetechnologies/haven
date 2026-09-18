import { describe, expect, test } from "bun:test"
import {
  ACCESS_SECTIONS,
  APPROVAL_INBOX_ACTIONS,
  APPROVAL_INBOX_COLUMNS,
  ASSIGNMENT_FORM_CONTROLS,
  ORG_SWITCHER,
  orgScopedScreenKey,
  projectKeysForPicker,
} from "./access-contract.ts"

describe("organization switching contract", () => {
  test("exposes the organization switcher control", () => {
    expect(ORG_SWITCHER).toEqual({ id: "active-org", label: "Organization" })
  })

  test("changes the mounted screen identity when the active organization changes", () => {
    expect(orgScopedScreenKey("demo", "projects")).toBe("demo:projects")
    expect(orgScopedScreenKey("other", "projects")).toBe("other:projects")
  })
})

describe("Access workspace contract", () => {
  test("renders assigned, inherited, and effective sections", () => {
    expect(ACCESS_SECTIONS).toEqual(["assigned", "inherited", "effective"])
  })

  test("exposes grant and revoke controls", () => {
    expect(ASSIGNMENT_FORM_CONTROLS).toEqual([
      "effect",
      "scope",
      "permission",
      "project",
      "key",
      "expires",
      "reason",
      "grant",
      "revoke",
    ])
  })

  test("builds human-readable key choices backed by stable IDs", () => {
    expect(
      projectKeysForPicker([
        { id: "key_123", name: "DATABASE_URL", ref: "haven://demo/default/dev/DATABASE_URL" },
      ]),
    ).toEqual([
      { value: "key_123", label: "DATABASE_URL · dev", ref: "haven://demo/default/dev/DATABASE_URL" },
    ])
  })
})

describe("Approval inbox contract", () => {
  test("exposes policy explanation and requester reason as separate columns", () => {
    expect(APPROVAL_INBOX_COLUMNS).toEqual([
      "Origin",
      "Owner",
      "Resource",
      "Stage",
      "Policy explanation",
      "Requester reason",
      "Actions",
    ])
  })

  test("exposes the review actions", () => {
    expect(APPROVAL_INBOX_ACTIONS).toEqual(["Approve", "Deny", "Escalate"])
  })
})
