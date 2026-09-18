import { expect, test } from "bun:test"
import { PERMISSIONS, ROLE_TEMPLATES, permissionAllowsScope, templateAllows } from "./permissions.ts"

test("catalog includes keys.reveal and approvals.breakglass", () => {
  expect(PERMISSIONS).toContain("keys.reveal")
  expect(PERMISSIONS).toContain("approvals.breakglass")
  expect(PERMISSIONS).toContain("org.permissions.manage")
})

test("superadmin template includes org.permissions.manage; user does not", () => {
  expect(templateAllows("superadmin", "org.permissions.manage")).toBe(true)
  expect(templateAllows("user", "org.permissions.manage")).toBe(false)
  expect(templateAllows("user", "approvals.normal")).toBe(true)
})

test("projects.create is org-scoped only", () => {
  expect(permissionAllowsScope("projects.create", "org")).toBe(true)
  expect(permissionAllowsScope("projects.create", "project")).toBe(false)
  expect(permissionAllowsScope("keys.reveal", "key")).toBe(true)
})
