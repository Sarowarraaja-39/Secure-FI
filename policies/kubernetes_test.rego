package securefi.kubernetes
import rego.v1

test_privileged_default_denied if {
  bad := {"kind":"Deployment","spec":{"template":{"spec":{"containers":[{"name":"unsafe"}]}}}}
  count(deny with input as bad) > 0
}
test_hardened_allowed if {
  good := {"kind":"Deployment","spec":{"template":{"spec":{"automountServiceAccountToken":false,
    "containers":[{"securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}}]}}}}
  count(deny with input as good) == 0
}
