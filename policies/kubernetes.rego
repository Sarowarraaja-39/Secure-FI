package securefi.kubernetes
import rego.v1

deny contains "Container must not allow privilege escalation" if {
  container := input.spec.template.spec.containers[_]
  not container.securityContext.allowPrivilegeEscalation == false
}
deny contains "Container must use a read-only root filesystem" if {
  container := input.spec.template.spec.containers[_]
  not container.securityContext.readOnlyRootFilesystem == true
}
deny contains "Container must drop ALL capabilities" if {
  container := input.spec.template.spec.containers[_]
  not "ALL" in container.securityContext.capabilities.drop
}
deny contains "Pod must disable service account token automount" if {
  input.kind == "Deployment"
  not input.spec.template.spec.automountServiceAccountToken == false
}
