# Control Mappings

Human-readable index: compliance control → Kyverno policy → rationale.
Source of truth for control text is the `compliance.framework/control-text` annotation in each policy file.

## ISO/IEC 27001:2022

| Control | Policy file | Status | Rationale |
|---|---|---|---|
| A.8.2 | `chart/templates/iso27001/iso-a8.2-no-privileged-nonroot.yaml` | Drafted, untested | Privileged access rights — disallow privileged containers, require `runAsNonRoot` (Pod- or container-level). Reclassified from A.8.9 (Configuration management): running privileged / as root is itself the grant of a privileged access right, not a configuration-management concern. |
| A.5.15 | `chart/templates/iso27001/iso-a5.15-no-wildcard-rbac.yaml` | Drafted (`foreach`), untested | Access control — no `*` verbs/resources in Roles/ClusterRoles. Excludes `system:*` and `cluster-admin`. |
| A.5.15 | `chart/templates/iso27001/iso-a5.15-no-default-serviceaccount-token.yaml` | Drafted, untested | Access control — Pods must not run as the implicit `default` ServiceAccount, and must explicitly set `automountServiceAccountToken: false` unless the workload calls the Kubernetes API. Complements the wildcard-RBAC policy: that one checks the permissions granted, this one checks which identity a Pod runs as. |
| A.8.24 | `chart/templates/iso27001/iso-a8.24-encrypted-storage.yaml` | Drafted, untested | Use of cryptography (at rest) — PVC must set `storageClassName`; referenced StorageClass is looked up via `apiCall` and must declare encryption. |
| A.8.24 | `chart/templates/iso27001/iso-a8.24-storageclass-encryption.yaml` | Drafted, untested | Use of cryptography (at rest) — StorageClass must carry a provider encryption parameter (EBS/Azure/GCP) or the on-prem attestation annotation `compliance.storage/encrypted-at-rest: "true"`. |
| A.8.24 | `chart/templates/iso27001/iso-a8.24-ingress-tls.yaml` | Drafted, untested | Use of cryptography (in transit) — Ingress must declare at least one `spec.tls` entry. |
| A.8.20 | `chart/templates/iso27001/iso-a8.20-require-networkpolicy.yaml` | Drafted, untested | Network security — Pods rejected/reported if their namespace has zero NetworkPolicies (counted via `apiCall`, not a pattern on the Namespace). |
| A.8.16 | `chart/templates/iso27001/iso-a8.16-require-probes.yaml` | Drafted, untested | Monitoring activities — require liveness/readiness probes on every app container. |
| A.5.23 | `chart/templates/iso27001/iso-a5.23-approved-registries.yaml` | Drafted, untested — **placeholder registry list** | Cloud services security — images only from approved registries. |
| A.8.31 | `chart/templates/iso27001/iso-a8.31-require-env-label.yaml` | Drafted, untested | Separation of environments — require `environment` label ∈ {dev, test, staging, prod}. |
| A.8.6 | `chart/templates/iso27001/iso-a8.6-require-resources.yaml` | Drafted, untested | Capacity management — require CPU/memory requests and limits. |
| A.8.28 | `chart/templates/iso27001/iso-a8.28-secure-coding-hardening.yaml` | Drafted, untested | Secure coding — containers must set `readOnlyRootFilesystem: true`; Pods must not set `hostPID: true`. |
| A.8.18 | `chart/templates/iso27001/iso-a8.18-disallow-dangerous-capabilities.yaml` | Drafted, untested | Use of privileged utility programs — containers must not add capabilities from a denylist (`compliance.frameworks.iso27001.disallowedCapabilities`, default includes `ALL`, `NET_ADMIN`, `SYS_ADMIN`, etc.). |
| A.8.21 | `chart/templates/iso27001/iso-a8.21-no-host-network.yaml` | Drafted, untested | Security of network services — Pods must not set `hostNetwork: true` or `hostIPC: true`. |

## CIS Kubernetes Benchmark

Only Section 5 ("Policies") is in scope. Sections 1–4 (control plane
component flags, etcd config, kubelet config) audit how node/control-plane
*processes* are configured on disk — Kyverno is an admission controller, it
only ever sees Kubernetes API objects, so it structurally cannot check
those. Use [kube-bench](https://github.com/aquasecurity/kube-bench) for
sections 1–4. Skipped within Section 5: 5.1.1/5.1.2/5.1.4 (audits of
*existing* RoleBindings, not a creation-time-preventable rule), 5.2.10
(Windows HostProcess containers, not applicable off-Windows), 5.4.2/5.5.1
(architecture/cluster-config recommendations, not object-level checks).

Sub-item numbers (5.x.y) drift slightly across CIS Kubernetes Benchmark
versions (v1.7 vs v1.8/1.9+); the numbers below follow the commonly-cited
v1.8 ordering. If auditing against a specific pinned CIS version, verify
numbers against that version's PDF — the control **text** and the check
itself are what matter for compliance, not the exact section number.

| Control | Policy file | Status | Rationale |
|---|---|---|---|
| 5.1.3 | `chart/templates/cis/cis-5.1.3-no-wildcard-rbac.yaml` | Drafted (`foreach`), untested | No `*` verbs/resources in Roles/ClusterRoles. Excludes `system:*` and `cluster-admin`. |
| 5.1.5 | `chart/templates/cis/cis-5.1.5-no-default-serviceaccount.yaml` | Drafted, untested | Pods must not run as the implicit `default` ServiceAccount. |
| 5.1.6 | `chart/templates/cis/cis-5.1.6-no-token-automount.yaml` | Drafted, untested | Pods must explicitly set `automountServiceAccountToken: false` unless the workload calls the Kubernetes API. |
| 5.1.7 | `chart/templates/cis/cis-5.1.7-limit-bind-impersonate-escalate.yaml` | Drafted (`foreach`), untested | Roles/ClusterRoles must not grant `bind`, `impersonate`, or `escalate` — privilege-escalation primitives. |
| 5.2.1 | `chart/templates/cis/cis-5.2.1-no-privileged-containers.yaml` | Drafted, untested | No privileged containers. |
| 5.2.2 | `chart/templates/cis/cis-5.2.2-no-host-pid.yaml` | Drafted, untested | No `hostPID`. |
| 5.2.3 | `chart/templates/cis/cis-5.2.3-no-host-ipc.yaml` | Drafted, untested | No `hostIPC`. |
| 5.2.4 | `chart/templates/cis/cis-5.2.4-no-host-network.yaml` | Drafted, untested | No `hostNetwork`. |
| 5.2.5 | `chart/templates/cis/cis-5.2.5-no-privilege-escalation.yaml` | Drafted, untested | Every container must explicitly set `allowPrivilegeEscalation: false` — it defaults to `true` when unset. |
| 5.2.6 | `chart/templates/cis/cis-5.2.6-no-root-containers.yaml` | Drafted, untested | Require `runAsNonRoot: true` (Pod- or container-level). |
| 5.2.7 | `chart/templates/cis/cis-5.2.7-drop-net-raw.yaml` | Drafted (`foreach`), untested | Every container must drop `NET_RAW` (or `ALL`) from `securityContext.capabilities.drop`. |
| 5.2.8 | `chart/templates/cis/cis-5.2.8-no-added-capabilities.yaml` | Drafted (`foreach`), untested | No container may set `securityContext.capabilities.add`. |
| 5.2.11 | `chart/templates/cis/cis-5.2.11-no-hostpath-volumes.yaml` | Drafted (`foreach`), untested | No `hostPath` volumes. |
| 5.2.12 | `chart/templates/cis/cis-5.2.12-no-host-ports.yaml` | Drafted (`foreach`), untested | No container port may set `hostPort`. |
| 5.3.2 | `chart/templates/cis/cis-5.3.2-require-networkpolicy.yaml` | Drafted, untested | Pods rejected/reported if their namespace has zero NetworkPolicies (counted via `apiCall`). Same mechanism as ISO A.8.20. |
| 5.4.1 | `chart/templates/cis/cis-5.4.1-no-secrets-as-env-vars.yaml` | Drafted (`foreach`), untested | No container may reference a Secret via `env`/`envFrom` — must mount as a volume instead. |
| 5.7.4 | `chart/templates/cis/cis-5.7.4-no-default-namespace.yaml` | Drafted, untested | Workloads must not be deployed to the `default` namespace. |

## SOC2

_Not started._

## HIPAA

_Not started._
