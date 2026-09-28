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

## CIS Kubernetes Benchmark

_Not started._

## SOC2

_Not started._

## HIPAA

_Not started._
