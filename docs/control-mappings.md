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

Source: AICPA *TSP Section 100, 2017 Trust Services Criteria for Security,
Availability, Processing Integrity, Confidentiality, and Privacy (With
Revised Points of Focus – 2022)*. The 2022 revision changed points of focus
only; the criterion text in each policy's `control-text` annotation is the
2017 wording, verbatim, sometimes followed by the specific point of focus
the policy implements.

SOC 2 is principles-based: unlike CIS, it never names a Kubernetes setting.
Each mapping below is an **interpretation** — the point of focus a policy
provides evidence for — and an auditor may map differently. Security (the
Common Criteria, CC) is mandatory in every SOC 2 report; Availability (A),
Confidentiality (C), Processing Integrity (PI) and Privacy (P) are optional
categories. Policies for A and C are included but can be disabled per-policy
if the report excludes them.

All disabled by default (`compliance.frameworks.soc2.enabled: false`), Audit
mode, same values-driven mechanism as ISO/CIS. Two policies are
additionally off by default because they can't work until real values exist:
`soc2-cc6.8-verify-image-signatures` (needs a cosign key) and
`soc2-cc8.1-restrict-direct-changes` (needs the GitOps/CI identity).

### Mapped criteria (25 policies, 10 criteria)

| Criterion | Policy file | Status | Rationale (point of focus) |
|---|---|---|---|
| CC6.1 | `chart/templates/soc2/soc2-cc6.1-restrict-privileged-containers.yaml` | Drafted, untested | *Restricts Logical Access* (administrative authorities) — no privileged containers, `allowPrivilegeEscalation: false` required, `runAsNonRoot: true` required. |
| CC6.1 | `chart/templates/soc2/soc2-cc6.1-restrict-host-access.yaml` | Drafted (`foreach`), untested | *Restricts Logical Access* (hardware) / *Considers Network Segmentation* — no `hostNetwork`/`hostPID`/`hostIPC`, no `hostPath` volumes, no `hostPort`. |
| CC6.1 | `chart/templates/soc2/soc2-cc6.1-restrict-capabilities.yaml` | Drafted (`foreach`), untested | *Restricts Logical Access* (administrative authorities) — added capabilities must be in an **allowlist** (`soc2.allowedCapabilities`, default `NET_BIND_SERVICE`, i.e. PSS restricted). Stricter than ISO A.8.18's denylist. |
| CC6.1 | `chart/templates/soc2/soc2-cc6.1-workload-identity.yaml` | Drafted, untested | *Identifies and Authenticates Users* (software) / *Manages Credentials for Infrastructure and Software* — dedicated ServiceAccount, `automountServiceAccountToken: false`. |
| CC6.1 | `chart/templates/soc2/soc2-cc6.1-no-anonymous-rbac-bindings.yaml` | Drafted, untested | *Identifies and Authenticates Users* — no (Cluster)RoleBinding to `system:anonymous`, `system:unauthenticated` or `system:authenticated`. Excludes `system:*` / `kubeadm:*` bindings by name. |
| CC6.1 | `chart/templates/soc2/soc2-cc6.1-require-networkpolicy.yaml` | Drafted, untested | *Considers Network Segmentation* — Pods flagged if their namespace has zero NetworkPolicies (`apiCall`). Same mechanism as ISO A.8.20. |
| CC6.1 | `chart/templates/soc2/soc2-cc6.1-storageclass-encryption.yaml` | Drafted, untested | *Uses Encryption to Protect Data* (at rest) — StorageClass must declare provider encryption or carry the on-prem attestation annotation. |
| CC6.1 | `chart/templates/soc2/soc2-cc6.1-pvc-encrypted-storage.yaml` | Drafted, untested | *Uses Encryption to Protect Data* (at rest) — PVC's StorageClass looked up via `apiCall` and checked with the same criteria. Needs Kyverno RBAC to read StorageClasses. |
| CC6.1 | `chart/templates/soc2/soc2-cc6.1-no-secrets-in-env.yaml` | Drafted (`foreach`), untested | *Manages Credentials* / *Protects Encryption Keys* — Secrets mounted as volumes, not `env`/`envFrom`. |
| CC6.1 | `chart/templates/soc2/soc2-cc6.1-require-ownership-labels.yaml` | Drafted, untested | *Identifies and Manages the Inventory of Information Assets* — workloads must carry `soc2.requiredLabels` (default `app.kubernetes.io/name`, `owner`). |
| CC6.3 | `chart/templates/soc2/soc2-cc6.3-no-wildcard-rbac.yaml` | Drafted (`foreach`), untested | Least privilege — no `*` verbs/resources in Roles/ClusterRoles. |
| CC6.3 | `chart/templates/soc2/soc2-cc6.3-no-escalation-verbs.yaml` | Drafted (`foreach`), untested | Least privilege / segregation of duties — no `bind`, `impersonate`, `escalate`. |
| CC6.3 | `chart/templates/soc2/soc2-cc6.3-restrict-cluster-admin-bindings.yaml` | Drafted, untested | Least privilege — no new bindings to `cluster-admin` except `system:*`, `kubeadm:*`, and names in `soc2.allowedClusterAdminBindings` (break-glass). |
| CC6.6 | `chart/templates/soc2/soc2-cc6.6-restrict-service-exposure.yaml` | Drafted, untested | *Restricts Access* (communication channels) / *Implements Boundary Protection Systems* — Service type ∈ `soc2.allowedServiceTypes` (no NodePort by default), no `externalIPs` (CVE-2020-8554). A bare-metal NodePort ingress controller needs a PolicyException. |
| CC6.7 | `chart/templates/soc2/soc2-cc6.7-ingress-tls.yaml` | Drafted, untested | *Uses Encryption Technologies or Secure Communication Channels* — Ingress must declare `spec.tls`. |
| CC6.8 | `chart/templates/soc2/soc2-cc6.8-approved-registries.yaml` | Drafted, untested — **placeholder registry list** | *Restricts Application and Software Installation* — images only from `soc2.approvedRegistries`. |
| CC6.8 | `chart/templates/soc2/soc2-cc6.8-readonly-root-filesystem.yaml` | Drafted, untested | *Restricts Software Installation* / *Detects Unauthorized Changes to Software* — `readOnlyRootFilesystem: true`. |
| CC6.8 | `chart/templates/soc2/soc2-cc6.8-require-seccomp.yaml` | Drafted, untested | Prevent malicious software — seccomp `RuntimeDefault`/`Localhost` at Pod or container level; `Unconfined` never allowed. |
| CC6.8 | `chart/templates/soc2/soc2-cc6.8-verify-image-signatures.yaml` | Drafted, untested — **disabled by default** | *Uses a Defined Change Control Process* for software — cosign signature verification (`verifyImages`, `mutateDigest: false`). `background: false` (registry call per image). Needs `soc2.imageVerification.publicKey`. |
| CC7.2 | `chart/templates/soc2/soc2-cc7.2-require-probes.yaml` | Drafted, untested | Monitors system components for anomalies — liveness + readiness probes on every container. |
| CC8.1 | `chart/templates/soc2/soc2-cc8.1-disallow-mutable-image-tags.yaml` | Drafted, untested | *Tracks System Changes* / *Creates Baseline Configuration* — explicit tag required, `:latest` disallowed. |
| CC8.1 | `chart/templates/soc2/soc2-cc8.1-restrict-direct-changes.yaml` | Drafted, untested — **disabled by default** | *Authorizes / Approves / Deploys Changes*, *Emergency Changes* — only `soc2.changeControl.allowedSubjects` (GitOps/CI identity + break-glass group) may CREATE/UPDATE/DELETE workloads, Services, Ingresses, NetworkPolicies, or `exec`/`attach` into Pods. `background: false` (decides on `request.userInfo`). Scope to prod namespaces. |
| A1.1 | `chart/templates/soc2/soc2-a1.1-require-resources.yaml` | Drafted, untested | Capacity management — CPU/memory requests and limits. *Optional category.* |
| A1.2 | `chart/templates/soc2/soc2-a1.2-require-replicas.yaml` | Drafted, untested | Recovery infrastructure — Deployments/StatefulSets run ≥ `soc2.minReplicas` (default 2). Noisy on a single-node lab; scope to prod. *Optional category.* |
| C1.1 | `chart/templates/soc2/soc2-c1.1-require-data-classification.yaml` | Drafted, untested | Identifies confidential information — Namespaces carry `data-classification` ∈ `soc2.dataClassificationValues`. *Optional category.* |

### Coverage of every criterion

All 61 criteria were reviewed. The rows below account for every criterion
not mapped above, and say where its evidence comes from instead. "Out of
admission scope" means the criterion is about an organizational process, a
physical control, or something Kubernetes never sends to an admission
webhook. It does not mean the criterion is unimportant.

| Criteria | Admission-checkable? | Where the evidence comes from instead |
|---|---|---|
| CC1.1–CC1.5 (control environment) | No: governance, ethics, board oversight, HR | Org policies, HR records |
| CC2.1–CC2.3 (communication & information) | No: internal/external communication | Policies, system description. Kyverno PolicyReports feed CC2.1 as "quality information" |
| CC3.1–CC3.4 (risk assessment) | No: risk process | Risk register |
| CC4.1–CC4.2 (monitoring activities) | Partly: the background scan *is* an ongoing evaluation (CC4.1) | Policy Reporter dashboard + `enforcement-promotion-log.md` as the deficiency-tracking trail (CC4.2) |
| CC5.1–CC5.3 (control activities) | No: meta-criteria about selecting controls | This document plus the chart itself (policy-as-code is the CC5.3 "policies put into action") |
| CC6.2 (user registration/deprovisioning) | No: Kubernetes has no user objects; humans come from OIDC/certs | IdP (OIDC) joiner/leaver process. kubeadm client certs can't be revoked, so auditors will ask about this. |
| CC6.4 (physical access) | No | Data-centre / cloud provider SOC 2 report (carve-out) |
| CC6.5 (disposal of physical assets) | No | Media sanitisation procedure |
| CC7.1 (detect config changes / vulnerabilities) | Mostly covered by the chart as a whole: "defined configuration standards" + "monitors for noncompliance" is exactly Kyverno background scanning | Vulnerability scanning of images (Trivy Operator / registry scanner) is **not** done by this chart and is required by CC7.1's point of focus. Also API-server audit logging. |
| CC7.2 (beyond probes) | No: anomaly detection needs runtime data | kube-apiserver audit log (`--audit-policy-file`, a control-plane flag, kube-bench territory) and runtime detection (Falco) |
| CC7.3–CC7.5 (incident evaluation, response, recovery) | No: process | IR runbook. Phase 2's remediation-as-PR agent produces CC7.4/CC7.5 evidence (remediation drafted, reviewed, merged) without touching the cluster. |
| CC8.1 (beyond the two policies) | No: PR review, testing, approval live in Git | Git history + PR approvals + reconciler sync log |
| CC9.1–CC9.2 (risk mitigation, vendors) | No | BCP, vendor reviews |
| A1.2 (backups) / A1.3 (recovery testing) | No: backup *schedules* and restore tests aren't objects a Pod admission sees | Velero schedules + restore-test records |
| C1.2 (disposal of confidential info) | No | Retention/deletion procedure |
| PI1.1–PI1.5 (processing integrity) | No: application-level input/processing/output correctness | Application controls |
| P1–P8 (privacy) | No: notice, consent, data-subject rights | Privacy program |

Known gaps a SOC 2 auditor would still expect for a Kubernetes system
that this chart does **not** close, and cannot close as an admission
controller: API-server audit logging, image vulnerability scanning, etcd
encryption of Secrets (`--encryption-provider-config`), and human identity
lifecycle. These belong to kube-bench / cluster-config evidence alongside
this chart.

## HIPAA

_Not started._
