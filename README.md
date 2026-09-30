# Kubernetes Compliance Controller

Admission-time compliance for Kubernetes: compliance controls (ISO 27001, CIS Kubernetes Benchmark, SOC 2) written as [Kyverno](https://kyverno.io) policies, packaged as one Helm chart, and surfaced in the [Policy Reporter](https://kyverno.github.io/policy-reporter/) dashboard.

Every policy starts in **Audit** (report only). You promote policies to **Enforce** (reject at admission) one at a time, once you've seen what they would break.

## What's in the box

| Framework | Policies | Scope | Default |
|---|---|---|---|
| ISO/IEC 27001:2022 | 14 (11 controls) | The Annex A controls that can be checked on Kubernetes objects | enabled, Audit |
| CIS Kubernetes Benchmark v2.0.x | 17 | Section 5 ("Policies") only | disabled |
| SOC 2 (AICPA TSC 2017, rev. 2022) | 25 (10 criteria) | Criteria that can be checked at admission time | disabled |
| HIPAA | not started | | |

Every policy carries annotations linking it back to its framework, control ID and control text. [docs/control-mappings.md](docs/control-mappings.md) is the human-readable index, including why each unmapped control can't be checked at admission time.

> **Status:** policies are hand-written and render as Helm templates, but have **not yet been tested against a live cluster**. Treat this as a reference implementation, not a certified control set. CIS numbering follows v2.0.x, cross-checked against kube-bench's `cis-2.0` config and not yet against the CIS PDF.

## How it works

1. **Install** the chart. It brings in Kyverno and Policy Reporter as subcharts.
2. **Choose** which frameworks (and individual policies) are active in `values.yaml`.
3. **Background scan** evaluates resources that already exist in the cluster against the new policies. No redeploy of your workloads is needed.
4. **Review** the findings in the Policy Reporter UI (it reads Kyverno's `PolicyReport` / `ClusterPolicyReport` resources).
5. **Fix or except** each finding: fix the workload, or add a `PolicyException` where the deviation is intentional.
6. **Promote** a policy to `Enforce`, per framework or per policy, and optionally per namespace, once its findings are clean. Record the decision in [docs/enforcement-promotion-log.md](docs/enforcement-promotion-log.md).
7. From then on, new non-compliant workloads are rejected at admission.

Audit versus Enforce, which frameworks are on, and which namespaces are in scope are all set from `values.yaml` (or `--set` at install time). You never edit a policy body to change its mode.

## Prerequisites

**Cluster**
- A running Kubernetes cluster. Developed against an on-prem kubeadm cluster; any conformant cluster should work.
- Admin access (`cluster-admin`) to install CRDs, webhooks and cluster-wide policies.
- Enough headroom for Kyverno's controllers. The default install is single-replica, not HA, which is fine for a lab or demo. Use multiple replicas for production.

**Tooling**
- `kubectl`, configured for the target cluster
- Helm 3
- Network access to the Kyverno and Policy Reporter chart repositories, or an internal mirror

**Versions**
- Kyverno **1.13 or newer** (Helm chart 3.3 or newer). The policies use per-rule `validate.failureAction`.

**Know before you enable**
- Kyverno needs RBAC to **read StorageClasses and NetworkPolicies** for the policies that look up other objects (`apiCall`), such as the storage encryption and require-NetworkPolicy checks.
- **Replace the placeholder registry list** in the approved-registries policy (`compliance.frameworks.iso27001.approvedRegistries`) with your own before promoting it to Enforce.
- Two SOC 2 policies are off by default because they need real values: image signature verification (a public key) and change control (allowed subjects).
- System namespaces (`kube-system` and similar) and third-party operators will show up as violations. Decide up front whether to scope them out or write exceptions.

**Access to the dashboard**
- A way to reach the Policy Reporter UI, for example `kubectl port-forward` or an Ingress.

## Repository layout

```
chart/                     Helm chart: Kyverno + Policy Reporter + all policies
  values.yaml              framework/policy toggles, mode, namespaces
  templates/{iso27001,cis,soc2}/   one ClusterPolicy template per policy
docs/
  control-mappings.md      control -> policy -> rationale
  enforcement-promotion-log.md
demo/                      a deliberately non-compliant Pod for the demo loop
```

## Scope and limits

- **Admission-time only.** Kyverno sees Kubernetes API objects, not node or control-plane process configuration. For CIS Benchmark Sections 1-4 (control plane, etcd, kubelet) use [kube-bench](https://github.com/aquasecurity/kube-bench).
- Most compliance controls are organizational or procedural and have no Kubernetes mapping. This project covers the subset that does.
- Policies support a compliance program. They are not a compliance certification.

## Roadmap

An AI layer is planned as Phase 2, with a hard boundary: **AI never changes a policy's enforcement mode and never modifies a live cluster resource.** Those actions stay deterministic and human-gated.

1. Draft a `ClusterPolicy` from raw control text, with a human reviewing before commit.
2. Draft remediation as a pull request against the source repo. The agent never writes to the cluster.

## License

Not yet specified. Add one before publishing.
