{{/*
Resolve whether a policy should be rendered: the framework must be enabled,
AND (if a per-policy override exists) that override's `enabled` must not be
false. Renders the literal string "true" or "false".

Usage:
  {{- $fw := .Values.compliance.frameworks.iso27001 }}
  {{- if eq (include "compliance.policyEnabled" (dict "framework" $fw "name" "iso-a8.2-no-privileged-nonroot")) "true" }}
  ...
  {{- end }}
*/}}
{{- define "compliance.policyEnabled" -}}
{{- $override := index .framework.policies .name | default dict -}}
{{- if hasKey $override "enabled" -}}
{{- and .framework.enabled $override.enabled -}}
{{- else -}}
{{- .framework.enabled -}}
{{- end -}}
{{- end -}}

{{/*
Resolve a policy's enforcement mode: a per-policy override wins, otherwise
the framework's default mode applies. Renders "audit" or "enforce" (matches
the compliance.mode annotation convention in CLAUDE.md); fails the render
with a clear error if the resolved value is anything else, so a typo in
values.yaml is caught at `helm template`/`helm install` time rather than
producing a ClusterPolicy Kyverno itself then rejects.

Usage:
  {{- $mode := include "compliance.policyMode" (dict "framework" $fw "name" "iso-a8.2-no-privileged-nonroot") }}
  failureAction: {{ $mode | lower | title }}   # "audit" -> "Audit"
*/}}
{{- define "compliance.policyMode" -}}
{{- $override := index .framework.policies .name | default dict -}}
{{- $mode := $override.mode | default .framework.mode -}}
{{- if not (has $mode (list "audit" "enforce")) -}}
{{- fail (printf "compliance: policy %q has mode %q, must be \"audit\" or \"enforce\"" .name $mode) -}}
{{- end -}}
{{- $mode -}}
{{- end -}}
