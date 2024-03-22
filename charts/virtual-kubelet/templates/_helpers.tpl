{{/* vim: set filetype=mustache: */}}

{{/*
Standard labels for helm resources
*/}}
{{- define "vk.labels" -}}
labels:
  heritage: "{{ .Release.Service }}"
  release: "{{ .Release.Name }}"
  revision: "{{ .Release.Revision }}"
  chart: "{{ .Chart.Name }}"
  chartVersion: "{{ .Chart.Version }}"
  app: {{ .Values.name }}
{{- end -}}
