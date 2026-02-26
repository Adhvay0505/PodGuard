# PodGuard
A simple Kubernetes security scanning tool written in Go.

## Features

- **Pod Security Scanning**: Detects risky pod and container settings
  - Privileged containers and privilege escalation
  - Root user execution and missing `runAsNonRoot`
  - Writable root filesystem and missing `readOnlyRootFilesystem`
  - Missing or unconfined seccomp profiles
  - Host network/PID/IPC namespace sharing
  - Shared process namespaces and unmasked `/proc`
  - Host ports and sensitive host path mounts
  - Service account token automounting and default service account usage
  - Mutable image tags (`:latest` or no tag)
  - Hardcoded secrets in environment variables
  - Missing `capabilities.drop: ["ALL"]`

- **RBAC Security Scanning**: Identifies dangerous RBAC permissions
  - Wildcard verbs/resources/API groups
  - Role escalation, bind, and impersonation verbs
  - Secret read access
  - Pod exec/port-forward and workload mutation

- **NetworkPolicy Scanning**: Flags risky or missing network policies
  - Missing default-deny ingress/egress per namespace
  - Overly permissive ingress/egress rules

- **Ingress Scanning**: Highlights TLS gaps and backend misconfigurations

- **Service Exposure Scanning**: Flags NodePort/LoadBalancer exposure and external IPs

- **Pod Security Standards (PSS)**: Checks namespace PSS label coverage

- **Secrets Exposure Scanning**: Detects secret leaks via env vars and ConfigMaps

- **Resource Hygiene Scanning**: Highlights missing resource requests/limits

- **ServiceAccount Scanning**: Finds service accounts that auto-mount tokens

## Installation

```bash
go build -o podguard ./cmd/podguard
```

## Usage

```bash
# Scan all namespaces for all security issues
./podguard

# Scan specific namespace
./podguard -namespace default

# Scan only pods
./podguard -type pods

# Scan only RBAC
./podguard -type rbac

# Output in JSON format
./podguard -output json

# Output to Markdown file
./podguard -output markdown -output-file report.md

# Use custom kubeconfig
./podguard -kubeconfig ~/.kube/config
```

## Command Line Options

- `-kubeconfig`: Path to kubeconfig file (default: uses in-cluster config or ~/.kube/config)
- `-namespace`: Namespace to scan (default: all namespaces)
- `-output`: Output format (table, json, markdown) (default: table)
- `-output-file`: Write output to a file (optional)
- `-type`: Scan type (pods, rbac, network, resources, serviceaccounts, services, ingress, pss, secrets, all) (default: all)

## Security Checks

### Pod Security
- **HIGH**: Privileged containers, privilege escalation, unconfined seccomp, host PID sharing, shared process namespaces, unmasked `/proc`, sensitive host path mounts, hardcoded secret env vars
- **MEDIUM**: Root user execution, host network/IPC sharing, missing seccomp, host ports, token automounting, mutable tags, missing capability drops
- **LOW**: Writable root filesystem, missing readOnlyRootFilesystem, default service account usage, missing runAsNonRoot

### RBAC Security
- **HIGH**: Wildcard verbs/resources, escalation/bind/impersonate, secret read, pod exec
- **MEDIUM**: Wildcard API groups, pod port-forward, workload mutation

### NetworkPolicy Security
- **HIGH**: Namespace missing default deny ingress/egress
- **MEDIUM**: Namespace missing egress policies, overly permissive rules

### Ingress Security
- **MEDIUM**: Missing TLS or TLS secret name
- **LOW**: Backend port not specified

### Service Exposure Security
- **MEDIUM**: NodePort/LoadBalancer exposure, external IPs, missing LB source ranges

### Pod Security Standards
- **HIGH**: Enforced `privileged` policy
- **MEDIUM**: Missing enforce label
- **LOW**: Missing warn/audit/enforce version labels

### Secrets Exposure
- **HIGH**: Plaintext secrets in ConfigMaps
- **MEDIUM**: Secrets injected via environment variables
- **LOW**: Mutable secrets without `immutable: true`

### ServiceAccount Security
- **MEDIUM**: Default service account auto-mounts token
- **LOW**: Non-default service account auto-mounts token

## Example Output

```
Found 3 security issues:

HIGH SEVERITY:
=========
Resource: Pod/nginx-deployment
Namespace: default
Issue: Container 'nginx' is running in privileged mode

Resource: Pod/privileged-pod
Namespace: kube-system
Issue: Pod is sharing host process ID namespace

MEDIUM SEVERITY:
=============
Resource: Pod/web-app
Namespace: production
Issue: Container 'app' is running as root user
```
