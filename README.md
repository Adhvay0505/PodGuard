# PodGuard
A simple Kubernetes security scanning tool written in Go.

## Features

- **Pod Security Scanning**: Detects common pod security issues
  - Privileged containers
  - Root user execution
  - Writable root filesystem
  - Host network/PID/IPC namespace sharing
  - Sensitive host path mounts

- **RBAC Security Scanning**: Identifies risky RBAC configurations
  - Wildcard verbs (*)
  - Wildcard resources (*)
  - Wildcard API groups (*)

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

# Use custom kubeconfig
./podguard -kubeconfig ~/.kube/config
```

## Command Line Options

- `-kubeconfig`: Path to kubeconfig file (default: uses in-cluster config or ~/.kube/config)
- `-namespace`: Namespace to scan (default: all namespaces)
- `-output`: Output format (table, json) (default: table)
- `-type`: Scan type (pods, rbac, all) (default: all)

## Security Checks

### Pod Security
- **HIGH**: Privileged containers, host PID sharing, sensitive host path mounts
- **MEDIUM**: Root user execution, host network/IPC sharing
- **LOW**: Writable root filesystem

### RBAC Security
- **HIGH**: Wildcard verbs or resources in roles
- **MEDIUM**: Wildcard API groups in cluster roles

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
