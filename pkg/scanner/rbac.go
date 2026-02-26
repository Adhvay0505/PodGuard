package scanner

import (
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
)

type RBACScanner struct{}

func NewRBACScanner() *RBACScanner {
	return &RBACScanner{}
}

func (s *RBACScanner) ScanClusterRole(role *rbacv1.ClusterRole) []SecurityIssue {
	var issues []SecurityIssue

	for _, rule := range role.Rules {
		if contains(rule.Verbs, "escalate") {
			issues = append(issues, SecurityIssue{
				Severity:    "HIGH",
				Resource:    "ClusterRole",
				Namespace:   "",
				Name:        role.Name,
				Description: fmt.Sprintf("ClusterRole '%s' allows role escalation (verb: escalate)", role.Name),
			})
		}

		if contains(rule.Verbs, "impersonate") {
			issues = append(issues, SecurityIssue{
				Severity:    "HIGH",
				Resource:    "ClusterRole",
				Namespace:   "",
				Name:        role.Name,
				Description: fmt.Sprintf("ClusterRole '%s' allows impersonation (verb: impersonate)", role.Name),
			})
		}

		if contains(rule.Verbs, "bind") && contains(rule.Resources, "clusterroles") {
			issues = append(issues, SecurityIssue{
				Severity:    "HIGH",
				Resource:    "ClusterRole",
				Namespace:   "",
				Name:        role.Name,
				Description: fmt.Sprintf("ClusterRole '%s' can bind clusterroles", role.Name),
			})
		}

		if contains(rule.Verbs, "*") {
			issues = append(issues, SecurityIssue{
				Severity:    "HIGH",
				Resource:    "ClusterRole",
				Namespace:   "",
				Name:        role.Name,
				Description: fmt.Sprintf("ClusterRole '%s' has wildcard verbs (*)", role.Name),
			})
		}

		if contains(rule.Resources, "*") {
			issues = append(issues, SecurityIssue{
				Severity:    "HIGH",
				Resource:    "ClusterRole",
				Namespace:   "",
				Name:        role.Name,
				Description: fmt.Sprintf("ClusterRole '%s' has wildcard resources (*)", role.Name),
			})
		}

		if contains(rule.APIGroups, "*") {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "ClusterRole",
				Namespace:   "",
				Name:        role.Name,
				Description: fmt.Sprintf("ClusterRole '%s' has wildcard API groups (*)", role.Name),
			})
		}

		if contains(rule.Resources, "secrets") && (contains(rule.Verbs, "*") || containsAny(rule.Verbs, []string{"get", "list", "watch"})) {
			issues = append(issues, SecurityIssue{
				Severity:    "HIGH",
				Resource:    "ClusterRole",
				Namespace:   "",
				Name:        role.Name,
				Description: fmt.Sprintf("ClusterRole '%s' can read secrets", role.Name),
			})
		}

		if contains(rule.Resources, "pods/exec") && (contains(rule.Verbs, "*") || contains(rule.Verbs, "create")) {
			issues = append(issues, SecurityIssue{
				Severity:    "HIGH",
				Resource:    "ClusterRole",
				Namespace:   "",
				Name:        role.Name,
				Description: fmt.Sprintf("ClusterRole '%s' can exec into pods", role.Name),
			})
		}

		if contains(rule.Resources, "pods/portforward") && (contains(rule.Verbs, "*") || contains(rule.Verbs, "create")) {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "ClusterRole",
				Namespace:   "",
				Name:        role.Name,
				Description: fmt.Sprintf("ClusterRole '%s' can port-forward to pods", role.Name),
			})
		}

		if contains(rule.Resources, "pods") && (contains(rule.Verbs, "*") || containsAny(rule.Verbs, []string{"create", "update", "patch"})) {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "ClusterRole",
				Namespace:   "",
				Name:        role.Name,
				Description: fmt.Sprintf("ClusterRole '%s' can modify pods", role.Name),
			})
		}

		if contains(rule.Resources, "deployments") && (contains(rule.Verbs, "*") || containsAny(rule.Verbs, []string{"create", "update", "patch"})) {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "ClusterRole",
				Namespace:   "",
				Name:        role.Name,
				Description: fmt.Sprintf("ClusterRole '%s' can modify deployments", role.Name),
			})
		}
	}

	return issues
}

func (s *RBACScanner) ScanRole(role *rbacv1.Role, namespace string) []SecurityIssue {
	var issues []SecurityIssue

	for _, rule := range role.Rules {
		if contains(rule.Verbs, "escalate") {
			issues = append(issues, SecurityIssue{
				Severity:    "HIGH",
				Resource:    "Role",
				Namespace:   namespace,
				Name:        role.Name,
				Description: fmt.Sprintf("Role '%s' allows role escalation (verb: escalate)", role.Name),
			})
		}

		if contains(rule.Verbs, "impersonate") {
			issues = append(issues, SecurityIssue{
				Severity:    "HIGH",
				Resource:    "Role",
				Namespace:   namespace,
				Name:        role.Name,
				Description: fmt.Sprintf("Role '%s' allows impersonation (verb: impersonate)", role.Name),
			})
		}

		if contains(rule.Verbs, "bind") && contains(rule.Resources, "roles") {
			issues = append(issues, SecurityIssue{
				Severity:    "HIGH",
				Resource:    "Role",
				Namespace:   namespace,
				Name:        role.Name,
				Description: fmt.Sprintf("Role '%s' can bind roles", role.Name),
			})
		}

		if contains(rule.Verbs, "*") {
			issues = append(issues, SecurityIssue{
				Severity:    "HIGH",
				Resource:    "Role",
				Namespace:   namespace,
				Name:        role.Name,
				Description: fmt.Sprintf("Role '%s' has wildcard verbs (*)", role.Name),
			})
		}

		if contains(rule.Resources, "*") {
			issues = append(issues, SecurityIssue{
				Severity:    "HIGH",
				Resource:    "Role",
				Namespace:   namespace,
				Name:        role.Name,
				Description: fmt.Sprintf("Role '%s' has wildcard resources (*)", role.Name),
			})
		}

		if contains(rule.Resources, "secrets") && (contains(rule.Verbs, "*") || containsAny(rule.Verbs, []string{"get", "list", "watch"})) {
			issues = append(issues, SecurityIssue{
				Severity:    "HIGH",
				Resource:    "Role",
				Namespace:   namespace,
				Name:        role.Name,
				Description: fmt.Sprintf("Role '%s' can read secrets", role.Name),
			})
		}

		if contains(rule.Resources, "pods/exec") && (contains(rule.Verbs, "*") || contains(rule.Verbs, "create")) {
			issues = append(issues, SecurityIssue{
				Severity:    "HIGH",
				Resource:    "Role",
				Namespace:   namespace,
				Name:        role.Name,
				Description: fmt.Sprintf("Role '%s' can exec into pods", role.Name),
			})
		}

		if contains(rule.Resources, "pods/portforward") && (contains(rule.Verbs, "*") || contains(rule.Verbs, "create")) {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "Role",
				Namespace:   namespace,
				Name:        role.Name,
				Description: fmt.Sprintf("Role '%s' can port-forward to pods", role.Name),
			})
		}

		if contains(rule.Resources, "pods") && (contains(rule.Verbs, "*") || containsAny(rule.Verbs, []string{"create", "update", "patch"})) {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "Role",
				Namespace:   namespace,
				Name:        role.Name,
				Description: fmt.Sprintf("Role '%s' can modify pods", role.Name),
			})
		}

		if contains(rule.Resources, "deployments") && (contains(rule.Verbs, "*") || containsAny(rule.Verbs, []string{"create", "update", "patch"})) {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "Role",
				Namespace:   namespace,
				Name:        role.Name,
				Description: fmt.Sprintf("Role '%s' can modify deployments", role.Name),
			})
		}
	}

	return issues
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsAny(slice []string, items []string) bool {
	for _, item := range items {
		if contains(slice, item) {
			return true
		}
	}
	return false
}
