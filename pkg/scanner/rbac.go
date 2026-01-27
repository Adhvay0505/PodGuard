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
	}

	return issues
}

func (s *RBACScanner) ScanRole(role *rbacv1.Role, namespace string) []SecurityIssue {
	var issues []SecurityIssue

	for _, rule := range role.Rules {
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
