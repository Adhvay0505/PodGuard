package scanner

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
)

type PodSecurityStandardsScanner struct{}

func NewPodSecurityStandardsScanner() *PodSecurityStandardsScanner {
	return &PodSecurityStandardsScanner{}
}

func (s *PodSecurityStandardsScanner) ScanNamespace(ns *corev1.Namespace) []SecurityIssue {
	var issues []SecurityIssue

	pssEnforce := ns.Labels["pod-security.kubernetes.io/enforce"]
	pssAudit := ns.Labels["pod-security.kubernetes.io/audit"]
	pssWarn := ns.Labels["pod-security.kubernetes.io/warn"]

	if pssEnforce == "" {
		issues = append(issues, SecurityIssue{
			Severity:    "HIGH",
			Resource:    "Namespace",
			Namespace:   ns.Name,
			Name:        ns.Name,
			Description: "Namespace has no pod security enforce label - pods may run with elevated privileges",
		})
	} else if pssEnforce != "restricted" {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Namespace",
			Namespace:   ns.Name,
			Name:        ns.Name,
			Description: "Namespace enforce level is '" + pssEnforce + "' - consider using 'restricted'",
		})
	}

	if pssAudit == "" {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Resource:    "Namespace",
			Namespace:   ns.Name,
			Name:        ns.Name,
			Description: "Namespace has no pod security audit label",
		})
	}

	if pssWarn == "" {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Resource:    "Namespace",
			Namespace:   ns.Name,
			Name:        ns.Name,
			Description: "Namespace has no pod security warn label",
		})
	}

	restrictedLabels := []string{
		"pod-security.kubernetes.io/enforce",
		"pod-security.kubernetes.io/audit",
		"pod-security.kubernetes.io/warn",
	}

	for _, label := range restrictedLabels {
		if val, ok := ns.Labels[label]; ok {
			if val == "privileged" {
				issues = append(issues, SecurityIssue{
					Severity:    "HIGH",
					Resource:    "Namespace",
					Namespace:   ns.Name,
					Name:        ns.Name,
					Description: "Namespace has privileged " + label + " label",
				})
			}
		}
	}

	return issues
}

func containsPrefix(slice []string, prefix string) bool {
	for _, s := range slice {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}
