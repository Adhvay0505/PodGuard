package scanner

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

const (
	pssEnforceLabel        = "pod-security.kubernetes.io/enforce"
	pssEnforceVersionLabel = "pod-security.kubernetes.io/enforce-version"
	pssWarnLabel           = "pod-security.kubernetes.io/warn"
	pssAuditLabel          = "pod-security.kubernetes.io/audit"
)

type PodSecurityStandardsScanner struct{}

func NewPodSecurityStandardsScanner() *PodSecurityStandardsScanner {
	return &PodSecurityStandardsScanner{}
}

func (s *PodSecurityStandardsScanner) ScanNamespace(namespace *corev1.Namespace) []SecurityIssue {
	var issues []SecurityIssue

	labels := namespace.Labels
	if labels == nil {
		labels = map[string]string{}
	}

	enforce := labels[pssEnforceLabel]
	if enforce == "" {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Namespace",
			Namespace:   namespace.Name,
			Name:        namespace.Name,
			Description: "Namespace does not set pod security enforce level",
		})
	} else if enforce == "privileged" {
		issues = append(issues, SecurityIssue{
			Severity:    "HIGH",
			Resource:    "Namespace",
			Namespace:   namespace.Name,
			Name:        namespace.Name,
			Description: "Namespace enforces privileged pod security level",
		})
	}

	if labels[pssEnforceVersionLabel] == "" && enforce != "" {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Resource:    "Namespace",
			Namespace:   namespace.Name,
			Name:        namespace.Name,
			Description: fmt.Sprintf("Namespace enforce level '%s' does not set an enforce version", enforce),
		})
	}

	if labels[pssWarnLabel] == "" {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Resource:    "Namespace",
			Namespace:   namespace.Name,
			Name:        namespace.Name,
			Description: "Namespace does not set a pod security warn level",
		})
	}

	if labels[pssAuditLabel] == "" {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Resource:    "Namespace",
			Namespace:   namespace.Name,
			Name:        namespace.Name,
			Description: "Namespace does not set a pod security audit level",
		})
	}

	return issues
}
