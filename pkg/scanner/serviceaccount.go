package scanner

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

type ServiceAccountScanner struct{}

func NewServiceAccountScanner() *ServiceAccountScanner {
	return &ServiceAccountScanner{}
}

func (s *ServiceAccountScanner) ScanServiceAccount(sa *corev1.ServiceAccount) []SecurityIssue {
	var issues []SecurityIssue

	automount := sa.AutomountServiceAccountToken
	if automount == nil || *automount {
		severity := "LOW"
		if sa.Name == "default" {
			severity = "MEDIUM"
		}
		issues = append(issues, SecurityIssue{
			Severity:    severity,
			Resource:    "ServiceAccount",
			Namespace:   sa.Namespace,
			Name:        sa.Name,
			Description: fmt.Sprintf("ServiceAccount '%s' is automounting the service account token", sa.Name),
		})
	}

	return issues
}
