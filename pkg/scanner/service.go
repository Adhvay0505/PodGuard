package scanner

import (
	corev1 "k8s.io/api/core/v1"
)

type ServiceScanner struct{}

func NewServiceScanner() *ServiceScanner {
	return &ServiceScanner{}
}

func (s *ServiceScanner) ScanService(service *corev1.Service) []SecurityIssue {
	var issues []SecurityIssue

	if service.Spec.Type == corev1.ServiceTypeNodePort {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Service",
			Namespace:   service.Namespace,
			Name:        service.Name,
			Description: "Service uses NodePort - exposes service on all nodes",
		})
	}

	if service.Spec.Type == corev1.ServiceTypeLoadBalancer {
		issues = append(issues, SecurityIssue{
			Severity:    "HIGH",
			Resource:    "Service",
			Namespace:   service.Namespace,
			Name:        service.Name,
			Description: "Service uses LoadBalancer - may expose to public internet",
		})
	}

	if service.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyTypeCluster {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Resource:    "Service",
			Namespace:   service.Namespace,
			Name:        service.Name,
			Description: "Service uses cluster-wide external traffic policy",
		})
	}

	if service.Spec.SessionAffinity == corev1.ServiceAffinityClientIP {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Resource:    "Service",
			Namespace:   service.Namespace,
			Name:        service.Name,
			Description: "Service uses ClientIP session affinity",
		})
	}

	return issues
}
