package scanner

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

type ServiceScanner struct{}

func NewServiceScanner() *ServiceScanner {
	return &ServiceScanner{}
}

func (s *ServiceScanner) ScanService(service *corev1.Service) []SecurityIssue {
	var issues []SecurityIssue

	switch service.Spec.Type {
	case corev1.ServiceTypeNodePort:
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Service",
			Namespace:   service.Namespace,
			Name:        service.Name,
			Description: "Service exposes a NodePort",
		})
	case corev1.ServiceTypeLoadBalancer:
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Service",
			Namespace:   service.Namespace,
			Name:        service.Name,
			Description: "Service is exposed via LoadBalancer",
		})
		if len(service.Spec.LoadBalancerSourceRanges) == 0 {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "Service",
				Namespace:   service.Namespace,
				Name:        service.Name,
				Description: "LoadBalancer service does not restrict source ranges",
			})
		}
	case corev1.ServiceTypeExternalName:
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Resource:    "Service",
			Namespace:   service.Namespace,
			Name:        service.Name,
			Description: fmt.Sprintf("Service uses ExternalName to resolve %s", service.Spec.ExternalName),
		})
	}

	if len(service.Spec.ExternalIPs) > 0 {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Service",
			Namespace:   service.Namespace,
			Name:        service.Name,
			Description: fmt.Sprintf("Service exposes external IPs: %v", service.Spec.ExternalIPs),
		})
	}

	return issues
}
