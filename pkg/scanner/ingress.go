package scanner

import (
	networkingv1 "k8s.io/api/networking/v1"
)

type IngressScanner struct{}

func NewIngressScanner() *IngressScanner {
	return &IngressScanner{}
}

func (s *IngressScanner) ScanIngress(ingress *networkingv1.Ingress) []SecurityIssue {
	var issues []SecurityIssue

	issues = append(issues, s.checkTLS(ingress)...)
	issues = append(issues, s.checkBackendPorts(ingress)...)

	return issues
}

func (s *IngressScanner) checkTLS(ingress *networkingv1.Ingress) []SecurityIssue {
	var issues []SecurityIssue

	if len(ingress.Spec.TLS) == 0 {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Ingress",
			Namespace:   ingress.Namespace,
			Name:        ingress.Name,
			Description: "Ingress does not configure TLS",
		})
		return issues
	}

	for _, tls := range ingress.Spec.TLS {
		if tls.SecretName == "" {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "Ingress",
				Namespace:   ingress.Namespace,
				Name:        ingress.Name,
				Description: "Ingress TLS configuration has no secret name specified",
			})
		}
	}

	return issues
}

func (s *IngressScanner) checkBackendPorts(ingress *networkingv1.Ingress) []SecurityIssue {
	var issues []SecurityIssue

	if ingress.Spec.DefaultBackend != nil && ingress.Spec.DefaultBackend.Service != nil {
		if ingress.Spec.DefaultBackend.Service.Port.Name == "" && ingress.Spec.DefaultBackend.Service.Port.Number == 0 {
			issues = append(issues, SecurityIssue{
				Severity:    "LOW",
				Resource:    "Ingress",
				Namespace:   ingress.Namespace,
				Name:        ingress.Name,
				Description: "Ingress default backend does not specify a service port",
			})
		}
	}

	for _, rule := range ingress.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service == nil {
				continue
			}
			if path.Backend.Service.Port.Name == "" && path.Backend.Service.Port.Number == 0 {
				issues = append(issues, SecurityIssue{
					Severity:    "LOW",
					Resource:    "Ingress",
					Namespace:   ingress.Namespace,
					Name:        ingress.Name,
					Description: "Ingress backend service does not specify a port",
				})
				return issues
			}
		}
	}

	return issues
}
