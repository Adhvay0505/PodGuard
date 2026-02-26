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
	issues = append(issues, s.checkAnnotations(ingress)...)

	return issues
}

func (s *IngressScanner) checkTLS(ingress *networkingv1.Ingress) []SecurityIssue {
	var issues []SecurityIssue

	if len(ingress.Spec.TLS) == 0 {
		issues = append(issues, SecurityIssue{
			Severity:    "HIGH",
			Resource:    "Ingress",
			Namespace:   ingress.Namespace,
			Name:        ingress.Name,
			Description: "Ingress does not use TLS (uses plain HTTP)",
		})
		return issues
	}

	for _, tls := range ingress.Spec.TLS {
		if len(tls.SecretName) == 0 {
			issues = append(issues, SecurityIssue{
				Severity:    "HIGH",
				Resource:    "Ingress",
				Namespace:   ingress.Namespace,
				Name:        ingress.Name,
				Description: "Ingress TLS configuration has no secret name specified",
			})
		}
	}

	return issues
}

func (s *IngressScanner) checkAnnotations(ingress *networkingv1.Ingress) []SecurityIssue {
	var issues []SecurityIssue

	annotations := ingress.GetAnnotations()

	if annotations == nil {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Resource:    "Ingress",
			Namespace:   ingress.Namespace,
			Name:        ingress.Name,
			Description: "Ingress has no annotations defined",
		})
		return issues
	}

	allowedHosts := annotations["kubernetes.io/ingress.allow-http"]
	if allowedHosts == "true" {
		issues = append(issues, SecurityIssue{
			Severity:    "HIGH",
			Resource:    "Ingress",
			Namespace:   ingress.Namespace,
			Name:        ingress.Name,
			Description: "Ingress explicitly allows HTTP traffic",
		})
	}

	return issues
}
