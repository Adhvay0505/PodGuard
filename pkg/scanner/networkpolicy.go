package scanner

import (
	networkingv1 "k8s.io/api/networking/v1"
)

type NetworkPolicyScanner struct{}

func NewNetworkPolicyScanner() *NetworkPolicyScanner {
	return &NetworkPolicyScanner{}
}

func (s *NetworkPolicyScanner) ScanNetworkPolicy(policy *networkingv1.NetworkPolicy, namespace string) []SecurityIssue {
	var issues []SecurityIssue

	issues = append(issues, s.checkIngressRules(policy)...)
	issues = append(issues, s.checkEgressRules(policy)...)
	issues = append(issues, s.checkPolicyTypes(policy)...)

	return issues
}

func (s *NetworkPolicyScanner) checkIngressRules(policy *networkingv1.NetworkPolicy) []SecurityIssue {
	var issues []SecurityIssue

	if len(policy.Spec.Ingress) == 0 {
		return issues
	}

	for _, ingress := range policy.Spec.Ingress {
		if len(ingress.From) == 0 {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "NetworkPolicy",
				Namespace:   policy.Namespace,
				Name:        policy.Name,
				Description: "NetworkPolicy has ingress rule with no 'from' selector (allows all traffic)",
			})
			continue
		}

		for _, from := range ingress.From {
			if from.IPBlock == nil && from.NamespaceSelector == nil && from.PodSelector == nil {
				issues = append(issues, SecurityIssue{
					Severity:    "MEDIUM",
					Resource:    "NetworkPolicy",
					Namespace:   policy.Namespace,
					Name:        policy.Name,
					Description: "NetworkPolicy ingress rule allows traffic from all sources",
				})
			}
		}
	}
	return issues
}

func (s *NetworkPolicyScanner) checkEgressRules(policy *networkingv1.NetworkPolicy) []SecurityIssue {
	var issues []SecurityIssue

	if len(policy.Spec.Egress) == 0 {
		return issues
	}

	for _, egress := range policy.Spec.Egress {
		if len(egress.To) == 0 {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "NetworkPolicy",
				Namespace:   policy.Namespace,
				Name:        policy.Name,
				Description: "NetworkPolicy has egress rule with no 'to' selector (allows all traffic)",
			})
			continue
		}

		for _, to := range egress.To {
			if to.IPBlock == nil && to.NamespaceSelector == nil && to.PodSelector == nil {
				issues = append(issues, SecurityIssue{
					Severity:    "MEDIUM",
					Resource:    "NetworkPolicy",
					Namespace:   policy.Namespace,
					Name:        policy.Name,
					Description: "NetworkPolicy egress rule allows traffic to all destinations",
				})
			}
		}
	}

	return issues
}

func (s *NetworkPolicyScanner) checkPolicyTypes(policy *networkingv1.NetworkPolicy) []SecurityIssue {
	var issues []SecurityIssue

	hasIngress := false
	hasEgress := false

	for _, pt := range policy.Spec.PolicyTypes {
		if pt == networkingv1.PolicyTypeIngress {
			hasIngress = true
		}
		if pt == networkingv1.PolicyTypeEgress {
			hasEgress = true
		}
	}

	if !hasIngress && !hasEgress {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Resource:    "NetworkPolicy",
			Namespace:   policy.Namespace,
			Name:        policy.Name,
			Description: "NetworkPolicy has no explicit policyTypes defined",
		})
	}

	return issues
}

type NamespaceScanner struct{}

func NewNamespaceScanner() *NamespaceScanner {
	return &NamespaceScanner{}
}

func (s *NamespaceScanner) ScanNamespace(namespace string, policies []networkingv1.NetworkPolicy) []SecurityIssue {
	var issues []SecurityIssue

	hasDefaultDenyIngress := false
	hasDefaultDenyEgress := false

	for _, policy := range policies {
		if policy.Namespace != namespace {
			continue
		}

		if isDefaultDenyPolicy(&policy) {
			for _, pt := range policy.Spec.PolicyTypes {
				if pt == networkingv1.PolicyTypeIngress && len(policy.Spec.Ingress) == 0 {
					hasDefaultDenyIngress = true
				}
				if pt == networkingv1.PolicyTypeEgress && len(policy.Spec.Egress) == 0 {
					hasDefaultDenyEgress = true
				}
			}
		}
	}

	if !hasDefaultDenyIngress {
		issues = append(issues, SecurityIssue{
			Severity:    "HIGH",
			Resource:    "Namespace",
			Namespace:   namespace,
			Name:        namespace,
			Description: "Namespace lacks a default deny ingress NetworkPolicy",
		})
	}

	if !hasDefaultDenyEgress {
		issues = append(issues, SecurityIssue{
			Severity:    "HIGH",
			Resource:    "Namespace",
			Namespace:   namespace,
			Name:        namespace,
			Description: "Namespace lacks a default deny egress NetworkPolicy",
		})
	}

	return issues
}

func isDefaultDenyPolicy(policy *networkingv1.NetworkPolicy) bool {
	return len(policy.Spec.PodSelector.MatchLabels) == 0 && len(policy.Spec.PodSelector.MatchExpressions) == 0
}
