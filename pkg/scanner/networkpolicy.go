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

	if policy.Spec.Ingress == nil || len(policy.Spec.Ingress) == 0 {
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
			if from.IPBlock == nil && len(from.NamespaceSelector.MatchLabels) == 0 && len(from.PodSelector.MatchLabels) == 0 {
				issues = append(issues, SecurityIssue{
					Severity:    "MEDIUM",
					Resource:    "NetworkPolicy",
					Namespace:   policy.Namespace,
					Name:        policy.Name,
					Description: "NetworkPolicy ingress rule allows traffic from all namespaces/pods",
				})
			}

			if from.IPBlock != nil && from.IPBlock.Except == nil {
				issues = append(issues, SecurityIssue{
					Severity:    "LOW",
					Resource:    "NetworkPolicy",
					Namespace:   policy.Namespace,
					Name:        policy.Name,
					Description: "NetworkPolicy ingress rule allows traffic from any IP block (CIDR)",
				})
			}
		}
	}
	return issues
}

func (s *NetworkPolicyScanner) checkEgressRules(policy *networkingv1.NetworkPolicy) []SecurityIssue {
	var issues []SecurityIssue

	if policy.Spec.Egress == nil || len(policy.Spec.Egress) == 0 {
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
			if to.IPBlock == nil && len(to.NamespaceSelector.MatchLabels) == 0 && len(to.PodSelector.MatchLabels) == 0 {
				issues = append(issues, SecurityIssue{
					Severity:    "MEDIUM",
					Resource:    "NetworkPolicy",
					Namespace:   policy.Namespace,
					Name:        policy.Name,
					Description: "NetworkPolicy egress rule allows traffic to all namespaces/pods",
				})
			}

			if to.IPBlock != nil && to.IPBlock.Except == nil {
				issues = append(issues, SecurityIssue{
					Severity:    "LOW",
					Resource:    "NetworkPolicy",
					Namespace:   policy.Namespace,
					Name:        policy.Name,
					Description: "NetworkPolicy egress rule allows traffic to any IP block (CIDR)",
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
		if pt == "Ingress" {
			hasIngress = true
		}
		if pt == "Egress" {
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
	hasAnyEgressPolicy := false

	for _, policy := range policies {
		if policy.Namespace != namespace {
			continue
		}

		policyTypeSet := policyTypes(&policy)

		if isDefaultDenyPolicy(&policy) {
			if policyTypeSet[networkingv1.PolicyTypeIngress] && len(policy.Spec.Ingress) == 0 {
				hasDefaultDenyIngress = true
			}
			if policyTypeSet[networkingv1.PolicyTypeEgress] && len(policy.Spec.Egress) == 0 {
				hasDefaultDenyEgress = true
			}
		}

		if policyTypeSet[networkingv1.PolicyTypeEgress] {
			hasAnyEgressPolicy = true
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

	if !hasAnyEgressPolicy {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Namespace",
			Namespace:   namespace,
			Name:        namespace,
			Description: "Namespace has no egress NetworkPolicies defined",
		})
	}

	return issues
}

func isDefaultDenyPolicy(policy *networkingv1.NetworkPolicy) bool {
	if len(policy.Spec.PodSelector.MatchLabels) == 0 && len(policy.Spec.PodSelector.MatchExpressions) == 0 {
		return true
	}

	return false
}

func policyTypes(policy *networkingv1.NetworkPolicy) map[networkingv1.PolicyType]bool {
	types := make(map[networkingv1.PolicyType]bool)
	if len(policy.Spec.PolicyTypes) > 0 {
		for _, policyType := range policy.Spec.PolicyTypes {
			types[policyType] = true
		}
		return types
	}

	if len(policy.Spec.Ingress) > 0 {
		types[networkingv1.PolicyTypeIngress] = true
	}
	if len(policy.Spec.Egress) > 0 {
		types[networkingv1.PolicyTypeEgress] = true
	}
	if len(types) == 0 {
		types[networkingv1.PolicyTypeIngress] = true
	}

	return types
}
