package scanner

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

type ResourceQuotaScanner struct{}

func NewResourceQuotaScanner() *ResourceQuotaScanner {
	return &ResourceQuotaScanner{}
}

func (s *ResourceQuotaScanner) ScanResourceQuota(rq *corev1.ResourceQuota, namespace string) []SecurityIssue {
	var issues []SecurityIssue

	if rq.Spec.Hard == nil || len(rq.Spec.Hard) == 0 {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "ResourceQuota",
			Namespace:   namespace,
			Name:        rq.Name,
			Description: "ResourceQuota has no hard limits defined",
		})
	}

	requestsCPU := rq.Spec.Hard[corev1.ResourceRequestsCPU]
	limitsCPU := rq.Spec.Hard[corev1.ResourceLimitsCPU]
	if requestsCPU.IsZero() && limitsCPU.IsZero() {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "ResourceQuota",
			Namespace:   namespace,
			Name:        rq.Name,
			Description: "ResourceQuota does not set CPU limits",
		})
	}

	requestsMemory := rq.Spec.Hard[corev1.ResourceRequestsMemory]
	limitsMemory := rq.Spec.Hard[corev1.ResourceLimitsMemory]
	if requestsMemory.IsZero() && limitsMemory.IsZero() {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "ResourceQuota",
			Namespace:   namespace,
			Name:        rq.Name,
			Description: "ResourceQuota does not set memory limits",
		})
	}

	pods := rq.Spec.Hard[corev1.ResourcePods]
	if pods.IsZero() {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "ResourceQuota",
			Namespace:   namespace,
			Name:        rq.Name,
			Description: "ResourceQuota does not limit number of pods",
		})
	}

	return issues
}

type LimitRangeScanner struct{}

func NewLimitRangeScanner() *LimitRangeScanner {
	return &LimitRangeScanner{}
}

func (s *LimitRangeScanner) ScanLimitRange(lr *corev1.LimitRange, namespace string) []SecurityIssue {
	var issues []SecurityIssue

	if lr.Spec.Limits == nil || len(lr.Spec.Limits) == 0 {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "LimitRange",
			Namespace:   namespace,
			Name:        lr.Name,
			Description: "LimitRange has no limits defined",
		})
		return issues
	}

	for _, limit := range lr.Spec.Limits {
		if limit.Default == nil {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "LimitRange",
				Namespace:   namespace,
				Name:        lr.Name,
				Description: fmt.Sprintf("LimitRange for %s has no default limits", limit.Type),
			})
		}

		if limit.DefaultRequest == nil {
			issues = append(issues, SecurityIssue{
				Severity:    "LOW",
				Resource:    "LimitRange",
				Namespace:   namespace,
				Name:        lr.Name,
				Description: fmt.Sprintf("LimitRange for %s has no default request", limit.Type),
			})
		}
	}

	return issues
}

type NamespaceQuotaScanner struct{}

func NewNamespaceQuotaScanner() *NamespaceQuotaScanner {
	return &NamespaceQuotaScanner{}
}

func (s *NamespaceQuotaScanner) ScanNamespace(namespace string, quotas []corev1.ResourceQuota, limitRanges []corev1.LimitRange) []SecurityIssue {
	var issues []SecurityIssue

	if len(quotas) == 0 {
		issues = append(issues, SecurityIssue{
			Severity:    "HIGH",
			Resource:    "Namespace",
			Namespace:   namespace,
			Name:        namespace,
			Description: "Namespace has no ResourceQuota - resources are unbounded",
		})
	}

	if len(limitRanges) == 0 {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Namespace",
			Namespace:   namespace,
			Name:        namespace,
			Description: "Namespace has no LimitRange - pods may run without defaults",
		})
	}

	hasCPUQuota := false
	hasMemoryQuota := false
	hasPodQuota := false

	for _, q := range quotas {
		cpuReq := q.Spec.Hard[corev1.ResourceRequestsCPU]
		cpuLim := q.Spec.Hard[corev1.ResourceLimitsCPU]
		memReq := q.Spec.Hard[corev1.ResourceRequestsMemory]
		memLim := q.Spec.Hard[corev1.ResourceLimitsMemory]
		pods := q.Spec.Hard[corev1.ResourcePods]

		if !cpuReq.IsZero() || !cpuLim.IsZero() {
			hasCPUQuota = true
		}
		if !memReq.IsZero() || !memLim.IsZero() {
			hasMemoryQuota = true
		}
		if !pods.IsZero() {
			hasPodQuota = true
		}
	}

	if !hasCPUQuota {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Namespace",
			Namespace:   namespace,
			Name:        namespace,
			Description: "Namespace has no CPU quota - CPU is unbounded",
		})
	}

	if !hasMemoryQuota {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Namespace",
			Namespace:   namespace,
			Name:        namespace,
			Description: "Namespace has no memory quota - memory is unbounded",
		})
	}

	if !hasPodQuota {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Namespace",
			Namespace:   namespace,
			Name:        namespace,
			Description: "Namespace has no pod count limit - can spawn unlimited pods",
		})
	}

	return issues
}
