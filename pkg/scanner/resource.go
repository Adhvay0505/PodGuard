package scanner

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

type ResourceScanner struct{}

func NewResourceScanner() *ResourceScanner {
	return &ResourceScanner{}
}

func (s *ResourceScanner) ScanPodResources(pod *corev1.Pod) []SecurityIssue {
	var issues []SecurityIssue

	for _, container := range pod.Spec.Containers {
		issues = append(issues, scanContainerResources(pod, container, "Container")...)
	}

	for _, container := range pod.Spec.InitContainers {
		issues = append(issues, scanContainerResources(pod, container, "Init container")...)
	}

	return issues
}

func scanContainerResources(pod *corev1.Pod, container corev1.Container, containerType string) []SecurityIssue {
	var issues []SecurityIssue

	if container.Resources.Requests == nil || container.Resources.Requests.Cpu().IsZero() {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Pod",
			Namespace:   pod.Namespace,
			Name:        pod.Name,
			Description: fmt.Sprintf("%s '%s' does not have CPU requests set", containerType, container.Name),
		})
	}

	if container.Resources.Requests == nil || container.Resources.Requests.Memory().IsZero() {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Pod",
			Namespace:   pod.Namespace,
			Name:        pod.Name,
			Description: fmt.Sprintf("%s '%s' does not have memory requests set", containerType, container.Name),
		})
	}

	if container.Resources.Limits == nil || container.Resources.Limits.Cpu().IsZero() {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Pod",
			Namespace:   pod.Namespace,
			Name:        pod.Name,
			Description: fmt.Sprintf("%s '%s' does not have CPU limits set", containerType, container.Name),
		})
	}

	if container.Resources.Limits == nil || container.Resources.Limits.Memory().IsZero() {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Pod",
			Namespace:   pod.Namespace,
			Name:        pod.Name,
			Description: fmt.Sprintf("%s '%s' does not have memory limits set", containerType, container.Name),
		})
	}

	return issues
}
