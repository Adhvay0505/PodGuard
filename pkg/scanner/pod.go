package scanner

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

type SecurityIssue struct {
	Severity    string
	Resource    string
	Namespace   string
	Name        string
	Description string
}

type PodScanner struct{}

func NewPodScanner() *PodScanner {
	return &PodScanner{}
}

func (s *PodScanner) ScanPod(pod *corev1.Pod) []SecurityIssue {
	var issues []SecurityIssue

	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil {
			if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
				issues = append(issues, SecurityIssue{
					Severity:    "HIGH",
					Resource:    "Pod",
					Namespace:   pod.Namespace,
					Name:        pod.Name,
					Description: fmt.Sprintf("Container '%s' is running in privileged mode", container.Name),
				})
			}

			if container.SecurityContext.RunAsUser != nil && *container.SecurityContext.RunAsUser == 0 {
				issues = append(issues, SecurityIssue{
					Severity:    "MEDIUM",
					Resource:    "Pod",
					Namespace:   pod.Namespace,
					Name:        pod.Name,
					Description: fmt.Sprintf("Container '%s' is running as root user", container.Name),
				})
			}

			if container.SecurityContext.ReadOnlyRootFilesystem != nil && !*container.SecurityContext.ReadOnlyRootFilesystem {
				issues = append(issues, SecurityIssue{
					Severity:    "LOW",
					Resource:    "Pod",
					Namespace:   pod.Namespace,
					Name:        pod.Name,
					Description: fmt.Sprintf("Container '%s' has writable root filesystem", container.Name),
				})
			}
		}
	}

	if pod.Spec.HostNetwork {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Pod",
			Namespace:   pod.Namespace,
			Name:        pod.Name,
			Description: "Pod is using host network namespace",
		})
	}

	if pod.Spec.HostPID {
		issues = append(issues, SecurityIssue{
			Severity:    "HIGH",
			Resource:    "Pod",
			Namespace:   pod.Namespace,
			Name:        pod.Name,
			Description: "Pod is sharing host process ID namespace",
		})
	}

	if pod.Spec.HostIPC {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Pod",
			Namespace:   pod.Namespace,
			Name:        pod.Name,
			Description: "Pod is sharing host IPC namespace",
		})
	}

	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath != nil {
			path := volume.HostPath.Path
			if strings.HasPrefix(path, "/var") || strings.HasPrefix(path, "/etc") || strings.HasPrefix(path, "/usr") {
				issues = append(issues, SecurityIssue{
					Severity:    "HIGH",
					Resource:    "Pod",
					Namespace:   pod.Namespace,
					Name:        pod.Name,
					Description: fmt.Sprintf("Pod mounts sensitive host path '%s'", path),
				})
			}
		}
	}

	return issues
}
