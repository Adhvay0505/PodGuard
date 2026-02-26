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
		issues = append(issues, scanContainerSecurity(pod, container, "Container")...)
	}

	for _, container := range pod.Spec.InitContainers {
		issues = append(issues, scanContainerSecurity(pod, container, "Init container")...)
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

	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Pod",
			Namespace:   pod.Namespace,
			Name:        pod.Name,
			Description: "Pod is automounting the service account token",
		})
	}

	if pod.Spec.ServiceAccountName == "" || pod.Spec.ServiceAccountName == "default" {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Resource:    "Pod",
			Namespace:   pod.Namespace,
			Name:        pod.Name,
			Description: "Pod is using the default service account",
		})
	}

	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath != nil {
			path := volume.HostPath.Path
			if isSensitiveHostPath(path) {
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

func scanContainerSecurity(pod *corev1.Pod, container corev1.Container, containerType string) []SecurityIssue {
	var issues []SecurityIssue

	securityContext := container.SecurityContext
	if securityContext == nil {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Pod",
			Namespace:   pod.Namespace,
			Name:        pod.Name,
			Description: fmt.Sprintf("%s '%s' does not define a securityContext", containerType, container.Name),
		})
	} else {
		if securityContext.Privileged != nil && *securityContext.Privileged {
			issues = append(issues, SecurityIssue{
				Severity:    "HIGH",
				Resource:    "Pod",
				Namespace:   pod.Namespace,
				Name:        pod.Name,
				Description: fmt.Sprintf("%s '%s' is running in privileged mode", containerType, container.Name),
			})
		}

		if securityContext.AllowPrivilegeEscalation == nil {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "Pod",
				Namespace:   pod.Namespace,
				Name:        pod.Name,
				Description: fmt.Sprintf("%s '%s' does not explicitly set allowPrivilegeEscalation", containerType, container.Name),
			})
		} else if *securityContext.AllowPrivilegeEscalation {
			issues = append(issues, SecurityIssue{
				Severity:    "HIGH",
				Resource:    "Pod",
				Namespace:   pod.Namespace,
				Name:        pod.Name,
				Description: fmt.Sprintf("%s '%s' allows privilege escalation", containerType, container.Name),
			})
		}

		if securityContext.RunAsUser != nil && *securityContext.RunAsUser == 0 {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "Pod",
				Namespace:   pod.Namespace,
				Name:        pod.Name,
				Description: fmt.Sprintf("%s '%s' is running as root user", containerType, container.Name),
			})
		}

		if securityContext.ReadOnlyRootFilesystem == nil {
			issues = append(issues, SecurityIssue{
				Severity:    "LOW",
				Resource:    "Pod",
				Namespace:   pod.Namespace,
				Name:        pod.Name,
				Description: fmt.Sprintf("%s '%s' does not set readOnlyRootFilesystem", containerType, container.Name),
			})
		} else if !*securityContext.ReadOnlyRootFilesystem {
			issues = append(issues, SecurityIssue{
				Severity:    "LOW",
				Resource:    "Pod",
				Namespace:   pod.Namespace,
				Name:        pod.Name,
				Description: fmt.Sprintf("%s '%s' has writable root filesystem", containerType, container.Name),
			})
		}

		if securityContext.Capabilities != nil && len(securityContext.Capabilities.Add) > 0 {
			severity := "MEDIUM"
			for _, cap := range securityContext.Capabilities.Add {
				if cap == "SYS_ADMIN" {
					severity = "HIGH"
					break
				}
			}
			issues = append(issues, SecurityIssue{
				Severity:    severity,
				Resource:    "Pod",
				Namespace:   pod.Namespace,
				Name:        pod.Name,
				Description: fmt.Sprintf("%s '%s' adds Linux capabilities: %v", containerType, container.Name, securityContext.Capabilities.Add),
			})
		}

		seccompProfile := securityContext.SeccompProfile
		if seccompProfile == nil && pod.Spec.SecurityContext != nil {
			seccompProfile = pod.Spec.SecurityContext.SeccompProfile
		}
		if seccompProfile == nil {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "Pod",
				Namespace:   pod.Namespace,
				Name:        pod.Name,
				Description: fmt.Sprintf("%s '%s' does not set a seccomp profile", containerType, container.Name),
			})
		} else if seccompProfile.Type == corev1.SeccompProfileTypeUnconfined {
			issues = append(issues, SecurityIssue{
				Severity:    "HIGH",
				Resource:    "Pod",
				Namespace:   pod.Namespace,
				Name:        pod.Name,
				Description: fmt.Sprintf("%s '%s' uses an unconfined seccomp profile", containerType, container.Name),
			})
		}
	}

	runAsNonRoot := effectiveRunAsNonRoot(pod, container)
	if runAsNonRoot == nil {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Resource:    "Pod",
			Namespace:   pod.Namespace,
			Name:        pod.Name,
			Description: fmt.Sprintf("%s '%s' does not set runAsNonRoot", containerType, container.Name),
		})
	} else if !*runAsNonRoot {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Pod",
			Namespace:   pod.Namespace,
			Name:        pod.Name,
			Description: fmt.Sprintf("%s '%s' does not enforce runAsNonRoot", containerType, container.Name),
		})
	}

	if usesMutableImageTag(container.Image) {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Pod",
			Namespace:   pod.Namespace,
			Name:        pod.Name,
			Description: fmt.Sprintf("%s '%s' uses a mutable image tag (%s)", containerType, container.Name, container.Image),
		})
	}

	for _, port := range container.Ports {
		if port.HostPort > 0 {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "Pod",
				Namespace:   pod.Namespace,
				Name:        pod.Name,
				Description: fmt.Sprintf("%s '%s' exposes host port %d", containerType, container.Name, port.HostPort),
			})
		}
	}

	return issues
}

func effectiveRunAsNonRoot(pod *corev1.Pod, container corev1.Container) *bool {
	if container.SecurityContext != nil && container.SecurityContext.RunAsNonRoot != nil {
		return container.SecurityContext.RunAsNonRoot
	}
	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsNonRoot != nil {
		return pod.Spec.SecurityContext.RunAsNonRoot
	}
	return nil
}

func usesMutableImageTag(image string) bool {
	if image == "" {
		return false
	}
	if strings.Contains(image, "@sha256:") {
		return false
	}

	lastColon := strings.LastIndex(image, ":")
	lastSlash := strings.LastIndex(image, "/")
	if lastColon == -1 || lastColon < lastSlash {
		return true
	}
	tag := image[lastColon+1:]
	return tag == "" || tag == "latest"
}

func isSensitiveHostPath(path string) bool {
	sensitivePrefixes := []string{
		"/boot",
		"/dev",
		"/etc",
		"/lib",
		"/lib64",
		"/proc",
		"/root",
		"/run",
		"/sys",
		"/usr",
		"/var",
		"/var/lib",
		"/var/lib/kubelet",
		"/var/lib/docker",
		"/var/run",
		"/var/run/docker.sock",
		"/run/containerd",
		"/run/containerd/containerd.sock",
	}
	for _, prefix := range sensitivePrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}
