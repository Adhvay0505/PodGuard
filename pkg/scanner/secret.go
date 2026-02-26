package scanner

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

type SecretScanner struct{}

func NewSecretScanner() *SecretScanner {
	return &SecretScanner{}
}

func (s *SecretScanner) ScanPod(pod *corev1.Pod) []SecurityIssue {
	var issues []SecurityIssue

	for _, container := range pod.Spec.Containers {
		issues = append(issues, s.scanContainer(pod, container, "Container")...)
	}
	for _, container := range pod.Spec.InitContainers {
		issues = append(issues, s.scanContainer(pod, container, "Init container")...)
	}

	for _, volume := range pod.Spec.Volumes {
		if volume.Secret != nil {
			issues = append(issues, SecurityIssue{
				Severity:    "LOW",
				Resource:    "Pod",
				Namespace:   pod.Namespace,
				Name:        pod.Name,
				Description: fmt.Sprintf("Pod mounts secret volume '%s'", volume.Name),
			})
		}

		if volume.Projected != nil {
			for _, source := range volume.Projected.Sources {
				if source.Secret != nil {
					issues = append(issues, SecurityIssue{
						Severity:    "LOW",
						Resource:    "Pod",
						Namespace:   pod.Namespace,
						Name:        pod.Name,
						Description: fmt.Sprintf("Pod mounts projected secret in volume '%s'", volume.Name),
					})
				}
			}
		}
	}

	return issues
}

func (s *SecretScanner) scanContainer(pod *corev1.Pod, container corev1.Container, containerType string) []SecurityIssue {
	var issues []SecurityIssue

	for _, env := range container.Env {
		if env.ValueFrom != nil {
			if env.ValueFrom.SecretKeyRef != nil {
				issues = append(issues, SecurityIssue{
					Severity:    "MEDIUM",
					Resource:    "Pod",
					Namespace:   pod.Namespace,
					Name:        pod.Name,
					Description: fmt.Sprintf("%s '%s' injects secret '%s' via env var %s", containerType, container.Name, env.ValueFrom.SecretKeyRef.Name, env.Name),
				})
			}

			if env.ValueFrom.ConfigMapKeyRef != nil && isSensitiveEnvName(env.Name) {
				issues = append(issues, SecurityIssue{
					Severity:    "HIGH",
					Resource:    "Pod",
					Namespace:   pod.Namespace,
					Name:        pod.Name,
					Description: fmt.Sprintf("%s '%s' maps env var %s from ConfigMap '%s' (possible secret in ConfigMap)", containerType, container.Name, env.Name, env.ValueFrom.ConfigMapKeyRef.Name),
				})
			}
		}
	}

	for _, envFrom := range container.EnvFrom {
		if envFrom.SecretRef != nil {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "Pod",
				Namespace:   pod.Namespace,
				Name:        pod.Name,
				Description: fmt.Sprintf("%s '%s' imports all keys from secret '%s' via envFrom", containerType, container.Name, envFrom.SecretRef.Name),
			})
		}
		if envFrom.ConfigMapRef != nil && isSensitiveName(envFrom.ConfigMapRef.Name) {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "Pod",
				Namespace:   pod.Namespace,
				Name:        pod.Name,
				Description: fmt.Sprintf("%s '%s' imports all keys from ConfigMap '%s' (name suggests secrets)", containerType, container.Name, envFrom.ConfigMapRef.Name),
			})
		}
	}

	return issues
}

func (s *SecretScanner) ScanConfigMap(configMap *corev1.ConfigMap) []SecurityIssue {
	var issues []SecurityIssue

	for key, value := range configMap.Data {
		if isSensitiveName(key) {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "ConfigMap",
				Namespace:   configMap.Namespace,
				Name:        configMap.Name,
				Description: fmt.Sprintf("ConfigMap key '%s' appears to contain sensitive data", key),
			})
		}

		if hasSensitiveValue(value) {
			issues = append(issues, SecurityIssue{
				Severity:    "HIGH",
				Resource:    "ConfigMap",
				Namespace:   configMap.Namespace,
				Name:        configMap.Name,
				Description: fmt.Sprintf("ConfigMap key '%s' contains plaintext secret-like data", key),
			})
		}
	}

	for key := range configMap.BinaryData {
		if isSensitiveName(key) {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "ConfigMap",
				Namespace:   configMap.Namespace,
				Name:        configMap.Name,
				Description: fmt.Sprintf("ConfigMap binary key '%s' appears to contain sensitive data", key),
			})
		}
	}

	return issues
}

func (s *SecretScanner) ScanSecret(secret *corev1.Secret) []SecurityIssue {
	var issues []SecurityIssue

	if secret.Type == corev1.SecretTypeServiceAccountToken {
		return issues
	}

	if secret.Immutable == nil || !*secret.Immutable {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Resource:    "Secret",
			Namespace:   secret.Namespace,
			Name:        secret.Name,
			Description: "Secret is mutable (consider immutable secrets for tamper resistance)",
		})
	}

	return issues
}

func isSensitiveName(name string) bool {
	normalized := strings.ToLower(name)
	keywords := []string{
		"password",
		"passwd",
		"pwd",
		"secret",
		"token",
		"apikey",
		"api_key",
		"accesskey",
		"access_key",
		"privatekey",
		"private_key",
		"jwt",
	}
	for _, keyword := range keywords {
		if strings.Contains(normalized, keyword) {
			return true
		}
	}
	return false
}

func hasSensitiveValue(value string) bool {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "-----begin") {
		return true
	}
	if strings.Contains(lower, "private key") {
		return true
	}
	if strings.Contains(lower, "aws_secret_access_key") {
		return true
	}
	if strings.Contains(lower, "password=") || strings.Contains(lower, "passwd=") || strings.Contains(lower, "secret=") || strings.Contains(lower, "token=") {
		return true
	}
	return false
}
