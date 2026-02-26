package scanner

import (
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

type SecretScanner struct{}

func NewSecretScanner() *SecretScanner {
	return &SecretScanner{}
}

var (
	awsKeyMatch        = regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`)
	githubTokenPattern = regexp.MustCompile(`(?i)(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}`)
	gitlabTokenPattern = regexp.MustCompile(`(?i)glpat-[0-9a-zA-Z\-_]{20,}`)
	slackTokenPattern  = regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,}`)
	privateKeyPattern  = regexp.MustCompile(`-----BEGIN .*PRIVATE KEY-----`)
	genericAPIKey      = regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret_key)[\s]*[=:][\s]*['"]?[A-Za-z0-9_\-]{16,}['"]?`)
	passwordPattern    = regexp.MustCompile(`(?i)(password|passwd|pwd)[\s]*[=:][\s]*['"]?[A-Za-z0-9@#$%^&*!]{8,}['"]?`)
	tokenPattern       = regexp.MustCompile(`(?i)(token|auth_token)[\s]*[=:][\s]*['"]?[A-Za-z0-9_\-\.]{16,}['"]?`)
)

func (s *SecretScanner) ScanPod(pod *corev1.Pod) []SecurityIssue {
	var issues []SecurityIssue

	for _, container := range pod.Spec.Containers {
		issues = append(issues, s.scanContainerEnvVars(pod, container, "Container")...)
	}

	for _, container := range pod.Spec.InitContainers {
		issues = append(issues, s.scanContainerEnvVars(pod, container, "Init container")...)
	}

	issues = append(issues, s.scanPodEnvFrom(pod)...)

	return issues
}

func (s *SecretScanner) scanContainerEnvVars(pod *corev1.Pod, container corev1.Container, containerType string) []SecurityIssue {
	var issues []SecurityIssue

	if container.Env == nil {
		return issues
	}

	for _, env := range container.Env {
		if env.Value == "" {
			continue
		}

		findings := s.scanForSecrets(env.Value)
		for _, finding := range findings {
			issues = append(issues, SecurityIssue{
				Severity:    finding.Severity,
				Resource:    "Pod",
				Namespace:   pod.Namespace,
				Name:        pod.Name,
				Description: finding.Description,
			})
		}

		if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
			if env.ValueFrom.SecretKeyRef.Optional != nil && !*env.ValueFrom.SecretKeyRef.Optional {
				issues = append(issues, SecurityIssue{
					Severity:    "MEDIUM",
					Resource:    "Pod",
					Namespace:   pod.Namespace,
					Name:        pod.Name,
					Description: "Container references required secret in env var",
				})
			}
		}
	}

	return issues
}

func (s *SecretScanner) scanPodEnvFrom(pod *corev1.Pod) []SecurityIssue {
	var issues []SecurityIssue

	for _, container := range pod.Spec.Containers {
		for _, envFrom := range container.EnvFrom {
			if envFrom.SecretRef != nil {
				issues = append(issues, SecurityIssue{
					Severity:    "HIGH",
					Resource:    "Pod",
					Namespace:   pod.Namespace,
					Name:        pod.Name,
					Description: "Container loads all secret values as environment variables",
				})
			}
		}
	}

	return issues
}

func (s *SecretScanner) ScanConfigMap(cm *corev1.ConfigMap) []SecurityIssue {
	var issues []SecurityIssue

	for key, value := range cm.Data {
		lowerKey := strings.ToLower(key)
		lowerValue := strings.ToLower(value)

		if strings.Contains(lowerKey, "password") || strings.Contains(lowerKey, "secret") ||
			strings.Contains(lowerKey, "key") || strings.Contains(lowerKey, "token") ||
			strings.Contains(lowerKey, "auth") || strings.Contains(lowerKey, "credential") {
			findings := s.scanForSecrets(value)
			for _, finding := range findings {
				issues = append(issues, SecurityIssue{
					Severity:    finding.Severity,
					Resource:    "ConfigMap",
					Namespace:   cm.Namespace,
					Name:        cm.Name,
					Description: "ConfigMap key '" + key + "' contains " + finding.Type,
				})
			}

			if len(findings) == 0 && (strings.Contains(lowerValue, "=") || len(value) > 20) {
				issues = append(issues, SecurityIssue{
					Severity:    "MEDIUM",
					Resource:    "ConfigMap",
					Namespace:   cm.Namespace,
					Name:        cm.Name,
					Description: "ConfigMap key '" + key + "' may contain sensitive data",
				})
			}
		}
	}

	return issues
}

func (s *SecretScanner) ScanSecret(secret *corev1.Secret) []SecurityIssue {
	var issues []SecurityIssue

	if secret.Type == corev1.SecretTypeOpaque {
		if len(secret.Data) == 0 && len(secret.StringData) == 0 {
			issues = append(issues, SecurityIssue{
				Severity:    "LOW",
				Resource:    "Secret",
				Namespace:   secret.Namespace,
				Name:        secret.Name,
				Description: "Secret contains no data",
			})
		}
	}

	return issues
}

type secretFinding struct {
	Severity    string
	Type        string
	Description string
}

func (s *SecretScanner) scanForSecrets(value string) []secretFinding {
	var findings []secretFinding

	if awsKeyMatch.MatchString(value) {
		findings = append(findings, secretFinding{
			Severity:    "CRITICAL",
			Type:        "AWS Access Key",
			Description: "Hardcoded AWS access key detected",
		})
	}

	if githubTokenPattern.MatchString(value) {
		findings = append(findings, secretFinding{
			Severity:    "CRITICAL",
			Type:        "GitHub Token",
			Description: "Hardcoded GitHub token detected",
		})
	}

	if gitlabTokenPattern.MatchString(value) {
		findings = append(findings, secretFinding{
			Severity:    "CRITICAL",
			Type:        "GitLab Token",
			Description: "Hardcoded GitLab token detected",
		})
	}

	if slackTokenPattern.MatchString(value) {
		findings = append(findings, secretFinding{
			Severity:    "CRITICAL",
			Type:        "Slack Token",
			Description: "Hardcoded Slack token detected",
		})
	}

	if privateKeyPattern.MatchString(value) {
		findings = append(findings, secretFinding{
			Severity:    "CRITICAL",
			Type:        "Private Key",
			Description: "Hardcoded private key detected",
		})
	}

	valueLower := strings.ToLower(value)
	if genericAPIKey.MatchString(value) && !strings.Contains(valueLower, "placeholder") {
		findings = append(findings, secretFinding{
			Severity:    "HIGH",
			Type:        "API Key",
			Description: "Hardcoded API key detected",
		})
	}

	if passwordPattern.MatchString(value) && !strings.Contains(valueLower, "placeholder") &&
		!strings.Contains(valueLower, "example") {
		findings = append(findings, secretFinding{
			Severity:    "HIGH",
			Type:        "Password",
			Description: "Hardcoded password detected",
		})
	}

	if tokenPattern.MatchString(value) && !strings.Contains(valueLower, "placeholder") &&
		!strings.Contains(valueLower, "example") {
		findings = append(findings, secretFinding{
			Severity:    "HIGH",
			Type:        "Token",
			Description: "Hardcoded token detected",
		})
	}

	return findings
}
