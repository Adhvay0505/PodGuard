package scanner

import (
	"crypto/subtle"
	"encoding/base64"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

type SecretScanner struct{}

func NewSecretScanner() *SecretScanner {
	return &SecretScanner{}
}

var (
	awsAccessKeyPattern = regexp.MustCompile(`(?i)(aws_access_key_id|aws_secret_access_key|aws_session_token)[\s]*[=:][\s]*[A-Z0-9]{20,}`)
	awsKeyMatch         = regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`)
	githubTokenPattern  = regexp.MustCompile(`(?i)(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}`)
	gitlabTokenPattern  = regexp.MustCompile(`(?i)glpat-[0-9a-zA-Z\-_]{20,}`)
	slackTokenPattern   = regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,}`)
	googleAPIKeyPattern = regexp.MustCompile(`(?i)AIza[0-9A-Za-z\-_]{35}`)
	datadogAPIKey       = regexp.MustCompile(`(?i)(datadog|dd)[\-_]?(api|app)\s*[_]?key[\s]*[=:][\s]*[a-f0-9]{32}`)
	stripeKeyPattern    = regexp.MustCompile(`(?i)(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}`)
	privateKeyPattern   = regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)
	sshPrivateKey       = regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`)
	basicAuthPattern    = regexp.MustCompile(`(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]{20,}`)
	bearerTokenPattern  = regexp.MustCompile(`(?i)Authorization:\s*Bearer\s+[A-Za-z0-9\-_.~+/]{20,}`)
	jwtTokenPattern     = regexp.MustCompile(`eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+`)
	genericAPIKey       = regexp.MustCompile(`(?i)(api[_-]?key|apikey|api_secret|secret_key|secretkey)[\s]*[=:][\s]*['"]?[A-Za-z0-9_\-]{16,}['"]?`)
	passwordPattern     = regexp.MustCompile(`(?i)(password|passwd|pwd|secret)[\s]*[=:][\s]*['"]?[A-Za-z0-9@#$%^&*!]{8,}['"]?`)
	tokenPattern        = regexp.MustCompile(`(?i)(token|auth_token|access_token)[\s]*[=:][\s]*['"]?[A-Za-z0-9_\-\.]{16,}['"]?`)
	connectionString    = regexp.MustCompile(`(?i)(mongodb|mysql|postgresql|redis|amqp|jdbc)://[^\s]+`)
	hexSecret           = regexp.MustCompile(`(?i)(secret|key|token)[\s]*[=:][\s]*['"]?[0-9a-f]{32,}['"]?`)
)

type SecretFinding struct {
	Severity    string
	Resource    string
	Namespace   string
	Name        string
	Description string
	Type        string
	Value       string
}

func (s *SecretScanner) ScanPod(pod *corev1.Pod) []SecurityIssue {
	var issues []SecurityIssue

	for _, container := range pod.Spec.Containers {
		issues = append(issues, s.scanContainerEnvVars(pod, container, "Container")...)
		issues = append(issues, s.scanContainerVolumes(pod, container, "Container")...)
	}

	for _, container := range pod.Spec.InitContainers {
		issues = append(issues, s.scanContainerEnvVars(pod, container, "Init container")...)
		issues = append(issues, s.scanContainerVolumes(pod, container, "Init container")...)
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

		value := env.Value
		findings := s.scanForSecrets(value)
		for _, finding := range findings {
			issues = append(issues, SecurityIssue{
				Severity:    finding.Severity,
				Resource:    "Pod",
				Namespace:   pod.Namespace,
				Name:        pod.Name,
				Description: finding.Description,
			})
		}

		if env.ValueFrom != nil {
			if env.ValueFrom.SecretKeyRef != nil {
				if env.ValueFrom.SecretKeyRef.Optional != nil && !*env.ValueFrom.SecretKeyRef.Optional {
					issues = append(issues, SecurityIssue{
						Severity:    "MEDIUM",
						Resource:    "Pod",
						Namespace:   pod.Namespace,
						Name:        pod.Name,
						Description: "Container references required secret in env var without version/dynamic rotation",
					})
				}
			}

			if env.ValueFrom.ConfigMapKeyRef != nil {
				issues = append(issues, SecurityIssue{
					Severity:    "LOW",
					Resource:    "Pod",
					Namespace:   pod.Namespace,
					Name:        pod.Name,
					Description: "Container uses ConfigMap for sensitive data in env var",
				})
			}
		}
	}

	return issues
}

func (s *SecretScanner) scanContainerVolumes(pod *corev1.Pod, container corev1.Container, containerType string) []SecurityIssue {
	var issues []SecurityIssue

	for _, volume := range pod.Spec.Volumes {
		if volume.Secret != nil {
			if volume.Secret.SecretName == "default-token-" {
				issues = append(issues, SecurityIssue{
					Severity:    "MEDIUM",
					Resource:    "Pod",
					Namespace:   pod.Namespace,
					Name:        pod.Name,
					Description: "Pod mounts the default service account token",
				})
			}

			if volume.Secret.Optional != nil && !*volume.Secret.Optional {
				issues = append(issues, SecurityIssue{
					Severity:    "LOW",
					Resource:    "Pod",
					Namespace:   pod.Namespace,
					Name:        pod.Name,
					Description: "Pod mounts a required secret - ensure rotation mechanism exists",
				})
			}
		}

		if volume.ConfigMap != nil {
			issues = append(issues, SecurityIssue{
				Severity:    "LOW",
				Resource:    "Pod",
				Namespace:   pod.Namespace,
				Name:        pod.Name,
				Description: "Pod mounts a ConfigMap which may contain sensitive data",
			})
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
					Description: "Container loads all secret values as environment variables - any process can read them",
				})
			}
			if envFrom.ConfigMapRef != nil {
				issues = append(issues, SecurityIssue{
					Severity:    "MEDIUM",
					Resource:    "Pod",
					Namespace:   pod.Namespace,
					Name:        pod.Name,
					Description: "Container loads all ConfigMap values as environment variables",
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
				Description: "Secret contains no data - may be a placeholder",
			})
		}
	}

	if secret.Type == corev1.SecretTypeServiceAccountToken {
		issues = append(issues, SecurityIssue{
			Severity:    "HIGH",
			Resource:    "Secret",
			Namespace:   secret.Namespace,
			Name:        secret.Name,
			Description: "Secret is a ServiceAccount token - ensure it's properly rotated",
		})
	}

	for key := range secret.Data {
		lowerKey := strings.ToLower(key)
		if strings.Contains(lowerKey, "token") || strings.Contains(lowerKey, "password") ||
			strings.Contains(lowerKey, "secret") || strings.Contains(lowerKey, "key") {
			decoded := s.decodeSecretValue(secret.Data[key])
			findings := s.scanForSecrets(decoded)
			for _, finding := range findings {
				issues = append(issues, SecurityIssue{
					Severity:    finding.Severity,
					Resource:    "Secret",
					Namespace:   secret.Namespace,
					Name:        secret.Name,
					Description: "Secret key '" + key + "' contains " + finding.Type,
				})
			}
		}
	}

	return issues
}

func (s *SecretScanner) decodeSecretValue(data []byte) string {
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err == nil {
		return string(decoded)
	}
	decoded, err = base64.URLEncoding.DecodeString(string(data))
	if err == nil {
		return string(decoded)
	}
	return string(data)
}

func (s *SecretScanner) scanForSecrets(value string) []SecretFinding {
	var findings []SecretFinding

	if awsKeyMatch.MatchString(value) {
		findings = append(findings, SecretFinding{
			Severity:    "CRITICAL",
			Type:        "AWS Access Key",
			Description: "Hardcoded AWS access key detected",
		})
	}

	if awsAccessKeyPattern.MatchString(value) {
		findings = append(findings, SecretFinding{
			Severity:    "CRITICAL",
			Type:        "AWS Credential",
			Description: "Hardcoded AWS credential pattern detected",
		})
	}

	if githubTokenPattern.MatchString(value) {
		findings = append(findings, SecretFinding{
			Severity:    "CRITICAL",
			Type:        "GitHub Token",
			Description: "Hardcoded GitHub token detected",
		})
	}

	if gitlabTokenPattern.MatchString(value) {
		findings = append(findings, SecretFinding{
			Severity:    "CRITICAL",
			Type:        "GitLab Token",
			Description: "Hardcoded GitLab token detected",
		})
	}

	if slackTokenPattern.MatchString(value) {
		findings = append(findings, SecretFinding{
			Severity:    "CRITICAL",
			Type:        "Slack Token",
			Description: "Hardcoded Slack token detected",
		})
	}

	if googleAPIKeyPattern.MatchString(value) {
		findings = append(findings, SecretFinding{
			Severity:    "CRITICAL",
			Type:        "Google API Key",
			Description: "Hardcoded Google API key detected",
		})
	}

	if datadogAPIKey.MatchString(value) {
		findings = append(findings, SecretFinding{
			Severity:    "CRITICAL",
			Type:        "Datadog API Key",
			Description: "Hardcoded Datadog API key detected",
		})
	}

	if stripeKeyPattern.MatchString(value) {
		findings = append(findings, SecretFinding{
			Severity:    "CRITICAL",
			Type:        "Stripe Key",
			Description: "Hardcoded Stripe API key detected",
		})
	}

	if privateKeyPattern.MatchString(value) || sshPrivateKey.MatchString(value) {
		findings = append(findings, SecretFinding{
			Severity:    "CRITICAL",
			Type:        "Private Key",
			Description: "Hardcoded private key detected",
		})
	}

	if basicAuthPattern.MatchString(value) || bearerTokenPattern.MatchString(value) {
		findings = append(findings, SecretFinding{
			Severity:    "HIGH",
			Type:        "HTTP Auth",
			Description: "Hardcoded HTTP authentication credentials detected",
		})
	}

	if jwtTokenPattern.MatchString(value) {
		findings = append(findings, SecretFinding{
			Severity:    "HIGH",
			Type:        "JWT Token",
			Description: "Hardcoded JWT token detected",
		})
	}

	if connectionString.MatchString(value) {
		findings = append(findings, SecretFinding{
			Severity:    "HIGH",
			Type:        "Database Connection String",
			Description: "Hardcoded database connection string detected",
		})
	}

	if genericAPIKey.MatchString(value) {
		findings = append(findings, SecretFinding{
			Severity:    "HIGH",
			Type:        "API Key",
			Description: "Hardcoded API key pattern detected",
		})
	}

	valueLower := strings.ToLower(value)
	if passwordPattern.MatchString(value) && !strings.Contains(valueLower, "placeholder") &&
		!strings.Contains(valueLower, "example") && !strings.Contains(valueLower, "change") {
		findings = append(findings, SecretFinding{
			Severity:    "HIGH",
			Type:        "Password",
			Description: "Hardcoded password detected",
		})
	}

	if tokenPattern.MatchString(value) && !strings.Contains(valueLower, "placeholder") &&
		!strings.Contains(valueLower, "example") && !strings.Contains(valueLower, "set_here") {
		findings = append(findings, SecretFinding{
			Severity:    "HIGH",
			Type:        "Token",
			Description: "Hardcoded token detected",
		})
	}

	if hexSecret.MatchString(value) && len(value) >= 40 {
		findings = append(findings, SecretFinding{
			Severity:    "MEDIUM",
			Type:        "Hex Secret",
			Description: "Suspicious hex-encoded secret detected",
		})
	}

	return findings
}

func isBase64Encoded(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return true
	}
	_, err = base64.URLEncoding.DecodeString(s)
	return err == nil
}

func constantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
