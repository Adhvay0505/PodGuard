package scanner

import (
	"testing"

	"podguard/pkg/scanner"

	corev1 "k8s.io/api/core/v1"
)

func TestPodScanner_ScanPod(t *testing.T) {
	scanner := scanner.NewPodScanner()

	tests := []struct {
		name     string
		pod      *corev1.Pod
		expected int
	}{
		{
			name: "Secure pod with no issues",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "secure-container",
							Image: "nginx:latest",
							SecurityContext: &corev1.SecurityContext{
								RunAsUser:                int64Ptr(1000),
								ReadOnlyRootFilesystem:   boolPtr(true),
								Privileged:               boolPtr(false),
								AllowPrivilegeEscalation: boolPtr(false),
								SeccompProfile: &corev1.SeccompProfile{
									Type: corev1.SeccompProfileTypeRuntimeDefault,
								},
							},
						},
					},
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: boolPtr(true),
					},
					ServiceAccountName:           "secure-sa",
					AutomountServiceAccountToken: boolPtr(false),
				},
			},
			expected: 0,
		},
		{
			name: "Pod with privileged container",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "privileged-container",
							Image: "nginx:latest",
							SecurityContext: &corev1.SecurityContext{
								Privileged: boolPtr(true),
							},
						},
					},
				},
			},
			expected: 7,
		},
		{
			name: "Pod with multiple security issues",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					HostNetwork: true,
					HostPID:     true,
					Containers: []corev1.Container{
						{
							Name:  "insecure-container",
							Image: "nginx:latest",
							SecurityContext: &corev1.SecurityContext{
								RunAsUser:              int64Ptr(0),
								ReadOnlyRootFilesystem: boolPtr(false),
								Privileged:             boolPtr(true),
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "host-etc",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/etc",
								},
							},
						},
					},
				},
			},
			expected: 11,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := scanner.ScanPod(tt.pod)
			if len(issues) != tt.expected {
				for _, issue := range issues {
					t.Logf("Issue: %+v", issue)
				}
				t.Errorf("Expected %d issues, got %d", tt.expected, len(issues))
			}
		})
	}
}

func int64Ptr(i int64) *int64 {
	return &i
}

func boolPtr(b bool) *bool {
	return &b
}
