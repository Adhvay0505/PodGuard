package scanner

import (
	"testing"

	"podguard/pkg/scanner"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestResourceScanner_ScanPodResources(t *testing.T) {
	scanner := scanner.NewResourceScanner()

	tests := []struct {
		name     string
		pod      *corev1.Pod
		expected int
	}{
		{
			name: "Pod with resources set",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "well-behaved-container",
							Image: "nginx:latest",
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("200m"),
									corev1.ResourceMemory: resource.MustParse("256Mi"),
								},
							},
						},
					},
				},
			},
			expected: 0,
		},
		{
			name: "Pod with no resources set",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "naughty-container",
							Image: "nginx:latest",
						},
					},
				},
			},
			expected: 4,
		},
		{
			name: "Pod with only requests set",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "half-behaved-container",
							Image: "nginx:latest",
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
							},
						},
					},
				},
			},
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := scanner.ScanPodResources(tt.pod)
			if len(issues) != tt.expected {
				t.Errorf("%s: Expected %d issues, got %d", tt.name, tt.expected, len(issues))
			}
		})
	}
}
