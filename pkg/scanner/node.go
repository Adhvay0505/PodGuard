package scanner

import (
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

type NodeScanner struct{}

func NewNodeScanner() *NodeScanner {
	return &NodeScanner{}
}

func (s *NodeScanner) ScanNode(node *corev1.Node) []SecurityIssue {
	var issues []SecurityIssue

	issues = append(issues, s.checkNodeConditions(node)...)
	issues = append(issues, s.checkNodeTaints(node)...)
	issues = append(issues, s.checkNodeLabels(node)...)

	return issues
}

func (s *NodeScanner) checkNodeConditions(node *corev1.Node) []SecurityIssue {
	var issues []SecurityIssue

	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			if condition.Status == corev1.ConditionFalse {
				issues = append(issues, SecurityIssue{
					Severity:    "HIGH",
					Resource:    "Node",
					Namespace:   "",
					Name:        node.Name,
					Description: "Node is not ready - workload may be scheduled to unhealthy node",
				})
			}
		}

		if condition.Type == corev1.NodeMemoryPressure {
			if condition.Status == corev1.ConditionTrue {
				issues = append(issues, SecurityIssue{
					Severity:    "MEDIUM",
					Resource:    "Node",
					Namespace:   "",
					Name:        node.Name,
					Description: "Node is under memory pressure",
				})
			}
		}

		if condition.Type == corev1.NodeDiskPressure {
			if condition.Status == corev1.ConditionTrue {
				issues = append(issues, SecurityIssue{
					Severity:    "MEDIUM",
					Resource:    "Node",
					Namespace:   "",
					Name:        node.Name,
					Description: "Node is under disk pressure",
				})
			}
		}

		if condition.Type == corev1.NodeNetworkUnavailable {
			if condition.Status == corev1.ConditionTrue {
				issues = append(issues, SecurityIssue{
					Severity:    "HIGH",
					Resource:    "Node",
					Namespace:   "",
					Name:        node.Name,
					Description: "Node network is unavailable",
				})
			}
		}

		if condition.LastHeartbeatTime.IsZero() || time.Since(condition.LastHeartbeatTime.Time) > 5*time.Minute {
			issues = append(issues, SecurityIssue{
				Severity:    "HIGH",
				Resource:    "Node",
				Namespace:   "",
				Name:        node.Name,
				Description: "Node heartbeat is stale - node may be unreachable",
			})
		}
	}

	return issues
}

func (s *NodeScanner) checkNodeTaints(node *corev1.Node) []SecurityIssue {
	var issues []SecurityIssue

	for _, taint := range node.Spec.Taints {
		if taint.Effect == corev1.TaintEffectNoSchedule {
			issues = append(issues, SecurityIssue{
				Severity:    "LOW",
				Resource:    "Node",
				Namespace:   "",
				Name:        node.Name,
				Description: fmt.Sprintf("Node has NoSchedule taint: %s", taint.Key),
			})
		}

		if taint.Effect == corev1.TaintEffectNoExecute {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "Node",
				Namespace:   "",
				Name:        node.Name,
				Description: fmt.Sprintf("Node has NoExecute taint - pods may be evicted: %s", taint.Key),
			})
		}
	}

	return issues
}

func (s *NodeScanner) checkNodeLabels(node *corev1.Node) []SecurityIssue {
	var issues []SecurityIssue

	criticalLabels := []string{
		"node.kubernetes.io/instance-type",
		"topology.kubernetes.io/region",
		"topology.kubernetes.io/zone",
		"kubernetes.io/arch",
		"kubernetes.io/os",
	}

	for _, label := range criticalLabels {
		if _, ok := node.Labels[label]; !ok {
			issues = append(issues, SecurityIssue{
				Severity:    "LOW",
				Resource:    "Node",
				Namespace:   "",
				Name:        node.Name,
				Description: fmt.Sprintf("Missing recommended label: %s", label),
			})
		}
	}

	for label := range node.Labels {
		if strings.Contains(label, "dedicated") || strings.Contains(label, "tenant") {
			if _, ok := node.Labels[label]; ok {
				issues = append(issues, SecurityIssue{
					Severity:    "LOW",
					Resource:    "Node",
					Namespace:   "",
					Name:        node.Name,
					Description: "Node has tenant/dedicated label - ensure proper node assignment",
				})
			}
		}
	}

	return issues
}
