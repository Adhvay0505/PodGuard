package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"strings"

	"podguard/pkg/k8s"
	"podguard/pkg/scanner"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func main() {
	kubeconfig := flag.String("kubeconfig", "", "Path to kubeconfig file")
	namespace := flag.String("namespace", "", "Namespace to scan (default: all namespaces)")
	outputFormat := flag.String("output", "table", "Output format (table, json)")
	scanType := flag.String("type", "all", "Scan type (pods, rbac, all)")
	flag.Parse()

	client, err := k8s.NewClient(*kubeconfig)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	var allIssues []scanner.SecurityIssue

	if *scanType == "pods" || *scanType == "all" {
		podIssues := scanPods(client, *namespace)
		allIssues = append(allIssues, podIssues...)
	}

	if *scanType == "rbac" || *scanType == "all" {
		rbacIssues := scanRBAC(client, *namespace)
		allIssues = append(allIssues, rbacIssues...)
	}

	outputResults(allIssues, *outputFormat)
}

func scanPods(client *k8s.Client, namespace string) []scanner.SecurityIssue {
	var issues []scanner.SecurityIssue
	podScanner := scanner.NewPodScanner()

	var pods *corev1.PodList
	var err error

	if namespace != "" {
		pods, err = client.Clientset.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{})
	} else {
		pods, err = client.Clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	}

	if err != nil {
		log.Printf("Failed to list pods: %v", err)
		return issues
	}

	for _, pod := range pods.Items {
		podIssues := podScanner.ScanPod(&pod)
		issues = append(issues, podIssues...)
	}

	return issues
}

func scanRBAC(client *k8s.Client, namespace string) []scanner.SecurityIssue {
	var issues []scanner.SecurityIssue
	rbacScanner := scanner.NewRBACScanner()

	if namespace == "" {
		clusterRoles, err := client.Clientset.RbacV1().ClusterRoles().List(context.Background(), metav1.ListOptions{})
		if err != nil {
			log.Printf("Failed to list cluster roles: %v", err)
		} else {
			for _, role := range clusterRoles.Items {
				roleIssues := rbacScanner.ScanClusterRole(&role)
				issues = append(issues, roleIssues...)
			}
		}
	}

	roles, err := client.Clientset.RbacV1().Roles(namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Printf("Failed to list roles: %v", err)
		return issues
	}

	for _, role := range roles.Items {
		roleIssues := rbacScanner.ScanRole(&role, role.Namespace)
		issues = append(issues, roleIssues...)
	}

	return issues
}

func outputResults(issues []scanner.SecurityIssue, format string) {
	if len(issues) == 0 {
		fmt.Println("No security issues found!")
		return
	}

	if format == "json" {
		jsonData, err := json.MarshalIndent(issues, "", "  ")
		if err != nil {
			log.Printf("Failed to marshal JSON: %v", err)
			return
		}
		fmt.Println(string(jsonData))
		return
	}

	fmt.Printf("Found %d security issues:\n\n", len(issues))

	severityGroups := make(map[string][]scanner.SecurityIssue)
	for _, issue := range issues {
		severityGroups[issue.Severity] = append(severityGroups[issue.Severity], issue)
	}

	for _, severity := range []string{"HIGH", "MEDIUM", "LOW"} {
		if issues, exists := severityGroups[severity]; exists && len(issues) > 0 {
			fmt.Printf("%s SEVERITY:\n", severity)
			fmt.Println(strings.Repeat("=", len(severity)+9))
			for _, issue := range issues {
				fmt.Printf("Resource: %s/%s\n", issue.Resource, issue.Name)
				if issue.Namespace != "" {
					fmt.Printf("Namespace: %s\n", issue.Namespace)
				}
				fmt.Printf("Issue: %s\n\n", issue.Description)
			}
		}
	}
}
