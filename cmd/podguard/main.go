package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"podguard/pkg/k8s"
	"podguard/pkg/scanner"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func main() {
	kubeconfig := flag.String("kubeconfig", "", "Path to kubeconfig file")
	namespace := flag.String("namespace", "", "Namespace to scan (default: all namespaces)")
	outputFormat := flag.String("output", "table", "Output format (table, json, markdown)")
	outputFile := flag.String("output-file", "", "Write output to a file (optional)")
	scanType := flag.String("type", "all", "Scan type (pods, rbac, network, resources, serviceaccounts, all)")
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

	if *scanType == "resources" || *scanType == "all" {
		resourceIssues := scanResources(client, *namespace)
		allIssues = append(allIssues, resourceIssues...)
	}

	if *scanType == "network" || *scanType == "all" {
		networkIssues := scanNetwork(client, *namespace)
		allIssues = append(allIssues, networkIssues...)
	}

	if *scanType == "serviceaccounts" || *scanType == "all" {
		serviceAccountIssues := scanServiceAccounts(client, *namespace)
		allIssues = append(allIssues, serviceAccountIssues...)
	}

	outputResults(allIssues, *outputFormat, *outputFile)
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

func scanResources(client *k8s.Client, namespace string) []scanner.SecurityIssue {
	var issues []scanner.SecurityIssue
	resourceScanner := scanner.NewResourceScanner()

	var pods *corev1.PodList
	var err error

	if namespace != "" {
		pods, err = client.Clientset.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{})
	} else {
		pods, err = client.Clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	}

	if err != nil {
		log.Printf("Failed to list pods for resource scan: %v", err)
		return issues
	}

	for _, pod := range pods.Items {
		podIssues := resourceScanner.ScanPodResources(&pod)
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

func scanNetwork(client *k8s.Client, namespace string) []scanner.SecurityIssue {
	var issues []scanner.SecurityIssue
	netpolScanner := scanner.NewNetworkPolicyScanner()
	nsScanner := scanner.NewNamespaceScanner()

	var netpols *networkingv1.NetworkPolicyList
	var err error

	if namespace != "" {
		netpols, err = client.Clientset.NetworkingV1().NetworkPolicies(namespace).List(context.Background(), metav1.ListOptions{})
	} else {
		netpols, err = client.Clientset.NetworkingV1().NetworkPolicies("").List(context.Background(), metav1.ListOptions{})
	}
	if err != nil {
		log.Printf("Failed to list network policies: %v", err)
		return issues
	}

	for i := range netpols.Items {
		policy := &netpols.Items[i]
		policyIssues := netpolScanner.ScanNetworkPolicy(policy, policy.Namespace)
		issues = append(issues, policyIssues...)
	}

	namespaceNames := []string{}
	if namespace != "" {
		namespaceNames = append(namespaceNames, namespace)
	} else {
		namespaces, err := client.Clientset.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
		if err != nil {
			log.Printf("Failed to list namespaces: %v", err)
			return issues
		}
		for _, ns := range namespaces.Items {
			namespaceNames = append(namespaceNames, ns.Name)
		}
	}

	policies := netpols.Items
	for _, ns := range namespaceNames {
		nsIssues := nsScanner.ScanNamespace(ns, policies)
		issues = append(issues, nsIssues...)
	}

	return issues
}

func scanServiceAccounts(client *k8s.Client, namespace string) []scanner.SecurityIssue {
	var issues []scanner.SecurityIssue
	saScanner := scanner.NewServiceAccountScanner()

	if namespace != "" {
		serviceAccounts, err := client.Clientset.CoreV1().ServiceAccounts(namespace).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			log.Printf("Failed to list service accounts: %v", err)
			return issues
		}
		for _, sa := range serviceAccounts.Items {
			issues = append(issues, saScanner.ScanServiceAccount(&sa)...)
		}
		return issues
	}

	nsList, err := client.Clientset.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Printf("Failed to list namespaces: %v", err)
		return issues
	}
	for _, ns := range nsList.Items {
		serviceAccounts, err := client.Clientset.CoreV1().ServiceAccounts(ns.Name).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			log.Printf("Failed to list service accounts for namespace %s: %v", ns.Name, err)
			continue
		}
		for _, sa := range serviceAccounts.Items {
			issues = append(issues, saScanner.ScanServiceAccount(&sa)...)
		}
	}

	return issues
}

func outputResults(issues []scanner.SecurityIssue, format string, outputFile string) {
	if len(issues) == 0 {
		message := "No security issues found!"
		fmt.Println(message)
		if outputFile != "" {
			if err := os.WriteFile(outputFile, []byte(message+"\n"), 0644); err != nil {
				log.Printf("Failed to write output file: %v", err)
			}
		}
		return
	}

	if format == "json" {
		jsonData, err := json.MarshalIndent(issues, "", "  ")
		if err != nil {
			log.Printf("Failed to marshal JSON: %v", err)
			return
		}
		output := string(jsonData) + "\n"
		fmt.Print(output)
		if outputFile != "" {
			if err := os.WriteFile(outputFile, []byte(output), 0644); err != nil {
				log.Printf("Failed to write output file: %v", err)
			}
		}
		return
	}

	output := buildHumanOutput(issues, format)
	fmt.Print(output)
	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(output), 0644); err != nil {
			log.Printf("Failed to write output file: %v", err)
		}
	}
}

func buildHumanOutput(issues []scanner.SecurityIssue, format string) string {
	if format == "markdown" || format == "md" {
		return buildMarkdownOutput(issues)
	}

	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("Found %d security issues:\n\n", len(issues)))

	severityGroups := make(map[string][]scanner.SecurityIssue)
	for _, issue := range issues {
		severityGroups[issue.Severity] = append(severityGroups[issue.Severity], issue)
	}

	for _, severity := range []string{"HIGH", "MEDIUM", "LOW"} {
		if issues, exists := severityGroups[severity]; exists && len(issues) > 0 {
			builder.WriteString(fmt.Sprintf("%s SEVERITY:\n", severity))
			builder.WriteString(strings.Repeat("=", len(severity)+9))
			builder.WriteString("\n")
			for _, issue := range issues {
				builder.WriteString(fmt.Sprintf("Resource: %s/%s\n", issue.Resource, issue.Name))
				if issue.Namespace != "" {
					builder.WriteString(fmt.Sprintf("Namespace: %s\n", issue.Namespace))
				}
				builder.WriteString(fmt.Sprintf("Issue: %s\n\n", issue.Description))
			}
		}
	}

	return builder.String()
}

func buildMarkdownOutput(issues []scanner.SecurityIssue) string {
	var builder strings.Builder
	builder.WriteString("# PodGuard Security Report\n\n")
	builder.WriteString(fmt.Sprintf("Found %d security issues.\n\n", len(issues)))

	counts := map[string]int{"HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, issue := range issues {
		counts[issue.Severity]++
	}
	builder.WriteString("Severity summary:\n")
	builder.WriteString(fmt.Sprintf("- HIGH: %d\n", counts["HIGH"]))
	builder.WriteString(fmt.Sprintf("- MEDIUM: %d\n", counts["MEDIUM"]))
	builder.WriteString(fmt.Sprintf("- LOW: %d\n\n", counts["LOW"]))

	builder.WriteString("| Severity | Resource | Namespace | Name | Issue |\n")
	builder.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, issue := range issues {
		namespace := issue.Namespace
		if namespace == "" {
			namespace = "-"
		}
		description := strings.ReplaceAll(issue.Description, "\n", " ")
		builder.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n", issue.Severity, issue.Resource, namespace, issue.Name, description))
	}

	return builder.String()
}
