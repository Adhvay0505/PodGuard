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
	scanType := flag.String("type", "all", "Scan type (pods, rbac, resources, network, sa, nodes, availability, quotas, all)")
	flag.Parse()

	client, err := k8s.NewClient(*kubeconfig)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	var allIssues []scanner.SecurityIssue

	if *scanType == "pods" || *scanType == "all" {
		allIssues = append(allIssues, scanPods(client, *namespace)...)
	}

	if *scanType == "rbac" || *scanType == "all" {
		allIssues = append(allIssues, scanRBAC(client, *namespace)...)
	}

	if *scanType == "resources" || *scanType == "all" {
		allIssues = append(allIssues, scanResources(client, *namespace)...)
	}

	if *scanType == "network" || *scanType == "all" {
		allIssues = append(allIssues, scanNetwork(client, *namespace)...)
	}

	if *scanType == "sa" || *scanType == "all" {
		allIssues = append(allIssues, scanServiceAccounts(client, *namespace)...)
	}

	if *scanType == "nodes" || *scanType == "all" {
		allIssues = append(allIssues, scanNodes(client)...)
	}

	if *scanType == "availability" || *scanType == "all" {
		allIssues = append(allIssues, scanAvailability(client, *namespace)...)
	}

	if *scanType == "quotas" || *scanType == "all" {
		allIssues = append(allIssues, scanQuotas(client, *namespace)...)
	}

	outputResults(allIssues, *outputFormat)
}

func scanPods(client *k8s.Client, namespace string) []scanner.SecurityIssue {
	var issues []scanner.SecurityIssue
	podScanner := scanner.NewPodScanner()
	pods, err := client.Clientset.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Printf("Failed to list pods: %v", err)
		return issues
	}
	for _, pod := range pods.Items {
		issues = append(issues, podScanner.ScanPod(&pod)...)
	}
	return issues
}

func scanRBAC(client *k8s.Client, namespace string) []scanner.SecurityIssue {
	var issues []scanner.SecurityIssue
	rbacScanner := scanner.NewRBACScanner()
	if namespace == "" {
		clusterRoles, _ := client.Clientset.RbacV1().ClusterRoles().List(context.Background(), metav1.ListOptions{})
		for _, role := range clusterRoles.Items {
			issues = append(issues, rbacScanner.ScanClusterRole(&role)...)
		}
	}
	roles, _ := client.Clientset.RbacV1().Roles(namespace).List(context.Background(), metav1.ListOptions{})
	for _, role := range roles.Items {
		issues = append(issues, rbacScanner.ScanRole(&role, role.Namespace)...)
	}
	return issues
}

func scanResources(client *k8s.Client, namespace string) []scanner.SecurityIssue {
	var issues []scanner.SecurityIssue
	resourceScanner := scanner.NewResourceScanner()
	pods, _ := client.Clientset.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{})
	for _, pod := range pods.Items {
		issues = append(issues, resourceScanner.ScanPodResources(&pod)...)
	}
	return issues
}

func scanNetwork(client *k8s.Client, namespace string) []scanner.SecurityIssue {
	var issues []scanner.SecurityIssue
	netpolScanner := scanner.NewNetworkPolicyScanner()
	nsScanner := scanner.NewNamespaceScanner()
	netpols, _ := client.Clientset.NetworkingV1().NetworkPolicies(namespace).List(context.Background(), metav1.ListOptions{})
	for _, policy := range netpols.Items {
		issues = append(issues, netpolScanner.ScanNetworkPolicy(&policy, policy.Namespace)...)
	}
	var namespaces *corev1.NamespaceList
	if namespace != "" {
		ns, _ := client.Clientset.CoreV1().Namespaces().Get(context.Background(), namespace, metav1.GetOptions{})
		namespaces = &corev1.NamespaceList{Items: []corev1.Namespace{*ns}}
	} else {
		namespaces, _ = client.Clientset.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	}
	for _, ns := range namespaces.Items {
		issues = append(issues, nsScanner.ScanNamespace(ns.Name, netpols.Items)...)
	}
	return issues
}

func scanServiceAccounts(client *k8s.Client, namespace string) []scanner.SecurityIssue {
	var issues []scanner.SecurityIssue
	saScanner := scanner.NewServiceAccountScanner()
	sas, _ := client.Clientset.CoreV1().ServiceAccounts(namespace).List(context.Background(), metav1.ListOptions{})
	for _, sa := range sas.Items {
		issues = append(issues, saScanner.ScanServiceAccount(&sa)...)
	}
	return issues
}

func scanNodes(client *k8s.Client) []scanner.SecurityIssue {
	var issues []scanner.SecurityIssue
	nodeScanner := scanner.NewNodeScanner()
	nodes, _ := client.Clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	for _, node := range nodes.Items {
		issues = append(issues, nodeScanner.ScanNode(&node)...)
	}
	return issues
}

func scanAvailability(client *k8s.Client, namespace string) []scanner.SecurityIssue {
	var issues []scanner.SecurityIssue
	availabilityScanner := scanner.NewAvailabilityScanner()
	deployments, _ := client.Clientset.AppsV1().Deployments(namespace).List(context.Background(), metav1.ListOptions{})
	for _, d := range deployments.Items {
		issues = append(issues, availabilityScanner.ScanDeployment(&d)...)
	}
	statefulsets, _ := client.Clientset.AppsV1().StatefulSets(namespace).List(context.Background(), metav1.ListOptions{})
	for _, s := range statefulsets.Items {
		issues = append(issues, availabilityScanner.ScanStatefulSet(&s)...)
	}
	return issues
}

func scanQuotas(client *k8s.Client, namespace string) []scanner.SecurityIssue {
	var issues []scanner.SecurityIssue
	quotaScanner := scanner.NewNamespaceQuotaScanner()
	var namespaces *corev1.NamespaceList
	if namespace != "" {
		ns, _ := client.Clientset.CoreV1().Namespaces().Get(context.Background(), namespace, metav1.GetOptions{})
		namespaces = &corev1.NamespaceList{Items: []corev1.Namespace{*ns}}
	} else {
		namespaces, _ = client.Clientset.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	}
	for _, ns := range namespaces.Items {
		quotas, _ := client.Clientset.CoreV1().ResourceQuotas(ns.Name).List(context.Background(), metav1.ListOptions{})
		limitRanges, _ := client.Clientset.CoreV1().LimitRanges(ns.Name).List(context.Background(), metav1.ListOptions{})
		issues = append(issues, quotaScanner.ScanNamespace(ns.Name, quotas.Items, limitRanges.Items)...)
	}
	return issues
}

func outputResults(issues []scanner.SecurityIssue, format string) {
	if len(issues) == 0 {
		fmt.Println("No security issues found!")
		return
	}
	if format == "json" {
		jsonData, _ := json.MarshalIndent(issues, "", "  ")
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
