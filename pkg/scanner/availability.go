package scanner

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	policyv1 "k8s.io/api/policy/v1"
)

type CronJobScanner struct{}

func NewCronJobScanner() *CronJobScanner {
	return &CronJobScanner{}
}

func (s *CronJobScanner) ScanCronJob(cronjob *batchv1beta1.CronJob) []SecurityIssue {
	var issues []SecurityIssue

	issues = append(issues, s.checkCronJobSchedule(cronjob)...)
	issues = append(issues, s.checkCronJobSecurityContext(cronjob)...)
	issues = append(issues, s.checkCronJobConcurrency(cronjob)...)
	issues = append(issues, s.checkCronJobFailedJobs(cronjob)...)

	return issues
}

func (s *CronJobScanner) checkCronJobSchedule(cronjob *batchv1beta1.CronJob) []SecurityIssue {
	var issues []SecurityIssue

	if cronjob.Spec.Schedule == "" {
		issues = append(issues, SecurityIssue{
			Severity:    "HIGH",
			Resource:    "CronJob",
			Namespace:   cronjob.Namespace,
			Name:        cronjob.Name,
			Description: "CronJob has no schedule defined",
		})
	}

	if cronjob.Spec.Suspend != nil && *cronjob.Spec.Suspend {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Resource:    "CronJob",
			Namespace:   cronjob.Namespace,
			Name:        cronjob.Name,
			Description: "CronJob is suspended - jobs will not run",
		})
	}

	schedule := cronjob.Spec.Schedule
	if schedule == "* * * * *" {
		issues = append(issues, SecurityIssue{
			Severity:    "HIGH",
			Resource:    "CronJob",
			Namespace:   cronjob.Namespace,
			Name:        cronjob.Name,
			Description: "CronJob runs every minute - potential resource exhaustion",
		})
	}

	return issues
}

func (s *CronJobScanner) checkCronJobSecurityContext(cronjob *batchv1beta1.CronJob) []SecurityIssue {
	var issues []SecurityIssue

	if cronjob.Spec.JobTemplate.Spec.Template.Spec.SecurityContext == nil {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "CronJob",
			Namespace:   cronjob.Namespace,
			Name:        cronjob.Name,
			Description: "CronJob does not set security context on pods",
		})
	}

	for _, container := range cronjob.Spec.JobTemplate.Spec.Template.Spec.Containers {
		if container.SecurityContext == nil {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "CronJob",
				Namespace:   cronjob.Namespace,
				Name:        cronjob.Name,
				Description: fmt.Sprintf("CronJob container '%s' does not set security context", container.Name),
			})
		}
	}

	return issues
}

func (s *CronJobScanner) checkCronJobConcurrency(cronjob *batchv1beta1.CronJob) []SecurityIssue {
	var issues []SecurityIssue

	if cronjob.Spec.ConcurrencyPolicy == "" || cronjob.Spec.ConcurrencyPolicy == "Allow" {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "CronJob",
			Namespace:   cronjob.Namespace,
			Name:        cronjob.Name,
			Description: "CronJob allows concurrent executions - may cause resource spikes",
		})
	}

	if cronjob.Spec.ConcurrencyPolicy == "Forbid" {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Resource:    "CronJob",
			Namespace:   cronjob.Namespace,
			Name:        cronjob.Name,
			Description: "CronJob forbids concurrent executions - missed jobs if longer than schedule",
		})
	}

	return issues
}

func (s *CronJobScanner) checkCronJobFailedJobs(cronjob *batchv1beta1.CronJob) []SecurityIssue {
	var issues []SecurityIssue

	if cronjob.Spec.FailedJobsHistoryLimit != nil && *cronjob.Spec.FailedJobsHistoryLimit == 0 {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "CronJob",
			Namespace:   cronjob.Namespace,
			Name:        cronjob.Name,
			Description: "CronJob does not keep failed job history - cannot debug failures",
		})
	}

	if cronjob.Spec.SuccessfulJobsHistoryLimit != nil && *cronjob.Spec.SuccessfulJobsHistoryLimit == 0 {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Resource:    "CronJob",
			Namespace:   cronjob.Namespace,
			Name:        cronjob.Name,
			Description: "CronJob does not keep successful job history",
		})
	}

	return issues
}

type PodDisruptionBudgetScanner struct{}

func NewPodDisruptionBudgetScanner() *PodDisruptionBudgetScanner {
	return &PodDisruptionBudgetScanner{}
}

func (s *PodDisruptionBudgetScanner) ScanPDB(pdb *policyv1.PodDisruptionBudget) []SecurityIssue {
	var issues []SecurityIssue

	if pdb.Spec.MinAvailable == nil && pdb.Spec.MaxUnavailable == nil {
		issues = append(issues, SecurityIssue{
			Severity:    "HIGH",
			Resource:    "PodDisruptionBudget",
			Namespace:   pdb.Namespace,
			Name:        pdb.Name,
			Description: "PodDisruptionBudget has no minAvailable or maxUnavailable set",
		})
	}

	return issues
}

type HorizontalPodAutoscalerScanner struct{}

func NewHorizontalPodAutoscalerScanner() *HorizontalPodAutoscalerScanner {
	return &HorizontalPodAutoscalerScanner{}
}

func (s *HorizontalPodAutoscalerScanner) ScanHPA(hpa *autoscalingv1.HorizontalPodAutoscaler) []SecurityIssue {
	var issues []SecurityIssue

	if hpa.Spec.MinReplicas != nil && *hpa.Spec.MinReplicas == 1 {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "HorizontalPodAutoscaler",
			Namespace:   hpa.Namespace,
			Name:        hpa.Name,
			Description: "HPA allows scaling to 1 replica - no high availability",
		})
	}

	if hpa.Spec.TargetCPUUtilizationPercentage != nil {
		if *hpa.Spec.TargetCPUUtilizationPercentage > 90 {
			issues = append(issues, SecurityIssue{
				Severity:    "MEDIUM",
				Resource:    "HorizontalPodAutoscaler",
				Namespace:   hpa.Namespace,
				Name:        hpa.Name,
				Description: "HPA triggers scaling at very high CPU utilization - risk of overload",
			})
		}
	}

	if hpa.Spec.MaxReplicas < 3 {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Resource:    "HorizontalPodAutoscaler",
			Namespace:   hpa.Namespace,
			Name:        hpa.Name,
			Description: "HPA has low max replicas - may not handle traffic spikes",
		})
	}

	return issues
}

type AvailabilityScanner struct{}

func NewAvailabilityScanner() *AvailabilityScanner {
	return &AvailabilityScanner{}
}

func (s *AvailabilityScanner) ScanDeployment(deployment *appsv1.Deployment) []SecurityIssue {
	var issues []SecurityIssue

	if deployment.Spec.Replicas != nil && *deployment.Spec.Replicas == 1 {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "Deployment",
			Namespace:   deployment.Namespace,
			Name:        deployment.Name,
			Description: "Deployment has only 1 replica - no high availability",
		})
	}

	if deployment.Spec.Strategy.Type == appsv1.RecreateDeploymentStrategyType {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Resource:    "Deployment",
			Namespace:   deployment.Namespace,
			Name:        deployment.Name,
			Description: "Deployment uses Recreate strategy - causes downtime during updates",
		})
	}

	return issues
}

func (s *AvailabilityScanner) ScanStatefulSet(statefulset *appsv1.StatefulSet) []SecurityIssue {
	var issues []SecurityIssue

	if statefulset.Spec.Replicas != nil && *statefulset.Spec.Replicas == 1 {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Resource:    "StatefulSet",
			Namespace:   statefulset.Namespace,
			Name:        statefulset.Name,
			Description: "StatefulSet has only 1 replica - no high availability",
		})
	}

	return issues
}
