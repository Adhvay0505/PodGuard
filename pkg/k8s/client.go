package k8s

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Client struct {
	Clientset *kubernetes.Clientset
	Config    *rest.Config
}

func NewClient(kubeconfigPath string) (*Client, error) {
	var config *rest.Config
	var err error

	if kubeconfigPath != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	} else {
		config, err = rest.InClusterConfig()
		if err != nil {
			config, err = clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
		}
	}

	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &Client{
		Clientset: clientset,
		Config:    config,
	}, nil
}
