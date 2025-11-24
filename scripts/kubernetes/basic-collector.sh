#!/bin/bash

# Function to display usage
usage() {
    echo "Usage: $0"
    echo "       The script will prompt for Namespace and Container selection."
}

echo "Incident Response Script for Kubernetes"
echo "======================================="

# List all namespaces
 echo "Available Namespaces:"
kubectl get namespaces -o jsonpath="{.items[*].metadata.name}" | tr ' ' '\n'
echo ""

# Prompt user to select a namespace
read -p "Enter the Namespace to set the context: " NAMESPACE

# Check if the namespace exists
if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
    echo "Error: Namespace $NAMESPACE does not exist."
    exit 1
fi

# Gather general information from the namespace
echo "Gathering general information from Namespace: $NAMESPACE"
echo "-------------------------------------------------------"

echo "1. Pods and their Containers:"
kubectl get pods --namespace "$NAMESPACE" -o wide 2> /dev/null || echo "Error: Failed to get pods."
echo ""

# Node details
echo "2. Node Details:"
kubectl get nodes -o wide 2> /dev/null || echo "Error: Failed to get node details."
echo ""

# Pod CPU and Memory usage
echo "3. Pod CPU and Memory Usage:"
kubectl top pod --namespace "$NAMESPACE" 2> /dev/null || echo "Error: Failed to get pod resource usage."
echo ""

# Services in the namespace
echo "4. Services in Namespace:"
kubectl get services --namespace "$NAMESPACE" 2> /dev/null || echo "Error: Failed to get services."
echo ""

# ConfigMaps in the namespace
echo "5. ConfigMaps in Namespace:"
kubectl get configmap --namespace "$NAMESPACE" 2> /dev/null || echo "Error: Failed to get ConfigMaps."
echo ""

# Secrets in the namespace
echo "6. Secrets in Namespace:"
kubectl get secrets --namespace "$NAMESPACE" 2> /dev/null || echo "Error: Failed to get secrets."
echo ""

# Deployments in the namespace
echo "7. Deployments in Namespace:"
kubectl get deployments --namespace "$NAMESPACE" 2> /dev/null || echo "Error: Failed to get deployments."
echo ""

# StatefulSets in the namespace
echo "8. StatefulSets in Namespace:"
kubectl get statefulsets --namespace "$NAMESPACE" 2> /dev/null || echo "Error: Failed to get StatefulSets."
echo ""

# Resource Quota and Limits
echo "9. Resource Quotas and Limits in Namespace:"
kubectl describe quota --namespace "$NAMESPACE" 2> /dev/null || echo "Error: Failed to get resource quota."
kubectl describe limitrange --namespace "$NAMESPACE" 2> /dev/null || echo "Error: Failed to get limit range."
echo ""

# List all containers in the namespace
echo "Containers in Namespace $NAMESPACE:"
kubectl get pods --namespace "$NAMESPACE" -o=jsonpath='{range .items[*]}{.metadata.name}{":\n"}{range .spec.containers[*]}  - {.name}{"\n"}{end}{end}' 2> /dev/null || echo "Error: Failed to get container details."
echo ""

# Prompt user to select a container or press enter to list all
read -p "Enter the Container name to gather details or press Enter to list all: " CONTAINER_NAME

# Process pods and containers based on the user input
if [ -n "$CONTAINER_NAME" ]; then
    echo "Gathering details for Container: $CONTAINER_NAME in Namespace: $NAMESPACE"
    echo "------------------------------------------------------------------------"
    
    PODS=$(kubectl get pods --namespace "$NAMESPACE" -o jsonpath="{.items[*].metadata.name}")

    for POD in $PODS; do
        if kubectl get pod "$POD" --namespace "$NAMESPACE" -o jsonpath="{.spec.containers[?(@.name=='$CONTAINER_NAME')].name}" &> /dev/null; then
            echo "Fetching details for Pod: $POD, Container: $CONTAINER_NAME"
            kubectl describe pod "$POD" --namespace "$NAMESPACE"
            kubectl logs "$POD" -c "$CONTAINER_NAME" --namespace "$NAMESPACE"
            kubectl get events --namespace "$NAMESPACE" --field-selector involvedObject.name="$POD",involvedObject.kind=Pod
        fi
    done
else
    echo "Listing details for all Containers in Namespace: $NAMESPACE."
    PODS=$(kubectl get pods --namespace "$NAMESPACE" -o jsonpath="{.items[*].metadata.name}")

    for POD in $PODS; do
        echo "Fetching details for Pod: $POD"
        kubectl describe pod "$POD" --namespace "$NAMESPACE"
        kubectl logs "$POD" --namespace "$NAMESPACE" --all-containers=true
        kubectl get events --namespace "$NAMESPACE" --field-selector involvedObject.name="$POD",involvedObject.kind=Pod
    done
fi

echo "Incident response data collection complete."
