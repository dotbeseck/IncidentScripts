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

# ... [Include here the general information gathering commands as above]

# List all containers in the namespace
echo "Containers in Namespace $NAMESPACE:"
kubectl get pods --namespace "$NAMESPACE" -o=jsonpath='{range .items[*]}{.metadata.name}{":\n"}{range .spec.containers[*]}  - {.name}{"\n"}{end}{end}'
echo ""

# Prompt user to select a container or press enter to list all
read -p "Enter the Container name to gather details or press Enter to list all: " CONTAINER_NAME

# Process pods and containers based on the user input
if [ -n "$CONTAINER_NAME" ]; then
    echo "Gathering details for Container: $CONTAINER_NAME in Namespace: $NAMESPACE"
    echo "------------------------------------------------------------------------"
    
    PODS=$(kubectl get pods --namespace "$NAMESPACE" -o=jsonpath="{.items[*].metadata.name}")

    for POD in $PODS; do
        # Attempt to get logs for specified container and handle error if it does not exist in this pod
        if kubectl get pod "$POD" --namespace "$NAMESPACE" -o jsonpath="{.spec.containers[?(@.name=='$CONTAINER_NAME')].name}" &> /dev/null; then
            echo "Fetching details for Pod: $POD, Container: $CONTAINER_NAME"
            kubectl describe pod "$POD" --namespace "$NAMESPACE"
            kubectl logs "$POD" -c "$CONTAINER_NAME" --namespace "$NAMESPACE"
            kubectl get events --namespace "$NAMESPACE" --field-selector involvedObject.name="$POD",involvedObject.kind=Pod
        else
            echo "Warning: Container $CONTAINER_NAME not found in Pod $POD."
        fi
    done
else
    echo "Listing details for all Containers in Namespace: $NAMESPACE."
    PODS=$(kubectl get pods --namespace "$NAMESPACE" -o=jsonpath="{.items[*].metadata.name}")

    for POD in $PODS; do
        echo "Fetching details for Pod: $POD"
        kubectl describe pod "$POD" --namespace "$NAMESPACE"
        kubectl logs "$POD" --namespace "$NAMESPACE" --all-containers=true
        kubectl get events --namespace "$NAMESPACE" --field-selector involvedObject.name="$POD",involvedObject.kind=Pod
    done
fi

echo "Incident response data collection complete."
