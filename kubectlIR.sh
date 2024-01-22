#!/bin/bash

# Function to display usage
usage() {
    echo "Usage: $0 [container-name]"
    echo "       container-name: Optional, name of a specific container in any Pod within the selected Namespace"
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

# Check for container name argument
CONTAINER_NAME=$1

# List all Pods and their containers in the namespace
echo "Listing all Pods and their Containers in Namespace: $NAMESPACE"
echo "--------------------------------------------------------------"
kubectl get pods --namespace "$NAMESPACE" -o=jsonpath='{range .items[*]}{.metadata.name}{"\n"}{range .spec.containers[*]}  - {.name}{"\n"}{end}{end}'
echo ""

# If a specific container is provided, gather details for that container
if [ -n "$CONTAINER_NAME" ]; then
    echo "Gathering details for Container: $CONTAINER_NAME in Namespace: $NAMESPACE"
    echo "------------------------------------------------------------------------"
    
    # Finding all pods containing the specified container
    PODS=$(kubectl get pods --namespace "$NAMESPACE" -o=jsonpath="{.items[?(@.spec.containers[*].name=='$CONTAINER_NAME')].metadata.name}")

    # Check if any pods were found
    if [ -z "$PODS" ]; then
        echo "Error: No Pods found with Container $CONTAINER_NAME in Namespace $NAMESPACE."
        exit 2
    fi

    for POD in $PODS; do
        echo "Fetching details for Pod: $POD, Container: $CONTAINER_NAME"

        # Get Pod Description
        echo "1. Pod Description for $POD"
        echo "----------------------------"
        kubectl describe pod "$POD" --namespace "$NAMESPACE"
        echo ""

        # Get Container Logs
        echo "2. Logs for Container $CONTAINER_NAME in Pod $POD"
        echo "--------------------------------------------------"
        kubectl logs "$POD" -c "$CONTAINER_NAME" --namespace "$NAMESPACE"
        echo ""

        # Get Events related to the Container
        echo "3. Events related to Container $CONTAINER_NAME in Pod $POD"
        echo "---------------------------------------------------------"
        kubectl get events --namespace "$NAMESPACE" --field-selector involvedObject.name="$POD",involvedObject.kind=Pod,involvedObject.fieldPath="spec.containers{$CONTAINER_NAME}"
        echo ""
    done
else
    echo "No specific container specified. Listing completed for all Pods and Containers in Namespace $NAMESPACE."
fi

echo "Incident response data collection complete."
