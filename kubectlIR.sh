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

# List all containers in the namespace
echo "Containers in Namespace $NAMESPACE:"
kubectl get pods --namespace "$NAMESPACE" -o=jsonpath='{range .items[*]}{.metadata.name}{":\n"}{range .spec.containers[*]}  - {.name}{"\n"}{end}{end}'
echo ""

# Prompt user to select a container or press enter to list all
read -p "Enter the Container name to gather details or press Enter to list all: " CONTAINER_NAME

# If a specific container is provided
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
        processPod "$POD" "$NAMESPACE" "$CONTAINER_NAME"
    done
else
    echo "Listing details for all Containers in Namespace $NAMESPACE."
    echo "-----------------------------------------------------------"
    PODS=$(kubectl get pods --namespace "$NAMESPACE" -o=jsonpath='{.items[*].metadata.name}')

    for POD in $PODS; do
        CONTAINERS=$(kubectl get pod "$POD" --namespace "$NAMESPACE" -o=jsonpath='{.spec.containers[*].name}')
        for CONTAINER in $CONTAINERS; do
            processPod "$POD" "$NAMESPACE" "$CONTAINER"
        done
    done
fi

echo "Incident response data collection complete."

# Function to process each pod and container
processPod() {
    local POD=$1
    local NAMESPACE=$2
    local CONTAINER=$3

    echo "Fetching details for Pod: $POD, Container: $CONTAINER"

    # Get Pod Description
    echo "1. Pod Description for $POD"
    echo "----------------------------"
    kubectl describe pod "$POD" --namespace "$NAMESPACE"
    echo ""

    # Get Container Logs
    echo "2. Logs for Container $CONTAINER in Pod $POD"
    echo "--------------------------------------------------"
    kubectl logs "$POD" -c "$CONTAINER" --namespace "$NAMESPACE"
    echo ""

    # Get Events related to the Container
    echo "3. Events related to Container $CONTAINER in Pod $POD"
    echo "---------------------------------------------------------"
    kubectl get events --namespace "$NAMESPACE" --field-selector involvedObject.name="$POD",involvedObject.kind=Pod,involvedObject.fieldPath="spec.containers{$CONTAINER}"
    echo ""
}
