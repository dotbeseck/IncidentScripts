#!/bin/bash

# Function to display usage
usage() {
    echo "Usage: $0 <pod-name> [container-name]"
    echo "       pod-name: Name of the Kubernetes Pod"
    echo "       container-name: Optional, name of a specific container in the Pod"
}

# Check minimum argument requirement
if [ "$#" -lt 1 ]; then
    usage
    exit 1
fi

POD_NAME=$1
CONTAINER_NAME=$2

echo "Incident Response Script for Kubernetes Pod"
echo "============================================"
echo "Gathering details for Pod: $POD_NAME"
echo ""

# Check if the pod exists
if ! kubectl get pod "$POD_NAME" &> /dev/null; then
    echo "Error: Pod $POD_NAME does not exist in the current context."
    exit 2
fi

# Get Pod Description
echo "1. Pod Description"
echo "------------------"
kubectl describe pod "$POD_NAME"
echo ""

# Get Pod Logs (and for specific container if provided)
echo "2. Pod Logs"
echo "-----------"
if [ -z "$CONTAINER_NAME" ]; then
    kubectl logs "$POD_NAME"
else
    echo "Fetching logs for container: $CONTAINER_NAME"
    kubectl logs "$POD_NAME" -c "$CONTAINER_NAME"
fi
echo ""

# Get Pod Status
echo "3. Pod Status"
echo "-------------"
kubectl get pod "$POD_NAME" -o wide
echo ""

# Get Events related to the Pod (and for specific container if provided)
echo "4. Related Events"
echo "-----------------"
selector="involvedObject.name=$POD_NAME"
[ -n "$CONTAINER_NAME" ] && selector="$selector,involvedObject.fieldPath=spec.containers{$CONTAINER_NAME}"
kubectl get events --field-selector "$selector"
echo ""

echo "Incident response data collection complete."
