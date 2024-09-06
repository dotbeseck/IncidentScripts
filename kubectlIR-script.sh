#!/bin/bash

# Function to display usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  -n, --namespace NAMESPACE   Specify the namespace (optional)"
    echo "  -c, --container CONTAINER   Specify the container name (optional)"
    echo "  -o, --output DIRECTORY      Specify the output directory (default: current directory)"
    echo "  -h, --help                  Display this help message"
}

# Parse command-line arguments
NAMESPACE=""
CONTAINER_NAME=""
OUTPUT_DIR="$(pwd)/k8s_incident_response_$(date +%Y%m%d_%H%M%S)"

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -n|--namespace)
        NAMESPACE="$2"
        shift 2
        ;;
        -c|--container)
        CONTAINER_NAME="$2"
        shift 2
        ;;
        -o|--output)
        OUTPUT_DIR="$2"
        shift 2
        ;;
        -h|--help)
        usage
        exit 0
        ;;
        *)
        echo "Unknown option: $1"
        usage
        exit 1
        ;;
    esac
done

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Function to log output
log_output() {
    local file_name="$1"
    local command="$2"
    echo "Executing: $command"
    eval "$command" > "$OUTPUT_DIR/$file_name" 2>&1 || echo "Error: Failed to execute command."
}

echo "Kubernetes Incident Response Script"
echo "==================================="

# If namespace is not provided, list and prompt for selection
if [ -z "$NAMESPACE" ]; then
     echo "Available Namespaces:"
    kubectl get namespaces -o jsonpath="{.items[*].metadata.name}" | tr ' ' '\n'
    echo ""
    read -p "Enter the Namespace to set the context: " NAMESPACE
fi

# Check if the namespace exists
if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
    echo "Error: Namespace $NAMESPACE does not exist."
    exit 1
fi

echo "Gathering information from Namespace: $NAMESPACE"
echo "-----------------------------------------------"

# Gather cluster-wide information
log_output "01_cluster_info.txt" "kubectl cluster-info dump"
log_output "02_nodes.txt" "kubectl get nodes -o wide"
log_output "03_events.txt" "kubectl get events --all-namespaces"

# Gather namespace-specific information
log_output "04_pods.txt" "kubectl get pods --namespace $NAMESPACE -o wide"
log_output "05_services.txt" "kubectl get services --namespace $NAMESPACE -o wide"
log_output "06_deployments.txt" "kubectl get deployments --namespace $NAMESPACE -o wide"
log_output "07_statefulsets.txt" "kubectl get statefulsets --namespace $NAMESPACE -o wide"
log_output "08_daemonsets.txt" "kubectl get daemonsets --namespace $NAMESPACE -o wide"
log_output "09_configmaps.txt" "kubectl get configmaps --namespace $NAMESPACE -o yaml"
log_output "10_secrets.txt" "kubectl get secrets --namespace $NAMESPACE"
log_output "11_ingress.txt" "kubectl get ingress --namespace $NAMESPACE -o yaml"
log_output "12_pv_pvc.txt" "kubectl get pv,pvc --namespace $NAMESPACE -o wide"
log_output "13_resource_quotas.txt" "kubectl describe quota --namespace $NAMESPACE"
log_output "14_limit_ranges.txt" "kubectl describe limitrange --namespace $NAMESPACE"
log_output "15_network_policies.txt" "kubectl get networkpolicies --namespace $NAMESPACE -o yaml"

# Function to gather pod-specific information
gather_pod_info() {
    local pod="$1"
    local pod_dir="$OUTPUT_DIR/pods/$pod"
    mkdir -p "$pod_dir"
    
    log_output "$pod_dir/describe.txt" "kubectl describe pod $pod --namespace $NAMESPACE"
    log_output "$pod_dir/logs.txt" "kubectl logs $pod --namespace $NAMESPACE --all-containers=true"
    log_output "$pod_dir/events.txt" "kubectl get events --namespace $NAMESPACE --field-selector involvedObject.name=$pod,involvedObject.kind=Pod"
}

# Gather information for all pods or a specific container
if [ -n "$CONTAINER_NAME" ]; then
    echo "Gathering details for Container: $CONTAINER_NAME in Namespace: $NAMESPACE"
    PODS=$(kubectl get pods --namespace "$NAMESPACE" -o jsonpath="{.items[*].metadata.name}")
    for POD in $PODS; do
        if kubectl get pod "$POD" --namespace "$NAMESPACE" -o jsonpath="{.spec.containers[?(@.name=='$CONTAINER_NAME')].name}" &> /dev/null; then
            gather_pod_info "$POD"
        fi
    done
else
    echo "Gathering details for all Pods in Namespace: $NAMESPACE"
    PODS=$(kubectl get pods --namespace "$NAMESPACE" -o jsonpath="{.items[*].metadata.name}")
    for POD in $PODS; do
        gather_pod_info "$POD"
    done
fi

echo "Incident response data collection complete. Output saved to: $OUTPUT_DIR"
