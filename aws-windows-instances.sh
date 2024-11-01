#!/bin/bash

# Get all AWS regions
regions=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)

echo "Searching for running Windows instances across all regions..."
echo "Region | Instance ID | Name | Instance Type | Private IP | Platform | State"
echo "-------|-------------|------|---------------|------------|-----------|-------"

for region in $regions; do
    # Set the AWS region
    export AWS_DEFAULT_REGION=$region
    
    # Describe instances with filters for Windows and running state
    instances=$(aws ec2 describe-instances \
        --filters "Name=platform,Values=windows" "Name=instance-state-name,Values=running" \
        --query 'Reservations[].Instances[].[InstanceId,Tags[?Key==`Name`].Value | [0],InstanceType,PrivateIpAddress,Platform,State.Name]' \
        --output text 2>/dev/null)
    
    # Check if any instances were found
    if [ ! -z "$instances" ]; then
        while read -r instance; do
            # Format the output
            instance_id=$(echo $instance | awk '{print $1}')
            name=$(echo $instance | awk '{print $2}')
            instance_type=$(echo $instance | awk '{print $3}')
            private_ip=$(echo $instance | awk '{print $4}')
            platform=$(echo $instance | awk '{print $5}')
            state=$(echo $instance | awk '{print $6}')
            
            # Handle cases where name tag might be missing
            if [ "$name" == "None" ]; then
                name="<No Name>"
            fi
            
            echo "$region | $instance_id | $name | $instance_type | $private_ip | $platform | $state"
        done <<< "$instances"
    fi
done
