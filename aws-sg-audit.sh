#!/bin/bash

# List ports to check
PORTS_TO_CHECK=(22 3389)

# Get all AWS regions
regions=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)

echo "Scanning security groups across all AWS regions..."

for region in $regions; do
    echo "Checking region: $region"
    
    # Get all security groups in the region
    security_groups=$(aws ec2 describe-security-groups \
        --region $region \
        --query 'SecurityGroups[].[GroupId,GroupName,VpcId]' \
        --output text)
    
    if [ -z "$security_groups" ]; then
        echo "No security groups found in $region"
        continue
    fi
    
    while read -r group_id group_name vpc_id; do
        # specifically filter for rules with 0.0.0.0/0
        open_ports=$(aws ec2 describe-security-groups \
            --region $region \
            --group-ids $group_id \
            --query 'SecurityGroups[].IpPermissions[?contains(IpRanges[].CidrIp, `0.0.0.0/0`)].[FromPort,ToPort]' \
            --output text)
        
        if [ ! -z "$open_ports" ]; then
            echo ""
            echo "WARNING: Found open ports in Security Group:"
            echo "Region: $region"
            echo "Security Group ID: $group_id"
            echo "Security Group Name: $group_name"
            echo "VPC ID: $vpc_id"
            echo "Open ports to 0.0.0.0/0:"
            
            while read -r from_port to_port; do
                if [ ! -z "$from_port" ]; then
                    # Check if this is one of our listed ports and label it with a weewoo
                    for check_port in "${PORTS_TO_CHECK[@]}"; do
                        if [ "$from_port" -le "$check_port" ] && [ "$to_port" -ge "$check_port" ]; then
                            echo "- Port $from_port-$to_port (includes sensitive port $check_port)"
                            continue 2
                        fi
                    done
                    echo "- Port $from_port-$to_port"
                fi
            done <<< "$open_ports"
            echo "----------------------------------------"
        fi
    done <<< "$security_groups"
done

echo "SDonezo"
