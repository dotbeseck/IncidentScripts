#!/usr/bin/env python3

import boto3
import argparse
import time
import sys
from botocore.exceptions import ClientError
from incident_scripts.utils.logger import setup_logger

# Set up logging
logger = setup_logger(__name__)

class ForensicSnapshot:
    def __init__(self, target_account_id, source_account_id=None):
        self.target_account_id = target_account_id
        self.session = boto3.Session()
        
        # Get source account ID if not provided
        if source_account_id:
            self.source_account_id = source_account_id
        else:
            sts = self.session.client('sts')
            self.source_account_id = sts.get_caller_identity()['Account']
            logger.info(f"Detected source account ID: {self.source_account_id}")

    def get_all_regions(self):
        """Get list of all AWS regions"""
        ec2 = self.session.client('ec2')
        try:
            regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
            return regions
        except ClientError as e:
            logger.error(f"Error getting regions: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error getting regions: {e}")
            return []

    def find_instance_region(self, instance_id):
        """Find which region an instance is in"""
        for region in self.get_all_regions():
            try:
                ec2 = self.session.client('ec2', region_name=region)
                ec2.describe_instances(InstanceIds=[instance_id])
                logger.info(f"Found instance {instance_id} in region {region}")
                return region
            except ClientError as e:
                if e.response['Error']['Code'] != 'InvalidInstanceID.NotFound':
                    logger.warning(f"Error checking region {region}: {e}")
                continue
        logger.error(f"Instance {instance_id} not found in any region")
        return None

    def create_snapshots(self, instance_id, region):
        """Create snapshots of all volumes attached to an instance"""
        ec2 = self.session.client('ec2', region_name=region)
        snapshots = []

        try:
            # Get instance volumes
            response = ec2.describe_instances(InstanceIds=[instance_id])
            volumes = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    for device in instance['BlockDeviceMappings']:
                        if 'Ebs' in device:
                            volumes.append(device['Ebs']['VolumeId'])

            # Create snapshot for each volume
            for volume_id in volumes:
                logger.info(f"Creating snapshot for volume {volume_id}")
                snapshot = ec2.create_snapshot(
                    VolumeId=volume_id,
                    Description=f"CSIRT snapshot for {instance_id}",
                    TagSpecifications=[{
                        'ResourceType': 'snapshot',
                        'Tags': [{
                            'Key': 'Name',
                            'Value': f'CSIRT_{instance_id}'
                        }]
                    }]
                )
                snapshots.append(snapshot['SnapshotId'])
                
                # Wait for snapshot completion
                logger.info(f"Waiting for snapshot {snapshot['SnapshotId']} to complete...")
                waiter = ec2.get_waiter('snapshot_completed')
                waiter.wait(SnapshotIds=[snapshot['SnapshotId']])

            return snapshots
        except ClientError as e:
            logger.error(f"Error creating snapshots: {e}")
            return []

    def share_snapshot(self, snapshot_id, region):
        """Share a snapshot with the target account"""
        ec2 = self.session.client('ec2', region_name=region)
        try:
            # Share the snapshot
            ec2.modify_snapshot_attribute(
                SnapshotId=snapshot_id,
                Attribute='createVolumePermission',
                OperationType='add',
                UserIds=[self.target_account_id]
            )
            logger.info(f"Shared snapshot {snapshot_id} with account {self.target_account_id}")
            return True
        except ClientError as e:
            logger.error(f"Error sharing snapshot: {e}")
            return False

    def copy_snapshot(self, snapshot_id, source_region, target_region):
        """Copy a snapshot to another region"""
        target_ec2 = self.session.client('ec2', region_name=target_region)
        try:
            # Copy the snapshot
            response = target_ec2.copy_snapshot(
                SourceRegion=source_region,
                SourceSnapshotId=snapshot_id,
                Description=f'Cross-region copy of {snapshot_id}',
                SourceOwner=self.source_account_id
            )
            new_snapshot_id = response['SnapshotId']
            
            # Wait for the copy to complete
            logger.info(f"Waiting for snapshot copy {new_snapshot_id} to complete...")
            waiter = target_ec2.get_waiter('snapshot_completed')
            waiter.wait(SnapshotIds=[new_snapshot_id])
            
            return new_snapshot_id
        except ClientError as e:
            logger.error(f"Error copying snapshot: {e}")
            return None

    def create_and_attach_volume(self, snapshot_id, instance_id, region):
        """Create a volume from a snapshot and attach it to an instance"""
        ec2 = self.session.client('ec2', region_name=region)
        try:
            # Get instance AZ
            response = ec2.describe_instances(InstanceIds=[instance_id])
            az = response['Reservations'][0]['Instances'][0]['Placement']['AvailabilityZone']
            
            # Create volume
            logger.info(f"Creating volume from snapshot {snapshot_id} in {az}")
            volume = ec2.create_volume(
                SnapshotId=snapshot_id,
                AvailabilityZone=az,
                TagSpecifications=[{
                    'ResourceType': 'volume',
                    'Tags': [{
                        'Key': 'Name',
                        'Value': f'CSIRT_{instance_id}'
                    }]
                }]
            )
            
            # Wait for volume to be available
            logger.info("Waiting for volume to become available...")
            waiter = ec2.get_waiter('volume_available')
            waiter.wait(VolumeIds=[volume['VolumeId']])
            
            # Find next available device name
            response = ec2.describe_instances(InstanceIds=[instance_id])
            used_devices = set()
            for device in response['Reservations'][0]['Instances'][0].get('BlockDeviceMappings', []):
                used_devices.add(device['DeviceName'])
            
            # Generate device name
            device_letter = 'h'
            while f"/dev/xvd{device_letter}" in used_devices:
                device_letter = chr(ord(device_letter) + 1)
            device_name = f"/dev/xvd{device_letter}"
            
            # Attach volume
            logger.info(f"Attaching volume {volume['VolumeId']} to {instance_id} at {device_name}")
            ec2.attach_volume(
                VolumeId=volume['VolumeId'],
                InstanceId=instance_id,
                Device=device_name
            )
            
            return volume['VolumeId']
        except ClientError as e:
            logger.error(f"Error creating/attaching volume: {e}")
            return None

def parse_args():
    parser = argparse.ArgumentParser(description='AWS Forensic Snapshot Tool')
    parser.add_argument('-t', '--target-account', required=True,
                      help='Target AWS Account ID')
    parser.add_argument('-s', '--source-account',
                      help='Source AWS Account ID (optional)')
    parser.add_argument('-f', '--file',
                      help='File containing instance IDs (one per line)')
    parser.add_argument('instances', nargs='*',
                      help='Instance IDs to process')
    return parser.parse_args()

def main():
    args = parse_args()
    
    # Get instance IDs
    instance_ids = []
    if args.file:
        try:
            with open(args.file, 'r') as f:
                instance_ids.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            logger.error(f"File not found: {args.file}")
            sys.exit(1)
    instance_ids.extend(args.instances)
    
    if not instance_ids:
        logger.error("No instance IDs provided")
        sys.exit(1)
    
    # Initialize forensic snapshot tool
    tool = ForensicSnapshot(args.target_account, args.source_account)
    
    # Process each instance
    for instance_id in instance_ids:
        logger.info(f"Processing instance: {instance_id}")
        
        # Find instance region
        region = tool.find_instance_region(instance_id)
        if not region:
            continue
        
        # Create snapshots
        snapshots = tool.create_snapshots(instance_id, region)
        if not snapshots:
            continue
        
        # Share snapshots
        for snapshot_id in snapshots:
            if tool.share_snapshot(snapshot_id, region):
                logger.info(f"Successfully shared snapshot {snapshot_id}")
            else:
                continue
        
        # Prompt for target account credentials
        print("\nSwitch to target account credentials before continuing.")
        input("Press Enter when ready with target account credentials...")
        
        # Create new session for target account
        tool = ForensicSnapshot(args.target_account)
        
        # Get target instance
        target_instance = input("Enter target instance ID for volume attachment: ")
        target_region = tool.find_instance_region(target_instance)
        if not target_region:
            continue
        
        # Process each snapshot
        for snapshot_id in snapshots:
            # Copy snapshot if regions are different
            if region != target_region:
                logger.info(f"Copying snapshot to target region {target_region}")
                snapshot_id = tool.copy_snapshot(snapshot_id, region, target_region)
                if not snapshot_id:
                    continue
            
            # Create and attach volume
            volume_id = tool.create_and_attach_volume(snapshot_id, target_instance, target_region)
            if volume_id:
                logger.info(f"Successfully created and attached volume {volume_id}")

if __name__ == '__main__':
    main()
