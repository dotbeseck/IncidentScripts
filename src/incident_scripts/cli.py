import argparse
import sys
from incident_scripts.utils.logger import setup_logger

logger = setup_logger(__name__)

def main():
    parser = argparse.ArgumentParser(description="Incident Response Scripts CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # AWS Subparser
    aws_parser = subparsers.add_parser("aws", help="AWS Forensic Tools")
    aws_subparsers = aws_parser.add_subparsers(dest="aws_command")
    
    # AWS Snapshot
    snapshot_parser = aws_subparsers.add_parser("snapshot", help="Create forensic snapshots")
    snapshot_parser.add_argument("-t", "--target-account", required=True, help="Target AWS Account ID")
    snapshot_parser.add_argument("-i", "--instances", nargs="+", help="Instance IDs")

    # Kubernetes Subparser
    k8s_parser = subparsers.add_parser("k8s", help="Kubernetes Analysis Tools")
    k8s_subparsers = k8s_parser.add_subparsers(dest="k8s_command")
    
    # K8s Audit
    audit_parser = k8s_subparsers.add_parser("audit", help="Parse audit logs")
    audit_parser.add_argument("logfile", help="Path to audit log file")

    args = parser.parse_args()

    if args.command == "aws":
        if args.aws_command == "snapshot":
            from incident_scripts.aws.forensic_snapshot import main as snapshot_main
            # We might need to adapt the main function or call the class directly
            # For now, let's assume we can import and run logic. 
            # Since the original script uses argparse, we might need to refactor it to accept args or call it via subprocess if we want to keep it as is.
            # But better to import.
            sys.argv = [sys.argv[0]] + ["-t", args.target_account] + args.instances
            snapshot_main()
    elif args.command == "k8s":
        if args.k8s_command == "audit":
            from incident_scripts.kubernetes.audit_parser import main as audit_main
            sys.argv = [sys.argv[0], args.logfile]
            audit_main()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
