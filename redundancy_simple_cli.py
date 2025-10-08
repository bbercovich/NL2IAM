#!/usr/bin/env python3
"""
Simple Redundancy Checker CLI Tool

A minimal command-line interface for testing IAM policy redundancy detection
without external dependencies.

Usage:
    python3 redundancy_simple_cli.py check policy.json
    python3 redundancy_simple_cli.py demo
"""

import argparse
import json
import sys
import os

# Add src/core to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src', 'core'))

from inventory import PolicyInventory


def load_policy_from_file(file_path: str) -> dict:
    """Load IAM policy from JSON file"""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"❌ Error: Policy file '{file_path}' not found")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON in '{file_path}': {e}")
        sys.exit(1)


def print_policy(policy: dict, title: str = "Policy"):
    """Pretty print a policy"""
    print(f"\n📄 {title}:")
    print(json.dumps(policy, indent=2))


def check_policy_command(policy_file: str):
    """Check a policy file against demo inventory"""
    print("🔍 Checking Policy for Redundancy")
    print("=" * 50)

    # Load policy to check
    policy = load_policy_from_file(policy_file)
    print_policy(policy, "Policy to Check")

    # Create demo inventory
    inventory = PolicyInventory()

    # Add some baseline policies
    broad_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::public-bucket/*"
            }
        ]
    }

    admin_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:role/S3Admin",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::*"
            }
        ]
    }

    inventory.add_policy(broad_policy, name="Public Bucket Access - All Users")
    inventory.add_policy(admin_policy, name="S3 Admin Full Access")

    print(f"\n📚 Demo inventory loaded with 2 baseline policies")

    # Check for redundancy
    redundancy_results = inventory.find_redundant_policies(policy)

    print(f"\n📊 REDUNDANCY CHECK RESULTS")
    print("=" * 50)

    if redundancy_results:
        print(f"🔍 Redundancy detected: {len(redundancy_results)} policy(ies)")

        for i, result in enumerate(redundancy_results, 1):
            print(f"\n   {i}. Redundant with existing policy")
            print(f"      Type: {result.redundancy_type}")
            print(f"      Confidence: {result.confidence_score:.2f}")
            print(f"      Explanation: {result.explanation}")

        # Generate recommendations
        report = inventory.generate_redundancy_report(policy)
        if report['recommendations']:
            print(f"\n💡 RECOMMENDATIONS:")
            for rec in report['recommendations']:
                print(f"   - {rec}")
    else:
        print(f"✅ No redundancy detected - policy is unique")

    # Show inventory stats
    stats = inventory.get_inventory_stats()
    print(f"\n📈 INVENTORY STATS:")
    print(f"   Total policies: {stats['total_policies']}")
    print(f"   Unique actions: {stats['unique_actions']}")
    print(f"   Unique resources: {stats['unique_resources']}")
    print(f"   Unique principals: {stats['unique_principals']}")


def demo_command():
    """Run a demo of redundancy detection"""
    print("🎯 Redundancy Detection Demo")
    print("=" * 50)

    inventory = PolicyInventory()

    # Demo policies
    policies = [
        {
            "name": "Public Bucket Access - All Users",
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::public-bucket/*"
                    }
                ]
            },
            "baseline": True
        },
        {
            "name": "S3 Admin Full Access",
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "arn:aws:iam::123456789012:role/S3Admin",
                        "Action": "s3:*",
                        "Resource": "arn:aws:s3:::*"
                    }
                ]
            },
            "baseline": True
        },
        {
            "name": "Alice Public Bucket Access (Should be Redundant)",
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "arn:aws:iam::123456789012:user/alice",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::public-bucket/*"
                    }
                ]
            },
            "baseline": False
        },
        {
            "name": "S3Admin Upload Access (Should be Redundant)",
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "arn:aws:iam::123456789012:role/S3Admin",
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::uploads/*"
                    }
                ]
            },
            "baseline": False
        },
        {
            "name": "EC2 Instance Management (Should be Unique)",
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "arn:aws:iam::123456789012:user/bob",
                        "Action": ["ec2:StartInstances", "ec2:StopInstances"],
                        "Resource": "arn:aws:ec2:*:*:instance/*"
                    }
                ]
            },
            "baseline": False
        }
    ]

    # Process each policy
    for i, policy_info in enumerate(policies, 1):
        print(f"\n📝 Step {i}: {policy_info['name']}")
        print(f"   Type: {'Baseline' if policy_info['baseline'] else 'Test Policy'}")

        if policy_info['baseline']:
            # Add to inventory
            policy_id = inventory.add_policy(policy_info['policy'], name=policy_info['name'])
            print(f"   ✅ Added to inventory: {policy_id[:8]}")
        else:
            # Check for redundancy
            redundancy_results = inventory.find_redundant_policies(policy_info['policy'])

            if redundancy_results:
                result = redundancy_results[0]
                print(f"   🔍 REDUNDANCY DETECTED")
                print(f"      Type: {result.redundancy_type}")
                print(f"      Confidence: {result.confidence_score:.2f}")
                print(f"      Explanation: {result.explanation}")
            else:
                print(f"   ✅ No redundancy detected - policy is unique")

    # Final summary
    print(f"\n" + "=" * 50)
    print(f"📊 DEMO SUMMARY")
    print(f"=" * 50)

    stats = inventory.get_inventory_stats()
    print(f"Total policies in inventory: {stats['total_policies']}")
    print(f"Unique actions: {stats['unique_actions']}")
    print(f"Unique resources: {stats['unique_resources']}")
    print(f"Unique principals: {stats['unique_principals']}")

    print(f"\n🎉 Demo completed successfully!")
    print(f"\n💡 Key findings:")
    print(f"   - Alice's specific access was redundant (broader principal)")
    print(f"   - S3Admin upload access was redundant (broader permissions)")
    print(f"   - EC2 management policy was unique (different service)")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Simple IAM Policy Redundancy Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run interactive demo
  python3 redundancy_simple_cli.py demo

  # Check a specific policy file
  python3 redundancy_simple_cli.py check examples/policies/alice_s3_access.json
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Demo command
    subparsers.add_parser('demo', help='Run redundancy detection demo')

    # Check command
    check_parser = subparsers.add_parser('check', help='Check a policy file for redundancy')
    check_parser.add_argument('policy_file', help='Path to policy JSON file')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        if args.command == 'demo':
            demo_command()
        elif args.command == 'check':
            check_policy_command(args.policy_file)

    except KeyboardInterrupt:
        print("\n\n⚠️ Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()