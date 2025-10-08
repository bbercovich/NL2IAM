#!/usr/bin/env python3
"""
Redundancy Checker CLI Tool

A command-line interface for testing IAM policy redundancy detection.
This tool demonstrates the complete redundancy checking workflow and can be used
for manual testing and validation.

Usage:
    python3 redundancy_cli.py --check policy.json
    python3 redundancy_cli.py --add-policy policy.json --name "Policy Name"
    python3 redundancy_cli.py --list-policies
    python3 redundancy_cli.py --clear-inventory
"""

import argparse
import json
import sys
import os
from pathlib import Path

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from agents.redundancy_checker import RedundancyChecker


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


def check_policy_redundancy(args):
    """Check a policy for redundancy"""
    print("🔍 Checking Policy for Redundancy")
    print("=" * 50)

    # Load policy
    policy = load_policy_from_file(args.check)
    policy_name = args.name or f"Policy from {args.check}"

    print_policy(policy, "Policy to Check")

    # Initialize checker
    inventory_path = args.inventory or "./data/policy_inventory.json"
    checker = RedundancyChecker(inventory_path=inventory_path)

    # Check for redundancy
    result = checker.check_redundancy(
        policy,
        policy_name=policy_name,
        add_to_inventory=args.add_if_unique
    )

    print(f"\n📊 REDUNDANCY CHECK RESULTS")
    print("=" * 50)
    print(f"✅ Check Status: {'Success' if result.success else 'Failed'}")

    if not result.success:
        print(f"❌ Error: {result.error_message}")
        return

    print(f"🔍 Has Redundancy: {'Yes' if result.has_redundancy else 'No'}")
    print(f"📝 Summary: {result.summary}")

    if result.has_redundancy:
        print(f"\n🔍 REDUNDANCY DETAILS:")
        for i, redundancy in enumerate(result.redundancy_results, 1):
            print(f"\n   {i}. Redundant Policy: {redundancy.redundant_policy_id[:8]}")
            print(f"      Type: {redundancy.redundancy_type}")
            print(f"      Confidence: {redundancy.confidence_score:.2f}")
            print(f"      Explanation: {redundancy.explanation}")

    if result.recommendations:
        print(f"\n💡 RECOMMENDATIONS:")
        for rec in result.recommendations:
            print(f"   {rec}")

    # Show inventory stats
    stats = checker.get_inventory_stats()
    print(f"\n📈 INVENTORY STATS:")
    print(f"   Total policies: {stats['total_policies']}")
    print(f"   Unique actions: {stats['unique_actions']}")
    print(f"   Unique resources: {stats['unique_resources']}")
    print(f"   Unique principals: {stats['unique_principals']}")


def add_policy(args):
    """Add a policy to the inventory"""
    print("📝 Adding Policy to Inventory")
    print("=" * 50)

    # Load policy
    policy = load_policy_from_file(args.add_policy)
    policy_name = args.name or f"Policy from {args.add_policy}"

    print_policy(policy, "Policy to Add")

    # Initialize checker
    inventory_path = args.inventory or "./data/policy_inventory.json"
    checker = RedundancyChecker(inventory_path=inventory_path)

    # Add policy
    policy_id = checker.add_existing_policy(
        policy,
        name=policy_name,
        description=args.description
    )

    print(f"\n✅ Policy added successfully!")
    print(f"   Policy ID: {policy_id}")
    print(f"   Name: {policy_name}")
    if args.description:
        print(f"   Description: {args.description}")

    # Show updated stats
    stats = checker.get_inventory_stats()
    print(f"\n📈 UPDATED INVENTORY STATS:")
    print(f"   Total policies: {stats['total_policies']}")


def list_policies(args):
    """List all policies in the inventory"""
    print("📋 Policy Inventory")
    print("=" * 50)

    # Initialize checker
    inventory_path = args.inventory or "./data/policy_inventory.json"
    checker = RedundancyChecker(inventory_path=inventory_path)

    # Get policies
    policies = checker.list_policies()

    if not policies:
        print("📝 Inventory is empty")
        return

    for i, policy_info in enumerate(policies, 1):
        print(f"\n{i}. {policy_info['name']}")
        print(f"   ID: {policy_info['id']}")
        print(f"   Source: {policy_info['source']}")
        if policy_info['description']:
            print(f"   Description: {policy_info['description']}")
        if policy_info['created_at']:
            print(f"   Created: {policy_info['created_at']}")

        if args.show_policies:
            print_policy(policy_info['policy'], f"Policy Content")

    # Show stats
    stats = checker.get_inventory_stats()
    print(f"\n📈 INVENTORY STATS:")
    print(f"   Total policies: {stats['total_policies']}")
    print(f"   Unique actions: {stats['unique_actions']}")
    print(f"   Unique resources: {stats['unique_resources']}")
    print(f"   Unique principals: {stats['unique_principals']}")


def clear_inventory(args):
    """Clear all policies from the inventory"""
    if not args.force:
        response = input("⚠️  This will delete all policies from the inventory. Are you sure? (y/N): ")
        if response.lower() != 'y':
            print("Operation cancelled.")
            return

    print("🗑️ Clearing Policy Inventory")
    print("=" * 50)

    # Initialize checker
    inventory_path = args.inventory or "./data/policy_inventory.json"
    checker = RedundancyChecker(inventory_path=inventory_path)

    # Clear inventory
    checker.clear_inventory()

    print("✅ Inventory cleared successfully!")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="IAM Policy Redundancy Checker CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check a policy for redundancy
  python3 redundancy_cli.py --check policy.json --name "My Policy"

  # Add a policy to inventory
  python3 redundancy_cli.py --add-policy policy.json --name "Base Policy"

  # List all policies
  python3 redundancy_cli.py --list-policies

  # Clear inventory
  python3 redundancy_cli.py --clear-inventory --force
        """
    )

    # Global options
    parser.add_argument(
        '--inventory',
        default='./data/policy_inventory.json',
        help='Path to policy inventory file (default: ./data/policy_inventory.json)'
    )

    # Commands
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        '--check',
        metavar='POLICY_FILE',
        help='Check a policy file for redundancy'
    )

    group.add_argument(
        '--add-policy',
        metavar='POLICY_FILE',
        help='Add a policy file to the inventory'
    )

    group.add_argument(
        '--list-policies',
        action='store_true',
        help='List all policies in the inventory'
    )

    group.add_argument(
        '--clear-inventory',
        action='store_true',
        help='Clear all policies from the inventory'
    )

    # Options for check command
    parser.add_argument(
        '--add-if-unique',
        action='store_true',
        help='Add the policy to inventory if no redundancy is found (used with --check)'
    )

    # Options for add-policy command
    parser.add_argument(
        '--name',
        help='Name for the policy'
    )

    parser.add_argument(
        '--description',
        help='Description for the policy'
    )

    # Options for list-policies command
    parser.add_argument(
        '--show-policies',
        action='store_true',
        help='Show full policy content when listing (used with --list-policies)'
    )

    # Options for clear-inventory command
    parser.add_argument(
        '--force',
        action='store_true',
        help='Skip confirmation prompt (used with --clear-inventory)'
    )

    args = parser.parse_args()

    try:
        if args.check:
            check_policy_redundancy(args)
        elif args.add_policy:
            add_policy(args)
        elif args.list_policies:
            list_policies(args)
        elif args.clear_inventory:
            clear_inventory(args)

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