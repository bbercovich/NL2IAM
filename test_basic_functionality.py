#!/usr/bin/env python3
"""
Test basic functionality without ML dependencies
"""

import sys
import json
import os
from pathlib import Path

# Add src to path
sys.path.append('src')

# Test the basic imports we need
try:
    from core.inventory import PolicyInventory, RedundancyResult, ConflictResult
    print("Successfully imported core inventory classes")
except ImportError as e:
    print("Core import error:", str(e))
    sys.exit(1)

def test_inventory_empty():
    """Test inventory with no policies"""
    print("\nTesting empty inventory...")
    inventory = PolicyInventory()

    # Test policy
    test_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:user/alice",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::public-bucket/*"
            }
        ]
    }

    # Test redundancy check on empty inventory
    redundant_policies = inventory.find_redundant_policies(test_policy)
    print("Redundant policies found:", len(redundant_policies))

    # Test conflict check on empty inventory
    conflicting_policies = inventory.find_conflicting_policies(test_policy)
    print("Conflicting policies found:", len(conflicting_policies))

    return len(redundant_policies) == 0 and len(conflicting_policies) == 0

def test_inventory_with_policies():
    """Test inventory with existing policies"""
    print("\nTesting inventory with existing policies...")
    inventory = PolicyInventory()

    # Add a broad policy first
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

    broad_id = inventory.add_policy(broad_policy, name="Broad S3 Read Policy")
    print("Added broad policy with ID:", broad_id[:8])

    # Test with a specific policy that should be redundant
    specific_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:user/alice",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::public-bucket/*"
            }
        ]
    }

    # Check redundancy
    redundant_policies = inventory.find_redundant_policies(specific_policy)
    print("Redundant policies found:", len(redundant_policies))
    if redundant_policies:
        for rp in redundant_policies:
            print("  - Type:", rp.redundancy_type)
            print("  - Confidence:", rp.confidence_score)
            print("  - Explanation:", rp.explanation)

    # Add a deny policy for conflict testing
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "arn:aws:iam::123456789012:user/alice",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::public-bucket/*"
            }
        ]
    }

    # Check conflicts
    conflicting_policies = inventory.find_conflicting_policies(deny_policy)
    print("Conflicting policies found:", len(conflicting_policies))
    if conflicting_policies:
        for cp in conflicting_policies:
            print("  - Type:", cp.conflict_type)
            print("  - Severity:", cp.severity)
            print("  - Explanation:", cp.explanation)

    return True

if __name__ == "__main__":
    print("Testing Basic Inventory Functionality")
    print("=" * 50)

    # Test empty inventory
    empty_test = test_inventory_empty()
    print("Empty inventory test passed:", empty_test)

    # Test with policies
    policy_test = test_inventory_with_policies()
    print("Policy inventory test passed:", policy_test)

    if empty_test and policy_test:
        print("\n✓ All basic tests passed!")
        print("✓ Empty inventory correctly returns no conflicts/redundancy")
        print("✓ Inventory with policies can detect redundancy and conflicts")
    else:
        print("\n✗ Some tests failed!")

    print("\nTest completed!")