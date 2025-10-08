#!/usr/bin/env python3
"""
Simple Redundancy Detection Test

Tests the core redundancy detection functionality without external dependencies.
"""

import sys
import os
import json

# Add the src/core directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'core'))

from inventory import PolicyInventory


def test_redundancy_detection():
    """Test basic redundancy detection scenarios"""
    print("🔍 Testing Redundancy Detection")
    print("=" * 50)

    inventory = PolicyInventory()

    # Test Case 1: Broad vs Specific Principal
    print("\n📝 Test 1: Broad vs Specific Principal")

    # Add broad policy (all users)
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

    broad_id = inventory.add_policy(broad_policy, name="Public Bucket Access")
    print(f"   Added broad policy: {broad_id[:8]}")

    # Check specific user policy
    alice_policy = {
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

    redundancy_results = inventory.find_redundant_policies(alice_policy)

    if redundancy_results:
        result = redundancy_results[0]
        print(f"   ✅ Redundancy detected: {result.redundancy_type}")
        print(f"   📊 Confidence: {result.confidence_score:.2f}")
        print(f"   📝 Explanation: {result.explanation}")
    else:
        print("   ❌ No redundancy detected (unexpected)")

    # Test Case 2: Admin vs Specific Action
    print("\n📝 Test 2: Admin vs Specific Action")

    # Add admin policy
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

    admin_id = inventory.add_policy(admin_policy, name="S3 Admin Policy")
    print(f"   Added admin policy: {admin_id[:8]}")

    # Check specific action policy
    specific_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:role/S3Admin",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::uploads/*"
            }
        ]
    }

    redundancy_results = inventory.find_redundant_policies(specific_policy)

    if redundancy_results:
        result = redundancy_results[0]
        print(f"   ✅ Redundancy detected: {result.redundancy_type}")
        print(f"   📊 Confidence: {result.confidence_score:.2f}")
        print(f"   📝 Explanation: {result.explanation}")
    else:
        print("   ❌ No redundancy detected (unexpected)")

    # Test Case 3: No Redundancy (Different Resources)
    print("\n📝 Test 3: Different Resources (No Redundancy)")

    different_bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:user/bob",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::private-bucket/*"
            }
        ]
    }

    redundancy_results = inventory.find_redundant_policies(different_bucket_policy)

    if redundancy_results:
        print("   ❌ Unexpected redundancy detected")
        for result in redundancy_results:
            print(f"      Type: {result.redundancy_type}, Confidence: {result.confidence_score:.2f}")
    else:
        print("   ✅ No redundancy detected (expected)")

    # Summary
    print("\n" + "=" * 50)
    print("📊 Summary")
    stats = inventory.get_inventory_stats()
    print(f"Total policies in inventory: {stats['total_policies']}")
    print(f"Unique actions: {stats['unique_actions']}")
    print(f"Unique resources: {stats['unique_resources']}")
    print(f"Unique principals: {stats['unique_principals']}")

    print("\n✅ Redundancy detection test completed successfully!")
    return True


if __name__ == "__main__":
    try:
        test_redundancy_detection()
        print("\n🎉 All tests passed!")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)