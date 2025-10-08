#!/usr/bin/env python3
"""
Test Enhanced Conflict & Redundancy Checker Agent
"""

import sys
import os
import json

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from agents.redundancy_checker import RedundancyChecker


def test_enhanced_checker():
    """Test the enhanced conflict & redundancy checker"""
    print("🔍 Testing Enhanced Conflict & Redundancy Checker Agent")
    print("=" * 70)

    # Initialize checker
    checker = RedundancyChecker()

    # Test policies for redundancy
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

    # Test policies for conflict
    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:user/bob",
                "Action": "s3:DeleteObject",
                "Resource": "arn:aws:s3:::sensitive-bucket/*"
            }
        ]
    }

    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "arn:aws:iam::123456789012:user/bob",
                "Action": "s3:DeleteObject",
                "Resource": "arn:aws:s3:::sensitive-bucket/*"
            }
        ]
    }

    # Add baseline policies
    print("📝 Adding baseline policies to inventory...")
    checker.add_existing_policy(broad_policy, "Public Bucket Access - All Users")
    checker.add_existing_policy(allow_policy, "Bob Delete Access - Allow")

    print("\n" + "=" * 70)
    print("🔍 TESTING REDUNDANCY DETECTION")

    # Check Alice's policy for redundancy
    print("\n📝 Checking Alice's policy for redundancy...")
    redundancy_result = checker.check_redundancy(alice_policy, "Alice's S3 Read Policy", add_to_inventory=False)

    print(f"\n📊 REDUNDANCY RESULTS:")
    print(f"   Success: {redundancy_result.success}")
    print(f"   Has Redundancy: {redundancy_result.has_redundancy}")
    print(f"   Summary: {redundancy_result.summary}")

    if redundancy_result.redundancy_results:
        print(f"\n📋 REDUNDANCY DETAILS:")
        for r in redundancy_result.redundancy_results:
            print(f"   - Type: {r.redundancy_type}")
            print(f"   - Confidence: {r.confidence_score:.2f}")
            print(f"   - Explanation: {r.explanation}")

    print("\n" + "=" * 70)
    print("🔍 TESTING CONFLICT DETECTION")

    # Check deny policy for conflicts
    print("\n📝 Checking deny policy for conflicts...")
    conflict_result = checker.check_conflicts(deny_policy, "Bob Delete Restriction - Deny")

    print(f"\n📊 CONFLICT RESULTS:")
    print(f"   Success: {conflict_result.success}")
    print(f"   Has Conflicts: {conflict_result.has_conflicts}")
    print(f"   Overall Risk Level: {conflict_result.overall_risk_level}")
    print(f"   Summary: {conflict_result.summary}")

    if conflict_result.conflict_results:
        print(f"\n📋 CONFLICT DETAILS:")
        for r in conflict_result.conflict_results:
            print(f"   - Type: {r.conflict_type}")
            print(f"   - Severity: {r.severity}")
            print(f"   - Confidence: {r.confidence_score:.2f}")
            print(f"   - Explanation: {r.explanation}")
            print(f"   - Affected Actions: {list(r.affected_actions)}")

    print("\n" + "=" * 70)
    print("🔍 TESTING COMPREHENSIVE VALIDATION")

    # Test comprehensive validation
    print("\n📝 Running comprehensive validation on deny policy...")
    validation_result = checker.validate_policy(deny_policy, "Bob Delete Restriction - Comprehensive", add_to_inventory=False)

    print(f"\n📊 COMPREHENSIVE VALIDATION RESULTS:")
    print(f"   Overall Success: {validation_result.success}")
    print(f"   Overall Recommendation: {validation_result.overall_recommendation}")

    print(f"\n   📋 Redundancy Check:")
    print(f"      Has Redundancy: {validation_result.redundancy_check.has_redundancy}")
    print(f"      Summary: {validation_result.redundancy_check.summary}")

    print(f"\n   📋 Conflict Check:")
    print(f"      Has Conflicts: {validation_result.conflict_check.has_conflicts}")
    print(f"      Risk Level: {validation_result.conflict_check.overall_risk_level}")
    print(f"      Summary: {validation_result.conflict_check.summary}")

    # Show inventory stats
    print(f"\n📈 INVENTORY STATS:")
    stats = checker.get_inventory_stats()
    print(f"   Total policies: {stats['total_policies']}")
    print(f"   Unique actions: {stats['unique_actions']}")
    print(f"   Unique resources: {stats['unique_resources']}")
    print(f"   Unique principals: {stats['unique_principals']}")

    print(f"\n🎉 Enhanced conflict & redundancy detection test completed!")
    return True


if __name__ == "__main__":
    try:
        test_enhanced_checker()
        print("\n✅ All enhanced checker tests passed!")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)