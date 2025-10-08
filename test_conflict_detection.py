#!/usr/bin/env python3
"""
Simple test for conflict detection functionality
"""

import sys
import os
import json

# Add the src/core directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src', 'core'))

from inventory import PolicyInventory


def test_conflict_detection():
    """Test conflict detection between Allow and Deny policies"""
    print("🔍 Testing Enhanced Conflict Detection")
    print("=" * 60)

    inventory = PolicyInventory()

    # Test Case 1: Allow vs Deny Conflict
    print("\n📝 Test 1: Allow vs Deny Conflict")

    # Add policy that ALLOWS s3:DeleteObject
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

    allow_id = inventory.add_policy(allow_policy, name="Bob Delete Access - Allow")
    print(f"   Added ALLOW policy: {allow_id[:8]}")

    # Test policy that DENIES the same action (should conflict)
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

    print(f"   Testing DENY policy for conflicts...")
    print(f"   Deny Policy: {json.dumps(deny_policy, indent=2)}")

    # Check for conflicts
    conflict_results = inventory.find_conflicting_policies(deny_policy)

    if conflict_results:
        result = conflict_results[0]
        print(f"\n   ⚠️  CONFLICT DETECTED:")
        print(f"      Type: {result.conflict_type}")
        print(f"      Severity: {result.severity}")
        print(f"      Confidence: {result.confidence_score:.2f}")
        print(f"      Explanation: {result.explanation}")
        print(f"      Affected Actions: {list(result.affected_actions)}")
        print(f"      Affected Resources: {list(result.affected_resources)}")
        print(f"      Affected Principals: {list(result.affected_principals)}")
    else:
        print("   ❌ No conflicts detected (unexpected)")

    # Test Case 2: No Conflict (Different Resources)
    print("\n📝 Test 2: Different Resources (No Conflict)")

    # Policy for different bucket (should NOT conflict)
    different_bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "arn:aws:iam::123456789012:user/bob",
                "Action": "s3:DeleteObject",
                "Resource": "arn:aws:s3:::different-bucket/*"
            }
        ]
    }

    conflict_results = inventory.find_conflicting_policies(different_bucket_policy)

    if conflict_results:
        print("   ❌ Unexpected conflict detected")
        for result in conflict_results:
            print(f"      Type: {result.conflict_type}, Severity: {result.severity}")
    else:
        print("   ✅ No conflicts detected (expected)")

    # Test Case 3: Comprehensive Conflict Report
    print("\n📝 Test 3: Comprehensive Conflict Report")

    conflict_report = inventory.generate_conflict_report(deny_policy)

    print(f"\n   📊 CONFLICT REPORT SUMMARY:")
    print(f"      Total existing policies: {conflict_report['total_existing_policies']}")
    print(f"      Conflicting policies found: {conflict_report['conflicting_policies_found']}")
    print(f"      Overall risk level: {conflict_report['overall_risk_level']}")

    if conflict_report['conflict_details']:
        print(f"\n   📋 CONFLICT DETAILS:")
        for detail in conflict_report['conflict_details']:
            print(f"      - Policy: {detail['conflicting_policy_name']}")
            print(f"        Type: {detail['conflict_type']}")
            print(f"        Severity: {detail['severity']}")
            print(f"        Confidence: {detail['confidence_score']:.2f}")
            print(f"        Explanation: {detail['explanation']}")

    if conflict_report['recommendations']:
        print(f"\n   💡 RECOMMENDATIONS:")
        for rec in conflict_report['recommendations']:
            print(f"      {rec}")

    # Summary
    print("\n" + "=" * 60)
    print("📊 Summary")
    stats = inventory.get_inventory_stats()
    print(f"Total policies in inventory: {stats['total_policies']}")
    print(f"Policies with allow: {stats['policies_with_allow']}")
    print(f"Policies with deny: {stats['policies_with_deny']}")

    print("\n✅ Enhanced conflict detection test completed successfully!")
    return True


if __name__ == "__main__":
    try:
        test_conflict_detection()
        print("\n🎉 All conflict detection tests passed!")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)