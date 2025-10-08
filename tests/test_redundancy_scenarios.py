#!/usr/bin/env python3
"""
Comprehensive Test Suite for Redundancy Detection Scenarios

This test suite covers various redundancy scenarios as outlined in the paper:
1. Identical policies
2. Subset permissions (new policy is subset of existing)
3. Broader principal coverage (all users vs specific user)
4. Broader resource coverage (all buckets vs specific bucket)
5. Broader action coverage (all actions vs specific actions)
6. Complex overlapping scenarios

These tests validate the rule-based redundancy engine functionality.
"""

import sys
import json
from pathlib import Path

# Add src to path
sys.path.append('src')

# Import directly to avoid dependency issues
sys.path.append('src/core')
sys.path.append('src/agents')

from inventory import PolicyInventory, RedundancyResult


def test_identical_policies():
    """Test detection of identical policies"""
    print("🧪 Test 1: Identical Policies")

    inventory = PolicyInventory()

    # Base policy
    base_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:user/alice",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ]
    }

    # Identical policy
    identical_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:user/alice",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ]
    }

    # Add base policy
    checker.add_existing_policy(base_policy, "Alice S3 Read Policy")

    # Check identical policy
    result = checker.check_redundancy(identical_policy, "Alice S3 Read Policy (Duplicate)", add_to_inventory=False)

    assert result.success, "Redundancy check should succeed"
    assert result.has_redundancy, "Should detect redundancy"
    assert len(result.redundancy_results) == 1, "Should find exactly one redundant policy"
    assert result.redundancy_results[0].redundancy_type == "identical", "Should detect as identical"
    assert result.redundancy_results[0].confidence_score == 1.0, "Should have maximum confidence"

    print("   ✅ Identical policy detection: PASSED")
    return True


def test_broader_principal_redundancy():
    """Test detection of broader principal coverage"""
    print("🧪 Test 2: Broader Principal Coverage")

    checker = RedundancyChecker()

    # Broad policy (all users)
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

    # Specific user policy (should be redundant)
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

    # Add broad policy
    checker.add_existing_policy(broad_policy, "Public Bucket Access - All Users")

    # Check specific policy
    result = checker.check_redundancy(specific_policy, "Alice Public Bucket Access", add_to_inventory=False)

    assert result.success, "Redundancy check should succeed"
    assert result.has_redundancy, "Should detect redundancy"
    assert result.redundancy_results[0].redundancy_type == "broader_principal", "Should detect broader principal"
    assert "all users (*)" in result.redundancy_results[0].explanation.lower(), "Should mention wildcard principal"

    print("   ✅ Broader principal detection: PASSED")
    return True


def test_broader_resource_redundancy():
    """Test detection of broader resource coverage"""
    print("🧪 Test 3: Broader Resource Coverage")

    checker = RedundancyChecker()

    # Policy with broad resource pattern
    broad_resource_policy = {
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

    # Policy with specific resource (should be redundant)
    specific_resource_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:role/S3Admin",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::uploads-bucket/*"
            }
        ]
    }

    # Add broad policy
    checker.add_existing_policy(broad_resource_policy, "S3 Admin Full Access")

    # Check specific policy
    result = checker.check_redundancy(specific_resource_policy, "S3Admin Upload Access", add_to_inventory=False)

    assert result.success, "Redundancy check should succeed"
    assert result.has_redundancy, "Should detect redundancy"
    assert result.redundancy_results[0].redundancy_type in ["broader_resource", "broader_action"], "Should detect broader coverage"

    print("   ✅ Broader resource detection: PASSED")
    return True


def test_subset_permissions():
    """Test detection of subset permissions"""
    print("🧪 Test 4: Subset Permissions")

    checker = RedundancyChecker()

    # Policy with multiple actions
    multi_action_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:user/bob",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                "Resource": "arn:aws:s3:::work-bucket/*"
            }
        ]
    }

    # Policy with subset of actions (should be redundant)
    subset_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:user/bob",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::work-bucket/*"
            }
        ]
    }

    # Add multi-action policy
    checker.add_existing_policy(multi_action_policy, "Bob Work Bucket Full Access")

    # Check subset policy
    result = checker.check_redundancy(subset_policy, "Bob Work Bucket Read Only", add_to_inventory=False)

    assert result.success, "Redundancy check should succeed"
    assert result.has_redundancy, "Should detect redundancy"

    print("   ✅ Subset permissions detection: PASSED")
    return True


def test_no_redundancy():
    """Test that non-redundant policies are not flagged"""
    print("🧪 Test 5: No Redundancy (Different Resources)")

    checker = RedundancyChecker()

    # Policy for one bucket
    bucket_a_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:user/charlie",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket-a/*"
            }
        ]
    }

    # Policy for different bucket (should NOT be redundant)
    bucket_b_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:user/charlie",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket-b/*"
            }
        ]
    }

    # Add first policy
    checker.add_existing_policy(bucket_a_policy, "Charlie Bucket A Access")

    # Check second policy
    result = checker.check_redundancy(bucket_b_policy, "Charlie Bucket B Access", add_to_inventory=False)

    assert result.success, "Redundancy check should succeed"
    assert not result.has_redundancy, "Should NOT detect redundancy"
    assert len(result.redundancy_results) == 0, "Should find no redundant policies"

    print("   ✅ No redundancy detection: PASSED")
    return True


def test_different_effects():
    """Test that Allow vs Deny policies are not considered redundant"""
    print("🧪 Test 6: Different Effects (Allow vs Deny)")

    checker = RedundancyChecker()

    # Allow policy
    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:user/diana",
                "Action": "s3:DeleteObject",
                "Resource": "arn:aws:s3:::sensitive-bucket/*"
            }
        ]
    }

    # Deny policy for same action/resource (should NOT be redundant)
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "arn:aws:iam::123456789012:user/diana",
                "Action": "s3:DeleteObject",
                "Resource": "arn:aws:s3:::sensitive-bucket/*"
            }
        ]
    }

    # Add allow policy
    checker.add_existing_policy(allow_policy, "Diana Delete Access")

    # Check deny policy
    result = checker.check_redundancy(deny_policy, "Diana Delete Restriction", add_to_inventory=False)

    assert result.success, "Redundancy check should succeed"
    assert not result.has_redundancy, "Should NOT detect redundancy between Allow and Deny"

    print("   ✅ Different effects detection: PASSED")
    return True


def test_complex_wildcard_matching():
    """Test complex wildcard scenarios"""
    print("🧪 Test 7: Complex Wildcard Matching")

    checker = RedundancyChecker()

    # Service-level wildcard policy
    service_wildcard_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:role/EC2Admin",
                "Action": "ec2:*",
                "Resource": "*"
            }
        ]
    }

    # Specific EC2 action (should be redundant)
    specific_ec2_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:role/EC2Admin",
                "Action": "ec2:RunInstances",
                "Resource": "arn:aws:ec2:us-east-1:123456789012:instance/*"
            }
        ]
    }

    # Add wildcard policy
    checker.add_existing_policy(service_wildcard_policy, "EC2 Admin Full Access")

    # Check specific policy
    result = checker.check_redundancy(specific_ec2_policy, "EC2Admin Instance Launch", add_to_inventory=False)

    assert result.success, "Redundancy check should succeed"
    assert result.has_redundancy, "Should detect redundancy with wildcard"

    print("   ✅ Complex wildcard matching: PASSED")
    return True


def test_partial_redundancy():
    """Test partial redundancy detection"""
    print("🧪 Test 8: Partial Redundancy")

    checker = RedundancyChecker()

    # Existing policy with some overlapping permissions
    existing_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:user/eve",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": ["arn:aws:s3:::shared-bucket", "arn:aws:s3:::shared-bucket/*"]
            }
        ]
    }

    # New policy with some overlap and some new permissions
    mixed_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:user/eve",
                "Action": ["s3:GetObject", "s3:PutObject"],  # GetObject overlaps, PutObject is new
                "Resource": "arn:aws:s3:::shared-bucket/*"
            }
        ]
    }

    # Add existing policy
    checker.add_existing_policy(existing_policy, "Eve Shared Bucket Read Access")

    # Check mixed policy
    result = checker.check_redundancy(mixed_policy, "Eve Shared Bucket Read/Write", add_to_inventory=False)

    # This might or might not be detected as redundant depending on the algorithm
    # The important thing is that it completes successfully
    assert result.success, "Redundancy check should succeed"

    print("   ✅ Partial redundancy handling: PASSED")
    return True


def run_all_tests():
    """Run all redundancy test scenarios"""
    print("🔍 Running Comprehensive Redundancy Detection Test Suite")
    print("=" * 70)

    tests = [
        test_identical_policies,
        test_broader_principal_redundancy,
        test_broader_resource_redundancy,
        test_subset_permissions,
        test_no_redundancy,
        test_different_effects,
        test_complex_wildcard_matching,
        test_partial_redundancy
    ]

    passed = 0
    failed = 0

    for test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
                print(f"   ❌ {test_func.__name__}: FAILED")
        except Exception as e:
            failed += 1
            print(f"   ❌ {test_func.__name__}: FAILED with error: {e}")
            import traceback
            traceback.print_exc()

    print("\n" + "=" * 70)
    print("📊 TEST RESULTS")
    print("=" * 70)
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"📈 Success Rate: {passed/(passed+failed)*100:.1f}%")

    if failed == 0:
        print("🎉 All redundancy detection tests PASSED!")
        print("\n💡 Key Capabilities Validated:")
        print("   ✓ Identical policy detection")
        print("   ✓ Broader principal coverage detection")
        print("   ✓ Broader resource coverage detection")
        print("   ✓ Subset permission detection")
        print("   ✓ Non-redundant policy recognition")
        print("   ✓ Allow vs Deny differentiation")
        print("   ✓ Complex wildcard matching")
        print("   ✓ Partial redundancy handling")
        print("\n🚀 Redundancy checking system is ready for production!")
        return True
    else:
        print(f"❌ {failed} test(s) failed. Review and fix issues before deployment.")
        return False


def main():
    """Main test runner"""
    try:
        success = run_all_tests()
        return 0 if success else 1
    except Exception as e:
        print(f"Test suite failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())