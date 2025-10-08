#!/usr/bin/env python3
"""
Standalone ConflictChecker Agent Test

Tests the ConflictChecker agent separately from RedundancyChecker
to validate the modular architecture requested by the user.
"""

import sys
import os
import json
import tempfile
from pathlib import Path

# Add src to path for imports
sys.path.append('src')

from agents.conflict_checker import ConflictChecker


def test_conflict_checker_standalone():
    """Test the ConflictChecker agent in isolation"""
    print("⚠️  Testing Standalone ConflictChecker Agent")
    print("=" * 60)

    # Use temporary file for inventory
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_inventory_path = f.name

    try:
        # Initialize checker
        checker = ConflictChecker(inventory_path=temp_inventory_path)

        # Test Case 1: No conflicts (empty inventory)
        print("\n📝 Test 1: Empty inventory - should have no conflicts")

        test_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "arn:aws:iam::123456789012:user/alice",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::test-bucket/*"
                }
            ]
        }

        result = checker.check_conflicts(test_policy, "Alice S3 Read")
        print(f"   Has conflicts: {result.has_conflicts}")
        print(f"   Summary: {result.summary}")
        assert not result.has_conflicts, "Empty inventory should have no conflicts"
        print("   ✅ PASSED: No conflicts with empty inventory")

        # Test Case 2: Add baseline policy and test allow vs deny conflict
        print("\n📝 Test 2: Allow vs Deny conflict detection")

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

        # Add baseline allow policy
        checker.add_existing_policy(allow_policy, "Bob Delete Access - Allow")

        # Check deny policy for conflicts
        result = checker.check_conflicts(deny_policy, "Bob Delete Restriction - Deny")

        print(f"   Has conflicts: {result.has_conflicts}")
        print(f"   Overall risk level: {result.overall_risk_level}")
        print(f"   Summary: {result.summary}")

        assert result.has_conflicts, "Should detect Allow vs Deny conflict"
        assert len(result.conflict_results) > 0, "Should have conflict results"

        conflict = result.conflict_results[0]
        print(f"   Conflict type: {conflict.conflict_type}")
        print(f"   Severity: {conflict.severity}")
        print(f"   Confidence: {conflict.confidence_score}")

        assert conflict.conflict_type == "deny_vs_allow", "Should detect deny vs allow conflict"
        assert conflict.confidence_score > 0.7, "Should have high confidence"
        print("   ✅ PASSED: Allow vs Deny conflict detected correctly")

        # Test Case 3: High-risk wildcard conflict
        print("\n📝 Test 3: High-risk wildcard conflict")

        wildcard_allow = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "iam:*",
                    "Resource": "*"
                }
            ]
        }

        iam_deny = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "iam:DeleteRole",
                    "Resource": "*"
                }
            ]
        }

        # Add wildcard allow policy
        checker.add_existing_policy(wildcard_allow, "Admin IAM Access")

        # Check specific IAM deny
        result = checker.check_conflicts(iam_deny, "IAM Delete Restriction")

        print(f"   Has conflicts: {result.has_conflicts}")
        print(f"   Overall risk level: {result.overall_risk_level}")

        assert result.has_conflicts, "Should detect wildcard conflict"
        assert result.overall_risk_level == "high", "Should be high risk due to wildcards and IAM"

        high_risk_conflicts = [c for c in result.conflict_results if c.severity == "high"]
        assert len(high_risk_conflicts) > 0, "Should have high-risk conflicts"
        print("   ✅ PASSED: High-risk wildcard conflict detected")

        # Test Case 4: No conflicts (different resources)
        print("\n📝 Test 4: No conflicts with different resources")

        different_resource_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "arn:aws:iam::123456789012:user/charlie",
                    "Action": ["ec2:StartInstances", "ec2:StopInstances"],
                    "Resource": "arn:aws:ec2:*:*:instance/*"
                }
            ]
        }

        result = checker.check_conflicts(different_resource_policy, "Charlie EC2 Management")

        print(f"   Has conflicts: {result.has_conflicts}")
        print(f"   Summary: {result.summary}")

        assert not result.has_conflicts, "Should not conflict with different service"
        print("   ✅ PASSED: No false positive conflicts")

        # Test Case 5: Policy inventory persistence
        print("\n📝 Test 5: Policy inventory persistence")

        # Check inventory stats
        stats = checker.get_inventory_stats()
        print(f"   Total policies: {stats['total_policies']}")
        print(f"   Policies with allow: {stats['policies_with_allow']}")
        print(f"   Policies with deny: {stats['policies_with_deny']}")

        assert stats['total_policies'] >= 3, "Should have baseline policies"
        assert stats['policies_with_allow'] >= 2, "Should have allow policies"

        # Test inventory file exists
        assert Path(temp_inventory_path).exists(), "Inventory file should exist"

        # Load and verify JSON structure
        with open(temp_inventory_path, 'r') as f:
            inventory_data = json.load(f)

        assert 'policies' in inventory_data, "Should have policies key"
        assert len(inventory_data['policies']) >= 3, "Should have saved policies"
        print("   ✅ PASSED: Inventory persistence working")

        # Test Case 6: Comprehensive conflict report
        print("\n📝 Test 6: Comprehensive conflict report")

        report = checker.get_conflict_report(deny_policy)

        print(f"   Conflicting policies found: {report['conflicting_policies_found']}")
        print(f"   Overall risk level: {report['overall_risk_level']}")
        print(f"   Has recommendations: {len(report['recommendations']) > 0}")

        assert report['conflicting_policies_found'] > 0, "Should find conflicting policies"
        assert report['overall_risk_level'] in ['low', 'medium', 'high'], "Should have valid risk level"
        assert len(report['recommendations']) > 0, "Should provide recommendations"
        print("   ✅ PASSED: Comprehensive conflict report generated")

        # Test Case 7: Invalid policy handling
        print("\n📝 Test 7: Invalid policy handling")

        invalid_policy = {
            "Version": "2012-10-17"
            # Missing Statement
        }

        result = checker.check_conflicts(invalid_policy, "Invalid Policy")

        print(f"   Success: {result.success}")
        print(f"   Error message: {result.error_message}")

        assert not result.success, "Should fail for invalid policy"
        assert result.error_message is not None, "Should provide error message"
        print("   ✅ PASSED: Invalid policy handled correctly")

        print("\n" + "=" * 60)
        print("📊 FINAL SUMMARY")
        print("=" * 60)

        final_stats = checker.get_inventory_stats()
        print(f"Total policies in inventory: {final_stats['total_policies']}")
        print(f"Unique actions tracked: {final_stats['unique_actions']}")
        print(f"Unique resources tracked: {final_stats['unique_resources']}")
        print(f"Unique principals tracked: {final_stats['unique_principals']}")

        # Show some recommendations
        print(f"\nSample conflict recommendations:")
        for rec in result.recommendations[:2]:
            print(f"  • {rec}")

        print("\n✅ ALL STANDALONE CONFLICT CHECKER TESTS PASSED")
        return True

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        # Cleanup temp file
        try:
            os.unlink(temp_inventory_path)
        except:
            pass


def test_conflict_checker_isolation():
    """Test that ConflictChecker works independently of RedundancyChecker"""
    print("\n" + "=" * 60)
    print("🔍 Testing ConflictChecker Isolation")
    print("=" * 60)

    try:
        # Create two separate checkers to ensure independence
        checker1 = ConflictChecker()
        checker2 = ConflictChecker()

        policy1 = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "arn:aws:iam::123456789012:user/test1",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket1/*"
                }
            ]
        }

        policy2 = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": "arn:aws:iam::123456789012:user/test1",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket1/*"
                }
            ]
        }

        # Add policy to checker1 only
        checker1.add_existing_policy(policy1, "Test Policy 1")

        # Check policy2 against both checkers
        result1 = checker1.check_conflicts(policy2, "Test Policy 2")
        result2 = checker2.check_conflicts(policy2, "Test Policy 2")

        print(f"Checker1 (with baseline): Has conflicts = {result1.has_conflicts}")
        print(f"Checker2 (empty): Has conflicts = {result2.has_conflicts}")

        assert result1.has_conflicts, "Checker1 should detect conflict"
        assert not result2.has_conflicts, "Checker2 should not detect conflict"

        print("✅ PASSED: ConflictChecker instances are properly isolated")
        return True

    except Exception as e:
        print(f"❌ Isolation test failed: {e}")
        return False


def main():
    """Run all standalone ConflictChecker tests"""
    print("🚀 Starting Standalone ConflictChecker Test Suite")
    print("=" * 70)

    all_passed = True

    # Test 1: Core functionality
    if not test_conflict_checker_standalone():
        all_passed = False

    # Test 2: Isolation
    if not test_conflict_checker_isolation():
        all_passed = False

    print("\n" + "=" * 70)
    print("🎯 TEST SUITE SUMMARY")
    print("=" * 70)

    if all_passed:
        print("✅ ALL TESTS PASSED")
        print("🎉 ConflictChecker agent is working correctly in standalone mode")
        print("📋 Ready for integration with modular pipeline")
        return True
    else:
        print("❌ SOME TESTS FAILED")
        print("🔧 ConflictChecker needs fixes before pipeline integration")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)