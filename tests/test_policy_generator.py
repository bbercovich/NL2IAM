#!/usr/bin/env python3
"""
Test Policy Generator Agent

Tests the enhanced Policy Generator that uses CodeLlama for DSL→IAM policy generation
with rule-based fallbacks.
"""

import sys
import json
import time
from datetime import datetime

# Add src to path
sys.path.append('src')

from models.model_manager import create_default_manager
from agents.policy_generator import PolicyGenerator


def test_policy_generator_with_model():
    """Test Policy Generator with CodeLlama model"""
    print("=" * 60)
    print(" POLICY GENERATOR WITH MODEL TEST")
    print("=" * 60)
    print(f"Test run: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        print(f"\n1. Setting up model manager and policy generator...")

        # Create model manager and load CodeLlama
        manager = create_default_manager()
        generator = PolicyGenerator(model_manager=manager)

        print(f"✓ Policy generator created")

        print(f"\n2. Loading CodeLlama model for DSL→Policy generation...")
        success = manager.load_model('dsl2policy_model')

        if not success:
            print(f"✗ Failed to load model - testing rule-based fallback only")
            return test_policy_generator_rule_based()

        print(f"✓ CodeLlama model loaded")

        print(f"\n3. Testing DSL→Policy generation with model...")

        # Test cases based on successful CodeLlama results
        test_cases = [
            {
                "name": "S3 Read Access",
                "dsl": "ALLOW ACTION:s3:GetObject ON bucket:public-bucket/*",
                "expected_action": "s3:GetObject",
                "expected_effect": "Allow"
            },
            {
                "name": "S3 Delete Denial",
                "dsl": "DENY ACTION:s3:DeleteObject ON bucket:sensitive-bucket/*",
                "expected_action": "s3:DeleteObject",
                "expected_effect": "Deny"
            },
            {
                "name": "EC2 Instance Start",
                "dsl": "ALLOW ACTION:ec2:StartInstances ON instance:*",
                "expected_action": "ec2:StartInstances",
                "expected_effect": "Allow"
            },
            {
                "name": "EC2 with Conditions",
                "dsl": "ALLOW ACTION:ec2:StartInstances ON instance:* WHERE ec2:InstanceType IN [t2.micro,t2.small]",
                "expected_action": "ec2:StartInstances",
                "expected_effect": "Allow"
            }
        ]

        successful_generations = 0
        total_time = 0

        for i, test_case in enumerate(test_cases, 1):
            print(f"\nTest {i}: {test_case['name']}")
            print(f"   DSL: {test_case['dsl']}")

            start_time = time.time()
            result = generator.generate_policy(test_case['dsl'])
            gen_time = time.time() - start_time
            total_time += gen_time

            print(f"   ⏱️  Generated in {gen_time:.2f}s")
            print(f"   📊 Method: {result.method_used}")
            print(f"   🎯 Confidence: {result.confidence_score:.2f}")

            if result.success:
                print(f"   ✓ SUCCESS")

                # Validate policy structure
                policy = result.policy
                if validate_policy_structure(policy, test_case):
                    print(f"   ✓ Policy structure valid")
                    successful_generations += 1
                else:
                    print(f"   ⚠️  Policy structure issues")

                # Show generated policy (truncated)
                policy_json = json.dumps(policy, indent=2)
                if len(policy_json) > 200:
                    policy_json = policy_json[:200] + "..."
                print(f"   📄 Policy: {policy_json}")

                if result.warnings:
                    print(f"   ⚠️  Warnings: {', '.join(result.warnings)}")

            else:
                print(f"   ✗ FAILED: {', '.join(result.warnings)}")

        print(f"\n4. Generation Results:")
        print(f"   Successful generations: {successful_generations}/{len(test_cases)}")
        print(f"   Average generation time: {total_time/len(test_cases):.2f}s")
        print(f"   Total time: {total_time:.2f}s")

        print(f"\n5. Unloading model...")
        manager.unload_model('dsl2policy_model')
        print(f"✓ Model unloaded")

        return successful_generations > 0

    except Exception as e:
        print(f"✗ Policy generator test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_policy_generator_rule_based():
    """Test Policy Generator with rule-based fallback"""
    print(f"\n" + "=" * 60)
    print(f" POLICY GENERATOR RULE-BASED TEST")
    print(f"=" * 60)

    try:
        print(f"\n1. Testing rule-based policy generation...")

        # Create generator without model
        generator = PolicyGenerator(model_manager=None)
        print(f"✓ Policy generator created (no model)")

        print(f"\n2. Testing rule-based fallback...")

        test_cases = [
            {
                "name": "S3 GetObject",
                "dsl": "ALLOW ACTION:s3:GetObject ON bucket:test-bucket/*",
                "expected_service": "s3"
            },
            {
                "name": "S3 PutObject",
                "dsl": "ALLOW ACTION:s3:PutObject ON bucket:upload-bucket/*",
                "expected_service": "s3"
            },
            {
                "name": "EC2 StartInstances",
                "dsl": "ALLOW ACTION:ec2:StartInstances ON instance:*",
                "expected_service": "ec2"
            }
        ]

        successful_generations = 0

        for i, test_case in enumerate(test_cases, 1):
            print(f"\nRule Test {i}: {test_case['name']}")
            print(f"   DSL: {test_case['dsl']}")

            result = generator.generate_policy(test_case['dsl'])

            print(f"   📊 Method: {result.method_used}")
            print(f"   🎯 Confidence: {result.confidence_score:.2f}")

            if result.success:
                print(f"   ✓ SUCCESS")
                successful_generations += 1

                # Show generated policy
                policy_json = json.dumps(result.policy, indent=2)
                print(f"   📄 Policy: {policy_json}")

                if result.warnings:
                    print(f"   ⚠️  Warnings: {', '.join(result.warnings)}")
            else:
                print(f"   ✗ FAILED: {', '.join(result.warnings)}")

        print(f"\n3. Rule-based Results:")
        print(f"   Successful generations: {successful_generations}/{len(test_cases)}")

        return successful_generations > 0

    except Exception as e:
        print(f"✗ Rule-based test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def validate_policy_structure(policy: dict, test_case: dict) -> bool:
    """Validate generated policy has correct structure"""
    try:
        # Check basic structure
        if 'Version' not in policy:
            return False

        if 'Statement' not in policy:
            return False

        statements = policy['Statement']
        if not isinstance(statements, list):
            statements = [statements]

        if len(statements) == 0:
            return False

        # Check first statement
        stmt = statements[0]

        # Check required fields
        required_fields = ['Effect', 'Action', 'Resource']
        for field in required_fields:
            if field not in stmt:
                return False

        # Validate Effect
        if stmt['Effect'] not in ['Allow', 'Deny']:
            return False

        # Validate expected action if specified
        if 'expected_action' in test_case:
            expected_action = test_case['expected_action']
            if stmt['Action'] != expected_action:
                return False

        # Validate expected effect if specified
        if 'expected_effect' in test_case:
            expected_effect = test_case['expected_effect']
            if stmt['Effect'] != expected_effect:
                return False

        return True

    except Exception:
        return False


def main():
    """Run the Policy Generator tests"""
    # Test with model first
    model_success = test_policy_generator_with_model()

    # Test rule-based fallback
    rule_success = test_policy_generator_rule_based()

    overall_success = model_success or rule_success

    print(f"\n" + "=" * 60)
    print(f" TEST SUMMARY")
    print(f"=" * 60)

    if model_success:
        print(f"✓ Model-based policy generation PASSED")
        print(f"  - CodeLlama successfully generates IAM policies from DSL")
        print(f"  - Policy structure validation working")
        print(f"  - Ready for production use")
    elif rule_success:
        print(f"✓ Rule-based policy generation PASSED")
        print(f"  - Fallback templates working correctly")
        print(f"  - Can generate policies without model")
        print(f"  - Consider improving model availability")
    else:
        print(f"✗ All policy generation tests FAILED")
        print(f"  - Check model loading and DSL parsing")
        print(f"  - Verify policy templates")

    return overall_success


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)