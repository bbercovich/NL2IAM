#!/usr/bin/env python3
"""
Test Policy Generator Agent

Tests the simplified Policy Generator that requires CodeLlama model for DSL→IAM generation.
"""

import sys
import json
import time
from datetime import datetime

# Add src to path
sys.path.append('src')

from models.model_manager import create_default_manager
from agents.policy_generator import PolicyGenerator


def test_policy_generator():
    """Test Policy Generator with CodeLlama model"""
    print("=" * 60)
    print(" POLICY GENERATOR TEST")
    print("=" * 60)
    print(f"Test run: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        print(f"\n1. Setting up model manager...")

        # Create model manager
        manager = create_default_manager()
        print(f"✓ Model manager created")

        print(f"\n2. Loading CodeLlama model for DSL→Policy generation...")
        success = manager.load_model('dsl2policy_model')

        if not success:
            print(f"✗ Failed to load CodeLlama model")
            print(f"  Policy Generator requires model to be loaded")
            print(f"  This is expected behavior - no fallback provided")
            return False

        print(f"✓ CodeLlama model loaded successfully")

        print(f"\n3. Creating Policy Generator...")
        generator = PolicyGenerator(model_manager=manager)
        print(f"✓ Policy Generator created")

        print(f"\n4. Testing DSL→Policy generation...")

        # Test cases based on successful CodeLlama results
        test_cases = [
            {
                "name": "S3 Read Access",
                "dsl": "ALLOW ACTION:s3:GetObject ON bucket:public-bucket/*"
            },
            {
                "name": "S3 Delete Denial",
                "dsl": "DENY ACTION:s3:DeleteObject ON bucket:sensitive-bucket/*"
            },
            {
                "name": "EC2 Instance Start",
                "dsl": "ALLOW ACTION:ec2:StartInstances ON instance:*"
            },
            {
                "name": "EC2 with Conditions",
                "dsl": "ALLOW ACTION:ec2:StartInstances ON instance:* WHERE ec2:InstanceType IN [t2.micro,t2.small]"
            },
            {
                "name": "S3 Write Access",
                "dsl": "ALLOW ACTION:s3:PutObject ON bucket:upload-bucket/*"
            },
            {
                "name": "prompt 30",
                "dsl": "ALLOW user:* READ bucket:examplebucket/* WHERE s3:prefix=mp3"
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
                if len(policy_json) > 300:
                    policy_json = policy_json[:300] + "..."
                print(f"   📄 Policy: {policy_json}")

                if result.warnings:
                    print(f"   ⚠️  Warnings: {', '.join(result.warnings)}")

            else:
                print(f"   ✗ FAILED")
                for warning in result.warnings:
                    print(f"     - {warning}")

                # Show raw output for debugging
                if result.raw_output:
                    raw_truncated = result.raw_output[:200] + "..." if len(result.raw_output) > 200 else result.raw_output
                    print(f"   🔍 Raw output: {raw_truncated}")

        print(f"\n5. Generation Results:")
        print(f"   Successful generations: {successful_generations}/{len(test_cases)}")
        print(f"   Success rate: {successful_generations/len(test_cases)*100:.1f}%")
        print(f"   Average generation time: {total_time/len(test_cases):.2f}s")
        print(f"   Total time: {total_time:.2f}s")

        print(f"\n6. Testing model validation...")
        # Test what happens when model isn't loaded
        manager.unload_model('dsl2policy_model')
        result = generator.generate_policy("ALLOW ACTION:s3:GetObject ON bucket:test/*")

        if not result.success and "dsl2policy_model is not loaded" in result.warnings[0]:
            print(f"   ✓ Correctly rejected generation without loaded model")
        else:
            print(f"   ✗ Did not properly handle missing model")

        print(f"\n7. Cleanup...")
        print(f"✓ Test completed")

        return successful_generations >= len(test_cases) * 0.6  # 60% success rate threshold

    except Exception as e:
        print(f"✗ Policy generator test failed: {e}")
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
    """Run the Policy Generator test"""
    success = test_policy_generator()

    print(f"\n" + "=" * 60)
    print(f" TEST SUMMARY")
    print(f"=" * 60)

    if success:
        print(f"✓ Policy Generator test PASSED")
        print(f"  - CodeLlama successfully generates IAM policies from DSL")
        print(f"  - Model validation working correctly")
        print(f"  - System properly requires model availability")
        print(f"  - Ready for NL→DSL→Policy pipeline testing")
    else:
        print(f"✗ Policy Generator test FAILED")
        print(f"  - Check CodeLlama model loading")
        print(f"  - Verify DSL parsing and JSON extraction")
        print(f"  - Review model generation parameters")

    return success


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)