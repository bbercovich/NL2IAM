#!/usr/bin/env python3
"""
NL2IAM System Pipeline Test

This script tests the complete NL2IAM pipeline from natural language
to AWS IAM policies, including conflict detection and policy inventory management.

Usage:
    python test_nl2iam_pipeline.py
"""

import sys
import json
import time
from datetime import datetime

# Add src to path
sys.path.append('src')

from agents.translator import NLToTranslator
from core.dsl import parse_dsl
from core.inventory import PolicyInventory
from models.model_manager import create_default_manager

def print_header(title):
    """Print a formatted header"""
    print(f"\n{'=' * 60}")
    print(f" {title}")
    print(f"{'=' * 60}")

def print_section(title):
    """Print a formatted section header"""
    print(f"\n{'-' * 40}")
    print(f" {title}")
    print(f"{'-' * 40}")

def test_environment():
    """Test the basic environment setup"""
    print_header("ENVIRONMENT TEST")

    try:
        import torch
        print(f"✓ PyTorch version: {torch.__version__}")
        print(f"✓ CUDA available: {torch.cuda.is_available()}")

        if torch.cuda.is_available():
            print(f"✓ GPU: {torch.cuda.get_device_name(0)}")
            print(f"✓ GPU Memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f}GB")

        import transformers
        print(f"✓ Transformers version: {transformers.__version__}")

        return True
    except Exception as e:
        print(f"✗ Environment error: {e}")
        return False

def test_dsl_parser():
    """Test the DSL parser functionality"""
    print_header("DSL PARSER TEST")

    test_dsl_examples = [
        "ALLOW ACTION:[s3:GetBucketLocation,s3:ListAllMyBuckets] ON *",
        "ALLOW ACTION:s3:ListBucket ON bucket:public-bucket",
        "DENY ACTION:s3:* ON bucket:sensitive-bucket/secret/*",
        "ALLOW ACTION:ec2:RunInstances ON instance:* WHERE ec2:InstanceType IN [t2.nano,t2.micro]"
    ]

    success_count = 0

    for i, dsl_text in enumerate(test_dsl_examples, 1):
        print(f"\nTest {i}: {dsl_text}")
        try:
            policy = parse_dsl(dsl_text)
            aws_policy = policy.to_aws_policy()
            print(f"✓ Parsed successfully")
            print(f"  Statements: {len(aws_policy['Statement'])}")
            success_count += 1
        except Exception as e:
            print(f"✗ Parse error: {e}")

    print(f"\n📊 DSL Parser Results: {success_count}/{len(test_dsl_examples)} successful")
    return success_count == len(test_dsl_examples)

def test_translator():
    """Test the natural language to DSL translator"""
    print_header("NL TO DSL TRANSLATOR TEST")

    translator = NLToTranslator()

    test_cases = [
        "Allow Alice to read files from the public bucket",
        "Deny deleting any objects in the sensitive bucket",
        "Allow starting small EC2 instances",
        "Let users list all S3 buckets",
        "Permit running t2.micro instances with specific conditions"
    ]

    results = []

    for i, nl_input in enumerate(test_cases, 1):
        print(f"\nTest {i}: {nl_input}")
        try:
            result = translator.translate(nl_input)
            print(f"✓ DSL: {result.dsl_output}")
            print(f"  Confidence: {result.confidence:.2f}")
            print(f"  Method: {result.reasoning}")
            results.append(result)
        except Exception as e:
            print(f"✗ Translation error: {e}")
            results.append(None)

    success_count = len([r for r in results if r is not None])
    print(f"\n📊 Translation Results: {success_count}/{len(test_cases)} successful")
    return results, success_count == len(test_cases)

def test_policy_inventory():
    """Test the policy inventory functionality"""
    print_header("POLICY INVENTORY TEST")

    inventory = PolicyInventory()

    # Test policies
    test_policies = [
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "arn:aws:s3:::my-bucket/*"
                }
            ]
        },
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/secret/*"
                }
            ]
        },
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/public/*"
                }
            ]
        }
    ]

    policy_ids = []

    print("\nAdding test policies...")
    for i, policy in enumerate(test_policies, 1):
        try:
            policy_id = inventory.add_policy(
                policy,
                name=f"Test-Policy-{i}",
                description=f"Test policy {i} for pipeline validation"
            )
            policy_ids.append(policy_id)
            print(f"✓ Added policy {i}: {policy_id[:12]}...")
        except Exception as e:
            print(f"✗ Error adding policy {i}: {e}")

    # Test conflict detection
    print("\nTesting conflict detection...")
    conflicts = inventory.find_conflicting_policies(test_policies[1])
    print(f"✓ Found {len(conflicts)} conflicts")

    # Test redundancy detection
    print("\nTesting redundancy detection...")
    redundant = inventory.find_redundant_policies(test_policies[2])
    print(f"✓ Found {len(redundant)} redundant policies")

    # Show stats
    stats = inventory.get_inventory_stats()
    print(f"\n📊 Inventory Stats: {stats}")

    return len(policy_ids) == len(test_policies)

def test_full_pipeline():
    """Test the complete end-to-end pipeline"""
    print_header("FULL PIPELINE TEST")

    # Initialize components
    translator = NLToTranslator()
    inventory = PolicyInventory()

    pipeline_tests = [
        {
            "name": "S3 Read Access",
            "input": "Allow Alice to read files from the public-bucket",
            "expected_service": "s3"
        },
        {
            "name": "S3 Delete Denial",
            "input": "Deny deleting objects in the sensitive-bucket",
            "expected_service": "s3"
        },
        {
            "name": "EC2 Instance Management",
            "input": "Allow starting t2.micro EC2 instances",
            "expected_service": "ec2"
        }
    ]

    successful_pipelines = 0

    for i, test in enumerate(pipeline_tests, 1):
        print_section(f"Pipeline Test {i}: {test['name']}")
        print(f"Input: {test['input']}")

        try:
            # Step 1: NL → DSL
            print("\n1. Translating NL to DSL...")
            translation_result = translator.translate(test['input'])
            print(f"   DSL: {translation_result.dsl_output}")
            print(f"   Confidence: {translation_result.confidence:.2f}")

            # Step 2: DSL → AWS Policy
            print("\n2. Converting DSL to AWS Policy...")
            policy = parse_dsl(translation_result.dsl_output)
            aws_policy = policy.to_aws_policy()
            print(f"   ✓ Policy generated with {len(aws_policy['Statement'])} statement(s)")

            # Step 3: Check conflicts and redundancy
            print("\n3. Checking conflicts and redundancy...")
            conflicts = inventory.find_conflicting_policies(aws_policy)
            redundant = inventory.find_redundant_policies(aws_policy)

            if conflicts:
                print(f"   ⚠️  {len(conflicts)} conflict(s) found")
                for policy_id, reason in conflicts:
                    print(f"      - {policy_id[:12]}...: {reason}")
            else:
                print(f"   ✓ No conflicts found")

            if redundant:
                print(f"   ⚠️  {len(redundant)} redundant policies found")
            else:
                print(f"   ✓ No redundant policies found")

            # Step 4: Add to inventory
            print("\n4. Adding to policy inventory...")
            policy_id = inventory.add_policy(
                aws_policy,
                name=test['name'],
                description=f"Generated from: {test['input']}"
            )
            print(f"   ✓ Added as {policy_id[:12]}...")

            # Step 5: Validate policy structure
            print("\n5. Validating policy structure...")
            if 'Version' in aws_policy and 'Statement' in aws_policy:
                print(f"   ✓ Valid policy structure")

                # Check if expected service is mentioned
                policy_str = json.dumps(aws_policy)
                if test['expected_service'] in policy_str.lower():
                    print(f"   ✓ Contains expected service: {test['expected_service']}")
                else:
                    print(f"   ⚠️  Expected service '{test['expected_service']}' not clearly identified")
            else:
                print(f"   ✗ Invalid policy structure")
                continue

            successful_pipelines += 1
            print(f"\n✓ Pipeline {i} completed successfully!")

        except Exception as e:
            print(f"\n✗ Pipeline {i} failed: {e}")
            import traceback
            traceback.print_exc()

    # Final summary
    print_section("PIPELINE SUMMARY")
    print(f"Successful pipelines: {successful_pipelines}/{len(pipeline_tests)}")
    print(f"Final inventory stats: {inventory.get_inventory_stats()}")

    return successful_pipelines == len(pipeline_tests)

def test_model_manager():
    """Test the model manager (without actually loading large models)"""
    print_header("MODEL MANAGER TEST")

    try:
        manager = create_default_manager()
        info = manager.get_model_info()

        print("✓ Model manager created successfully")
        print(f"✓ Registered models: {list(info['registered_models'].keys())}")
        print(f"✓ Memory info available: {'cuda' in info['memory_usage']}")

        # Test model configuration
        for model_id, model_info in info['registered_models'].items():
            print(f"  - {model_id}: {model_info['model_type']} for {model_info['task']}")

        return True
    except Exception as e:
        print(f"✗ Model manager error: {e}")
        return False

def main():
    """Run all tests"""
    print_header("NL2IAM PIPELINE TEST SUITE")
    print(f"Test run: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    test_results = {}

    # Run all tests
    test_results['environment'] = test_environment()
    test_results['dsl_parser'] = test_dsl_parser()
    test_results['translator'], _ = test_translator()
    test_results['inventory'] = test_policy_inventory()
    test_results['model_manager'] = test_model_manager()
    test_results['full_pipeline'] = test_full_pipeline()

    # Final summary
    print_header("TEST SUMMARY")

    total_tests = len(test_results)
    passed_tests = sum(1 for result in test_results.values() if result)

    for test_name, result in test_results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{test_name.replace('_', ' ').title():<20} {status}")

    print(f"\nOverall Result: {passed_tests}/{total_tests} tests passed")

    if passed_tests == total_tests:
        print("\n🎉 All tests passed! Your NL2IAM system is working correctly.")
    else:
        print(f"\n⚠️  {total_tests - passed_tests} test(s) failed. Check the output above for details.")

    return passed_tests == total_tests

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)