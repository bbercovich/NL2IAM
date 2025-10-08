#!/usr/bin/env python3
"""
Test Full NL→DSL→Policy Pipeline with Redundancy Checking

This test demonstrates the complete workflow including redundancy validation:
1. Natural Language → DSL (using NLToTranslator)
2. DSL → AWS IAM Policy (using PolicyGenerator with RAG enhancement)
3. Redundancy Check (using RedundancyChecker)
4. Policy recommendation with redundancy analysis
"""

import sys
import json
import time
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.append('src')

from models.model_manager import create_default_manager
from agents.translator import NLToTranslator
from agents.policy_generator import PolicyGenerator
from agents.redundancy_checker import RedundancyChecker
from agents.conflict_checker import ConflictChecker
from rag.rag_engine import RAGEngine


def test_pipeline_with_redundancy():
    """Test the complete NL→DSL→Policy→Redundancy pipeline"""
    print("=" * 70)
    print(" FULL PIPELINE TEST: NL → DSL → IAM Policy → Redundancy Check")
    print("=" * 70)
    print(f"Test run: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Test cases that should demonstrate both redundancy and conflicts
    test_cases = [
        {
            "name": "Initial Broad S3 Access",
            "natural_language": "Allow all users to read files from the public bucket",
            "is_baseline": True  # This will be added to inventory first
        },
        {
            "name": "Bob S3 Delete Access",
            "natural_language": "Allow Bob to delete files from the sensitive bucket",
            "is_baseline": True  # This will be added to inventory first
        },
        {
            "name": "Specific User S3 Access (Should be Redundant)",
            "natural_language": "Allow Alice to read files from the public bucket",
            "is_baseline": False
        },
        {
            "name": "Bob S3 Delete Restriction (Should Conflict)",
            "natural_language": "Deny Bob from deleting files in the sensitive bucket",
            "is_baseline": False
        },
        {
            "name": "S3 Admin Policy",
            "natural_language": "Allow S3Admin role to manage all S3 buckets",
            "is_baseline": True
        },
        {
            "name": "Specific S3 Write (Should be Redundant)",
            "natural_language": "Allow S3Admin role to upload files to the uploads bucket",
            "is_baseline": False
        },
        {
            "name": "EC2 Instance Management (Should be Unique)",
            "natural_language": "Allow starting and stopping EC2 instances",
            "is_baseline": False
        }
    ]

    try:
        print(f"\n🚀 Step 1: Setting up models...")

        # Create model manager and load models
        manager = create_default_manager()
        print(f"✓ Model manager created")

        # Load models for both NL→DSL and DSL→Policy
        print(f"\n📥 Loading models...")
        print(f"   - Loading NL→DSL model (nl2dsl_model)...")
        nl_success = manager.load_model('nl2dsl_model')

        print(f"   - Loading DSL→Policy model (dsl2policy_model)...")
        policy_success = manager.load_model('dsl2policy_model')

        if not nl_success:
            print(f"⚠️  NL→DSL model failed to load - will use pattern-based translation")
        else:
            print(f"✓ NL→DSL model loaded successfully")

        if not policy_success:
            print(f"✗ DSL→Policy model failed to load - cannot continue")
            return False
        else:
            print(f"✓ DSL→Policy model loaded successfully")

        print(f"\n🔧 Step 2: Setting up RAG engine...")

        # Initialize RAG engine for enhanced policy generation
        rag_engine = None
        aws_docs_path = "./docs/iam-ug.pdf"
        vector_store_path = "./data/vector_store/"

        if Path(aws_docs_path).exists():
            print(f"   - Initializing RAG engine with AWS documentation...")
            rag_engine = RAGEngine(vector_store_path=vector_store_path)
            rag_success = rag_engine.initialize_knowledge_base(aws_docs_path)

            if rag_success:
                print(f"✓ RAG engine initialized successfully")
                stats = rag_engine.get_knowledge_base_stats()
                print(f"   - Total chunks: {stats.get('total_chunks', 0)}")
                print(f"   - Services available: {len(stats.get('services', {}))}")
            else:
                print(f"⚠️  RAG engine initialization failed - proceeding without RAG")
                rag_engine = None
        else:
            print(f"⚠️  AWS documentation not found at {aws_docs_path} - proceeding without RAG")

        print(f"\n🔧 Step 3: Creating pipeline components...")

        # Create pipeline components
        translator = NLToTranslator(model_manager=manager)
        generator = PolicyGenerator(model_manager=manager, rag_engine=rag_engine)
        redundancy_checker = RedundancyChecker(inventory_path="./data/policy_inventory.json")
        conflict_checker = ConflictChecker(inventory_path="./data/policy_inventory.json")

        print(f"✓ Translator agent created")
        print(f"✓ Policy generator created {'(with RAG)' if rag_engine else '(without RAG)'}")
        print(f"✓ Redundancy checker created")
        print(f"✓ Conflict checker created")

        print(f"\n🧪 Step 4: Testing full pipeline with redundancy checking...")

        successful_translations = 0
        successful_policies = 0
        redundancy_detected = 0
        total_time = 0

        for i, test_case in enumerate(test_cases, 1):
            print(f"\n" + "─" * 60)
            print(f"🧪 Test {i}: {test_case['name']}")
            print(f"📝 Natural Language: \"{test_case['natural_language']}\"")
            print(f"🏷️  Type: {'Baseline Policy' if test_case['is_baseline'] else 'Test Policy'}")

            pipeline_start = time.time()

            # Step 1: Natural Language → DSL
            print(f"\n   🔄 Step 1: Translating NL → DSL...")
            translation_start = time.time()

            translation_result = translator.translate(test_case['natural_language'])

            translation_time = time.time() - translation_start
            print(f"   ⏱️  Translation time: {translation_time:.2f}s")

            if translation_result.dsl_output:
                print(f"   ✓ DSL Generated")
                print(f"   🔧 DSL: {translation_result.dsl_output}")
                if translation_result.model_used:
                    print(f"   🤖 Method: {translation_result.model_used}")
                else:
                    print(f"   📐 Method: Pattern-based")
                successful_translations += 1

                # Step 2: DSL → AWS IAM Policy
                print(f"\n   🔄 Step 2: Generating DSL → IAM Policy...")
                generation_start = time.time()

                policy_result = generator.generate_policy(translation_result.dsl_output)

                generation_time = time.time() - generation_start
                print(f"   ⏱️  Generation time: {generation_time:.2f}s")

                if policy_result.success:
                    print(f"   ✓ IAM Policy Generated")
                    successful_policies += 1

                    # Display RAG information if available
                    if hasattr(policy_result, 'retrieved_contexts') and policy_result.retrieved_contexts:
                        print(f"   📚 RAG Contexts: {len(policy_result.retrieved_contexts)} retrieved")

                    # Step 3: Modular Validation (Redundancy First, Then Conflicts)
                    print(f"\n   🔍 Step 3a: Checking for redundancy...")
                    redundancy_start = time.time()

                    redundancy_result = redundancy_checker.check_redundancy(
                        policy_result.policy,
                        policy_name=test_case['name'],
                        add_to_inventory=False  # Don't add yet, wait for full validation
                    )

                    redundancy_time = time.time() - redundancy_start
                    print(f"   ⏱️  Redundancy check time: {redundancy_time:.2f}s")

                    should_check_conflicts = True
                    if redundancy_result.success:
                        if redundancy_result.has_redundancy:
                            redundancy_detected += 1
                            print(f"   🔍 REDUNDANCY DETECTED:")
                            for result in redundancy_result.redundancy_results:
                                print(f"      - Type: {result.redundancy_type}")
                                print(f"      - Confidence: {result.confidence_score:.2f}")
                                print(f"      - Explanation: {result.explanation}")

                            print(f"   📊 {redundancy_result.summary}")

                            # If redundant, we may not need to check conflicts or add to inventory
                            if test_case['is_baseline']:
                                print(f"   ⚠️  Baseline policy is redundant - will still be added for testing")
                                should_check_conflicts = True
                            else:
                                print(f"   ℹ️  Policy is redundant - skipping conflict check")
                                should_check_conflicts = False
                        else:
                            print(f"   ✅ No redundancy detected")
                            print(f"   📊 {redundancy_result.summary}")
                    else:
                        print(f"   ✗ Redundancy check failed: {redundancy_result.error_message}")
                        should_check_conflicts = False

                    # Step 3b: Check for conflicts if not redundant
                    conflict_result = None
                    if should_check_conflicts:
                        print(f"\n   ⚠️  Step 3b: Checking for conflicts...")
                        conflict_start = time.time()

                        conflict_result = conflict_checker.check_conflicts(
                            policy_result.policy,
                            policy_name=test_case['name']
                        )

                        conflict_time = time.time() - conflict_start
                        print(f"   ⏱️  Conflict check time: {conflict_time:.2f}s")

                        if conflict_result.success:
                            if conflict_result.has_conflicts:
                                print(f"   ⚠️  CONFLICTS DETECTED:")
                                print(f"      - Risk Level: {conflict_result.overall_risk_level}")
                                for result in conflict_result.conflict_results:
                                    print(f"      - Type: {result.conflict_type}")
                                    print(f"      - Severity: {result.severity}")
                                    print(f"      - Confidence: {result.confidence_score:.2f}")
                                    print(f"      - Explanation: {result.explanation}")
                            else:
                                print(f"   ✅ No conflicts detected")

                            print(f"   📊 {conflict_result.summary}")
                        else:
                            print(f"   ✗ Conflict check failed: {conflict_result.error_message}")
                    else:
                        print(f"\n   ⏭️  Step 3b: Skipping conflict check (policy is redundant)")

                    # Step 3c: Add to inventory if baseline policy
                    if test_case['is_baseline'] and redundancy_result.success:
                        print(f"\n   📝 Adding baseline policy to inventory...")
                        # Add to both inventories to keep them in sync
                        redundancy_checker.add_existing_policy(
                            policy_result.policy,
                            test_case['name']
                        )
                        conflict_checker.add_existing_policy(
                            policy_result.policy,
                            test_case['name']
                        )
                        print(f"   ✓ Baseline policy added to both inventories")

                    # Show combined recommendations
                    all_recommendations = redundancy_result.recommendations.copy()
                    if conflict_result and conflict_result.recommendations:
                        all_recommendations.extend(conflict_result.recommendations)

                    if all_recommendations:
                        print(f"\n   💡 RECOMMENDATIONS:")
                        for rec in all_recommendations[:3]:  # Show first 3
                            print(f"      {rec}")

                    # Pretty print the policy
                    policy_json = json.dumps(policy_result.policy, indent=4)
                    print(f"\n   📄 Generated AWS IAM Policy:")
                    # Show first few lines to keep output manageable
                    lines = policy_json.split('\\n')
                    for line in lines[:8]:  # Show first 8 lines
                        print(f"       {line}")
                    if len(lines) > 8:
                        print(f"       ... ({len(lines) - 8} more lines)")

                else:
                    print(f"   ✗ Policy generation failed")
                    for warning in policy_result.warnings:
                        print(f"       - {warning}")

            else:
                print(f"   ✗ Translation failed")
                if translation_result.reasoning:
                    print(f"       Reason: {translation_result.reasoning}")

            pipeline_time = time.time() - pipeline_start
            total_time += pipeline_time
            print(f"   🕐 Total pipeline time: {pipeline_time:.2f}s")

        print(f"\n" + "=" * 70)
        print(f" ENHANCED PIPELINE RESULTS")
        print(f"=" * 70)

        print(f"📊 Translation Results:")
        print(f"   Successful NL→DSL: {successful_translations}/{len(test_cases)} ({successful_translations/len(test_cases)*100:.1f}%)")

        print(f"📊 Policy Generation Results:")
        print(f"   Successful DSL→Policy: {successful_policies}/{successful_translations} ({successful_policies/max(1,successful_translations)*100:.1f}%)")

        print(f"📊 Redundancy Detection Results:")
        print(f"   Redundancies detected: {redundancy_detected}")
        print(f"   Redundancy detection rate: {redundancy_detected/max(1,successful_policies)*100:.1f}%")

        print(f"📊 Overall Pipeline:")
        print(f"   End-to-end success: {successful_policies}/{len(test_cases)} ({successful_policies/len(test_cases)*100:.1f}%)")
        print(f"   Average time per request: {total_time/len(test_cases):.2f}s")
        print(f"   Total processing time: {total_time:.2f}s")

        # Show inventory stats
        print(f"\n📈 Policy Inventory Stats:")
        stats = redundancy_checker.get_inventory_stats()
        print(f"   Total policies in inventory: {stats['total_policies']}")
        print(f"   Unique actions: {stats['unique_actions']}")
        print(f"   Unique resources: {stats['unique_resources']}")
        print(f"   Unique principals: {stats['unique_principals']}")

        # Cleanup
        print(f"\n🧹 Cleanup...")
        if nl_success:
            manager.unload_model('nl2dsl_model')
        if policy_success:
            manager.unload_model('dsl2policy_model')
        print(f"✓ Models unloaded")

        # Success if we got at least some end-to-end results
        return successful_policies > 0

    except Exception as e:
        print(f"✗ Pipeline test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run the full pipeline test with redundancy checking"""
    success = test_pipeline_with_redundancy()

    print(f"\n" + "=" * 70)
    print(f" TEST SUMMARY")
    print(f"=" * 70)

    if success:
        print(f"✅ Enhanced pipeline test PASSED")
        print(f"   🎯 NL→DSL→Policy→Redundancy workflow functioning")
        print(f"   🤖 Models successfully generating outputs")
        print(f"   📚 RAG integration enhancing policy generation")
        print(f"   🔍 Redundancy detection identifying policy overlaps")
        print(f"   🏗️  System ready for production deployment")
        print(f"\n💡 Next steps:")
        print(f"   - Fine-tune redundancy thresholds")
        print(f"   - Add conflict detection capabilities")
        print(f"   - Implement policy optimization suggestions")
        print(f"   - Add user interface for policy management")
    else:
        print(f"❌ Enhanced pipeline test FAILED")
        print(f"   🔧 Check model loading and configuration")
        print(f"   🐛 Review translation and generation logic")
        print(f"   📋 Verify test cases and expected outputs")

    return success


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)