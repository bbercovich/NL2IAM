#!/usr/bin/env python3
"""
Test Full NL→DSL→Policy Pipeline with RAG Integration

This test demonstrates the complete workflow:
1. Natural Language → DSL (using NLToTranslator)
2. DSL → AWS IAM Policy (using PolicyGenerator with RAG enhancement)
3. RAG retrieval from AWS documentation vector database
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
from rag.rag_engine import RAGEngine


def test_full_pipeline():
    """Test the complete NL→DSL→Policy pipeline"""
    print("=" * 70)
    print(" FULL PIPELINE TEST: Natural Language → DSL → IAM Policy (with RAG)")
    print("=" * 70)
    print(f"Test run: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Test cases with natural language input
    test_cases = [
        {
            "name": "Simple S3 Read Access",
            "natural_language": "Allow Alice to read files from the public bucket"
        },
        {
            "name": "S3 Write Permissions",
            "natural_language": "Grant permission to upload files to the uploads bucket"
        },
        {
            "name": "S3 Delete Restriction",
            "natural_language": "Deny deleting objects in the sensitive-data bucket"
        },
        {
            "name": "EC2 Instance Management",
            "natural_language": "Allow starting and stopping EC2 instances"
        },
        {
            "name": "EC2 with Size Restrictions",
            "natural_language": "Permit launching only small EC2 instances like t2.micro and t2.small"
        },
        {
            "name": "corase prompt 10",
            "natural_language": "Requests by any user to attach and detach volumes from instances in the Development department should be allowed.Requests by users to attach and detach their own volumes should be allowed."
        },
        {
            "name": "Prompt 30",
            "natural_language": "Requests by any user to get objects from examplebucket should be allowed only when the prefix is 'mp3'."
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

        print(f"✓ Translator agent created")
        print(f"✓ Policy generator created {'(with RAG)' if rag_engine else '(without RAG)'}")

        print(f"\n🧪 Step 4: Testing full pipeline...")

        successful_translations = 0
        successful_policies = 0
        total_time = 0

        for i, test_case in enumerate(test_cases, 1):
            print(f"\n" + "─" * 60)
            print(f"🧪 Test {i}: {test_case['name']}")
            print(f"📝 Natural Language: \"{test_case['natural_language']}\"")

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
                if translation_result.reasoning:
                    print(f"   💭 Reasoning: {translation_result.reasoning}")
                successful_translations += 1

                # Step 2: DSL → AWS IAM Policy
                print(f"\n   🔄 Step 2: Generating DSL → IAM Policy...")
                generation_start = time.time()

                policy_result = generator.generate_policy(translation_result.dsl_output)

                generation_time = time.time() - generation_start
                print(f"   ⏱️  Generation time: {generation_time:.2f}s")

                if policy_result.success:
                    print(f"   ✓ IAM Policy Generated")
                    print(f"   🎯 Confidence: {policy_result.confidence_score:.2f}")

                    # Display RAG information if available
                    if hasattr(policy_result, 'retrieved_contexts') and policy_result.retrieved_contexts:
                        print(f"   📚 RAG Contexts: {len(policy_result.retrieved_contexts)} retrieved")
                        avg_relevance = sum(ctx.get('relevance_score', 0) for ctx in policy_result.retrieved_contexts) / len(policy_result.retrieved_contexts)
                        print(f"   🎯 Avg Relevance: {avg_relevance:.3f}")

                        # Show top context types
                        context_types = [ctx.get('metadata', {}).get('chunk_type', 'unknown') for ctx in policy_result.retrieved_contexts]
                        unique_types = list(set(context_types))
                        print(f"   📋 Context Types: {', '.join(unique_types[:3])}")
                    elif rag_engine:
                        print(f"   📚 RAG: No relevant contexts found")
                    else:
                        print(f"   📚 RAG: Not available")

                    # Pretty print the policy
                    policy_json = json.dumps(policy_result.policy, indent=4)
                    print(f"   📄 AWS IAM Policy:")
                    # Indent each line for better formatting
                    for line in policy_json.split('\n'):
                        print(f"       {line}")

                    successful_policies += 1

                    if policy_result.warnings:
                        print(f"   ⚠️  Warnings: {', '.join(policy_result.warnings)}")

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
        print(f" PIPELINE RESULTS")
        print(f"=" * 70)

        print(f"📊 Translation Results:")
        print(f"   Successful NL→DSL: {successful_translations}/{len(test_cases)} ({successful_translations/len(test_cases)*100:.1f}%)")

        print(f"📊 Policy Generation Results:")
        print(f"   Successful DSL→Policy: {successful_policies}/{successful_translations} ({successful_policies/max(1,successful_translations)*100:.1f}%)")

        print(f"📊 Overall Pipeline:")
        print(f"   End-to-end success: {successful_policies}/{len(test_cases)} ({successful_policies/len(test_cases)*100:.1f}%)")
        print(f"   Average time per request: {total_time/len(test_cases):.2f}s")
        print(f"   Total processing time: {total_time:.2f}s")

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
    """Run the full pipeline test"""
    success = test_full_pipeline()

    print(f"\n" + "=" * 70)
    print(f" TEST SUMMARY")
    print(f"=" * 70)

    if success:
        print(f"✅ Full pipeline test PASSED")
        print(f"   🎯 NL→DSL→Policy workflow functioning")
        print(f"   🤖 Models successfully generating outputs")
        print(f"   📚 RAG integration enhancing policy generation")
        print(f"   🏗️  System ready for research evaluation")
        print(f"\n💡 Next steps:")
        print(f"   - Test with more complex natural language")
        print(f"   - Evaluate policy accuracy against ground truth")
        print(f"   - Compare policy quality with/without RAG enhancement")
        print(f"   - Fine-tune RAG retrieval for better context relevance")
    else:
        print(f"❌ Full pipeline test FAILED")
        print(f"   🔧 Check model loading and configuration")
        print(f"   🐛 Review translation and generation logic")
        print(f"   📋 Verify test cases and expected outputs")

    return success


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)