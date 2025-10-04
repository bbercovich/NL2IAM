#!/usr/bin/env python3
"""
Test script for RAG integration with Policy Generator

This script tests the complete RAG pipeline:
1. Initialize RAG engine with AWS documentation
2. Test context retrieval for DSL statements
3. Test policy generation with RAG enhancement
"""

import sys
import logging
from pathlib import Path

# Add src to path
sys.path.append('src')

from rag.rag_engine import RAGEngine
from agents.policy_generator import PolicyGenerator
from models.model_manager import ModelManager


def test_rag_engine():
    """Test RAG engine initialization and basic functionality"""
    print("=" * 60)
    print("Testing RAG Engine Initialization")
    print("=" * 60)

    # Initialize RAG engine
    rag_engine = RAGEngine(vector_store_path="./data/vector_store/")

    # Test knowledge base initialization
    aws_docs_path = "../docs/iam-ug.pdf"

    if not Path(aws_docs_path).exists():
        print(f"❌ AWS documentation not found at: {aws_docs_path}")
        print("Please ensure the AWS IAM User Guide PDF is available.")
        return None

    print("📚 Initializing knowledge base with AWS IAM documentation...")
    success = rag_engine.initialize_knowledge_base(aws_docs_path)

    if success:
        print("✅ Knowledge base initialized successfully")

        # Show stats
        stats = rag_engine.get_knowledge_base_stats()
        print(f"📊 Knowledge base stats:")
        print(f"   Total chunks: {stats.get('total_chunks', 0)}")
        print(f"   Chunk types: {stats.get('chunk_types', {})}")
        print(f"   Top services: {dict(list(stats.get('services', {}).items())[:5])}")

        return rag_engine
    else:
        print("❌ Failed to initialize knowledge base")
        return None


def test_context_retrieval(rag_engine):
    """Test context retrieval for various DSL statements"""
    print("\n" + "=" * 60)
    print("Testing Context Retrieval")
    print("=" * 60)

    test_dsl_statements = [
        "ALLOW user:alice ACTION:s3:GetObject ON bucket:public-bucket/*",
        "DENY user:bob ACTION:ec2:TerminateInstances ON instance:*",
        "ALLOW role:developer ACTION:dynamodb:GetItem ON table:user-data",
        "ALLOW * ACTION:iam:ListUsers WHERE aws:RequestedRegion=us-east-1"
    ]

    for i, dsl_statement in enumerate(test_dsl_statements, 1):
        print(f"\n🔍 Test {i}: {dsl_statement}")

        result = rag_engine.retrieve_context(dsl_statement, n_results=3)

        print(f"   Retrieved contexts: {len(result.retrieved_contexts)}")

        if result.retrieved_contexts:
            avg_relevance = result.retrieval_metadata.get('average_relevance_score', 0)
            print(f"   Average relevance: {avg_relevance:.3f}")

            for j, context in enumerate(result.retrieved_contexts[:2], 1):
                print(f"   Context {j} (Score: {context['relevance_score']:.3f}, "
                      f"Type: {context['metadata']['chunk_type']})")
                print(f"      {context['content'][:100]}...")
        else:
            print("   ⚠️ No relevant contexts found")


def test_policy_generation_with_rag(rag_engine):
    """Test policy generation with RAG integration"""
    print("\n" + "=" * 60)
    print("Testing Policy Generation with RAG")
    print("=" * 60)

    # Note: This test assumes you have a model manager available
    # For demonstration, we'll create a mock test
    print("📝 Testing policy generation integration...")

    try:
        # Mock model manager for testing (replace with actual when available)
        class MockModelManager:
            def is_model_loaded(self, model_name):
                return False  # Simulate no model loaded for this test

            def generate(self, model_name, prompt, **kwargs):
                return '{"Version": "2012-10-17", "Statement": []}'

        # Create policy generator with RAG
        mock_model_manager = MockModelManager()
        policy_generator = PolicyGenerator(mock_model_manager, rag_engine)

        test_dsl = "ALLOW user:alice ACTION:s3:GetObject ON bucket:public-bucket/*"
        print(f"🔧 Generating policy for: {test_dsl}")

        result = policy_generator.generate_policy(test_dsl)

        print(f"✅ Generation completed:")
        print(f"   Success: {result.success}")
        print(f"   Warnings: {len(result.warnings)}")

        if result.retrieved_contexts:
            print(f"   RAG contexts used: {len(result.retrieved_contexts)}")
        else:
            print("   ⚠️ No RAG contexts available")

        for warning in result.warnings:
            print(f"   ⚠️ {warning}")

    except Exception as e:
        print(f"❌ Error testing policy generation: {e}")


def main():
    """Main test function"""
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    print("🚀 RAG Integration Test Suite")
    print("Testing AWS IAM Policy Generation with Retrieval-Augmented Generation")

    # Test 1: RAG Engine Initialization
    rag_engine = test_rag_engine()

    if rag_engine is None:
        print("\n❌ RAG engine initialization failed. Cannot proceed with tests.")
        return

    # Test 2: Context Retrieval
    test_context_retrieval(rag_engine)

    # Test 3: Policy Generation Integration
    test_policy_generation_with_rag(rag_engine)

    print("\n" + "=" * 60)
    print("✅ RAG Integration Tests Completed")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Load your actual models in the ModelManager")
    print("2. Test with real policy generation")
    print("3. Evaluate policy quality with and without RAG")


if __name__ == "__main__":
    main()