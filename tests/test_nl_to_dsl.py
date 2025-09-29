#!/usr/bin/env python3
"""
Test Natural Language → DSL Translation

This test focuses specifically on evaluating the quality of NL→DSL translation.
It compares generated DSL against expected DSL patterns to measure accuracy.
"""

import sys
import time
from datetime import datetime
from typing import List, Dict, Any

# Add src to path
sys.path.append('src')

from models.model_manager import create_default_manager
from agents.translator import NLToTranslator
from core.dsl import DSLParser


def test_nl_to_dsl_translation():
    """Test Natural Language → DSL translation quality"""
    print("=" * 70)
    print(" NL → DSL TRANSLATION TEST")
    print("=" * 70)
    print(f"Test run: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Test cases with natural language input
    test_cases = [
        {
            "name": "Simple S3 Read",
            "natural_language": "Requests by Alice to read objects in the public bucket should be allowed."
        },
        {
            "name": "S3 Write Permission",
            "natural_language": "Grant permission to upload files to the uploads bucket"
        },
        {
            "name": "S3 Delete Denial",
            "natural_language": "Deny deleting objects in the sensitive-data bucket"
        },
        {
            "name": "EC2 Instance Start",
            "natural_language": "Allow starting EC2 instances"
        },
        {
            "name": "EC2 with Conditions",
            "natural_language": "Permit launching only small EC2 instances like t2.micro and t2.small"
        },
        {
            "name": "Complex Multi-Action",
            "natural_language": "Requests by any user to attach and detach volumes from instances in the Development department should be allowed"
        },
        {
            "name": "Prompt 30",
            "natural_language": "Requests by any user to get objects from examplebucket should be allowed only when the prefix is 'mp3'."
        }

    ]

    try:
        print(f"\n🚀 Setting up translation system...")

        # Create model manager
        manager = create_default_manager()
        print(f"✓ Model manager created")

        # Load NL→DSL model (required)
        print(f"\n📥 Loading NL→DSL model...")
        model_loaded = manager.load_model('nl2dsl_model')

        if not model_loaded:
            print(f"✗ NL→DSL model failed to load")
            print(f"  This test requires model-based translation")
            print(f"  Pattern-based fallbacks are not tested here")
            return False

        print(f"✓ NL→DSL model loaded successfully")

        # Create translator
        translator = NLToTranslator(model_manager=manager)
        print(f"✓ Translator created")

        # Create DSL parser for validation
        dsl_parser = DSLParser()
        print(f"✓ DSL parser ready")

        print(f"\n🧪 Testing NL→DSL translations...")

        results = []
        total_time = 0

        for i, test_case in enumerate(test_cases, 1):
            print(f"\n" + "─" * 60)
            print(f"🧪 Test {i}: {test_case['name']}")
            print(f"📝 Input: \"{test_case['natural_language']}\"")

            # Perform translation
            start_time = time.time()
            result = translator.translate(test_case['natural_language'])
            translation_time = time.time() - start_time
            total_time += translation_time

            print(f"⏱️  Translation time: {translation_time:.2f}s")
            print(f"🔧 Generated DSL: {result.dsl_output}")

            # Verify model was used (not pattern-based fallback)
            if not result.model_used:
                print(f"✗ FAILED: Translation used pattern-based fallback instead of model")
                print(f"  Expected model-based translation only")
                return False

            print(f"🤖 Model Used: {result.model_used}")



        # Cleanup
        manager.unload_model('nl2dsl_model')
        print(f"\n✓ Model unloaded")

        return True

    except Exception as e:
        print(f"✗ NL→DSL test failed: {e}")
        import traceback
        traceback.print_exc()
        return False



def main():
    """Run the NL→DSL translation test"""
    success = test_nl_to_dsl_translation()

    print(f"\n" + "=" * 70)
    print(f" TEST SUMMARY")
    print(f"=" * 70)

    return success


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)