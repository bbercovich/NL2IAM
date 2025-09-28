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

    # Test cases with natural language input and expected DSL patterns
    test_cases = [
        {
            "name": "Simple S3 Read",
            "natural_language": "Allow Alice to read files from the public bucket",
            "expected_patterns": [
                "ALLOW ACTION:s3:GetObject ON bucket:public",
                "ALLOW ACTION:s3:GetObject ON bucket:public-bucket",
                "ALLOW ACTION:s3:* ON bucket:public"
            ],
            "expected_elements": {
                "effect": "ALLOW",
                "service": "s3",
                "action_contains": ["GetObject", "Get", "*"],
                "resource_type": "bucket",
                "resource_name_contains": ["public"]
            }
        },
        {
            "name": "S3 Write Permission",
            "natural_language": "Grant permission to upload files to the uploads bucket",
            "expected_patterns": [
                "ALLOW ACTION:s3:PutObject ON bucket:uploads",
                "ALLOW ACTION:s3:PutObject ON bucket:upload",
                "ALLOW ACTION:s3:* ON bucket:uploads"
            ],
            "expected_elements": {
                "effect": "ALLOW",
                "service": "s3",
                "action_contains": ["PutObject", "Put", "*"],
                "resource_type": "bucket",
                "resource_name_contains": ["upload"]
            }
        },
        {
            "name": "S3 Delete Denial",
            "natural_language": "Deny deleting objects in the sensitive-data bucket",
            "expected_patterns": [
                "DENY ACTION:s3:DeleteObject ON bucket:sensitive-data",
                "DENY ACTION:s3:DeleteObject ON bucket:sensitive",
                "DENY ACTION:s3:Delete* ON bucket:sensitive-data"
            ],
            "expected_elements": {
                "effect": "DENY",
                "service": "s3",
                "action_contains": ["DeleteObject", "Delete"],
                "resource_type": "bucket",
                "resource_name_contains": ["sensitive"]
            }
        },
        {
            "name": "EC2 Instance Start",
            "natural_language": "Allow starting EC2 instances",
            "expected_patterns": [
                "ALLOW ACTION:ec2:StartInstances ON instance:*",
                "ALLOW ACTION:ec2:StartInstances ON *",
                "ALLOW ACTION:ec2:Start* ON instance:*"
            ],
            "expected_elements": {
                "effect": "ALLOW",
                "service": "ec2",
                "action_contains": ["StartInstances", "Start"],
                "resource_type": "instance",
                "resource_name_contains": ["*"]
            }
        },
        {
            "name": "EC2 with Conditions",
            "natural_language": "Permit launching only small EC2 instances like t2.micro and t2.small",
            "expected_patterns": [
                "ALLOW ACTION:ec2:RunInstances ON instance:* WHERE ec2:InstanceType IN [t2.micro,t2.small]",
                "ALLOW ACTION:ec2:StartInstances ON instance:* WHERE ec2:InstanceType IN [t2.micro,t2.small]",
                "ALLOW ACTION:ec2:*Instances ON instance:* WHERE *InstanceType* IN [t2.micro,t2.small]"
            ],
            "expected_elements": {
                "effect": "ALLOW",
                "service": "ec2",
                "action_contains": ["RunInstances", "StartInstances", "Instances"],
                "resource_type": "instance",
                "resource_name_contains": ["*"],
                "conditions": ["t2.micro", "t2.small", "InstanceType"]
            }
        },
        {
            "name": "Complex Multi-Action",
            "natural_language": "Requests by any user to attach and detach volumes from instances in the Development department should be allowed",
            "expected_patterns": [
                "ALLOW ACTION:ec2:AttachVolume,ec2:DetachVolume ON *",
                "ALLOW ACTION:ec2:*Volume ON instance:*",
                "ALLOW ACTION:ec2:AttachVolume ON * AND ALLOW ACTION:ec2:DetachVolume ON *"
            ],
            "expected_elements": {
                "effect": "ALLOW",
                "service": "ec2",
                "action_contains": ["AttachVolume", "DetachVolume", "Volume"],
                "resource_type": ["instance", "volume", "*"],
                "resource_name_contains": ["*"]
            }
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
            print(f"🎯 Confidence: {result.confidence:.2f}")

            # Verify model was used (not pattern-based fallback)
            if not result.model_used:
                print(f"✗ FAILED: Translation used pattern-based fallback instead of model")
                print(f"  Expected model-based translation only")
                return False

            print(f"🤖 Model Used: {result.model_used}")

            # Analyze translation quality
            quality_score = analyze_translation_quality(
                result.dsl_output,
                test_case["expected_patterns"],
                test_case["expected_elements"]
            )

            # Test DSL parsing
            parse_success = test_dsl_parsing(dsl_parser, result.dsl_output)

            # Record results
            test_result = {
                "name": test_case["name"],
                "input": test_case["natural_language"],
                "output": result.dsl_output,
                "confidence": result.confidence,
                "quality_score": quality_score,
                "parse_success": parse_success,
                "translation_time": translation_time,
                "model_used": result.model_used
            }
            results.append(test_result)

            # Display quality assessment
            print(f"📊 Quality Score: {quality_score:.2f}/1.0")
            print(f"✅ DSL Parsing: {'✓ Valid' if parse_success else '✗ Invalid'}")

            if quality_score < 0.5:
                print(f"⚠️  Low quality translation - review expected patterns:")
                for pattern in test_case["expected_patterns"][:2]:
                    print(f"   Expected: {pattern}")

        # Summary results
        print(f"\n" + "=" * 70)
        print(f" TRANSLATION QUALITY ANALYSIS")
        print(f"=" * 70)

        avg_quality = sum(r["quality_score"] for r in results) / len(results)
        avg_confidence = sum(r["confidence"] for r in results) / len(results)
        parse_success_rate = sum(1 for r in results if r["parse_success"]) / len(results)
        avg_time = total_time / len(results)

        print(f"📊 Overall Metrics:")
        print(f"   Average Quality Score: {avg_quality:.2f}/1.0")
        print(f"   Average Confidence: {avg_confidence:.2f}")
        print(f"   DSL Parse Success Rate: {parse_success_rate*100:.1f}%")
        print(f"   Average Translation Time: {avg_time:.2f}s")

        print(f"\n📋 Individual Results:")
        for result in results:
            status = "✓" if result["quality_score"] >= 0.6 else "⚠️" if result["quality_score"] >= 0.3 else "✗"
            print(f"   {status} {result['name']}: Quality={result['quality_score']:.2f}, Parse={'✓' if result['parse_success'] else '✗'}")

        print(f"\n💡 Translation Quality Guidelines:")
        print(f"   🟢 Excellent (0.8-1.0): Ready for production")
        print(f"   🟡 Good (0.6-0.8): Minor refinements needed")
        print(f"   🟠 Fair (0.3-0.6): Significant improvements needed")
        print(f"   🔴 Poor (0.0-0.3): Major rework required")

        # Cleanup
        manager.unload_model('nl2dsl_model')
        print(f"\n✓ Model unloaded")

        return avg_quality >= 0.5  # Success if average quality is decent

    except Exception as e:
        print(f"✗ NL→DSL test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def analyze_translation_quality(generated_dsl: str, expected_patterns: List[str], expected_elements: Dict[str, Any]) -> float:
    """
    Analyze the quality of DSL translation against expected patterns and elements
    Returns a score from 0.0 to 1.0
    """
    if not generated_dsl or generated_dsl.strip() == "":
        return 0.0

    score = 0.0
    max_score = 0.0

    # Check against expected patterns (exact or partial matches)
    pattern_score = 0.0
    for pattern in expected_patterns:
        if pattern.lower() in generated_dsl.lower():
            pattern_score = 1.0
            break
        # Partial matching for key components
        pattern_parts = pattern.lower().split()
        dsl_parts = generated_dsl.lower().split()
        common_parts = len(set(pattern_parts) & set(dsl_parts))
        if common_parts > 0:
            pattern_score = max(pattern_score, common_parts / len(pattern_parts))

    score += pattern_score * 0.4  # 40% weight for pattern matching
    max_score += 0.4

    # Check individual elements
    elements = expected_elements

    # Effect (ALLOW/DENY)
    if "effect" in elements:
        if elements["effect"].upper() in generated_dsl.upper():
            score += 0.15
        max_score += 0.15

    # Service
    if "service" in elements:
        if elements["service"].lower() in generated_dsl.lower():
            score += 0.15
        max_score += 0.15

    # Action
    if "action_contains" in elements:
        action_found = False
        for action in elements["action_contains"]:
            if action.lower() in generated_dsl.lower():
                action_found = True
                break
        if action_found:
            score += 0.15
        max_score += 0.15

    # Resource type
    if "resource_type" in elements:
        resource_types = elements["resource_type"] if isinstance(elements["resource_type"], list) else [elements["resource_type"]]
        resource_found = False
        for resource_type in resource_types:
            if resource_type.lower() in generated_dsl.lower():
                resource_found = True
                break
        if resource_found:
            score += 0.1
        max_score += 0.1

    # Resource name
    if "resource_name_contains" in elements:
        resource_found = False
        for resource_name in elements["resource_name_contains"]:
            if resource_name.lower() in generated_dsl.lower():
                resource_found = True
                break
        if resource_found:
            score += 0.05
        max_score += 0.05

    # Conditions
    if "conditions" in elements:
        condition_score = 0.0
        condition_count = 0
        for condition in elements["conditions"]:
            if condition.lower() in generated_dsl.lower():
                condition_score += 1
            condition_count += 1
        if condition_count > 0:
            score += (condition_score / condition_count) * 0.1
        max_score += 0.1

    return score / max_score if max_score > 0 else 0.0


def test_dsl_parsing(parser: DSLParser, dsl_text: str) -> bool:
    """Test if the generated DSL can be successfully parsed"""
    try:
        result = parser.parse(dsl_text)
        return result is not None and result.statements and len(result.statements) > 0
    except Exception:
        return False


def main():
    """Run the NL→DSL translation test"""
    success = test_nl_to_dsl_translation()

    print(f"\n" + "=" * 70)
    print(f" TEST SUMMARY")
    print(f"=" * 70)

    if success:
        print(f"✅ NL→DSL translation test PASSED")
        print(f"   🎯 Translation quality meets minimum standards")
        print(f"   🔧 DSL generation functioning correctly")
        print(f"   📈 Ready for quality improvement iterations")
        print(f"\n💡 Next steps:")
        print(f"   - Analyze low-scoring translations")
        print(f"   - Improve pattern matching or model prompts")
        print(f"   - Add more diverse test cases")
        print(f"   - Fine-tune model if using model-based translation")
    else:
        print(f"❌ NL→DSL translation test FAILED")
        print(f"   🔧 Translation quality below acceptable threshold")
        print(f"   📋 Review translator logic and patterns")
        print(f"   🤖 Consider model improvements or better prompts")

    return success


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)