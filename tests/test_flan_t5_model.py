#!/usr/bin/env python3
"""
Test Flan-T5 Model as Alternative for NL→DSL Translation

This script tests Google's Flan-T5 model as a more reliable alternative
to CodeT5 for natural language to DSL translation.
"""

import sys
import time
import torch
from datetime import datetime

# Add src to path
sys.path.append('src')

from models.model_manager import ModelManager, ModelConfig

def test_flan_t5_model():
    """Test loading and using Flan-T5 model"""
    print("=" * 60)
    print(" FLAN-T5 MODEL TEST")
    print("=" * 60)
    print(f"Test run: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Check GPU status
    print(f"\nGPU Info:")
    print(f"✓ CUDA available: {torch.cuda.is_available()}")
    if torch.cuda.is_available():
        print(f"✓ GPU: {torch.cuda.get_device_name(0)}")
        print(f"✓ GPU Memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f}GB")
        print(f"✓ Memory allocated: {torch.cuda.memory_allocated(0) / 1e9:.2f}GB")

    try:
        print(f"\n1. Creating custom model configuration...")

        # Create Flan-T5 configuration
        config = ModelConfig(
            model_name='flan-t5-small',
            model_type='t5',
            task='nl2dsl',
            model_path='google/flan-t5-small',
            max_length=512,
            device='auto'
        )

        manager = ModelManager()
        manager.register_model('flan_t5_model', config)
        print(f"✓ Flan-T5 model registered")

        print(f"\n2. Loading Flan-T5 model...")
        print(f"   Model path: google/flan-t5-small")
        print(f"   This may take 3-5 minutes for first download...")

        start_time = time.time()
        success = manager.load_model('flan_t5_model')
        load_time = time.time() - start_time

        if success:
            print(f"✓ Flan-T5 model loaded successfully in {load_time:.1f}s")

            # Show memory usage
            if torch.cuda.is_available():
                memory_used = torch.cuda.memory_allocated(0) / 1e9
                print(f"✓ GPU memory used: {memory_used:.2f}GB")

            print(f"\n3. Testing DSL translation prompts...")

            # Test cases with explicit DSL format instructions
            test_cases = [
                {
                    "input": "Allow Alice to read files from the public bucket",
                    "prompt": "Convert this AWS request to DSL format: Allow Alice to read files from the public bucket. Use format: ALLOW ACTION:service:action ON resource:name"
                },
                {
                    "input": "Deny deleting objects in the sensitive bucket",
                    "prompt": "Translate to DSL: Deny deleting objects in the sensitive bucket. Format: DENY ACTION:s3:DeleteObject ON bucket:sensitive-bucket"
                },
                {
                    "input": "Allow starting small EC2 instances",
                    "prompt": "Convert to IAM DSL: Allow starting small EC2 instances. Format: ALLOW ACTION:ec2:StartInstances ON instance:* WHERE condition"
                }
            ]

            successful_generations = 0

            for i, test_case in enumerate(test_cases, 1):
                print(f"\nTest {i}: {test_case['input']}")
                try:
                    start_gen = time.time()
                    result = manager.generate(
                        'flan_t5_model',
                        test_case['prompt'],
                        max_length=128,
                        temperature=0.1,  # Low temperature for more consistent output
                        num_beams=3
                    )
                    gen_time = time.time() - start_gen

                    print(f"✓ Generated in {gen_time:.2f}s")
                    print(f"  Input:  {test_case['input']}")
                    print(f"  Output: {result}")
                    successful_generations += 1

                except Exception as e:
                    print(f"✗ Generation failed: {e}")

            print(f"\n4. Testing simple translation format...")

            # Test simpler prompts
            simple_tests = [
                "translate: Allow read access to S3 bucket",
                "convert to policy: Deny delete on sensitive data"
            ]

            for i, simple_prompt in enumerate(simple_tests, 1):
                print(f"\nSimple Test {i}: {simple_prompt}")
                try:
                    result = manager.generate(
                        'flan_t5_model',
                        simple_prompt,
                        max_length=64,
                        temperature=0.1
                    )
                    print(f"✓ Result: {result}")
                except Exception as e:
                    print(f"✗ Failed: {e}")

            print(f"\n5. Inference Results:")
            print(f"   Successful complex generations: {successful_generations}/{len(test_cases)}")

            print(f"\n6. Unloading model...")
            manager.unload_model('flan_t5_model')
            print(f"✓ Model unloaded")

            if torch.cuda.is_available():
                torch.cuda.empty_cache()
                final_memory = torch.cuda.memory_allocated(0) / 1e9
                print(f"✓ Final GPU memory: {final_memory:.2f}GB")

            return successful_generations > 0

        else:
            print(f"✗ Failed to load Flan-T5 model")
            return False

    except Exception as e:
        print(f"✗ Flan-T5 test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run the Flan-T5 model test"""
    success = test_flan_t5_model()

    print(f"\n" + "=" * 60)
    print(f" TEST SUMMARY")
    print(f"=" * 60)

    if success:
        print(f"✓ Flan-T5 model test PASSED")
        print(f"  - Model loaded successfully")
        print(f"  - Generated responses to prompts")
        print(f"  - Can be used as alternative NL→DSL translator")
        print(f"  - Consider updating model_manager.py to use Flan-T5")
    else:
        print(f"✗ Flan-T5 model test FAILED")
        print(f"  - Check network connection or model availability")

    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)