#!/usr/bin/env python3
"""
Test LLaMA Model for DSL→Policy Generation

This script tests loading and using a LLaMA-based model for converting
DSL statements into AWS IAM policies.
"""

import sys
import time
import torch
from datetime import datetime

# Add src to path
sys.path.append('src')

from models.model_manager import create_default_manager, ModelManager, ModelConfig

def test_llama_model():
    """Test loading and using LLaMA model for DSL→Policy"""
    print("=" * 60)
    print(" LLAMA MODEL TEST")
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
        print(f"\n1. Testing default LLaMA configuration...")

        manager = create_default_manager()
        print(f"✓ Model manager created with default LLaMA config")

        print(f"\n2. Loading LLaMA model (dsl2policy_model)...")
        print(f"   Model path: codellama/CodeLlama-7b-Instruct-hf")
        print(f"   Using 8-bit quantization for memory efficiency")
        print(f"   This may take 10-15 minutes for first download...")

        start_time = time.time()
        success = manager.load_model('dsl2policy_model')
        load_time = time.time() - start_time

        if success:
            print(f"✓ LLaMA model loaded successfully in {load_time:.1f}s")

            # Show memory usage
            if torch.cuda.is_available():
                memory_used = torch.cuda.memory_allocated(0) / 1e9
                print(f"✓ GPU memory used: {memory_used:.2f}GB")

            print(f"\n3. Testing DSL→Policy generation...")

            # Test cases with DSL input
            test_cases = [
                {
                    "dsl": "ALLOW ACTION:s3:GetObject ON bucket:public-bucket/*",
                    "description": "Simple S3 read access"
                },
                {
                    "dsl": "DENY ACTION:s3:DeleteObject ON bucket:sensitive-bucket/*",
                    "description": "S3 delete denial"
                },
                {
                    "dsl": "ALLOW ACTION:ec2:StartInstances ON instance:* WHERE ec2:InstanceType IN [t2.micro,t2.small]",
                    "description": "EC2 instance management with conditions"
                }
            ]

            successful_generations = 0

            for i, test_case in enumerate(test_cases, 1):
                print(f"\nTest {i}: {test_case['description']}")
                print(f"   DSL: {test_case['dsl']}")

                # Create a prompt for DSL→Policy conversion
                prompt = f"""Convert this AWS IAM DSL statement to a valid AWS IAM policy JSON:

DSL: {test_case['dsl']}

Generate a complete AWS IAM policy with Version and Statement fields:"""

                try:
                    start_gen = time.time()
                    result = manager.generate(
                        'dsl2policy_model',
                        prompt,
                        max_new_tokens=200,
                        temperature=0.1,
                        top_p=0.9
                    )
                    gen_time = time.time() - start_gen

                    print(f"✓ Generated in {gen_time:.2f}s")
                    print(f"   Result: {result[:200]}...")  # Show first 200 chars
                    successful_generations += 1

                except Exception as e:
                    print(f"✗ Generation failed: {e}")

            print(f"\n4. Testing simple prompts...")

            simple_tests = [
                "Generate AWS IAM policy for S3 read access",
                "Create policy: allow EC2 start"
            ]

            for i, simple_prompt in enumerate(simple_tests, 1):
                print(f"\nSimple Test {i}: {simple_prompt}")
                try:
                    result = manager.generate(
                        'dsl2policy_model',
                        simple_prompt,
                        max_new_tokens=100,
                        temperature=0.1
                    )
                    print(f"✓ Result: {result[:150]}...")
                except Exception as e:
                    print(f"✗ Failed: {e}")

            print(f"\n5. Generation Results:")
            print(f"   Successful DSL→Policy generations: {successful_generations}/{len(test_cases)}")

            print(f"\n6. Unloading model...")
            manager.unload_model('dsl2policy_model')
            print(f"✓ Model unloaded")

            if torch.cuda.is_available():
                torch.cuda.empty_cache()
                final_memory = torch.cuda.memory_allocated(0) / 1e9
                print(f"✓ Final GPU memory: {final_memory:.2f}GB")

            return successful_generations > 0

        else:
            print(f"✗ Failed to load LLaMA model")
            return False

    except Exception as e:
        print(f"✗ LLaMA test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_alternative_llama():
    """Test alternative LLaMA configuration"""
    print(f"\n" + "-" * 60)
    print(f" TESTING ALTERNATIVE LLAMA MODEL")
    print(f"-" * 60)

    try:
        # Try a smaller, more accessible model
        config = ModelConfig(
            model_name='llama2-7b-chat',
            model_type='llama',
            task='dsl2policy',
            model_path='meta-llama/Llama-2-7b-chat-hf',  # Alternative path
            max_length=2048,
            device='auto',
            load_in_8bit=True
        )

        manager = ModelManager()
        manager.register_model('alt_llama_model', config)

        print(f"Trying alternative LLaMA model...")
        success = manager.load_model('alt_llama_model')

        if success:
            print(f"✓ Alternative LLaMA loaded")

            # Quick test
            result = manager.generate(
                'alt_llama_model',
                "Create AWS IAM policy for S3 access",
                max_new_tokens=50
            )
            print(f"✓ Generated: {result}")

            manager.unload_model('alt_llama_model')
            return True
        else:
            print(f"✗ Alternative LLaMA failed to load")
            return False

    except Exception as e:
        print(f"✗ Alternative test failed: {e}")
        return False

def main():
    """Run the LLaMA model tests"""
    success1 = test_llama_model()

    # If main test fails, try alternative
    success2 = False
    if not success1:
        success2 = test_alternative_llama()

    overall_success = success1 or success2

    print(f"\n" + "=" * 60)
    print(f" TEST SUMMARY")
    print(f"=" * 60)

    if success1:
        print(f"✓ Default LLaMA model test PASSED")
        print(f"  - CodeLlama-7B-Instruct loaded successfully")
        print(f"  - Generated policy text from DSL input")
        print(f"  - Model can be used for DSL→Policy generation")
    elif success2:
        print(f"✓ Alternative LLaMA model test PASSED")
        print(f"  - Alternative LLaMA model works")
        print(f"  - Consider updating configuration")
    else:
        print(f"✗ All LLaMA model tests FAILED")
        print(f"  - Models may require authentication")
        print(f"  - Check HuggingFace access tokens")
        print(f"  - Consider using different models")

    return overall_success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)