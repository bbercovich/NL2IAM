#!/usr/bin/env python3
"""
Test CodeT5 Model Loading and Inference

This script tests the original CodeT5 model configuration for NL→DSL translation.
"""

import sys
import time
import torch
from datetime import datetime

# Add src to path
sys.path.append('src')

from models.model_manager import create_default_manager

def test_codet5_model():
    """Test loading and using the CodeT5 model"""
    print("=" * 60)
    print(" CODET5 MODEL TEST")
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
        print(f"\n1. Creating model manager...")
        manager = create_default_manager()
        print(f"✓ Model manager created")

        print(f"\n2. Loading CodeT5 model (nl2dsl_model)...")
        print(f"   Model path: Salesforce/codet5-small")
        print(f"   This may take 5-10 minutes for first download...")

        start_time = time.time()
        success = manager.load_model('nl2dsl_model')
        load_time = time.time() - start_time

        if success:
            print(f"✓ CodeT5 model loaded successfully in {load_time:.1f}s")

            # Show memory usage
            if torch.cuda.is_available():
                memory_used = torch.cuda.memory_allocated(0) / 1e9
                print(f"✓ GPU memory used: {memory_used:.2f}GB")

            print(f"\n3. Testing model inference...")

            # Test cases for NL→DSL translation
            test_cases = [
                "Allow Alice to read files from the public bucket",
                "Deny deleting objects in the sensitive bucket",
                "Allow starting small EC2 instances",
                "Permit running t2.micro instances"
            ]

            successful_generations = 0

            for i, test_input in enumerate(test_cases, 1):
                print(f"\nTest {i}: {test_input}")
                try:
                    start_gen = time.time()
                    result = manager.generate(
                        'nl2dsl_model',
                        f"Translate to DSL: {test_input}",
                        max_length=128,
                        temperature=0.3,
                        num_beams=4
                    )
                    gen_time = time.time() - start_gen

                    print(f"✓ Generated in {gen_time:.2f}s: {result}")
                    successful_generations += 1

                except Exception as e:
                    print(f"✗ Generation failed: {e}")

            print(f"\n4. Inference Results:")
            print(f"   Successful generations: {successful_generations}/{len(test_cases)}")

            print(f"\n5. Unloading model...")
            manager.unload_model('nl2dsl_model')
            print(f"✓ Model unloaded")

            if torch.cuda.is_available():
                torch.cuda.empty_cache()
                final_memory = torch.cuda.memory_allocated(0) / 1e9
                print(f"✓ Final GPU memory: {final_memory:.2f}GB")

            return successful_generations > 0

        else:
            print(f"✗ Failed to load CodeT5 model")
            return False

    except Exception as e:
        print(f"✗ CodeT5 test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run the CodeT5 model test"""
    success = test_codet5_model()

    print(f"\n" + "=" * 60)
    print(f" TEST SUMMARY")
    print(f"=" * 60)

    if success:
        print(f"✓ CodeT5 model test PASSED")
        print(f"  - Model loaded successfully")
        print(f"  - Generated text from natural language input")
        print(f"  - Model can be used for NL→DSL translation")
    else:
        print(f"✗ CodeT5 model test FAILED")
        print(f"  - Check model availability or try alternative models")

    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)