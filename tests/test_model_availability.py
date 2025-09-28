#!/usr/bin/env python3
"""
Test Model Availability and Access

This script checks which models are accessible from HuggingFace
and provides recommendations for the best models to use.
"""

import sys
import time
import torch
from datetime import datetime

# Add src to path
sys.path.append('src')

def test_basic_access():
    """Test basic HuggingFace access and functionality"""
    print("=" * 60)
    print(" MODEL AVAILABILITY TEST")
    print("=" * 60)
    print(f"Test run: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    print(f"\n1. Testing basic imports...")
    try:
        from transformers import AutoTokenizer, AutoModel, AutoModelForSeq2SeqLM, AutoModelForCausalLM
        print(f"✓ Transformers library working")
    except ImportError as e:
        print(f"✗ Transformers import failed: {e}")
        return False

    print(f"\n2. Testing GPU access...")
    print(f"✓ CUDA available: {torch.cuda.is_available()}")
    if torch.cuda.is_available():
        print(f"✓ GPU: {torch.cuda.get_device_name(0)}")
        print(f"✓ GPU Memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f}GB")

    return True

def test_model_access(model_path, model_type="auto"):
    """Test access to a specific model"""
    print(f"\nTesting model: {model_path}")
    try:
        from transformers import AutoTokenizer, AutoModelForSeq2SeqLM, AutoModelForCausalLM

        start_time = time.time()

        # Try to load tokenizer first (faster)
        tokenizer = AutoTokenizer.from_pretrained(model_path)
        tokenizer_time = time.time() - start_time

        print(f"  ✓ Tokenizer loaded in {tokenizer_time:.1f}s")

        # Try to load model config (without weights)
        if model_type == "seq2seq":
            model = AutoModelForSeq2SeqLM.from_pretrained(model_path, torch_dtype=torch.float32)
        elif model_type == "causal":
            model = AutoModelForCausalLM.from_pretrained(model_path, torch_dtype=torch.float32)
        else:
            # Let AutoModel figure it out
            from transformers import AutoModel
            model = AutoModel.from_pretrained(model_path, torch_dtype=torch.float32)

        load_time = time.time() - start_time
        print(f"  ✓ Model loaded in {load_time:.1f}s")

        # Get model size info
        param_count = sum(p.numel() for p in model.parameters())
        print(f"  ✓ Parameters: {param_count / 1e6:.1f}M")

        # Clean up
        del model
        del tokenizer
        if torch.cuda.is_available():
            torch.cuda.empty_cache()

        return True

    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return False

def test_small_models():
    """Test small, reliable models that should work"""
    print(f"\n" + "=" * 60)
    print(f" TESTING SMALL/RELIABLE MODELS")
    print(f"=" * 60)

    small_models = [
        {
            "name": "T5-Small",
            "path": "t5-small",
            "type": "seq2seq",
            "use_case": "General seq2seq tasks"
        },
        {
            "name": "Flan-T5-Small",
            "path": "google/flan-t5-small",
            "type": "seq2seq",
            "use_case": "Instruction following"
        },
        {
            "name": "DistilBERT",
            "path": "distilbert-base-uncased",
            "type": "auto",
            "use_case": "Text understanding"
        }
    ]

    successful_models = []

    for model_info in small_models:
        print(f"\n{'-' * 40}")
        print(f"Testing {model_info['name']}")
        print(f"Use case: {model_info['use_case']}")

        success = test_model_access(model_info['path'], model_info['type'])
        if success:
            successful_models.append(model_info)

    return successful_models

def test_medium_models():
    """Test medium-sized models for production use"""
    print(f"\n" + "=" * 60)
    print(f" TESTING MEDIUM-SIZED MODELS")
    print(f"=" * 60)

    medium_models = [
        {
            "name": "Flan-T5-Base",
            "path": "google/flan-t5-base",
            "type": "seq2seq",
            "use_case": "Better instruction following"
        },
        {
            "name": "CodeT5-Base",
            "path": "Salesforce/codet5-base",
            "type": "seq2seq",
            "use_case": "Code generation"
        },
        {
            "name": "T5-Base",
            "path": "t5-base",
            "type": "seq2seq",
            "use_case": "General seq2seq"
        }
    ]

    successful_models = []

    for model_info in medium_models:
        print(f"\n{'-' * 40}")
        print(f"Testing {model_info['name']}")
        print(f"Use case: {model_info['use_case']}")

        success = test_model_access(model_info['path'], model_info['type'])
        if success:
            successful_models.append(model_info)

    return successful_models

def test_generation_capability(model_path):
    """Test actual text generation with a model"""
    print(f"\nTesting generation with {model_path}")
    try:
        from transformers import AutoTokenizer, AutoModelForSeq2SeqLM

        tokenizer = AutoTokenizer.from_pretrained(model_path)
        model = AutoModelForSeq2SeqLM.from_pretrained(model_path)

        # Test input
        input_text = "translate English to DSL: Allow Alice to read S3 files"
        inputs = tokenizer.encode(input_text, return_tensors="pt")

        # Generate
        with torch.no_grad():
            outputs = model.generate(
                inputs,
                max_length=50,
                num_beams=3,
                temperature=0.7,
                do_sample=True
            )

        # Decode
        result = tokenizer.decode(outputs[0], skip_special_tokens=True)
        print(f"  ✓ Generated: {result}")

        # Clean up
        del model
        del tokenizer
        if torch.cuda.is_available():
            torch.cuda.empty_cache()

        return True

    except Exception as e:
        print(f"  ✗ Generation failed: {e}")
        return False

def main():
    """Run all model availability tests"""
    if not test_basic_access():
        print("Basic access failed - check installation")
        return False

    print(f"\n" + "=" * 60)
    print(f" COMPREHENSIVE MODEL TESTING")
    print(f"=" * 60)

    # Test small models first
    small_successful = test_small_models()

    # Test medium models
    medium_successful = test_medium_models()

    # Test generation with best available model
    if small_successful:
        print(f"\n" + "=" * 60)
        print(f" TESTING GENERATION CAPABILITY")
        print(f"=" * 60)
        best_model = small_successful[0]['path']
        test_generation_capability(best_model)

    # Final recommendations
    print(f"\n" + "=" * 60)
    print(f" RECOMMENDATIONS")
    print(f"=" * 60)

    if small_successful:
        print(f"✓ Available small models ({len(small_successful)}):")
        for model in small_successful:
            print(f"  - {model['name']}: {model['path']}")

    if medium_successful:
        print(f"✓ Available medium models ({len(medium_successful)}):")
        for model in medium_successful:
            print(f"  - {model['name']}: {model['path']}")

    if small_successful or medium_successful:
        print(f"\n📋 Recommended configuration:")
        if medium_successful:
            rec_model = medium_successful[0]
        else:
            rec_model = small_successful[0]

        print(f"   For NL→DSL: {rec_model['name']} ({rec_model['path']})")
        print(f"   Use case: {rec_model['use_case']}")
        print(f"\n   Update your model_manager.py:")
        print(f"   model_path = '{rec_model['path']}'")

        return True
    else:
        print(f"✗ No models accessible - check network/authentication")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)