"""
Model Manager for NL2IAM System

This module manages the loading and inference of local models for:
1. Natural Language to DSL translation (BERT-based models)
2. DSL to AWS IAM Policy generation (LLaMA-based models)

All models run locally for security considerations as specified in the paper.
"""

import os
import json
import time
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from abc import ABC, abstractmethod
import logging

try:
    import torch
    from transformers import (
        AutoTokenizer, AutoModelForSeq2SeqLM, AutoModelForCausalLM,
        T5ForConditionalGeneration, T5Tokenizer,
        pipeline
    )
    # Note: CodeT5 uses the same classes as T5, LlamaTokenizer is now AutoTokenizer
    TRANSFORMERS_AVAILABLE = True
except ImportError as e:
    TRANSFORMERS_AVAILABLE = False
    print(f"Warning: transformers not available: {e}")


@dataclass
class ModelConfig:
    """Configuration for a model"""
    model_name: str
    model_type: str  # "bert", "t5", "codet5", "llama", "mistral"
    task: str  # "nl2dsl", "dsl2policy"
    model_path: str
    tokenizer_path: Optional[str] = None
    max_length: int = 512
    device: str = "auto"
    load_in_8bit: bool = False
    load_in_4bit: bool = False
    trust_remote_code: bool = False


class BaseModel(ABC):
    """Base class for all models"""

    def __init__(self, config: ModelConfig):
        self.config = config
        self.model = None
        self.tokenizer = None
        self.device = self._get_device()
        self.is_loaded = False

    @abstractmethod
    def load_model(self) -> bool:
        """Load the model and tokenizer"""
        pass

    @abstractmethod
    def generate(self, input_text: str, **kwargs) -> str:
        """Generate output from input text"""
        pass

    def _get_device(self) -> str:
        """Determine the best device to use"""
        if self.config.device == "auto":
            if torch.cuda.is_available():
                return "cuda"
            elif hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
                return "mps"
            else:
                return "cpu"
        return self.config.device

    def unload_model(self):
        """Unload model to free memory"""
        if self.model is not None:
            del self.model
            self.model = None
        if self.tokenizer is not None:
            del self.tokenizer
            self.tokenizer = None
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        self.is_loaded = False


class T5BasedModel(BaseModel):
    """T5/CodeT5 based model for sequence-to-sequence tasks"""

    def load_model(self) -> bool:
        """Load T5 or CodeT5 model"""
        try:
            # Use AutoTokenizer and T5 classes for both T5 and CodeT5
            self.tokenizer = AutoTokenizer.from_pretrained(self.config.model_path)
            self.model = T5ForConditionalGeneration.from_pretrained(self.config.model_path)

            self.model.to(self.device)
            self.model.eval()
            self.is_loaded = True
            return True

        except Exception as e:
            print(f"Error loading T5 model: {e}")
            return False

    def generate(self, input_text: str, **kwargs) -> str:
        """Generate output using T5 model"""
        if not self.is_loaded:
            raise ValueError("Model not loaded")

        # Default generation parameters
        max_length = kwargs.get('max_length', self.config.max_length)
        num_beams = kwargs.get('num_beams', 4)
        temperature = kwargs.get('temperature', 0.7)
        do_sample = kwargs.get('do_sample', True)

        # Tokenize input
        inputs = self.tokenizer.encode(
            input_text,
            return_tensors="pt",
            max_length=self.config.max_length,
            truncation=True,
            padding=True
        ).to(self.device)

        # Generate
        with torch.no_grad():
            outputs = self.model.generate(
                inputs,
                max_length=max_length,
                num_beams=num_beams,
                temperature=temperature,
                do_sample=do_sample,
                pad_token_id=self.tokenizer.eos_token_id
            )

        # Decode output
        output_text = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        return output_text.strip()


class LlamaBasedModel(BaseModel):
    """LLaMA-based model for causal language modeling"""

    def load_model(self) -> bool:
        """Load LLaMA model"""
        try:
            # Use AutoTokenizer for modern LLaMA models
            self.tokenizer = AutoTokenizer.from_pretrained(self.config.model_path)

            # Ensure we have a pad token
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token

            # Load model with quantization options if specified
            load_kwargs = {}
            if self.config.load_in_8bit:
                load_kwargs['load_in_8bit'] = True
            elif self.config.load_in_4bit:
                load_kwargs['load_in_4bit'] = True

            self.model = AutoModelForCausalLM.from_pretrained(
                self.config.model_path,
                torch_dtype=torch.float16 if self.device == "cuda" else torch.float32,
                **load_kwargs
            )

            if not (self.config.load_in_8bit or self.config.load_in_4bit):
                self.model.to(self.device)

            self.model.eval()
            self.is_loaded = True
            return True

        except Exception as e:
            print(f"Error loading LLaMA model: {e}")
            return False

    def generate(self, input_text: str, **kwargs) -> str:
        """Generate output using LLaMA model"""
        if not self.is_loaded:
            raise ValueError("Model not loaded")

        # Default generation parameters
        max_new_tokens = kwargs.get('max_new_tokens', 256)
        temperature = kwargs.get('temperature', 0.7)
        top_p = kwargs.get('top_p', 0.9)
        do_sample = kwargs.get('do_sample', True)

        # Tokenize input
        inputs = self.tokenizer.encode(
            input_text,
            return_tensors="pt",
            max_length=self.config.max_length,
            truncation=True
        ).to(self.device)

        # Generate
        with torch.no_grad():
            outputs = self.model.generate(
                inputs,
                max_new_tokens=max_new_tokens,
                temperature=temperature,
                top_p=top_p,
                do_sample=do_sample,
                pad_token_id=self.tokenizer.eos_token_id,
                eos_token_id=self.tokenizer.eos_token_id
            )

        # Decode only the new tokens
        new_tokens = outputs[0][inputs.shape[1]:]
        output_text = self.tokenizer.decode(new_tokens, skip_special_tokens=True)
        return output_text.strip()


class ModelManager:
    """
    Manages multiple models for the NL2IAM system.

    Handles model loading, inference, and resource management to stay within
    budget constraints on RunPod.
    """

    def __init__(self):
        self.models: Dict[str, BaseModel] = {}
        self.model_configs: Dict[str, ModelConfig] = {}
        self.logger = logging.getLogger(__name__)

    def register_model(self, model_id: str, config: ModelConfig):
        """Register a model configuration"""
        self.model_configs[model_id] = config

    def load_model(self, model_id: str) -> bool:
        """Load a specific model"""
        if model_id not in self.model_configs:
            raise ValueError(f"Model {model_id} not registered")

        config = self.model_configs[model_id]

        # Create appropriate model instance
        if config.model_type in ["t5", "codet5"]:
            model = T5BasedModel(config)
        elif config.model_type in ["llama", "mistral"]:
            model = LlamaBasedModel(config)
        else:
            raise ValueError(f"Unsupported model type: {config.model_type}")

        success = model.load_model()
        if success:
            self.models[model_id] = model
            self.logger.info(f"Successfully loaded model: {model_id}")
        else:
            self.logger.error(f"Failed to load model: {model_id}")

        return success

    def unload_model(self, model_id: str):
        """Unload a specific model to free memory"""
        if model_id in self.models:
            self.models[model_id].unload_model()
            del self.models[model_id]
            self.logger.info(f"Unloaded model: {model_id}")

    def unload_all_models(self):
        """Unload all models"""
        for model_id in list(self.models.keys()):
            self.unload_model(model_id)

    def generate(self, model_id: str, input_text: str, **kwargs) -> str:
        """Generate output using a specific model"""
        if model_id not in self.models:
            # Try to load the model if it's registered but not loaded
            if model_id in self.model_configs:
                self.load_model(model_id)
            else:
                raise ValueError(f"Model {model_id} not available")

        if model_id not in self.models:
            raise ValueError(f"Failed to load model {model_id}")

        start_time = time.time()
        result = self.models[model_id].generate(input_text, **kwargs)
        end_time = time.time()

        self.logger.info(f"Generated output with {model_id} in {end_time - start_time:.2f}s")
        return result

    def is_model_loaded(self, model_id: str) -> bool:
        """Check if a model is currently loaded"""
        return model_id in self.models and self.models[model_id].is_loaded

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about registered and loaded models"""
        info = {
            "registered_models": {},
            "loaded_models": {},
            "memory_usage": self._get_memory_usage()
        }

        for model_id, config in self.model_configs.items():
            info["registered_models"][model_id] = {
                "model_type": config.model_type,
                "task": config.task,
                "device": config.device
            }

        for model_id, model in self.models.items():
            info["loaded_models"][model_id] = {
                "is_loaded": model.is_loaded,
                "device": model.device
            }

        return info

    def _get_memory_usage(self) -> Dict[str, Any]:
        """Get current memory usage"""
        memory_info = {}

        if torch.cuda.is_available():
            memory_info["cuda"] = {
                "allocated": torch.cuda.memory_allocated(),
                "cached": torch.cuda.memory_reserved(),
                "max_allocated": torch.cuda.max_memory_allocated()
            }

        return memory_info


# Recommended model configurations for RunPod deployment
RECOMMENDED_MODELS = {
    "nl2dsl_model": ModelConfig(
        model_name="CodeT5-small",
        model_type="codet5",
        task="nl2dsl",
        model_path="Salesforce/codet5-small",
        max_length=512,
        device="auto"
    ),
    "dsl2policy_model": ModelConfig(
        model_name="CodeLlama-7B",
        model_type="llama",
        task="dsl2policy",
        model_path="codellama/CodeLlama-7b-Instruct-hf",
        max_length=2048,
        device="auto",
        load_in_8bit=True  # For memory efficiency
    )
}


def create_default_manager() -> ModelManager:
    """Create a model manager with recommended configurations"""
    manager = ModelManager()

    for model_id, config in RECOMMENDED_MODELS.items():
        manager.register_model(model_id, config)

    return manager


# Test script
if __name__ == "__main__":
    if not TRANSFORMERS_AVAILABLE:
        print("Transformers not available. Install with: pip install transformers torch")
        exit(1)

    # Test model manager
    manager = create_default_manager()
    print("Model Manager Info:")
    print(json.dumps(manager.get_model_info(), indent=2))

    # Note: Actual model loading would require the models to be available
    # This is just testing the infrastructure
    print("\nModel manager created successfully!")