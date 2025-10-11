# OpenAI Model Setup for NL2IAM

This guide explains how to configure and use OpenAI models with the NL2IAM system for natural language to DSL translation.

## Prerequisites

1. **OpenAI API Account**: You need an active OpenAI API account with billing enabled
2. **API Key**: Obtain your API key from [OpenAI Platform](https://platform.openai.com/api-keys)

## Installation

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Set up API Key** (choose one method):

   **Option A: Environment Variable (Recommended)**
   ```bash
   export OPENAI_API_KEY="your-api-key-here"
   ```

   **Option B: Add to .env file**
   ```bash
   echo "OPENAI_API_KEY=your-api-key-here" >> .env
   ```

## Available OpenAI Models

The system supports the following OpenAI models for natural language to DSL translation:

| Model ID | OpenAI Model | Use Case | Cost |
|----------|--------------|----------|------|
| `nl2dsl_openai_gpt4` | gpt-4 | High accuracy, complex requests | High |
| `nl2dsl_openai_gpt4o` | gpt-4o | Optimized version of GPT-4 | Medium-High |
| `nl2dsl_openai_gpt35` | gpt-3.5-turbo | Fast, cost-effective | Low |

## Usage Example

### Basic Usage

```python
from src.models.model_manager import create_default_manager
from src.agents.translator import NLToTranslator

# Create model manager with OpenAI support
manager = create_default_manager()

# Load an OpenAI model (e.g., GPT-4)
success = manager.load_model("nl2dsl_openai_gpt4")
if not success:
    print("Failed to load OpenAI model. Check your API key.")
    exit(1)

# Create translator
translator = NLToTranslator(model_manager=manager)

# Translate natural language to DSL
result = translator.translate("Allow Alice to read files from the public bucket")
print(f"DSL: {result.dsl_output}")
```

### Using with translator.py

Modify your translator.py script to use OpenAI models:

```python
# Update the model ID in your translator to use OpenAI
if self.model_manager and self.model_manager.is_model_loaded("nl2dsl_openai_gpt4"):
    return self._model_based_translation(cleaned_input, **kwargs)
```

## Configuration

You can customize OpenAI model parameters by modifying the ModelConfig:

```python
from src.models.model_manager import ModelConfig, ModelManager

# Custom OpenAI configuration
custom_config = ModelConfig(
    model_name="Custom GPT-4",
    model_type="openai",
    task="nl2dsl",
    model_path="gpt-4",
    max_tokens=1024,        # Increase for longer outputs
    temperature=0.0         # Lower for more deterministic results
)

manager = ModelManager()
manager.register_model("custom_gpt4", custom_config)
manager.load_model("custom_gpt4")
```

## Testing the Setup

Create a test script to verify everything works:

```python
# test_openai_setup.py
import os
from src.models.model_manager import create_default_manager

def test_openai_setup():
    # Check if API key is set
    if not os.getenv('OPENAI_API_KEY'):
        print("❌ OPENAI_API_KEY not found in environment")
        return False

    # Test model loading
    manager = create_default_manager()
    success = manager.load_model("nl2dsl_openai_gpt35")  # Use cheaper model for testing

    if success:
        print("✅ OpenAI model loaded successfully")

        # Test a simple generation
        try:
            result = manager.generate(
                "nl2dsl_openai_gpt35",
                "Convert this: Allow read access to S3 bucket"
            )
            print(f"✅ Generation test passed: {result[:100]}...")
            return True
        except Exception as e:
            print(f"❌ Generation failed: {e}")
            return False
    else:
        print("❌ Failed to load OpenAI model")
        return False

if __name__ == "__main__":
    test_openai_setup()
```

Run the test:
```bash
python test_openai_setup.py
```

## Cost Considerations

OpenAI models are charged per token:

- **GPT-4**: ~$0.03 per 1K input tokens, ~$0.06 per 1K output tokens
- **GPT-4o**: ~$0.005 per 1K input tokens, ~$0.015 per 1K output tokens
- **GPT-3.5-turbo**: ~$0.001 per 1K input tokens, ~$0.002 per 1K output tokens

For development and testing, start with GPT-3.5-turbo to minimize costs.

## Troubleshooting

### Common Issues

1. **API Key Error**
   ```
   Error: OpenAI API key not found
   ```
   **Solution**: Ensure OPENAI_API_KEY environment variable is set

2. **Rate Limit Exceeded**
   ```
   Error: Rate limit exceeded
   ```
   **Solution**: Implement retry logic or upgrade your OpenAI plan

3. **Model Not Found**
   ```
   Error: Model gpt-4 not found
   ```
   **Solution**: Check your OpenAI account has access to the requested model

4. **Network Issues**
   ```
   Error: Connection timeout
   ```
   **Solution**: Check internet connection and OpenAI service status

### Debug Mode

Enable debug logging to see detailed API calls:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Your code here
```

## Security Notes

- **Never commit API keys** to version control
- Use environment variables or secure secret management
- Consider using API key rotation for production deployments
- Monitor your OpenAI usage dashboard for unexpected charges

## Integration with Existing Pipeline

The OpenAI models integrate seamlessly with your existing NL2IAM pipeline:

1. **Natural Language Input** → OpenAI Model → **DSL Output**
2. **DSL** → Local LLaMA Model → **AWS IAM Policy**

This hybrid approach allows you to leverage OpenAI's strong natural language understanding while keeping policy generation local for security.