# Hugging Face Authentication Setup

This guide explains how to set up authentication for accessing gated Hugging Face models like Llama-3.1-8B-Instruct and Llama-3.3-70B-Instruct.

## Prerequisites

Make sure you have installed the requirements:
```bash
pip install -r requirements.txt
```

## Step 1: Create Hugging Face Account

1. Go to [huggingface.co](https://huggingface.co) and create an account if you don't have one
2. Verify your email address

## Step 2: Request Access to Gated Models

For the models we're using, you need to request access:

1. **Llama-3.1-8B-Instruct**: Visit [meta-llama/Meta-Llama-3.1-8B-Instruct](https://huggingface.co/meta-llama/Meta-Llama-3.1-8B-Instruct)
2. **Llama-3.3-70B-Instruct**: Visit [meta-llama/Llama-3.3-70B-Instruct](https://huggingface.co/meta-llama/Llama-3.3-70B-Instruct)

Click "Request access" on each model page and accept the license terms. Access is usually granted within a few minutes to hours.

## Step 3: Create Access Token

1. Go to [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens)
2. Click "New token"
3. Give it a name like "NL2IAM-access"
4. Select "Read" permission (sufficient for downloading models)
5. Click "Generate a token"
6. **Copy the token immediately** - you won't be able to see it again

## Step 4: Authenticate on Your GPU Host

On your container/GPU host, run:

```bash
huggingface-cli login
```

When prompted, paste your access token. The CLI will store your credentials securely.

Alternatively, you can set the token as an environment variable:
```bash
export HUGGINGFACE_HUB_TOKEN="your_token_here"
```

## Step 5: Verify Authentication

Test that authentication works:
```bash
huggingface-cli whoami
```

You should see your username displayed.

## Step 6: Test Model Access

Try downloading a small config file to verify access:
```bash
python -c "from transformers import AutoTokenizer; AutoTokenizer.from_pretrained('meta-llama/Meta-Llama-3.1-8B-Instruct')"
```

If this runs without errors, you're ready to use the models!

## Model Configurations Available

In `src/models/model_manager.py`, you now have these options:

- `nl2dsl_model`: Uses Llama-3.1-8B-Instruct (default)
- `nl2dsl_model_llama33_70b`: Uses Llama-3.3-70B-Instruct (requires more VRAM)
- `nl2dsl_model_codellama`: Uses CodeLlama-7B (fallback, no auth needed)

## Troubleshooting

**401 Client Error**: Your access token is invalid or you don't have access to the model
- Re-run `huggingface-cli login` with a valid token
- Make sure you've been granted access to the specific model

**Out of Memory**: The 70B model requires significant VRAM
- Use the 8B model instead, or enable 4-bit quantization
- Check your GPU memory with `nvidia-smi`

**Model not found**:
- Verify the model name is correct
- Check that you have access to the specific model variant