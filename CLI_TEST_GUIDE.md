# NL2IAM CLI Testing Guide

This guide will help you test the new NL2IAM CLI on your GPU box.

## 🧪 Testing Steps

### 1. Basic Structure Test (Run First)
```bash
# Test CLI structure without loading models
python test_cli_basic.py
```
This validates that the CLI can be imported and basic functionality works.

### 2. Full CLI Test (GPU Box)
```bash
# Normal mode
python nl2iam_cli.py

# Debug mode (recommended for testing)
python nl2iam_cli.py --debug

# Custom inventory path
python nl2iam_cli.py --debug --inventory-path ./test_policies.json
```

### 3. Test Scenarios

#### Test Case 1: Simple S3 Policy
**Input:** `Allow Alice to read files from the public bucket`
**Expected:** Should generate a policy with s3:GetObject action

#### Test Case 2: Deny Policy
**Input:** `Deny deleting objects in the sensitive-data bucket`
**Expected:** Should generate a policy with Effect: "Deny"

#### Test Case 3: EC2 Policy with Conditions
**Input:** `Allow launching only small EC2 instances like t2.micro and t2.small`
**Expected:** Should generate policy with EC2 actions and instance type conditions

#### Test Case 4: Complex Policy
**Input:** `Requests by any user to attach and detach volumes from instances in the Development department should be allowed`
**Expected:** Should generate policy with EC2 volume actions and department conditions

### 4. CLI Commands to Test
- `help` - Show help information
- `stats` - Show inventory statistics
- `quit` - Exit the program

### 5. Debug Mode Features to Verify
- Shows intermediate DSL translation
- Asks for confirmation before proceeding
- Allows editing of generated DSL
- Shows detailed error information

## 📋 Expected Workflow

1. **Initialization**
   - Loads NL→DSL model
   - Loads DSL→Policy model
   - Initializes RAG engine (if AWS docs available)
   - Sets up redundancy and conflict checkers

2. **Policy Generation Loop**
   - Takes natural language input
   - Converts to DSL (shows in debug mode)
   - Generates IAM policy with RAG enhancement
   - Checks for redundancy against existing policies
   - Checks for conflicts with existing policies
   - Adds to policy inventory if user confirms

3. **User Interactions**
   - In debug mode: asks to continue after DSL generation
   - If redundancy found: shows details and asks to continue/restart
   - If conflicts found: shows details and asks to continue/restart
   - After successful creation: shows final policy

## 🐛 Debugging Tips

### If Models Fail to Load
- Check if transformers and torch are installed
- Ensure sufficient GPU memory
- Try with smaller models first

### If RAG Fails to Initialize
- Check if `./docs/iam-ug.pdf` exists
- Verify vector store directory permissions
- RAG failure is non-fatal - CLI will continue without it

### If Inventory Issues
- Check file permissions for inventory path
- Default inventory path: `./data/policy_inventory.json`
- Directory will be created automatically

## 🔍 What to Look For

### ✅ Success Indicators
- All models load successfully
- RAG engine initializes (if docs available)
- Natural language converts to reasonable DSL
- DSL generates valid IAM JSON policy
- Redundancy/conflict checking works
- Policies are saved to inventory

### ⚠️ Acceptable Issues
- RAG initialization failure (will work without it)
- Some NL→DSL translations might need manual editing in debug mode
- Redundancy/conflicts detected (expected behavior)

### ❌ Failure Indicators
- Cannot import required modules
- Models fail to load completely
- Generated policies are malformed JSON
- CLI crashes on normal inputs

## 📤 Results to Share

Please run the tests and share:

1. **Basic test output:** `python test_cli_basic.py`
2. **Full CLI session:** Try 2-3 policy generations in debug mode
3. **Any error messages** you encounter
4. **Generated policies** (if successful)

Example test session:
```bash
python nl2iam_cli.py --debug
# Try: "Allow Alice to read files from the public bucket"
# Try: "Deny deleting objects in the audit bucket"
# Try: "help"
# Try: "stats"
# Try: "quit"
```

## 🛠️ Troubleshooting

### Memory Issues
```bash
# Try with smaller batch sizes or model quantization
# The CLI is configured to use 8-bit quantization by default
```

### Missing Dependencies
```bash
pip install transformers torch sentence-transformers chromadb
```

### File Permissions
```bash
# Ensure directories exist and are writable
mkdir -p data
chmod 755 data
```

Let me know what happens when you run these tests!