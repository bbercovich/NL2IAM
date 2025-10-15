# Quacky Policy Comparison Scripts

This directory contains scripts to compare NL2IAM generated policies with ground truth using the Quacky tool.

## Prerequisites

1. Install Quacky following instructions at: https://github.com/vlab-cs-ucsb/quacky
2. Ensure Quacky is accessible at the expected path (default: `/home/user/Research/quacky/src`)

## Scripts Overview

### 1. `compare_with_quacky.py`
Main comparison script that compares policies between two directories using Quacky.

**Usage:**
```bash
# Basic comparison
python compare_with_quacky.py testdata/GroundTruth results/no-rag

# Custom range and Quacky path
python compare_with_quacky.py testdata/GroundTruth results/with-rag \
  --start 0 --end 10 \
  --quacky-path /path/to/quacky/src \
  --output detailed_results.json
```

**Arguments:**
- `ground_truth_dir`: Directory with `ground_truth_X.json` files
- `generated_dir`: Directory with `generated_X.json` files
- `--start`: Starting index (default: 0)
- `--end`: Ending index (default: 46)
- `--quacky-path`: Path to Quacky source (default: `/home/user/Research/quacky/src`)
- `--timeout`: Timeout per comparison in seconds (default: 300)
- `--output`: Save detailed JSON results to file

### 2. `batch_compare_all_modes.py`
Batch script to compare multiple NL2IAM modes against ground truth.

**Usage:**
```bash
# Compare all modes
python batch_compare_all_modes.py testdata/GroundTruth results/

# Custom settings
python batch_compare_all_modes.py testdata/GroundTruth results/ \
  --start 0 --end 10 \
  --quacky-path /custom/path/to/quacky/src \
  --output-dir ./analysis_results
```

**Expected Directory Structure:**
```
results/
├── with-rag-with-validation/     # Generated with RAG + validation
├── with-rag-no-validation/       # Generated with RAG, no validation
├── no-rag-with-validation/       # Generated without RAG + validation
└── no-rag-no-validation/         # Generated without RAG or validation
```

Each directory should contain files named `generated_0.json`, `generated_1.json`, etc.

## Comparison Results Interpretation

Quacky determines the relationship between policies:

- **Equivalent**: Policies grant identical permissions
- **Ground Truth More Permissive**: GT allows more access than generated policy
- **Ground Truth Less Permissive**: GT allows less access than generated policy
- **Incomparable**: Policies have different, non-overlapping permission sets

## Workflow Example

1. **Generate policies in batch mode:**
   ```bash
   # With RAG + validation
   python nl2iam_cli.py --batch testdata/Corase --output results/with-rag-with-validation

   # Without RAG + validation
   python nl2iam_cli.py --batch testdata/Corase --output results/no-rag-with-validation --no-rag

   # With RAG, no validation
   python nl2iam_cli.py --batch testdata/Corase --output results/with-rag-no-validation --skip-validation

   # Without RAG or validation
   python nl2iam_cli.py --batch testdata/Corase --output results/no-rag-no-validation --no-rag --skip-validation
   ```

2. **Run batch comparison:**
   ```bash
   python batch_compare_all_modes.py testdata/GroundTruth results/ --output-dir analysis_results
   ```

3. **Generate comparative summary:**
   ```bash
   python analysis_results/generate_comparative_summary.py
   ```

## Output Files

### Individual Comparison Results
- **JSON files**: Detailed results for each mode comparison
- **Summary statistics**: Success rates, timing, relationship breakdowns

### Comparative Analysis
- **Cross-mode comparison**: How different modes perform relative to each other
- **Equivalent policy rates**: Which modes produce policies most similar to ground truth
- **Permissiveness analysis**: Whether generated policies tend to be more/less permissive

## Troubleshooting

### Common Issues:

1. **Quacky not found**: Verify the `--quacky-path` points to the correct directory
2. **Timeouts**: Increase `--timeout` for complex policies (some may take 10+ minutes)
3. **Missing files**: Ensure file naming follows the expected pattern (`ground_truth_X.json`, `generated_X.json`)
4. **Permission errors**: Make sure scripts are executable (`chmod +x *.py`)

### Performance Notes:
- Each comparison can take 1-5 minutes depending on policy complexity
- Use smaller index ranges (`--start 0 --end 5`) for initial testing
- Consider running overnight for full datasets (47 policies × 4 modes = ~3-4 hours)

## Example Output

```
QUACKY POLICY COMPARISON SUMMARY
================================================================================
Generated: 2024-01-15T14:30:22.123456
Ground Truth Directory: testdata/GroundTruth
Generated Policies Directory: results/no-rag
Index Range: 0 to 46

COMPARISON STATISTICS:
----------------------------------------
Total Policy Pairs: 47
Successful Comparisons: 45
Timeouts: 1
Errors: 1
Success Rate: 95.7%

POLICY RELATIONSHIP BREAKDOWN:
----------------------------------------
Equivalent Policies: 12 (26.7%)
Ground Truth More Permissive: 18 (40.0%)
Ground Truth Less Permissive: 10 (22.2%)
Incomparable Policies: 5 (11.1%)

INTERPRETATION:
----------------------------------------
📈 Generated policies tend to be MORE permissive than ground truth
```