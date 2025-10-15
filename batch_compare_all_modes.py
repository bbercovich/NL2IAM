#!/usr/bin/env python3
"""
Batch comparison script to run Quacky comparisons across all NL2IAM modes
Compares results from different combinations: with/without RAG, with/without validation
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path
from datetime import datetime

def run_comparison(ground_truth_dir: str, generated_dir: str, mode_name: str,
                  quacky_path: str, start_idx: int, end_idx: int, output_dir: str):
    """Run comparison for a specific mode and save results"""

    print(f"\n{'='*60}")
    print(f"COMPARING MODE: {mode_name.upper()}")
    print(f"{'='*60}")

    # Create output filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = Path(output_dir) / f"quacky_results_{mode_name}_{timestamp}.json"

    # Run the comparison
    cmd = [
        'python3', 'compare_with_quacky.py',
        ground_truth_dir,
        generated_dir,
        '--start', str(start_idx),
        '--end', str(end_idx),
        '--quacky-path', quacky_path,
        '--output', str(output_file)
    ]

    try:
        result = subprocess.run(cmd, check=True, text=True)
        print(f"✅ Successfully completed comparison for {mode_name}")
        return str(output_file)
    except subprocess.CalledProcessError as e:
        print(f"❌ Error running comparison for {mode_name}: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(
        description="Run Quacky comparisons across all NL2IAM modes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Compare all modes with default settings
  python batch_compare_all_modes.py testdata/GroundTruth results/

  # Compare specific range and custom Quacky path
  python batch_compare_all_modes.py testdata/GroundTruth results/ \\
    --start 0 --end 10 --quacky-path /custom/path/to/quacky/src

Expected directory structure:
  results/
    ├── with-rag-with-validation/    (generated_0.json, generated_1.json, ...)
    ├── with-rag-no-validation/      (generated_0.json, generated_1.json, ...)
    ├── no-rag-with-validation/      (generated_0.json, generated_1.json, ...)
    └── no-rag-no-validation/        (generated_0.json, generated_1.json, ...)
        """
    )

    parser.add_argument(
        'ground_truth_dir',
        help='Directory containing ground_truth_X.json files'
    )

    parser.add_argument(
        'results_base_dir',
        help='Base directory containing subdirectories for each mode'
    )

    parser.add_argument(
        '--start',
        type=int,
        default=0,
        help='Starting index for comparison (default: 0)'
    )

    parser.add_argument(
        '--end',
        type=int,
        default=46,
        help='Ending index for comparison (default: 46)'
    )

    parser.add_argument(
        '--quacky-path',
        type=str,
        default="/workspace/quacky/src",
        help='Path to Quacky source directory'
    )

    parser.add_argument(
        '--output-dir',
        type=str,
        default="./comparison_results",
        help='Directory to save comparison results (default: ./comparison_results)'
    )

    parser.add_argument(
        '--modes',
        nargs='+',
        default=['with-rag-with-validation', 'with-rag-no-validation',
                'no-rag-with-validation', 'no-rag-no-validation'],
        help='List of mode subdirectories to compare'
    )

    args = parser.parse_args()

    # Validate inputs
    if not Path(args.ground_truth_dir).exists():
        print(f"❌ Ground truth directory not found: {args.ground_truth_dir}")
        sys.exit(1)

    if not Path(args.results_base_dir).exists():
        print(f"❌ Results base directory not found: {args.results_base_dir}")
        sys.exit(1)

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"🚀 Starting batch comparison across {len(args.modes)} modes")
    print(f"📂 Ground truth: {args.ground_truth_dir}")
    print(f"📂 Results base: {args.results_base_dir}")
    print(f"📊 Index range: {args.start} to {args.end}")
    print(f"💾 Output directory: {output_dir}")

    successful_comparisons = []
    failed_comparisons = []

    # Run comparisons for each mode
    for mode in args.modes:
        generated_dir = Path(args.results_base_dir) / mode

        if not generated_dir.exists():
            print(f"⚠️  Skipping {mode}: directory not found at {generated_dir}")
            failed_comparisons.append(mode)
            continue

        result_file = run_comparison(
            args.ground_truth_dir,
            str(generated_dir),
            mode,
            args.quacky_path,
            args.start,
            args.end,
            str(output_dir)
        )

        if result_file:
            successful_comparisons.append((mode, result_file))
        else:
            failed_comparisons.append(mode)

    # Summary
    print(f"\n{'='*60}")
    print(f"BATCH COMPARISON SUMMARY")
    print(f"{'='*60}")
    print(f"✅ Successful comparisons: {len(successful_comparisons)}")
    print(f"❌ Failed comparisons: {len(failed_comparisons)}")

    if successful_comparisons:
        print(f"\n📊 Results saved:")
        for mode, file_path in successful_comparisons:
            print(f"   • {mode}: {file_path}")

    if failed_comparisons:
        print(f"\n⚠️  Failed modes:")
        for mode in failed_comparisons:
            print(f"   • {mode}")

    # Create summary script
    create_summary_script(output_dir, successful_comparisons)

def create_summary_script(output_dir: Path, successful_comparisons: list):
    """Create a script to generate comparative summaries"""
    script_content = f'''#!/usr/bin/env python3
"""
Auto-generated script to create comparative summary of all Quacky results
Generated on: {datetime.now().isoformat()}
"""

import json
from pathlib import Path
from collections import defaultdict

def load_and_summarize():
    """Load all comparison results and create comparative summary"""

    results = {{}}

    # Load all result files
'''

    for mode, file_path in successful_comparisons:
        script_content += f'''
    # Load {mode} results
    try:
        with open(r"{file_path}", 'r') as f:
            results["{mode}"] = json.load(f)
    except Exception as e:
        print(f"Error loading {mode}: {{e}}")
'''

    script_content += '''

    # Create comparative summary
    print("="*80)
    print("COMPARATIVE SUMMARY ACROSS ALL MODES")
    print("="*80)

    mode_stats = {}

    for mode, data in results.items():
        if 'summary' in data:
            summary = data['summary']
            mode_stats[mode] = {
                'total': summary['total_compared'],
                'successful': summary['successful_comparisons'],
                'relationships': dict(summary['relationships'])
            }

            print(f"\\n{mode.upper()}:")
            print(f"  Total comparisons: {summary['total_compared']}")
            print(f"  Successful: {summary['successful_comparisons']}")

            if summary['successful_comparisons'] > 0:
                for rel, count in summary['relationships'].items():
                    pct = (count / summary['successful_comparisons']) * 100
                    print(f"  {rel}: {count} ({pct:.1f}%)")

    # Cross-mode comparison
    if len(mode_stats) > 1:
        print("\\n" + "="*60)
        print("CROSS-MODE COMPARISON")
        print("="*60)

        # Compare equivalent policies across modes
        equiv_rates = {}
        for mode, stats in mode_stats.items():
            if stats['successful'] > 0:
                equiv_rate = stats['relationships'].get('equivalent', 0) / stats['successful'] * 100
                equiv_rates[mode] = equiv_rate

        if equiv_rates:
            print("\\nEquivalent Policy Rates:")
            for mode, rate in sorted(equiv_rates.items(), key=lambda x: x[1], reverse=True):
                print(f"  {mode}: {rate:.1f}%")

if __name__ == "__main__":
    load_and_summarize()
'''

    summary_script_path = output_dir / "generate_comparative_summary.py"
    with open(summary_script_path, 'w') as f:
        f.write(script_content)

    # Make it executable
    os.chmod(summary_script_path, 0o755)

    print(f"\n📝 Comparative summary script created: {summary_script_path}")
    print(f"   Run: python {summary_script_path}")

if __name__ == "__main__":
    main()