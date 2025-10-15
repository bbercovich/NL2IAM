#!/usr/bin/env python3
"""
Compare NL2IAM generated policies with ground truth using Quacky
Compares generated policies from different modes (with/without RAG, with/without validation)
against ground truth policies and provides statistics on policy relationships.
"""

import os
import json
import subprocess
import sys
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from collections import defaultdict

class QuackyComparator:
    """Compare policies using Quacky and generate comprehensive statistics"""

    def __init__(self, quacky_path: str = "/workspace/quacky/src", timeout: int = 300):
        """
        Initialize the comparator

        Args:
            quacky_path: Path to Quacky source directory
            timeout: Timeout in seconds for each Quacky comparison
        """
        self.quacky_path = quacky_path
        self.timeout = timeout
        self.results = []

    def run_quacky_comparison(self, gt_policy_path: str, generated_policy_path: str) -> Dict:
        """
        Run Quacky to compare two policies

        Args:
            gt_policy_path: Path to ground truth policy
            generated_policy_path: Path to generated policy

        Returns:
            Dictionary with comparison results
        """
        try:
            result = subprocess.run([
                'python', 'quacky.py',
                '-p1', gt_policy_path,
                '-p2', generated_policy_path,
                '-b', '50',  # Lower bound for faster analysis
                '-c'  # use constraints
            ], capture_output=True, text=True, cwd=self.quacky_path, timeout=self.timeout)

            return self._parse_quacky_output(result.stdout, result.stderr, gt_policy_path, generated_policy_path)

        except subprocess.TimeoutExpired:
            return {
                'status': 'timeout',
                'relationship': 'timeout',
                'error': f'Analysis timed out after {self.timeout} seconds',
                'gt_path': gt_policy_path,
                'generated_path': generated_policy_path
            }
        except Exception as e:
            return {
                'status': 'error',
                'relationship': 'error',
                'error': str(e),
                'gt_path': gt_policy_path,
                'generated_path': generated_policy_path
            }

    def _parse_quacky_output(self, stdout: str, stderr: str, gt_path: str, gen_path: str) -> Dict:
        """Parse Quacky output to extract relationship information"""

        # Extract timing information
        solve_times = []
        count_times = []

        for line in stdout.split('\n'):
            if 'Solve Time (ms)' in line:
                try:
                    time_val = float(line.split('Solve Time (ms)')[1].strip().split()[0])
                    solve_times.append(time_val)
                except:
                    pass
            elif 'Count Time (ms)' in line:
                try:
                    time_val = float(line.split('Count Time (ms)')[1].strip().split()[0])
                    count_times.append(time_val)
                except:
                    pass

        total_time = sum(solve_times) + sum(count_times)

        # Determine relationship based on Quacky output
        relationship = 'unknown'
        status = 'success'

        if "Policy 1 and Policy 2 are equivalent" in stdout:
            relationship = "equivalent"
        elif "Policy 1 is more permissive than Policy 2" in stdout:
            relationship = "gt_more_permissive"  # Ground truth is more permissive than generated
        elif "Policy 1 is less permissive than Policy 2" in stdout:
            relationship = "gt_less_permissive"  # Ground truth is less permissive than generated
        elif "Policy 1 and Policy 2 do not subsume each other" in stdout:
            relationship = "incomparable"
        elif stderr and "error" in stderr.lower():
            relationship = "error"
            status = "error"
        else:
            relationship = "unknown"
            status = "unknown"

        return {
            'status': status,
            'relationship': relationship,
            'solve_times': solve_times,
            'count_times': count_times,
            'total_time': total_time,
            'stdout': stdout,
            'stderr': stderr,
            'gt_path': gt_path,
            'generated_path': gen_path
        }

    def compare_directory_pairs(self, ground_truth_dir: str, generated_dir: str,
                               start_index: int = 0, end_index: int = 46) -> Dict:
        """
        Compare all policy pairs between ground truth and generated directories

        Args:
            ground_truth_dir: Directory containing ground_truth_X.json files
            generated_dir: Directory containing generated_X.json files
            start_index: Starting index for comparison
            end_index: Ending index for comparison (inclusive)

        Returns:
            Dictionary with comprehensive comparison results
        """
        gt_path = Path(ground_truth_dir)
        gen_path = Path(generated_dir)

        if not gt_path.exists():
            raise FileNotFoundError(f"Ground truth directory not found: {ground_truth_dir}")
        if not gen_path.exists():
            raise FileNotFoundError(f"Generated policies directory not found: {generated_dir}")

        comparison_results = {
            'metadata': {
                'ground_truth_dir': str(gt_path),
                'generated_dir': str(gen_path),
                'start_index': start_index,
                'end_index': end_index,
                'timestamp': datetime.now().isoformat(),
                'quacky_path': self.quacky_path,
                'timeout': self.timeout
            },
            'individual_results': [],
            'summary': {
                'total_compared': 0,
                'successful_comparisons': 0,
                'timeouts': 0,
                'errors': 0,
                'relationships': defaultdict(int)
            }
        }

        print(f"Comparing policies from index {start_index} to {end_index}")
        print(f"Ground truth: {gt_path}")
        print(f"Generated: {gen_path}")
        print("-" * 60)

        for i in range(start_index, end_index + 1):
            gt_file = gt_path / f"ground_truth_{i}.json"
            gen_file = gen_path / f"generated_{i}.json"

            # Check if both files exist
            if not gt_file.exists():
                print(f"⚠️  Skipping index {i}: ground truth file not found")
                continue
            if not gen_file.exists():
                print(f"⚠️  Skipping index {i}: generated file not found")
                continue

            print(f"🔄 Comparing pair {i}...", end=" ")

            # Run Quacky comparison
            result = self.run_quacky_comparison(str(gt_file), str(gen_file))
            result['index'] = i

            comparison_results['individual_results'].append(result)
            comparison_results['summary']['total_compared'] += 1

            # Update summary statistics
            if result['status'] == 'success':
                comparison_results['summary']['successful_comparisons'] += 1
                comparison_results['summary']['relationships'][result['relationship']] += 1
                print(f"✅ {result['relationship']}")
            elif result['status'] == 'timeout':
                comparison_results['summary']['timeouts'] += 1
                print(f"⏰ TIMEOUT")
            else:
                comparison_results['summary']['errors'] += 1
                print(f"❌ ERROR")

        return comparison_results

    def generate_summary_report(self, results: Dict) -> str:
        """Generate a human-readable summary report"""
        summary = results['summary']
        metadata = results['metadata']

        report = []
        report.append("=" * 80)
        report.append("QUACKY POLICY COMPARISON SUMMARY")
        report.append("=" * 80)
        report.append(f"Generated: {metadata['timestamp']}")
        report.append(f"Ground Truth Directory: {metadata['ground_truth_dir']}")
        report.append(f"Generated Policies Directory: {metadata['generated_dir']}")
        report.append(f"Index Range: {metadata['start_index']} to {metadata['end_index']}")
        report.append("")

        report.append("COMPARISON STATISTICS:")
        report.append("-" * 40)
        report.append(f"Total Policy Pairs: {summary['total_compared']}")
        report.append(f"Successful Comparisons: {summary['successful_comparisons']}")
        report.append(f"Timeouts: {summary['timeouts']}")
        report.append(f"Errors: {summary['errors']}")

        if summary['successful_comparisons'] > 0:
            success_rate = (summary['successful_comparisons'] / summary['total_compared']) * 100
            report.append(f"Success Rate: {success_rate:.1f}%")

        report.append("")
        report.append("POLICY RELATIONSHIP BREAKDOWN:")
        report.append("-" * 40)

        relationship_labels = {
            'equivalent': 'Equivalent Policies',
            'gt_more_permissive': 'Ground Truth More Permissive',
            'gt_less_permissive': 'Ground Truth Less Permissive',
            'incomparable': 'Incomparable Policies'
        }

        for rel_type, count in summary['relationships'].items():
            label = relationship_labels.get(rel_type, rel_type.title())
            percentage = (count / summary['successful_comparisons']) * 100 if summary['successful_comparisons'] > 0 else 0
            report.append(f"{label}: {count} ({percentage:.1f}%)")

        # Add interpretation
        report.append("")
        report.append("INTERPRETATION:")
        report.append("-" * 40)
        gt_more = summary['relationships']['gt_more_permissive']
        gt_less = summary['relationships']['gt_less_permissive']

        if gt_more > gt_less:
            report.append("📈 Generated policies tend to be MORE permissive than ground truth")
        elif gt_less > gt_more:
            report.append("📉 Generated policies tend to be LESS permissive than ground truth")
        else:
            report.append("⚖️  Generated policies show balanced permissiveness compared to ground truth")

        return "\n".join(report)

    def save_results(self, results: Dict, output_file: str):
        """Save detailed results to JSON file"""
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"📁 Detailed results saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Compare NL2IAM generated policies with ground truth using Quacky",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Compare no-rag results with ground truth
  python compare_with_quacky.py testdata/GroundTruth results/no-rag

  # Compare specific range of policies
  python compare_with_quacky.py testdata/GroundTruth results/no-rag --start 0 --end 10

  # Use custom Quacky path and save detailed results
  python compare_with_quacky.py testdata/GroundTruth results/with-rag \\
    --quacky-path /path/to/quacky/src \\
    --output results_analysis.json
        """
    )

    parser.add_argument(
        'ground_truth_dir',
        help='Directory containing ground_truth_X.json files'
    )

    parser.add_argument(
        'generated_dir',
        help='Directory containing generated_X.json files'
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
        '--timeout',
        type=int,
        default=300,
        help='Timeout in seconds for each comparison (default: 300)'
    )

    parser.add_argument(
        '--output',
        type=str,
        help='Output file for detailed JSON results (optional)'
    )

    args = parser.parse_args()

    # Initialize comparator
    comparator = QuackyComparator(
        quacky_path=args.quacky_path,
        timeout=args.timeout
    )

    try:
        # Run comparison
        results = comparator.compare_directory_pairs(
            args.ground_truth_dir,
            args.generated_dir,
            args.start,
            args.end
        )

        # Generate and display summary
        print("\n")
        summary_report = comparator.generate_summary_report(results)
        print(summary_report)

        # Save detailed results if requested
        if args.output:
            comparator.save_results(results, args.output)

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()