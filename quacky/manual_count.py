#!/usr/bin/env python3
"""
Manually count the results from the log file
"""
import re

def count_results(log_file):
    with open(log_file, 'r') as f:
        content = f.read()

    # Count different result types
    equivalent = len(re.findall(r"Policy 1 and Policy 2 are equivalent", content))
    more_permissive = len(re.findall(r"Policy 1 is more permissive than Policy 2", content))
    less_permissive = len(re.findall(r"Policy 1 is less permissive than Policy 2", content))
    incomparable = len(re.findall(r"Policy 1 and Policy 2 do not subsume each other", content))
    timeout = len(re.findall(r"Analysis timed out", content))
    error = len(re.findall(r"Error:", content))

    total = equivalent + more_permissive + less_permissive + incomparable + timeout + error

    print(f"=== MANUAL COUNT RESULTS ===")
    print(f"Total cases: {total}")
    print(f"Equivalent: {equivalent} ({equivalent/total*100:.1f}%)")
    print(f"More permissive: {more_permissive} ({more_permissive/total*100:.1f}%)")
    print(f"Less permissive: {less_permissive} ({less_permissive/total*100:.1f}%)")
    print(f"Incomparable: {incomparable} ({incomparable/total*100:.1f}%)")
    print(f"Timeout: {timeout} ({timeout/total*100:.1f}%)")
    print(f"Error: {error} ({error/total*100:.1f}%)")

if __name__ == "__main__":
    import sys
    import glob

    if len(sys.argv) != 2:
        print("Usage: python3 manual_count.py <mode>")
        print("Mode should be 'fine' or 'coarse'")
        sys.exit(1)

    mode = sys.argv[1]
    if mode not in ['fine', 'coarse']:
        print("Mode must be 'fine' or 'coarse'")
        sys.exit(1)

    # Find the most recent log file for the specified mode
    log_pattern = f"replicated_experiment_logs/{mode}/experiment_log_{mode}_*.txt"
    log_files = glob.glob(log_pattern)

    if not log_files:
        print(f"No log files found for mode '{mode}'")
        sys.exit(1)

    # Use the most recent log file
    latest_log = max(log_files, key=lambda x: x.split('_')[-1].split('.')[0])
    print(f"Using log file: {latest_log}")
    count_results(latest_log)
