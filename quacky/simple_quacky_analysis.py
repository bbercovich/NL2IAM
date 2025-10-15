#!/usr/bin/env python3
"""
Simple Quacky analysis script that just runs quacky.py and saves output for visualization.
Much simpler than the complex analyze_with_quacky.py
"""
import os
import subprocess
import sys
from pathlib import Path
from datetime import datetime

def run_quacky_simple(gt_policy_path, synth_policy_path, quacky_path="/home/user/Research/quacky/src"):
    """Run Quacky and return the raw output"""
    try:
        result = subprocess.run([
            'python', f'{quacky_path}/quacky.py',
            '-p1', gt_policy_path,
            '-p2', synth_policy_path,
            '-b', '50',  # Lower bound for faster analysis
            '-c'  # use constraints
        ], capture_output=True, text=True, cwd=quacky_path, timeout=300)  # 5 minute timeout

        return result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return "TIMEOUT", "Analysis timed out after 5 minutes"
    except Exception as e:
        return f"ERROR: {str(e)}", str(e)

def generate_simple_log(mode_name, max_cases=10):
    """Generate a simple log file for analysis"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Create output directory structure
    output_dir = Path("/home/user/Research/Synthesizing_Access_Control_Policy/replicated_experiment_logs") / mode_name
    output_dir.mkdir(parents=True, exist_ok=True)

    log_filename = output_dir / f"experiment_log_{mode_name}_{timestamp}.txt"

    base_dir = Path("/home/user/Research/Synthesizing_Access_Control_Policy/Project_Files")
    gt_dir = base_dir / "experiment_2_results"
    results_dir = base_dir / "results" / mode_name

    with open(log_filename, 'w') as f:
        f.write(f"Started logging at: {timestamp}\n")
        f.write(f"Log file: {os.path.abspath(log_filename)}\n\n")
        f.write(f"Experiment 2 - Policy Comparison Analysis - {mode_name.upper()} Mode\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("=" * 80 + "\n\n")

        for i in range(min(max_cases, 47)):  # Limit to first 10 cases for testing
            gt_path = gt_dir / f"ground_truth_{i}.json"
            synth_path = results_dir / f"{i}_policy.json"

            if not gt_path.exists() or not synth_path.exists():
                print(f"Skipping case {i}: missing files")
                continue

            print(f"Analyzing case {i}...")

            f.write("===============================================================================\n")
            f.write(f"Processing pair {i}\n")
            f.write("===============================================================================\n\n")

            f.write("Quacky Results:\n")

            # Run Quacky
            stdout, stderr = run_quacky_simple(str(gt_path), str(synth_path))

            if "TIMEOUT" in stdout:
                f.write("Analysis timed out after 5 minutes\n")
                print(f"Case {i}: TIMEOUT")
            elif "ERROR" in stdout:
                f.write(f"Error: {stdout}\n")
                print(f"Case {i}: ERROR")
            else:
                # Extract timing information and write in the expected format
                solve_times = []
                count_times = []

                for line in stdout.split('\n'):
                    if 'Solve Time (ms)' in line:
                        try:
                            time_val = float(line.split('Solve Time (ms)')[1].strip().split()[0])
                            solve_times.append(time_val)
                            f.write(f"Solve Time (ms): {time_val}\n")
                        except:
                            pass
                    elif 'Count Time (ms)' in line:
                        try:
                            time_val = float(line.split('Count Time (ms)')[1].strip().split()[0])
                            count_times.append(time_val)
                            f.write(f"Count Time (ms): {time_val}\n")
                        except:
                            pass

                # Determine relationship
                if "Policy 1 and Policy 2 are equivalent" in stdout:
                    f.write(f"\nPolicy 1 and Policy 2 are equivalent\n")
                    print(f"Case {i}: equivalent")
                elif "Policy 1 is more permissive than Policy 2" in stdout:
                    f.write(f"\nPolicy 1 is more permissive than Policy 2\n")
                    print(f"Case {i}: more_permissive")
                elif "Policy 1 is less permissive than Policy 2" in stdout:
                    f.write(f"\nPolicy 1 is less permissive than Policy 2\n")
                    print(f"Case {i}: less_permissive")
                else:
                    f.write(f"\nPolicy 1 and Policy 2 do not subsume each other.\n")
                    print(f"Case {i}: incomparable")

            f.write("\n")

    return log_filename

if __name__ == "__main__":
    if len(sys.argv) > 1:
        mode = sys.argv[1]
        max_cases = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    else:
        mode = "coarse"
        max_cases = 10

    print(f"Running simple Quacky analysis for {mode} mode (max {max_cases} cases)")
    log_file = generate_simple_log(mode, max_cases)
    print(f"Generated log file: {log_file}")
