# analyze_with_quacky.py
import os
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime

def run_quacky_analysis(gt_policy_path, synth_policy_path, quacky_path="/home/user/Research/quacky/src"):
    """Run Quacky analysis on two policies and return detailed results"""
    try:
        # Use Quacky to compare policies
        result = subprocess.run([
            'python', f'{quacky_path}/quacky.py',
            '-p1', gt_policy_path,
            '-p2', synth_policy_path,
            '-b', '100',  # bound for analysis
            '-c'  # use constraints
        ], capture_output=True, text=True, cwd=quacky_path)

        # Parse Quacky output to extract timing and relationship information
        output = result.stdout
        stderr = result.stderr

        # Extract timing information
        solve_times = []
        count_times = []

        for line in output.split('\n'):
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
        output_lower = output.lower()

        if "policy 1 ⇏ policy 2" in output_lower and "policy 2 ⇏ policy 1" in output_lower:
            # Both directions are unsatisfiable, meaning they're equivalent
            relationship = "Policy 1 and Policy 2 are equivalent"
            result_type = "equivalent"
        elif "policy 1 ⇏ policy 2" in output_lower and "policy 2 ⇏ policy 1" not in output_lower:
            # Policy 1 is not more permissive than policy 2, but policy 2 might be more permissive than policy 1
            relationship = "Policy 1 is less permissive than Policy 2"
            result_type = "less_permissive"
        elif "policy 2 ⇏ policy 1" in output_lower and "policy 1 ⇏ policy 2" not in output_lower:
            # Policy 2 is not more permissive than policy 1, but policy 1 might be more permissive than policy 2
            relationship = "Policy 1 is more permissive than Policy 2"
            result_type = "more_permissive"
        else:
            # Both are satisfiable, meaning they're incomparable
            relationship = "Policy 1 and Policy 2 are incomparable"
            result_type = "incomparable"

        return {
            'relationship': relationship,
            'result_type': result_type,
            'total_time': total_time,
            'solve_times': solve_times,
            'count_times': count_times,
            'raw_output': output,
            'stderr': stderr
        }

    except Exception as e:
        return {
            'relationship': f"Error: {str(e)}",
            'result_type': "error",
            'total_time': 0,
            'solve_times': [],
            'count_times': [],
            'raw_output': "",
            'stderr': str(e)
        }

def generate_quacky_log(results, mode_name):
    """Generate a log file in the format expected by analysis.py"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"experiment_log_{mode_name}_{timestamp}.txt"

    with open(log_filename, 'w') as f:
        f.write(f"Started logging at: {timestamp}\n")
        f.write(f"Log file: {os.path.abspath(log_filename)}\n\n")
        f.write(f"Experiment 2 - Policy Comparison Analysis - {mode_name.upper()} Mode\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("=" * 80 + "\n\n")

        for result in results:
            if result["result_type"] == "missing_files":
                continue

            f.write("===============================================================================\n")
            f.write(f"Processing pair {result['case']}\n")
            f.write("===============================================================================\n\n")

            # Write Quacky output in the expected format
            f.write("Quacky Results:\n")

            # Extract and format timing information from raw output
            raw_output = result["raw_output"]
            solve_times = []
            count_times = []

            for line in raw_output.split('\n'):
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

            # Write the relationship statement in the expected format
            if result["result_type"] == "equivalent":
                f.write(f"\n{result['relationship']}\n")
            elif result["result_type"] == "more_permissive":
                f.write(f"\n{result['relationship']}\n")
            elif result["result_type"] == "less_permissive":
                f.write(f"\n{result['relationship']}\n")
            else:  # incomparable
                f.write(f"\nPolicy 1 and Policy 2 do not subsume each other.\n")

            f.write("\n")

    return log_filename

def analyze_all_policies():
    # Set up paths
    base_dir = Path("/home/user/Research/Synthesizing_Access_Control_Policy/Project_Files")
    gt_dir = base_dir / "experiment_2_results"
    coarse_dir = base_dir / "results" / "coarse"
    fine_dir = base_dir / "results" / "fine"

    # Analyze coarse mode
    print("Analyzing coarse mode policies...")
    coarse_results = []
    for i in range(47):  # 0-46
        gt_path = gt_dir / f"ground_truth_{i}.json"
        synth_path = coarse_dir / f"{i}_policy.json"

        if gt_path.exists() and synth_path.exists():
            print(f"Analyzing case {i}...")
            result = run_quacky_analysis(str(gt_path), str(synth_path))
            result.update({
                "case": i,
                "ground_truth": f"ground_truth_{i}.json",
                "synthesized": f"{i}_policy.json"
            })
            coarse_results.append(result)
            print(f"Case {i}: {result['result_type']}")
        else:
            print(f"Missing files for case {i}: gt={gt_path.exists()}, synth={synth_path.exists()}")
            coarse_results.append({
                "case": i,
                "ground_truth": f"ground_truth_{i}.json",
                "synthesized": f"{i}_policy.json",
                "result_type": "missing_files",
                "relationship": "Missing files",
                "total_time": 0,
                "raw_output": ""
            })

    # Analyze fine mode
    print("\nAnalyzing fine mode policies...")
    fine_results = []
    for i in range(47):  # 0-46
        gt_path = gt_dir / f"ground_truth_{i}.json"
        synth_path = fine_dir / f"{i}_policy.json"

        if gt_path.exists() and synth_path.exists():
            print(f"Analyzing case {i}...")
            result = run_quacky_analysis(str(gt_path), str(synth_path))
            result.update({
                "case": i,
                "ground_truth": f"ground_truth_{i}.json",
                "synthesized": f"{i}_policy.json"
            })
            fine_results.append(result)
            print(f"Case {i}: {result['result_type']}")
        else:
            print(f"Missing files for case {i}: gt={gt_path.exists()}, synth={synth_path.exists()}")
            fine_results.append({
                "case": i,
                "ground_truth": f"ground_truth_{i}.json",
                "synthesized": f"{i}_policy.json",
                "result_type": "missing_files",
                "relationship": "Missing files",
                "total_time": 0,
                "raw_output": ""
            })

    # Generate log files for analysis.py
    coarse_log = generate_quacky_log(coarse_results, "coarse")
    fine_log = generate_quacky_log(fine_results, "fine")

    print(f"\nGenerated log files:")
    print(f"Coarse mode: {coarse_log}")
    print(f"Fine mode: {fine_log}")

    # Save JSON results as well
    with open("coarse_quacky_results.json", "w") as f:
        json.dump(coarse_results, f, indent=2)

    with open("fine_quacky_results.json", "w") as f:
        json.dump(fine_results, f, indent=2)

    # Print summary
    print("\n=== COARSE MODE SUMMARY ===")
    coarse_summary = {}
    for result in coarse_results:
        res = result["result_type"]
        coarse_summary[res] = coarse_summary.get(res, 0) + 1
    for k, v in coarse_summary.items():
        print(f"{k}: {v}")

    print("\n=== FINE MODE SUMMARY ===")
    fine_summary = {}
    for result in fine_results:
        res = result["result_type"]
        fine_summary[res] = fine_summary.get(res, 0) + 1
    for k, v in fine_summary.items():
        print(f"{k}: {v}")

    return coarse_log, fine_log

if __name__ == "__main__":
    analyze_all_policies()
