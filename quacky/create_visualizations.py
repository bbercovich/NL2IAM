#!/usr/bin/env python3
"""
Create visualizations from the manual count results
"""
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
import os

def create_visualizations():
    # Results from manual count
    results = {
        'Equivalent': 27,
        'More Permissive': 2,
        'Less Permissive': 3,
        'Incomparable': 13,
        'Timeout': 2
    }

    # Create output directory
    output_dir = "fine_analysis_results"
    os.makedirs(output_dir, exist_ok=True)

    # Set Seaborn style
    sns.set_theme(style="whitegrid")

    # Create DataFrame
    df = pd.DataFrame([
        {'result': 'Equivalent', 'count': 27},
        {'result': 'More Permissive', 'count': 2},
        {'result': 'Less Permissive', 'count': 3},
        {'result': 'Incomparable', 'count': 13},
        {'result': 'Timeout', 'count': 2}
    ])

    # 1. Pie Chart
    plt.figure(figsize=(10, 8))
    colors = ['#1f77b4', '#ff7f0e', '#d62728', '#2ca02c', '#ff69b4']
    plt.pie(df['count'], labels=df['result'], autopct='%1.1f%%', colors=colors)
    plt.title('Distribution of Policy Comparison Results (Fine Mode)')
    plt.savefig(os.path.join(output_dir, 'results_pie_chart.png'))
    plt.close()

    # 2. Bar Chart
    plt.figure(figsize=(12, 6))
    category_order = ['Equivalent', 'Less Permissive', 'Incomparable', 'More Permissive', 'Timeout']
    sns.countplot(data=df, x='result', order=category_order)
    plt.xticks(rotation=45)
    plt.title('Count of Different Comparison Results (Fine Mode)')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'results_bar_chart.png'))
    plt.close()

    # 3. Summary statistics
    total = df['count'].sum()
    result_stats = {row['result']: row['count']/total*100 for _, row in df.iterrows()}

    # Save statistics to text file
    with open(os.path.join(output_dir, 'analysis_summary.txt'), 'w') as f:
        f.write("Summary Statistics - Fine Mode\n")
        f.write("=============================\n\n")
        f.write("Result Distribution:\n")
        for result, percentage in result_stats.items():
            f.write(f"{result}: {percentage:.1f}%\n")

    print("Generated visualizations in fine_analysis_results/")
    print(f"\n=== FINE MODE RESULTS SUMMARY ===")
    print(f"Total cases analyzed: {total}")
    for result, count in results.items():
        print(f"{result}: {count} ({count/total*100:.1f}%)")

if __name__ == "__main__":
    create_visualizations()
