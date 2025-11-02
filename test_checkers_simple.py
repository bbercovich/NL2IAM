#!/usr/bin/env python3
"""
Test the updated redundancy and conflict checkers
"""

import sys
import json
from pathlib import Path

# Add src to path
sys.path.append('src')

try:
    from agents.redundancy_checker import RedundancyChecker
    from agents.conflict_checker import ConflictChecker
    print("Successfully imported modules")
except ImportError as e:
    print("Import error:", str(e))
    sys.exit(1)

def test_empty_inventory():
    """Test checkers with empty inventory"""
    print("Testing with empty inventory...")

    # Initialize checkers without model manager first
    redundancy_checker = RedundancyChecker(inventory_path="./test_inventory.json")
    conflict_checker = ConflictChecker(inventory_path="./test_inventory.json")

    # Test policy
    test_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:user/alice",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::public-bucket/*"
            }
        ]
    }

    # Test redundancy check
    print("\nTesting redundancy checker...")
    redundancy_result = redundancy_checker.check_redundancy(test_policy, "Test Policy", add_to_inventory=False)
    print("Redundancy Check Success:", redundancy_result.success)
    print("Has Redundancy:", redundancy_result.has_redundancy)
    print("Summary:", redundancy_result.summary)
    print("Recommendations:", redundancy_result.recommendations)

    # Test conflict check
    print("\nTesting conflict checker...")
    conflict_result = conflict_checker.check_conflicts(test_policy, "Test Policy")
    print("Conflict Check Success:", conflict_result.success)
    print("Has Conflicts:", conflict_result.has_conflicts)
    print("Summary:", conflict_result.summary)
    print("Recommendations:", conflict_result.recommendations)

if __name__ == "__main__":
    print("Testing Updated Redundancy and Conflict Checkers")
    print("=" * 60)

    # Clean up test inventory if it exists
    test_inv_path = Path("./test_inventory.json")
    if test_inv_path.exists():
        test_inv_path.unlink()

    test_empty_inventory()

    # Clean up
    if test_inv_path.exists():
        test_inv_path.unlink()

    print("\nTest completed!")