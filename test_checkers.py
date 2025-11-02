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
    from models.model_manager import create_default_manager
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
    print(f"Redundancy Check Success: {redundancy_result.success}")
    print(f"Has Redundancy: {redundancy_result.has_redundancy}")
    print(f"Summary: {redundancy_result.summary}")
    print(f"Recommendations: {redundancy_result.recommendations}")

    # Test conflict check
    print("\nTesting conflict checker...")
    conflict_result = conflict_checker.check_conflicts(test_policy, "Test Policy")
    print(f"Conflict Check Success: {conflict_result.success}")
    print(f"Has Conflicts: {conflict_result.has_conflicts}")
    print(f"Summary: {conflict_result.summary}")
    print(f"Recommendations: {conflict_result.recommendations}")

def test_with_model_manager():
    """Test checkers with model manager"""
    print("\n" + "="*60)
    print("Testing with model manager...")

    try:
        # Initialize model manager
        model_manager = create_default_manager()
        print("Model manager created")

        # Try to load DSL model for testing
        try:
            dsl_loaded = model_manager.load_model('dsl2policy_model')
            print(f"DSL model loaded: {dsl_loaded}")
        except Exception as e:
            print(f"Could not load DSL model: {e}")

        # Initialize checkers with model manager
        redundancy_checker = RedundancyChecker(inventory_path="./test_inventory.json", model_manager=model_manager)
        conflict_checker = ConflictChecker(inventory_path="./test_inventory.json", model_manager=model_manager)

        # Test policy
        test_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "arn:aws:iam::123456789012:user/bob",
                    "Action": "s3:PutObject",
                    "Resource": "arn:aws:s3:::uploads/*"
                }
            ]
        }

        # Test redundancy check with LLM
        print("\nTesting LLM-based redundancy checker...")
        redundancy_result = redundancy_checker.check_redundancy(test_policy, "Bob Upload Policy", add_to_inventory=True)
        print(f"Redundancy Check Success: {redundancy_result.success}")
        print(f"Has Redundancy: {redundancy_result.has_redundancy}")
        print(f"Summary: {redundancy_result.summary}")

        # Test conflict check with LLM
        print("\nTesting LLM-based conflict checker...")
        conflict_result = conflict_checker.check_conflicts(test_policy, "Bob Upload Policy")
        print(f"Conflict Check Success: {conflict_result.success}")
        print(f"Has Conflicts: {conflict_result.has_conflicts}")
        print(f"Summary: {conflict_result.summary}")

    except Exception as e:
        print(f"Error testing with model manager: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("Testing Updated Redundancy and Conflict Checkers")
    print("=" * 60)

    # Clean up test inventory if it exists
    test_inv_path = Path("./test_inventory.json")
    if test_inv_path.exists():
        test_inv_path.unlink()

    test_empty_inventory()
    test_with_model_manager()

    # Clean up
    if test_inv_path.exists():
        test_inv_path.unlink()

    print("\nTest completed!")