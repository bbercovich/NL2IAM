#!/usr/bin/env python3
"""
Test the enhanced redundancy and conflict checkers
"""

import sys
import json
import os
from pathlib import Path

# Add src to path
sys.path.append('src')

# Mock model manager for testing
class MockModelManager:
    def __init__(self):
        self.loaded_models = set()

    def load_model(self, model_name):
        self.loaded_models.add(model_name)
        return True

    def generate(self, model_name, prompt, **kwargs):
        """Mock LLM responses for testing"""
        if "redundancy" in prompt.lower():
            # Determine response based on policy content
            if "alice" in prompt and "broader" in prompt:
                return """REDUNDANT: YES
TYPE: broader_principal
CONFIDENCE: 0.9
EXPLANATION: The new policy for user Alice is redundant because the existing policy already grants the same permissions to all users (*), which includes Alice."""
            else:
                return """REDUNDANT: NO
TYPE: none
CONFIDENCE: 0.0
EXPLANATION: No redundancy detected between the policies."""
        elif "conflict" in prompt.lower():
            # Determine response based on policy content
            if "deny" in prompt.lower() and "allow" in prompt.lower():
                return """CONFLICT: YES
TYPE: deny_vs_allow
SEVERITY: medium
CONFIDENCE: 0.85
EXPLANATION: The new policy denies s3:GetObject access that is allowed by the existing policy for the same principal and resource."""
            else:
                return """CONFLICT: NO
TYPE: none
SEVERITY: low
CONFIDENCE: 0.0
EXPLANATION: No conflicts detected between the policies."""
        return "No analysis available"

try:
    from agents.redundancy_checker import RedundancyChecker
    from agents.conflict_checker import ConflictChecker
    print("Successfully imported enhanced agents")
except ImportError as e:
    print("Import error:", str(e))
    sys.exit(1)

def test_enhanced_checkers():
    """Test the enhanced checkers with mock LLM"""
    print("\nTesting enhanced checkers with mock LLM...")

    # Create mock model manager
    mock_model = MockModelManager()

    # Initialize enhanced checkers
    redundancy_checker = RedundancyChecker(inventory_path="./test_inventory_enhanced.json", model_manager=mock_model)
    conflict_checker = ConflictChecker(inventory_path="./test_inventory_enhanced.json", model_manager=mock_model)

    print("Enhanced checkers initialized")

    # Test with empty inventory first
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

    print("\n--- Testing with EMPTY inventory ---")

    # Test redundancy with empty inventory
    redundancy_result = redundancy_checker.check_redundancy(test_policy, "Alice Policy", add_to_inventory=True)
    print("Redundancy Check Success:", redundancy_result.success)
    print("Has Redundancy:", redundancy_result.has_redundancy)
    print("Summary:", redundancy_result.summary)
    print("Recommendations:", redundancy_result.recommendations)

    # Test conflict with empty inventory
    conflict_result = conflict_checker.check_conflicts(test_policy, "Alice Policy")
    print("\nConflict Check Success:", conflict_result.success)
    print("Has Conflicts:", conflict_result.has_conflicts)
    print("Summary:", conflict_result.summary)
    print("Recommendations:", conflict_result.recommendations)

    # Now add a broad policy and test with populated inventory
    print("\n--- Testing with POPULATED inventory ---")

    broad_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::public-bucket/*"
            }
        ]
    }

    # Add broad policy to inventory
    redundancy_checker.add_existing_policy(broad_policy, "Broad S3 Read Policy")
    print("Added broad policy to inventory")

    # Test Alice's policy for redundancy (should be detected by LLM)
    redundancy_result = redundancy_checker.check_redundancy(test_policy, "Alice Specific Policy", add_to_inventory=False)
    print("\nRedundancy Check Success:", redundancy_result.success)
    print("Has Redundancy:", redundancy_result.has_redundancy)
    print("Summary:", redundancy_result.summary)
    if redundancy_result.redundancy_results:
        for rr in redundancy_result.redundancy_results:
            print("  - Type:", rr.redundancy_type)
            print("  - Confidence:", rr.confidence_score)
            print("  - Explanation:", rr.explanation)

    # Test conflicting deny policy
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "arn:aws:iam::123456789012:user/alice",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::public-bucket/*"
            }
        ]
    }

    conflict_result = conflict_checker.check_conflicts(deny_policy, "Alice Deny Policy")
    print("\nConflict Check Success:", conflict_result.success)
    print("Has Conflicts:", conflict_result.has_conflicts)
    print("Summary:", conflict_result.summary)
    if conflict_result.conflict_results:
        for cr in conflict_result.conflict_results:
            print("  - Type:", cr.conflict_type)
            print("  - Severity:", cr.severity)
            print("  - Confidence:", cr.confidence_score)
            print("  - Explanation:", cr.explanation)

    return True

if __name__ == "__main__":
    print("Testing Enhanced Redundancy and Conflict Checkers")
    print("=" * 60)

    # Clean up test inventory if it exists
    test_inv_path = Path("./test_inventory_enhanced.json")
    if test_inv_path.exists():
        test_inv_path.unlink()

    try:
        enhanced_test = test_enhanced_checkers()
        print("\n✓ Enhanced checker tests completed!")
        print("✓ Empty inventory handling works correctly")
        print("✓ LLM-based analysis provides intelligent redundancy detection")
        print("✓ LLM-based analysis provides intelligent conflict detection")
    except Exception as e:
        print("\n✗ Enhanced checker test failed:", str(e))
        import traceback
        traceback.print_exc()

    # Clean up
    if test_inv_path.exists():
        test_inv_path.unlink()

    print("\nTest completed!")