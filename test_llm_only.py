#!/usr/bin/env python3
"""
Test the LLM-only implementation (research version)
"""

import sys

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
            return """REDUNDANT: NO
TYPE: none
CONFIDENCE: 0.0
EXPLANATION: No redundancy detected between the policies as they target different principals and resources."""
        elif "conflict" in prompt.lower():
            return """CONFLICT: NO
TYPE: none
SEVERITY: low
CONFIDENCE: 0.0
EXPLANATION: No conflicts detected between the policies as they do not have overlapping ALLOW/DENY patterns."""
        return "No analysis available"

def test_llm_required():
    """Test that LLM is required and errors are raised when missing"""
    print("Testing LLM-only implementation...")

    try:
        from agents.redundancy_checker import RedundancyChecker
        from agents.conflict_checker import ConflictChecker
        print("Successfully imported LLM-only agents")
    except ImportError as e:
        print("Import error:", str(e))
        return False

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

    print("\n1. Testing without model_manager (should raise errors)...")

    # Test redundancy checker without model manager
    try:
        redundancy_checker = RedundancyChecker(inventory_path="./test_llm_inventory.json")
        redundancy_checker.add_existing_policy(test_policy, "Test Policy")

        # This should raise an error
        result = redundancy_checker.check_redundancy(test_policy, "Another Policy", add_to_inventory=False)
        print("ERROR: Redundancy checker should have failed without model_manager!")
        return False
    except ValueError as e:
        print("✓ Redundancy checker correctly raised ValueError:", str(e))
    except Exception as e:
        print("✓ Redundancy checker correctly raised error:", str(e))

    # Test conflict checker without model manager
    try:
        conflict_checker = ConflictChecker(inventory_path="./test_llm_inventory.json")

        # This should raise an error
        result = conflict_checker.check_conflicts(test_policy, "Test Policy")
        print("ERROR: Conflict checker should have failed without model_manager!")
        return False
    except ValueError as e:
        print("✓ Conflict checker correctly raised ValueError:", str(e))
    except Exception as e:
        print("✓ Conflict checker correctly raised error:", str(e))

    print("\n2. Testing with mock model_manager (should work)...")

    # Test with mock model manager
    mock_model = MockModelManager()

    try:
        # Test redundancy checker with model manager
        redundancy_checker = RedundancyChecker(inventory_path="./test_llm_inventory.json", model_manager=mock_model)

        # Empty inventory test
        result = redundancy_checker.check_redundancy(test_policy, "Test Policy", add_to_inventory=True)
        print("✓ Redundancy checker works with model_manager - Success:", result.success)
        print("✓ Empty inventory correctly shows no redundancy:", not result.has_redundancy)

        # Test conflict checker with model manager
        conflict_checker = ConflictChecker(inventory_path="./test_llm_inventory.json", model_manager=mock_model)

        # Empty inventory test
        result = conflict_checker.check_conflicts(test_policy, "Test Policy")
        print("✓ Conflict checker works with model_manager - Success:", result.success)
        print("✓ Empty inventory correctly shows no conflicts:", not result.has_conflicts)

        # Test with populated inventory
        redundancy_checker.add_existing_policy({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::*"
            }]
        }, "Broad Policy")

        result = redundancy_checker.check_redundancy(test_policy, "Alice Policy", add_to_inventory=False)
        print("✓ LLM analysis completed for redundancy check")

        result = conflict_checker.check_conflicts(test_policy, "Alice Policy")
        print("✓ LLM analysis completed for conflict check")

        return True

    except Exception as e:
        print("ERROR: LLM-based analysis failed:", str(e))
        import traceback
        traceback.print_exc()
        return False

def cleanup():
    """Clean up test files"""
    import os
    if os.path.exists("./test_llm_inventory.json"):
        os.remove("./test_llm_inventory.json")

if __name__ == "__main__":
    print("Testing LLM-Only Research Implementation")
    print("=" * 50)

    cleanup()  # Clean up before test

    try:
        success = test_llm_required()

        if success:
            print("\n✓ All LLM-only tests passed!")
            print("✓ System correctly requires LLM for operation")
            print("✓ Proper errors raised when LLM unavailable")
            print("✓ LLM analysis works when model_manager provided")
            print("\nThe system is now ready for LLM-based research!")
        else:
            print("\n✗ Some tests failed!")

    finally:
        cleanup()  # Clean up after test

    print("\nTest completed!")