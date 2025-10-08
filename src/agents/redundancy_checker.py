#!/usr/bin/env python3
"""
Redundancy Checker Agent

This agent implements the Conflict & Redundancy Checker component as described
in the paper's Validation Pipeline. It compares new IAM policies against the
Policy Inventory to detect redundancy patterns.

Key features:
- Rule-based engine for redundancy detection
- Detailed analysis with confidence scores
- Human-readable explanations and recommendations
- Integration with Policy Inventory system
"""

import json
import sys
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

# Add src to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from core.inventory import PolicyInventory, RedundancyResult


@dataclass
class RedundancyCheckResult:
    """Result of redundancy check operation"""
    success: bool
    has_redundancy: bool
    redundancy_results: List[RedundancyResult]
    summary: str
    recommendations: List[str]
    error_message: Optional[str] = None


class RedundancyChecker:
    """
    Redundancy Checker Agent for IAM Policy Validation Pipeline

    As specified in the paper architecture:
    - Rule-based engine comparing new policy against Policy Inventory
    - Detects redundancy patterns including identical policies and subset permissions
    - Provides detailed analysis with explanations
    - Outputs recommendations for policy optimization
    """

    def __init__(self, inventory_path: Optional[str] = None):
        """
        Initialize the redundancy checker.

        Args:
            inventory_path: Optional path to persistent policy inventory
        """
        self.inventory = PolicyInventory()
        self.inventory_path = inventory_path

        # Load existing policies if inventory path provided
        if inventory_path and Path(inventory_path).exists():
            self._load_inventory(inventory_path)

    def check_redundancy(
        self,
        new_policy: Dict[str, Any],
        policy_name: Optional[str] = None,
        add_to_inventory: bool = True
    ) -> RedundancyCheckResult:
        """
        Check if a new policy is redundant with existing policies.

        Args:
            new_policy: The IAM policy JSON to check for redundancy
            policy_name: Optional name for the policy (for reporting)
            add_to_inventory: Whether to add the policy to inventory after checking

        Returns:
            RedundancyCheckResult with detailed analysis
        """
        try:
            # Validate policy structure
            if not self._is_valid_policy(new_policy):
                return RedundancyCheckResult(
                    success=False,
                    has_redundancy=False,
                    redundancy_results=[],
                    summary="Invalid policy structure",
                    recommendations=[],
                    error_message="Policy must have Version and Statement fields"
                )

            # Check for redundancy
            redundancy_results = self.inventory.find_redundant_policies(new_policy)

            # Generate summary and recommendations
            summary = self._generate_summary(redundancy_results, policy_name)
            recommendations = self._generate_recommendations(redundancy_results)

            # Add policy to inventory if requested and not redundant
            if add_to_inventory and not redundancy_results:
                policy_id = self.inventory.add_policy(
                    new_policy,
                    name=policy_name or f"Policy-{len(self.inventory.policies) + 1}"
                )
                summary += f" Policy added to inventory with ID: {policy_id[:8]}"
            elif add_to_inventory and redundancy_results:
                summary += " Policy NOT added to inventory due to redundancy."

            # Save inventory if path provided
            if self.inventory_path:
                self._save_inventory(self.inventory_path)

            return RedundancyCheckResult(
                success=True,
                has_redundancy=len(redundancy_results) > 0,
                redundancy_results=redundancy_results,
                summary=summary,
                recommendations=recommendations
            )

        except Exception as e:
            return RedundancyCheckResult(
                success=False,
                has_redundancy=False,
                redundancy_results=[],
                summary=f"Error during redundancy check: {str(e)}",
                recommendations=[],
                error_message=str(e)
            )

    def get_redundancy_report(self, new_policy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a comprehensive redundancy report.

        Args:
            new_policy: The policy to analyze

        Returns:
            Detailed redundancy report
        """
        return self.inventory.generate_redundancy_report(new_policy)

    def add_existing_policy(
        self,
        policy: Dict[str, Any],
        name: str,
        description: Optional[str] = None
    ) -> str:
        """
        Add an existing policy to the inventory.

        Args:
            policy: The IAM policy JSON
            name: Policy name
            description: Optional policy description

        Returns:
            Policy ID
        """
        policy_id = self.inventory.add_policy(
            policy,
            name=name,
            description=description,
            source="imported"
        )

        if self.inventory_path:
            self._save_inventory(self.inventory_path)

        return policy_id

    def list_policies(self) -> List[Dict[str, Any]]:
        """
        List all policies in the inventory.

        Returns:
            List of policy metadata
        """
        policies = []
        for policy_id in self.inventory.list_policies():
            metadata = self.inventory.get_policy_metadata(policy_id)
            policy_data = self.inventory.get_policy(policy_id)

            policies.append({
                'id': policy_id,
                'name': metadata.name if metadata else 'Unknown',
                'description': metadata.description if metadata else None,
                'created_at': metadata.created_at.isoformat() if metadata else None,
                'source': metadata.source if metadata else 'unknown',
                'policy': policy_data
            })

        return policies

    def get_inventory_stats(self) -> Dict[str, Any]:
        """Get statistics about the policy inventory."""
        return self.inventory.get_inventory_stats()

    def clear_inventory(self) -> None:
        """Clear all policies from the inventory."""
        policy_ids = self.inventory.list_policies().copy()
        for policy_id in policy_ids:
            self.inventory.remove_policy(policy_id)

        if self.inventory_path:
            self._save_inventory(self.inventory_path)

    def _is_valid_policy(self, policy: Dict[str, Any]) -> bool:
        """Validate basic IAM policy structure."""
        if not isinstance(policy, dict):
            return False

        # Check required fields
        if "Version" not in policy or "Statement" not in policy:
            return False

        # Validate statements
        statements = policy["Statement"]
        if isinstance(statements, dict):
            statements = [statements]

        if not isinstance(statements, list) or len(statements) == 0:
            return False

        for stmt in statements:
            if not isinstance(stmt, dict):
                return False
            if "Effect" not in stmt:
                return False
            if stmt["Effect"] not in ["Allow", "Deny"]:
                return False

        return True

    def _generate_summary(
        self,
        redundancy_results: List[RedundancyResult],
        policy_name: Optional[str]
    ) -> str:
        """Generate a summary of redundancy check results."""
        policy_ref = f"Policy '{policy_name}'" if policy_name else "Policy"

        if not redundancy_results:
            return f"{policy_ref} has no redundancy with existing policies."

        high_confidence = [r for r in redundancy_results if r.confidence_score >= 0.9]
        medium_confidence = [r for r in redundancy_results if 0.7 <= r.confidence_score < 0.9]

        if high_confidence:
            return f"{policy_ref} is redundant with {len(high_confidence)} existing policy(ies) (high confidence)."
        elif medium_confidence:
            return f"{policy_ref} has potential redundancy with {len(medium_confidence)} existing policy(ies) (medium confidence)."
        else:
            return f"{policy_ref} has low-confidence redundancy patterns detected."

    def _generate_recommendations(
        self,
        redundancy_results: List[RedundancyResult]
    ) -> List[str]:
        """Generate recommendations based on redundancy analysis."""
        recommendations = []

        if not redundancy_results:
            recommendations.append("✅ No redundancy detected. Policy can be safely created.")
            return recommendations

        for result in redundancy_results:
            if result.redundancy_type == "identical":
                recommendations.append(
                    f"⚠️  Policy is identical to existing policy. Consider reusing the existing policy instead."
                )
            elif result.redundancy_type == "broader_principal":
                recommendations.append(
                    f"⚠️  Existing policy already grants these permissions to a broader set of principals. "
                    f"The new policy may be unnecessary unless more restrictive conditions are needed."
                )
            elif result.redundancy_type == "subset":
                recommendations.append(
                    f"⚠️  New policy permissions are already covered by existing policy. "
                    f"Consider removing redundant permissions or consolidating policies."
                )
            elif result.redundancy_type == "partial":
                recommendations.append(
                    f"⚠️  Most permissions in the new policy are already granted by existing policies. "
                    f"Review for optimization opportunities."
                )

            if result.confidence_score < 0.8:
                recommendations.append(
                    f"📝 Low confidence detection - manual review recommended."
                )

        return recommendations

    def _load_inventory(self, inventory_path: str) -> None:
        """Load policies from persistent storage."""
        try:
            with open(inventory_path, 'r') as f:
                data = json.load(f)

            for policy_data in data.get('policies', []):
                self.inventory.add_policy(
                    policy_data['policy'],
                    policy_id=policy_data.get('id'),
                    name=policy_data.get('name'),
                    description=policy_data.get('description'),
                    source=policy_data.get('source', 'imported')
                )
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Warning: Could not load inventory from {inventory_path}: {e}")

    def _save_inventory(self, inventory_path: str) -> None:
        """Save policies to persistent storage."""
        try:
            policies_data = []
            for policy_id in self.inventory.list_policies():
                metadata = self.inventory.get_policy_metadata(policy_id)
                policy = self.inventory.get_policy(policy_id)

                policies_data.append({
                    'id': policy_id,
                    'name': metadata.name if metadata else 'Unknown',
                    'description': metadata.description if metadata else None,
                    'created_at': metadata.created_at.isoformat() if metadata else None,
                    'source': metadata.source if metadata else 'unknown',
                    'policy': policy
                })

            # Create directory if it doesn't exist
            Path(inventory_path).parent.mkdir(parents=True, exist_ok=True)

            with open(inventory_path, 'w') as f:
                json.dump({'policies': policies_data}, f, indent=2)

        except Exception as e:
            print(f"Warning: Could not save inventory to {inventory_path}: {e}")


def main():
    """Test the redundancy checker"""
    print("🔍 Testing Redundancy Checker Agent")
    print("=" * 60)

    # Initialize checker
    checker = RedundancyChecker()

    # Test policies
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

    alice_policy = {
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

    # Add broad policy first
    print("📝 Adding broad policy to inventory...")
    checker.add_existing_policy(broad_policy, "Public Bucket Access - All Users")

    # Check Alice's policy for redundancy
    print("\n🔍 Checking Alice's policy for redundancy...")
    result = checker.check_redundancy(alice_policy, "Alice's S3 Read Policy", add_to_inventory=False)

    print(f"\n📊 RESULTS:")
    print(f"   Success: {result.success}")
    print(f"   Has Redundancy: {result.has_redundancy}")
    print(f"   Summary: {result.summary}")

    if result.redundancy_results:
        print(f"\n📋 REDUNDANCY DETAILS:")
        for r in result.redundancy_results:
            print(f"   - Type: {r.redundancy_type}")
            print(f"   - Confidence: {r.confidence_score:.2f}")
            print(f"   - Explanation: {r.explanation}")

    if result.recommendations:
        print(f"\n💡 RECOMMENDATIONS:")
        for rec in result.recommendations:
            print(f"   {rec}")

    print(f"\n📈 INVENTORY STATS:")
    stats = checker.get_inventory_stats()
    print(f"   Total policies: {stats['total_policies']}")
    print(f"   Unique actions: {stats['unique_actions']}")
    print(f"   Unique resources: {stats['unique_resources']}")
    print(f"   Unique principals: {stats['unique_principals']}")


if __name__ == "__main__":
    main()