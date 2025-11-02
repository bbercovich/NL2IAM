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
    LLM-Based Redundancy Checker Agent for IAM Policy Validation Pipeline

    Research implementation using LLM-only analysis:
    - Requires LLM model manager for operation (no fallback to rule-based)
    - Uses LLM to intelligently assess redundancy with proper principal checking
    - Detects redundancy patterns including identical policies and subset permissions
    - Provides detailed analysis with explanations
    - Outputs recommendations for policy optimization
    - Returns errors if LLM is unavailable (research requirement)
    """

    def __init__(self, inventory_path: Optional[str] = None, model_manager=None):
        """
        Initialize the redundancy checker.

        Args:
            inventory_path: Optional path to persistent policy inventory
            model_manager: Model manager for LLM-based analysis
        """
        self.inventory = PolicyInventory()
        self.inventory_path = inventory_path
        self.model_manager = model_manager

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
        Check if a new policy is redundant with existing policies using LLM analysis.

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

            # Get all existing policies
            existing_policies = self.list_policies()

            # If no existing policies, no redundancy possible
            if not existing_policies:
                if add_to_inventory:
                    policy_id = self.inventory.add_policy(
                        new_policy,
                        name=policy_name or f"Policy-{len(self.inventory.policies) + 1}"
                    )
                    if self.inventory_path:
                        self._save_inventory(self.inventory_path)
                    summary = f"No existing policies to check against. Policy added with ID: {policy_id[:8]}"
                else:
                    summary = "No existing policies to check against."

                return RedundancyCheckResult(
                    success=True,
                    has_redundancy=False,
                    redundancy_results=[],
                    summary=summary,
                    recommendations=["✅ No redundancy detected. Policy can be safely created."]
                )

            # Use LLM-based redundancy checking
            redundancy_results = self._llm_check_redundancy(new_policy, existing_policies)

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
                    f"⚠️  Some permissions in the new policy are already granted by existing policies. "
                    f"Consider optimizing to include only new permissions."
                )

            # Try to access additional analysis data
            try:
                # Parse the explanation for redundant actions and suggestions
                explanation = result.explanation
                if "redundant actions:" in explanation.lower() or "actions:" in explanation.lower():
                    recommendations.append(
                        f"📝 Review explanation for specific redundant actions"
                    )

                if "suggestion:" in explanation.lower() or "optimize" in explanation.lower():
                    recommendations.append(
                        f"💡 See detailed explanation for optimization suggestions"
                    )
            except:
                pass

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

    def _llm_check_redundancy(self, new_policy: Dict[str, Any], existing_policies: List[Dict[str, Any]]) -> List:
        """
        Use LLM to intelligently check for redundancy with proper principal analysis.
        Optimized to batch multiple policies for efficiency.
        """
        redundancy_results = []

        if not self.model_manager:
            raise ValueError("Model manager is required for LLM-based redundancy checking. This research system requires LLM analysis.")

        # Batch process policies in groups to reduce API calls
        batch_size = 5  # Process 5 policies per LLM call

        for i in range(0, len(existing_policies), batch_size):
            batch = existing_policies[i:i+batch_size]

            # Create prompt for batch analysis
            prompt = self._create_batch_redundancy_analysis_prompt(new_policy, batch)

            # Get LLM analysis for the batch
            try:
                response = self.model_manager.generate(
                    'dsl2policy_model',
                    prompt,
                    max_new_tokens=400,  # More tokens for batch response
                    temperature=0.1,
                    top_p=0.9
                )

                # Parse batch response
                batch_analyses = self._parse_batch_redundancy_response(response, batch)

                # Process each analysis in the batch
                for j, analysis in enumerate(batch_analyses):
                    if analysis['is_redundant']:
                        existing_policy_data = batch[j]
                        from core.inventory import RedundancyResult
                        redundancy_result = RedundancyResult(
                            is_redundant=True,
                            redundant_policy_id=existing_policy_data['id'],
                            redundancy_type=analysis['redundancy_type'],
                            explanation=analysis['explanation'],
                            new_policy_statements=new_policy.get('Statement', []),
                            existing_policy_statements=existing_policy_data['policy'].get('Statement', []),
                            confidence_score=analysis['confidence_score']
                        )
                        redundancy_results.append(redundancy_result)

            except Exception as e:
                # Fallback to individual analysis for this batch
                print(f"Warning: Batch analysis failed, falling back to individual analysis: {e}")
                batch_results = self._individual_redundancy_check(new_policy, batch)
                redundancy_results.extend(batch_results)

        return redundancy_results

    def _individual_redundancy_check(self, new_policy: Dict[str, Any], policies_batch: List[Dict[str, Any]]) -> List:
        """
        Fallback method for individual policy checking when batch fails.
        """
        redundancy_results = []

        for existing_policy_data in policies_batch:
            existing_policy = existing_policy_data['policy']
            existing_name = existing_policy_data['name']
            existing_id = existing_policy_data['id']

            # Create prompt for LLM analysis
            prompt = self._create_redundancy_analysis_prompt(new_policy, existing_policy, existing_name)

            # Get LLM analysis
            try:
                response = self.model_manager.generate(
                    'dsl2policy_model',
                    prompt,
                    max_new_tokens=200,
                    temperature=0.1,
                    top_p=0.9
                )

                # Parse LLM response
                analysis = self._parse_redundancy_response(response)

                if analysis['is_redundant']:
                    from core.inventory import RedundancyResult
                    redundancy_result = RedundancyResult(
                        is_redundant=True,
                        redundant_policy_id=existing_id,
                        redundancy_type=analysis['redundancy_type'],
                        explanation=analysis['explanation'],
                        new_policy_statements=new_policy.get('Statement', []),
                        existing_policy_statements=existing_policy.get('Statement', []),
                        confidence_score=analysis['confidence_score']
                    )
                    redundancy_results.append(redundancy_result)

            except Exception as e:
                raise RuntimeError(f"LLM analysis failed for policy {existing_name}: {e}. LLM-based analysis is required for this research system.")

        return redundancy_results

    def _create_redundancy_analysis_prompt(self, new_policy: Dict[str, Any], existing_policy: Dict[str, Any], existing_name: str) -> str:
        """
        Create a prompt for LLM-based redundancy analysis with granular detection.
        """
        prompt = f"""You are an AWS IAM policy expert. Analyze if the NEW policy has redundancy with the EXISTING policy at both the whole-policy and statement/action level.

REDUNDANCY TYPES TO CHECK:
1. **Whole Policy Redundancy**: The entire new policy is covered by the existing policy
2. **Statement-Level Redundancy**: Individual statements in the new policy are already covered
3. **Action-Level Redundancy**: Specific actions within statements are already granted
4. **Partial Redundancy**: Some permissions overlap but not all

KEY ANALYSIS RULES:
- A specific user principal (e.g., arn:aws:iam::123:user/alice) is covered by broader principals like "*" or "arn:aws:iam::123:*"
- Specific actions are covered by broader actions (e.g., s3:GetObject is covered by s3:*)
- Specific resources are covered by broader resources (e.g., arn:aws:s3:::bucket/file.txt is covered by arn:aws:s3:::bucket/*)
- Check each statement and action individually, not just the whole policy

NEW POLICY:
{json.dumps(new_policy, indent=2)}

EXISTING POLICY ({existing_name}):
{json.dumps(existing_policy, indent=2)}

Provide your analysis in this exact format:
REDUNDANT: [YES/NO]
TYPE: [identical/subset/broader_principal/broader_resource/partial/none]
CONFIDENCE: [0.0-1.0]
EXPLANATION: [Detailed explanation including which specific statements/actions are redundant]
REDUNDANT_ACTIONS: [List specific redundant actions, or "none"]
OPTIMIZED_SUGGESTION: [Suggest how to modify the new policy to remove redundancy, or "no changes needed"]
"""
        return prompt

    def _parse_redundancy_response(self, response: str) -> Dict[str, Any]:
        """
        Parse LLM response for enhanced redundancy analysis.
        """
        analysis = {
            'is_redundant': False,
            'redundancy_type': 'none',
            'confidence_score': 0.0,
            'explanation': 'No redundancy detected',
            'redundant_actions': [],
            'optimized_suggestion': 'No changes needed'
        }

        try:
            lines = response.strip().split('\n')

            for line in lines:
                line = line.strip()
                if line.startswith('REDUNDANT:'):
                    redundant_val = line.split(':', 1)[1].strip().upper()
                    analysis['is_redundant'] = redundant_val in ['YES', 'TRUE']
                elif line.startswith('TYPE:'):
                    analysis['redundancy_type'] = line.split(':', 1)[1].strip().lower()
                elif line.startswith('CONFIDENCE:'):
                    try:
                        confidence_str = line.split(':', 1)[1].strip()
                        analysis['confidence_score'] = float(confidence_str)
                    except ValueError:
                        analysis['confidence_score'] = 0.5
                elif line.startswith('EXPLANATION:'):
                    explanation = line.split(':', 1)[1].strip()
                    # Handle multi-line explanations
                    analysis['explanation'] = explanation
                elif line.startswith('REDUNDANT_ACTIONS:'):
                    actions_str = line.split(':', 1)[1].strip()
                    if actions_str.lower() != 'none':
                        # Parse list of actions (could be comma-separated)
                        analysis['redundant_actions'] = [action.strip() for action in actions_str.split(',')]
                elif line.startswith('OPTIMIZED_SUGGESTION:'):
                    suggestion = line.split(':', 1)[1].strip()
                    analysis['optimized_suggestion'] = suggestion

        except Exception as e:
            print(f"Warning: Failed to parse redundancy response: {e}")

        return analysis

    def _create_batch_redundancy_analysis_prompt(self, new_policy: Dict[str, Any], existing_policies_batch: List[Dict[str, Any]]) -> str:
        """
        Create a prompt for batch LLM-based redundancy analysis.
        """
        existing_policies_text = ""
        for i, policy_data in enumerate(existing_policies_batch):
            existing_policies_text += f"\nEXISTING POLICY {i+1} ({policy_data['name']}):\n{json.dumps(policy_data['policy'], indent=2)}\n"

        prompt = f"""You are an AWS IAM policy expert. Analyze if the NEW policy is redundant with any of the EXISTING policies.

A policy is redundant if:
1. The new policy grants permissions that are already covered by an existing policy
2. The principals in the new policy are the same as or covered by the existing policy principals
3. The resources and actions overlap significantly

Key considerations:
- A specific user principal (e.g., arn:aws:iam::123:user/alice) is covered by broader principals like "*" or "arn:aws:iam::123:*"
- Specific actions are covered by broader actions (e.g., s3:GetObject is covered by s3:*)
- Specific resources are covered by broader resources (e.g., arn:aws:s3:::bucket/file.txt is covered by arn:aws:s3:::bucket/*)

NEW POLICY:
{json.dumps(new_policy, indent=2)}
{existing_policies_text}

For each existing policy, provide your analysis in this exact format:
POLICY_1:
REDUNDANT: [YES/NO]
TYPE: [identical/subset/broader_principal/broader_resource/partial/none]
CONFIDENCE: [0.0-1.0]
EXPLANATION: [Detailed explanation including specific redundant statements/actions]
REDUNDANT_ACTIONS: [List specific redundant actions, or "none"]
OPTIMIZED_SUGGESTION: [Suggest how to modify the new policy to remove redundancy, or "no changes needed"]

POLICY_2:
[Continue for each policy...]
"""
        return prompt

    def _parse_batch_redundancy_response(self, response: str, policies_batch: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse LLM batch response for redundancy analysis.
        """
        analyses = []

        # Initialize default analyses for all policies in batch
        for _ in policies_batch:
            analyses.append({
                'is_redundant': False,
                'redundancy_type': 'none',
                'confidence_score': 0.0,
                'explanation': 'No redundancy detected',
                'redundant_actions': [],
                'optimized_suggestion': 'No changes needed'
            })

        try:
            # Split response by policy sections
            policy_sections = response.split('POLICY_')

            for i, section in enumerate(policy_sections[1:]):  # Skip first empty section
                if i >= len(analyses):
                    break

                lines = section.strip().split('\n')
                analysis = analyses[i]

                for line in lines:
                    line = line.strip()
                    if line.startswith('REDUNDANT:'):
                        redundant_val = line.split(':', 1)[1].strip().upper()
                        analysis['is_redundant'] = redundant_val in ['YES', 'TRUE']
                    elif line.startswith('TYPE:'):
                        analysis['redundancy_type'] = line.split(':', 1)[1].strip().lower()
                    elif line.startswith('CONFIDENCE:'):
                        try:
                            confidence_str = line.split(':', 1)[1].strip()
                            analysis['confidence_score'] = float(confidence_str)
                        except ValueError:
                            analysis['confidence_score'] = 0.5
                    elif line.startswith('EXPLANATION:'):
                        analysis['explanation'] = line.split(':', 1)[1].strip()
                    elif line.startswith('REDUNDANT_ACTIONS:'):
                        actions_str = line.split(':', 1)[1].strip()
                        if actions_str.lower() != 'none':
                            analysis['redundant_actions'] = [action.strip() for action in actions_str.split(',')]
                    elif line.startswith('OPTIMIZED_SUGGESTION:'):
                        analysis['optimized_suggestion'] = line.split(':', 1)[1].strip()

        except Exception as e:
            print(f"Warning: Failed to parse batch redundancy response: {e}")

        return analyses

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