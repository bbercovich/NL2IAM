#!/usr/bin/env python3
"""
Conflict Checker Agent

This agent implements the Conflict Detection component as described in the paper's
Validation Pipeline. It compares new IAM policies against the Policy Inventory to
detect Allow vs Deny conflicts and overlapping permissions.

Key features:
- Rule-based engine for conflict detection
- Risk-based severity classification (High/Medium/Low)
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

from core.inventory import PolicyInventory, ConflictResult


@dataclass
class ConflictCheckResult:
    """Result of conflict check operation"""
    success: bool
    has_conflicts: bool
    conflict_results: List[ConflictResult]
    overall_risk_level: str
    summary: str
    recommendations: List[str]
    error_message: Optional[str] = None


class ConflictChecker:
    """
    LLM-Based Conflict Checker Agent for IAM Policy Validation Pipeline

    Research implementation using LLM-only analysis:
    - Requires LLM model manager for operation (no fallback to rule-based)
    - Uses LLM to intelligently detect Allow vs Deny conflicts with proper principal checking
    - Detects conflicts when ALLOW and DENY affect same resources for same/overlapping principals
    - Provides risk-based severity classification
    - Outputs detailed analysis with explanations and recommendations
    - Returns errors if LLM is unavailable (research requirement)
    """

    def __init__(self, inventory_path: Optional[str] = None, model_manager=None, rag_engine=None):
        """
        Initialize the conflict checker.

        Args:
            inventory_path: Optional path to persistent policy inventory
            model_manager: Model manager for LLM-based analysis
            rag_engine: RAG engine for AWS documentation context
        """
        self.inventory = PolicyInventory()
        self.inventory_path = inventory_path
        self.model_manager = model_manager
        self.rag_engine = rag_engine

        # Load existing policies if inventory path provided
        if inventory_path and Path(inventory_path).exists():
            self._load_inventory(inventory_path)

    def check_conflicts(
        self,
        new_policy: Dict[str, Any],
        policy_name: Optional[str] = None
    ) -> ConflictCheckResult:
        """
        Check if a new policy conflicts with existing policies using LLM analysis.

        Args:
            new_policy: The IAM policy JSON to check for conflicts
            policy_name: Optional name for the policy (for reporting)

        Returns:
            ConflictCheckResult with detailed analysis
        """
        try:
            # Validate policy structure
            if not self._is_valid_policy(new_policy):
                return ConflictCheckResult(
                    success=False,
                    has_conflicts=False,
                    conflict_results=[],
                    overall_risk_level="none",
                    summary="Invalid policy structure",
                    recommendations=[],
                    error_message="Policy must have Version and Statement fields"
                )

            # Get all existing policies
            existing_policies = self.list_policies()

            # Debug: Show how many existing policies we're checking against
            print(f"DEBUG - Conflict checker found {len(existing_policies)} existing policies to check against")
            for i, policy in enumerate(existing_policies):
                print(f"  Policy {i+1}: {policy['name']} (ID: {policy['id'][:8]}...)")

            # If no existing policies, no conflicts possible
            if not existing_policies:
                return ConflictCheckResult(
                    success=True,
                    has_conflicts=False,
                    conflict_results=[],
                    overall_risk_level="none",
                    summary="No existing policies to check against.",
                    recommendations=["✅ No conflicts detected. Policy can be safely created."]
                )

            # Use LLM-based conflict checking
            conflict_results = self._llm_check_conflicts(new_policy, existing_policies)

            # Generate summary and recommendations
            summary = self._generate_conflict_summary(conflict_results, policy_name)
            recommendations = self._generate_conflict_recommendations(conflict_results)

            # Determine overall risk level
            overall_risk_level = self._determine_overall_risk_level(conflict_results)

            # Save inventory if path provided
            if self.inventory_path:
                self._save_inventory(self.inventory_path)

            return ConflictCheckResult(
                success=True,
                has_conflicts=len(conflict_results) > 0,
                conflict_results=conflict_results,
                overall_risk_level=overall_risk_level,
                summary=summary,
                recommendations=recommendations
            )

        except Exception as e:
            return ConflictCheckResult(
                success=False,
                has_conflicts=False,
                conflict_results=[],
                overall_risk_level="none",
                summary=f"Error during conflict check: {str(e)}",
                recommendations=[],
                error_message=str(e)
            )

    def get_conflict_report(self, new_policy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a comprehensive conflict report.

        Args:
            new_policy: The policy to analyze

        Returns:
            Detailed conflict report
        """
        return self.inventory.generate_conflict_report(new_policy)

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

    def _generate_conflict_summary(
        self,
        conflict_results: List[ConflictResult],
        policy_name: Optional[str]
    ) -> str:
        """Generate a summary of conflict check results."""
        policy_ref = f"Policy '{policy_name}'" if policy_name else "Policy"

        if not conflict_results:
            return f"{policy_ref} has no conflicts with existing policies."

        high_risk = [r for r in conflict_results if r.severity == "high"]
        medium_risk = [r for r in conflict_results if r.severity == "medium"]
        low_risk = [r for r in conflict_results if r.severity == "low"]

        if high_risk:
            return f"{policy_ref} has HIGH RISK conflicts with {len(high_risk)} existing policy(ies)."
        elif medium_risk:
            return f"{policy_ref} has MEDIUM RISK conflicts with {len(medium_risk)} existing policy(ies)."
        elif low_risk:
            return f"{policy_ref} has LOW RISK conflicts with {len(low_risk)} existing policy(ies)."
        else:
            return f"{policy_ref} has potential conflicts detected."

    def _generate_conflict_recommendations(
        self,
        conflict_results: List[ConflictResult]
    ) -> List[str]:
        """Generate recommendations based on conflict analysis."""
        recommendations = []

        if not conflict_results:
            recommendations.append("✅ No conflicts detected. Policy can be safely created.")
            return recommendations

        for result in conflict_results:
            if result.severity == "high":
                recommendations.append(
                    f"🚨 HIGH PRIORITY: Review and resolve critical conflict. "
                    f"This may cause serious security issues or access problems."
                )
            elif result.severity == "medium":
                recommendations.append(
                    f"⚠️  MEDIUM PRIORITY: Verify that conflicting permissions are intentional. "
                    f"May cause unexpected access patterns."
                )
            elif result.severity == "low":
                recommendations.append(
                    f"ℹ️  LOW PRIORITY: Consider reviewing for policy consistency."
                )

            if result.conflict_type == "allow_vs_deny":
                recommendations.append(
                    f"📝 New policy grants permissions that are explicitly denied elsewhere. "
                    f"This may override intended security restrictions."
                )
            elif result.conflict_type == "deny_vs_allow":
                recommendations.append(
                    f"📝 New policy restricts permissions that are granted elsewhere. "
                    f"This may block expected functionality."
                )

        return recommendations

    def _determine_overall_risk_level(self, conflict_results: List[ConflictResult]) -> str:
        """Determine overall risk level from conflict results."""
        if not conflict_results:
            return "none"

        risk_levels = [result.severity for result in conflict_results]
        if "high" in risk_levels:
            return "high"
        elif "medium" in risk_levels:
            return "medium"
        else:
            return "low"

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

    def _llm_check_conflicts(self, new_policy: Dict[str, Any], existing_policies: List[Dict[str, Any]]) -> List:
        """
        Simple RAG-enhanced LLM conflict checking.
        """
        conflict_results = []

        if not self.model_manager:
            raise ValueError("Model manager is required for LLM-based conflict checking. This research system requires LLM analysis.")

        # Check each existing policy individually with RAG context
        for existing_policy_data in existing_policies:
            existing_policy = existing_policy_data['policy']
            existing_name = existing_policy_data['name']
            existing_id = existing_policy_data['id']

            # Get RAG context for these policies
            rag_context = self._get_rag_context(new_policy, existing_policy)

            # Create simple prompt with RAG context
            prompt = self._create_simple_conflict_prompt(new_policy, existing_policy, existing_name, rag_context)

            try:
                response = self.model_manager.generate(
                    'dsl2policy_model',
                    prompt,
                    max_new_tokens=300,
                    temperature=0.1,
                    top_p=0.9
                )

                # Parse simple response
                has_conflict, explanation = self._parse_simple_response(response)

                # Debug: Print the LLM response
                print(f"DEBUG - LLM Response for conflict check with {existing_name}:")
                print(f"Response: {response[:200]}...")
                print(f"Parsed - Conflict: {has_conflict}, Explanation: {explanation[:100]}...")

                if has_conflict:
                    from core.inventory import ConflictResult
                    conflict_result = ConflictResult(
                        has_conflict=True,
                        conflicting_policy_id=existing_id,
                        conflict_type="detected",
                        explanation=explanation,
                        conflicting_statements=[],
                        affected_actions=set(),
                        affected_resources=set(),
                        affected_principals=set(),
                        severity="medium",
                        confidence_score=0.9
                    )
                    conflict_results.append(conflict_result)

            except Exception as e:
                raise RuntimeError(f"LLM analysis failed for policy {existing_name}: {e}. LLM-based analysis is required for this research system.")

        return conflict_results

    def _get_rag_context(self, new_policy: Dict[str, Any], existing_policy: Dict[str, Any]) -> str:
        """Get RAG context for policy comparison."""
        if not self.rag_engine:
            return "No AWS documentation context available."

        try:
            # Create a query based on the policies' actions and resources
            query_parts = []

            # Extract actions from both policies
            for policy in [new_policy, existing_policy]:
                statements = policy.get('Statement', [])
                if isinstance(statements, dict):
                    statements = [statements]

                for stmt in statements:
                    actions = stmt.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    query_parts.extend(actions[:2])  # Take first 2 actions to keep query focused

            query = " ".join(query_parts[:4])  # Limit query length

            # Get RAG context
            retrieval_result = self.rag_engine.retrieve_context(query)
            return retrieval_result.augmented_prompt

        except Exception as e:
            print(f"Warning: RAG context retrieval failed: {e}")
            return "AWS documentation context unavailable."

    def _create_simple_conflict_prompt(self, new_policy: Dict[str, Any], existing_policy: Dict[str, Any], existing_name: str, rag_context: str) -> str:
        """Create a simple, clear conflict analysis prompt."""
        return f"""You are an AWS IAM policy expert. Analyze if the NEW policy conflicts with the EXISTING policy.

A conflict occurs when:
- NEW policy ALLOWS actions that EXISTING policy DENIES for the same or overlapping principals/resources
- NEW policy DENIES actions that EXISTING policy ALLOWS for the same or overlapping principals/resources

EXISTING POLICY ({existing_name}):
{json.dumps(existing_policy, indent=2)}

NEW POLICY:
{json.dumps(new_policy, indent=2)}

AWS DOCUMENTATION CONTEXT:
{rag_context}

Based on your AWS IAM expertise and the documentation context, do these policies conflict?

Answer with:
CONFLICT: YES or NO
EXPLANATION: [Clear explanation of why they do or don't conflict]
"""

    def _parse_simple_response(self, response: str) -> Tuple[bool, str]:
        """Parse the simple LLM response."""
        has_conflict = False
        explanation = "No conflicts detected"

        try:
            lines = response.strip().split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('CONFLICT:'):
                    conflict_val = line.split(':', 1)[1].strip().upper()
                    has_conflict = conflict_val in ['YES', 'TRUE']
                elif line.startswith('EXPLANATION:'):
                    explanation = line.split(':', 1)[1].strip()
        except Exception as e:
            print(f"Warning: Failed to parse response: {e}")

        return has_conflict, explanation

    def _create_conflict_analysis_prompt(self, new_policy: Dict[str, Any], existing_policy: Dict[str, Any], existing_name: str) -> str:
        """
        Create a prompt for LLM-based conflict analysis.
        """
        prompt = f"""You are an AWS IAM policy expert. Analyze if the NEW policy conflicts with the EXISTING policy.

A conflict occurs when:
1. NEW policy has ALLOW statements that grant permissions for the same resources/actions that are DENIED by EXISTING policy for the same or overlapping principals
2. NEW policy has DENY statements that deny permissions for the same resources/actions that are ALLOWED by EXISTING policy for the same or overlapping principals

Key considerations:
- Principals must overlap: specific user (arn:aws:iam::123:user/alice) overlaps with broader principals like "*" or "arn:aws:iam::123:*"
- Actions must overlap: specific actions conflict with broader actions (e.g., s3:GetObject conflicts with s3:*)
- Resources must overlap: specific resources conflict with broader resources (e.g., arn:aws:s3:::bucket/file.txt conflicts with arn:aws:s3:::bucket/*)

NEW POLICY:
{json.dumps(new_policy, indent=2)}

EXISTING POLICY ({existing_name}):
{json.dumps(existing_policy, indent=2)}

Provide your analysis in this exact format:
CONFLICT: [YES/NO]
TYPE: [allow_vs_deny/deny_vs_allow/none]
SEVERITY: [high/medium/low]
CONFIDENCE: [0.0-1.0]
EXPLANATION: [Clear explanation of the conflict or why there is no conflict]
"""
        return prompt

    def _parse_conflict_response(self, response: str) -> Dict[str, Any]:
        """
        Parse LLM response for conflict analysis.
        """
        analysis = {
            'has_conflict': False,
            'conflict_type': 'none',
            'severity': 'low',
            'confidence_score': 0.0,
            'explanation': 'No conflicts detected',
            'affected_actions': [],
            'affected_resources': [],
            'affected_principals': []
        }

        try:
            lines = response.strip().split('\n')

            for line in lines:
                line = line.strip()
                if line.startswith('CONFLICT:'):
                    conflict_val = line.split(':', 1)[1].strip().upper()
                    analysis['has_conflict'] = conflict_val in ['YES', 'TRUE']
                elif line.startswith('TYPE:'):
                    analysis['conflict_type'] = line.split(':', 1)[1].strip().lower()
                elif line.startswith('SEVERITY:'):
                    analysis['severity'] = line.split(':', 1)[1].strip().lower()
                elif line.startswith('CONFIDENCE:'):
                    try:
                        confidence_str = line.split(':', 1)[1].strip()
                        analysis['confidence_score'] = float(confidence_str)
                    except ValueError:
                        analysis['confidence_score'] = 0.5
                elif line.startswith('EXPLANATION:'):
                    analysis['explanation'] = line.split(':', 1)[1].strip()

        except Exception as e:
            print(f"Warning: Failed to parse conflict response: {e}")

        return analysis

    def _create_batch_conflict_analysis_prompt(self, new_policy: Dict[str, Any], existing_policies_batch: List[Dict[str, Any]]) -> str:
        """
        Create a prompt for batch LLM-based conflict analysis.
        """
        existing_policies_text = ""
        for i, policy_data in enumerate(existing_policies_batch):
            existing_policies_text += f"\nEXISTING POLICY {i+1} ({policy_data['name']}):\n{json.dumps(policy_data['policy'], indent=2)}\n"

        prompt = f"""You are an AWS IAM policy expert. Analyze if the NEW policy conflicts with any of the EXISTING policies.

A conflict occurs when:
1. NEW policy has ALLOW statements that grant permissions for the same resources/actions that are DENIED by EXISTING policy for the same or overlapping principals
2. NEW policy has DENY statements that deny permissions for the same resources/actions that are ALLOWED by EXISTING policy for the same or overlapping principals

Key considerations:
- Principals must overlap: specific user (arn:aws:iam::123:user/alice) overlaps with broader principals like "*" or "arn:aws:iam::123:*"
- Actions must overlap: specific actions conflict with broader actions (e.g., s3:GetObject conflicts with s3:*)
- Resources must overlap: specific resources conflict with broader resources (e.g., arn:aws:s3:::bucket/file.txt conflicts with arn:aws:s3:::bucket/*)

NEW POLICY:
{json.dumps(new_policy, indent=2)}
{existing_policies_text}

For each existing policy, provide your analysis in this exact format:
POLICY_1:
CONFLICT: [YES/NO]
TYPE: [allow_vs_deny/deny_vs_allow/none]
SEVERITY: [high/medium/low]
CONFIDENCE: [0.0-1.0]
EXPLANATION: [Clear explanation]

POLICY_2:
[Continue for each policy...]
"""
        return prompt

    def _parse_batch_conflict_response(self, response: str, policies_batch: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse LLM batch response for conflict analysis.
        """
        analyses = []

        # Initialize default analyses for all policies in batch
        for _ in policies_batch:
            analyses.append({
                'has_conflict': False,
                'conflict_type': 'none',
                'severity': 'low',
                'confidence_score': 0.0,
                'explanation': 'No conflicts detected',
                'affected_actions': [],
                'affected_resources': [],
                'affected_principals': []
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
                    if line.startswith('CONFLICT:'):
                        conflict_val = line.split(':', 1)[1].strip().upper()
                        analysis['has_conflict'] = conflict_val in ['YES', 'TRUE']
                    elif line.startswith('TYPE:'):
                        analysis['conflict_type'] = line.split(':', 1)[1].strip().lower()
                    elif line.startswith('SEVERITY:'):
                        analysis['severity'] = line.split(':', 1)[1].strip().lower()
                    elif line.startswith('CONFIDENCE:'):
                        try:
                            confidence_str = line.split(':', 1)[1].strip()
                            analysis['confidence_score'] = float(confidence_str)
                        except ValueError:
                            analysis['confidence_score'] = 0.5
                    elif line.startswith('EXPLANATION:'):
                        analysis['explanation'] = line.split(':', 1)[1].strip()

        except Exception as e:
            print(f"Warning: Failed to parse batch conflict response: {e}")

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
    """Test the conflict checker"""
    print("⚠️  Testing Conflict Checker Agent")
    print("=" * 60)

    # Initialize checker
    checker = ConflictChecker()

    # Test policies for conflict
    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:user/bob",
                "Action": "s3:DeleteObject",
                "Resource": "arn:aws:s3:::sensitive-bucket/*"
            }
        ]
    }

    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "arn:aws:iam::123456789012:user/bob",
                "Action": "s3:DeleteObject",
                "Resource": "arn:aws:s3:::sensitive-bucket/*"
            }
        ]
    }

    no_conflict_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:user/charlie",
                "Action": ["ec2:StartInstances", "ec2:StopInstances"],
                "Resource": "arn:aws:ec2:*:*:instance/*"
            }
        ]
    }

    # Add allow policy first
    print("📝 Adding baseline allow policy to inventory...")
    checker.add_existing_policy(allow_policy, "Bob Delete Access - Allow")

    # Check deny policy for conflicts
    print("\n⚠️  Checking deny policy for conflicts...")
    result = checker.check_conflicts(deny_policy, "Bob Delete Restriction - Deny")

    print(f"\n📊 CONFLICT CHECK RESULTS:")
    print(f"   Success: {result.success}")
    print(f"   Has Conflicts: {result.has_conflicts}")
    print(f"   Overall Risk Level: {result.overall_risk_level}")
    print(f"   Summary: {result.summary}")

    if result.conflict_results:
        print(f"\n📋 CONFLICT DETAILS:")
        for r in result.conflict_results:
            print(f"   - Type: {r.conflict_type}")
            print(f"   - Severity: {r.severity}")
            print(f"   - Confidence: {r.confidence_score:.2f}")
            print(f"   - Explanation: {r.explanation}")
            print(f"   - Affected Actions: {list(r.affected_actions)}")

    if result.recommendations:
        print(f"\n💡 RECOMMENDATIONS:")
        for rec in result.recommendations:
            print(f"   {rec}")

    # Check policy with no conflicts
    print("\n" + "-" * 40)
    print("\n✅ Checking policy with no conflicts...")
    no_conflict_result = checker.check_conflicts(no_conflict_policy, "Charlie EC2 Management")

    print(f"\n📊 NO CONFLICT CHECK RESULTS:")
    print(f"   Has Conflicts: {no_conflict_result.has_conflicts}")
    print(f"   Summary: {no_conflict_result.summary}")

    # Show inventory stats
    print(f"\n📈 INVENTORY STATS:")
    stats = checker.get_inventory_stats()
    print(f"   Total policies: {stats['total_policies']}")
    print(f"   Policies with allow: {stats['policies_with_allow']}")
    print(f"   Policies with deny: {stats['policies_with_deny']}")

    print(f"\n🎉 Conflict checker test completed!")


if __name__ == "__main__":
    main()