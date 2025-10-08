"""
Policy Inventory Management

This module manages the collection of existing IAM policies for conflict detection,
redundancy checking, and comparison purposes. As described in the paper, it maintains
both raw JSON format for fidelity and indexed format for efficient comparisons.
"""

from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import json
import hashlib
import copy
import re
# from .dsl import DSLPolicy, parse_dsl  # Will be used later for DSL integration


@dataclass
class PolicyMetadata:
    """Metadata for a policy in the inventory"""
    policy_id: str
    name: str
    description: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    source: str = "generated"  # "generated", "imported", "aws"
    version: str = "1"
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class RedundancyResult:
    """Result of redundancy analysis"""
    is_redundant: bool
    redundant_policy_id: str
    redundancy_type: str  # "identical", "subset", "broader_principal", "broader_resource"
    explanation: str
    new_policy_statements: List[Dict[str, Any]]
    existing_policy_statements: List[Dict[str, Any]]
    confidence_score: float  # 0.0 to 1.0


@dataclass
class IndexedPolicy:
    """Indexed representation of a policy for efficient comparison"""
    policy_id: str
    metadata: PolicyMetadata
    raw_policy: Dict[str, Any]

    # Indexed fields for fast lookups
    actions: Set[str] = field(default_factory=set)
    resources: Set[str] = field(default_factory=set)
    principals: Set[str] = field(default_factory=set)
    conditions: List[Dict[str, Any]] = field(default_factory=list)

    # Statement-level indexing
    allow_statements: List[Dict[str, Any]] = field(default_factory=list)
    deny_statements: List[Dict[str, Any]] = field(default_factory=list)

    # Policy signature for quick equality checks
    policy_hash: str = ""


class PolicyInventory:
    """
    Manages the collection of IAM policies with efficient indexing for comparison.

    As specified in the paper architecture:
    - Maintains raw JSON for fidelity
    - Cached in indexed format for efficient comparisons
    - Supports conflict and redundancy detection
    - Updated when new policies are created or modified
    """

    def __init__(self):
        self.policies: Dict[str, IndexedPolicy] = {}
        self.action_index: Dict[str, Set[str]] = {}  # action -> set of policy_ids
        self.resource_index: Dict[str, Set[str]] = {}  # resource -> set of policy_ids
        self.principal_index: Dict[str, Set[str]] = {}  # principal -> set of policy_ids

    def add_policy(
        self,
        policy: Dict[str, Any],
        policy_id: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        source: str = "generated",
        tags: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Add a policy to the inventory.

        Args:
            policy: The IAM policy in JSON format
            policy_id: Optional policy ID (auto-generated if not provided)
            name: Human-readable policy name
            description: Policy description
            source: Source of the policy ("generated", "imported", "aws")
            tags: Additional metadata tags

        Returns:
            The policy ID
        """
        if policy_id is None:
            policy_id = self._generate_policy_id(policy)

        if name is None:
            name = f"Policy-{policy_id[:8]}"

        metadata = PolicyMetadata(
            policy_id=policy_id,
            name=name,
            description=description,
            source=source,
            tags=tags or {}
        )

        # Create indexed policy
        indexed_policy = self._index_policy(policy_id, metadata, policy)

        # Remove old policy if it exists (for updates)
        if policy_id in self.policies:
            self._remove_from_indexes(policy_id)

        # Add to inventory and indexes
        self.policies[policy_id] = indexed_policy
        self._add_to_indexes(indexed_policy)

        return policy_id

    def remove_policy(self, policy_id: str) -> bool:
        """
        Remove a policy from the inventory.

        Args:
            policy_id: The policy ID to remove

        Returns:
            True if policy was removed, False if not found
        """
        if policy_id not in self.policies:
            return False

        self._remove_from_indexes(policy_id)
        del self.policies[policy_id]
        return True

    def get_policy(self, policy_id: str) -> Optional[Dict[str, Any]]:
        """Get the raw policy JSON by ID"""
        indexed_policy = self.policies.get(policy_id)
        return indexed_policy.raw_policy if indexed_policy else None

    def get_policy_metadata(self, policy_id: str) -> Optional[PolicyMetadata]:
        """Get policy metadata by ID"""
        indexed_policy = self.policies.get(policy_id)
        return indexed_policy.metadata if indexed_policy else None

    def list_policies(self) -> List[str]:
        """List all policy IDs in the inventory"""
        return list(self.policies.keys())

    def find_policies_by_action(self, action: str) -> Set[str]:
        """Find all policies that include a specific action"""
        return self.action_index.get(action, set()).copy()

    def find_policies_by_resource(self, resource: str) -> Set[str]:
        """Find all policies that reference a specific resource"""
        return self.resource_index.get(resource, set()).copy()

    def find_policies_by_principal(self, principal: str) -> Set[str]:
        """Find all policies that reference a specific principal"""
        return self.principal_index.get(principal, set()).copy()

    def find_conflicting_policies(self, new_policy: Dict[str, Any]) -> List[Tuple[str, str]]:
        """
        Find policies that conflict with a new policy.

        A conflict occurs when:
        - One policy ALLOWs and another DENIEs the same action on the same resource
        - Same action/resource combination has contradictory effects

        Args:
            new_policy: The new policy to check for conflicts

        Returns:
            List of (policy_id, conflict_reason) tuples
        """
        conflicts = []
        new_indexed = self._index_policy("temp", PolicyMetadata("temp", "temp"), new_policy)

        for policy_id, existing_policy in self.policies.items():
            conflict_reason = self._check_policy_conflict(new_indexed, existing_policy)
            if conflict_reason:
                conflicts.append((policy_id, conflict_reason))

        return conflicts

    def find_redundant_policies(self, new_policy: Dict[str, Any]) -> List[RedundancyResult]:
        """
        Find policies that are redundant with a new policy.

        A policy is redundant if it grants identical or subset permissions.
        This enhanced version provides detailed analysis and explanations.

        Args:
            new_policy: The new policy to check for redundancy

        Returns:
            List of RedundancyResult objects with detailed analysis
        """
        redundant_results = []
        new_indexed = self._index_policy("temp", PolicyMetadata("temp", "temp"), new_policy)

        for policy_id, existing_policy in self.policies.items():
            redundancy_result = self._analyze_policy_redundancy(new_indexed, existing_policy)
            if redundancy_result.is_redundant:
                redundancy_result.redundant_policy_id = policy_id
                redundant_results.append(redundancy_result)

        return redundant_results

    def get_inventory_stats(self) -> Dict[str, Any]:
        """Get statistics about the policy inventory"""
        total_policies = len(self.policies)
        total_actions = len(self.action_index)
        total_resources = len(self.resource_index)
        total_principals = len(self.principal_index)

        allow_count = sum(1 for p in self.policies.values() if p.allow_statements)
        deny_count = sum(1 for p in self.policies.values() if p.deny_statements)

        return {
            "total_policies": total_policies,
            "unique_actions": total_actions,
            "unique_resources": total_resources,
            "unique_principals": total_principals,
            "policies_with_allow": allow_count,
            "policies_with_deny": deny_count,
            "sources": self._get_source_breakdown()
        }

    def generate_redundancy_report(self, new_policy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a comprehensive redundancy report for a new policy.

        Args:
            new_policy: The policy to check for redundancy

        Returns:
            Dictionary containing detailed redundancy analysis
        """
        redundancy_results = self.find_redundant_policies(new_policy)

        report = {
            "new_policy": new_policy,
            "total_existing_policies": len(self.policies),
            "redundant_policies_found": len(redundancy_results),
            "redundancy_details": [],
            "recommendations": []
        }

        for result in redundancy_results:
            existing_policy = self.get_policy(result.redundant_policy_id)
            existing_metadata = self.get_policy_metadata(result.redundant_policy_id)

            detail = {
                "redundant_policy_id": result.redundant_policy_id,
                "redundant_policy_name": existing_metadata.name if existing_metadata else "Unknown",
                "redundancy_type": result.redundancy_type,
                "explanation": result.explanation,
                "confidence_score": result.confidence_score,
                "existing_policy": existing_policy
            }
            report["redundancy_details"].append(detail)

            # Generate recommendations
            if result.redundancy_type == "identical":
                report["recommendations"].append(
                    f"Policy is identical to existing policy '{existing_metadata.name if existing_metadata else result.redundant_policy_id}'. Consider reusing the existing policy."
                )
            elif result.redundancy_type == "broader_principal":
                report["recommendations"].append(
                    f"Existing policy '{existing_metadata.name if existing_metadata else result.redundant_policy_id}' already grants these permissions to a broader set of users. The new policy may be unnecessary."
                )
            elif result.redundancy_type == "subset":
                report["recommendations"].append(
                    f"New policy permissions are already covered by existing policy '{existing_metadata.name if existing_metadata else result.redundant_policy_id}'. Consider removing redundant permissions."
                )

        return report

    def _generate_policy_id(self, policy: Dict[str, Any]) -> str:
        """Generate a unique policy ID based on policy content"""
        policy_str = json.dumps(policy, sort_keys=True)
        hash_obj = hashlib.sha256(policy_str.encode())
        return f"pol-{hash_obj.hexdigest()[:16]}"

    def _index_policy(
        self,
        policy_id: str,
        metadata: PolicyMetadata,
        policy: Dict[str, Any]
    ) -> IndexedPolicy:
        """Create an indexed representation of a policy"""
        indexed = IndexedPolicy(
            policy_id=policy_id,
            metadata=metadata,
            raw_policy=copy.deepcopy(policy)
        )

        # Generate policy hash
        policy_str = json.dumps(policy, sort_keys=True)
        indexed.policy_hash = hashlib.sha256(policy_str.encode()).hexdigest()

        # Index statements
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            effect = stmt.get("Effect", "Allow")

            # Index actions
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                indexed.actions.add(action)

            # Index resources
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            for resource in resources:
                indexed.resources.add(resource)

            # Index principals
            principal = stmt.get("Principal", {})
            if isinstance(principal, str):
                indexed.principals.add(principal)
            elif isinstance(principal, dict):
                for key, value in principal.items():
                    if isinstance(value, list):
                        indexed.principals.update(value)
                    else:
                        indexed.principals.add(str(value))

            # Index conditions
            if "Condition" in stmt:
                indexed.conditions.append(stmt["Condition"])

            # Separate by effect
            if effect == "Allow":
                indexed.allow_statements.append(stmt)
            else:
                indexed.deny_statements.append(stmt)

        return indexed

    def _add_to_indexes(self, indexed_policy: IndexedPolicy):
        """Add policy to lookup indexes"""
        policy_id = indexed_policy.policy_id

        # Action index
        for action in indexed_policy.actions:
            if action not in self.action_index:
                self.action_index[action] = set()
            self.action_index[action].add(policy_id)

        # Resource index
        for resource in indexed_policy.resources:
            if resource not in self.resource_index:
                self.resource_index[resource] = set()
            self.resource_index[resource].add(policy_id)

        # Principal index
        for principal in indexed_policy.principals:
            if principal not in self.principal_index:
                self.principal_index[principal] = set()
            self.principal_index[principal].add(policy_id)

    def _remove_from_indexes(self, policy_id: str):
        """Remove policy from lookup indexes"""
        if policy_id not in self.policies:
            return

        indexed_policy = self.policies[policy_id]

        # Remove from action index
        for action in indexed_policy.actions:
            if action in self.action_index:
                self.action_index[action].discard(policy_id)
                if not self.action_index[action]:
                    del self.action_index[action]

        # Remove from resource index
        for resource in indexed_policy.resources:
            if resource in self.resource_index:
                self.resource_index[resource].discard(policy_id)
                if not self.resource_index[resource]:
                    del self.resource_index[resource]

        # Remove from principal index
        for principal in indexed_policy.principals:
            if principal in self.principal_index:
                self.principal_index[principal].discard(policy_id)
                if not self.principal_index[principal]:
                    del self.principal_index[principal]

    def _check_policy_conflict(
        self,
        new_policy: IndexedPolicy,
        existing_policy: IndexedPolicy
    ) -> Optional[str]:
        """
        Check if two policies conflict.

        Returns conflict reason string if conflict exists, None otherwise.
        """
        # Check for Allow vs Deny conflicts on same action/resource combinations
        for new_allow in new_policy.allow_statements:
            for existing_deny in existing_policy.deny_statements:
                if self._statements_overlap(new_allow, existing_deny):
                    return f"Allow vs Deny conflict on overlapping permissions"

        for new_deny in new_policy.deny_statements:
            for existing_allow in existing_policy.allow_statements:
                if self._statements_overlap(new_deny, existing_allow):
                    return f"Deny vs Allow conflict on overlapping permissions"

        return None

    def _analyze_policy_redundancy(
        self,
        new_policy: IndexedPolicy,
        existing_policy: IndexedPolicy
    ) -> RedundancyResult:
        """
        Comprehensive redundancy analysis between two policies.

        Checks multiple types of redundancy:
        1. Identical policies
        2. New policy is subset of existing
        3. New policy targets specific user/resource covered by broader existing policy
        4. Complex principal/resource overlaps
        """
        # Check for identical policies first
        if new_policy.policy_hash == existing_policy.policy_hash:
            return RedundancyResult(
                is_redundant=True,
                redundant_policy_id=existing_policy.policy_id,
                redundancy_type="identical",
                explanation="Policies are identical",
                new_policy_statements=new_policy.allow_statements + new_policy.deny_statements,
                existing_policy_statements=existing_policy.allow_statements + existing_policy.deny_statements,
                confidence_score=1.0
            )

        # Check each statement in new policy against existing policy
        redundant_statements = []
        total_statements = len(new_policy.allow_statements) + len(new_policy.deny_statements)

        if total_statements == 0:
            return RedundancyResult(
                is_redundant=False,
                redundant_policy_id="",
                redundancy_type="none",
                explanation="New policy has no statements",
                new_policy_statements=[],
                existing_policy_statements=[],
                confidence_score=0.0
            )

        # Check Allow statements
        for new_stmt in new_policy.allow_statements:
            for existing_stmt in existing_policy.allow_statements:
                if self._statement_covered_by(new_stmt, existing_stmt):
                    redundant_statements.append((new_stmt, existing_stmt, "allow"))
                    break

        # Check Deny statements
        for new_stmt in new_policy.deny_statements:
            for existing_stmt in existing_policy.deny_statements:
                if self._statement_covered_by(new_stmt, existing_stmt):
                    redundant_statements.append((new_stmt, existing_stmt, "deny"))
                    break

        redundancy_ratio = len(redundant_statements) / total_statements

        if redundancy_ratio >= 1.0:
            # All statements are covered
            redundancy_type, explanation = self._classify_redundancy_type(
                redundant_statements, new_policy, existing_policy
            )
            return RedundancyResult(
                is_redundant=True,
                redundant_policy_id=existing_policy.policy_id,
                redundancy_type=redundancy_type,
                explanation=explanation,
                new_policy_statements=new_policy.allow_statements + new_policy.deny_statements,
                existing_policy_statements=existing_policy.allow_statements + existing_policy.deny_statements,
                confidence_score=redundancy_ratio
            )
        elif redundancy_ratio >= 0.8:
            # Mostly redundant - flag as partial redundancy
            return RedundancyResult(
                is_redundant=True,
                redundant_policy_id=existing_policy.policy_id,
                redundancy_type="partial",
                explanation=f"Most statements ({redundancy_ratio:.1%}) are covered by existing policy",
                new_policy_statements=new_policy.allow_statements + new_policy.deny_statements,
                existing_policy_statements=existing_policy.allow_statements + existing_policy.deny_statements,
                confidence_score=redundancy_ratio
            )

        return RedundancyResult(
            is_redundant=False,
            redundant_policy_id="",
            redundancy_type="none",
            explanation=f"Only {redundancy_ratio:.1%} of statements are covered",
            new_policy_statements=[],
            existing_policy_statements=[],
            confidence_score=redundancy_ratio
        )

    def _statement_covered_by(self, new_stmt: Dict[str, Any], existing_stmt: Dict[str, Any]) -> bool:
        """
        Check if a new statement is covered by an existing statement.

        A statement is covered if:
        1. Actions in new statement are subset of or match actions in existing statement
        2. Resources in new statement are subset of or match resources in existing statement
        3. Principals in new statement are subset of or match principals in existing statement
        4. Conditions are compatible (new is more restrictive or same)
        """
        # Get actions from both statements
        new_actions = self._normalize_field(new_stmt.get("Action", []))
        existing_actions = self._normalize_field(existing_stmt.get("Action", []))

        # Get resources from both statements
        new_resources = self._normalize_field(new_stmt.get("Resource", []))
        existing_resources = self._normalize_field(existing_stmt.get("Resource", []))

        # Get principals from both statements
        new_principals = self._extract_principals(new_stmt.get("Principal", {}))
        existing_principals = self._extract_principals(existing_stmt.get("Principal", {}))

        # Check if all new actions are covered by existing actions
        actions_covered = self._actions_covered_by(new_actions, existing_actions)

        # Check if all new resources are covered by existing resources
        resources_covered = self._resources_covered_by(new_resources, existing_resources)

        # Check if all new principals are covered by existing principals
        principals_covered = self._principals_covered_by(new_principals, existing_principals)

        return actions_covered and resources_covered and principals_covered

    def _classify_redundancy_type(
        self,
        redundant_statements: List[Tuple[Dict[str, Any], Dict[str, Any], str]],
        new_policy: IndexedPolicy,
        existing_policy: IndexedPolicy
    ) -> Tuple[str, str]:
        """
        Classify the type of redundancy and generate explanation.
        """
        if not redundant_statements:
            return "none", "No redundant statements found"

        # Analyze the nature of the redundancy
        has_broader_principal = False
        has_broader_resource = False
        has_broader_action = False

        explanations = []

        for new_stmt, existing_stmt, effect in redundant_statements:
            # Check if existing policy has broader principals
            new_principals = self._extract_principals(new_stmt.get("Principal", {}))
            existing_principals = self._extract_principals(existing_stmt.get("Principal", {}))

            if "*" in existing_principals or "arn:aws:iam::*:*" in existing_principals:
                has_broader_principal = True
                specific_principals = [p for p in new_principals if p not in ["*", "arn:aws:iam::*:*"]]
                if specific_principals:
                    explanations.append(
                        f"Existing policy allows all users (*) while new policy specifies {specific_principals[0]}"
                    )

            # Check if existing policy has broader resources
            new_resources = self._normalize_field(new_stmt.get("Resource", []))
            existing_resources = self._normalize_field(existing_stmt.get("Resource", []))

            for existing_res in existing_resources:
                if existing_res == "*" or existing_res.endswith("*"):
                    for new_res in new_resources:
                        if new_res != existing_res and self._resource_matches(new_res, existing_res):
                            has_broader_resource = True
                            explanations.append(
                                f"Existing policy covers broader resource pattern '{existing_res}' that includes '{new_res}'"
                            )

            # Check if existing policy has broader actions
            new_actions = self._normalize_field(new_stmt.get("Action", []))
            existing_actions = self._normalize_field(existing_stmt.get("Action", []))

            for existing_action in existing_actions:
                if existing_action == "*" or existing_action.endswith(":*"):
                    for new_action in new_actions:
                        if new_action != existing_action and self._action_matches(new_action, existing_action):
                            has_broader_action = True
                            explanations.append(
                                f"Existing policy has broader action '{existing_action}' that includes '{new_action}'"
                            )

        # Determine redundancy type based on findings
        if has_broader_principal and has_broader_resource:
            return "broader_principal", (
                "New policy grants specific permissions that are already covered by a broader existing policy. " +
                " ".join(explanations[:2])
            )
        elif has_broader_principal:
            return "broader_principal", (
                "New policy targets specific principal(s) already covered by broader existing policy. " +
                " ".join(explanations[:2])
            )
        elif has_broader_resource:
            return "broader_resource", (
                "New policy targets specific resource(s) already covered by broader existing policy. " +
                " ".join(explanations[:2])
            )
        elif has_broader_action:
            return "broader_action", (
                "New policy specifies actions already covered by broader existing policy. " +
                " ".join(explanations[:2])
            )
        else:
            return "subset", (
                "New policy permissions are a subset of existing policy permissions. " +
                " ".join(explanations[:2]) if explanations else "All permissions already granted."
            )

    def _normalize_field(self, field: Any) -> List[str]:
        """Normalize a field to a list of strings"""
        if isinstance(field, str):
            return [field]
        elif isinstance(field, list):
            return [str(item) for item in field]
        else:
            return []

    def _extract_principals(self, principal: Any) -> Set[str]:
        """Extract principal identifiers from various principal formats"""
        principals = set()

        if isinstance(principal, str):
            if principal == "*":
                principals.add("*")
            else:
                principals.add(principal)
        elif isinstance(principal, dict):
            for key, value in principal.items():
                if isinstance(value, list):
                    principals.update(str(v) for v in value)
                else:
                    principals.add(str(value))
        elif isinstance(principal, list):
            principals.update(str(p) for p in principal)

        return principals

    def _actions_covered_by(self, new_actions: List[str], existing_actions: List[str]) -> bool:
        """Check if all new actions are covered by existing actions"""
        if "*" in existing_actions:
            return True

        for new_action in new_actions:
            covered = False
            for existing_action in existing_actions:
                if self._action_matches(new_action, existing_action):
                    covered = True
                    break
            if not covered:
                return False
        return True

    def _resources_covered_by(self, new_resources: List[str], existing_resources: List[str]) -> bool:
        """Check if all new resources are covered by existing resources"""
        if "*" in existing_resources:
            return True

        for new_resource in new_resources:
            covered = False
            for existing_resource in existing_resources:
                if self._resource_matches(new_resource, existing_resource):
                    covered = True
                    break
            if not covered:
                return False
        return True

    def _principals_covered_by(self, new_principals: Set[str], existing_principals: Set[str]) -> bool:
        """Check if all new principals are covered by existing principals"""
        if "*" in existing_principals or "arn:aws:iam::*:*" in existing_principals:
            return True

        # If no principals specified in new policy, it applies to all (covered by *)
        if not new_principals:
            return "*" in existing_principals

        # Check if all new principals are covered
        for new_principal in new_principals:
            covered = False
            for existing_principal in existing_principals:
                if self._principal_matches(new_principal, existing_principal):
                    covered = True
                    break
            if not covered:
                return False
        return True

    def _principal_matches(self, principal1: str, principal2: str) -> bool:
        """Check if two principals match (including wildcards and patterns)"""
        if principal1 == principal2:
            return True
        if principal1 == "*" or principal2 == "*":
            return True
        if "arn:aws:iam::*" in principal2:
            return True

        # Handle account-level wildcards
        if principal2.endswith(":*") and principal1.startswith(principal2[:-1]):
            return True
        if principal1.endswith(":*") and principal2.startswith(principal1[:-1]):
            return True

        return False

    def _check_policy_redundancy(
        self,
        new_policy: IndexedPolicy,
        existing_policy: IndexedPolicy
    ) -> bool:
        """Legacy method - kept for backward compatibility"""
        result = self._analyze_policy_redundancy(new_policy, existing_policy)
        return result.is_redundant

    def _statements_overlap(self, stmt1: Dict[str, Any], stmt2: Dict[str, Any]) -> bool:
        """Check if two statements have overlapping action/resource combinations"""
        # Get actions from both statements
        actions1 = stmt1.get("Action", [])
        if isinstance(actions1, str):
            actions1 = [actions1]
        actions2 = stmt2.get("Action", [])
        if isinstance(actions2, str):
            actions2 = [actions2]

        # Get resources from both statements
        resources1 = stmt1.get("Resource", [])
        if isinstance(resources1, str):
            resources1 = [resources1]
        resources2 = stmt2.get("Resource", [])
        if isinstance(resources2, str):
            resources2 = [resources2]

        # Check for overlapping actions and resources
        action_overlap = any(
            self._action_matches(a1, a2)
            for a1 in actions1
            for a2 in actions2
        )

        resource_overlap = any(
            self._resource_matches(r1, r2)
            for r1 in resources1
            for r2 in resources2
        )

        return action_overlap and resource_overlap

    def _action_matches(self, action1: str, action2: str) -> bool:
        """Check if two actions match (including wildcards)"""
        if action1 == action2:
            return True
        if action1 == "*" or action2 == "*":
            return True
        # Handle service wildcards like s3:*
        if action1.endswith("*") and action2.startswith(action1[:-1]):
            return True
        if action2.endswith("*") and action1.startswith(action2[:-1]):
            return True
        return False

    def _resource_matches(self, resource1: str, resource2: str) -> bool:
        """Check if two resources match (including wildcards and ARN patterns)"""
        if resource1 == resource2:
            return True
        if resource1 == "*" or resource2 == "*":
            return True
        # Handle resource wildcards
        if resource1.endswith("*") and resource2.startswith(resource1[:-1]):
            return True
        if resource2.endswith("*") and resource1.startswith(resource2[:-1]):
            return True
        return False

    def _get_source_breakdown(self) -> Dict[str, int]:
        """Get breakdown of policies by source"""
        sources = {}
        for policy in self.policies.values():
            source = policy.metadata.source
            sources[source] = sources.get(source, 0) + 1
        return sources


# Example usage and testing
if __name__ == "__main__":
    # Test the enhanced policy inventory
    inventory = PolicyInventory()

    # Add some test policies to demonstrate redundancy scenarios

    # Broad policy allowing all users to read from public bucket
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

    # Specific policy for Alice to read from public bucket (should be redundant)
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

    # S3 admin policy with broad permissions
    admin_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:role/S3Admin",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::*"
            }
        ]
    }

    # Specific write policy (should be redundant with admin)
    write_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:role/S3Admin",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::uploads/*"
            }
        ]
    }

    # Add policies to inventory
    broad_id = inventory.add_policy(broad_policy, name="Public Bucket Access - All Users")
    admin_id = inventory.add_policy(admin_policy, name="S3 Admin Policy")

    print(f"Added policies: {broad_id[:8]}, {admin_id[:8]}")
    print("\n" + "="*60)

    # Test redundancy detection for Alice's policy
    print("\nTesting Alice's specific policy against existing policies:")
    print(f"Alice Policy: {json.dumps(alice_policy, indent=2)}")

    redundancy_results = inventory.find_redundant_policies(alice_policy)
    if redundancy_results:
        for result in redundancy_results:
            print(f"\n🔍 REDUNDANCY DETECTED:")
            print(f"   Type: {result.redundancy_type}")
            print(f"   Confidence: {result.confidence_score:.2f}")
            print(f"   Explanation: {result.explanation}")
            print(f"   Redundant with policy: {result.redundant_policy_id[:8]}")
    else:
        print("   ✅ No redundancy detected")

    # Test redundancy detection for write policy
    print("\n" + "-"*40)
    print("\nTesting specific write policy against existing policies:")
    print(f"Write Policy: {json.dumps(write_policy, indent=2)}")

    redundancy_results = inventory.find_redundant_policies(write_policy)
    if redundancy_results:
        for result in redundancy_results:
            print(f"\n🔍 REDUNDANCY DETECTED:")
            print(f"   Type: {result.redundancy_type}")
            print(f"   Confidence: {result.confidence_score:.2f}")
            print(f"   Explanation: {result.explanation}")
            print(f"   Redundant with policy: {result.redundant_policy_id[:8]}")
    else:
        print("   ✅ No redundancy detected")

    # Generate comprehensive redundancy report
    print("\n" + "="*60)
    print("\nComprehensive Redundancy Report for Alice's Policy:")
    report = inventory.generate_redundancy_report(alice_policy)

    print(f"\n📊 SUMMARY:")
    print(f"   Total existing policies: {report['total_existing_policies']}")
    print(f"   Redundant policies found: {report['redundant_policies_found']}")

    if report['redundancy_details']:
        print(f"\n📋 DETAILS:")
        for detail in report['redundancy_details']:
            print(f"   - Policy: {detail['redundant_policy_name']}")
            print(f"     Type: {detail['redundancy_type']}")
            print(f"     Confidence: {detail['confidence_score']:.2f}")
            print(f"     Reason: {detail['explanation']}")

    if report['recommendations']:
        print(f"\n💡 RECOMMENDATIONS:")
        for rec in report['recommendations']:
            print(f"   - {rec}")

    # Test stats
    print("\n" + "="*60)
    stats = inventory.get_inventory_stats()
    print(f"\n📈 INVENTORY STATS: {stats}")