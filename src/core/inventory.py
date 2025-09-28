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

    def find_redundant_policies(self, new_policy: Dict[str, Any]) -> List[str]:
        """
        Find policies that are redundant with a new policy.

        A policy is redundant if it grants identical or subset permissions.

        Args:
            new_policy: The new policy to check for redundancy

        Returns:
            List of policy IDs that are redundant
        """
        redundant = []
        new_indexed = self._index_policy("temp", PolicyMetadata("temp", "temp"), new_policy)

        for policy_id, existing_policy in self.policies.items():
            if self._check_policy_redundancy(new_indexed, existing_policy):
                redundant.append(policy_id)

        return redundant

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

    def _check_policy_redundancy(
        self,
        new_policy: IndexedPolicy,
        existing_policy: IndexedPolicy
    ) -> bool:
        """Check if new policy is redundant with existing policy"""
        # Simple redundancy check: if all actions and resources are subsets
        new_actions = new_policy.actions
        new_resources = new_policy.resources
        existing_actions = existing_policy.actions
        existing_resources = existing_policy.resources

        # Check if new policy permissions are subset of existing
        return (new_actions.issubset(existing_actions) and
                new_resources.issubset(existing_resources))

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
    # Test the policy inventory
    inventory = PolicyInventory()

    # Add some test policies
    policy1 = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ]
    }

    policy2 = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/secret/*"
            }
        ]
    }

    policy3 = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/public/*"
            }
        ]
    }

    # Add policies
    id1 = inventory.add_policy(policy1, name="S3 Read/Write Policy")
    id2 = inventory.add_policy(policy2, name="S3 Secret Deny Policy")
    id3 = inventory.add_policy(policy3, name="S3 Public Read Policy")

    print(f"Added policies: {id1[:8]}, {id2[:8]}, {id3[:8]}")

    # Test conflict detection
    conflicts = inventory.find_conflicting_policies(policy2)
    print(f"Conflicts for policy2: {conflicts}")

    # Test redundancy detection
    redundant = inventory.find_redundant_policies(policy3)
    print(f"Redundant policies for policy3: {redundant}")

    # Test stats
    stats = inventory.get_inventory_stats()
    print(f"Inventory stats: {stats}")

    # Test action lookup
    s3_policies = inventory.find_policies_by_action("s3:GetObject")
    print(f"Policies with s3:GetObject: {s3_policies}")