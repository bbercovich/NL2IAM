#!/usr/bin/env python3
"""
Policy Validator Agent

Validates AWS IAM policies for correct JSON structure and IAM-specific requirements.
If validation fails, it works with the LLM to attempt to fix the policy.
"""

import json
import re
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from datetime import datetime

from models.model_manager import ModelManager
from rag.rag_engine import RAGEngine


@dataclass
class ValidationResult:
    """Result of policy validation"""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    fixed_policy: Optional[Dict] = None
    attempt_count: int = 1
    fix_successful: bool = False


class PolicyValidator:
    """
    AWS IAM Policy Validator Agent

    Validates IAM policies for:
    - Valid JSON structure
    - Required IAM policy fields
    - Valid AWS service actions
    - Proper resource ARN format
    - Condition structure compliance
    """

    def __init__(self, model_manager: ModelManager, rag_engine: Optional[RAGEngine] = None):
        """
        Initialize Policy Validator with required model manager and optional RAG engine

        Args:
            model_manager: ModelManager instance with loaded models
            rag_engine: Optional RAG engine for context retrieval
        """
        if model_manager is None:
            raise ValueError("PolicyValidator requires a ModelManager instance")

        self.model_manager = model_manager
        self.rag_engine = rag_engine

        # IAM policy validation rules
        self.required_fields = {"Version", "Statement"}
        self.valid_versions = {"2012-10-17", "2008-10-17"}
        self.valid_effects = {"Allow", "Deny"}
        self.statement_required_fields = {"Effect", "Action"}
        self.optional_statement_fields = {"Resource", "Principal", "Condition", "Sid"}

        # Common AWS service patterns for validation
        self.aws_service_pattern = re.compile(r'^[a-z0-9-]+:[a-zA-Z0-9*]+$')
        self.arn_pattern = re.compile(r'^arn:aws[a-z0-9-]*:[a-z0-9-]*:[a-z0-9-]*:[0-9]*:.+$')

    def validate_policy(self, policy: Any, max_fix_attempts: int = 2) -> ValidationResult:
        """
        Validate an IAM policy and attempt to fix it if invalid

        Args:
            policy: The policy to validate (should be a dict)
            max_fix_attempts: Maximum number of fix attempts (default: 2)

        Returns:
            ValidationResult with validation status and any fixes
        """
        # First, validate the current policy
        result = self._validate_policy_structure(policy)

        if result.is_valid:
            return result

        # If invalid and we have fix attempts left, try to fix it
        if max_fix_attempts > 0:
            return self._attempt_policy_fix(policy, result, max_fix_attempts)

        return result

    def _validate_policy_structure(self, policy: Any) -> ValidationResult:
        """
        Validate the basic structure of an IAM policy

        Args:
            policy: The policy to validate

        Returns:
            ValidationResult with validation details
        """
        errors = []
        warnings = []

        # Check if policy is a dictionary
        if not isinstance(policy, dict):
            errors.append(f"Policy must be a JSON object, got {type(policy).__name__}")
            return ValidationResult(is_valid=False, errors=errors, warnings=warnings)

        # Check required top-level fields
        missing_fields = self.required_fields - set(policy.keys())
        if missing_fields:
            errors.append(f"Missing required fields: {', '.join(missing_fields)}")

        # Validate Version field
        if "Version" in policy:
            if policy["Version"] not in self.valid_versions:
                errors.append(f"Invalid Version '{policy['Version']}'. Must be one of: {', '.join(self.valid_versions)}")

        # Validate Statement field
        if "Statement" in policy:
            statement_errors, statement_warnings = self._validate_statements(policy["Statement"])
            errors.extend(statement_errors)
            warnings.extend(statement_warnings)

        # Check for unexpected top-level fields
        expected_fields = {"Version", "Statement", "Id"}
        unexpected_fields = set(policy.keys()) - expected_fields
        if unexpected_fields:
            warnings.append(f"Unexpected top-level fields: {', '.join(unexpected_fields)}")

        is_valid = len(errors) == 0
        return ValidationResult(is_valid=is_valid, errors=errors, warnings=warnings)

    def _validate_statements(self, statements: Any) -> tuple[List[str], List[str]]:
        """
        Validate the Statement field of an IAM policy

        Args:
            statements: The Statement field value

        Returns:
            Tuple of (errors, warnings)
        """
        errors = []
        warnings = []

        # Statement can be a single object or an array
        if isinstance(statements, dict):
            statements = [statements]
        elif not isinstance(statements, list):
            errors.append(f"Statement must be an object or array, got {type(statements).__name__}")
            return errors, warnings

        for i, statement in enumerate(statements):
            if not isinstance(statement, dict):
                errors.append(f"Statement[{i}] must be an object, got {type(statement).__name__}")
                continue

            # Check required statement fields
            missing_fields = self.statement_required_fields - set(statement.keys())
            if missing_fields:
                errors.append(f"Statement[{i}] missing required fields: {', '.join(missing_fields)}")

            # Validate Effect
            if "Effect" in statement:
                if statement["Effect"] not in self.valid_effects:
                    errors.append(f"Statement[{i}] has invalid Effect '{statement['Effect']}'. Must be 'Allow' or 'Deny'")

            # Validate Action
            if "Action" in statement:
                action_errors, action_warnings = self._validate_actions(statement["Action"], i)
                errors.extend(action_errors)
                warnings.extend(action_warnings)

            # Validate Resource (if present)
            if "Resource" in statement:
                resource_errors, resource_warnings = self._validate_resources(statement["Resource"], i)
                errors.extend(resource_errors)
                warnings.extend(resource_warnings)

            # Validate Principal (if present)
            if "Principal" in statement:
                principal_errors, principal_warnings = self._validate_principal(statement["Principal"], i)
                errors.extend(principal_errors)
                warnings.extend(principal_warnings)

            # Validate Condition (if present)
            if "Condition" in statement:
                condition_errors, condition_warnings = self._validate_condition(statement["Condition"], i)
                errors.extend(condition_errors)
                warnings.extend(condition_warnings)

            # Check for unexpected statement fields
            expected_statement_fields = self.statement_required_fields | self.optional_statement_fields
            unexpected_fields = set(statement.keys()) - expected_statement_fields
            if unexpected_fields:
                warnings.append(f"Statement[{i}] has unexpected fields: {', '.join(unexpected_fields)}")

        return errors, warnings

    def _validate_actions(self, actions: Any, statement_index: int) -> tuple[List[str], List[str]]:
        """Validate Action field"""
        errors = []
        warnings = []

        if isinstance(actions, str):
            actions = [actions]
        elif not isinstance(actions, list):
            errors.append(f"Statement[{statement_index}] Action must be string or array")
            return errors, warnings

        for action in actions:
            if not isinstance(action, str):
                errors.append(f"Statement[{statement_index}] Action values must be strings")
                continue

            # Basic format validation for AWS actions
            if action != "*" and not self.aws_service_pattern.match(action):
                warnings.append(f"Statement[{statement_index}] Action '{action}' may not be a valid AWS action format")

        return errors, warnings

    def _validate_resources(self, resources: Any, statement_index: int) -> tuple[List[str], List[str]]:
        """Validate Resource field"""
        errors = []
        warnings = []

        if isinstance(resources, str):
            resources = [resources]
        elif not isinstance(resources, list):
            errors.append(f"Statement[{statement_index}] Resource must be string or array")
            return errors, warnings

        for resource in resources:
            if not isinstance(resource, str):
                errors.append(f"Statement[{statement_index}] Resource values must be strings")
                continue

            # Basic ARN format validation
            if resource != "*" and not self.arn_pattern.match(resource):
                warnings.append(f"Statement[{statement_index}] Resource '{resource}' may not be a valid ARN format")

        return errors, warnings

    def _validate_principal(self, principal: Any, statement_index: int) -> tuple[List[str], List[str]]:
        """Validate Principal field"""
        errors = []
        warnings = []

        if isinstance(principal, str):
            if principal not in ["*"]:
                warnings.append(f"Statement[{statement_index}] Principal string should typically be '*' for public access")
        elif isinstance(principal, dict):
            # Principal object should have valid AWS principal types
            valid_principal_keys = {"AWS", "Service", "Federated", "CanonicalUser"}
            for key in principal.keys():
                if key not in valid_principal_keys:
                    warnings.append(f"Statement[{statement_index}] Principal has unexpected key '{key}'")
        else:
            errors.append(f"Statement[{statement_index}] Principal must be string or object")

        return errors, warnings

    def _validate_condition(self, condition: Any, statement_index: int) -> tuple[List[str], List[str]]:
        """Validate Condition field"""
        errors = []
        warnings = []

        if not isinstance(condition, dict):
            errors.append(f"Statement[{statement_index}] Condition must be an object")
            return errors, warnings

        # Basic structure validation - conditions should have operator -> key -> value structure
        for operator, conditions in condition.items():
            if not isinstance(conditions, dict):
                errors.append(f"Statement[{statement_index}] Condition operator '{operator}' must have object value")

        return errors, warnings

    def _attempt_policy_fix(self, original_policy: Any, validation_result: ValidationResult, max_attempts: int) -> ValidationResult:
        """
        Attempt to fix an invalid policy using the LLM

        Args:
            original_policy: The original invalid policy
            validation_result: The validation result with errors
            max_attempts: Maximum number of fix attempts

        Returns:
            ValidationResult with fix attempt results
        """
        current_policy = original_policy
        attempt_count = 0

        while attempt_count < max_attempts:
            attempt_count += 1

            # Create a fix prompt for the LLM
            fix_prompt = self._create_fix_prompt(current_policy, validation_result.errors, validation_result.warnings)

            try:
                # Get LLM response
                raw_output = self.model_manager.generate(
                    'dsl2policy_model',  # Use the same model as policy generation
                    fix_prompt,
                    max_new_tokens=500,
                    temperature=0.1,  # Low temperature for consistency
                    top_p=0.9
                )

                # Extract JSON from the output
                fixed_policy = self._extract_json_from_output(raw_output)

                if fixed_policy is None:
                    validation_result.errors.append(f"Fix attempt {attempt_count}: Could not extract valid JSON from LLM response")
                    continue

                # Validate the fixed policy
                new_validation = self._validate_policy_structure(fixed_policy)

                if new_validation.is_valid:
                    # Success! Return the fixed policy
                    return ValidationResult(
                        is_valid=True,
                        errors=[],
                        warnings=new_validation.warnings,
                        fixed_policy=fixed_policy,
                        attempt_count=attempt_count,
                        fix_successful=True
                    )
                else:
                    # Still invalid, try again with new errors
                    current_policy = fixed_policy
                    validation_result = new_validation

            except Exception as e:
                validation_result.errors.append(f"Fix attempt {attempt_count}: Error during LLM generation: {str(e)}")

        # All fix attempts failed
        return ValidationResult(
            is_valid=False,
            errors=validation_result.errors + [f"Failed to fix policy after {max_attempts} attempts"],
            warnings=validation_result.warnings,
            fixed_policy=None,
            attempt_count=attempt_count,
            fix_successful=False
        )

    def _create_fix_prompt(self, policy: Any, errors: List[str], warnings: List[str]) -> str:
        """
        Create a prompt for the LLM to fix policy validation errors

        Args:
            policy: The invalid policy
            errors: List of validation errors
            warnings: List of validation warnings

        Returns:
            Formatted prompt for the LLM
        """
        # Add RAG context if available
        rag_context = ""
        if self.rag_engine:
            try:
                query = f"AWS IAM policy validation errors: {' '.join(errors[:3])}"  # Limit query length
                retrieval_result = self.rag_engine.retrieve_context(query)
                if retrieval_result and retrieval_result.augmented_prompt:
                    rag_context = f"\n\nRelevant AWS Documentation:\n{retrieval_result.augmented_prompt}"
            except Exception:
                pass  # Continue without RAG context if retrieval fails

        policy_json = json.dumps(policy, indent=2) if isinstance(policy, dict) else str(policy)

        return f"""You are an AWS IAM policy validation expert. Fix the following invalid IAM policy.

INVALID POLICY:
{policy_json}

VALIDATION ERRORS:
{chr(10).join(f"- {error}" for error in errors)}

VALIDATION WARNINGS:
{chr(10).join(f"- {warning}" for warning in warnings)}

TASK: Generate a corrected AWS IAM policy that fixes all validation errors while preserving the original intent.

REQUIREMENTS:
- Output ONLY valid JSON for the corrected IAM policy
- Fix all validation errors listed above
- Preserve the original policy's intent and permissions
- Use AWS IAM policy best practices
- Ensure proper JSON structure and formatting{rag_context}

CORRECTED POLICY:"""

    def _extract_json_from_output(self, raw_output: str) -> Optional[Dict]:
        """
        Extract JSON policy from LLM output

        Args:
            raw_output: Raw text output from LLM

        Returns:
            Parsed JSON policy or None if extraction fails
        """
        # Try to find JSON in the output
        json_patterns = [
            r'\{.*\}',  # Basic JSON object pattern
            r'```json\s*(\{.*?\})\s*```',  # JSON in code blocks
            r'```\s*(\{.*?\})\s*```',  # JSON in generic code blocks
        ]

        for pattern in json_patterns:
            matches = re.findall(pattern, raw_output, re.DOTALL)
            for match in matches:
                try:
                    # Clean up the match
                    json_str = match.strip()
                    if not json_str.startswith('{'):
                        continue

                    # Try to parse as JSON
                    policy = json.loads(json_str)
                    if isinstance(policy, dict):
                        return policy
                except (json.JSONDecodeError, ValueError):
                    continue

        # If no patterns worked, try parsing the entire output as JSON
        try:
            policy = json.loads(raw_output.strip())
            if isinstance(policy, dict):
                return policy
        except (json.JSONDecodeError, ValueError):
            pass

        return None

    def get_validation_stats(self) -> Dict[str, Any]:
        """Get statistics about policy validation"""
        return {
            "validator_name": "PolicyValidator",
            "supported_versions": list(self.valid_versions),
            "required_fields": list(self.required_fields),
            "statement_required_fields": list(self.statement_required_fields),
            "has_rag_support": self.rag_engine is not None
        }