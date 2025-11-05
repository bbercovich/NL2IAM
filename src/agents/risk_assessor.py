#!/usr/bin/env python3
"""
Risk Assessor Agent

Provides detailed explanations of IAM policies and performs risk assessments
before policies are stored in the inventory.
"""

import json
import re
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from models.model_manager import ModelManager
from rag.rag_engine import RAGEngine


class RiskLevel(Enum):
    """Risk levels for IAM policies"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RiskFactor:
    """Individual risk factor in a policy"""
    factor_type: str
    description: str
    risk_level: RiskLevel
    affected_resources: List[str]
    mitigation_suggestions: List[str]


@dataclass
class PolicyExplanation:
    """Human-readable explanation of what a policy does"""
    summary: str
    detailed_breakdown: List[str]
    principal_explanation: str
    resource_explanation: str
    conditions_explanation: Optional[str] = None


@dataclass
class RiskAssessmentResult:
    """Result of policy risk assessment and explanation"""
    policy_explanation: PolicyExplanation
    overall_risk_level: RiskLevel
    risk_score: float  # 0-100 scale
    risk_factors: List[RiskFactor]
    security_recommendations: List[str]
    compliance_notes: List[str]
    success: bool
    error_message: Optional[str] = None


class RiskAssessor:
    """
    AWS IAM Policy Risk Assessment and Explanation Agent

    Provides:
    - Human-readable policy explanations
    - Risk assessment and scoring
    - Security recommendations
    - Compliance considerations
    """

    def __init__(self, model_manager: ModelManager, rag_engine: Optional[RAGEngine] = None):
        """
        Initialize Risk Assessor with required model manager and optional RAG engine

        Args:
            model_manager: ModelManager instance with loaded models
            rag_engine: Optional RAG engine for context retrieval
        """
        if model_manager is None:
            raise ValueError("RiskAssessor requires a ModelManager instance")

        self.model_manager = model_manager
        self.rag_engine = rag_engine

        # Risk assessment criteria
        self.high_risk_actions = {
            "iam:*", "sts:AssumeRole", "iam:PassRole", "iam:CreateRole", "iam:AttachRolePolicy",
            "iam:PutRolePolicy", "iam:DeleteRole", "iam:CreateUser", "iam:DeleteUser",
            "s3:DeleteBucket", "ec2:TerminateInstances", "rds:DeleteDBInstance",
            "lambda:InvokeFunction", "kms:Decrypt", "kms:GenerateDataKey"
        }

        self.critical_risk_actions = {
            "iam:CreateAccessKey", "iam:DeleteAccessKey", "sts:GetFederationToken",
            "iam:CreateLoginProfile", "iam:ChangePassword", "iam:UpdateLoginProfile",
            "organizations:*", "account:*"
        }

        self.sensitive_resources = {
            "arn:aws:s3:::*/*", "arn:aws:iam::*:role/*", "arn:aws:kms:*:*:key/*",
            "arn:aws:secretsmanager:*:*:secret:*", "arn:aws:ssm:*:*:parameter/*"
        }

    def assess_policy(self, policy: Dict[str, Any], policy_name: str = None) -> RiskAssessmentResult:
        """
        Perform comprehensive risk assessment and explanation of an IAM policy

        Args:
            policy: The IAM policy to assess
            policy_name: Optional name for the policy

        Returns:
            RiskAssessmentResult with explanation and risk assessment
        """
        try:
            # Step 1: Generate human-readable explanation
            explanation = self._generate_policy_explanation(policy, policy_name)

            # Step 2: Analyze risk factors
            risk_factors = self._analyze_risk_factors(policy)

            # Step 3: Calculate overall risk score and level
            risk_score, risk_level = self._calculate_risk_score(risk_factors, policy)

            # Step 4: Generate security recommendations
            recommendations = self._generate_security_recommendations(policy, risk_factors)

            # Step 5: Check compliance considerations
            compliance_notes = self._check_compliance_considerations(policy, risk_factors)

            return RiskAssessmentResult(
                policy_explanation=explanation,
                overall_risk_level=risk_level,
                risk_score=risk_score,
                risk_factors=risk_factors,
                security_recommendations=recommendations,
                compliance_notes=compliance_notes,
                success=True
            )

        except Exception as e:
            return RiskAssessmentResult(
                policy_explanation=PolicyExplanation("Error generating explanation", [], "", ""),
                overall_risk_level=RiskLevel.MEDIUM,
                risk_score=50.0,
                risk_factors=[],
                security_recommendations=[],
                compliance_notes=[],
                success=False,
                error_message=str(e)
            )

    def _generate_policy_explanation(self, policy: Dict[str, Any], policy_name: str = None) -> PolicyExplanation:
        """Generate human-readable explanation of the policy using LLM"""

        # Create explanation prompt
        explanation_prompt = self._create_explanation_prompt(policy, policy_name)

        try:
            # Get LLM explanation
            raw_output = self.model_manager.generate(
                'dsl2policy_model',
                explanation_prompt,
                max_new_tokens=400,
                temperature=0.3,
                top_p=0.9
            )

            # Parse the LLM output into structured explanation
            return self._parse_explanation_output(raw_output, policy)

        except Exception as e:
            # Fallback to basic explanation if LLM fails
            return self._generate_basic_explanation(policy)

    def _create_explanation_prompt(self, policy: Dict[str, Any], policy_name: str = None) -> str:
        """Create prompt for policy explanation"""

        # Add RAG context if available
        rag_context = ""
        if self.rag_engine:
            try:
                # Query for AWS documentation about the actions in the policy
                actions = self._extract_actions_from_policy(policy)
                query = f"AWS IAM policy actions: {' '.join(actions[:5])}"  # Limit query length
                retrieval_result = self.rag_engine.retrieve_context(query)
                if retrieval_result and retrieval_result.augmented_prompt:
                    rag_context = f"\n\nRelevant AWS Documentation:\n{retrieval_result.augmented_prompt}"
            except Exception:
                pass

        policy_json = json.dumps(policy, indent=2)
        name_context = f" named '{policy_name}'" if policy_name else ""

        return f"""You are an AWS IAM security expert. Explain the following IAM policy{name_context} in simple, human-readable terms.

IAM POLICY:
{policy_json}

TASK: Provide a clear explanation that covers:
1. SUMMARY: One sentence describing what this policy does overall
2. DETAILED_BREAKDOWN: List of specific permissions granted (one per line)
3. PRINCIPAL_EXPLANATION: Who this policy applies to
4. RESOURCE_EXPLANATION: What AWS resources are affected
5. CONDITIONS_EXPLANATION: Any conditions or restrictions (if present)

Format your response as:
SUMMARY: [one sentence summary]
DETAILED_BREAKDOWN:
- [permission 1]
- [permission 2]
- [etc.]
PRINCIPAL_EXPLANATION: [who this applies to]
RESOURCE_EXPLANATION: [what resources are affected]
CONDITIONS_EXPLANATION: [conditions if any, or "None"]

Be specific about AWS services, actions, and resources. Avoid technical jargon.{rag_context}"""

    def _parse_explanation_output(self, raw_output: str, policy: Dict[str, Any]) -> PolicyExplanation:
        """Parse LLM explanation output into structured format"""

        try:
            # Extract sections from the output
            summary_match = re.search(r'SUMMARY:\s*(.*?)(?:\n|$)', raw_output, re.IGNORECASE)
            summary = summary_match.group(1).strip() if summary_match else "Policy grants AWS permissions"

            # Extract detailed breakdown
            breakdown_section = re.search(r'DETAILED_BREAKDOWN:\s*(.*?)(?=PRINCIPAL_EXPLANATION|$)',
                                        raw_output, re.IGNORECASE | re.DOTALL)
            if breakdown_section:
                breakdown_text = breakdown_section.group(1).strip()
                detailed_breakdown = [line.strip().lstrip('- ') for line in breakdown_text.split('\n')
                                    if line.strip() and line.strip().startswith('-')]
            else:
                detailed_breakdown = ["Grants specified AWS permissions"]

            # Extract principal explanation
            principal_match = re.search(r'PRINCIPAL_EXPLANATION:\s*(.*?)(?=RESOURCE_EXPLANATION|$)',
                                      raw_output, re.IGNORECASE)
            principal_explanation = principal_match.group(1).strip() if principal_match else "Applies to specified principals"

            # Extract resource explanation
            resource_match = re.search(r'RESOURCE_EXPLANATION:\s*(.*?)(?=CONDITIONS_EXPLANATION|$)',
                                     raw_output, re.IGNORECASE)
            resource_explanation = resource_match.group(1).strip() if resource_match else "Affects specified AWS resources"

            # Extract conditions explanation
            conditions_match = re.search(r'CONDITIONS_EXPLANATION:\s*(.*?)(?:\n|$)',
                                       raw_output, re.IGNORECASE)
            conditions_explanation = None
            if conditions_match:
                conditions_text = conditions_match.group(1).strip()
                if conditions_text.lower() not in ['none', 'no conditions', 'n/a']:
                    conditions_explanation = conditions_text

            return PolicyExplanation(
                summary=summary,
                detailed_breakdown=detailed_breakdown,
                principal_explanation=principal_explanation,
                resource_explanation=resource_explanation,
                conditions_explanation=conditions_explanation
            )

        except Exception:
            # Fallback if parsing fails
            return self._generate_basic_explanation(policy)

    def _generate_basic_explanation(self, policy: Dict[str, Any]) -> PolicyExplanation:
        """Generate basic explanation without LLM"""
        actions = self._extract_actions_from_policy(policy)
        resources = self._extract_resources_from_policy(policy)

        summary = f"Policy grants {len(actions)} AWS permission(s) on {len(resources)} resource(s)"
        detailed_breakdown = [f"Allows {action}" for action in actions[:10]]  # Limit to 10
        principal_explanation = "Applies to the entity this policy is attached to"
        resource_explanation = f"Affects {len(resources)} AWS resource(s)"

        return PolicyExplanation(
            summary=summary,
            detailed_breakdown=detailed_breakdown,
            principal_explanation=principal_explanation,
            resource_explanation=resource_explanation
        )

    def _analyze_risk_factors(self, policy: Dict[str, Any]) -> List[RiskFactor]:
        """Analyze policy for risk factors"""
        risk_factors = []

        # Check for wildcard permissions
        if self._has_wildcard_actions(policy):
            risk_factors.append(RiskFactor(
                factor_type="Overly Broad Permissions",
                description="Policy uses wildcard (*) actions which grant extensive permissions",
                risk_level=RiskLevel.HIGH,
                affected_resources=self._extract_resources_from_policy(policy),
                mitigation_suggestions=[
                    "Replace wildcard actions with specific required actions",
                    "Follow principle of least privilege"
                ]
            ))

        # Check for high-risk actions
        actions = self._extract_actions_from_policy(policy)
        high_risk_found = set(actions) & self.high_risk_actions
        critical_risk_found = set(actions) & self.critical_risk_actions

        if critical_risk_found:
            risk_factors.append(RiskFactor(
                factor_type="Critical Risk Actions",
                description=f"Policy includes critical risk actions: {', '.join(critical_risk_found)}",
                risk_level=RiskLevel.CRITICAL,
                affected_resources=self._extract_resources_from_policy(policy),
                mitigation_suggestions=[
                    "Review necessity of critical actions",
                    "Implement additional conditions and constraints",
                    "Consider using temporary credentials"
                ]
            ))

        if high_risk_found:
            risk_factors.append(RiskFactor(
                factor_type="High Risk Actions",
                description=f"Policy includes high-risk actions: {', '.join(high_risk_found)}",
                risk_level=RiskLevel.HIGH,
                affected_resources=self._extract_resources_from_policy(policy),
                mitigation_suggestions=[
                    "Add conditions to limit when actions can be performed",
                    "Restrict to specific resources where possible"
                ]
            ))

        # Check for wildcard resources
        if self._has_wildcard_resources(policy):
            risk_factors.append(RiskFactor(
                factor_type="Wildcard Resources",
                description="Policy grants access to all resources (*)",
                risk_level=RiskLevel.HIGH,
                affected_resources=["*"],
                mitigation_suggestions=[
                    "Specify exact resource ARNs instead of wildcards",
                    "Limit scope to required resources only"
                ]
            ))

        # Check for missing conditions
        if not self._has_conditions(policy):
            risk_factors.append(RiskFactor(
                factor_type="No Access Conditions",
                description="Policy lacks conditions to limit when/how it can be used",
                risk_level=RiskLevel.MEDIUM,
                affected_resources=self._extract_resources_from_policy(policy),
                mitigation_suggestions=[
                    "Add IP address restrictions",
                    "Add time-based conditions",
                    "Add MFA requirements for sensitive actions"
                ]
            ))

        # Check for public access
        if self._allows_public_access(policy):
            risk_factors.append(RiskFactor(
                factor_type="Public Access",
                description="Policy may allow public access via Principal: '*'",
                risk_level=RiskLevel.CRITICAL,
                affected_resources=self._extract_resources_from_policy(policy),
                mitigation_suggestions=[
                    "Remove public access unless absolutely necessary",
                    "Use specific principals instead of wildcards",
                    "Add strict conditions for public access"
                ]
            ))

        return risk_factors

    def _calculate_risk_score(self, risk_factors: List[RiskFactor], policy: Dict[str, Any]) -> tuple[float, RiskLevel]:
        """Calculate overall risk score and level"""
        base_score = 20.0  # Base score for any policy

        # Add points based on risk factors
        for factor in risk_factors:
            if factor.risk_level == RiskLevel.CRITICAL:
                base_score += 30.0
            elif factor.risk_level == RiskLevel.HIGH:
                base_score += 20.0
            elif factor.risk_level == RiskLevel.MEDIUM:
                base_score += 10.0
            else:  # LOW
                base_score += 5.0

        # Cap at 100
        risk_score = min(base_score, 100.0)

        # Determine risk level
        if risk_score >= 80:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 60:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 40:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

        return risk_score, risk_level

    def _generate_security_recommendations(self, policy: Dict[str, Any], risk_factors: List[RiskFactor]) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []

        # Collect all mitigation suggestions from risk factors
        for factor in risk_factors:
            recommendations.extend(factor.mitigation_suggestions)

        # Add general recommendations
        recommendations.extend([
            "Regularly review and audit this policy's usage",
            "Monitor access logs for unusual activity",
            "Consider implementing AWS CloudTrail for auditing"
        ])

        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)

        return unique_recommendations[:10]  # Limit to top 10 recommendations

    def _check_compliance_considerations(self, policy: Dict[str, Any], risk_factors: List[RiskFactor]) -> List[str]:
        """Check for compliance considerations"""
        compliance_notes = []

        # Check for data access patterns
        actions = self._extract_actions_from_policy(policy)

        if any("s3:" in action for action in actions):
            compliance_notes.append("Data access policy - consider GDPR/CCPA compliance requirements")

        if any("logs:" in action for action in actions):
            compliance_notes.append("Log access policy - ensure compliance with data retention policies")

        if any("kms:" in action for action in actions):
            compliance_notes.append("Encryption key access - verify compliance with data protection regulations")

        # Check for administrative access
        if any(factor.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH] for factor in risk_factors):
            compliance_notes.append("High-risk policy - may require additional approval processes")

        return compliance_notes

    # Helper methods for policy analysis
    def _extract_actions_from_policy(self, policy: Dict[str, Any]) -> List[str]:
        """Extract all actions from policy statements"""
        actions = []
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            statement_actions = statement.get("Action", [])
            if isinstance(statement_actions, str):
                statement_actions = [statement_actions]
            actions.extend(statement_actions)

        return actions

    def _extract_resources_from_policy(self, policy: Dict[str, Any]) -> List[str]:
        """Extract all resources from policy statements"""
        resources = []
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            statement_resources = statement.get("Resource", [])
            if isinstance(statement_resources, str):
                statement_resources = [statement_resources]
            resources.extend(statement_resources)

        return resources if resources else ["*"]

    def _has_wildcard_actions(self, policy: Dict[str, Any]) -> bool:
        """Check if policy has wildcard actions"""
        actions = self._extract_actions_from_policy(policy)
        return "*" in actions or any("*" in action for action in actions)

    def _has_wildcard_resources(self, policy: Dict[str, Any]) -> bool:
        """Check if policy has wildcard resources"""
        resources = self._extract_resources_from_policy(policy)
        return "*" in resources

    def _has_conditions(self, policy: Dict[str, Any]) -> bool:
        """Check if policy has any conditions"""
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        return any("Condition" in statement for statement in statements)

    def _allows_public_access(self, policy: Dict[str, Any]) -> bool:
        """Check if policy allows public access"""
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            principal = statement.get("Principal")
            if principal == "*" or (isinstance(principal, dict) and "*" in principal.get("AWS", [])):
                return True

        return False

    def get_assessment_stats(self) -> Dict[str, Any]:
        """Get statistics about risk assessment capabilities"""
        return {
            "assessor_name": "RiskAssessor",
            "high_risk_actions_count": len(self.high_risk_actions),
            "critical_risk_actions_count": len(self.critical_risk_actions),
            "has_rag_support": self.rag_engine is not None,
            "risk_levels": [level.value for level in RiskLevel]
        }