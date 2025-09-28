#!/usr/bin/env python3
"""
Policy Generator Agent

Converts DSL statements to AWS IAM policies using LLM and RAG.
Based on successful CodeLlama testing, this agent generates proper IAM JSON policies.
"""

import json
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

from core.dsl import RegexDSLParser
from models.model_manager import ModelManager


@dataclass
class PolicyGenerationResult:
    """Result of policy generation"""
    policy: Optional[Dict]
    dsl_statement: str
    success: bool
    confidence_score: float
    generation_time: float
    method_used: str  # 'model', 'rule_based', 'hybrid'
    warnings: List[str]
    raw_output: str


class PolicyGenerator:
    """
    Generates AWS IAM policies from DSL statements using LLM + RAG approach
    """

    def __init__(self, model_manager: Optional[ModelManager] = None):
        self.model_manager = model_manager
        self.dsl_parser = RegexDSLParser()

        # RAG placeholder - would connect to AWS docs knowledge base
        self.rag_enabled = False

        # Policy templates for rule-based fallback
        self.policy_templates = {
            's3': {
                'GetObject': {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Action': 's3:GetObject',
                        'Resource': 'arn:aws:s3:::BUCKET/*'
                    }]
                },
                'PutObject': {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Action': 's3:PutObject',
                        'Resource': 'arn:aws:s3:::BUCKET/*'
                    }]
                }
            },
            'ec2': {
                'StartInstances': {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Action': 'ec2:StartInstances',
                        'Resource': '*'
                    }]
                }
            }
        }

    def generate_policy(self, dsl_statement: str, use_rag: bool = True) -> PolicyGenerationResult:
        """
        Generate AWS IAM policy from DSL statement

        Args:
            dsl_statement: DSL input like "ALLOW ACTION:s3:GetObject ON bucket:my-bucket/*"
            use_rag: Whether to enhance with RAG (placeholder for now)

        Returns:
            PolicyGenerationResult with generated policy and metadata
        """
        start_time = datetime.now()
        warnings = []

        # Step 1: Parse DSL to understand structure
        try:
            parsed_dsl = self.dsl_parser.parse(dsl_statement)
            if not parsed_dsl or not parsed_dsl.statements:
                return self._create_error_result(dsl_statement, "Failed to parse DSL", start_time)
        except Exception as e:
            return self._create_error_result(dsl_statement, f"DSL parsing error: {e}", start_time)

        # Step 2: Try model-based generation first (CodeLlama)
        if self.model_manager and self.model_manager.is_model_loaded('dsl2policy_model'):
            try:
                result = self._generate_with_model(dsl_statement, parsed_dsl, start_time)
                if result.success:
                    return result
                else:
                    warnings.extend(result.warnings)
            except Exception as e:
                warnings.append(f"Model generation failed: {e}")

        # Step 3: Fallback to rule-based generation
        try:
            return self._generate_rule_based(dsl_statement, parsed_dsl, warnings, start_time)
        except Exception as e:
            return self._create_error_result(
                dsl_statement,
                f"All generation methods failed. Last error: {e}",
                start_time,
                warnings
            )

    def _generate_with_model(self, dsl_statement: str, parsed_dsl, start_time: datetime) -> PolicyGenerationResult:
        """Generate policy using CodeLlama model"""

        # Create enhanced prompt based on test results
        prompt = f"""Convert this AWS IAM DSL statement to a valid AWS IAM policy JSON:

DSL: {dsl_statement}

Generate a complete AWS IAM policy with Version and Statement fields. Use proper AWS ARN format for resources.
Output only valid JSON without markdown formatting:"""

        try:
            # Generate using the model with parameters that worked in testing
            raw_output = self.model_manager.generate(
                'dsl2policy_model',
                prompt,
                max_new_tokens=300,
                temperature=0.1,
                top_p=0.9
            )

            # Extract JSON from the model output
            policy_json = self._extract_json_from_output(raw_output)

            if policy_json:
                # Validate the generated policy
                validation_result = self._validate_policy(policy_json)

                generation_time = (datetime.now() - start_time).total_seconds()

                return PolicyGenerationResult(
                    policy=policy_json,
                    dsl_statement=dsl_statement,
                    success=True,
                    confidence_score=validation_result['confidence'],
                    generation_time=generation_time,
                    method_used='model',
                    warnings=validation_result['warnings'],
                    raw_output=raw_output
                )
            else:
                return PolicyGenerationResult(
                    policy=None,
                    dsl_statement=dsl_statement,
                    success=False,
                    confidence_score=0.0,
                    generation_time=(datetime.now() - start_time).total_seconds(),
                    method_used='model',
                    warnings=['Failed to extract valid JSON from model output'],
                    raw_output=raw_output
                )

        except Exception as e:
            return PolicyGenerationResult(
                policy=None,
                dsl_statement=dsl_statement,
                success=False,
                confidence_score=0.0,
                generation_time=(datetime.now() - start_time).total_seconds(),
                method_used='model',
                warnings=[f'Model generation error: {e}'],
                raw_output=''
            )

    def _generate_rule_based(self, dsl_statement: str, parsed_dsl, warnings: List[str], start_time: datetime) -> PolicyGenerationResult:
        """Generate policy using rule-based templates"""

        statement = parsed_dsl.statements[0]  # Use first statement

        # Extract service and action
        service = statement.action.service
        action_name = statement.action.action

        # Get template
        if service in self.policy_templates and action_name in self.policy_templates[service]:
            template = self.policy_templates[service][action_name].copy()

            # Customize based on DSL
            policy_statement = template['Statement'][0]

            # Set effect
            policy_statement['Effect'] = statement.effect.title()  # 'Allow' or 'Deny'

            # Set resource
            if statement.resource.resource_type == 'bucket':
                # S3 bucket resource
                bucket_name = statement.resource.identifier
                if bucket_name.endswith('/*'):
                    bucket_name = bucket_name[:-2]
                policy_statement['Resource'] = f'arn:aws:s3:::{bucket_name}/*'
            elif statement.resource.resource_type == 'instance':
                # EC2 instance resource
                if statement.resource.identifier == '*':
                    policy_statement['Resource'] = 'arn:aws:ec2:*:*:instance/*'
                else:
                    policy_statement['Resource'] = f'arn:aws:ec2:*:*:instance/{statement.resource.identifier}'

            # Add conditions if present
            if statement.conditions:
                policy_statement['Condition'] = {}
                for condition in statement.conditions:
                    if condition.operator.lower() == 'in':
                        policy_statement['Condition']['StringEquals'] = {
                            condition.attribute: condition.values
                        }

            generation_time = (datetime.now() - start_time).total_seconds()
            warnings.append("Used rule-based generation (model not available)")

            return PolicyGenerationResult(
                policy=template,
                dsl_statement=dsl_statement,
                success=True,
                confidence_score=0.8,  # High confidence for rule-based
                generation_time=generation_time,
                method_used='rule_based',
                warnings=warnings,
                raw_output=json.dumps(template, indent=2)
            )
        else:
            # No template available
            warnings.append(f"No template available for {service}:{action_name}")
            return self._create_error_result(dsl_statement, "No generation method available", start_time, warnings)

    def _extract_json_from_output(self, raw_output: str) -> Optional[Dict]:
        """Extract JSON policy from model output"""

        # Remove markdown formatting
        text = raw_output.strip()
        if text.startswith('```json'):
            text = text[7:]
        if text.startswith('```'):
            text = text[3:]
        if text.endswith('```'):
            text = text[:-3]

        # Find JSON object
        json_patterns = [
            r'\{[^{}]*"Version"[^{}]*\}',  # Simple JSON
            r'\{.*?"Version".*?\}',       # JSON with nested objects
        ]

        for pattern in json_patterns:
            matches = re.findall(pattern, text, re.DOTALL)
            for match in matches:
                try:
                    # Attempt to parse as JSON
                    policy = json.loads(match)
                    if isinstance(policy, dict) and 'Version' in policy:
                        return policy
                except json.JSONDecodeError:
                    continue

        # Try parsing entire text as JSON
        try:
            policy = json.loads(text)
            if isinstance(policy, dict):
                return policy
        except json.JSONDecodeError:
            pass

        return None

    def _validate_policy(self, policy: Dict) -> Dict:
        """Basic validation of generated policy"""
        warnings = []
        confidence = 1.0

        # Check required fields
        if 'Version' not in policy:
            warnings.append("Missing Version field")
            confidence -= 0.3

        if 'Statement' not in policy:
            warnings.append("Missing Statement field")
            confidence -= 0.5
        else:
            statements = policy['Statement']
            if not isinstance(statements, list):
                statements = [statements]

            for i, stmt in enumerate(statements):
                if 'Effect' not in stmt:
                    warnings.append(f"Statement {i}: Missing Effect")
                    confidence -= 0.2

                if 'Action' not in stmt:
                    warnings.append(f"Statement {i}: Missing Action")
                    confidence -= 0.2

                if 'Resource' not in stmt:
                    warnings.append(f"Statement {i}: Missing Resource")
                    confidence -= 0.2

        return {
            'confidence': max(0.0, confidence),
            'warnings': warnings
        }

    def _create_error_result(self, dsl_statement: str, error_msg: str, start_time: datetime, warnings: List[str] = None) -> PolicyGenerationResult:
        """Create error result"""
        if warnings is None:
            warnings = []
        warnings.append(error_msg)

        return PolicyGenerationResult(
            policy=None,
            dsl_statement=dsl_statement,
            success=False,
            confidence_score=0.0,
            generation_time=(datetime.now() - start_time).total_seconds(),
            method_used='none',
            warnings=warnings,
            raw_output=''
        )

    def enable_rag(self, rag_engine):
        """Enable RAG enhancement (placeholder for future implementation)"""
        self.rag_enabled = True
        # Would store reference to RAG engine here
        pass

    def get_generation_stats(self) -> Dict:
        """Get statistics about policy generation"""
        # Placeholder for tracking generation metrics
        return {
            'total_generated': 0,
            'model_success_rate': 0.0,
            'rule_based_fallbacks': 0,
            'average_generation_time': 0.0
        }