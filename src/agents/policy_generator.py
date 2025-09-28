#!/usr/bin/env python3
"""
Policy Generator Agent

Converts DSL statements to AWS IAM policies using CodeLlama model.
This is a research system focused on testing model-based generation.
"""

import json
import re
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime

from core.dsl import DSLParser
from models.model_manager import ModelManager


@dataclass
class PolicyGenerationResult:
    """Result of policy generation"""
    policy: Optional[Dict]
    dsl_statement: str
    success: bool
    confidence_score: float
    generation_time: float
    warnings: List[str]
    raw_output: str


class PolicyGenerator:
    """
    Generates AWS IAM policies from DSL statements using CodeLlama model
    """

    def __init__(self, model_manager: ModelManager):
        """
        Initialize Policy Generator with required model manager

        Args:
            model_manager: ModelManager instance with loaded models
        """
        if model_manager is None:
            raise ValueError("PolicyGenerator requires a ModelManager instance")

        self.model_manager = model_manager
        self.dsl_parser = DSLParser()

    def generate_policy(self, dsl_statement: str) -> PolicyGenerationResult:
        """
        Generate AWS IAM policy from DSL statement using CodeLlama

        Args:
            dsl_statement: DSL input like "ALLOW ACTION:s3:GetObject ON bucket:my-bucket/*"

        Returns:
            PolicyGenerationResult with generated policy and metadata
        """
        start_time = datetime.now()
        warnings = []

        # Validate model is loaded
        if not self.model_manager.is_model_loaded('dsl2policy_model'):
            return self._create_error_result(
                dsl_statement,
                "dsl2policy_model is not loaded. Load the model first.",
                start_time
            )

        # Parse DSL to validate structure (optional validation)
        try:
            parsed_dsl = self.dsl_parser.parse(dsl_statement)
            if not parsed_dsl or not parsed_dsl.statements:
                warnings.append("DSL parsing failed - proceeding with raw DSL")
        except Exception as e:
            warnings.append(f"DSL parsing error: {e} - proceeding with raw DSL")

        # Generate with CodeLlama model
        try:
            return self._generate_with_model(dsl_statement, warnings, start_time)
        except Exception as e:
            return self._create_error_result(
                dsl_statement,
                f"Model generation failed: {e}",
                start_time,
                warnings
            )

    def _generate_with_model(self, dsl_statement: str, warnings: List[str], start_time: datetime) -> PolicyGenerationResult:
        """Generate policy using CodeLlama model"""

        # Create optimized prompt based on successful test results
        prompt = f"""Convert this AWS IAM DSL statement to a valid AWS IAM policy JSON:

DSL: {dsl_statement}

Generate a complete AWS IAM policy with Version and Statement fields. Use proper AWS ARN format for resources.
Output only valid JSON without markdown formatting:"""

        # Generate using CodeLlama with proven parameters
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
            warnings.extend(validation_result['warnings'])

            generation_time = (datetime.now() - start_time).total_seconds()

            return PolicyGenerationResult(
                policy=policy_json,
                dsl_statement=dsl_statement,
                success=True,
                confidence_score=validation_result['confidence'],
                generation_time=generation_time,
                warnings=warnings,
                raw_output=raw_output
            )
        else:
            return PolicyGenerationResult(
                policy=None,
                dsl_statement=dsl_statement,
                success=False,
                confidence_score=0.0,
                generation_time=(datetime.now() - start_time).total_seconds(),
                warnings=warnings + ['Failed to extract valid JSON from model output'],
                raw_output=raw_output
            )

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

        # Find JSON object patterns
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
            warnings=warnings,
            raw_output=''
        )

    def get_model_status(self) -> Dict:
        """Get current model status"""
        return {
            'dsl2policy_model_loaded': self.model_manager.is_model_loaded('dsl2policy_model'),
            'available_models': list(self.model_manager.loaded_models.keys())
        }