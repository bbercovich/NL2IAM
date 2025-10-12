#!/usr/bin/env python3
"""
Policy Generator Agent

Converts DSL statements to AWS IAM policies
"""

import json
import re
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime

from core.dsl import DSLParser
from models.model_manager import ModelManager
from rag.rag_engine import RAGEngine


@dataclass
class PolicyGenerationResult:
    """Result of policy generation"""
    policy: Optional[Dict]
    dsl_statement: str
    success: bool
    generation_time: float
    warnings: List[str]
    raw_output: str
    retrieved_contexts: Optional[List[Dict]] = None
    retrieval_metadata: Optional[Dict] = None


class PolicyGenerator:
    """
    Generates AWS IAM policies from DSL statements
    """

    def __init__(self, model_manager: ModelManager, rag_engine: Optional[RAGEngine] = None):
        """
        Initialize Policy Generator with required model manager and optional RAG engine

        Args:
            model_manager: ModelManager instance with loaded models
            rag_engine: Optional RAG engine for context retrieval
        """
        if model_manager is None:
            raise ValueError("PolicyGenerator requires a ModelManager instance")

        self.model_manager = model_manager
        self.dsl_parser = DSLParser()
        self.rag_engine = rag_engine
        self._rag_enabled = rag_engine is not None

    def generate_policy(self, dsl_statement: str) -> PolicyGenerationResult:
        """
        Generate AWS IAM policy from DSL statement

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
        """Generate policy using CodeLlama model with optional RAG enhancement"""

        retrieved_contexts = None
        retrieval_metadata = None

        # Use RAG engine if available and enabled to get relevant context
        if self.rag_engine and self._rag_enabled:
            try:
                retrieval_result = self.rag_engine.retrieve_context(dsl_statement)
                prompt = retrieval_result.augmented_prompt
                retrieved_contexts = retrieval_result.retrieved_contexts
                retrieval_metadata = retrieval_result.retrieval_metadata

                if retrieved_contexts:
                    warnings.append(f"Used {len(retrieved_contexts)} context chunks from AWS documentation")
                else:
                    warnings.append("No relevant context found in AWS documentation")

            except Exception as e:
                warnings.append(f"RAG context retrieval failed: {e}")
                prompt = self._create_fallback_prompt(dsl_statement)
        else:
            # Create basic prompt without RAG
            prompt = self._create_fallback_prompt(dsl_statement)

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
                generation_time=generation_time,
                warnings=warnings,
                raw_output=raw_output,
                retrieved_contexts=retrieved_contexts,
                retrieval_metadata=retrieval_metadata
            )
        else:
            return PolicyGenerationResult(
                policy=None,
                dsl_statement=dsl_statement,
                success=False,
                generation_time=(datetime.now() - start_time).total_seconds(),
                warnings=warnings + ['Failed to extract valid JSON from model output'],
                raw_output=raw_output,
                retrieved_contexts=retrieved_contexts,
                retrieval_metadata=retrieval_metadata
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

        # Remove truncation indicators
        text = text.replace('...', '')

        # Try parsing entire text as JSON first (most common case)
        try:
            policy = json.loads(text)
            if isinstance(policy, dict) and 'Version' in policy:
                return policy
        except json.JSONDecodeError:
            pass

        # Find complete JSON objects with proper bracket matching
        brace_count = 0
        start_pos = -1

        for i, char in enumerate(text):
            if char == '{':
                if brace_count == 0:
                    start_pos = i
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0 and start_pos != -1:
                    # Found complete JSON object
                    json_text = text[start_pos:i+1]
                    try:
                        policy = json.loads(json_text)
                        if isinstance(policy, dict) and 'Version' in policy:
                            return policy
                    except json.JSONDecodeError:
                        continue

        # Fallback: regex patterns for partial matches
        json_patterns = [
            r'\{[^{}]*"Version"[^{}]*"Statement"[^{}]*\}',  # Simple pattern
            r'\{.*?"Version".*?"Statement".*?\}',           # More flexible
        ]

        for pattern in json_patterns:
            matches = re.findall(pattern, text, re.DOTALL)
            for match in matches:
                try:
                    policy = json.loads(match)
                    if isinstance(policy, dict) and 'Version' in policy:
                        return policy
                except json.JSONDecodeError:
                    continue

        return None

    def _create_fallback_prompt(self, dsl_statement: str) -> str:
        """Create fallback prompt when RAG is not available or fails"""
        return f"""Convert this AWS IAM DSL statement to a valid AWS IAM policy JSON:

DSL: {dsl_statement}

Generate a complete AWS IAM policy with Version and Statement fields. Use proper AWS ARN format for resources.
Output only valid JSON without markdown formatting:"""

    def _validate_policy(self, policy: Dict) -> Dict:
        """Basic validation of generated policy"""
        warnings = []

        # Check required fields
        if 'Version' not in policy:
            warnings.append("Missing Version field")

        if 'Statement' not in policy:
            warnings.append("Missing Statement field")
        else:
            statements = policy['Statement']
            if not isinstance(statements, list):
                statements = [statements]

            for i, stmt in enumerate(statements):
                if 'Effect' not in stmt:
                    warnings.append(f"Statement {i}: Missing Effect")

                if 'Action' not in stmt:
                    warnings.append(f"Statement {i}: Missing Action")

                if 'Resource' not in stmt:
                    warnings.append(f"Statement {i}: Missing Resource")

        return {
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
            generation_time=(datetime.now() - start_time).total_seconds(),
            warnings=warnings,
            raw_output=''
        )

    def set_rag_enabled(self, enabled: bool) -> None:
        """Enable or disable RAG for policy generation"""
        self._rag_enabled = enabled and self.rag_engine is not None

    def is_rag_enabled(self) -> bool:
        """Check if RAG is currently enabled"""
        return self._rag_enabled and self.rag_engine is not None

    def get_model_status(self) -> Dict:
        """Get current model status"""
        return {
            'dsl2policy_model_loaded': self.model_manager.is_model_loaded('dsl2policy_model'),
            'available_models': list(self.model_manager.loaded_models.keys()),
            'rag_enabled': self.is_rag_enabled(),
            'rag_available': self.rag_engine is not None
        }