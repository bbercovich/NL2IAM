"""
Translator Agent: Natural Language to DSL Conversion

This agent converts coarse-grained natural language requests into the intermediate
Domain-Specific Language (DSL) format. As specified in the paper, it uses a
lightweight local LLM optimized for translation.

Input: Natural language description of desired access
Output: Intermediate DSL (internal use, but logged for debugging)
"""

import re
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import logging


@dataclass
class TranslationResult:
    """Result of natural language to DSL translation"""
    original_text: str
    dsl_output: str
    confidence: float
    reasoning: Optional[str] = None
    model_used: Optional[str] = None


class NLToTranslator:
    """
    Translator Agent for converting natural language to DSL.

    This agent handles the first stage of the pipeline: converting user requests
    like "Allow Alice to read files from the public bucket" into structured DSL
    like "ALLOW ACTION:s3:GetObject ON bucket:public-bucket/*"
    """

    def __init__(self, model_manager=None):
        self.model_manager = model_manager
        self.logger = logging.getLogger(__name__)

        # Pattern-based fallback rules for when model is not available
        self.fallback_patterns = self._build_fallback_patterns()

        # Template mappings for common patterns
        self.service_mappings = {
            's3': ['s3', 'bucket', 'object', 'file', 'storage'],
            'ec2': ['ec2', 'instance', 'server', 'vm', 'compute'],
            'iam': ['iam', 'user', 'role', 'group', 'identity'],
            'lambda': ['lambda', 'function', 'serverless'],
            'rds': ['rds', 'database', 'db'],
            'ssm': ['ssm', 'parameter', 'session']
        }

        self.action_mappings = {
            # S3 actions
            'read': ['s3:GetObject', 's3:GetObjectVersion'],
            'write': ['s3:PutObject', 's3:PutObjectAcl'],
            'delete': ['s3:DeleteObject', 's3:DeleteObjectVersion'],
            'list': ['s3:ListBucket', 's3:ListBucketVersions'],

            # EC2 actions
            'start': ['ec2:StartInstances'],
            'stop': ['ec2:StopInstances'],
            'terminate': ['ec2:TerminateInstances'],
            'describe': ['ec2:DescribeInstances'],
            'run': ['ec2:RunInstances'],

            # IAM actions
            'create': ['iam:CreateUser', 'iam:CreateRole'],
            'get': ['iam:GetUser', 'iam:GetRole'],
            'update': ['iam:UpdateUser', 'iam:UpdateRole']
        }

    def translate(self, natural_language: str, **kwargs) -> TranslationResult:
        """
        Translate natural language to DSL.

        Args:
            natural_language: The user's natural language request
            **kwargs: Additional parameters for translation

        Returns:
            TranslationResult with the DSL output and metadata
        """
        # Clean and preprocess the input
        cleaned_input = self._preprocess_input(natural_language)

        # Try model-based translation if available
        if self.model_manager and self.model_manager.is_model_loaded("nl2dsl_model"):
            return self._model_based_translation(cleaned_input, **kwargs)
        else:
            # Fall back to pattern-based translation
            self.logger.warning("Model not available, using pattern-based translation")
            return self._pattern_based_translation(cleaned_input, **kwargs)

    def _preprocess_input(self, text: str) -> str:
        """Preprocess the natural language input"""
        # Remove extra whitespace
        text = ' '.join(text.split())

        # Convert to lowercase for processing (we'll maintain original case in output)
        text = text.lower()

        # Remove punctuation at the end
        text = text.rstrip('.,!?;')

        return text

    def _model_based_translation(self, text: str, **kwargs) -> TranslationResult:
        """Use the loaded model for translation"""
        try:
            # Construct prompt for the model
            prompt = self._build_model_prompt(text)

            # Generate DSL using the model
            dsl_output = self.model_manager.generate(
                "nl2dsl_model",
                prompt,
                max_length=kwargs.get('max_length', 256),
                temperature=kwargs.get('temperature', 0.3),
                do_sample=kwargs.get('do_sample', True)
            )

            # Clean up the model output
            dsl_output = self._clean_model_output(dsl_output)

            # Validate the DSL output
            confidence = self._calculate_confidence(text, dsl_output)

            return TranslationResult(
                original_text=text,
                dsl_output=dsl_output,
                confidence=confidence,
                reasoning="Model-based translation",
                model_used="nl2dsl_model"
            )

        except Exception as e:
            self.logger.error(f"Model-based translation failed: {e}")
            # Fall back to pattern-based approach
            return self._pattern_based_translation(text, **kwargs)

    def _pattern_based_translation(self, text: str, **kwargs) -> TranslationResult:
        """Pattern-based translation as fallback"""
        try:
            # Extract components from natural language
            components = self._extract_components(text)

            # Build DSL from components
            dsl_output = self._build_dsl_from_components(components)

            # Calculate confidence based on how many components we identified
            confidence = self._calculate_pattern_confidence(components)

            return TranslationResult(
                original_text=text,
                dsl_output=dsl_output,
                confidence=confidence,
                reasoning="Pattern-based translation",
                model_used="fallback_patterns"
            )

        except Exception as e:
            self.logger.error(f"Pattern-based translation failed: {e}")

            # Last resort: very basic template
            return TranslationResult(
                original_text=text,
                dsl_output="ALLOW ACTION:* ON *",
                confidence=0.1,
                reasoning=f"Basic fallback due to error: {e}",
                model_used="basic_fallback"
            )

    def _build_model_prompt(self, text: str) -> str:
        """Build a prompt for the model"""
        prompt = f"""
Translate the following natural language request into AWS IAM DSL format.

DSL Format Rules:
- Use: (ALLOW|DENY) ACTION:<actions> ON <resources> [WHERE <conditions>]
- Actions: AWS service:action format (e.g., s3:GetObject, ec2:StartInstances)
- Resources: resource_type:resource_name format (e.g., bucket:my-bucket, instance:*)
- Multiple actions: [action1,action2,action3]
- Conditions: WHERE key operator value (e.g., WHERE ec2:InstanceType IN [t2.micro,t2.small])

Examples:
Input: "Allow Alice to read files from the public bucket"
Output: ALLOW ACTION:s3:GetObject ON bucket:public-bucket/*

Input: "Deny access to delete any S3 objects in the sensitive bucket"
Output: DENY ACTION:s3:DeleteObject ON bucket:sensitive-bucket/*

Input: "Allow starting and stopping small EC2 instances"
Output: ALLOW ACTION:[ec2:StartInstances,ec2:StopInstances] ON instance:* WHERE ec2:InstanceType IN [t2.nano,t2.micro,t2.small]

Now translate:
Input: "{text}"
Output:"""

        return prompt

    def _clean_model_output(self, output: str) -> str:
        """Clean up model output to get valid DSL"""
        # Remove the input part if the model repeated it
        if "Output:" in output:
            output = output.split("Output:")[-1]

        # Remove extra whitespace and newlines
        output = output.strip()

        # Take only the first line (in case model generated multiple options)
        output = output.split('\n')[0]

        # Basic validation - ensure it starts with ALLOW or DENY
        if not (output.startswith('ALLOW') or output.startswith('DENY')):
            # Try to find a valid line in the output
            lines = output.split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('ALLOW') or line.startswith('DENY'):
                    output = line
                    break

        return output

    def _extract_components(self, text: str) -> Dict[str, Any]:
        """Extract components from natural language using patterns"""
        components = {
            'effect': 'ALLOW',  # Default
            'actions': [],
            'resources': [],
            'subjects': [],
            'conditions': {}
        }

        # Detect effect (ALLOW/DENY)
        if any(word in text for word in ['deny', 'block', 'prevent', 'forbid', 'prohibit']):
            components['effect'] = 'DENY'

        # Extract actions using patterns
        components['actions'] = self._extract_actions(text)

        # Extract resources
        components['resources'] = self._extract_resources(text)

        # Extract subjects (users, roles, etc.)
        components['subjects'] = self._extract_subjects(text)

        # Extract conditions
        components['conditions'] = self._extract_conditions(text)

        return components

    def _extract_actions(self, text: str) -> List[str]:
        """Extract actions from natural language"""
        actions = []

        # Map common verbs to AWS actions
        for verb, aws_actions in self.action_mappings.items():
            if verb in text:
                # Determine service context
                service = self._determine_service(text)
                if service:
                    # Filter actions by service
                    for action in aws_actions:
                        if action.startswith(f"{service}:"):
                            actions.append(action)
                else:
                    # Add all matching actions
                    actions.extend(aws_actions)

        # Handle wildcards
        if any(word in text for word in ['all', 'any', 'everything', 'anything']):
            service = self._determine_service(text)
            if service:
                actions.append(f"{service}:*")
            else:
                actions.append("*")

        # Default action if none found
        if not actions:
            service = self._determine_service(text)
            if service:
                actions.append(f"{service}:*")
            else:
                actions.append("*")

        return actions

    def _extract_resources(self, text: str) -> List[str]:
        """Extract resources from natural language"""
        resources = []

        # Look for specific resource patterns
        bucket_match = re.search(r'bucket[:\s]*([a-zA-Z0-9\-]+)', text)
        if bucket_match:
            bucket_name = bucket_match.group(1)
            # Check if it's about objects in the bucket
            if any(word in text for word in ['file', 'object', 'content']):
                resources.append(f"bucket:{bucket_name}/*")
            else:
                resources.append(f"bucket:{bucket_name}")

        # Look for instance patterns
        instance_match = re.search(r'instance[:\s]*([a-zA-Z0-9\-*]+)', text)
        if instance_match:
            instance_name = instance_match.group(1)
            resources.append(f"instance:{instance_name}")

        # Look for general resource patterns
        if 'all' in text or 'any' in text:
            resources.append("*")

        # Default resource if none found but we have a service
        service = self._determine_service(text)
        if not resources and service:
            if service == 's3':
                resources.append("bucket:*")
            elif service == 'ec2':
                resources.append("instance:*")
            else:
                resources.append("*")

        if not resources:
            resources.append("*")

        return resources

    def _extract_subjects(self, text: str) -> List[str]:
        """Extract subjects (users, roles) from natural language"""
        subjects = []

        # Look for user names
        user_match = re.search(r'(?:user|for)\s+([a-zA-Z][a-zA-Z0-9\-_]*)', text)
        if user_match:
            subjects.append(f"user:{user_match.group(1)}")

        # Look for role names
        role_match = re.search(r'role\s+([a-zA-Z][a-zA-Z0-9\-_]*)', text)
        if role_match:
            subjects.append(f"role:{role_match.group(1)}")

        return subjects

    def _extract_conditions(self, text: str) -> Dict[str, Any]:
        """Extract conditions from natural language"""
        conditions = {}

        # Instance type conditions
        if 'small' in text or 'micro' in text:
            conditions['ec2:InstanceType'] = ['t2.nano', 't2.micro', 't2.small']
        elif 'large' in text:
            conditions['ec2:InstanceType'] = ['t2.large', 't2.xlarge']

        # Time-based conditions
        if 'business hours' in text:
            conditions['aws:RequestedRegion'] = 'us-east-1'  # Example

        return conditions

    def _determine_service(self, text: str) -> Optional[str]:
        """Determine the AWS service from natural language"""
        for service, keywords in self.service_mappings.items():
            if any(keyword in text for keyword in keywords):
                return service
        return None

    def _build_dsl_from_components(self, components: Dict[str, Any]) -> str:
        """Build DSL string from extracted components"""
        effect = components['effect']

        # Format actions
        actions = components['actions']
        if len(actions) == 1:
            action_str = actions[0]
        else:
            action_str = f"[{','.join(actions)}]"

        # Format resources
        resources = components['resources']
        if len(resources) == 1:
            resource_str = resources[0]
        else:
            resource_str = f"[{','.join(resources)}]"

        # Build basic DSL
        dsl = f"{effect} ACTION:{action_str} ON {resource_str}"

        # Add conditions if present
        conditions = components['conditions']
        if conditions:
            condition_parts = []
            for key, value in conditions.items():
                if isinstance(value, list):
                    value_str = f"[{','.join(map(str, value))}]"
                    condition_parts.append(f"{key} IN {value_str}")
                else:
                    condition_parts.append(f"{key} = {value}")

            if condition_parts:
                dsl += f" WHERE {' AND '.join(condition_parts)}"

        return dsl

    def _calculate_confidence(self, input_text: str, dsl_output: str) -> float:
        """Calculate confidence in the translation"""
        confidence = 0.5  # Base confidence

        # Check if DSL is syntactically valid
        if dsl_output.startswith(('ALLOW', 'DENY')) and 'ACTION:' in dsl_output and 'ON' in dsl_output:
            confidence += 0.3

        # Check if we identified specific services/actions
        if any(service in dsl_output for service in ['s3:', 'ec2:', 'iam:', 'lambda:']):
            confidence += 0.2

        # Check if we have specific resources
        if not dsl_output.endswith('ON *'):
            confidence += 0.1

        return min(confidence, 1.0)

    def _calculate_pattern_confidence(self, components: Dict[str, Any]) -> float:
        """Calculate confidence for pattern-based translation"""
        confidence = 0.3  # Base confidence for pattern-based

        # Boost confidence based on identified components
        if components['actions'] and components['actions'] != ['*']:
            confidence += 0.2

        if components['resources'] and components['resources'] != ['*']:
            confidence += 0.2

        if components['conditions']:
            confidence += 0.1

        if components['subjects']:
            confidence += 0.1

        return min(confidence, 0.8)  # Cap pattern-based confidence

    def _build_fallback_patterns(self) -> Dict[str, str]:
        """Build fallback patterns for common requests"""
        return {
            'read s3': 'ALLOW ACTION:s3:GetObject ON bucket:*',
            'write s3': 'ALLOW ACTION:s3:PutObject ON bucket:*',
            'list s3': 'ALLOW ACTION:s3:ListBucket ON bucket:*',
            'start instance': 'ALLOW ACTION:ec2:StartInstances ON instance:*',
            'stop instance': 'ALLOW ACTION:ec2:StopInstances ON instance:*',
            'describe instance': 'ALLOW ACTION:ec2:DescribeInstances ON instance:*'
        }


# Example usage and testing
if __name__ == "__main__":
    # Test the translator without model
    translator = NLToTranslator()

    test_inputs = [
        "Allow Alice to read files from the public bucket",
        "Deny deleting any objects in the sensitive bucket",
        "Allow starting small EC2 instances",
        "Let users list all S3 buckets",
        "Permit running t2.micro instances in us-east-1"
    ]

    print("Testing NL to DSL Translation:")
    print("=" * 50)

    for i, test_input in enumerate(test_inputs, 1):
        result = translator.translate(test_input)
        print(f"\nTest {i}:")
        print(f"Input:      {result.original_text}")
        print(f"Output:     {result.dsl_output}")
        print(f"Confidence: {result.confidence:.2f}")
        print(f"Method:     {result.reasoning}")
        print(f"Model:      {result.model_used}")