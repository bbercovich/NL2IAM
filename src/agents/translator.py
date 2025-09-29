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
    reasoning: Optional[str] = None
    model_used: Optional[str] = None


class NLToTranslator:
    """
    Translator Agent for converting natural language to DSL.

    This agent handles the first stage of the pipeline: converting user requests
    like "Requests by Alice to read objects in the public bucket should be allowed." into structured DSL
    like "ALLOW user:alice READ bucket:public-bucket/*"
    """

    def __init__(self, model_manager=None):
        self.model_manager = model_manager
        self.logger = logging.getLogger(__name__)


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
            self.logger.warning("Model not available")
            return None

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
            # Might need some addtonal work here
            #dsl_output = self._clean_model_output(dsl_output)


            return TranslationResult(
                original_text=text,
                dsl_output=dsl_output,
                reasoning="Model-based translation",
                model_used="nl2dsl_model"
            )

        except Exception as e:
            self.logger.error(f"Model-based translation failed: {e}")
            return None



    def _build_model_prompt(self, text: str) -> str:
        """Build a prompt for the model"""
        prompt = f"""You are an expert AWS IAM policy translator. Convert natural language requests into precise AWS IAM DSL statements.

CRITICAL REQUIREMENTS:
- Output ONLY the DSL statement(s), no explanations or commentary
- Use exact DSL syntax as specified in the format rules
- Handle complex scenarios with multiple conditions and exceptions
- Ensure proper formatting with numbered statements when multiple rules are needed

DSL FORMAT RULES:
- Basic format: (ALLOW|DENY) [role:role_name|user:username|*] [ACTION:action] ON [resource_type:resource_name|*] [WHERE conditions]
- Actions: Use service:action format (e.g., s3:GetObject, ec2:StartInstances) or generic verbs (READ, WRITE, DELETE)
- Resources: Use resource_type:resource_name format (e.g., bucket:my-bucket, instance:*) or * for all resources
- Multiple actions: Use [action1,action2,action3] format
- Multiple resources: Use [resource1,resource2] format
- Conditions: WHERE key operator value (e.g., WHERE ec2:InstanceType IN [t2.micro,t2.small])
- Principal specification: role:rolename, user:username, or * for any user/role
- Complex conditions: Use AND/OR operators, NOT for negations
- Case insensitive matching: Use IGNORECASE operator
- String matching: Use LIKE operator with arrays for multiple patterns
- Multi-statement policies: Number each statement (1., 2., etc.)

EXAMPLES:
Input: "Requests by Alice to read objects in the public bucket should be allowed."
Output: ALLOW user:alice READ bucket:public-bucket/*

Input: "Requests by Bob to delete objects in the audit bucket should be denied."
Output: DENY user:bob DELETE bucket:audit-bucket/*

Input: "Requests by any user to attach and detach volumes from instances in the Development department should be allowed. Requests by users to attach and detach their own volumes should be allowed."
Output: 1. ALLOW ACTION:[ec2:AttachVolume,ec2:DetachVolume] ON instance:* WHERE ec2:ResourceTag/Department=Development
2. ALLOW ACTION:[ec2:AttachVolume,ec2:DetachVolume] ON volume:* WHERE ec2:ResourceTag/VolumeUser=${{aws:username}}

Input: "Requests by any user to perform all actions on objects in the example bucket should be allowed only when the request comes from IP address 219.77.225.236 and the referrer is from example.com domains or specified CloudFront distributions. Requests by AWS Lambda should be allowed regardless of conditions. All other requests should be denied."
Output: 1. ALLOW * ACTION:* ON bucket:example/*
WHERE aws:Referer LIKE [
"https://www.example.com/*",
"https://example.com/*",
"https://example.herokuapp.com/*",
"https://dfgdsfgdfg.cloudfront.net/*",
"https://yygertwgbvcv.cloudfront.net/*"
]
AND aws:SourceIp="219.77.225.236"
2. DENY NOT role:lambda.amazonaws.com ACTION:* ON bucket:example/*
WHERE NOT aws:Referer LIKE [
"https://www.example.com/*",
"https://example.com/*",
"https://example.herokuapp.com/*",
"https://dfgdsfgdfg.cloudfront.net/*",
"https://yygertwgbvcv.cloudfront.net/*"
]
AND NOT aws:SourceIp="219.77.225.236"

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