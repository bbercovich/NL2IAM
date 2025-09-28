"""
Regex-based DSL Parser for AWS IAM Policy Generation

This module provides a simple regex-based parser for the DSL that's easier to debug
and more reliable for the initial implementation.
"""

import re
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass


@dataclass
class DSLAction:
    """Represents an action in the DSL"""
    name: str

    def to_aws_action(self) -> str:
        """Convert DSL action to AWS IAM action format"""
        return self.name


@dataclass
class DSLResource:
    """Represents a resource in the DSL"""
    resource_type: str
    resource_name: str

    def to_aws_arn(self) -> str:
        """Convert DSL resource to AWS ARN format"""
        # Map common resource types to AWS service prefixes
        service_mapping = {
            'bucket': 's3',
            'instance': 'ec2',
            'volume': 'ec2',
            'network-interface': 'ec2',
            'security-group': 'ec2',
            'subnet': 'ec2',
            'image': 'ec2',
            'function': 'lambda',
            'role': 'iam',
            'user': 'iam',
            'group': 'iam'
        }

        service = service_mapping.get(self.resource_type, self.resource_type)

        if self.resource_name == "*":
            if self.resource_type == "bucket":
                return "arn:aws:s3:::*"
            return "*"

        # Handle specific resource ARN patterns
        if self.resource_type == "bucket":
            if "/" in self.resource_name:
                bucket, key = self.resource_name.split("/", 1)
                return f"arn:aws:s3:::{bucket}/{key}"
            else:
                return f"arn:aws:s3:::{self.resource_name}"
        elif self.resource_type in ["instance", "volume", "security-group", "subnet", "network-interface", "image"]:
            return f"arn:aws:ec2:*:*:{self.resource_type}/{self.resource_name}"
        elif self.resource_type in ["role", "user", "group"]:
            return f"arn:aws:iam::*:{self.resource_type}/{self.resource_name}"
        elif self.resource_type == "function":
            return f"arn:aws:lambda:*:*:function:{self.resource_name}"
        else:
            return f"arn:aws:{service}:*:*:{self.resource_type}/{self.resource_name}"


@dataclass
class DSLCondition:
    """Represents a condition in the DSL"""
    key: str
    operator: str
    value: Union[str, List[str], int, float]

    def to_aws_condition(self) -> Dict[str, Any]:
        """Convert DSL condition to AWS IAM condition format"""
        # Map DSL operators to AWS condition operators
        operator_mapping = {
            'IN': 'ForAnyValue:StringEquals',
            'LIKE': 'StringLike',
            '=': 'StringEquals',
            '!=': 'StringNotEquals',
            '<=': 'NumericLessThanEquals',
            '>=': 'NumericGreaterThanEquals',
            '<': 'NumericLessThan',
            '>': 'NumericGreaterThan'
        }

        aws_operator = operator_mapping.get(self.operator, 'StringEquals')

        # Handle list values for IN operator
        if self.operator == 'IN' and isinstance(self.value, list):
            return {aws_operator: {self.key: self.value}}
        elif self.operator == 'LIKE':
            # Convert LIKE patterns to AWS StringLike format
            if isinstance(self.value, list):
                patterns = [pattern.replace('*', '*') for pattern in self.value]
                return {aws_operator: {self.key: patterns}}
            else:
                pattern = str(self.value).replace('*', '*')
                return {aws_operator: {self.key: pattern}}
        else:
            return {aws_operator: {self.key: self.value}}


@dataclass
class DSLStatement:
    """Represents a complete DSL statement"""
    effect: str  # ALLOW or DENY
    actions: List[DSLAction]
    resources: List[DSLResource]
    conditions: Optional[List[DSLCondition]] = None

    def to_aws_statement(self) -> Dict[str, Any]:
        """Convert DSL statement to AWS IAM policy statement"""
        statement = {
            "Effect": "Allow" if self.effect == "ALLOW" else "Deny",
            "Action": [action.to_aws_action() for action in self.actions],
            "Resource": [resource.to_aws_arn() for resource in self.resources]
        }

        # Simplify single-item lists
        if len(statement["Action"]) == 1:
            statement["Action"] = statement["Action"][0]
        if len(statement["Resource"]) == 1:
            statement["Resource"] = statement["Resource"][0]

        # Add conditions if present
        if self.conditions:
            condition_dict = {}
            for condition in self.conditions:
                aws_condition = condition.to_aws_condition()
                for operator, values in aws_condition.items():
                    if operator not in condition_dict:
                        condition_dict[operator] = {}
                    condition_dict[operator].update(values)
            statement["Condition"] = condition_dict

        return statement


@dataclass
class DSLPolicy:
    """Represents a complete DSL policy with multiple statements"""
    statements: List[DSLStatement]

    def to_aws_policy(self) -> Dict[str, Any]:
        """Convert DSL policy to AWS IAM policy JSON"""
        return {
            "Version": "2012-10-17",
            "Statement": [stmt.to_aws_statement() for stmt in self.statements]
        }


class RegexDSLParser:
    """Regex-based DSL parser for AWS IAM policies"""

    def __init__(self):
        # Pattern for the main statement structure
        self.statement_pattern = re.compile(
            r'(ALLOW|DENY)\s+ACTION:(.*?)\s+ON\s+(.*?)(?:\s+WHERE\s+(.*?))?(?=\n|$|ALLOW|DENY)',
            re.MULTILINE | re.DOTALL
        )

    def parse(self, dsl_text: str) -> DSLPolicy:
        """Parse DSL text into a DSLPolicy object"""
        try:
            # Clean up the input text
            cleaned_text = self._clean_dsl_text(dsl_text)

            # Find all statements
            statements = []
            for match in self.statement_pattern.finditer(cleaned_text):
                effect = match.group(1).strip()
                actions_str = match.group(2).strip()
                resources_str = match.group(3).strip()
                conditions_str = match.group(4).strip() if match.group(4) else None

                # Parse statement components
                actions = self._parse_actions(actions_str)
                resources = self._parse_resources(resources_str)
                conditions = self._parse_conditions(conditions_str) if conditions_str else None

                statements.append(DSLStatement(effect, actions, resources, conditions))

            if not statements:
                raise ValueError("No valid statements found")

            return DSLPolicy(statements)

        except Exception as e:
            raise ValueError(f"Failed to parse DSL: {e}")

    def _clean_dsl_text(self, text: str) -> str:
        """Clean and normalize DSL text"""
        # Remove numbered prefixes like "1. ", "2. "
        lines = text.strip().split('\n')
        cleaned_lines = []

        for line in lines:
            line = line.strip()
            if line:
                # Remove numbered list prefixes
                line = re.sub(r'^\d+\.\s*', '', line)
                cleaned_lines.append(line)

        # Join with spaces to make regex matching easier
        return ' '.join(cleaned_lines) + ' '

    def _parse_actions(self, actions_str: str) -> List[DSLAction]:
        """Parse action string into DSLAction objects"""
        actions = []

        # Handle list format [action1,action2,...]
        if actions_str.startswith('[') and actions_str.endswith(']'):
            actions_list = actions_str[1:-1].split(',')
            for action in actions_list:
                actions.append(DSLAction(action.strip()))
        else:
            # Single action
            actions.append(DSLAction(actions_str.strip()))

        return actions

    def _parse_resources(self, resources_str: str) -> List[DSLResource]:
        """Parse resource string into DSLResource objects"""
        resources = []

        # Handle wildcard
        if resources_str.strip() == '*':
            resources.append(DSLResource('*', '*'))
            return resources

        # Handle list format [resource1,resource2,...]
        if resources_str.startswith('[') and resources_str.endswith(']'):
            resources_list = resources_str[1:-1].split(',')
            for resource in resources_list:
                resource = resource.strip()
                if ':' in resource:
                    resource_type, resource_name = resource.split(':', 1)
                    resources.append(DSLResource(resource_type.strip(), resource_name.strip()))
                else:
                    resources.append(DSLResource('*', resource.strip()))
        else:
            # Single resource
            resource = resources_str.strip()
            if ':' in resource:
                resource_type, resource_name = resource.split(':', 1)
                resources.append(DSLResource(resource_type.strip(), resource_name.strip()))
            else:
                resources.append(DSLResource('*', resource.strip()))

        return resources

    def _parse_conditions(self, conditions_str: str) -> List[DSLCondition]:
        """Parse condition string into DSLCondition objects"""
        conditions = []

        # Split on AND
        condition_parts = re.split(r'\s+AND\s+', conditions_str)

        for part in condition_parts:
            part = part.strip()
            # Match condition pattern: key operator value
            match = re.match(r'(\w+(?::\w+)?)\s+(IN|LIKE|=|!=|<=|>=|<|>)\s+(.+)', part)
            if match:
                key = match.group(1).strip()
                operator = match.group(2).strip()
                value_str = match.group(3).strip()

                # Parse value
                value = self._parse_condition_value(value_str)
                conditions.append(DSLCondition(key, operator, value))

        return conditions

    def _parse_condition_value(self, value_str: str) -> Union[str, List[str], int, float]:
        """Parse condition value (could be string, number, or list)"""
        value_str = value_str.strip()

        # Handle list values [item1,item2,...]
        if value_str.startswith('[') and value_str.endswith(']'):
            items = value_str[1:-1].split(',')
            values = []
            for item in items:
                item = item.strip().strip('"\'')
                # Try to convert to number
                try:
                    if '.' in item:
                        values.append(float(item))
                    else:
                        values.append(int(item))
                except ValueError:
                    values.append(item)
            return values
        else:
            # Single value - try to convert to number
            value_str = value_str.strip('"\'')
            try:
                if '.' in value_str:
                    return float(value_str)
                else:
                    return int(value_str)
            except ValueError:
                return value_str


def parse_dsl(dsl_text: str) -> DSLPolicy:
    """Convenience function to parse DSL text"""
    parser = RegexDSLParser()
    return parser.parse(dsl_text)


# Test the parser
if __name__ == "__main__":
    test_dsl = """
    1. ALLOW ACTION:[s3:GetBucketLocation,s3:ListAllMyBuckets] ON *
    2. ALLOW ACTION:s3:ListBucket ON bucket:bluebolt
    3. DENY ACTION:s3:* ON bucket:bluebolt/Management/*
    """

    try:
        policy = parse_dsl(test_dsl)
        print("✓ DSL parsing successful!")
        print(f"Parsed {len(policy.statements)} statements")

        for i, stmt in enumerate(policy.statements):
            print(f"\nStatement {i+1}:")
            print(f"  Effect: {stmt.effect}")
            print(f"  Actions: {[a.name for a in stmt.actions]}")
            print(f"  Resources: {[(r.resource_type, r.resource_name) for r in stmt.resources]}")
            if stmt.conditions:
                print(f"  Conditions: {[(c.key, c.operator, c.value) for c in stmt.conditions]}")

        import json
        aws_policy = policy.to_aws_policy()
        print("\n✓ AWS policy conversion successful!")
        print(json.dumps(aws_policy, indent=2))

    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()