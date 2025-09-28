"""
Simplified DSL Parser using pyparsing for AWS IAM Policy Generation
"""

import re
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass
import pyparsing as pp


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


class SimpleDSLParser:
    """Simple DSL parser using pyparsing"""

    def __init__(self):
        self._build_grammar()

    def _build_grammar(self):
        """Build the pyparsing grammar"""
        # Set up whitespace handling
        pp.ParserElement.setDefaultWhitespaceChars(' \t')

        # Basic tokens
        word = pp.Word(pp.alphanums + "_-")
        aws_action = pp.Combine(word + ":" + word)
        wildcard = pp.Literal("*")

        # Action definitions
        action_name = aws_action | wildcard
        action_list = pp.Suppress("[") + pp.delimitedList(action_name) + pp.Suppress("]")
        actions = action_list | action_name

        # Resource definitions
        resource_part = word | wildcard | pp.Combine("${" + word + "}")
        resource_path = pp.Combine(resource_part + pp.ZeroOrMore("/" + resource_part))
        resource_name = resource_path
        resource_spec = pp.Combine(word + ":" + resource_name)
        resource_list = pp.Suppress("[") + pp.delimitedList(resource_spec | wildcard) + pp.Suppress("]")
        resources = resource_list | resource_spec | wildcard

        # Condition definitions
        condition_key = pp.Combine(word + pp.Optional(":" + word))
        operator = pp.oneOf("IN LIKE = != <= >= < >")
        quoted_string = pp.QuotedString('"', escChar='\\') | pp.QuotedString("'", escChar='\\')
        string_value = quoted_string | resource_path
        number_value = pp.pyparsing_common.number
        value_list = pp.Suppress("[") + pp.delimitedList(string_value | number_value) + pp.Suppress("]")
        value = value_list | string_value | number_value
        condition = pp.Group(condition_key + operator + value)
        conditions = pp.delimitedList(condition, "AND")

        # Main statement
        effect = pp.oneOf("ALLOW DENY")
        statement = pp.Group(effect + pp.Suppress("ACTION:") + actions +
                           pp.Suppress("ON") + resources +
                           pp.Optional(pp.Suppress("WHERE") + conditions))

        # Policy (multiple statements separated by newlines or semicolons)
        statement_separator = pp.LineEnd() | pp.Literal(";")
        policy = statement + pp.ZeroOrMore(pp.Suppress(pp.Optional(statement_separator)) + statement)

        self.parser = policy

    def parse(self, dsl_text: str) -> DSLPolicy:
        """Parse DSL text into a DSLPolicy object"""
        try:
            # Clean up the input text
            cleaned_text = self._clean_dsl_text(dsl_text)
            print(f"Cleaned text: {repr(cleaned_text)}")

            # Parse the text
            parsed = self.parser.parseString(cleaned_text, parseAll=True)

            # Convert parsed results to DSL objects
            statements = []
            for stmt_data in parsed:
                statements.append(self._convert_statement(stmt_data))

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

        return '\n'.join(cleaned_lines)

    def _convert_statement(self, stmt_data) -> DSLStatement:
        """Convert parsed statement data to DSLStatement object"""
        effect = stmt_data[0]
        actions_data = stmt_data[1]
        resources_data = stmt_data[2]
        conditions_data = stmt_data[3] if len(stmt_data) > 3 else None

        # Convert actions
        actions = []
        if isinstance(actions_data, list):
            for action in actions_data:
                actions.append(DSLAction(str(action)))
        else:
            actions.append(DSLAction(str(actions_data)))

        # Convert resources
        resources = []
        if isinstance(resources_data, list):
            for resource in resources_data:
                if str(resource) == "*":
                    resources.append(DSLResource("*", "*"))
                else:
                    parts = str(resource).split(":", 1)
                    if len(parts) == 2:
                        resources.append(DSLResource(parts[0], parts[1]))
                    else:
                        resources.append(DSLResource("*", str(resource)))
        else:
            if str(resources_data) == "*":
                resources.append(DSLResource("*", "*"))
            else:
                parts = str(resources_data).split(":", 1)
                if len(parts) == 2:
                    resources.append(DSLResource(parts[0], parts[1]))
                else:
                    resources.append(DSLResource("*", str(resources_data)))

        # Convert conditions
        conditions = None
        if conditions_data:
            conditions = []
            for cond_data in conditions_data:
                key = str(cond_data[0])
                op = str(cond_data[1])
                value = cond_data[2]
                if isinstance(value, list):
                    value = [str(v) for v in value]
                else:
                    value = str(value)
                conditions.append(DSLCondition(key, op, value))

        return DSLStatement(effect, actions, resources, conditions)


def parse_dsl(dsl_text: str) -> DSLPolicy:
    """Convenience function to parse DSL text"""
    parser = SimpleDSLParser()
    return parser.parse(dsl_text)


# Test the parser
if __name__ == "__main__":
    test_dsl = """
    ALLOW ACTION:[s3:GetBucketLocation,s3:ListAllMyBuckets] ON *
    ALLOW ACTION:s3:ListBucket ON bucket:bluebolt
    DENY ACTION:s3:* ON bucket:bluebolt/Management/*
    """

    try:
        policy = parse_dsl(test_dsl)
        print("✓ DSL parsing successful!")
        print(f"Parsed {len(policy.statements)} statements")

        import json
        aws_policy = policy.to_aws_policy()
        print("✓ AWS policy conversion successful!")
        print(json.dumps(aws_policy, indent=2))

    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()