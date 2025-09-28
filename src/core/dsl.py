"""
Domain-Specific Language (DSL) for AWS IAM Policy Generation

This module defines the grammar and parser for a SQL-like DSL that serves as an
intermediate representation between natural language and AWS IAM policies.

DSL Grammar:
    statement: (ALLOW|DENY) ACTION:<actions> ON <resources> [WHERE <conditions>]

    actions: action_name | action_list | "*"
    action_list: "[" action_name ("," action_name)* "]"

    resources: resource | resource_list | "*"
    resource_list: "[" resource ("," resource)* "]"
    resource: resource_type ":" resource_name

    conditions: condition ("AND" condition)*
    condition: condition_key operator value
    operator: "IN" | "LIKE" | "=" | "!=" | "<=" | ">=" | "<" | ">"

Example DSL:
    ALLOW ACTION:[s3:GetBucketLocation,s3:ListAllMyBuckets] ON *
    ALLOW ACTION:s3:ListBucket ON bucket:bluebolt WHERE s3:prefix IN ["", "Production/"]
    DENY ACTION:s3:* ON bucket:bluebolt/Management/*
"""

# Re-export the working implementation from dsl_regex
from .dsl_regex import (
    DSLAction,
    DSLResource,
    DSLCondition,
    DSLStatement,
    DSLPolicy,
    RegexDSLParser as DSLParser,
    parse_dsl
)

__all__ = [
    'DSLAction',
    'DSLResource',
    'DSLCondition',
    'DSLStatement',
    'DSLPolicy',
    'DSLParser',
    'parse_dsl'
]