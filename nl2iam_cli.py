#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NL2IAM Interactive CLI

This CLI provides an interactive interface for the complete NL2IAM pipeline:
1. Natural Language → DSL conversion
2. DSL → AWS IAM Policy generation (with RAG enhancement)
3. Redundancy checking against existing policies
4. Conflict checking for policy conflicts
5. Policy inventory management

Usage:
    python nl2iam_cli.py [--debug] [--inventory-path PATH]

Features:
- Debug mode: Shows intermediate DSL and asks for confirmation
- Normal mode: Streamlined workflow
- Interactive prompts at each validation step
- Policy inventory management
- Comprehensive error handling
"""

import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime

# Add src to path
sys.path.append('src')

try:
    from models.model_manager import create_default_manager
    from agents.translator import NLToTranslator
    from agents.policy_generator import PolicyGenerator
    from agents.redundancy_checker import RedundancyChecker
    from agents.conflict_checker import ConflictChecker
    from rag.rag_engine import RAGEngine
except ImportError as e:
    print(f"❌ Error importing required modules: {e}")
    print("Please ensure you're running from the project root directory and all dependencies are installed.")
    sys.exit(1)


class NL2IAMSession:
    """Manages a single CLI session with state and configurations"""

    def __init__(self, debug_mode: bool = False, inventory_path: Optional[str] = None,
                 use_rag: bool = True, skip_validation: bool = False):
        self.debug_mode = debug_mode
        self.inventory_path = inventory_path or "./data/policy_inventory.json"
        self.use_rag = use_rag
        self.skip_validation = skip_validation

        # Pipeline components
        self.model_manager = None
        self.translator = None
        self.policy_generator = None
        self.redundancy_checker = None
        self.conflict_checker = None
        self.rag_engine = None

        # Session state
        self.initialized = False
        self.policies_created = 0

        # Setup logging
        logging.basicConfig(
            level=logging.INFO if debug_mode else logging.WARNING,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    def initialize(self) -> bool:
        """Initialize all pipeline components"""
        print("🚀 Initializing NL2IAM Pipeline...")
        print("=" * 60)

        try:
            # Initialize model manager
            print("📥 Setting up model manager...")
            self.model_manager = create_default_manager()

            # Load models
            print("⏳ Loading NL→DSL model...")
            nl_success = self.model_manager.load_model('nl2dsl_model')
            if not nl_success:
                print("⚠️  NL→DSL model failed to load - using pattern-based translation")
            else:
                print("✅ NL→DSL model loaded successfully")

            print("⏳ Loading DSL→Policy model...")
            policy_success = self.model_manager.load_model('dsl2policy_model')
            if not policy_success:
                print("❌ DSL→Policy model failed to load - cannot continue")
                return False
            else:
                print("✅ DSL→Policy model loaded successfully")

            # Initialize RAG engine if enabled
            if self.use_rag:
                print("📚 Setting up RAG engine...")
                aws_docs_path = "./docs/iam-ug.pdf"
                vector_store_path = "./data/vector_store/"

                if Path(aws_docs_path).exists():
                    self.rag_engine = RAGEngine(vector_store_path=vector_store_path)
                    rag_success = self.rag_engine.initialize_knowledge_base(aws_docs_path)
                    if rag_success:
                        print("✅ RAG engine initialized with AWS documentation")
                        stats = self.rag_engine.get_knowledge_base_stats()
                        print(f"   📊 Knowledge base: {stats.get('total_chunks', 0)} chunks")
                    else:
                        print("⚠️  RAG engine initialization failed - proceeding without RAG")
                        self.rag_engine = None
                else:
                    print(f"⚠️  AWS documentation not found at {aws_docs_path}")
                    print("   📝 Proceeding without RAG enhancement")
                    self.rag_engine = None
            else:
                print("🚫 RAG disabled - proceeding without documentation enhancement")
                self.rag_engine = None

            # Initialize pipeline agents
            print("🔧 Creating pipeline agents...")
            self.translator = NLToTranslator(model_manager=self.model_manager)
            self.policy_generator = PolicyGenerator(
                model_manager=self.model_manager,
                rag_engine=self.rag_engine
            )
            self.redundancy_checker = RedundancyChecker(inventory_path=self.inventory_path)
            self.conflict_checker = ConflictChecker(inventory_path=self.inventory_path)

            print("✅ All pipeline components initialized successfully!")

            # Show inventory stats
            stats = self.redundancy_checker.get_inventory_stats()
            print(f"📋 Policy Inventory: {stats['total_policies']} existing policies")

            self.initialized = True
            return True

        except Exception as e:
            print(f"❌ Initialization failed: {e}")
            if self.debug_mode:
                import traceback
                traceback.print_exc()
            return False

    def cleanup(self):
        """Clean up resources"""
        if self.model_manager:
            print("🧹 Cleaning up models...")
            self.model_manager.unload_all_models()

    def run_interactive_session(self):
        """Run the main interactive session loop"""
        if not self.initialized:
            print("❌ Session not initialized. Call initialize() first.")
            return

        print("\n" + "=" * 60)
        print("🎯 NL2IAM Interactive Policy Generator")
        print("=" * 60)
        print("Generate AWS IAM policies from natural language descriptions.")
        print("")
        print("💡 Example inputs:")
        print("   • Allow Alice to read files from the public bucket")
        print("   • Deny deleting objects in the sensitive-data bucket")
        print("   • Permit launching only small EC2 instances like t2.micro")
        print("")
        print("Commands:")
        print("   • 'quit' or 'exit' - End the session")
        print("   • 'help' - Show examples and tips")
        print("   • 'stats' - Show inventory statistics")
        if self.debug_mode:
            print("🐛 Debug mode: You'll see intermediate steps and confirmations.")
        if not self.use_rag:
            print("🚫 RAG disabled: Policies generated without AWS documentation context.")
        if self.skip_validation:
            print("⚠️  Validation disabled: Redundancy and conflict checks will be skipped.")
        print()

        while True:
            try:
                # Get natural language input
                print("📝 Describe the IAM policy you want to create:")
                nl_input = input("👤 > ").strip()

                if not nl_input:
                    print("   Please enter a policy description or type 'help' for examples.")
                    continue

                # Check for special commands
                if nl_input.lower() in ['quit', 'exit', 'q']:
                    break
                elif nl_input.lower() in ['help', 'h', '?']:
                    self.show_help()
                    continue
                elif nl_input.lower() in ['stats', 'status']:
                    self.show_inventory_stats()
                    continue

                # Validate input length
                if len(nl_input) < 10:
                    print("⚠️  Policy description seems too short. Please provide more detail.")
                    continue

                if len(nl_input) > 500:
                    print("⚠️  Policy description is very long. Consider breaking it into smaller, specific requests.")
                    continue

                # Process the request
                success = self.process_policy_request(nl_input)

                if success:
                    self.policies_created += 1
                    print(f"\n✅ Policy created successfully! (Total this session: {self.policies_created})")
                else:
                    print(f"\n❌ Policy creation was cancelled or failed.")

                print("\n" + "-" * 40)

            except KeyboardInterrupt:
                print("\n\n👋 Session interrupted. Goodbye!")
                break
            except EOFError:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"\n❌ Unexpected error: {e}")
                if self.debug_mode:
                    import traceback
                    traceback.print_exc()
                print("Try rephrasing your request or type 'help' for examples.")

        print(f"\n📊 Session Summary:")
        print(f"   Policies created: {self.policies_created}")
        print(f"   Debug mode: {'On' if self.debug_mode else 'Off'}")
        print("👋 Thank you for using NL2IAM!")

    def show_help(self):
        """Display help information"""
        print("\n📚 NL2IAM Help")
        print("=" * 40)
        print("\n💡 Good policy descriptions are:")
        print("   • Specific about who (user, role, group)")
        print("   • Clear about what actions (read, write, delete, etc.)")
        print("   • Explicit about resources (bucket names, instance types)")
        print("   • Include conditions when relevant")
        print("\n✅ Examples:")
        print("   • 'Allow user Alice to read objects from the public-data bucket'")
        print("   • 'Deny all users from deleting objects in the audit-logs bucket'")
        print("   • 'Allow role DataScientist to launch t2.micro and t2.small EC2 instances'")
        print("   • 'Allow uploading files to the uploads bucket only during business hours'")
        print("\n❌ Avoid vague descriptions:")
        print("   • 'Give Alice access' (access to what?)")
        print("   • 'S3 permissions' (which actions? which buckets?)")
        print("   • 'EC2 stuff' (what specifically?)")
        print("\n🏷️  Commands:")
        print("   • 'help' - Show this help")
        print("   • 'stats' - Show current inventory statistics")
        print("   • 'quit' - Exit the program")
        print()

    def show_inventory_stats(self):
        """Display current inventory statistics"""
        print("\n📊 Policy Inventory Statistics")
        print("=" * 40)
        try:
            stats = self.redundancy_checker.get_inventory_stats()
            print(f"   Total policies: {stats['total_policies']}")
            print(f"   Unique actions: {stats['unique_actions']}")
            print(f"   Unique resources: {stats['unique_resources']}")
            print(f"   Unique principals: {stats['unique_principals']}")

            if stats['total_policies'] > 0:
                print("\n📋 Recent policies:")
                policies = self.redundancy_checker.list_policies()
                for policy in policies[-3:]:  # Show last 3 policies
                    print(f"   • {policy['name']} (ID: {policy['id'][:8]}...)")
        except Exception as e:
            print(f"   ❌ Error retrieving stats: {e}")
        print()

    def process_policy_request(self, natural_language: str) -> bool:
        """
        Process a complete policy request through the pipeline

        Returns:
            True if policy was successfully created and added to inventory
            False if process was cancelled or failed
        """
        print(f"\n🔄 Processing request: \"{natural_language}\"")
        print("─" * 60)

        # Step 1: Natural Language → DSL
        print("🔤 Step 1: Converting natural language to DSL...")

        translation_result = self.translator.translate(natural_language)
        if not translation_result or not translation_result.dsl_output:
            print("❌ Failed to translate natural language to DSL")
            return False

        dsl_output = translation_result.dsl_output
        print(f"✅ DSL Generated: {dsl_output}")

        # Debug mode: Show DSL and ask for confirmation
        if self.debug_mode:
            print(f"\n🐛 DEBUG MODE")
            print(f"   📝 Generated DSL: {dsl_output}")
            if translation_result.reasoning:
                print(f"   💭 Method: {translation_result.reasoning}")

            while True:
                response = input("   ❓ Continue with this DSL? (y/n/edit): ").strip().lower()
                if response in ['y', 'yes']:
                    break
                elif response in ['n', 'no']:
                    return False
                elif response in ['e', 'edit']:
                    new_dsl = input("   ✏️  Enter corrected DSL: ").strip()
                    if new_dsl:
                        dsl_output = new_dsl
                        print(f"   ✅ Using edited DSL: {dsl_output}")
                        break
                else:
                    print("   Please enter 'y' (yes), 'n' (no), or 'edit'")

        # Step 2: DSL → AWS IAM Policy
        print(f"\n🏗️  Step 2: Generating AWS IAM policy from DSL...")

        policy_result = self.policy_generator.generate_policy(dsl_output)
        if not policy_result.success:
            print("❌ Failed to generate IAM policy")
            for warning in policy_result.warnings:
                print(f"   ⚠️  {warning}")
            return False

        candidate_policy = policy_result.policy
        print("✅ IAM Policy generated successfully")

        # Show RAG info if available
        if policy_result.retrieved_contexts:
            print(f"📚 Enhanced with {len(policy_result.retrieved_contexts)} AWS documentation contexts")

        # Pretty print the policy
        print("\n📄 Generated Policy:")
        print(json.dumps(candidate_policy, indent=2))

        # Step 3: Redundancy Check (if validation is enabled)
        if not self.skip_validation:
            print(f"\n🔍 Step 3: Checking for redundancy...")

            redundancy_result = self.redundancy_checker.check_redundancy(
                candidate_policy,
                policy_name=f"Policy-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                add_to_inventory=False  # Don't add yet
            )

            if not redundancy_result.success:
                print(f"❌ Redundancy check failed: {redundancy_result.error_message}")
                return False

            if redundancy_result.has_redundancy:
                print("⚠️  REDUNDANCY DETECTED")
                print(f"   📋 {redundancy_result.summary}")

                # Show redundancy details
                for result in redundancy_result.redundancy_results:
                    print(f"\n   🔍 Redundancy Details:")
                    print(f"      Type: {result.redundancy_type}")
                    print(f"      Confidence: {result.confidence_score:.2f}")
                    print(f"      Explanation: {result.explanation}")

                    # Show conflicting policy
                    conflicting_policy_id = result.conflicting_policy_id
                    conflicting_policies = self.redundancy_checker.list_policies()
                    conflicting_policy = next(
                        (p for p in conflicting_policies if p['id'] == conflicting_policy_id),
                        None
                    )

                    if conflicting_policy:
                        print(f"      📄 Existing Policy '{conflicting_policy['name']}':")
                        print(json.dumps(conflicting_policy['policy'], indent=8))

                # Show recommendations
                print(f"\n   💡 Recommendations:")
                for rec in redundancy_result.recommendations:
                    print(f"      {rec}")

                # Ask user what to do
                while True:
                    response = input(f"\n   ❓ Continue anyway or start over? (continue/restart): ").strip().lower()
                    if response in ['c', 'continue']:
                        break
                    elif response in ['r', 'restart', 's', 'start']:
                        return False
                    else:
                        print("   Please enter 'continue' or 'restart'")
            else:
                print("✅ No redundancy detected")

            # Step 4: Conflict Check
            print(f"\n⚔️  Step 4: Checking for conflicts...")

            conflict_result = self.conflict_checker.check_conflicts(
                candidate_policy,
                policy_name=f"Policy-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            )

            if not conflict_result.success:
                print(f"❌ Conflict check failed: {conflict_result.error_message}")
                return False

            if conflict_result.has_conflicts:
                print(f"⚠️  CONFLICTS DETECTED")
                print(f"   🚨 Risk Level: {conflict_result.overall_risk_level.upper()}")
                print(f"   📋 {conflict_result.summary}")

                # Show conflict details
                for result in conflict_result.conflict_results:
                    print(f"\n   ⚔️  Conflict Details:")
                    print(f"      Type: {result.conflict_type}")
                    print(f"      Severity: {result.severity}")
                    print(f"      Confidence: {result.confidence_score:.2f}")
                    print(f"      Explanation: {result.explanation}")
                    print(f"      Affected Actions: {list(result.affected_actions)}")

                    # Show conflicting policy
                    conflicting_policy_id = result.conflicting_policy_id
                    conflicting_policies = self.conflict_checker.list_policies()
                    conflicting_policy = next(
                        (p for p in conflicting_policies if p['id'] == conflicting_policy_id),
                        None
                    )

                    if conflicting_policy:
                        print(f"      📄 Conflicting Policy '{conflicting_policy['name']}':")
                        print(json.dumps(conflicting_policy['policy'], indent=8))

                # Show recommendations
                print(f"\n   💡 Recommendations:")
                for rec in conflict_result.recommendations:
                    print(f"      {rec}")

                # Ask user what to do
                while True:
                    response = input(f"\n   ❓ Continue anyway or start over? (continue/restart): ").strip().lower()
                    if response in ['c', 'continue']:
                        break
                    elif response in ['r', 'restart', 's', 'start']:
                        return False
                    else:
                        print("   Please enter 'continue' or 'restart'")
            else:
                print("✅ No conflicts detected")
        else:
            print("\n⚠️  Steps 3-4: Validation checks skipped (--skip-validation flag enabled)")

        # Step 3/5: Add to Policy Inventory (Step number depends on whether validation was skipped)
        final_step = "3" if self.skip_validation else "5"
        print(f"\n💾 Step {final_step}: Adding policy to inventory...")

        policy_name = f"NL2IAM-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        policy_description = f"Generated from: {natural_language[:100]}..."

        try:
            policy_id = self.redundancy_checker.add_existing_policy(
                candidate_policy,
                name=policy_name,
                description=policy_description
            )

            print(f"✅ Policy added to inventory")
            print(f"   📋 Policy ID: {policy_id[:8]}...")
            print(f"   📝 Policy Name: {policy_name}")

            # Show final policy
            print(f"\n📄 Final Policy (saved to inventory):")
            print(json.dumps(candidate_policy, indent=2))

            return True

        except Exception as e:
            print(f"❌ Failed to add policy to inventory: {e}")
            return False


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="NL2IAM Interactive CLI - Generate AWS IAM policies from natural language",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python nl2iam_cli.py                           # Normal mode with RAG and validation
  python nl2iam_cli.py --debug                   # Debug mode with step confirmations
  python nl2iam_cli.py --no-rag                  # Generate policies without AWS documentation context
  python nl2iam_cli.py --skip-validation         # Skip redundancy and conflict checks
  python nl2iam_cli.py --no-rag --skip-validation # Fastest mode: no RAG, no validation
  python nl2iam_cli.py --inventory-path ./my_policies.json  # Custom inventory file

Benchmarking Options:
  --no-rag: Disable Retrieval Augmented Generation for baseline comparison
  --skip-validation: Skip redundancy/conflict checks for speed testing

Debug Mode Features:
  - Shows intermediate DSL translation
  - Allows editing of generated DSL
  - More detailed logging and error information

Natural Language Examples:
  "Allow Alice to read files from the public bucket"
  "Deny deleting objects in the sensitive-data bucket"
  "Permit launching only small EC2 instances like t2.micro"
        """
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode with step-by-step confirmations'
    )

    parser.add_argument(
        '--inventory-path',
        type=str,
        help='Path to policy inventory file (default: ./data/policy_inventory.json)'
    )

    parser.add_argument(
        '--no-rag',
        action='store_true',
        help='Disable RAG (Retrieval Augmented Generation) - generate policies without AWS documentation context'
    )

    parser.add_argument(
        '--skip-validation',
        action='store_true',
        help='Skip redundancy and conflict validation checks'
    )

    args = parser.parse_args()

    # Create session
    session = NL2IAMSession(
        debug_mode=args.debug,
        inventory_path=args.inventory_path,
        use_rag=not args.no_rag,
        skip_validation=args.skip_validation
    )

    try:
        # Initialize pipeline
        if not session.initialize():
            print("❌ Failed to initialize. Please check your setup and try again.")
            sys.exit(1)

        # Run interactive session
        session.run_interactive_session()

    except KeyboardInterrupt:
        print("\n\n👋 Session interrupted. Goodbye!")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        # Cleanup
        session.cleanup()


if __name__ == "__main__":
    main()