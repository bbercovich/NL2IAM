#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Basic CLI Test - Tests CLI functionality without requiring model loading

This script tests the CLI structure and basic functionality without loading
the heavy models, which is useful for quick validation.
"""

import sys
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch

# Add src to path
sys.path.append('src')

try:
    from nl2iam_cli import NL2IAMSession
    print("✓ Successfully imported NL2IAMSession")
except ImportError as e:
    print(f"✗ Failed to import CLI: {e}")
    sys.exit(1)


def test_session_creation():
    """Test basic session creation"""
    print("Testing session creation...")

    try:
        session = NL2IAMSession(debug_mode=True)
        assert session.debug_mode == True
        assert session.initialized == False
        assert session.policies_created == 0
        print("✓ Session creation works")
        return True
    except Exception as e:
        print(f"✗ Session creation failed: {e}")
        return False


def test_inventory_path_handling():
    """Test inventory path handling"""
    print("🧪 Testing inventory path handling...")

    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            test_inventory = {"policies": []}
            json.dump(test_inventory, f)
            temp_path = f.name

        session = NL2IAMSession(inventory_path=temp_path)
        assert session.inventory_path == temp_path
        print("✅ Inventory path handling works")

        # Cleanup
        Path(temp_path).unlink()
        return True
    except Exception as e:
        print(f"❌ Inventory path handling failed: {e}")
        return False


def test_help_functionality():
    """Test help display functionality"""
    print("🧪 Testing help functionality...")

    try:
        session = NL2IAMSession()

        # Capture output (in real test, this would just print)
        session.show_help()
        print("✅ Help functionality works")
        return True
    except Exception as e:
        print(f"❌ Help functionality failed: {e}")
        return False


def test_import_dependencies():
    """Test that all required dependencies can be imported"""
    print("🧪 Testing dependency imports...")

    required_imports = [
        'models.model_manager',
        'agents.translator',
        'agents.policy_generator',
        'agents.redundancy_checker',
        'agents.conflict_checker',
        'rag.rag_engine'
    ]

    failed_imports = []

    for module in required_imports:
        try:
            __import__(module)
            print(f"   ✅ {module}")
        except ImportError as e:
            print(f"   ❌ {module}: {e}")
            failed_imports.append(module)

    if failed_imports:
        print(f"❌ Failed to import {len(failed_imports)} modules")
        return False
    else:
        print("✅ All dependencies imported successfully")
        return True


def main():
    """Run basic CLI tests"""
    print("🧪 Running Basic CLI Tests")
    print("=" * 50)
    print("These tests validate CLI structure without loading models.\n")

    tests = [
        test_import_dependencies,
        test_session_creation,
        test_inventory_path_handling,
        test_help_functionality
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1
        print()

    print("=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All basic tests passed! CLI structure is working correctly.")
        print("\n💡 Next step: Test with full models on your GPU box:")
        print("   python nl2iam_cli.py --debug")
        return True
    else:
        print("❌ Some tests failed. Please fix issues before testing with models.")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)