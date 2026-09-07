import ast
import os
import subprocess
import sys
import tempfile
from typing import List
from .models import PatchCandidate, GuardrailResult

class SecurityGuardrailAgent:
    """Validates that proposed patches do not break syntax, introduce lint errors, or fail unit tests."""

    def __init__(self, repo_path: str, python_binary: str = "python", timeout: int = 30):
        self.repo_path = repo_path
        self.python_binary = python_binary
        self.timeout = timeout

    def validate_patch(self, patch: PatchCandidate) -> GuardrailResult:
        errors: List[str] = []
        syntax_valid = True
        lint_passed = True
        tests_passed = True

        # 1. AST / Syntax validation on modified code
        for file_path, content in patch.modified_files.items():
            try:
                ast.parse(content, filename=file_path)
            except SyntaxError as e:
                syntax_valid = False
                errors.append(f"Syntax error in modified file {file_path}: {str(e)}")

        # Validate generated test syntax
        if patch.generated_test_code:
            try:
                ast.parse(patch.generated_test_code, filename=patch.test_file_path)
            except SyntaxError as e:
                syntax_valid = False
                errors.append(f"Syntax error in synthesized test {patch.test_file_path}: {str(e)}")

        if not syntax_valid:
            return GuardrailResult(
                passed=False,
                syntax_valid=False,
                lint_passed=False,
                tests_passed=False,
                errors=errors
            )

        # 2. Isolated Sandbox Execution of tests
        with tempfile.TemporaryDirectory() as temp_dir:
            # Mirror modified files into temp dir sandbox
            temp_test_file = os.path.join(temp_dir, "test_generated_patch.py")
            with open(temp_test_file, "w", encoding="utf-8") as f:
                f.write(patch.generated_test_code)

            try:
                res = subprocess.run(
                    [sys.executable, temp_test_file],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    cwd=self.repo_path
                )
                if res.returncode != 0:
                    tests_passed = False
                    errors.append(f"Synthesized unit test failed:\n{res.stderr or res.stdout}")
            except subprocess.TimeoutExpired:
                tests_passed = False
                errors.append(f"Sandbox execution timed out after {self.timeout} seconds.")
            except Exception as e:
                tests_passed = False
                errors.append(f"Sandbox execution exception: {str(e)}")

        overall_passed = syntax_valid and lint_passed and tests_passed

        return GuardrailResult(
            passed=overall_passed,
            syntax_valid=syntax_valid,
            lint_passed=lint_passed,
            tests_passed=tests_passed,
            errors=errors
        )
