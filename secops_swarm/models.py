from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

@dataclass
class VulnerabilityAdvisory:
    cve_id: str
    summary: str
    severity: str
    cwe_id: Optional[str] = None
    affected_package: Optional[str] = None
    vulnerable_functions: List[str] = field(default_factory=list)
    raw_payload: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Finding:
    advisory_id: str
    file_path: str
    line_number: int
    matched_pattern: str
    function_name: Optional[str] = None
    context_code: str = ""

@dataclass
class VerificationResult:
    finding: Finding
    is_reachable: bool
    reachability_path: List[str] = field(default_factory=list)
    reasoning: str = ""

@dataclass
class PatchCandidate:
    verification: VerificationResult
    modified_files: Dict[str, str] = field(default_factory=dict) # file_path -> new_content
    diff: str = ""
    generated_test_code: str = ""
    test_file_path: str = ""

@dataclass
class GuardrailResult:
    passed: bool
    syntax_valid: bool
    lint_passed: bool
    tests_passed: bool
    errors: List[str] = field(default_factory=list)

@dataclass
class PullRequestPayload:
    title: str
    branch_name: str
    body: str
    modified_files: Dict[str, str]
    test_files: Dict[str, str]
