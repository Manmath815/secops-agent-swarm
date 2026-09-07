import os
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class SwarmConfig:
    repo_path: str = "."
    sandbox_timeout: int = 30
    python_binary: str = "python"
    allowed_cwe_rules: List[str] = field(default_factory=lambda: [
        "CWE-89",   # SQL Injection
        "CWE-79",   # Cross-site Scripting
        "CWE-22",   # Path Traversal
        "CWE-78",   # OS Command Injection
        "CWE-502",  # Deserialization of Untrusted Data
    ])
    auto_create_pr: bool = True
