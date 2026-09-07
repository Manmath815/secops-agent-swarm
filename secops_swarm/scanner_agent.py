import ast
import os
import re
from typing import List, Dict, Any
from .models import VulnerabilityAdvisory, Finding

class ThreatScannerAgent:
    """Parses incoming CVE advisories and scans target repository AST for exposed vulnerable functions/patterns."""

    def __init__(self, repo_path: str):
        self.repo_path = repo_path

    def parse_advisory(self, raw_data: Dict[str, Any]) -> VulnerabilityAdvisory:
        cve_id = raw_data.get("id") or raw_data.get("cve_id", "CVE-UNKNOWN")
        summary = raw_data.get("summary") or raw_data.get("details", "")
        severity = raw_data.get("severity", "MEDIUM")
        cwe_id = raw_data.get("cwe_id")
        
        # Parse vulnerable functions if available
        vulnerable_functions = raw_data.get("vulnerable_functions", [])
        if not vulnerable_functions and summary:
            # Fallback heuristic: match function names mentioned in summary
            matches = re.findall(r'`([a-zA-Z0-9_]+)\(\)`', summary)
            if matches:
                vulnerable_functions = list(set(matches))

        return VulnerabilityAdvisory(
            cve_id=cve_id,
            summary=summary,
            severity=severity,
            cwe_id=cwe_id,
            affected_package=raw_data.get("affected_package"),
            vulnerable_functions=vulnerable_functions,
            raw_payload=raw_data
        )

    def scan_repository(self, advisory: VulnerabilityAdvisory) -> List[Finding]:
        findings = []
        for root, _, files in os.walk(self.repo_path):
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, self.repo_path)
                    file_findings = self._scan_file(rel_path, full_path, advisory)
                    findings.extend(file_findings)
        return findings

    def _scan_file(self, rel_path: str, full_path: str, advisory: VulnerabilityAdvisory) -> List[Finding]:
        findings = []
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()
            tree = ast.parse(content, filename=full_path)
        except Exception:
            return findings

        lines = content.splitlines()

        for node in ast.walk(tree):
            # 1. Match specific vulnerable function names if listed in advisory
            if isinstance(node, ast.FunctionDef):
                if node.name in advisory.vulnerable_functions:
                    line_no = node.lineno
                    ctx = lines[line_no - 1] if line_no <= len(lines) else ""
                    findings.append(Finding(
                        advisory_id=advisory.cve_id,
                        file_path=rel_path,
                        line_number=line_no,
                        matched_pattern=f"Function definition match: {node.name}",
                        function_name=node.name,
                        context_code=ctx.strip()
                    ))
            
            # 2. Match function calls to vulnerable target functions
            elif isinstance(node, ast.Call):
                func_name = None
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                
                if func_name and func_name in advisory.vulnerable_functions:
                    line_no = node.lineno
                    ctx = lines[line_no - 1] if line_no <= len(lines) else ""
                    findings.append(Finding(
                        advisory_id=advisory.cve_id,
                        file_path=rel_path,
                        line_number=line_no,
                        matched_pattern=f"Function call match: {func_name}",
                        function_name=func_name,
                        context_code=ctx.strip()
                    ))

        return findings
