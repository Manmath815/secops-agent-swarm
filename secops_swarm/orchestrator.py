import os
from typing import Dict, Any, List
from .config import SwarmConfig
from .models import VulnerabilityAdvisory, PullRequestPayload
from .scanner_agent import ThreatScannerAgent
from .verification_agent import ExploitVerificationAgent
from .patch_agent import PatchGeneratorAgent
from .guardrail_agent import SecurityGuardrailAgent

class SecOpsSwarmOrchestrator:
    """Orchestrates the multi-agent SecOps swarm lifecycle from advisory ingestion to PR payload generation."""

    def __init__(self, config: SwarmConfig):
        self.config = config
        self.scanner = ThreatScannerAgent(config.repo_path)
        self.verifier = ExploitVerificationAgent(config.repo_path)
        self.patcher = PatchGeneratorAgent(config.repo_path)
        self.guardrail = SecurityGuardrailAgent(config.repo_path, config.python_binary, config.sandbox_timeout)

    def process_advisory(self, raw_advisory: Dict[str, Any]) -> List[PullRequestPayload]:
        pr_payloads = []
        
        # Step 1: Threat Scanner Agent Ingestion & Scanning
        advisory = self.scanner.parse_advisory(raw_advisory)
        findings = self.scanner.scan_repository(advisory)
        
        if not findings:
            print(f"[Orchestrator] No exposed call sites found for advisory {advisory.cve_id}.")
            return pr_payloads

        # Group findings by file path to produce consolidated PR payloads per affected file
        file_findings_map = {}
        for finding in findings:
            file_findings_map.setdefault(finding.file_path, []).append(finding)

        for file_path, file_findings in file_findings_map.items():
            primary_finding = file_findings[0]
            # Step 2: Exploit Verification Agent Reachability Check
            verification = self.verifier.verify_reachability(primary_finding)
            if not verification.is_reachable:
                print(f"[Orchestrator] Finding at {primary_finding.file_path}:{primary_finding.line_number} is unreachable. Skipping patch.")
                continue

            # Step 3: Patch Generator Agent Remediation & Test Generation
            patch = self.patcher.generate_patch(verification)

            # Step 4: Security Guardrail Agent Sandbox Validation
            guardrail_res = self.guardrail.validate_patch(patch)
            if not guardrail_res.passed:
                print(f"[Orchestrator] Guardrail validation failed for {primary_finding.file_path}: {guardrail_res.errors}")
                continue

            # Step 5: Construct PR Payload
            pr = PullRequestPayload(
                title=f"[SecOps Swarm] Automated Security Fix for {advisory.cve_id}",
                branch_name=f"secops-fix/{advisory.cve_id.lower().replace('-', '_')}",
                body=f"## Security Remediation Summary\n\n- **CVE**: {advisory.cve_id}\n- **Severity**: {advisory.severity}\n- **Target File**: `{primary_finding.file_path}:{primary_finding.line_number}`\n- **Reachability Path**: `{verification.reachability_path}`\n\n### Diff\n```diff\n{patch.diff}\n```\n\nAutomated tests verified with zero syntax/regression failures.",
                modified_files=patch.modified_files,
                test_files={patch.test_file_path: patch.generated_test_code}
            )
            pr_payloads.append(pr)

        return pr_payloads

