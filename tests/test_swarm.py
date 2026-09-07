import os
import shutil
import tempfile
import unittest

from secops_swarm.config import SwarmConfig
from secops_swarm.orchestrator import SecOpsSwarmOrchestrator
from secops_swarm.scanner_agent import ThreatScannerAgent
from secops_swarm.verification_agent import ExploitVerificationAgent
from secops_swarm.patch_agent import PatchGeneratorAgent
from secops_swarm.guardrail_agent import SecurityGuardrailAgent

class TestSecOpsSwarm(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        
        # Create dummy sample application file with a target vulnerable function call
        self.sample_file = os.path.join(self.temp_dir, "app.py")
        with open(self.sample_file, "w", encoding="utf-8") as f:
            f.write("""
def parse_user_input(data):
    # Vulnerable target function callsite
    vulnerable_eval(data)

def vulnerable_eval(payload):
    return eval(payload)
""")

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_end_to_end_swarm_pipeline(self):
        config = SwarmConfig(repo_path=self.temp_dir)
        orchestrator = SecOpsSwarmOrchestrator(config)

        raw_advisory = {
            "cve_id": "CVE-2026-9999",
            "summary": "Remote Code Execution via vulnerable_eval() function call",
            "severity": "CRITICAL",
            "vulnerable_functions": ["vulnerable_eval"]
        }

        prs = orchestrator.process_advisory(raw_advisory)
        self.assertEqual(len(prs), 1)
        pr = prs[0]
        
        self.assertIn("CVE-2026-9999", pr.title)
        self.assertEqual(pr.branch_name, "secops-fix/cve_2026_9999")
        self.assertIn("app.py", pr.modified_files)

if __name__ == "__main__":
    unittest.main()
