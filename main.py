import argparse
import json
import os
import sys
from secops_swarm.config import SwarmConfig
from secops_swarm.orchestrator import SecOpsSwarmOrchestrator

def main():
    parser = argparse.ArgumentParser(description="Autonomous SecOps Agent Swarm CLI")
    parser.add_argument("--repo", default=".", help="Path to connected repository")
    parser.add_argument("--advisory-file", help="Path to JSON file containing raw CVE advisory")
    parser.add_argument("--cve", help="CVE ID (for quick manual testing)")
    parser.add_argument("--vulnerable-func", help="Vulnerable function name to target")
    
    args = parser.parse_args()

    config = SwarmConfig(repo_path=os.path.abspath(args.repo))
    orchestrator = SecOpsSwarmOrchestrator(config)

    raw_advisory = {}
    if args.advisory_file and os.path.exists(args.advisory_file):
        with open(args.advisory_file, "r", encoding="utf-8") as f:
            raw_advisory = json.load(f)
    elif args.cve:
        raw_advisory = {
            "cve_id": args.cve,
            "summary": f"Vulnerability in `{args.vulnerable_func}()`",
            "severity": "HIGH",
            "vulnerable_functions": [args.vulnerable_func] if args.vulnerable_func else []
        }
    else:
        print("Please provide --advisory-file or --cve")
        sys.exit(1)

    print(f"[*] Ingesting advisory for repo: {config.repo_path}")
    prs = orchestrator.process_advisory(raw_advisory)

    print(f"\n[+] Processing completed. Generated {len(prs)} Pull Request payloads:")
    for i, pr in enumerate(prs, 1):
        print(f"\n--- PR #{i}: {pr.title} ---")
        print(f"Branch: {pr.branch_name}")
        print(f"Body:\n{pr.body}")

if __name__ == "__main__":
    main()
