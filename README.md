# Autonomous SecOps Agent Swarm

An event-driven multi-agent Security Operations (SecOps) system in Python that ingests vulnerability advisories (CVE/OSV), performs safe AST-based reachability analysis, synthesizes code remediation patches with unit tests, and verifies safety via an isolated sandbox guardrail.

## Architecture & Agents

- **Threat Scanner Agent (`secops_swarm/scanner_agent.py`)**: Ingests vulnerability advisories and scans target repository code AST for exposed functions and call sites.
- **Exploit Verification Agent (`secops_swarm/verification_agent.py`)**: Builds an in-memory call graph to verify if vulnerable function calls are reachable from application entry points.
- **Patch Generator Agent (`secops_swarm/patch_agent.py`)**: Synthesizes remediation guards around vulnerable line contexts and auto-generates unit test cases (`tests/test_fix_*.py`).
- **Security Guardrail Agent (`secops_swarm/guardrail_agent.py`)**: Validates AST syntax and executes test suites in an isolated temporary subprocess sandbox.
- **Swarm Orchestrator (`secops_swarm/orchestrator.py`)**: Drives the multi-agent pipeline lifecycle and outputs structured Pull Request payloads.

## Installation & Setup

```bash
# Clone repository
git clone https://github.com/<YOUR-USERNAME>/<YOUR-REPO-NAME>.git
cd <YOUR-REPO-NAME>
```

## Usage

Run the swarm CLI on a target repository with a CVE advisory payload:

```bash
python main.py --repo . --cve CVE-2026-9999 --vulnerable-func vulnerable_eval
```

## Running Tests

Run the full unit test suite:

```bash
python -m unittest discover tests
```
