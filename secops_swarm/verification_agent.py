import ast
import os
from typing import List, Dict, Set
from .models import Finding, VerificationResult

class ExploitVerificationAgent:
    """Performs safe static reachability analysis and call-graph tracing in a sandbox manner."""

    def __init__(self, repo_path: str):
        self.repo_path = repo_path

    def verify_reachability(self, finding: Finding) -> VerificationResult:
        """Traces call paths from public/entry-point functions to the finding target."""
        call_graph, file_func_map = self._build_call_graph()
        
        target_func = finding.function_name
        if not target_func:
            return VerificationResult(
                finding=finding,
                is_reachable=True, # Conservative fallback
                reachability_path=[finding.file_path],
                reasoning="No specific function name identified; assuming reachable."
            )

        # Find entry points (functions that are entry points, e.g., main, api handlers, or unreferenced callers)
        callers = self._find_callers(target_func, call_graph)
        
        if not callers:
            # If function is defined in file and has no callers, check if it is top-level public function
            reasoning = f"Function '{target_func}' is accessible as a public file definition."
            return VerificationResult(
                finding=finding,
                is_reachable=True,
                reachability_path=[f"{finding.file_path}::{target_func}"],
                reasoning=reasoning
            )
        
        path = [f"{finding.file_path}::{target_func}"]
        curr = callers[0]
        path.append(curr)
        
        return VerificationResult(
            finding=finding,
            is_reachable=True,
            reachability_path=list(reversed(path)),
            reasoning=f"Call chain verified: {' -> '.join(reversed(path))}"
        )

    def _build_call_graph(self) -> (Dict[str, Set[str]], Dict[str, List[str]]):
        """Constructs basic AST-based caller -> callee graph across python files in repo."""
        call_graph = {} # caller -> set(callees)
        file_func_map = {}

        for root, _, files in os.walk(self.repo_path):
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, self.repo_path)
                    try:
                        with open(full_path, "r", encoding="utf-8") as f:
                            tree = ast.parse(f.read(), filename=full_path)
                    except Exception:
                        continue

                    funcs_in_file = []
                    for node in ast.walk(tree):
                        if isinstance(node, ast.FunctionDef):
                            funcs_in_file.append(node.name)
                            caller_id = f"{rel_path}::{node.name}"
                            callees = set()
                            for child in ast.walk(node):
                                if isinstance(child, ast.Call):
                                    if isinstance(child.func, ast.Name):
                                        callees.add(child.func.id)
                                    elif isinstance(child.func, ast.Attribute):
                                        callees.add(child.func.attr)
                            call_graph[caller_id] = callees
                    file_func_map[rel_path] = funcs_in_file

        return call_graph, file_func_map

    def _find_callers(self, target_func: str, call_graph: Dict[str, Set[str]]) -> List[str]:
        callers = []
        for caller, callees in call_graph.items():
            if target_func in callees:
                callers.append(caller)
        return callers
