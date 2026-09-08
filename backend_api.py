import os
import sys
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

from secops_swarm.config import SwarmConfig
from secops_swarm.orchestrator import SecOpsSwarmOrchestrator

app = FastAPI(
    title="Autonomous SecOps Agent Swarm API",
    description="REST API for vulnerability reachability analysis, automated patch synthesis, and sandbox verification.",
    version="1.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

config = SwarmConfig(repo_path=os.path.abspath("."))
orchestrator = SecOpsSwarmOrchestrator(config)

class AdvisoryRequest(BaseModel):
    cve_id: str = Field(..., example="CVE-2026-9999")
    summary: str = Field(..., example="Remote Code Execution vulnerability in vulnerable_eval()")
    severity: str = Field(default="HIGH", example="HIGH")
    cwe_id: Optional[str] = Field(default="CWE-78", example="CWE-78")
    affected_package: Optional[str] = None
    vulnerable_functions: List[str] = Field(default_factory=list, example=["vulnerable_eval"])

class PullRequestResponse(BaseModel):
    title: str
    branch_name: str
    body: str
    modified_files: Dict[str, str]
    test_files: Dict[str, str]

class ScanResponse(BaseModel):
    success: bool
    cve_id: str
    prs_generated: int
    prs: List[PullRequestResponse]

@app.get("/")
def health_check():
    return {
        "status": "online",
        "service": "Autonomous SecOps Agent Swarm API",
        "agents": ["ThreatScanner", "ExploitVerification", "PatchGenerator", "SecurityGuardrail"]
    }

@app.post("/api/scan", response_model=ScanResponse)
def scan_and_remediate(advisory: AdvisoryRequest):
    try:
        raw_advisory = advisory.model_dump()
        prs = orchestrator.process_advisory(raw_advisory)
        
        pr_responses = [
            PullRequestResponse(
                title=pr.title,
                branch_name=pr.branch_name,
                body=pr.body,
                modified_files=pr.modified_files,
                test_files=pr.test_files
            ) for pr in prs
        ]

        return ScanResponse(
            success=True,
            cve_id=advisory.cve_id,
            prs_generated=len(prs),
            prs=pr_responses
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
