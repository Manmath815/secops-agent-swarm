import http.server
import socketserver
import json
import os
import sys
from urllib.parse import parse_qs, urlparse

from secops_swarm.config import SwarmConfig
from secops_swarm.orchestrator import SecOpsSwarmOrchestrator

PORT = 8000
REPO_DIR = os.path.abspath(".")
config = SwarmConfig(repo_path=REPO_DIR)
orchestrator = SecOpsSwarmOrchestrator(config)

class SecOpsHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/api/scan':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            try:
                raw_advisory = json.loads(post_data.decode('utf-8'))
                
                # Execute full SecOps Swarm pipeline live
                prs = orchestrator.process_advisory(raw_advisory)
                
                response_payload = {
                    "success": True,
                    "cve_id": raw_advisory.get("cve_id", "CVE-UNKNOWN"),
                    "prs_generated": len(prs),
                    "prs": [
                        {
                            "title": pr.title,
                            "branch_name": pr.branch_name,
                            "body": pr.body,
                            "modified_files": pr.modified_files,
                            "test_files": pr.test_files
                        } for pr in prs
                    ]
                }
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(response_payload).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": str(e)}).encode('utf-8'))
        else:
            self.send_error(404, "Endpoint not found")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        # Serve static files (index.html, etc)
        super().do_GET()

def run_server():
    with socketserver.TCPServer(("", PORT), SecOpsHandler) as httpd:
        print(f"[*] SecOps Agent Swarm Backend Server running on http://localhost:{PORT}")
        httpd.serve_forever()

if __name__ == "__main__":
    run_server()
