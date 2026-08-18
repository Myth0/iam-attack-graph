"""
API layer for the IAM Attack Path Grapher.

Thin, stateless FastAPI wrapper around the engine. No database,
no file persistence — every request is processed entirely in
memory and discarded after the response is sent (see THREAT_MODEL.md).
"""

from __future__ import annotations
import json
import sys
from pathlib import Path

# Ensure repo root is importable regardless of Vercel's working directory
sys.path.append(str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from engine.parser import parse_iam_export
from engine.graph_builder import build_graph
from engine.analyzer import analyze

MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB — real IAM exports are far smaller

app = FastAPI(
    title="IAM Attack Path Grapher API",
    description="Analyzes AWS IAM exports for privilege escalation paths. "
                 "Stateless: nothing uploaded is stored.",
    version="0.1.0",
)

# Frontend will run on a different origin during local dev; tighten
# this to the real deployed frontend origin before going live.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: restrict at deployment time (Stage 6)
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict:
    """Trivial liveness check for hosting platform + CI."""
    return {"status": "ok"}


@app.post("/analyze")
async def analyze_iam_export(file: UploadFile = File(...)) -> dict:
    """
    Accept an IAM export JSON file, run the full analysis pipeline,
    and return findings + graph data. Nothing is written to disk.
    """
    contents = await file.read()

    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 5MB).")

    try:
        data = json.loads(contents)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")

    try:
        principals = parse_iam_export(data)
    except Exception as e:
        # Pydantic validation errors, missing keys, etc. — never leak
        # a raw stack trace to the client.
        raise HTTPException(status_code=400, detail=f"Could not parse IAM export: {e}")

    graph = build_graph(principals)
    findings = analyze(principals, graph)

    return {
        "summary": {
            "principal_count": len(principals),
            "relationship_count": graph.number_of_edges(),
            "finding_count": len(findings),
        },
        "findings": [
            {
                "principal_arn": f.principal_arn,
                "principal_name": f.principal_name,
                "technique_id": f.technique_id,
                "technique_name": f.technique_name,
                "severity": f.severity,
                "description": f.description,
            }
            for f in findings
        ],
        "graph": {
            "nodes": [
                {"id": arn, "name": data["name"], "type": data["type"]}
                for arn, data in graph.nodes(data=True)
            ],
            "edges": [
                {"source": u, "target": v, "relationship": d["relationship"]}
                for u, v, d in graph.edges(data=True)
            ],
        },
    }
