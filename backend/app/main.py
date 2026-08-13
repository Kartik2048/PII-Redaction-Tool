"""
FastAPI Backend Server (main.py)

Exposes REST endpoints for PII Redaction (/redact), Health Monitoring (/health),
API Info (/), and Evaluation Metrics (/evaluate).
"""

import base64
import io
import os
import sys
from typing import Optional

from fastapi import FastAPI, File, UploadFile, Query, Form, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, JSONResponse

# Ensure backend root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.redactor import redact_document
from app.evaluator import evaluate_redaction_engine

app = FastAPI(
    title="PII Redaction Engine API",
    description="Backend API for PII detection, pseudonym redaction, and evaluation metrics.",
    version="1.0.0",
)

# Enable CORS Middleware
origins = ["*"]
frontend_url = os.getenv("FRONTEND_URL")
if frontend_url:
    origins.append(frontend_url)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)


@app.get("/", tags=["Info"])
def root_info():
    """Health check & API root endpoint."""
    return {
        "status": "online",
        "app": "PII Redaction Engine API",
        "version": "1.0.0",
        "docs_url": "/docs",
    }


@app.get("/health", tags=["Health"])
def health_check():
    """Container health monitoring endpoint for Hugging Face / Render Spaces."""
    return {"status": "healthy"}


@app.post("/redact", tags=["Redaction"])
async def redact_docx_endpoint(
    file: UploadFile = File(...),
    return_metadata: bool = Query(
        False, description="Set to true to receive JSON metadata alongside redacted file base64"
    ),
    spacy_model: str = Query("en_core_web_sm", description="spaCy language model to load"),
):
    """
    Accepts a .docx file upload, redacts all detected PII entities with persistent
    pseudonym mapping while preserving run formatting, and returns redacted file or metadata.
    """
    if not file.filename or not file.filename.lower().endswith(".docx"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Only Microsoft Word (.docx) documents are supported.",
        )

    content = await file.read()
    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    try:
        redacted_bytes, metadata = redact_document(
            doc_input=content, spacy_model=spacy_model
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Redaction processing failed: {str(e)}",
        )

    if return_metadata:
        encoded_doc = base64.b64encode(redacted_bytes).decode("utf-8")
        return {
            "filename": file.filename,
            "redacted_filename": f"redacted_{file.filename}",
            "redacted_file_base64": encoded_doc,
            "metadata": metadata,
        }

    # Default binary download response
    out_filename = f"redacted_{file.filename}"
    return Response(
        content=redacted_bytes,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={
            "Content-Disposition": f'attachment; filename="{out_filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )


@app.get("/evaluate", tags=["Evaluation"])
def evaluate_endpoint():
    """
    Triggers evaluation of the redaction engine against the Red Herring Prospectus
    ground truth benchmark dataset and returns Precision, Recall, F1, and per-entity metrics.
    """
    try:
        report = evaluate_redaction_engine()
        return report
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Evaluation failed: {str(e)}",
        )
