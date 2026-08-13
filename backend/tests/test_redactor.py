"""
Unit and Integration Tests for PII Redaction Engine (app/pii_redactor.py & app/redact_docx.py)
"""

import io
import os
import sys
import pytest
import docx

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.pii_redactor import PIIRedactor
from app.redact_docx import redact_docx_document, replace_in_runs


# ---------------------------------------------------------------------------
# 1. Test Deterministic Faker & Consistency
# ---------------------------------------------------------------------------
def test_deterministic_fake_consistency():
    redactor = PIIRedactor()

    # Same input string must always produce identical pseudonym
    fake1 = redactor.get_deterministic_fake("Rashi Patil", "full_name")
    fake2 = redactor.get_deterministic_fake("Rashi Patil", "full_name")
    fake3 = redactor.get_deterministic_fake("Rashi Patil", "full_name")
    assert fake1 == fake2 == fake3

    email1 = redactor.get_deterministic_fake("cs.connect@kshinternational.com", "email")
    email2 = redactor.get_deterministic_fake("cs.connect@kshinternational.com", "email")
    assert email1 == email2


# ---------------------------------------------------------------------------
# 2. Test Person and Company Validation
# ---------------------------------------------------------------------------
def test_person_and_company_validation():
    redactor = PIIRedactor()

    # Genuine person names
    assert redactor.is_valid_person_name("Kushal Subbayya Hegde") is True
    assert redactor.is_valid_person_name("Sarthak Malvadkar") is True

    # Generic words, statutory terms, numbers must NOT be accepted as person names
    assert redactor.is_valid_person_name("Corporate Officer") is False
    assert redactor.is_valid_person_name("1,528.00") is False
    assert redactor.is_valid_person_name("Equity Shares") is False
    assert redactor.is_valid_person_name("Securities and Exchange Board of India") is False

    # Commercial companies
    assert redactor.is_valid_company_name("Waterloo Industrial Park VI Private Limited") is True
    assert redactor.is_valid_company_name("Kirtane & Pandit LLP") is True
    assert redactor.is_valid_company_name("Acme Corp") is True

    # Authorities must NOT be treated as private company PII
    assert redactor.is_valid_company_name("Registrar of Companies") is False
    assert redactor.is_valid_company_name("Reserve Bank of India") is False


# ---------------------------------------------------------------------------
# 3. Test Structural Pattern Detection
# ---------------------------------------------------------------------------
def test_structural_pattern_detection():
    redactor = PIIRedactor()

    # Email
    detected = redactor.detect_pii("Contact us at support@example.com immediately.")
    assert "email" in detected
    assert "support@example.com" in detected["email"]

    # Phone
    detected = redactor.detect_pii("Call +91 9876543210 for details.")
    assert "phone" in detected

    # IP Address
    detected = redactor.detect_pii("Server IP is 192.168.1.100")
    assert "ip_address" in detected
    assert "192.168.1.100" in detected["ip_address"]

    # Govt IDs (PAN, CIN, SSN)
    detected = redactor.detect_pii("SSN: 123-45-6789, PAN: ABCDE1234F, CIN: L12345MH2020PLC123456")
    assert "ssn" in detected
    assert "cin_pan" in detected
    assert "ABCDE1234F" in detected["cin_pan"]
    assert "L12345MH2020PLC123456" in detected["cin_pan"]

    # Registration number
    detected = redactor.detect_pii("Registration INR000004058 and M-12345")
    assert "reg_no" in detected


# ---------------------------------------------------------------------------
# 4. Test Text Redaction with Replacements
# ---------------------------------------------------------------------------
def test_text_redaction():
    redactor = PIIRedactor()
    text = "Director Sarthak Malvadkar with PAN ABCDE1234F and SSN 123-45-6789."
    redacted = redactor.redact_text(text)

    assert "Sarthak Malvadkar" not in redacted
    assert "ABCDE1234F" not in redacted
    assert "123-45-6789" not in redacted


# ---------------------------------------------------------------------------
# 5. Integration Test: Full DOCX Redaction & Layout Preservation
# ---------------------------------------------------------------------------
def test_docx_redaction_and_layout_preservation():
    doc = docx.Document()

    # Header
    section = doc.sections[0]
    header_p = section.header.paragraphs[0]
    header_p.text = "Confidential Document - Contact: admin@company.com"

    # Paragraph with mixed formatting runs
    p1 = doc.add_paragraph()
    r1 = p1.add_run("Promoter: ")
    r1.bold = True
    r2 = p1.add_run("Rashi Patil")
    r3 = p1.add_run(" holds PAN ")
    r4 = p1.add_run("ABCDE1234F")
    r4.italic = True
    r5 = p1.add_run(" and email cs.connect@kshinternational.com.")

    # Table
    table = doc.add_table(rows=2, cols=2)
    table.cell(0, 0).paragraphs[0].text = "Officer Name"
    table.cell(0, 1).paragraphs[0].text = "Phone Number"
    table.cell(1, 0).paragraphs[0].text = "Compliance Officer: Rashi Patil"
    table.cell(1, 1).paragraphs[0].text = "+91 98765 43210"

    # Footer
    footer_p = section.footer.paragraphs[0]
    footer_p.text = "Registered Office: Mumbai. Date: 01/01/1985"

    # Save to bytes
    doc_bytes_io = io.BytesIO()
    doc.save(doc_bytes_io)
    input_bytes = doc_bytes_io.getvalue()

    # Redact DOCX document
    redacted_bytes, metadata = redact_docx_document(input_bytes)

    # 1. Verify Metadata
    assert metadata["total_entities_found"] > 0
    assert len(metadata["pseudonym_mappings"]) > 0

    # 2. Reload redacted docx
    redacted_doc = docx.Document(io.BytesIO(redacted_bytes))

    full_redacted_text = ""
    for p in redacted_doc.paragraphs:
        full_redacted_text += p.text + "\n"
    for table in redacted_doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for p in cell.paragraphs:
                    full_redacted_text += p.text + "\n"

    # Verify sensitive data was redacted
    assert "ABCDE1234F" not in full_redacted_text
    assert "cs.connect@kshinternational.com" not in full_redacted_text
