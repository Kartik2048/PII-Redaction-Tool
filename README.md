# Enterprise PII Redaction Engine & Evaluation Tool

A decoupled, production-ready PII Redaction Engine built with **FastAPI**, **Presidio Analyzer**, **spaCy NER**, **Faker**, **python-docx**, and a modern **Next.js** frontend UI optimized for Vercel and Hugging Face Spaces deployment.

---

## 🚀 Architecture Overview

```
 ┌─────────────────────────────────────────────────────────┐
 │                   Next.js Frontend (Vercel)            │
 │  - Document Redactor (Drag-and-Drop .docx Upload)       │
 │  - Searchable Pseudonym Mapping Table                   │
 │  - Benchmark Evaluation Dashboard                       │
 └────────────────────────────┬────────────────────────────┘
                              │ HTTP / REST API
                              ▼
 ┌─────────────────────────────────────────────────────────┐
 │               FastAPI Backend (Hugging Face Spaces)     │
 │  - Presidio Analyzer Engine + spaCy (en_core_web_sm)    │
 │  - Custom Pattern Recognizers (Regex + Luhn Check)      │
 │  - Contextual Score Booster ("Promoter:", "CIN:")       │
 │  - Thread-Safe PseudonymMapper (Faker)                  │
 │  - Layout-Preserving Docx Redactor (Run-Level Engine)   │
 └─────────────────────────────────────────────────────────┘
```

---

## 💡 Core Approach

1. **Hybrid Detection Engine**:
   - **Deterministic Regex Rules**: Strict patterns for emails, phone numbers, IP addresses, credit cards, government/corporate IDs (US SSN, Indian PAN, Aadhaar, CIN), and dates.
   - **Luhn Algorithm Checksum**: Validates credit card number candidates (`validate_result`).
   - **Contextual Score Boosting**: Enhances `PERSON`, `ORGANIZATION`, and `LOCATION` entity confidence scores when legal/corporate triggers (`"Promoter:"`, `"Compliance Officer"`, `"Registered Office"`, `"Pvt Ltd"`, `"Limited"`, `"LLP"`, `"CIN:"`) appear in text proximity.

2. **Persistent Pseudonymization**:
   - Thread-safe `PseudonymMapper` dictionary backed by `Faker` and `threading.Lock()`.
   - Guarantees deterministic consistency: If `"Rashi Patil"` appears 10 times in a document, it maps to the exact same fake name throughout the execution lifecycle.

3. **Layout & Formatting Preservation (`python-docx`)**:
   - Iterates through `doc.paragraphs`, `doc.tables` (cell paragraphs and nested tables), and `doc.sections` (header/footer paragraphs and tables).
   - Performs **run-level text replacement** (`_apply_run_replacements`), processing replacements in reverse order of start index to preserve font families, bold, italics, font sizes, colors, and cell structures intact.

---

## 🔒 Supported PII Types

| Entity Type | Recognition Strategy | Example Input | Example Pseudonym Output |
| :--- | :--- | :--- | :--- |
| **FULL_NAMES / PERSON** | spaCy NER + Presidio + Context Booster | `Sarthak Malvadkar` | `John Doe` |
| **EMAIL** | Custom Regex (`\b[A-Za-z0-9._%+-]+@...`) | `cs.connect@kshinternational.com` | `john.doe@example.com` |
| **PHONE** | Custom Regex (`\+?\s*91...`) | `+91 22 4009 4400` | `(555) 019-2834` |
| **COMPANY_NAMES / ORG** | spaCy NER + Presidio + Legal Boosters | `KSH INTERNATIONAL LIMITED` | `Acme Corp` |
| **ADDRESSES / LOCATION** | spaCy NER + Presidio | `Birdewadi Pune` | `Springfield, IL` |
| **SSN_GOVT_ID** | Custom Regex (US SSN, PAN, Aadhaar, CIN) | `U28129PN1979PLC141032` | `ABC-12-3456` |
| **CREDIT_CARD** | Regex + Luhn Algorithm Validation | `4532-0151-1283-0366` | `4111-1111-1111-1111` |
| **DATE_OF_BIRTH** | Numeric & Textual Date Regex | `July 30, 1979` | `1992-05-14` |
| **IP_ADDRESS** | IPv4 Pattern Matching | `192.168.1.100` | `10.0.0.1` |

---

## ⚖️ Observed Tradeoffs & False Positives/Negatives

1. **Corporate Names vs General Nouns**:
   - In financial prospectuses, phrases like `"Waterloo Industrial Park VI Private Limited"` are long and complex. General NER models often misclassify alphanumeric corporate titles or break them into fragmented tokens. Adding contextual triggers (`"Promoter:"`, `"Registered Office"`) boosted recall significantly.
2. **Fragmented Phone Numbers & Spacing**:
   - Phone numbers in Indian prospectus documents often contain spaces (`"+ 91 20 45053237"` or `"+91 22 4009 4400"`). Custom regex pattern tuning was required to balance recall without catching numerical table values.
3. **SEBI Registration Numbers**:
   - Numbers like `"INM000013004"` resemble alphanumeric codes. Mapping them under `GOVT_ID` via custom pattern recognizers eliminated false negative misses.

---

## 🛠️ Local Execution Guide

### Prerequisites
- Python 3.10+
- Node.js 18+

### 1. Run Backend Server (Port 7860)
```bash
cd backend
python -m pip install -r requirements.txt
python -m spacy download en_core_web_sm

# Start FastAPI server via Uvicorn
uvicorn app.main:app --host 0.0.0.0 --port 7860 --reload
```
API Documentation will be available at `http://localhost:7860/docs`.

### 2. Run Test Suite
```bash
# Run unit & integration tests
python -m pytest backend/tests/
```

### 3. Run Frontend UI (Port 3000)
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:3000` in your browser.

---

## 🌐 Deployment Strategy

- **Backend**: Containerized via Docker (`backend/Dockerfile`) and ready for instant hosting on **Hugging Face Spaces** (exposing port `7860`).
- **Frontend**: Configured for zero-config automatic deployment on **Vercel** (`frontend/vercel.json`), with `NEXT_PUBLIC_API_URL` connecting to the production backend URL.
