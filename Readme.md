# 🛡️ Quantum-Proof Cryptographic Scanner

> **"Quantum-Ready Cybersecurity for Future-Safe Banking"**
>
> Punjab National Bank — Cybersecurity Hackathon 2025-26

A full-stack software scanner that validates deployment of **quantum-proof ciphers** across public-facing applications and generates a **Cryptographic Bill of Materials (CBOM)** inventory — enabling PNB to proactively defend against *Harvest Now, Decrypt Later* (HNDL) quantum threats.

---

## Table of Contents

1. [Problem Statement](#problem-statement)
2. [Solution Overview](#solution-overview)
3. [Architecture](#architecture)
4. [Key Features](#key-features)
5. [Tech Stack](#tech-stack)
6. [Project Structure](#project-structure)
7. [Setup & Installation](#setup--installation)
8. [Usage & Demo Walkthrough](#usage--demo-walkthrough)
9. [API Reference](#api-reference)
10. [Deliverables Mapping](#deliverables-mapping)
11. [Testing](#testing)
12. [PQC Standards Referenced](#pqc-standards-referenced)

---

## Problem Statement

> *To develop a software scanner to validate deployment of Quantum-proof cipher and create cryptographic bill of material inventory for public facing applications (Web Server, API, System).*

Banks face a systemic vulnerability: adversaries can intercept encrypted data today and decrypt it once Cryptanalytically Relevant Quantum Computers (CRQCs) emerge. This solution provides complete cryptographic visibility, risk assessment, and a clear migration path to post-quantum safety.

---

## Solution Overview

```
┌─────────────────┐     ┌──────────────────────────────────────────────────┐
│   React Frontend │────▶│              FastAPI Backend                     │
│   (Dashboard)    │◀────│                                                  │
└─────────────────┘     │  ┌─────────────┐  ┌──────────────┐              │
                        │  │ TLS Scanner  │  │ PQC Classifier│              │
                        │  │ (sslyze)     │  │              │              │
                        │  └──────┬───────┘  └──────┬───────┘              │
                        │         │                  │                      │
                        │  ┌──────▼──────────────────▼───────┐             │
                        │  │      Scoring Engine (0-100)      │             │
                        │  └──────┬──────────────────┬───────┘             │
                        │         │                  │                      │
                        │  ┌──────▼───────┐  ┌──────▼───────┐             │
                        │  │ CBOM Generator│  │  Recommender  │             │
                        │  │ (CycloneDX)   │  │ (PQC Migration)│            │
                        │  └──────────────┘  └──────────────┘             │
                        │  ┌──────────────┐  ┌──────────────┐             │
                        │  │ HNDL Risk    │  │  Compliance   │             │
                        │  │ Calculator   │  │  (RBI/NIST/..)│             │
                        │  └──────────────┘  └──────────────┘             │
                        │  ┌──────────────┐  ┌──────────────┐             │
                        │  │ Report Gen   │  │ Badge/Label   │             │
                        │  │ (HTML/PDF)   │  │ Generator     │             │
                        │  └──────────────┘  └──────────────┘             │
                        │                    ┌──────────────┐             │
                        │                    │  SQLite DB    │             │
                        │                    └──────────────┘             │
                        └──────────────────────────────────────────────────┘
```

### How It Works

1. **Input**: User provides target hostnames/IPs (single, multiple, or CSV upload)
2. **Scan**: TLS scanner probes each target across TLS 1.0 → 1.3 using sslyze, extracting certificates, cipher suites, key exchange algorithms, and signature algorithms
3. **Classify**: PQC classifier evaluates each cryptographic component against NIST post-quantum standards
4. **Score**: Scoring engine computes a 0-100 Quantum Readiness Score with weighted categories
5. **Output**: CBOM, recommendations, compliance reports, risk timelines, and certificate badges are generated

---

## Key Features

### Core Capabilities

| Feature | Description |
|---------|-------------|
| **TLS Scanning** | Deep TLS 1.0–1.3 probing via sslyze — extracts certs, cipher suites, key exchange, signature algos |
| **CBOM Generation** | CycloneDX v1.6 JSON output — standardized cryptographic bill of materials |
| **Quantum Readiness Score** | 0-100 weighted score: TLS version (25%), Key Exchange (35%), Symmetric Cipher (15%), Signature (25%) |
| **PQC Classification** | Every crypto component classified: PQC Ready / Quantum-Safe / Vulnerable / Deprecated |
| **Migration Recommendations** | Specific PQC algorithm recommendations with NIST FIPS references (ML-KEM, ML-DSA, SLH-DSA) |
| **Certificate Labels** | "PQC Ready" / "Quantum-Safe" / "At Risk" / "Critical" SVG badges per asset |
| **Parallel Scanning** | Concurrent scanning of multiple targets using ThreadPoolExecutor (up to 8 workers) |

### Advanced Capabilities

| Feature | Description |
|---------|-------------|
| **HNDL Risk Timeline** | Estimates when each algorithm becomes vulnerable based on CRQC arrival projections (2028-2042) |
| **Data Exposure Modeling** | Maps banking data types (PII, transactions, credentials) against quantum threat windows |
| **Regulatory Compliance** | Automated compliance checks: RBI IT Framework, PCI-DSS v4.0, NIST CSF v2.0, CERT-In |
| **HTML Reports** | Print-ready HTML reports with full scan results, suitable for PDF export |
| **Bulk CSV Upload** | Upload CSV of targets for batch scanning |
| **Interactive Dashboard** | Real-time charts showing quantum readiness distribution, score trends, and compliance overview |

### Scoring Labels

| Score Range | Label | Meaning |
|-------------|-------|---------|
| 90 – 100 | **PQC Ready** 🟢 | Fully quantum-safe, NIST PQC algorithms deployed |
| 60 – 89 | **Quantum-Safe** 🔵 | Strong classical crypto, not yet PQC |
| 30 – 59 | **At Risk** 🟡 | Vulnerable to near-term quantum threats |
| 0 – 29 | **Critical** 🔴 | Immediate migration required |

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| **Backend** | Python 3.12, FastAPI, SQLAlchemy, sslyze, cryptography |
| **Frontend** | React 19, Vite 7, TailwindCSS 4, Recharts, React Router |
| **Database** | SQLite (zero-config, portable) |
| **CBOM Standard** | CycloneDX v1.6 |
| **PQC Standards** | NIST FIPS 203, 204, 205, 206 |
| **Testing** | pytest (45 unit tests) |

---

## Project Structure

```
PnB Hackathon/
├── backend/
│   ├── main.py                    # FastAPI app — 15+ REST endpoints
│   ├── requirements.txt           # Python dependencies
│   ├── scanner/
│   │   └── tls_scanner.py         # TLS 1.0-1.3 probing engine (sslyze)
│   ├── analysis/
│   │   ├── scoring.py             # 0-100 quantum readiness scoring
│   │   ├── pqc_classifier.py      # Quantum safety classification
│   │   ├── recommender.py         # PQC migration recommendations
│   │   ├── hndl_risk.py           # HNDL risk timeline calculator
│   │   ├── compliance.py          # Regulatory compliance mapping
│   │   ├── report_generator.py    # HTML report generator
│   │   └── badge_generator.py     # SVG certificate badge generator
│   ├── cbom/
│   │   └── generator.py           # CycloneDX v1.6 CBOM generator
│   ├── models/
│   │   ├── database.py            # SQLAlchemy ORM (Scan, Asset)
│   │   └── schemas.py             # Pydantic request/response schemas
│   └── tests/
│       └── test_analysis.py       # 45 unit tests (pytest)
├── frontend/
│   ├── src/
│   │   ├── App.jsx                # Root app — routing, layout, navigation
│   │   ├── api/client.js          # Axios API client (12 endpoints)
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx      # Overview — pie chart, line chart, stats
│   │   │   ├── Scans.jsx          # Launch scans, view history
│   │   │   ├── Assets.jsx         # Asset inventory with scores & labels
│   │   │   ├── CBOM.jsx           # CycloneDX CBOM viewer/exporter
│   │   │   ├── Recommendations.jsx # PQC migration action items
│   │   │   ├── HNDLRisk.jsx       # HNDL risk timeline dashboard
│   │   │   └── Compliance.jsx     # Regulatory compliance viewer
│   │   └── components/
│   │       ├── ScoreCard.jsx      # Circular score visualization
│   │       ├── LabelBadge.jsx     # Quantum readiness label badges
│   │       └── Toast.jsx          # Toast notification system
│   └── package.json
└── Readme.md
```

---

## Setup & Installation

### Prerequisites

- **Python 3.10+** (tested with 3.12)
- **Node.js 18+** and npm

### 1. Clone & Create Virtual Environment

```bash
git clone <repository-url>
cd "PnB Hackathon"
python3 -m venv PnB-env
source PnB-env/bin/activate
```

### 2. Install Backend Dependencies

```bash
cd backend
pip install -r requirements.txt
pip install python-multipart   # Required for CSV upload
```

### 3. Start Backend Server

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The API is now live at `http://localhost:8000`. Interactive docs at `http://localhost:8000/docs`.

### 4. Install Frontend Dependencies

```bash
cd ../frontend
npm install
```

### 5. Start Frontend Dev Server

```bash
npm run dev
```

Dashboard is now live at `http://localhost:5173`.

---

## Usage & Demo Walkthrough

### Quick Scan (Single Target)

1. Open `http://localhost:5173` in your browser
2. Navigate to the **Scans** page
3. Enter target hostname(s) — e.g., `google.com, github.com, pnbindia.in`
4. Click **Start Scan** — targets are scanned in parallel
5. Results appear with quantum readiness scores and labels

### Bulk Scan (CSV Upload)

1. Prepare a CSV file with a `hostname` column:
   ```csv
   hostname
   google.com
   github.com
   pnbindia.in
   onlinesbi.sbi
   ```
2. Go to **Scans** page → Upload CSV
3. All targets are scanned in parallel with results saved to the database

### Explore Results

| Page | What You'll See |
|------|-----------------|
| **Dashboard** | Quantum readiness distribution (pie chart), score trends (line chart), asset count, average score |
| **Assets** | All scanned assets with scores, labels, certificate details, cipher suites |
| **CBOM** | CycloneDX v1.6 JSON — click to view/export the cryptographic bill of materials |
| **Recommendations** | Per-asset PQC migration steps with NIST FIPS algorithm references |
| **HNDL Risk** | Timeline showing when each asset's crypto may be broken by CRQCs |
| **Compliance** | Per-asset compliance status against RBI, PCI-DSS v4.0, NIST CSF, CERT-In |

### Generate Reports & Badges

- **HTML Report**: `GET /api/scan/{scan_id}/report` — print-ready report (use browser Print → PDF)
- **SVG Badge**: `GET /api/asset/{asset_id}/badge` — embeddable quantum readiness certificate

### API Quick Test (curl)

```bash
# Launch a scan
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"targets": ["google.com", "github.com"]}'

# Get scan results
curl http://localhost:8000/api/scans

# Get CBOM for a scan
curl http://localhost:8000/api/cbom/1

# Get recommendations
curl http://localhost:8000/api/recommendations

# Get HNDL risk for an asset
curl http://localhost:8000/api/asset/1/hndl

# Get compliance status
curl http://localhost:8000/api/asset/1/compliance

# Get dashboard summary
curl http://localhost:8000/api/dashboard/summary
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan` | Scan targets `{"targets": ["host1", "host2"]}` |
| POST | `/api/scan/csv` | Upload CSV file with hostnames |
| GET | `/api/scan/{id}` | Get scan results by ID |
| GET | `/api/scans` | List all scans |
| GET | `/api/assets` | List all scanned assets |
| GET | `/api/asset/{id}` | Get asset details |
| GET | `/api/cbom/{scan_id}` | Get CycloneDX v1.6 CBOM |
| GET | `/api/dashboard/summary` | Dashboard aggregated stats |
| GET | `/api/recommendations` | PQC migration recommendations |
| GET | `/api/asset/{id}/hndl` | HNDL risk timeline for asset |
| GET | `/api/hndl/summary` | HNDL risk summary across assets |
| GET | `/api/asset/{id}/compliance` | Regulatory compliance for asset |
| GET | `/api/compliance/summary` | Compliance summary across assets |
| GET | `/api/asset/{id}/badge` | SVG quantum readiness badge |
| GET | `/api/scan/{id}/report` | HTML scan report |

---

## Deliverables Mapping

Mapping each hackathon requirement to its implementation:

| # | Hackathon Requirement | Implementation |
|---|----------------------|----------------|
| 1 | Crypto inventory discovery (TLS, VPN, APIs) | `scanner/tls_scanner.py` — probes TLS 1.0-1.3, extracts certs, ciphers, key exchange |
| 2 | CBOM (Cryptographic Bill of Materials) | `cbom/generator.py` — CycloneDX v1.6 JSON standard |
| 3 | Quantum-safe validation & scoring | `analysis/scoring.py` + `analysis/pqc_classifier.py` — 0-100 score with label |
| 4 | PQC migration recommendations | `analysis/recommender.py` — NIST FIPS 203/204/205/206 migration paths |
| 5 | "PQC Ready" / "Quantum-Safe" certificate labels | `analysis/badge_generator.py` — SVG badges per asset |
| 6 | HNDL risk assessment | `analysis/hndl_risk.py` — CRQC timeline projections + banking data exposure |
| 7 | Dashboard & reporting | React dashboard (7 pages) + `analysis/report_generator.py` (HTML reports) |

---

## Testing

Run the full test suite:

```bash
cd backend
pip install pytest
python -m pytest tests/test_analysis.py -v
```

**45 tests** covering:

| Module | Tests | Coverage |
|--------|-------|----------|
| Scoring Engine | 17 | TLS/kex/symmetric/signature scoring, full asset label assertions |
| PQC Classifier | 11 | Key exchange, signature, symmetric, TLS version classification |
| Recommender | 5 | Migration recommendations, FIPS references, edge cases |
| HNDL Risk | 8 | CRQC timelines, data exposure scenarios, PQC-safe detection |
| Compliance | 3 | Regulatory framework mapping, compliance percentages |

---

## PQC Standards Referenced

| Standard | Algorithm | Use Case |
|----------|-----------|----------|
| **NIST FIPS 203** | ML-KEM (Kyber) | Key Encapsulation Mechanism |
| **NIST FIPS 204** | ML-DSA (Dilithium) | Digital Signatures |
| **NIST FIPS 205** | SLH-DSA (SPHINCS+) | Hash-based Digital Signatures |
| **NIST FIPS 206** | FN-DSA (FALCON) | Lattice-based Digital Signatures |

### CRQC Timeline Projections Used

| Algorithm | Earliest Break | Likely Break | Latest Break |
|-----------|---------------|-------------|-------------|
| RSA-2048 | 2030 | 2033 | 2038 |
| RSA-4096 | 2033 | 2037 | 2042 |
| ECDSA-256 | 2029 | 2032 | 2036 |
| ECDHE | 2029 | 2032 | 2036 |

---

## Regulatory Compliance Frameworks

- **RBI IT Framework** — Reserve Bank of India guidelines for cryptographic controls
- **PCI-DSS v4.0** — Payment Card Industry Data Security Standard
- **NIST Cybersecurity Framework v2.0** — Cryptographic agility requirements
- **CERT-In** — Indian Computer Emergency Response Team guidelines

---

*Built for PNB Cybersecurity Hackathon 2025-26*
