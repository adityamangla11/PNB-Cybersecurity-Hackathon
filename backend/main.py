import datetime
import io
import csv
import threading
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, Response
from sqlalchemy.orm import Session
from sqlalchemy import func

from models.database import init_db, get_db, Scan, Asset
from models.schemas import ScanRequest, ScanResponse, AssetSummary, AssetDetail, DashboardSummary
from scanner.tls_scanner import scan_target, parse_target
from analysis.pqc_classifier import classify_asset
from analysis.scoring import compute_score
from analysis.recommender import generate_recommendations
from analysis.hndl_risk import compute_hndl_risk
from analysis.compliance import assess_compliance
from analysis.report_generator import generate_html_report
from analysis.badge_generator import generate_badge_svg
from cbom.generator import generate_cbom, cbom_to_json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("Database initialized")
    yield


app = FastAPI(
    title="PNB Quantum-Proof Crypto Scanner",
    description="Scanner to validate deployment of quantum-proof ciphers and generate CBOM for public-facing applications",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _run_scan_background(scan_id: int):
    """Execute scan in background thread."""
    from models.database import SessionLocal
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        scan.status = "running"
        db.commit()

        targets = []
        for asset_stub in db.query(Asset).filter(Asset.scan_id == scan_id).all():
            targets.append((asset_stub.id, asset_stub.host, asset_stub.port))

        # Parallel scanning with thread pool
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _scan_single(target_tuple):
            asset_id, host, port = target_tuple
            logger.info(f"Scanning {host}:{port}...")
            result = scan_target(host, port)
            return asset_id, host, port, result

        max_workers = min(8, len(targets))
        scan_results = {}
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_scan_single, t): t for t in targets}
            for future in as_completed(futures):
                target_tuple = futures[future]
                try:
                    scan_results[target_tuple[0]] = future.result()
                except Exception as e:
                    logger.error(f"Error scanning {target_tuple[1]}:{target_tuple[2]}: {e}")
                    scan_results[target_tuple[0]] = None

        # Save results sequentially (DB writes are not thread-safe)
        for asset_id, host, port in targets:
            entry = scan_results.get(asset_id)
            try:
                if entry is None:
                    scan.completed_targets += 1
                    db.commit()
                    continue

                _, _, _, result = entry

                asset = db.query(Asset).filter(Asset.id == asset_id).first()
                if not asset:
                    continue

                # Populate TLS info
                asset.tls_versions = result.tls_versions
                asset.highest_tls_version = result.highest_tls_version
                asset.asset_type = result.asset_type

                # Certificate info
                asset.cert_subject = result.cert_info.subject
                asset.cert_issuer = result.cert_info.issuer
                asset.cert_not_before = result.cert_info.not_before
                asset.cert_not_after = result.cert_info.not_after
                asset.cert_key_type = result.cert_info.key_type
                asset.cert_key_size = result.cert_info.key_size
                asset.cert_signature_algorithm = result.cert_info.signature_algorithm
                asset.cert_serial_number = result.cert_info.serial_number

                # Cipher suites & key exchange
                asset.cipher_suites = result.cipher_suites
                asset.key_exchange_algorithms = result.key_exchange_algorithms

                # Classification
                asset_data = {
                    "tls_versions": result.tls_versions,
                    "highest_tls_version": result.highest_tls_version,
                    "key_exchange_algorithms": result.key_exchange_algorithms,
                    "cert_signature_algorithm": result.cert_info.signature_algorithm,
                    "cert_key_type": result.cert_info.key_type,
                    "cipher_suites": result.cipher_suites,
                }
                classification = classify_asset(asset_data)
                asset.classification_details = classification

                # Scoring
                score, label = compute_score(asset_data)
                asset.score = score
                asset.label = label

                # Recommendations
                recommendations = generate_recommendations(asset_data, classification)
                asset.recommendations = recommendations

                asset.scanned_at = datetime.datetime.utcnow()

                scan.completed_targets += 1
                db.commit()
                logger.info(f"Completed {host}:{port} — Score: {score}, Label: {label}")

            except Exception as e:
                logger.error(f"Error scanning {host}:{port}: {e}")
                scan.completed_targets += 1
                db.commit()

        scan.status = "completed"
        db.commit()
        logger.info(f"Scan {scan_id} completed")

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            db.commit()
    finally:
        db.close()


# --- API Routes ---

@app.post("/api/scan", response_model=ScanResponse)
def start_scan(request: ScanRequest, db: Session = Depends(get_db)):
    """Start a new crypto scan for the given targets."""
    if not request.targets:
        raise HTTPException(status_code=400, detail="No targets provided")
    if len(request.targets) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 targets per scan")

    scan = Scan(
        total_targets=len(request.targets),
        status="pending",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Create asset stubs
    for target in request.targets:
        host, port = parse_target(target)
        asset = Asset(scan_id=scan.id, host=host, port=port)
        db.add(asset)
    db.commit()

    # Launch background scan
    thread = threading.Thread(target=_run_scan_background, args=(scan.id,), daemon=True)
    thread.start()

    db.refresh(scan)
    return scan


@app.get("/api/scan/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Get scan status and summary."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.get("/api/scans", response_model=list[ScanResponse])
def list_scans(db: Session = Depends(get_db)):
    """List all scans ordered by most recent."""
    return db.query(Scan).order_by(Scan.created_at.desc()).limit(50).all()


@app.get("/api/assets", response_model=list[AssetSummary])
def list_assets(scan_id: int = None, db: Session = Depends(get_db)):
    """List all discovered crypto assets, optionally filtered by scan."""
    query = db.query(Asset)
    if scan_id:
        query = query.filter(Asset.scan_id == scan_id)
    return query.order_by(Asset.score.asc()).all()


@app.get("/api/asset/{asset_id}", response_model=AssetDetail)
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    """Get detailed view of a specific asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@app.get("/api/cbom/{scan_id}")
def get_cbom(scan_id: int, db: Session = Depends(get_db)):
    """Generate and return CBOM in CycloneDX JSON format."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    asset_dicts = []
    for a in assets:
        asset_dicts.append({
            "host": a.host,
            "port": a.port,
            "asset_type": a.asset_type,
            "tls_versions": a.tls_versions,
            "highest_tls_version": a.highest_tls_version,
            "cert_subject": a.cert_subject,
            "cert_issuer": a.cert_issuer,
            "cert_not_after": a.cert_not_after,
            "cert_key_type": a.cert_key_type,
            "cert_key_size": a.cert_key_size,
            "cert_signature_algorithm": a.cert_signature_algorithm,
            "cipher_suites": a.cipher_suites,
            "key_exchange_algorithms": a.key_exchange_algorithms,
            "score": a.score,
            "label": a.label,
            "classification_details": a.classification_details,
        })

    scan_date = scan.created_at.isoformat() + "Z" if scan.created_at else None
    cbom = generate_cbom(scan_id, asset_dicts, scan_date)

    return JSONResponse(
        content=cbom,
        headers={"Content-Disposition": f"attachment; filename=cbom_scan_{scan_id}.json"},
    )


@app.get("/api/dashboard/summary", response_model=DashboardSummary)
def get_dashboard_summary(db: Session = Depends(get_db)):
    """Get aggregated dashboard summary."""
    # Count assets by label (from most recent completed scan, or all)
    total = db.query(Asset).count()
    pqc_ready = db.query(Asset).filter(Asset.label == "PQC Ready").count()
    quantum_safe = db.query(Asset).filter(Asset.label == "Quantum-Safe").count()
    at_risk = db.query(Asset).filter(Asset.label == "At Risk").count()
    critical = db.query(Asset).filter(Asset.label == "Critical").count()

    label_distribution = {
        "PQC Ready": pqc_ready,
        "Quantum-Safe": quantum_safe,
        "At Risk": at_risk,
        "Critical": critical,
    }

    # Score trend: average score per scan over time
    score_trend = []
    scans = db.query(Scan).filter(Scan.status == "completed").order_by(Scan.created_at.asc()).all()
    for s in scans:
        avg_score = db.query(func.avg(Asset.score)).filter(Asset.scan_id == s.id).scalar()
        if avg_score is not None:
            score_trend.append({
                "scan_id": s.id,
                "date": s.created_at.isoformat() if s.created_at else "",
                "avg_score": round(float(avg_score), 1),
            })

    # Recent scans
    recent_scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(10).all()

    return DashboardSummary(
        total_assets=total,
        pqc_ready=pqc_ready,
        quantum_safe=quantum_safe,
        at_risk=at_risk,
        critical=critical,
        label_distribution=label_distribution,
        score_trend=score_trend,
        recent_scans=recent_scans,
    )


@app.get("/api/recommendations")
def get_all_recommendations(db: Session = Depends(get_db)):
    """Get all recommendations across all assets."""
    assets = db.query(Asset).filter(Asset.recommendations.isnot(None)).all()
    all_recs = []
    for asset in assets:
        if asset.recommendations:
            for rec in asset.recommendations:
                rec["asset_host"] = asset.host
                rec["asset_port"] = asset.port
                rec["asset_id"] = asset.id
                rec["asset_score"] = asset.score
                rec["asset_label"] = asset.label
                all_recs.append(rec)

    # Sort by priority
    priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    all_recs.sort(key=lambda r: priority_order.get(r.get("priority", "Low"), 3))
    return all_recs


# --- HNDL Risk Timeline ---

@app.get("/api/asset/{asset_id}/hndl")
def get_hndl_risk(asset_id: int, db: Session = Depends(get_db)):
    """Get HNDL (Harvest Now, Decrypt Later) risk timeline for an asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    asset_data = {
        "cert_key_type": asset.cert_key_type,
        "cert_key_size": asset.cert_key_size,
        "cert_signature_algorithm": asset.cert_signature_algorithm,
        "key_exchange_algorithms": asset.key_exchange_algorithms,
        "tls_versions": asset.tls_versions,
    }
    return compute_hndl_risk(asset_data)


@app.get("/api/hndl/summary")
def get_hndl_summary(db: Session = Depends(get_db)):
    """Aggregate HNDL risk across all assets."""
    assets = db.query(Asset).filter(Asset.score.isnot(None)).all()
    results = []
    for asset in assets:
        asset_data = {
            "cert_key_type": asset.cert_key_type,
            "cert_key_size": asset.cert_key_size,
            "cert_signature_algorithm": asset.cert_signature_algorithm,
            "key_exchange_algorithms": asset.key_exchange_algorithms,
            "tls_versions": asset.tls_versions,
        }
        risk = compute_hndl_risk(asset_data)
        risk["host"] = asset.host
        risk["port"] = asset.port
        risk["asset_id"] = asset.id
        risk["score"] = asset.score
        risk["label"] = asset.label
        results.append(risk)
    return results


# --- Compliance ---

@app.get("/api/asset/{asset_id}/compliance")
def get_asset_compliance(asset_id: int, db: Session = Depends(get_db)):
    """Get regulatory compliance report for an asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    asset_data = {
        "tls_versions": asset.tls_versions,
        "cert_key_type": asset.cert_key_type,
        "cert_key_size": asset.cert_key_size,
        "cert_signature_algorithm": asset.cert_signature_algorithm,
        "key_exchange_algorithms": asset.key_exchange_algorithms,
        "cipher_suites": asset.cipher_suites,
        "cert_not_after": asset.cert_not_after,
        "score": asset.score,
        "label": asset.label,
    }
    classification = asset.classification_details or {}
    return assess_compliance(asset_data, classification)


@app.get("/api/compliance/summary")
def get_compliance_summary(db: Session = Depends(get_db)):
    """Get aggregated compliance summary across all assets."""
    assets = db.query(Asset).filter(Asset.score.isnot(None)).all()
    if not assets:
        return {"frameworks": {}, "assets": []}

    all_results = []
    for asset in assets:
        asset_data = {
            "tls_versions": asset.tls_versions,
            "cert_key_type": asset.cert_key_type,
            "cert_key_size": asset.cert_key_size,
            "cert_signature_algorithm": asset.cert_signature_algorithm,
            "key_exchange_algorithms": asset.key_exchange_algorithms,
            "cipher_suites": asset.cipher_suites,
            "cert_not_after": asset.cert_not_after,
            "score": asset.score,
            "label": asset.label,
        }
        classification = asset.classification_details or {}
        compliance = assess_compliance(asset_data, classification)
        all_results.append({
            "host": asset.host,
            "port": asset.port,
            "asset_id": asset.id,
            "compliance": compliance,
        })

    # Aggregate per-framework averages
    from collections import defaultdict
    fw_totals = defaultdict(lambda: {"sum_pct": 0, "count": 0})
    for r in all_results:
        for fw_id, fw_data in r["compliance"].items():
            fw_totals[fw_id]["sum_pct"] += fw_data["compliance_percentage"]
            fw_totals[fw_id]["count"] += 1
            fw_totals[fw_id]["name"] = fw_data["name"]

    frameworks = {}
    for fw_id, data in fw_totals.items():
        frameworks[fw_id] = {
            "name": data["name"],
            "avg_compliance_percentage": round(data["sum_pct"] / data["count"]) if data["count"] else 0,
            "asset_count": data["count"],
        }

    return {"frameworks": frameworks, "assets": all_results}


# --- Certificate Badge ---

@app.get("/api/asset/{asset_id}/badge")
def get_badge(asset_id: int, db: Session = Depends(get_db)):
    """Generate PQC readiness badge for an asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    svg = generate_badge_svg(
        host=asset.host,
        port=asset.port,
        score=asset.score or 0,
        label=asset.label or "Unknown",
        scan_date=asset.scanned_at.strftime("%Y-%m-%d") if asset.scanned_at else None,
    )
    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={"Content-Disposition": f"inline; filename=badge_{asset.host}.svg"},
    )


# --- HTML Report ---

@app.get("/api/scan/{scan_id}/report")
def get_scan_report(scan_id: int, db: Session = Depends(get_db)):
    """Generate full HTML report for a scan (can be printed to PDF)."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    asset_dicts = []
    all_recs = []
    for a in assets:
        d = {
            "host": a.host, "port": a.port,
            "highest_tls_version": a.highest_tls_version,
            "cert_key_type": a.cert_key_type,
            "cert_key_size": a.cert_key_size,
            "cert_signature_algorithm": a.cert_signature_algorithm,
            "score": a.score, "label": a.label,
        }
        asset_dicts.append(d)
        if a.recommendations:
            for rec in a.recommendations:
                rec["asset_host"] = a.host
                rec["asset_port"] = a.port
                all_recs.append(rec)

    scan_data = {
        "id": scan.id,
        "created_at": scan.created_at.isoformat() if scan.created_at else "",
    }
    html = generate_html_report(scan_data, asset_dicts, all_recs)
    return HTMLResponse(content=html)


# --- Bulk CSV Upload ---

@app.post("/api/scan/csv", response_model=ScanResponse)
async def start_scan_from_csv(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Upload a CSV file with targets (host, port) to start a bulk scan."""
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="File must be a .csv")

    content = await file.read()
    text = content.decode("utf-8")
    reader = csv.reader(io.StringIO(text))

    targets = []
    for row in reader:
        if not row or row[0].strip().lower() in ("host", "hostname", "target", "url", ""):
            continue
        host = row[0].strip()
        port = int(row[1].strip()) if len(row) > 1 and row[1].strip().isdigit() else 443
        targets.append(f"{host}:{port}")

    if not targets:
        raise HTTPException(status_code=400, detail="No valid targets found in CSV")
    if len(targets) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 targets per scan")

    scan = Scan(total_targets=len(targets), status="pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    for t in targets:
        host, port = parse_target(t)
        asset = Asset(scan_id=scan.id, host=host, port=port)
        db.add(asset)
    db.commit()

    thread = threading.Thread(target=_run_scan_background, args=(scan.id,), daemon=True)
    thread.start()

    db.refresh(scan)
    return scan
