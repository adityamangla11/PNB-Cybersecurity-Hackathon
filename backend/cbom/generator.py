"""
Cryptographic Bill of Materials (CBOM) Generator

Generates CBOM in CycloneDX v1.6 JSON format for scanned crypto assets.
"""

import datetime
import uuid
import json


def _make_crypto_component(asset: dict, idx: int) -> dict:
    """Build a CycloneDX crypto-asset component from an asset record."""
    properties = []

    # TLS versions
    for ver in (asset.get("tls_versions") or []):
        properties.append({"name": "tls:version", "value": ver})

    # Cipher suites
    for suite in (asset.get("cipher_suites") or []):
        properties.append({"name": "tls:cipherSuite", "value": suite.get("name", "")})
        if suite.get("bits"):
            properties.append({"name": "tls:cipherBits", "value": str(suite["bits"])})

    # Key exchange
    for kex in (asset.get("key_exchange_algorithms") or []):
        properties.append({"name": "crypto:keyExchange", "value": kex})

    # Certificate info
    if asset.get("cert_key_type"):
        properties.append({"name": "cert:keyType", "value": asset["cert_key_type"]})
    if asset.get("cert_key_size"):
        properties.append({"name": "cert:keySize", "value": str(asset["cert_key_size"])})
    if asset.get("cert_signature_algorithm"):
        properties.append({"name": "cert:signatureAlgorithm", "value": asset["cert_signature_algorithm"]})
    if asset.get("cert_subject"):
        properties.append({"name": "cert:subject", "value": asset["cert_subject"]})
    if asset.get("cert_issuer"):
        properties.append({"name": "cert:issuer", "value": asset["cert_issuer"]})
    if asset.get("cert_not_after"):
        exp = asset["cert_not_after"]
        if isinstance(exp, datetime.datetime):
            exp = exp.isoformat()
        properties.append({"name": "cert:expiresAt", "value": exp})

    # Quantum readiness
    properties.append({"name": "quantum:score", "value": str(asset.get("score", 0))})
    properties.append({"name": "quantum:label", "value": asset.get("label", "Unknown")})

    # Classification details
    classification = asset.get("classification_details") or {}
    for vuln in classification.get("vulnerabilities", []):
        properties.append({"name": "quantum:vulnerability", "value": vuln})

    component = {
        "type": "crypto-asset",
        "bom-ref": f"crypto-{asset.get('host', 'unknown')}-{asset.get('port', 443)}-{idx}",
        "name": f"{asset.get('host', 'unknown')}:{asset.get('port', 443)}",
        "version": asset.get("highest_tls_version", "unknown"),
        "description": f"Cryptographic asset inventory for {asset.get('host', 'unknown')} ({asset.get('asset_type', 'web_server')})",
        "properties": properties,
    }

    return component


def generate_cbom(scan_id: int, assets: list[dict], scan_date: str = None) -> dict:
    """
    Generate a CycloneDX v1.6 CBOM JSON document.

    Args:
        scan_id: The scan identifier
        assets: List of asset dicts (from DB records)
        scan_date: ISO date string for the scan

    Returns:
        CycloneDX CBOM dict
    """
    if not scan_date:
        scan_date = datetime.datetime.utcnow().isoformat() + "Z"

    components = []
    for idx, asset in enumerate(assets):
        components.append(_make_crypto_component(asset, idx))

    # Build vulnerability entries for quantum-vulnerable findings
    vulnerabilities = []
    for idx, asset in enumerate(assets):
        classification = asset.get("classification_details") or {}
        for vuln_desc in classification.get("vulnerabilities", []):
            vuln_id = f"QUANTUM-{scan_id}-{idx}-{len(vulnerabilities)}"
            vuln = {
                "id": vuln_id,
                "description": vuln_desc,
                "source": {"name": "PNB Quantum Scanner", "url": "https://pnb-quantum-scanner.internal"},
                "ratings": [
                    {
                        "severity": "high" if "key exchange" in vuln_desc.lower() or "signature" in vuln_desc.lower() else "medium",
                        "method": "other",
                    }
                ],
                "affects": [
                    {
                        "ref": f"crypto-{asset.get('host', 'unknown')}-{asset.get('port', 443)}-{idx}",
                    }
                ],
                "recommendation": "Migrate to NIST-standardized post-quantum algorithms (FIPS 203/204/205).",
            }
            vulnerabilities.append(vuln)

    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": scan_date,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "PNB Quantum-Proof Crypto Scanner",
                        "version": "1.0.0",
                        "description": "Cryptographic inventory scanner for quantum readiness assessment",
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": "PNB Public-Facing Infrastructure",
                "description": "Cryptographic Bill of Materials for PNB internet-exposed services",
            },
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }

    return cbom


def cbom_to_json(cbom: dict) -> str:
    """Serialize CBOM to JSON string."""
    return json.dumps(cbom, indent=2, default=str)
