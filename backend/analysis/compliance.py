"""
Compliance Mapping Engine

Maps quantum-readiness findings to relevant regulatory frameworks:
- RBI Cybersecurity Framework (India banking regulator)
- PCI-DSS v4.0
- NIST Cybersecurity Framework
- CERT-In guidelines
"""

COMPLIANCE_FRAMEWORKS = {
    "RBI": {
        "name": "RBI Cybersecurity Framework",
        "full_name": "Reserve Bank of India - Cybersecurity Framework for Banks",
        "mappings": {
            "deprecated_tls": {
                "clause": "Annex 1 - Baseline Cyber Security Controls",
                "requirement": "Banks should ensure use of latest TLS versions for all internet-facing applications. Deprecated protocols (TLS 1.0, 1.1) must be disabled.",
                "status_field": "tls_versions",
            },
            "weak_ciphers": {
                "clause": "Annex 1, Section 4.2 - Data in Transit",
                "requirement": "Strong encryption algorithms must be deployed for all data in transit. Weak ciphers (3DES, RC4) are prohibited.",
                "status_field": "cipher_strength",
            },
            "crypto_inventory": {
                "clause": "Annex 3 - IT Governance",
                "requirement": "Banks must maintain an inventory of cryptographic assets and algorithms used across all systems.",
                "status_field": "cbom_generated",
            },
            "quantum_readiness": {
                "clause": "Circular on IT Risk Management (2024)",
                "requirement": "Banks should assess exposure to quantum computing threats and develop a migration roadmap to quantum-safe cryptography.",
                "status_field": "quantum_score",
            },
        },
    },
    "PCI_DSS": {
        "name": "PCI-DSS v4.0",
        "full_name": "Payment Card Industry Data Security Standard v4.0",
        "mappings": {
            "deprecated_tls": {
                "clause": "Requirement 4.2.1",
                "requirement": "Strong cryptography and security protocols must protect cardholder data during transmission. TLS 1.0 and early TLS 1.1 are not considered strong cryptography.",
                "status_field": "tls_versions",
            },
            "weak_ciphers": {
                "clause": "Requirement 2.2.5 / 4.2.1",
                "requirement": "Only strong cipher suites approved for use. Weak algorithms (DES, RC4, MD5) are not allowed for protecting cardholder data.",
                "status_field": "cipher_strength",
            },
            "cert_management": {
                "clause": "Requirement 4.2.1.1",
                "requirement": "Certificates used for PAN transmissions must be valid and not expired. Review certificate inventory periodically.",
                "status_field": "cert_validity",
            },
            "key_management": {
                "clause": "Requirement 3.6 / 3.7",
                "requirement": "Cryptographic key management procedures must be documented and implemented. Key exchange mechanisms must use industry-accepted algorithms.",
                "status_field": "key_exchange",
            },
        },
    },
    "NIST_CSF": {
        "name": "NIST Cybersecurity Framework",
        "full_name": "NIST Cybersecurity Framework v2.0 + PQC Migration Guidelines",
        "mappings": {
            "pqc_readiness": {
                "clause": "NIST IR 8547 - Transition to PQC",
                "requirement": "Organizations should inventory all cryptographic systems and prioritize migration to NIST-standardized PQC algorithms (FIPS 203, 204, 205).",
                "status_field": "quantum_score",
            },
            "crypto_agility": {
                "clause": "NIST SP 800-131A Rev 2",
                "requirement": "Systems should support crypto-agility — the ability to switch algorithms without significant code changes. This enables smoother PQC transition.",
                "status_field": "crypto_agility",
            },
            "algorithm_standards": {
                "clause": "FIPS 140-3 / FIPS 203 / FIPS 204",
                "requirement": "Use validated implementations of approved algorithms. For PQC: ML-KEM (FIPS 203) for key exchange, ML-DSA (FIPS 204) for signatures.",
                "status_field": "algorithm_compliance",
            },
        },
    },
    "CERT_IN": {
        "name": "CERT-In Directions",
        "full_name": "Indian Computer Emergency Response Team - Cybersecurity Directions (2022)",
        "mappings": {
            "incident_reporting": {
                "clause": "Direction 6(iv)",
                "requirement": "Organizations must report cryptographic failures and data breaches within 6 hours. HNDL attacks when detected must be reported.",
                "status_field": "monitoring",
            },
            "security_audit": {
                "clause": "Direction 6(i)",
                "requirement": "Regular security audits must include assessment of cryptographic strength and quantum readiness.",
                "status_field": "audit_ready",
            },
        },
    },
}


def assess_compliance(asset_data: dict, classification: dict) -> dict:
    """
    Assess an asset's compliance with regulatory frameworks.

    Returns a dict with compliance status per framework and per requirement.
    """
    results = {}

    # Pre-compute status checks
    tls_versions = asset_data.get("tls_versions", [])
    has_deprecated_tls = "TLS 1.0" in tls_versions or "TLS 1.1" in tls_versions
    has_tls_13 = "TLS 1.3" in tls_versions

    weak_ciphers_found = any(
        s.get("category") in ("Quantum-Vulnerable",) and "cipher" in s.get("algorithm", "").lower()
        for s in classification.get("symmetric_ciphers", [])
        if not s.get("quantum_safe")
    )

    has_any_weak_symmetric = any(
        not s.get("quantum_safe")
        for s in classification.get("symmetric_ciphers", [])
    )

    vulnerabilities = classification.get("vulnerabilities", [])
    score = asset_data.get("score", 0)
    label = asset_data.get("label", "Unknown")

    cert_not_after = asset_data.get("cert_not_after")
    cert_valid = True
    if cert_not_after:
        import datetime
        if isinstance(cert_not_after, str):
            try:
                cert_not_after = datetime.datetime.fromisoformat(cert_not_after)
            except (ValueError, TypeError):
                pass
        if isinstance(cert_not_after, datetime.datetime):
            cert_valid = cert_not_after > datetime.datetime.utcnow()

    has_pqc_kex = any(
        k.get("quantum_safe") and k.get("category") in ("PQC-Ready", "Hybrid PQC")
        for k in classification.get("key_exchanges", [])
    )

    status_map = {
        "tls_versions": "compliant" if not has_deprecated_tls else "non-compliant",
        "cipher_strength": "compliant" if not has_any_weak_symmetric else "non-compliant",
        "cbom_generated": "compliant",  # We generate CBOM, so always compliant here
        "quantum_score": "compliant" if score >= 60 else "needs-attention" if score >= 30 else "non-compliant",
        "cert_validity": "compliant" if cert_valid else "non-compliant",
        "key_exchange": "compliant" if has_pqc_kex else "needs-attention",
        "crypto_agility": "needs-attention",  # Always recommend improving
        "algorithm_compliance": "compliant" if label in ("PQC Ready", "Quantum-Safe") else "needs-attention",
        "monitoring": "needs-attention",  # Recommend setting up monitoring
        "audit_ready": "compliant" if score >= 30 else "non-compliant",
    }

    for fw_id, framework in COMPLIANCE_FRAMEWORKS.items():
        fw_result = {
            "name": framework["name"],
            "full_name": framework["full_name"],
            "requirements": [],
            "compliant_count": 0,
            "total_count": 0,
            "compliance_percentage": 0,
        }

        for req_id, req in framework["mappings"].items():
            status = status_map.get(req["status_field"], "unknown")
            fw_result["requirements"].append({
                "id": req_id,
                "clause": req["clause"],
                "requirement": req["requirement"],
                "status": status,
            })
            fw_result["total_count"] += 1
            if status == "compliant":
                fw_result["compliant_count"] += 1

        if fw_result["total_count"] > 0:
            fw_result["compliance_percentage"] = round(
                fw_result["compliant_count"] / fw_result["total_count"] * 100
            )

        results[fw_id] = fw_result

    return results
