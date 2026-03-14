"""
HNDL (Harvest Now, Decrypt Later) Risk Timeline Calculator

Estimates when data protected by current cryptographic algorithms
may become vulnerable to quantum decryption, based on:
- Algorithm type and key size
- Projected CRQC (Cryptanalytically Relevant Quantum Computer) timelines
- Data sensitivity shelf life
"""

# Estimated year ranges when CRQCs can break each algorithm family
# Based on NIST, NSA, and academic projections (conservative to aggressive)
CRQC_TIMELINE = {
    "RSA-1024": {"earliest": 2028, "likely": 2030, "latest": 2033},
    "RSA-2048": {"earliest": 2030, "likely": 2033, "latest": 2038},
    "RSA-3072": {"earliest": 2031, "likely": 2035, "latest": 2040},
    "RSA-4096": {"earliest": 2033, "likely": 2037, "latest": 2042},
    "ECDSA-256": {"earliest": 2029, "likely": 2032, "latest": 2036},
    "ECDSA-384": {"earliest": 2030, "likely": 2034, "latest": 2038},
    "ECDH-256": {"earliest": 2029, "likely": 2032, "latest": 2036},
    "ECDHE": {"earliest": 2029, "likely": 2032, "latest": 2036},
    "DH-2048": {"earliest": 2030, "likely": 2033, "latest": 2038},
    "DHE": {"earliest": 2030, "likely": 2033, "latest": 2038},
    "DSA-2048": {"earliest": 2030, "likely": 2033, "latest": 2038},
}

# Banking data sensitivity shelf life (years the data remains valuable)
DATA_SHELF_LIFE = {
    "banking_transactions": 7,
    "customer_pii": 25,
    "account_credentials": 5,
    "regulatory_records": 10,
    "strategic_communications": 15,
    "default": 10,
}


def _get_algo_key(key_type: str, key_size: int, algo_name: str = "") -> str:
    """Map algorithm info to a CRQC timeline key."""
    algo_upper = algo_name.upper() if algo_name else ""
    key_type_upper = key_type.upper()

    # PQC algorithms are not vulnerable to quantum attacks
    pqc_keywords = ("ML-KEM", "ML-DSA", "SLH-DSA", "FN-DSA", "KYBER", "DILITHIUM", "SPHINCS", "FALCON")
    for pqc in pqc_keywords:
        if pqc in key_type_upper or pqc in algo_upper:
            return None

    if "RSA" in key_type_upper:
        if key_size <= 1024:
            return "RSA-1024"
        elif key_size <= 2048:
            return "RSA-2048"
        elif key_size <= 3072:
            return "RSA-3072"
        else:
            return "RSA-4096"
    elif "ECDSA" in key_type_upper or "EC" in key_type_upper:
        if key_size <= 256:
            return "ECDSA-256"
        else:
            return "ECDSA-384"
    elif "ECDHE" in algo_upper or "ECDH" in algo_upper:
        return "ECDHE"
    elif "DHE" in algo_upper or "DH" in key_type_upper:
        return "DHE"
    elif "DSA" in key_type_upper:
        return "DSA-2048"

    return None


def compute_hndl_risk(asset_data: dict) -> dict:
    """
    Compute HNDL risk assessment for an asset.

    Returns:
        dict with risk timeline, urgency, and narrative explanation
    """
    current_year = 2026
    risks = []

    # Assess certificate algorithm risk
    cert_key_type = asset_data.get("cert_key_type", "")
    cert_key_size = asset_data.get("cert_key_size", 0)
    cert_sig = asset_data.get("cert_signature_algorithm", "")

    algo_key = _get_algo_key(cert_key_type, cert_key_size, cert_sig)
    if algo_key and algo_key in CRQC_TIMELINE:
        timeline = CRQC_TIMELINE[algo_key]
        risks.append({
            "component": f"Certificate ({cert_key_type}-{cert_key_size})",
            "algorithm": f"{cert_key_type}-{cert_key_size}",
            "attack": "Shor's Algorithm (integer factorization / ECDLP)",
            "crqc_earliest": timeline["earliest"],
            "crqc_likely": timeline["likely"],
            "crqc_latest": timeline["latest"],
            "years_until_risk_earliest": max(0, timeline["earliest"] - current_year),
            "years_until_risk_likely": max(0, timeline["likely"] - current_year),
        })

    # Assess key exchange risk
    for kex in (asset_data.get("key_exchange_algorithms") or []):
        kex_key = _get_algo_key("", 0, kex)
        if kex_key and kex_key in CRQC_TIMELINE:
            timeline = CRQC_TIMELINE[kex_key]
            risks.append({
                "component": f"Key Exchange ({kex})",
                "algorithm": kex,
                "attack": "Shor's Algorithm",
                "crqc_earliest": timeline["earliest"],
                "crqc_likely": timeline["likely"],
                "crqc_latest": timeline["latest"],
                "years_until_risk_earliest": max(0, timeline["earliest"] - current_year),
                "years_until_risk_likely": max(0, timeline["likely"] - current_year),
            })

    if not risks:
        return {
            "risk_level": "none",
            "risks": [],
            "summary": "No HNDL-vulnerable cryptographic components detected.",
            "data_exposure_scenarios": [],
        }

    # Find the earliest at-risk date across all components
    earliest_risk = min(r["crqc_earliest"] for r in risks)
    likely_risk = min(r["crqc_likely"] for r in risks)
    years_until = max(0, earliest_risk - current_year)

    # Data exposure scenarios
    scenarios = []
    for data_type, shelf_life in DATA_SHELF_LIFE.items():
        if data_type == "default":
            continue
        harvest_year = current_year  # data harvested now
        value_until = harvest_year + shelf_life
        if value_until >= earliest_risk:
            exposure_years = value_until - earliest_risk
            scenarios.append({
                "data_type": data_type.replace("_", " ").title(),
                "shelf_life_years": shelf_life,
                "data_valuable_until": value_until,
                "crqc_available_by": earliest_risk,
                "exposure_window_years": exposure_years,
                "at_risk": True,
                "narrative": f"{data_type.replace('_', ' ').title()} harvested today remains valuable until {value_until}. "
                            f"CRQCs may be available by {earliest_risk}, leaving a {exposure_years}-year window "
                            f"where adversaries can decrypt harvested data.",
            })
        else:
            scenarios.append({
                "data_type": data_type.replace("_", " ").title(),
                "shelf_life_years": shelf_life,
                "data_valuable_until": value_until,
                "crqc_available_by": earliest_risk,
                "exposure_window_years": 0,
                "at_risk": False,
                "narrative": f"{data_type.replace('_', ' ').title()} data expires before CRQCs are expected.",
            })

    at_risk_scenarios = [s for s in scenarios if s["at_risk"]]

    if years_until <= 3:
        risk_level = "critical"
        urgency = "IMMEDIATE"
    elif years_until <= 6:
        risk_level = "high"
        urgency = "URGENT"
    elif years_until <= 10:
        risk_level = "medium"
        urgency = "PLAN NOW"
    else:
        risk_level = "low"
        urgency = "MONITOR"

    summary = (
        f"Data encrypted with current algorithms may be decryptable as early as {earliest_risk} "
        f"(most likely by {likely_risk}). {len(at_risk_scenarios)} out of {len(scenarios) } banking data "
        f"categories are at risk from HNDL attacks. Migration urgency: {urgency}."
    )

    return {
        "risk_level": risk_level,
        "urgency": urgency,
        "earliest_risk_year": earliest_risk,
        "likely_risk_year": likely_risk,
        "years_until_earliest_risk": years_until,
        "risks": risks,
        "data_exposure_scenarios": scenarios,
        "at_risk_scenario_count": len(at_risk_scenarios),
        "total_scenario_count": len(scenarios),
        "summary": summary,
    }
