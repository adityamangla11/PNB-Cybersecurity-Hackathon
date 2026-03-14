"""
Quantum Readiness Scoring Engine

Computes a 0-100 score for each asset based on:
  - TLS version (25%)
  - Key exchange algorithm (35%)
  - Symmetric cipher strength (15%)
  - Signature algorithm (25%)
"""


def _score_tls_version(tls_versions: list[str], highest_version: str) -> float:
    """Score 0-25 based on TLS version support."""
    if not highest_version:
        return 0.0

    # Base score from highest version
    version_scores = {"TLS 1.3": 25.0, "TLS 1.2": 15.0, "TLS 1.1": 5.0, "TLS 1.0": 0.0}
    score = version_scores.get(highest_version, 0.0)

    # Penalize if deprecated versions are also enabled
    if "TLS 1.0" in tls_versions or "TLS 1.1" in tls_versions:
        score = max(0, score - 5)

    return score


def _score_key_exchange(kex_algorithms: list[str]) -> float:
    """Score 0-35 based on key exchange algorithms."""
    if not kex_algorithms:
        return 0.0

    best_score = 0.0
    for kex in kex_algorithms:
        kex_upper = kex.upper()
        if any(pqc in kex_upper for pqc in ["ML-KEM", "KYBER", "HYBRID PQC"]):
            best_score = max(best_score, 35.0)
        elif "ECDHE" in kex_upper or "X25519" in kex_upper:
            best_score = max(best_score, 10.0)
        elif "DHE" in kex_upper:
            best_score = max(best_score, 7.0)
        elif "RSA" in kex_upper:
            best_score = max(best_score, 2.0)

    return best_score


def _score_symmetric_cipher(cipher_suites: list[dict]) -> float:
    """Score 0-15 based on strongest symmetric cipher."""
    if not cipher_suites:
        return 0.0

    best_score = 0.0
    for suite in cipher_suites:
        name = suite.get("name", "").upper()
        bits = suite.get("bits", 0)

        if bits >= 256 or "AES_256" in name or "AES-256" in name or "CHACHA20" in name:
            best_score = max(best_score, 15.0)
        elif bits >= 128 or "AES_128" in name or "AES-128" in name:
            best_score = max(best_score, 10.0)
        elif "3DES" in name or "RC4" in name or "DES" in name:
            best_score = max(best_score, 0.0)
        else:
            best_score = max(best_score, 5.0)

    return best_score


def _score_signature(sig_algo: str, key_type: str) -> float:
    """Score 0-25 based on signature algorithm."""
    combined = f"{sig_algo} {key_type}".upper()

    # PQC signatures
    pqc_keywords = ["ML-DSA", "DILITHIUM", "SLH-DSA", "SPHINCS", "FN-DSA", "FALCON"]
    if any(kw in combined for kw in pqc_keywords):
        return 25.0

    # Classical but functional
    if "ECDSA" in combined or "ED25519" in combined or "ED448" in combined:
        return 8.0
    if "RSA" in combined:
        return 5.0
    if "DSA" in combined:
        return 3.0

    return 0.0


def compute_score(asset_data: dict) -> tuple[float, str]:
    """
    Compute the Quantum Readiness Score (0-100) for an asset.

    Returns (score, label) where label is one of:
      - "PQC Ready" (≥90)
      - "Quantum-Safe" (60-89)
      - "At Risk" (30-59)
      - "Critical" (<30)
    """
    tls_score = _score_tls_version(
        asset_data.get("tls_versions", []),
        asset_data.get("highest_tls_version", ""),
    )
    kex_score = _score_key_exchange(asset_data.get("key_exchange_algorithms", []))
    sym_score = _score_symmetric_cipher(asset_data.get("cipher_suites", []))
    sig_score = _score_signature(
        asset_data.get("cert_signature_algorithm", ""),
        asset_data.get("cert_key_type", ""),
    )

    total = tls_score + kex_score + sym_score + sig_score

    if total >= 90:
        label = "PQC Ready"
    elif total >= 60:
        label = "Quantum-Safe"
    elif total >= 30:
        label = "At Risk"
    else:
        label = "Critical"

    return round(total, 1), label
