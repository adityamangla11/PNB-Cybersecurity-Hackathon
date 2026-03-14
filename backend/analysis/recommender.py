"""
Recommendation Engine

Generates actionable PQC migration recommendations for each asset
based on its current cryptographic configuration.
"""

MIGRATION_MAP = {
    # Key Exchange migrations
    "RSA": {
        "current": "RSA Key Exchange",
        "recommended": "ML-KEM-768 (FIPS 203)",
        "priority": "Critical",
        "rationale": "RSA key exchange is vulnerable to Shor's algorithm. Quantum computers can factor large integers in polynomial time, breaking RSA completely.",
        "action": "Configure server to use ML-KEM-768 (Kyber) for key encapsulation. As a transition step, use hybrid X25519Kyber768 which combines classical ECDH with PQC.",
        "standard": "NIST FIPS 203 (ML-KEM)",
    },
    "DHE": {
        "current": "Diffie-Hellman Ephemeral",
        "recommended": "ML-KEM-768 (FIPS 203)",
        "priority": "Critical",
        "rationale": "DHE relies on the discrete logarithm problem, which is solvable by Shor's algorithm on quantum computers.",
        "action": "Migrate to ML-KEM-768 or hybrid X25519Kyber768 key exchange.",
        "standard": "NIST FIPS 203 (ML-KEM)",
    },
    "ECDHE": {
        "current": "Elliptic Curve Diffie-Hellman Ephemeral",
        "recommended": "ML-KEM-768 or Hybrid X25519Kyber768 (FIPS 203)",
        "priority": "High",
        "rationale": "ECDHE is based on the Elliptic Curve Discrete Logarithm Problem (ECDLP), which Shor's algorithm can solve. Currently secure but must be migrated before CRQCs emerge.",
        "action": "Deploy hybrid key exchange (X25519Kyber768) as transition, then move to pure ML-KEM when ecosystem supports it. Update TLS libraries to versions supporting PQC (e.g., OpenSSL 3.5+, BoringSSL).",
        "standard": "NIST FIPS 203 (ML-KEM)",
    },

    # Signature migrations
    "RSA_SIG": {
        "current": "RSA Signature (Certificate)",
        "recommended": "ML-DSA-65 (FIPS 204)",
        "priority": "High",
        "rationale": "RSA signatures are vulnerable to Shor's algorithm. Certificate chains using RSA signatures need migration to PQC.",
        "action": "Request certificates signed with ML-DSA (Dilithium) from your CA. Deploy hybrid certificates (RSA + ML-DSA) during transition. Update certificate validation libraries.",
        "standard": "NIST FIPS 204 (ML-DSA)",
    },
    "ECDSA_SIG": {
        "current": "ECDSA Signature (Certificate)",
        "recommended": "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
        "priority": "High",
        "rationale": "ECDSA relies on ECDLP, vulnerable to Shor's algorithm. While currently secure, HNDL attacks mean data signed today could be forged when CRQCs arrive.",
        "action": "Transition to ML-DSA-65 for performance-critical applications or SLH-DSA for highest assurance (hash-based, conservative). Use hybrid certificates during migration.",
        "standard": "NIST FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA)",
    },

    # TLS version migrations
    "TLS 1.0": {
        "current": "TLS 1.0",
        "recommended": "TLS 1.3",
        "priority": "Critical",
        "rationale": "TLS 1.0 is deprecated (RFC 8996). Known vulnerabilities include BEAST, POODLE. Does not support modern AEAD ciphers.",
        "action": "Disable TLS 1.0 immediately. Configure minimum TLS version to 1.2, preferably 1.3.",
        "standard": "RFC 8996, PCI DSS requirement",
    },
    "TLS 1.1": {
        "current": "TLS 1.1",
        "recommended": "TLS 1.3",
        "priority": "Critical",
        "rationale": "TLS 1.1 is deprecated (RFC 8996). Does not support modern AEAD ciphers or PQC key exchange.",
        "action": "Disable TLS 1.1. Configure minimum TLS version to 1.2, preferably 1.3.",
        "standard": "RFC 8996, PCI DSS requirement",
    },

    # Weak cipher migrations
    "3DES": {
        "current": "3DES (Triple DES)",
        "recommended": "AES-256-GCM",
        "priority": "Critical",
        "rationale": "3DES has an effective key length of 112 bits and is vulnerable to Sweet32 birthday attacks. Already insecure against classical attacks.",
        "action": "Disable 3DES cipher suites immediately. Enable AES-256-GCM and CHACHA20-POLY1305.",
        "standard": "NIST SP 800-131A Rev 2",
    },
    "RC4": {
        "current": "RC4",
        "recommended": "AES-256-GCM",
        "priority": "Critical",
        "rationale": "RC4 is broken. Known biases allow plaintext recovery. Prohibited by RFC 7465.",
        "action": "Disable RC4 immediately. Use AES-256-GCM or CHACHA20-POLY1305.",
        "standard": "RFC 7465",
    },
    "AES-128": {
        "current": "AES-128",
        "recommended": "AES-256-GCM",
        "priority": "Medium",
        "rationale": "AES-128 has effective key length of 64 bits against Grover's algorithm. While still computationally secure (2^64 quantum ops), upgrading to 256-bit provides full quantum resistance.",
        "action": "Configure server to prefer AES-256-GCM cipher suites over AES-128 variants.",
        "standard": "NIST recommendation for post-quantum symmetric security",
    },
}


def generate_recommendations(asset_data: dict, classification: dict) -> list[dict]:
    """Generate actionable PQC migration recommendations for an asset."""
    recommendations = []
    seen = set()

    # Key exchange recommendations
    for kex_cls in classification.get("key_exchanges", []):
        if not kex_cls["quantum_safe"] and kex_cls["algorithm"] not in seen:
            seen.add(kex_cls["algorithm"])
            algo = kex_cls["algorithm"].upper()
            if "RSA" in algo:
                rec = MIGRATION_MAP.get("RSA")
            elif "DHE" in algo and "ECDHE" not in algo:
                rec = MIGRATION_MAP.get("DHE")
            elif "ECDHE" in algo or "ECDH" in algo:
                rec = MIGRATION_MAP.get("ECDHE")
            else:
                rec = None

            if rec:
                recommendations.append({**rec, "affected_component": f"Key Exchange: {kex_cls['algorithm']}"})

    # Signature recommendations
    for sig_cls in classification.get("signatures", []):
        if not sig_cls["quantum_safe"] and sig_cls["algorithm"] not in seen:
            seen.add(sig_cls["algorithm"])
            algo = sig_cls["algorithm"].upper()
            if "RSA" in algo:
                rec = MIGRATION_MAP.get("RSA_SIG")
            elif "ECDSA" in algo or "EC" in algo:
                rec = MIGRATION_MAP.get("ECDSA_SIG")
            else:
                rec = MIGRATION_MAP.get("RSA_SIG")  # fallback

            if rec:
                recommendations.append({**rec, "affected_component": f"Certificate Signature: {sig_cls['algorithm']}"})

    # TLS version recommendations
    for tls_cls in classification.get("tls_versions", []):
        ver = tls_cls["version"]
        if not tls_cls["secure"] and ver not in seen:
            seen.add(ver)
            rec = MIGRATION_MAP.get(ver)
            if rec:
                recommendations.append({**rec, "affected_component": f"Protocol: {ver}"})

    # Weak cipher recommendations
    for sym_cls in classification.get("symmetric_ciphers", []):
        if not sym_cls["quantum_safe"]:
            name = sym_cls["algorithm"].upper()
            if "3DES" in name or "DES" in name:
                rec = MIGRATION_MAP.get("3DES")
            elif "RC4" in name:
                rec = MIGRATION_MAP.get("RC4")
            else:
                continue
            if rec and sym_cls["algorithm"] not in seen:
                seen.add(sym_cls["algorithm"])
                recommendations.append({**rec, "affected_component": f"Cipher: {sym_cls['algorithm']}"})

    # AES-128 upgrade recommendation
    for sym_cls in classification.get("symmetric_ciphers", []):
        if sym_cls.get("category") == "Marginally Safe" and sym_cls["algorithm"] not in seen:
            seen.add(sym_cls["algorithm"])
            rec = MIGRATION_MAP.get("AES-128")
            if rec:
                recommendations.append({**rec, "affected_component": f"Cipher: {sym_cls['algorithm']}"})

    # Sort by priority
    priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    recommendations.sort(key=lambda r: priority_order.get(r.get("priority", "Low"), 3))

    return recommendations
