"""
Quantum Safety Classification Engine

Categorizes cryptographic primitives by quantum resistance level based on
NIST Post-Quantum Cryptography standards (FIPS 203, 204, 205, 206).
"""

# --- Quantum Safety Categories ---

QUANTUM_VULNERABLE_KEX = {
    "RSA", "DH", "DHE", "ECDH", "ECDHE",
}

PQC_READY_KEX = {
    "ML-KEM (Kyber)", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    "X25519Kyber768 (Hybrid PQC)", "KYBER", "CRYSTALS-KYBER",
}

QUANTUM_VULNERABLE_SIG = {
    "RSA", "ECDSA", "DSA", "Ed25519", "Ed448",
    "sha256WithRSAEncryption", "sha384WithRSAEncryption", "sha512WithRSAEncryption",
    "sha1WithRSAEncryption", "md5WithRSAEncryption",
    "ecdsa-with-SHA256", "ecdsa-with-SHA384", "ecdsa-with-SHA512",
}

PQC_READY_SIG = {
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s",
    "SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
    "FN-DSA-512", "FN-DSA-1024",
    "CRYSTALS-DILITHIUM", "SPHINCS+", "FALCON",
}

STRONG_SYMMETRIC = {
    "AES-256-GCM", "AES-256-CBC", "AES-256-CCM",
    "CHACHA20-POLY1305", "CHACHA20",
    "AES_256_GCM", "AES_256_CBC",
    "CHACHA20_POLY1305",
}

MODERATE_SYMMETRIC = {
    "AES-128-GCM", "AES-128-CBC", "AES-128-CCM",
    "AES_128_GCM", "AES_128_CBC",
}

WEAK_SYMMETRIC = {
    "3DES", "DES-CBC3", "RC4", "DES", "RC2",
    "DES_CBC3_SHA",
}


def classify_key_exchange(kex: str) -> dict:
    """Classify a key exchange algorithm."""
    kex_upper = kex.upper().strip()

    for pqc in PQC_READY_KEX:
        if pqc.upper() in kex_upper or kex_upper in pqc.upper():
            return {
                "algorithm": kex,
                "category": "PQC-Ready",
                "quantum_safe": True,
                "details": f"Uses NIST-standardized post-quantum key encapsulation (FIPS 203). Resistant to Shor's algorithm.",
            }

    if "HYBRID" in kex_upper or "KYBER" in kex_upper:
        return {
            "algorithm": kex,
            "category": "Hybrid PQC",
            "quantum_safe": True,
            "details": "Hybrid key exchange combining classical and post-quantum algorithms. Quantum-safe.",
        }

    for vuln in QUANTUM_VULNERABLE_KEX:
        if vuln.upper() in kex_upper:
            threat = "Shor's algorithm" if vuln in ("RSA", "DH", "DHE") else "Shor's algorithm (ECDLP)"
            return {
                "algorithm": kex,
                "category": "Quantum-Vulnerable",
                "quantum_safe": False,
                "details": f"Vulnerable to quantum attack via {threat}. Migrate to ML-KEM (FIPS 203).",
            }

    return {
        "algorithm": kex,
        "category": "Unknown",
        "quantum_safe": False,
        "details": "Unrecognized key exchange algorithm. Manual review recommended.",
    }


def classify_signature(sig_algo: str, key_type: str = "") -> dict:
    """Classify a signature / certificate algorithm."""
    combined = f"{sig_algo} {key_type}".upper().strip()

    for pqc in PQC_READY_SIG:
        if pqc.upper() in combined:
            return {
                "algorithm": sig_algo,
                "category": "PQC-Ready",
                "quantum_safe": True,
                "details": "Uses NIST-standardized post-quantum digital signature (FIPS 204/205/206).",
            }

    for vuln_sig in QUANTUM_VULNERABLE_SIG:
        if vuln_sig.upper() in combined:
            replacement = "ML-DSA (FIPS 204)" if "RSA" in combined or "DSA" in combined else "ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)"
            return {
                "algorithm": sig_algo,
                "category": "Quantum-Vulnerable",
                "quantum_safe": False,
                "details": f"Signature algorithm vulnerable to quantum attacks. Migrate to {replacement}.",
            }

    return {
        "algorithm": sig_algo,
        "category": "Unknown",
        "quantum_safe": False,
        "details": "Unrecognized signature algorithm.",
    }


def classify_symmetric(cipher_name: str) -> dict:
    """Classify a symmetric cipher."""
    name_upper = cipher_name.upper().replace("-", "_").replace(" ", "_")

    for strong in STRONG_SYMMETRIC:
        if strong.upper().replace("-", "_") in name_upper:
            return {
                "algorithm": cipher_name,
                "category": "Quantum-Resistant",
                "quantum_safe": True,
                "details": "256-bit symmetric cipher. Grover's algorithm halves effective key length to 128-bit, still considered secure.",
            }

    for moderate in MODERATE_SYMMETRIC:
        if moderate.upper().replace("-", "_") in name_upper:
            return {
                "algorithm": cipher_name,
                "category": "Marginally Safe",
                "quantum_safe": True,
                "details": "128-bit symmetric cipher. Grover's reduces effective key to 64-bit. Consider upgrading to 256-bit variant.",
            }

    for weak in WEAK_SYMMETRIC:
        if weak.upper().replace("-", "_") in name_upper:
            return {
                "algorithm": cipher_name,
                "category": "Quantum-Vulnerable",
                "quantum_safe": False,
                "details": "Weak/legacy cipher, already insecure against classical attacks. Must be disabled immediately.",
            }

    return {
        "algorithm": cipher_name,
        "category": "Unknown",
        "quantum_safe": False,
        "details": "Unrecognized symmetric cipher.",
    }


def classify_tls_version(version: str) -> dict:
    """Classify a TLS version."""
    if version == "TLS 1.3":
        return {
            "version": version,
            "category": "Current",
            "secure": True,
            "details": "Latest TLS version. Only allows AEAD ciphers. Recommended.",
        }
    elif version == "TLS 1.2":
        return {
            "version": version,
            "category": "Acceptable",
            "secure": True,
            "details": "Still secure when configured with strong cipher suites. Disable weak ciphers.",
        }
    elif version in ("TLS 1.1", "TLS 1.0"):
        return {
            "version": version,
            "category": "Deprecated",
            "secure": False,
            "details": f"{version} is deprecated (RFC 8996). Must be disabled.",
        }
    return {
        "version": version,
        "category": "Unknown",
        "secure": False,
        "details": "Unrecognized TLS version.",
    }


def classify_asset(scan_result) -> dict:
    """Run full classification on a scan result. Returns classification details dict."""
    details = {
        "tls_versions": [],
        "key_exchanges": [],
        "signatures": [],
        "symmetric_ciphers": [],
        "overall_quantum_safe": False,
        "vulnerabilities": [],
    }

    # TLS versions
    for ver in (scan_result.get("tls_versions") or []):
        cls = classify_tls_version(ver)
        details["tls_versions"].append(cls)
        if not cls["secure"]:
            details["vulnerabilities"].append(f"Deprecated TLS version: {ver}")

    # Key exchanges
    for kex in (scan_result.get("key_exchange_algorithms") or []):
        cls = classify_key_exchange(kex)
        details["key_exchanges"].append(cls)
        if not cls["quantum_safe"]:
            details["vulnerabilities"].append(f"Quantum-vulnerable key exchange: {kex}")

    # Signature (from certificate)
    sig_algo = scan_result.get("cert_signature_algorithm", "")
    key_type = scan_result.get("cert_key_type", "")
    if sig_algo:
        cls = classify_signature(sig_algo, key_type)
        details["signatures"].append(cls)
        if not cls["quantum_safe"]:
            details["vulnerabilities"].append(f"Quantum-vulnerable signature: {sig_algo}")

    # Symmetric ciphers from cipher suites
    seen_ciphers = set()
    for suite in (scan_result.get("cipher_suites") or []):
        name = suite.get("name", "")
        if name and name not in seen_ciphers:
            seen_ciphers.add(name)
            cls = classify_symmetric(name)
            details["symmetric_ciphers"].append(cls)
            if not cls["quantum_safe"]:
                details["vulnerabilities"].append(f"Weak cipher: {name}")

    # Determine overall quantum safety
    has_pqc_kex = any(k["quantum_safe"] and k["category"] in ("PQC-Ready", "Hybrid PQC") for k in details["key_exchanges"])
    has_pqc_sig = any(s["quantum_safe"] and s["category"] == "PQC-Ready" for s in details["signatures"])
    all_tls_secure = all(t["secure"] for t in details["tls_versions"]) if details["tls_versions"] else False

    details["overall_quantum_safe"] = has_pqc_kex and has_pqc_sig and all_tls_secure

    return details
