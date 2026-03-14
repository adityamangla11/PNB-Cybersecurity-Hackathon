"""
Unit tests for the PNB QuantumShield analysis modules.

Run with:  python -m pytest tests/ -v
"""

import pytest
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis.scoring import compute_score, _score_tls_version, _score_key_exchange, _score_symmetric_cipher, _score_signature
from analysis.pqc_classifier import classify_key_exchange, classify_signature, classify_symmetric, classify_tls_version, classify_asset
from analysis.recommender import generate_recommendations
from analysis.hndl_risk import compute_hndl_risk, _get_algo_key
from analysis.compliance import assess_compliance


# ────────────────── Scoring Engine Tests ──────────────────

class TestScoringEngine:
    def test_tls13_only_scores_25(self):
        score = _score_tls_version(["TLS 1.3"], "TLS 1.3")
        assert score == 25.0

    def test_tls12_only_scores_15(self):
        score = _score_tls_version(["TLS 1.2"], "TLS 1.2")
        assert score == 15.0

    def test_tls10_penalty(self):
        score = _score_tls_version(["TLS 1.3", "TLS 1.0"], "TLS 1.3")
        assert score == 20.0  # 25 - 5 penalty

    def test_pqc_kex_scores_35(self):
        score = _score_key_exchange(["ML-KEM-768"])
        assert score == 35.0

    def test_ecdhe_kex_scores_10(self):
        score = _score_key_exchange(["ECDHE"])
        assert score == 10.0

    def test_rsa_kex_scores_2(self):
        score = _score_key_exchange(["RSA"])
        assert score == 2.0

    def test_empty_kex_scores_0(self):
        score = _score_key_exchange([])
        assert score == 0.0

    def test_aes256_scores_15(self):
        score = _score_symmetric_cipher([{"name": "AES_256_GCM", "bits": 256}])
        assert score == 15.0

    def test_aes128_scores_10(self):
        score = _score_symmetric_cipher([{"name": "AES_128_GCM", "bits": 128}])
        assert score == 10.0

    def test_3des_scores_0(self):
        score = _score_symmetric_cipher([{"name": "DES-CBC3-SHA", "bits": 112}])
        assert score == 0.0

    def test_pqc_signature_scores_25(self):
        score = _score_signature("ML-DSA-65", "ML-DSA")
        assert score == 25.0

    def test_ecdsa_signature_scores_8(self):
        score = _score_signature("ecdsa-with-SHA256", "ECDSA")
        assert score == 8.0

    def test_rsa_signature_scores_5(self):
        score = _score_signature("sha256WithRSAEncryption", "RSA")
        assert score == 5.0

    def test_full_pqc_asset_is_pqc_ready(self):
        asset = {
            "tls_versions": ["TLS 1.3"],
            "highest_tls_version": "TLS 1.3",
            "key_exchange_algorithms": ["ML-KEM-768"],
            "cert_signature_algorithm": "ML-DSA-65",
            "cert_key_type": "ML-DSA",
            "cipher_suites": [{"name": "AES_256_GCM_SHA384", "bits": 256}],
        }
        score, label = compute_score(asset)
        assert score == 100.0
        assert label == "PQC Ready"

    def test_typical_ecdsa_tls13_is_at_risk(self):
        asset = {
            "tls_versions": ["TLS 1.3", "TLS 1.2"],
            "highest_tls_version": "TLS 1.3",
            "key_exchange_algorithms": ["ECDHE"],
            "cert_signature_algorithm": "ecdsa-with-SHA256",
            "cert_key_type": "ECDSA",
            "cipher_suites": [{"name": "AES_256_GCM_SHA384", "bits": 256}],
        }
        score, label = compute_score(asset)
        assert 30 <= score < 60
        assert label == "At Risk"

    def test_legacy_rsa_tls10_is_critical(self):
        asset = {
            "tls_versions": ["TLS 1.0"],
            "highest_tls_version": "TLS 1.0",
            "key_exchange_algorithms": ["RSA"],
            "cert_signature_algorithm": "sha1WithRSAEncryption",
            "cert_key_type": "RSA",
            "cipher_suites": [{"name": "DES-CBC3-SHA", "bits": 112}],
        }
        score, label = compute_score(asset)
        assert score < 30
        assert label == "Critical"

    def test_empty_asset_is_critical(self):
        score, label = compute_score({})
        assert score == 0.0
        assert label == "Critical"


# ────────────────── PQC Classifier Tests ──────────────────

class TestPQCClassifier:
    def test_ecdhe_is_vulnerable(self):
        result = classify_key_exchange("ECDHE")
        assert result["quantum_safe"] is False
        assert result["category"] == "Quantum-Vulnerable"

    def test_mlkem_is_pqc_ready(self):
        result = classify_key_exchange("ML-KEM-768")
        assert result["quantum_safe"] is True
        assert result["category"] == "PQC-Ready"

    def test_hybrid_kyber_is_safe(self):
        result = classify_key_exchange("X25519Kyber768 (Hybrid PQC)")
        assert result["quantum_safe"] is True

    def test_rsa_sig_is_vulnerable(self):
        result = classify_signature("sha256WithRSAEncryption", "RSA")
        assert result["quantum_safe"] is False
        assert result["category"] == "Quantum-Vulnerable"

    def test_mldsa_sig_is_pqc_ready(self):
        result = classify_signature("ML-DSA-65", "ML-DSA")
        assert result["quantum_safe"] is True
        assert result["category"] == "PQC-Ready"

    def test_aes256_is_quantum_resistant(self):
        result = classify_symmetric("AES-256-GCM")
        assert result["quantum_safe"] is True
        assert result["category"] == "Quantum-Resistant"

    def test_3des_is_vulnerable(self):
        result = classify_symmetric("DES-CBC3")
        assert result["quantum_safe"] is False
        assert result["category"] == "Quantum-Vulnerable"

    def test_chacha20_is_quantum_resistant(self):
        result = classify_symmetric("CHACHA20-POLY1305")
        assert result["quantum_safe"] is True
        assert result["category"] == "Quantum-Resistant"

    def test_tls13_is_current(self):
        result = classify_tls_version("TLS 1.3")
        assert result["secure"] is True
        assert result["category"] == "Current"

    def test_tls10_is_deprecated(self):
        result = classify_tls_version("TLS 1.0")
        assert result["secure"] is False
        assert result["category"] == "Deprecated"

    def test_classify_asset_returns_all_sections(self):
        asset_data = {
            "tls_versions": ["TLS 1.3"],
            "highest_tls_version": "TLS 1.3",
            "key_exchange_algorithms": ["ECDHE"],
            "cert_signature_algorithm": "ecdsa-with-SHA256",
            "cert_key_type": "ECDSA",
            "cipher_suites": [{"name": "AES_256_GCM_SHA384", "bits": 256}],
        }
        result = classify_asset(asset_data)
        assert "tls_versions" in result
        assert "key_exchanges" in result
        assert "signatures" in result
        assert "symmetric_ciphers" in result
        assert "vulnerabilities" in result


# ────────────────── Recommender Tests ──────────────────

class TestRecommender:
    def _make_classified_asset(self, kex="ECDHE", sig="ecdsa-with-SHA256", key_type="ECDSA"):
        asset_data = {
            "tls_versions": ["TLS 1.3"],
            "highest_tls_version": "TLS 1.3",
            "key_exchange_algorithms": [kex],
            "cert_signature_algorithm": sig,
            "cert_key_type": key_type,
            "cipher_suites": [{"name": "AES_256_GCM_SHA384", "bits": 256}],
        }
        classification = classify_asset(asset_data)
        return asset_data, classification

    def test_ecdhe_recommends_mlkem(self):
        asset_data, classification = self._make_classified_asset()
        recs = generate_recommendations(asset_data, classification)
        kex_recs = [r for r in recs if "Key Exchange" in r.get("affected_component", "")]
        assert len(kex_recs) >= 1
        assert "ML-KEM" in kex_recs[0]["recommended"]

    def test_rsa_sig_recommends_mldsa(self):
        asset_data, classification = self._make_classified_asset(sig="sha256WithRSAEncryption", key_type="RSA")
        recs = generate_recommendations(asset_data, classification)
        sig_recs = [r for r in recs if "Signature" in r.get("affected_component", "")]
        assert len(sig_recs) >= 1
        assert "ML-DSA" in sig_recs[0]["recommended"]

    def test_pqc_asset_has_no_recommendations(self):
        asset_data = {
            "tls_versions": ["TLS 1.3"],
            "highest_tls_version": "TLS 1.3",
            "key_exchange_algorithms": ["ML-KEM-768"],
            "cert_signature_algorithm": "ML-DSA-65",
            "cert_key_type": "ML-DSA",
            "cipher_suites": [{"name": "AES_256_GCM_SHA384", "bits": 256}],
        }
        classification = classify_asset(asset_data)
        recs = generate_recommendations(asset_data, classification)
        assert len(recs) == 0

    def test_deprecated_tls_recommends_upgrade(self):
        asset_data = {
            "tls_versions": ["TLS 1.0", "TLS 1.2"],
            "highest_tls_version": "TLS 1.2",
            "key_exchange_algorithms": ["ECDHE"],
            "cert_signature_algorithm": "ecdsa-with-SHA256",
            "cert_key_type": "ECDSA",
            "cipher_suites": [{"name": "AES_256_GCM_SHA384", "bits": 256}],
        }
        classification = classify_asset(asset_data)
        recs = generate_recommendations(asset_data, classification)
        tls_recs = [r for r in recs if "Protocol" in r.get("affected_component", "")]
        assert len(tls_recs) >= 1
        assert "TLS 1.3" in tls_recs[0]["recommended"]

    def test_recommendations_have_required_fields(self):
        asset_data, classification = self._make_classified_asset()
        recs = generate_recommendations(asset_data, classification)
        for rec in recs:
            assert "current" in rec
            assert "recommended" in rec
            assert "priority" in rec
            assert "rationale" in rec
            assert "action" in rec
            assert "standard" in rec


# ────────────────── HNDL Risk Tests ──────────────────

class TestHNDLRisk:
    def test_algo_key_rsa_2048(self):
        key = _get_algo_key("RSA", 2048)
        assert key == "RSA-2048"

    def test_algo_key_ecdsa_256(self):
        key = _get_algo_key("ECDSA", 256)
        assert key == "ECDSA-256"

    def test_algo_key_ecdhe_from_name(self):
        key = _get_algo_key("", 0, "ECDHE")
        assert key == "ECDHE"

    def test_algo_key_unknown(self):
        key = _get_algo_key("UNKNOWN", 0)
        assert key is None

    def test_ecdsa256_is_critical_risk(self):
        asset_data = {
            "cert_key_type": "ECDSA",
            "cert_key_size": 256,
            "cert_signature_algorithm": "ecdsa-with-SHA256",
            "key_exchange_algorithms": ["ECDHE"],
        }
        result = compute_hndl_risk(asset_data)
        assert result["risk_level"] == "critical"
        assert result["urgency"] == "IMMEDIATE"
        assert result["earliest_risk_year"] == 2029

    def test_rsa4096_has_longer_timeline(self):
        asset_data = {
            "cert_key_type": "RSA",
            "cert_key_size": 4096,
            "cert_signature_algorithm": "sha256WithRSAEncryption",
            "key_exchange_algorithms": [],
        }
        result = compute_hndl_risk(asset_data)
        assert result["earliest_risk_year"] == 2033

    def test_no_vulnerable_algos_returns_none(self):
        asset_data = {
            "cert_key_type": "ML-DSA",
            "cert_key_size": 0,
            "cert_signature_algorithm": "ML-DSA-65",
            "key_exchange_algorithms": ["ML-KEM-768"],
        }
        result = compute_hndl_risk(asset_data)
        assert result["risk_level"] == "none"

    def test_data_exposure_scenarios_populated(self):
        asset_data = {
            "cert_key_type": "ECDSA",
            "cert_key_size": 256,
            "cert_signature_algorithm": "ecdsa-with-SHA256",
            "key_exchange_algorithms": ["ECDHE"],
        }
        result = compute_hndl_risk(asset_data)
        assert len(result["data_exposure_scenarios"]) > 0
        at_risk = [s for s in result["data_exposure_scenarios"] if s["at_risk"]]
        assert len(at_risk) > 0  # Banking data with long shelf life should be at risk

    def test_customer_pii_is_most_exposed(self):
        """Customer PII has 25-year shelf life — should have longest exposure window."""
        asset_data = {
            "cert_key_type": "ECDSA",
            "cert_key_size": 256,
            "cert_signature_algorithm": "ecdsa-with-SHA256",
            "key_exchange_algorithms": [],
        }
        result = compute_hndl_risk(asset_data)
        pii = [s for s in result["data_exposure_scenarios"] if s["data_type"] == "Customer Pii"]
        assert len(pii) == 1
        assert pii[0]["at_risk"] is True
        assert pii[0]["exposure_window_years"] > 0


# ────────────────── Compliance Tests ──────────────────

class TestCompliance:
    def test_tls13_only_is_compliant(self):
        asset_data = {
            "tls_versions": ["TLS 1.3"],
            "cert_key_type": "ECDSA",
            "cert_key_size": 256,
            "cert_signature_algorithm": "ecdsa-with-SHA256",
            "key_exchange_algorithms": ["ECDHE"],
            "cipher_suites": [{"name": "AES_256_GCM_SHA384", "bits": 256}],
            "cert_not_after": "2027-01-01T00:00:00",
            "score": 58,
            "label": "At Risk",
        }
        classification = classify_asset(asset_data)
        result = assess_compliance(asset_data, classification)

        assert "RBI" in result
        assert "PCI_DSS" in result
        assert "NIST_CSF" in result
        assert "CERT_IN" in result

        # TLS should be compliant (no deprecated versions)
        rbi_reqs = {r["id"]: r for r in result["RBI"]["requirements"]}
        assert rbi_reqs["deprecated_tls"]["status"] == "compliant"

    def test_deprecated_tls_is_noncompliant(self):
        asset_data = {
            "tls_versions": ["TLS 1.0", "TLS 1.2"],
            "score": 20,
            "label": "Critical",
            "cert_not_after": "2027-01-01T00:00:00",
        }
        classification = {"symmetric_ciphers": [], "key_exchanges": [], "signatures": [], "vulnerabilities": []}
        result = assess_compliance(asset_data, classification)

        rbi_reqs = {r["id"]: r for r in result["RBI"]["requirements"]}
        assert rbi_reqs["deprecated_tls"]["status"] == "non-compliant"

    def test_compliance_percentage_format(self):
        asset_data = {
            "tls_versions": ["TLS 1.3"],
            "score": 95,
            "label": "PQC Ready",
            "cert_not_after": "2027-01-01T00:00:00",
        }
        classification = {"symmetric_ciphers": [], "key_exchanges": [], "signatures": [], "vulnerabilities": []}
        result = assess_compliance(asset_data, classification)

        for fw_id, fw_data in result.items():
            assert 0 <= fw_data["compliance_percentage"] <= 100
            assert fw_data["compliant_count"] <= fw_data["total_count"]
