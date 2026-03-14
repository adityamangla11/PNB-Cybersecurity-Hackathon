import ssl
import socket
import datetime
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional

try:
    from sslyze import (
        Scanner, ServerScanRequest, ServerNetworkLocation,
        ScanCommand, ServerScanResultAsDict,
    )
    from sslyze.errors import ServerHostnameCouldNotBeResolved
    SSLYZE_AVAILABLE = True
except ImportError:
    SSLYZE_AVAILABLE = False

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa

logger = logging.getLogger(__name__)

TLS_VERSION_MAP = {
    ssl.TLSVersion.TLSv1: "TLS 1.0",
    ssl.TLSVersion.TLSv1_1: "TLS 1.1",
    ssl.TLSVersion.TLSv1_2: "TLS 1.2",
    ssl.TLSVersion.TLSv1_3: "TLS 1.3",
}

TLS_VERSION_RANK = {"TLS 1.3": 4, "TLS 1.2": 3, "TLS 1.1": 2, "TLS 1.0": 1}


@dataclass
class CertInfo:
    subject: str = ""
    issuer: str = ""
    not_before: Optional[datetime.datetime] = None
    not_after: Optional[datetime.datetime] = None
    key_type: str = ""
    key_size: int = 0
    signature_algorithm: str = ""
    serial_number: str = ""


@dataclass
class ScanResult:
    host: str = ""
    port: int = 443
    asset_type: str = "web_server"
    tls_versions: list[str] = field(default_factory=list)
    highest_tls_version: str = ""
    cert_info: CertInfo = field(default_factory=CertInfo)
    cipher_suites: list[dict] = field(default_factory=list)
    key_exchange_algorithms: list[str] = field(default_factory=list)
    error: Optional[str] = None


def _get_key_info(public_key) -> tuple[str, int]:
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ECDSA", public_key.key_size
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    elif isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", 448
    elif isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size
    return "Unknown", 0


def _extract_cert_info(der_cert: bytes) -> CertInfo:
    cert = x509.load_der_x509_certificate(der_cert)
    pub = cert.public_key()
    key_type, key_size = _get_key_info(pub)
    sig_algo = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown")

    return CertInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        key_type=key_type,
        key_size=key_size,
        signature_algorithm=sig_algo,
        serial_number=format(cert.serial_number, 'x'),
    )


def _probe_tls_version(host: str, port: int, tls_version) -> bool:
    """Check if a specific TLS version is supported."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = tls_version
        ctx.maximum_version = tls_version
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return True
    except (ssl.SSLError, OSError, socket.timeout):
        return False


def _get_cipher_suites_for_version(host: str, port: int, tls_version) -> list[dict]:
    """Get cipher suites accepted by the server for a TLS version."""
    suites = []
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = tls_version
        ctx.maximum_version = tls_version
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    suites.append({
                        "name": cipher[0],
                        "protocol": cipher[1],
                        "bits": cipher[2],
                    })
    except (ssl.SSLError, OSError, socket.timeout):
        pass
    return suites


def _extract_key_exchange(cipher_name: str, protocol: str = "") -> str:
    """Extract key exchange algorithm from cipher suite name."""
    cipher_upper = cipher_name.upper()
    protocol_upper = protocol.upper() if protocol else ""

    # PQC key exchanges
    if "X25519KYBER" in cipher_upper:
        return "X25519Kyber768 (Hybrid PQC)"
    if "KYBER" in cipher_upper or "ML-KEM" in cipher_upper or "MLKEM" in cipher_upper:
        return "ML-KEM (Kyber)"

    # Classical key exchanges
    if "ECDHE" in cipher_upper or "ECDH" in cipher_upper:
        return "ECDHE"
    if "DHE" in cipher_upper or "EDH" in cipher_upper:
        return "DHE"
    if "RSA" in cipher_upper:
        return "RSA"

    # TLS 1.3 cipher suites (TLS_AES_256_GCM_SHA384 etc.) don't embed
    # the key exchange in the name — TLS 1.3 always uses ephemeral
    # key exchange (ECDHE with X25519 or P-256 by default)
    if cipher_upper.startswith("TLS_") or "TLSV1.3" in protocol_upper or "TLS 1.3" in protocol_upper:
        return "ECDHE (X25519)"

    return "Unknown"


def scan_target(host: str, port: int = 443) -> ScanResult:
    """Scan a single target for TLS configuration and crypto details."""
    result = ScanResult(host=host, port=port)

    # 1. Probe TLS versions
    versions_to_probe = [
        (ssl.TLSVersion.TLSv1, "TLS 1.0"),
        (ssl.TLSVersion.TLSv1_1, "TLS 1.1"),
        (ssl.TLSVersion.TLSv1_2, "TLS 1.2"),
        (ssl.TLSVersion.TLSv1_3, "TLS 1.3"),
    ]

    for tls_ver, ver_name in versions_to_probe:
        try:
            if _probe_tls_version(host, port, tls_ver):
                result.tls_versions.append(ver_name)
        except Exception:
            pass

    if not result.tls_versions:
        # Fallback: try a generic connection
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    ver = ssock.version()
                    if ver:
                        result.tls_versions.append(ver.replace("v", " ").replace("TLSv", "TLS "))
        except Exception as e:
            result.error = f"Could not establish TLS connection: {str(e)}"
            return result

    # Determine highest TLS version
    if result.tls_versions:
        result.highest_tls_version = max(
            result.tls_versions, key=lambda v: TLS_VERSION_RANK.get(v, 0)
        )

    # 2. Get certificate info and cipher suites via default connection
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                # Certificate
                der_cert = ssock.getpeercert(binary_form=True)
                if der_cert:
                    result.cert_info = _extract_cert_info(der_cert)

                # Negotiated cipher
                cipher = ssock.cipher()
                if cipher:
                    suite_info = {
                        "name": cipher[0],
                        "protocol": cipher[1],
                        "bits": cipher[2],
                    }
                    if suite_info not in result.cipher_suites:
                        result.cipher_suites.append(suite_info)
    except Exception as e:
        if not result.error:
            result.error = f"Certificate/cipher extraction error: {str(e)}"

    # 3. Collect cipher suites per TLS version
    for tls_ver, ver_name in versions_to_probe:
        if ver_name in result.tls_versions:
            suites = _get_cipher_suites_for_version(host, port, tls_ver)
            for s in suites:
                s["tls_version"] = ver_name
                if s not in result.cipher_suites:
                    result.cipher_suites.append(s)

    # 4. Extract key exchange algorithms
    kex_set = set()
    for suite in result.cipher_suites:
        kex = _extract_key_exchange(suite["name"], suite.get("protocol", ""))
        kex_set.add(kex)
    result.key_exchange_algorithms = sorted(kex_set)

    # 5. Detect asset type via HTTP headers
    try:
        import httpx
        resp = httpx.get(
            f"https://{host}:{port}/",
            verify=False, timeout=5, follow_redirects=True
        )
        content_type = resp.headers.get("content-type", "")
        server = resp.headers.get("server", "")
        if "application/json" in content_type or "application/xml" in content_type:
            result.asset_type = "api"
        elif "vpn" in server.lower() or "vpn" in host.lower():
            result.asset_type = "vpn"
        else:
            result.asset_type = "web_server"
    except Exception:
        pass  # keep default web_server

    return result


def parse_target(target: str) -> tuple[str, int]:
    """Parse 'host' or 'host:port' into (host, port)."""
    target = target.strip()
    if target.startswith("https://"):
        target = target[8:]
    elif target.startswith("http://"):
        target = target[7:]
    target = target.rstrip("/")

    if ":" in target:
        parts = target.rsplit(":", 1)
        try:
            return parts[0], int(parts[1])
        except ValueError:
            return target, 443
    return target, 443
