import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DATABASE_URL = "sqlite:///./quantum_scanner.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    status = Column(String, default="pending")  # pending, running, completed, failed
    total_targets = Column(Integer, default=0)
    completed_targets = Column(Integer, default=0)

    assets = relationship("Asset", back_populates="scan", cascade="all, delete-orphan")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True)
    host = Column(String, index=True)
    port = Column(Integer, default=443)
    asset_type = Column(String, default="web_server")  # web_server, api, vpn

    # TLS info
    tls_versions = Column(JSON)
    highest_tls_version = Column(String)

    # Certificate info
    cert_subject = Column(String)
    cert_issuer = Column(String)
    cert_not_before = Column(DateTime)
    cert_not_after = Column(DateTime)
    cert_key_type = Column(String)
    cert_key_size = Column(Integer)
    cert_signature_algorithm = Column(String)
    cert_serial_number = Column(String)

    # Cipher suites & key exchange
    cipher_suites = Column(JSON)
    key_exchange_algorithms = Column(JSON)

    # Scoring
    score = Column(Float, default=0.0)
    label = Column(String, default="Unknown")  # PQC Ready, Quantum-Safe, At Risk, Critical

    # Classification details
    classification_details = Column(JSON)

    # Recommendations
    recommendations = Column(JSON)

    scanned_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan", back_populates="assets")


def init_db():
    Base.metadata.create_all(bind=engine)
