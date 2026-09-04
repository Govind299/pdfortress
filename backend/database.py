"""
database.py
-----------
Handles all database setup and session management.
Uses SQLAlchemy ORM with SQLite for the development phase.
PostgreSQL can be swapped in for production by changing DATABASE_URL.
Author: Khushali (D24DIT007)
"""

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

# SQLite file-based database for development
# Switch to "postgresql://user:pass@host/dbname" for production
DATABASE_URL = "sqlite:///./pdfortress_v2.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}  # Required for SQLite with FastAPI
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


class Scan(Base):
    """
    Represents a single PDF scan record.
    Stores the file metadata and the final analysis verdict.
    """
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    original_filename = Column(String, nullable=False)        # e.g. "invoice.pdf"
    stored_filename = Column(String, unique=True, nullable=False)  # UUID-based safe name
    upload_time = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="PENDING")                 # "PENDING", "PROCESSING", "COMPLETED", "FAILED"
    verdict = Column(String, nullable=True)                   # "Safe", "Suspicious", "Malicious"
    risk_score = Column(Float, nullable=True)                 # Numeric score 0-100+
    analysis_summary = Column(Text, nullable=True)            # JSON string of full findings
    is_encrypted = Column(Integer, default=0)                 # 0=No, 1=Yes (SQLite has no bool)
    page_count = Column(Integer, nullable=True)
    author = Column(String, nullable=True)
    batch_id = Column(String, nullable=True, index=True)      # Batch upload tracking UUID


def init_db():
    """Creates all database tables if they don't already exist and handles column migration."""
    Base.metadata.create_all(bind=engine)
    try:
        with engine.connect() as conn:
            conn.execute(text("ALTER TABLE scans ADD COLUMN batch_id TEXT"))
            conn.commit()
    except Exception:
        pass



def get_db():
    """
    Dependency function for FastAPI.
    Provides a database session per request and ensures it closes after.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def cleanup_expired_scans(hours: int = 24, upload_dir: str = "uploads") -> dict:
    """
    Server-side cleanup routine.
    Purges temporary file uploads and database records older than specified hours (default 24h).
    Author: Raj Patel (23DIT007)
    """
    import os
    from datetime import timedelta
    db = SessionLocal()
    cleaned_files = 0
    cleaned_records = 0
    try:
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        expired_scans = db.query(Scan).filter(Scan.upload_time < cutoff).all()

        for scan in expired_scans:
            if scan.stored_filename:
                file_path = os.path.join(upload_dir, scan.stored_filename)
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                        cleaned_files += 1
                    except Exception:
                        pass
            db.delete(scan)
            cleaned_records += 1

        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

    return {"cleaned_files": cleaned_files, "cleaned_records": cleaned_records}

