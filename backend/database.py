"""
database.py
-----------
Handles all database setup and session management.
Uses SQLAlchemy ORM with SQLite for the development phase.
PostgreSQL can be swapped in for production by changing DATABASE_URL.
Author: Khushali (D24DIT007)
"""

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

# SQLite file-based database for development
# Switch to "postgresql://user:pass@host/dbname" for production
DATABASE_URL = "sqlite:///./pdfortress.db"

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
    verdict = Column(String, nullable=True)                   # "Safe", "Suspicious", "Malicious"
    risk_score = Column(Float, nullable=True)                 # Numeric score 0-100+
    analysis_summary = Column(Text, nullable=True)            # JSON string of full findings
    is_encrypted = Column(Integer, default=0)                 # 0=No, 1=Yes (SQLite has no bool)
    page_count = Column(Integer, nullable=True)
    author = Column(String, nullable=True)


def init_db():
    """Creates all database tables if they don't already exist."""
    Base.metadata.create_all(bind=engine)


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
