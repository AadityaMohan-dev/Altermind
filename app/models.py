from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from .db import Base

def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)

class Event(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String, index=True, nullable=False)
    username = Column(String, default="unknown")
    source_ip = Column(String, default="unknown")
    process_name = Column(String, default="")
    command_line = Column(Text, default="")
    message = Column(Text, default="")
    timestamp = Column(DateTime, default=utcnow)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("events.id"), nullable=False)
    rule_id = Column(String, nullable=False)
    title = Column(String, nullable=False)
    severity = Column(String, default="medium")
    evidence = Column(Text, default="")
    status = Column(String, default="open")
    created_at = Column(DateTime, default=utcnow)
    event = relationship("Event")
    case = relationship("Case", back_populates="alert", uselist=False)

class Case(Base):
    __tablename__ = "cases"
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), unique=True, nullable=False)
    title = Column(String, nullable=False)
    status = Column(String, default="open")
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=utcnow)
    alert = relationship("Alert", back_populates="case")
