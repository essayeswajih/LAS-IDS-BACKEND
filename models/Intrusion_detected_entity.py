from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import relationship
from db.database import Base

class IntrusionDetected(Base):
    __tablename__ = "intrusions_detected"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    detected_attack = Column(String, nullable=True)
    description = Column(String, nullable=False)
    timestamp = Column(DateTime, default=func.now())
    severity = Column(String,nullable=True) 
    report_id = Column(Integer, ForeignKey("reports.id"), nullable=False)
    report = relationship("Report", back_populates="intrusions")