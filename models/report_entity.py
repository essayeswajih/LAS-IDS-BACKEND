from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, func
from db.database import Base
from sqlalchemy.orm import relationship


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    created_at = Column(DateTime, default=func.now())

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="reports")

    intrusions = relationship("IntrusionDetected", back_populates="report")