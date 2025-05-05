from sqlalchemy import DateTime, Float, Integer, String, Column, ForeignKey, Text, func
from sqlalchemy.orm import relationship
from db.database import Base

class Log(Base):
    __tablename__ = "log"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    log_of = Column(String)
    file_name = Column(String)
    file_type = Column(String)
    file_hash = Column(String)
    rows_count = Column(Integer)
    log_format = Column(Text)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime)
    size = Column(Float)
    rows = relationship("Row", back_populates="owner")

    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User", back_populates="logs")