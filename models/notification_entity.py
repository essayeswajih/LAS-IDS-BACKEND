from sqlalchemy import Boolean, DateTime, Integer, String, Column, ForeignKey, func
from sqlalchemy.orm import relationship
from db.database import Base

class Notification(Base):
    __tablename__ = "notification"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    title = Column(String)
    message = Column(String)
    icon = Column(String)
    details = Column(String)
    created_at = Column(DateTime, default=func.now())
    seen = Column(Boolean, default=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User", back_populates="notifications")