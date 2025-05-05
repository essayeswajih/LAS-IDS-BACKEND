from sqlalchemy import Integer, String, Column, ForeignKey, Enum, DateTime, func
from sqlalchemy.orm import relationship
from db.database import Base
from enum import Enum as PyEnum


class RoleEnum(PyEnum):
    user = "user"
    pro = "pro"
    admin = "admin"
    

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer,primary_key = True, autoincrement = True, index= True)
    username = Column(String, unique=True)
    firstName = Column(String)
    lastName = Column(String)
    company = Column(String)
    role = Column(Enum(RoleEnum), default=RoleEnum.user)
    email = Column(String,unique = True)
    hashed_password = Column(String)
    room_name = Column(String)
    created_at = Column(DateTime, default=func.now())
    stripe_customer_id = Column(String, nullable=True)
    
    notifications = relationship("Notification", back_populates="user")
    logs = relationship("Log", back_populates="user")  
    reports = relationship("Report", back_populates="user")