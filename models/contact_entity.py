from sqlalchemy import Column, Integer, String, Text
from db.database import Base


class Contact(Base):
    __tablename__ = "contact"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String)
    email = Column(String)
    subject = Column(String)
    message = Column(Text)