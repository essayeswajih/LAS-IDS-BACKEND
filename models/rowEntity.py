from sqlalchemy import Integer, String, Column, ForeignKey
from sqlalchemy.orm import relationship
from db.database import Base

class Row(Base):
    __tablename__ = "row"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ip = Column(String, index=True)
    url = Column(String)
    timestamp = Column(String)
    method = Column(String)
    status = Column(Integer)
    referer = Column(String)
    user_agent = Column(String)
    response_size = Column(Integer)
    
    # Additional fields for compatibility with other log types
    protocol = Column(String, nullable=True)     # Network protocol (e.g., TCP, UDP, HTTP)
    src_port = Column(Integer, nullable=True)    # Source port (for firewall/network logs)
    dest_port = Column(Integer, nullable=True)   # Destination port (for network logs)
    message = Column(String, nullable=True)      # General message field for log entries
    level = Column(String, nullable=True)        # Log level (e.g., INFO, ERROR, WARNING)
    component = Column(String, nullable=True)    # Component or service generating the log
    user = Column(String, nullable=True)
    remote_logname = Column(String, nullable=True)

    request = Column(String, nullable=True)
    pid = Column(String, nullable=True)
    tid = Column(String, nullable=True)
    module = Column(String, nullable=True)
    event_id = Column(Integer, nullable=True)

    entry_type = Column(Integer, nullable=True)
    provider_name = Column(String, nullable=True)
    computer_name = Column(String, nullable=True)
    task_display_name = Column(String, nullable=True)
    level_display_name = Column(String, nullable=True)
    account_name =  Column(String, nullable=True)
    run_as_user =  Column(String, nullable=True)
    hostname = Column(String, nullable=True)

    log_id = Column(Integer, ForeignKey('log.id'))
    owner = relationship("Log", back_populates="rows")
