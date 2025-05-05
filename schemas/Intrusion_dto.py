from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class IntrusionCreateRequest(BaseModel):
    description: Optional[str] = None
    detected_attack: Optional[str] = None
    severity: str = "low"

    class Config:
        from_attributes = True
        arbitrary_types_allowed = True


class IntrusionDTO(BaseModel):
    id: int
    description: Optional[str] = None
    detected_attack: Optional[str] = None
    severity: str = "low"
    timestamp: Optional[datetime] = None
    report_id: int

    class Config:
        from_attributes = True
        arbitrary_types_allowed = True
