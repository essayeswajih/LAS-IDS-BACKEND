from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel
from schemas.Intrusion_dto import IntrusionCreateRequest, IntrusionDTO


class ReportCreateRequest(BaseModel):
    id: Optional[int] = None
    title: Optional[str] = None
    description: Optional[str] = None
    intrusions: List[IntrusionCreateRequest] = []

    class Config:
        from_attributes = True
        arbitrary_types_allowed = True


class ReportDTO(BaseModel):
    id: Optional[int] = None
    title: Optional[str] = None
    description: Optional[str] = None
    intrusions: List[IntrusionDTO] = []
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True
        arbitrary_types_allowed = True

class ReporLitetDTO(BaseModel):
    id: Optional[int] = None
    title: Optional[str] = None
    description: Optional[str] = None
    created_at: Optional[datetime] = None
    intrusion_count: Optional[int] = None

    class Config:
        from_attributes = True
        arbitrary_types_allowed = True