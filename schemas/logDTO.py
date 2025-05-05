from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, SkipValidation
from schemas.rowDTO import RowDTO 

class LogDTO(BaseModel):
    id: int
    rows: List[RowDTO] = []
    log_of: Optional[str] = None
    file_name: Optional[str] = None
    file_type: Optional[str] = None
    file_hash: Optional[str] = None
    rows_count: Optional[int] = 0
    log_format: Optional[str] = None
    size: Optional[float] = None
    created_at: Optional[SkipValidation[datetime]] = None
    updated_at: Optional[SkipValidation[datetime]] = None

    class Config:
        from_attributes = True
        arbitrary_types_allowed = True

class LogCreate(BaseModel):
    log_of: Optional[str] = None
    file_name: Optional[str] = None
    file_type: Optional[str] = None
    file_hash: Optional[str] = None
    rows_count: Optional[int] = 0
    log_format: Optional[str] = None
    size: Optional[float] = None

    class Config:
        from_attributes = True
        arbitrary_types_allowed = True

class LogWithoutRowsDTO(BaseModel):
    id: int
    log_of: Optional[str] = None
    file_name: Optional[str] = None
    file_type: Optional[str] = None
    file_hash: Optional[str] = None
    rows_count: Optional[int] = 0
    log_format: Optional[str] = None
    size: Optional[float] = None
    created_at: Optional[SkipValidation[datetime]] = None
    updated_at: Optional[SkipValidation[datetime]] = None

    class Config:
        from_attributes = True
        arbitrary_types_allowed = True