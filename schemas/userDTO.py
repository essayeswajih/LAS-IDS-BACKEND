from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, EmailStr, SkipValidation
from models.usersEntity import RoleEnum
from schemas.logDTO import LogDTO
from schemas.notificationDTO import NotificationDTO
from schemas.rowDTO import RowDTO 

class UserDTO(BaseModel):
    id: Optional[int] = None
    username: Optional[str] = None
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    company: Optional[str] = None
    role: RoleEnum = RoleEnum.user
    email: str
    hashed_password: Optional[str] = None
    room_name: Optional[str] = None
    notifications: Optional[List[NotificationDTO]] = []
    logs: Optional[List[LogDTO]] = []
    created_at: Optional[SkipValidation[datetime]] = None

    class Config:
        from_attributes = True

class UserLiteDTO(BaseModel):
    id: Optional[int] = None
    username: Optional[str] = None
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    company: Optional[str] = None
    role: RoleEnum = RoleEnum.user
    email: str
    room_name: Optional[str] = None
    created_at: Optional[SkipValidation[datetime]] = None
    
    class Config:
        from_attributes = True