from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class NotificationDTO(BaseModel):
    id: Optional[int] = None
    title: Optional[str] = Field(None, example="New Notification")
    message: Optional[str] = Field(None, example="You have a new message")
    icon: Optional[str] = Field(None, example="bell")
    details: Optional[str] = Field(None, example="No details")
    created_at: Optional[datetime] = Field(default_factory=datetime.now)
    seen: Optional[bool] = Field(default=False)
    class Config:
        from_attributes = True 