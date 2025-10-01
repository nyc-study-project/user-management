from __future__ import annotations
from uuid import UUID, uuid4
from datetime import datetime, timedelta
from pydantic import BaseModel, Field

class SessionBase(BaseModel):
    user_id: UUID = Field(..., description="The user this session belongs to")

class SessionCreate(SessionBase):
    pass   #session created automatically during login 

class SessionRead(SessionBase):
    session_id: UUID = Field(default_factory=uuid4, description="Unique session token")
    expires_at: datetime = Field(default_factory=lambda: datetime.utcnow() + timedelta(hours=1),
                                 description="Session expiry time (UTC)")