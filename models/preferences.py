from __future__ import annotations
from typing import  Any, Dict, Literal, Optional
from uuid import UUID, uuid4
from datetime import datetime
from pydantic import BaseModel, Field

'''1-to-1 with users meaning one preference set belongs to one user'''

'''Shared core fields for all models, open to changes to these fields since I was a bit unsure about it'''
class PreferencesBase(BaseModel):
    wifi_required: Optional[bool] = Field(
        None,
        description="Does the user require WiFi?",
        json_schema_extra={"example": True},
    )
    outlets_required: Optional[bool] = Field(
        None, description="Does the user need power outlets?", json_schema_extra={"example": True}
    )
    seating_preference: Optional[Literal["1-5", "6-10", "11-20", "20+"]]= Field(
        None, description="Preferred group size or seating capacity.", json_schema_extra={"example": "1-5"}
    )
    refreshments_preferred: Optional[list[str]] = Field(
        None,
        description="Preferred refreshments or food availability.",
        json_schema_extra={"example": ["coffee", "pastries"]},
    )
    environment: Optional[list[Literal["quiet", "lively", "indoor", "outdoor", "moderate"]]] = Field(
        None,
        description="Preferred environment types (noise level, setting).",
        json_schema_extra={"example": ["quiet", "indoor"]},
    )
    #food_available: Optional[bool] = Field(
        #None,
        #description="Preference for food availability.",
        #json_schema_extra={"example": True},
    #)
    #other_preferences: Optional[Dict[str, Any]] = Field(
        #default_factory=dict,
        #description="Flexible additional preferences so we're not limiting what preferences the user can enter.",
        #json_schema_extra={"example": {"nice_view": True}},
    #)
     #open_late: Optional[bool] = Field(
       # None,
       # description="Does the user prefer spots open late?",
       # json_schema_extra={"example": False},
    # )
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "wifi_required": True,
                    "outlets_required": True,
                    "seating_preference": "1-5",
                    "refreshments_preferred": ["coffee", "pastries"],
                    "environment": ["quiet", "indoor"],
                }
            ]
        }
    }

class PreferencesCreate(PreferencesBase):
    """Payload for creating preferences. No additional fields added, just inherit base"""
    pass 

class PreferencesUpdate(BaseModel):
    """Partial update for preferences (only send fields to change)"""
    wifi_required: Optional[bool] = None    
    outlets_required: Optional[bool] = None
    seating_preference: Optional[Literal["1-5", "6-10", "11-20", "20+"]] = None
    refreshments_preferred: Optional[list[str]] = None
    environment: Optional[list[Literal["quiet", "lively", "indoor", "outdoor", "moderate"]]] = None

class PreferencesRead(PreferencesBase):
    id: UUID = Field(default_factory=uuid4, description="Preferences ID")
    user_id: UUID = Field(..., description="Associated user ID")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp (UTC)")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Last update timestamp (UTC)")