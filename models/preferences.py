from __future__ import annotations
from typing import Optional
from uuid import UUID, uuid4
from datetime import datetime
from pydantic import BaseModel, Field

'''1-to-1 with users meaning one preference set belongs to one user'''

'''Shared core fields for all models, open to changes to these fields since I was a bit unsure about it'''
class PreferencesBase(BaseModel):
    environment: Optional[Literal["quiet", "lively", "moderate"]] = Field(
        None,
        description="Preferred noise/environment level.",
        json_schema_extra={"example": "quiet"},
    )
    wifi_required: Optional[bool] = Field(
        None,
        description="Does the user require WiFi?",
        json_schema_extra={"example": True},
    )
    open_late: Optional[bool] = Field(
        None,
        description="Does the user prefer spots open late?",
        json_schema_extra={"example": False},
    )
    refreshments_available: Optional[bool] = Field(
        None,
        description="Preference for drink availability.",
        json_schema_extra={"example": True},
    )
    food_available: Optional[bool] = Field(
        None,
        description="Preference for food availability.",
        json_schema_extra={"example": True},
    )
    outlets_available: Optional[bool] = Field(
        None,
        description="Preference for power outlets availability.",
        json_schema_extra={"example": True},
    )
    other_preferences: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Flexible additional preferences so we're not limiting what preferences the user can enter.",
        json_schema_extra={"example": {"nice_view": True}},
    )
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "environment": "quiet",
                    "wifi_required": True,
                    "open_late": False,
                    "refreshments_available": True,
                    "food_available": False,
                    "outlets_available": True,
                    "other_preferences": {"plants": True},
                }
            ]
        }
    )

    class PreferencesCreate(PreferencesBase):
        """Payload for creating preferences. No additional fields added, just iherit base"""
        pass 

    class PreferencesUpdate(BaseModel):
        """Partial update for preferences (only send fields to change)"""
        environment: Optional[Literal["quiet", "lively", "moderate"]] = None
        wifi_required: Optional[bool] = None
        open_late: Optional[bool] = None
        refreshments_available: Optional[bool] = None
        food_available: Optional[bool] = None
        outlets_available: Optional[bool] = None
        other_preferences: Optional[Dict[str, Any]] = None

class PreferencesRead(PreferencesBase):
    id: UUID = Field(default_factory=uuid4, description="Preferences ID")
    user_id: UUID = Field(..., description="Associated user ID")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp (UTC)")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Last update timestamp (UTC)")