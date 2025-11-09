from __future__ import annotations

from typing import Optional
from uuid import UUID, uuid4
from datetime import datetime
from pydantic import BaseModel, Field, StringConstraints
from typing_extensions import Annotated

# Username alphanumeric, 3–20 chars
UsernameType = Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_]{3,20}$")]

'''Shared core fields for all models'''
class UserBase(BaseModel):
    username: UsernameType = Field(
        ...,
        description="Unique username used for login.",
        json_schema_extra={"example": "student123"},
    )
    age: Optional[int] = Field(
        None,
        description="Age of the user.",
        json_schema_extra={"example": 21},
    )
    occupation: Optional[str] = Field(
        None,
        description="Occupation (e.g., student, professional).",
        json_schema_extra={"example": "student"},
    )
    location: Optional[str] = Field(
        None,
        description="Location (borough or ZIP).",
        json_schema_extra={"example": "Brooklyn"},
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "username": "student123",
                    "age": 21,
                    "occupation": "student",
                    "location": "Brooklyn",
                }
            ]
        }
    }


class UserCreate(UserBase):
    """Payload for creating a user account (adding password here)"""
    password: str = Field(
        ...,
        description="Raw password (will be hashed before storage)",
        json_schema_extra={"example": "StrongP@ssw0rd"},
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "username": "student123",
                    "age": 21,
                    "occupation": "student",
                    "location": "Brooklyn",
                    "password": "StrongP@ssw0rd"
                }
            ]
        }
    }

'''Contains only the fields that the user is allowed to change'''
class UserUpdate(BaseModel):
    """Partial update for user profile; supply only fields to change."""
    age: Optional[int] = Field(None, json_schema_extra={"example": 22})
    occupation: Optional[str] = Field(None, json_schema_extra={"example": "professional"})
    location: Optional[str] = Field(None, json_schema_extra={"example": "Manhattan"})

'''The full user profile returned to the client including server-generated fields'''
class UserRead(UserBase):
    id: UUID = Field(default_factory=uuid4, description="Server-generated User ID")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Account creation time (UTC)")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Last update time (UTC)")