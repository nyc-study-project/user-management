from __future__ import annotations

import os
import socket
from datetime import datetime

from typing import Dict, List
from uuid import UUID

from fastapi import FastAPI, HTTPException
from fastapi import Query, Path
from typing import Optional

from models.user import UserCreate, UserRead, UserUpdate
from models.preferences import PreferencesRead, PreferencesCreate, PreferencesUpdate
from models.session import SessionCreate, SessionRead
from models.health import Health

port = int(os.environ.get("FASTAPIPORT", 8000))

app = FastAPI(
    title="User Management Microservice",
    description="Handles registration, login, authentication, and user preferences for study spots app",
)

# -----------------------------------------------------------------------------
# User endpoints
# -----------------------------------------------------------------------------

@app.get("/users/{id}")
def get_user(id: UUID):
    raise HTTPException(status_code=501, detail="Not implemented: Get user profile by ID")

@app.put("/users/{id}")
def update_user(id: UUID):
    raise HTTPException(status_code=501, detail="Not implemented: Update user profile")

@app.delete("/users/{id}")
def delete_user(id: UUID):
    raise HTTPException(status_code=501, detail="Not implemented: Delete user profile and associated preferences and sessions")

@app.get("/users")
def list_users():
    raise HTTPException(status_code=501, detail="Not implemented: List all users")

# -----------------------------------------------------------------------------
# Preferences endpoints
# -----------------------------------------------------------------------------

@app.get("/users/{id}/preferences")
def get_preferences(id: UUID):
    raise HTTPException(status_code=501, detail="Not implemented: Retrieve preferences for a user")

@app.put("/users/{id}/preferences")
def update_preferences(id: UUID):
    raise HTTPException(status_code=501, detail="Not implemented: Update preferences for a user")

@app.delete("/users/{id}/preferences")
def delete_preferences(id: UUID):
    raise HTTPException(status_code=501, detail="Not implemented: Delete/reset preferences for a user")

# -----------------------------------------------------------------------------
# Session endpoints
# -----------------------------------------------------------------------------

@app.post("/auth/register")
def register_user():
    raise HTTPException(status_code=501, detail="Not implemented: Create new user and hash password")

@app.post("/auth/login")
def login_user():
    raise HTTPException(status_code=501, detail="Not implemented: Authenticate user and create session")

@app.post("/auth/logout")
def logout_user():
    raise HTTPException(status_code=501, detail="Not implemented: Invalidate current session")

@app.get("/auth/me")
def get_current_user():
    raise HTTPException(status_code=501, detail="Not implemented: Return current authenticated user profile")


# -----------------------------------------------------------------------------
# Health endpoints
# -----------------------------------------------------------------------------

def make_health(echo: Optional[str], path_echo: Optional[str]=None) -> Health:
    return Health(
        status=200,
        status_message="OK",
        timestamp=datetime.utcnow().isoformat() + "Z",
        ip_address=socket.gethostbyname(socket.gethostname()),
        echo=echo,
        path_echo=path_echo
    )

@app.get("/health", response_model=Health)
def get_health_no_path(echo: str | None = Query(None, description="Optional echo string")):
    # Works because path_echo is optional in the model
    return make_health(echo=echo, path_echo=None)

@app.get("/health/{path_echo}", response_model=Health)
def get_health_with_path(
    path_echo: str = Path(..., description="Required echo in the URL path"),
    echo: str | None = Query(None, description="Optional echo string"),
):
    return make_health(echo=echo, path_echo=path_echo)

# -----------------------------------------------------------------------------
# Root
# -----------------------------------------------------------------------------
@app.get("/")
def root():
    return {"message": "Welcome to the User-Management API. See /docs for OpenAPI UI."}

# -----------------------------------------------------------------------------
# Entrypoint for `python main.py`
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
