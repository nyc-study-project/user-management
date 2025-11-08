from __future__ import annotations

import hashlib
import os
import socket
from datetime import datetime

from typing import Dict, List
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query, Path, Response, Header, status
from typing import Optional
import bcrypt

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
# In-memory storage (simulates DB) for testing
# -----------------------------------------------------------------------------
users_db: Dict[UUID, UserRead] = {}
password_hashes: Dict[UUID, bytes] = {}  # user_id -> password hash


# -----------------------------------------------------------------------------
# Utility helpers
# -----------------------------------------------------------------------------
def generate_etag(user: UserRead) -> str:
    """Create an ETag based on last update timestamp."""
    return hashlib.sha256(user.updated_at.isoformat().encode()).hexdigest()

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed)



# --- Seeded test users for local development (NOT for production) ---
# NOTE: These are stored only in-memory and are intended to make manual testing easier.
# Do NOT commit real credentials to source control.
test_user = UserRead(
    username="testuser",
    age=22,
    occupation="student",
    location="Queens",
)
users_db[test_user.id] = test_user
password_hashes[test_user.id] = hash_password("password123")  # example password for local testing
print(f"[DEV] Seeded test user: username={test_user.username} id={test_user.id}")

test_user2 = UserRead(
    username="alice99",
    age=28,
    occupation="professional",
    location="Manhattan",
)
users_db[test_user2.id] = test_user2
password_hashes[test_user2.id] = hash_password("s3cr3t")
print(f"[DEV] Seeded test user: username={test_user2.username} id={test_user2.id}")



# -----------------------------------------------------------------------------
# User endpoints
# -----------------------------------------------------------------------------

@app.get("/users/{id}", response_model=UserRead)
def get_user(id: UUID, response: Response):
    """Retrieve a user profile by ID with ETag support."""
    user = users_db.get(id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    etag = generate_etag(user)
    response.headers["ETag"] = etag
    return user

@app.put("/users/{id}", response_model=UserRead)
def update_user(
    id: UUID,
    user_update: UserUpdate,
    if_match: Optional[str] = Header(None, alias="If-Match")
):
    """Update a user if ETag matches."""
    user = users_db.get(id) # fetch user
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    current_etag = generate_etag(user) # current ETag
    if if_match and if_match != current_etag: # do not update if the resources has been modified since you fetched it
        raise HTTPException(status_code=412, detail="ETag mismatch (resource modified)")
    
    updated_data = user.model_dump()
    for key, value in user_update.model_dump(exclude_unset=True).items():
        updated_data[key] = value
    updated_data["updated_at"] = datetime.utcnow()

    new_user = UserRead(**updated_data)
    users_db[id] = new_user
    return new_user


@app.delete("/users/{id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(id: UUID):
    """Delete a user profile."""
    if id not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    
    del users_db[id]
    password_hashes.pop(id, None)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@app.get("/users", response_model=List[UserRead])
def list_users(skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=50),
    occupation: Optional[str] = Query(None),
    location: Optional[str] = Query(None),
    ):
    """List users with pagination and optional filters."""
    results = list(users_db.values())

    if occupation:
        results = [u for u in results if u.occupation == occupation]
    if location:
        results = [u for u in results if u.location == location]

    return results[skip : skip + limit]

    

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
