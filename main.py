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
from models.session import SessionCreate, SessionRead, LoginRequest
from models.health import Health

import mysql.connector


def get_connection():
    """Return a MySQL connection depending on the environment."""
    try:
        if os.environ.get("ENV") == "local":
            return mysql.connector.connect(
                host="127.0.0.1",
                user="root",     
                password=os.environ["DB_PASSWORD"], 
                database="user_management",
                port=3306,
            )
        else:
            return mysql.connector.connect(
                host=os.environ["DB_HOST"],
                user=os.environ["DB_USER"],
                password=os.environ["DB_PASSWORD"],
                database=os.environ["DB_NAME"],
                port=int(os.environ.get("DB_PORT", 3306)),
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database connection failed: {e}")
    
Session = get_connection()
print(Session)

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
sessions_db: Dict[UUID, SessionRead] = {}
preferences_db: Dict[UUID, PreferencesRead] = {}




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

preferences_db[test_user.id] = PreferencesRead(
    user_id=test_user.id,
    wifi_required=True,
    outlets_required=True,
    seating_preference="1-5",
    refreshments_preferred=["coffee"],
    environment=["quiet", "indoor"],
)

preferences_db[test_user2.id] = PreferencesRead(
    user_id=test_user2.id,
    wifi_required=False,
    outlets_required=True,
    seating_preference="6-10",
    refreshments_preferred=["water", "pastries"],
    environment=["lively", "outdoor"],
)



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

@app.get("/users/{id}/preferences", response_model=PreferencesRead)
def get_preferences(id: UUID):
    """Retrieve a user's saved preferences."""
    user = users_db.get(id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    preferences = preferences_db.get(id)
    if not preferences:
        raise HTTPException(status_code=404, detail="Preferences not set for this user")

    return preferences

@app.post("/users/{id}/preferences", response_model=PreferencesRead, status_code=201)
def create_preferences(id: UUID, prefs: PreferencesCreate):
    """Create preferences for a user (one-to-one relationship)."""
    user = users_db.get(id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if id in preferences_db:
        raise HTTPException(status_code=400, detail="Preferences already exist for this user")

    new_prefs = PreferencesRead(
        user_id=id,
        **prefs.model_dump(exclude_unset=True)
    )
    preferences_db[id] = new_prefs
    return new_prefs

@app.put("/users/{id}/preferences", response_model=PreferencesRead)
def update_preferences(id: UUID, prefs_update: PreferencesUpdate):
    """Update existing user preferences."""
    user = users_db.get(id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    existing_prefs = preferences_db.get(id)
    if not existing_prefs:
        raise HTTPException(status_code=404, detail="Preferences not found for this user")

    updated_data = existing_prefs.model_dump()
    for key, value in prefs_update.model_dump(exclude_unset=True).items():
        updated_data[key] = value
    updated_data["updated_at"] = datetime.utcnow()

    updated_prefs = PreferencesRead(**updated_data)
    preferences_db[id] = updated_prefs
    return updated_prefs

@app.delete("/users/{id}/preferences", status_code=204)
def delete_preferences(id: UUID):
    """Delete or reset user preferences."""
    user = users_db.get(id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if id not in preferences_db:
        raise HTTPException(status_code=404, detail="Preferences not found")

    del preferences_db[id]
    return Response(status_code=204)

# -----------------------------------------------------------------------------
# Session endpoints
# -----------------------------------------------------------------------------

@app.post("/auth/register", response_model=UserRead, status_code=201)
def register_user(user: UserCreate):
    try:
        """Create a new user with hashed password."""
        # Check if username is already taken
        if any(u.username == user.username for u in users_db.values()):
            raise HTTPException(status_code=400, detail="Username already exists")
        
        # Create user and hash password
        new_user = UserRead(
            username=user.username,
            age=user.age,
            occupation=user.occupation,
            location=user.location,
        )
        users_db[new_user.id] = new_user
        password_hashes[new_user.id] = hash_password(user.password)
        return new_user
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error during registration") from e


@app.post("/auth/login")
def login_user(credentials: LoginRequest):
    try:
        """Authenticate user and create a new session."""
        username = credentials.username
        password = credentials.password

        if not username or not password:
            raise HTTPException(status_code=400, detail="Username and password required")
        
        # Find user by username
        user = next((u for u in users_db.values() if u.username == username), None)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Verify password
        hashed_pw = password_hashes.get(user.id)
        if not hashed_pw or not verify_password(password, hashed_pw):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Create new session
        session = SessionRead(user_id=user.id)
        sessions_db[session.session_id] = session

        #print(sessions_db)

        return {
            "message": "Login successful",
            "session_id": str(session.session_id),
            "expires_at": session.expires_at,
            "user_id": str(user.id)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error during login") from e

@app.post("/auth/logout", status_code=204)
def logout_user(
    auth: str = Header(
        ...,
        description="Bearer token containing your session ID",
        example="Bearer 123e4567-e89b-12d3-a456-426614174000"
    )
):
    """Logout user by deleting session."""
    if not auth:
        raise HTTPException(status_code=400, detail="Missing Authorization header")

    # Expect the header to be something like "Bearer <session_id>"
    try:
        token = auth.split(" ")[1]
        session_id = UUID(token)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Authorization format")

    if session_id not in sessions_db:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    # Delete session
    del sessions_db[session_id]
    #print(sessions_db)
    return Response(status_code=204)

@app.get("/auth/me", response_model=UserRead)
def get_current_user(
        auth: str = Header(
        ...,
        description="Bearer token containing your session ID",
        example="Bearer 123e4567-e89b-12d3-a456-426614174000"
    )):
    """Return the current authenticated user's profile."""
    if not auth:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    
    try:
        token = auth.split(" ")[1]
        session_id = UUID(token)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Authorization format")

    session = sessions_db.get(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    # Check expiry
    if session.expires_at < datetime.utcnow():
        del sessions_db[session_id]
        raise HTTPException(status_code=401, detail="Session expired")

    # Return user info
    user = users_db.get(session.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user


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
