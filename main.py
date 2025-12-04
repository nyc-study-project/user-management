from __future__ import annotations

import hashlib
import os
import socket
from datetime import datetime
import json

from typing import List
from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException, Query, Path, Response, Header, status, Request
from typing import Optional
import bcrypt

from models.user import UserRead, UserUpdate
from models.preferences import PreferencesRead, PreferencesCreate, PreferencesUpdate
from models.health import Health

import mysql.connector

from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware

import my_secrets

GOOGLE_CLIENT_ID = my_secrets.GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET = my_secrets.GOOGLE_CLIENT_SECRET
SESSION_SECRET_KEY = my_secrets.SECRET_KEY

# replace this with direct connection to Cloud SQL using private IP already in VM's version of user_management
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
    

def execute_query(query, params=None, fetchone=False, fetchall=False, commit=False):
    """Generic helper for running MySQL queries safely."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(query, params or ())
        if commit:
            conn.commit()
        if fetchone:
            return cursor.fetchone()
        if fetchall:
            return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()
    
Session = get_connection()

port = int(os.environ.get("FASTAPIPORT", 8000))

app = FastAPI(
    title="User Management Microservice",
    description="Handles registration, login, authentication, and user preferences for study spots app",
)

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET_KEY,
)

oauth = OAuth()

oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

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

# -----------------------------------------------------------------------------
# Database helpers for users
# -----------------------------------------------------------------------------
def get_user_by_id(user_id: UUID):
    query = "SELECT * FROM users WHERE id = %s"
    return execute_query(query, (str(user_id),), fetchone=True)

def update_user_record(user_id: UUID, fields: dict):
    # dynamic query builder for partial updates
    set_clause = ", ".join([f"{col}=%s" for col in fields])
    values = list(fields.values()) + [str(user_id)]
    query = f"UPDATE users SET {set_clause}, updated_at=NOW() WHERE id=%s"
    execute_query(query, values, commit=True)
    return get_user_by_id(user_id)

def delete_user_record(user_id: UUID):
    query = "DELETE FROM users WHERE id = %s"
    execute_query(query, (str(user_id),), commit=True)

def list_users_db(skip: int, limit: int, occupation: Optional[str], location: Optional[str]):
    base_query = "SELECT * FROM users"
    params = []
    filters = []

    if occupation:
        filters.append("occupation = %s")
        params.append(occupation)
    if location:
        filters.append("location = %s")
        params.append(location)

    if filters:
        base_query += " WHERE " + " AND ".join(filters)
    base_query += " LIMIT %s OFFSET %s"
    params += [limit, skip]

    return execute_query(base_query, tuple(params), fetchall=True)


# -----------------------------------------------------------------------------
# User endpoints
# -----------------------------------------------------------------------------

@app.get("/users/{id}", response_model=UserRead)
def get_user(id: UUID, response: Response):
    """Retrieve a user profile by ID with ETag support."""
    row = get_user_by_id(id)
    if not row:
        raise HTTPException(status_code=404, detail="User not found")

    user = UserRead(**row)
    ETag = generate_etag(user)
    response.headers["ETag"] = ETag

    return user

@app.put("/users/{id}", response_model=UserRead)
def update_user(
    id: UUID,
    user_update: UserUpdate,
    if_match: Optional[str] = Header(None, alias="E-Tag")
):
    """Update a user if ETag matches."""
    # fetch user
    existing = get_user_by_id(id)
    if not existing:
        raise HTTPException(status_code=404, detail="User not found")
    
    current_user = UserRead(**existing)
    current_etag = generate_etag(current_user) # current ETag, will be different than if-match if update timestamp changed

    if if_match and if_match != current_etag: # do not update if the resources has been modified since you fetched it
        raise HTTPException(status_code=412, detail="ETag mismatch (resource modified)")
    
    updates = user_update.model_dump(exclude_unset=True)
    if not updates:
        return current_user

    updated = update_user_record(id, updates)
    return UserRead(**updated)


@app.delete("/users/{id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(id: UUID):
    """Delete a user profile."""
    existing = get_user_by_id(id)
    if not existing:
        raise HTTPException(status_code=404, detail="User not found")
    
    delete_user_record(id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@app.get("/users", response_model=List[UserRead])
def list_users(skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=50),
    occupation: Optional[str] = Query(None),
    location: Optional[str] = Query(None),
    ):
    """List users with pagination and optional filters."""
    rows = list_users_db(skip, limit, occupation, location)
    return [UserRead(**row) for row in rows]

# -----------------------------------------------------------------------------
# Database helpers for sessions
# -----------------------------------------------------------------------------

def get_session_by_id(session_id: UUID):
    query = "SELECT * FROM sessions WHERE session_id = %s"
    return execute_query(query, (str(session_id),), fetchone=True)

def insert_session(user_id: UUID, expires_at: datetime):
    session_id = str(uuid4())
    query = """
        INSERT INTO sessions (session_id, user_id, expires_at)
        VALUES (%s, %s, %s)
    """
    execute_query(query, (session_id, str(user_id), expires_at), commit=True)
    return get_session_by_id(session_id)

def delete_session(session_id: UUID):
    query = "DELETE FROM sessions WHERE session_id = %s"
    execute_query(query, (str(session_id),), commit=True)

# -----------------------------------------------------------------------------
# Database helpers for preferences
# -----------------------------------------------------------------------------

def get_preferences_by_user_id(user_id: UUID):
    query = "SELECT * FROM preferences WHERE user_id = %s"
    row = execute_query(query, (str(user_id),), fetchone=True)
    if not row:
        return None
    
    # Convert JSON string columns back to Python lists
    if row.get("refreshments_preferred"):
        row["refreshments_preferred"] = json.loads(row["refreshments_preferred"])
    if row.get("environment"):
        row["environment"] = json.loads(row["environment"])

    return PreferencesRead(**row)

def insert_preferences(user_id: UUID, prefs: PreferencesCreate):
    query = """
        INSERT INTO preferences (
            user_id, wifi_required, outlets_required,
            seating_preference, refreshments_preferred, environment,
            created_at, updated_at
        )
        VALUES (%s, %s, %s, %s, %s, %s, NOW(), NOW())
    """
    execute_query(
        query,
        (
            str(user_id),
            prefs.wifi_required,
            prefs.outlets_required,
            prefs.seating_preference,
            json.dumps(prefs.refreshments_preferred) if prefs.refreshments_preferred else None,
            json.dumps(prefs.environment) if prefs.environment else None,
        ),
        commit=True,
    )
    return get_preferences_by_user_id(user_id)

def update_preferences_record(user_id: UUID, updates: dict):
    # Convert any list fields to JSON strings
    updates_copy = updates.copy()
    for key in ["environment", "refreshments_preferred"]:
        if key in updates_copy and updates_copy[key] is not None:
            updates_copy[key] = json.dumps(updates_copy[key])

    set_clause = ", ".join(f"{col}=%s" for col in updates_copy)
    params = list(updates_copy.values()) + [str(user_id)]
    query = f"""
        UPDATE preferences
        SET {set_clause}, updated_at=NOW()
        WHERE user_id=%s
    """
    execute_query(query, params, commit=True)
    return get_preferences_by_user_id(user_id)

def delete_preferences_record(user_id: UUID):
    query = "DELETE FROM preferences WHERE user_id = %s"
    execute_query(query, (str(user_id),), commit=True)

# -----------------------------------------------------------------------------
# Preferences endpoints
# -----------------------------------------------------------------------------

@app.get("/users/{id}/preferences", response_model=PreferencesRead)
def get_preferences(id: UUID):
    """Retrieve a user's saved preferences."""
    user = get_user_by_id(id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    prefs = get_preferences_by_user_id(id)
    if not prefs:
        raise HTTPException(status_code=404, detail="Preferences not set for this user")

    return prefs

@app.post("/users/{id}/preferences", response_model=PreferencesRead, status_code=201)
def create_preferences(id: UUID, prefs: PreferencesCreate):
    """Create preferences for a user (one-to-one relationship)."""
    user = get_user_by_id(id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if get_preferences_by_user_id(id):
        raise HTTPException(status_code=400, detail="Preferences already exist")

    new_prefs = insert_preferences(id, prefs)
    return new_prefs

@app.put("/users/{id}/preferences", response_model=PreferencesRead)
def update_preferences(id: UUID, prefs_update: PreferencesUpdate):
    """Update existing user preferences."""
    user = get_user_by_id(id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    existing = get_preferences_by_user_id(id)
    if not existing:
        raise HTTPException(status_code=404, detail="Preferences not found")

    updates = prefs_update.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields provided to update")
    
    updated_row = update_preferences_record(id, updates)

    return updated_row

@app.delete("/users/{id}/preferences", status_code=204)
def delete_preferences(id: UUID):
    """Delete or reset user preferences."""
    user = get_user_by_id(id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not get_preferences_by_user_id(id):
        raise HTTPException(status_code=404, detail="Preferences not found")

    delete_preferences_record(id)
    return Response(status_code=204)

# -----------------------------------------------------------------------------
# Session + Google endpoints
# -----------------------------------------------------------------------------

@app.get("/auth/login/google")
async def login_with_google(request: Request):
    redirect_uri = request.url_for("google_auth_callback")
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/callback/google")
async def google_auth_callback(request: Request):
    token = await oauth.google.authorize_access_token(request)

    # this contains id_token with email, name, etc.
    user_info = token.get("userinfo")
    if not user_info:
        raise HTTPException(status_code=400, detail="Invalid Google login")

    google_id = user_info["sub"]
    email = user_info["email"]
    name = user_info.get("name")

    # 1. Look up user in DB by google_id
    query = "SELECT * FROM users WHERE google_id = %s"
    db_user = execute_query(query, (google_id,), fetchone=True)

    # 2. If not exists, create one
    if not db_user:
        new_id = str(uuid4())
        query = """
            INSERT INTO users (id, google_id, email, display_name, created_at, updated_at)
            VALUES (%s, %s, %s, %s, NOW(), NOW())
        """
        execute_query(
            query,
            (new_id, google_id, email, name),
            commit=True
        )
        user_id = new_id
    else:
        user_id = db_user["id"]

    # 3. Create a session (same as before)
    expires = datetime.utcnow().timestamp() + 3600
    expires_at = datetime.utcfromtimestamp(expires)
    session = insert_session(UUID(user_id), expires_at)

    # 4. Return session ID to the frontend
    return {
        "session_id": session["session_id"],
        "expires_at": session["expires_at"],
        "user_id": session["user_id"]
    }



"""@app.post("/auth/register", response_model=UserRead, status_code=201)
def register_user(user: UserCreate):
    # Check if username is already taken
    existing = get_user_by_username(user.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
        
    # Create user and hash password
    hashed_pw = hash_password(user.password)
    new_user_row = insert_user(user, hashed_pw)

    return UserRead(
    id=UUID(new_user_row["id"]),
    username=new_user_row["username"],
    age=new_user_row["age"],
    occupation=new_user_row["occupation"],
    location=new_user_row["location"],
    created_at=new_user_row["created_at"],
    updated_at=new_user_row["updated_at"],
    )

@app.post("/auth/login")
def login_user(credentials: LoginRequest):
    username = credentials.username
    password = credentials.password

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")
        
    # Find user by username
    user_row = get_user_by_username(username)
    if not user_row:
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    # Verify password
    if not verify_password(password, user_row["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    # Create new session
    expires = datetime.utcnow().timestamp() + 3600  # 1 hour
    expires_at = datetime.utcfromtimestamp(expires)

    new_session = insert_session(UUID(user_row["id"]), expires_at)

    return {
        "message": "Login successful",
        "session_id": new_session["session_id"],
        "expires_at": new_session["expires_at"],
        "user_id": new_session["user_id"],
    } """

@app.post("/auth/logout", status_code=204)
def logout_user(
    auth: str = Header(
        ...,
        description="Token containing your session ID",
        example="Bearer 123e4567-e89b-12d3-a456-426614174000"
    )
):
    """Logout user by deleting session."""
    if not auth:
        raise HTTPException(status_code=400, detail="Missing Authorization header")

    # Expect the header to be something like "Bearer <session_id>"
    try:
        session_id = UUID(auth.split(" ")[1])
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Authorization format")

    session = get_session_by_id(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    # Delete session
    delete_session(session_id)
    return Response(status_code=204)

@app.get("/auth/me", response_model=UserRead)
def get_current_user(
        auth: str = Header(
        ...,
        description="Token containing your session ID",
        example="Bearer 123e4567-e89b-12d3-a456-426614174000"
    )):
    """Return the current authenticated user's profile."""
    if not auth:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    
    try:
        session_id = UUID(auth.split(" ")[1])
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Authorization format")

    session = get_session_by_id(session_id)

    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    # Check expiry
    if session["expires_at"] < datetime.utcnow():
        delete_session(session_id)
        raise HTTPException(status_code=401, detail="Session expired")

    # Return user info
    user_row = get_user_by_id(UUID(session["user_id"]))
    if not user_row:
        raise HTTPException(status_code=404, detail="User not found")

    return UserRead(**user_row)


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
