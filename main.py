from __future__ import annotations

import hashlib
import os
import socket
from datetime import datetime

from typing import Dict, List
from uuid import UUID, uuid4

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

def get_user_by_username(username: str):
    query = "SELECT * FROM users WHERE username = %s"
    return execute_query(query, (username,), fetchone=True)

def insert_user(user: UserCreate, hashed_pw: bytes):
    user_id = str(uuid4())  # or just str(uuid4())
    query = """
        INSERT INTO users (id, username, password_hash, age, occupation, location, created_at, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, NOW(), NOW())
    """
    print(query)
    execute_query(
        query,
        (user_id, user.username, hashed_pw.decode(), user.age, user.occupation, user.location),
        commit=True,
    )
    return get_user_by_id(user_id)

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
    print(f"ETag for user {id}: {ETag}")

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
    """Create a new user with hashed password."""
    try:
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

    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error during registration.") from e


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
