from __future__ import annotations

import hashlib
import os
import socket
from datetime import datetime, timedelta
import json
import jwt

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
JWT_SECRET = my_secrets.JWT_SECRET  
REDIRECT_URI = "https://composite-gateway-642518168067.us-east1.run.app/auth/callback/google"
JWT_ALGO = "HS256"


def get_connection():
    return mysql.connector.connect(
        host="10.38.80.5",
        user="root",
        password="root-password",
        database="user_management",
        port=3306,
    )
    

def execute_query(query, params=None, fetchone=False, fetchall=False, commit=False):
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
    https_only=True,        
    same_site="lax"
)

oauth = OAuth()

oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

def generate_etag(user: UserRead) -> str:
    return hashlib.sha256(user.updated_at.isoformat().encode()).hexdigest()

def verify_jwt(auth_header: str):
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    else:
        token = auth_header

    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        return decoded
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_user_by_id(user_id: UUID):
    query = "SELECT * FROM users WHERE id = %s"
    return execute_query(query, (str(user_id),), fetchone=True)

def update_user_record(user_id: UUID, fields: dict):
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


@app.get("/users/{id}", response_model=UserRead)
def get_user(id: UUID, response: Response, auth: str = Header(None)):
    verify_jwt(auth)

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
    if_match: Optional[str] = Header(None, alias="E-Tag"),
    auth: str = Header(None)
):
    verify_jwt(auth)

    existing = get_user_by_id(id)
    if not existing:
        raise HTTPException(status_code=404, detail="User not found")
    
    current_user = UserRead(**existing)
    current_etag = generate_etag(current_user)

    if if_match and if_match != current_etag:
        raise HTTPException(status_code=412, detail="ETag mismatch (resource modified)")
    
    updates = user_update.model_dump(exclude_unset=True)
    if not updates:
        return current_user

    updated = update_user_record(id, updates)
    return UserRead(**updated)


@app.delete("/users/{id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(id: UUID, auth: str = Header(None)):
    verify_jwt(auth)

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
    auth: str = Header(None)
    ):
    verify_jwt(auth)

    rows = list_users_db(skip, limit, occupation, location)
    return [UserRead(**row) for row in rows]


def get_preferences_by_user_id(user_id: UUID):
    query = "SELECT * FROM preferences WHERE user_id = %s"
    row = execute_query(query, (str(user_id),), fetchone=True)
    if not row:
        return None
    
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


@app.get("/users/{id}/preferences", response_model=PreferencesRead)
def get_preferences(id: UUID, auth: str = Header(None)):
    verify_jwt(auth)
    
    user = get_user_by_id(id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    prefs = get_preferences_by_user_id(id)
    if not prefs:
        raise HTTPException(status_code=404, detail="Preferences not set for this user")

    return prefs

@app.post("/users/{id}/preferences", response_model=PreferencesRead, status_code=201)
def create_preferences(id: UUID, prefs: PreferencesCreate, auth: str = Header(None)):
    verify_jwt(auth)

    user = get_user_by_id(id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if get_preferences_by_user_id(id):
        raise HTTPException(status_code=400, detail="Preferences already exist")

    new_prefs = insert_preferences(id, prefs)
    return new_prefs

@app.put("/users/{id}/preferences", response_model=PreferencesRead)
def update_preferences(id: UUID, prefs_update: PreferencesUpdate, auth: str = Header(None)):
    verify_jwt(auth)

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
def delete_preferences(id: UUID, auth: str = Header(None)):
    verify_jwt(auth)

    user = get_user_by_id(id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not get_preferences_by_user_id(id):
        raise HTTPException(status_code=404, detail="Preferences not found")

    delete_preferences_record(id)
    return Response(status_code=204)


@app.get("/auth/login/google")
async def login_with_google(request: Request):
    return await oauth.google.authorize_redirect(request, REDIRECT_URI)

@app.get("/auth/callback/google")
async def google_auth_callback(request: Request):
    token = await oauth.google.authorize_access_token(request)

    user_info = token.get("userinfo")
    if not user_info:
        raise HTTPException(status_code=400, detail="Invalid Google login")

    google_id = user_info["sub"]
    email = user_info["email"]
    name = user_info.get("name")

    query = "SELECT * FROM users WHERE google_id = %s"
    db_user = execute_query(query, (google_id,), fetchone=True)

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

    payload = {
        "sub": user_id,
        "email": email,
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    jwt_token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

    return {"jwt": jwt_token}


@app.get("/auth/me", response_model=UserRead)
def get_current_user(auth: str = Header(...)):
    decoded = verify_jwt(auth)
    user_id = decoded["sub"]

    user = get_user_by_id(UUID(user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return UserRead(**user)


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
    return make_health(echo=echo, path_echo=None)

@app.get("/health/{path_echo}", response_model=Health)
def get_health_with_path(
    path_echo: str = Path(..., description="Required echo in the URL path"),
    echo: str | None = Query(None, description="Optional echo string"),
):
    return make_health(echo=echo, path_echo=path_echo)


@app.get("/")
def root():
    return {"message": "Welcome to the User-Management API. See /docs for OpenAPI UI."}

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
