from __future__ import annotations

import os
import socket
import json
import bcrypt
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from uuid import UUID, uuid4

import mysql.connector
from fastapi import FastAPI, HTTPException, Query, Path, Header

from models import preferences
from models import user
from models import session
from models import health
from models.user import UserCreate, UserRead, UserUpdate
from models.preferences import PreferencesRead, PreferencesCreate, PreferencesUpdate
from models.session import SessionRead
from models.health import Health

# -----------------------------------------------------------------------------
# Database Connection
# -----------------------------------------------------------------------------
def get_connection():
    if os.environ.get("ENV") == "local":
        return mysql.connector.connect(
            host="127.0.0.1",
            user="root",
            password="",
            database="mydb",
            port=3306
        )
    else:
        return mysql.connector.connect(
            host="34.138.240.11",
            user="avi",
            password="columbia25",
            database="nycstudyspots",
            port=3306
        )


def execute_query(queries: list, only_one=False):
    conn, cursor = None, None
    result = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        for i, (query, params) in enumerate(queries):
            cursor.execute(query, params)
            if i == len(queries) - 1:
                if query.strip().upper().startswith("SELECT"):
                    result = cursor.fetchone() if only_one else cursor.fetchall()
                else:
                    result = cursor.rowcount
        conn.commit()
    except mysql.connector.Error as err:
        if conn:
            conn.rollback()
        raise Exception(f"DB Error: {err}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
    return result


# -----------------------------------------------------------------------------
# FastAPI Setup
# -----------------------------------------------------------------------------
port = int(os.environ.get("PORT", 8010))
app = FastAPI(title="User Management Service", description="Handles user accounts, sessions, and preferences", version="0.1.0")

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # or ["http://localhost:5173"] for stricter
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))

def generate_token() -> str:
    return str(uuid4())

# -----------------------------------------------------------------------------
# Authentication
# -----------------------------------------------------------------------------
@app.post("/auth/register", response_model=UserRead, status_code=201)
def register_user(user: UserCreate):
    try:
        user_id = str(uuid4())
        hashed_pw = hash_password(user.password)
        now = datetime.utcnow()

        queries = [
            ("SELECT id FROM users WHERE username = %s;", (user.username,)),
            (
                """
                INSERT INTO users (id, username, hashed_password, age, occupation, location, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                """,
                (user_id, user.username, hashed_pw, user.age, user.occupation, user.location, now, now),
            ),
            ("SELECT id, username, age, occupation, location, created_at, updated_at FROM users WHERE id = %s;", (user_id,)),
        ]

        existing = execute_query([queries[0]], only_one=True)
        if existing:
            raise HTTPException(status_code=400, detail="Username already registered.")

        new_user = execute_query(queries[1:], only_one=True)
        return UserRead(**new_user)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# NOTE: remove response_model here so we can return session_token verbatim
@app.post("/auth/login")
def login_user(credentials: Dict[str, str]):
    try:
        username = credentials.get("username")
        password = credentials.get("password")
        if not username or not password:
            raise HTTPException(status_code=400, detail="Missing username or password.")

        queries = [("SELECT * FROM users WHERE username = %s;", (username,))]
        user_row = execute_query(queries, only_one=True)
        if not user_row or not verify_password(password, user_row["hashed_password"]):
            raise HTTPException(status_code=401, detail="Invalid credentials.")

        session_id = str(uuid4())
        token = generate_token()
        created_at = datetime.utcnow()
        expires_at = created_at + timedelta(hours=1)

        insert_session = [
            (
                """
                INSERT INTO sessions (id, user_id, session_token, created_at, expires_at)
                VALUES (%s, %s, %s, %s, %s);
                """,
                (session_id, user_row["id"], token, created_at, expires_at),
            )
        ]
        execute_query(insert_session)

        # Return a raw dict so the token is preserved in the response
        return {
            "session_id": session_id,
            "user_id": user_row["id"],
            "session_token": token,
            "created_at": created_at,
            "expires_at": expires_at,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/auth/logout")
def logout_user(payload: Dict[str, str]):
    try:
        token = payload.get("session_token")
        if not token:
            raise HTTPException(status_code=400, detail="Missing session_token.")
        queries = [("DELETE FROM sessions WHERE session_token = %s;", (token,))]
        execute_query(queries)
        return {"status": "logged_out"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/auth/me", response_model=UserRead)
def get_current_user(authorization: Optional[str] = Header(None)):
    try:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing Authorization header.")
        token = authorization.split(" ")[1]
        queries = [
            (
                """
                SELECT u.id, u.username, u.age, u.occupation, u.location, u.created_at, u.updated_at
                FROM users u
                JOIN sessions s ON u.id = s.user_id
                WHERE s.session_token = %s AND s.expires_at > UTC_TIMESTAMP();
                """,
                (token,),
            )
        ]
        row = execute_query(queries, only_one=True)
        if not row:
            raise HTTPException(status_code=401, detail="Invalid or expired session token.")
        return UserRead(**row)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# -----------------------------------------------------------------------------
# Users
# -----------------------------------------------------------------------------
@app.get("/users", response_model=List[UserRead])
def list_users():
    try:
        queries = [("SELECT id, username, age, occupation, location, created_at, updated_at FROM users;", ())]
        users = execute_query(queries) or []
        return [UserRead(**u) for u in users]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/users/{id}", response_model=UserRead)
def get_user(id: UUID):
    try:
        queries = [("SELECT id, username, age, occupation, location, created_at, updated_at FROM users WHERE id = %s;", (str(id),))]
        row = execute_query(queries, only_one=True)
        if not row:
            raise HTTPException(status_code=404, detail="User not found.")
        return UserRead(**row)
    except HTTPException:
        # preserve explicit 4xx responses
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/users/{id}", response_model=UserRead)
def update_user(id: UUID, update: UserUpdate):
    try:
        data = update.model_dump(exclude_unset=True)
        if not data:
            raise HTTPException(status_code=400, detail="No fields to update.")

        set_clause = ", ".join(f"{k} = %s" for k in data.keys())
        params = list(data.values()) + [str(id)]
        queries = [
            (f"UPDATE users SET {set_clause}, updated_at = UTC_TIMESTAMP() WHERE id = %s;", tuple(params)),
            ("SELECT id, username, age, occupation, location, created_at, updated_at FROM users WHERE id = %s;", (str(id),)),
        ]
        updated = execute_query(queries, only_one=True)
        if not updated:
            raise HTTPException(status_code=404, detail="User not found.")
        return UserRead(**updated)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/users/{id}")
def delete_user(id: UUID):
    try:
        queries = [
            ("DELETE FROM preferences WHERE user_id = %s;", (str(id),)),
            ("DELETE FROM sessions WHERE user_id = %s;", (str(id),)),
            ("DELETE FROM users WHERE id = %s;", (str(id),)),
        ]
        execute_query(queries)
        return {"status": "deleted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# -----------------------------------------------------------------------------
# Preferences
# -----------------------------------------------------------------------------
@app.get("/users/{id}/preferences", response_model=PreferencesRead)
def get_preferences(id: UUID):
    try:
        queries = [("SELECT * FROM preferences WHERE user_id = %s;", (str(id),))]
        prefs = execute_query(queries, only_one=True)
        if not prefs:
            raise HTTPException(status_code=404, detail="Preferences not found.")
        prefs["preferred_neighborhoods"] = json.loads(prefs.get("preferred_neighborhoods") or "[]")
        return PreferencesRead(**prefs)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/users/{id}/preferences", response_model=PreferencesRead)
def update_preferences(id: UUID, update: PreferencesUpdate):
    try:
        data = update.model_dump(exclude_unset=True)
        data["preferred_neighborhoods"] = json.dumps(data.get("preferred_neighborhoods", []))
        queries = [("SELECT id FROM preferences WHERE user_id = %s;", (str(id),))]
        existing = execute_query(queries, only_one=True)
        now = datetime.utcnow()

        if existing:
            set_clause = ", ".join(f"{k} = %s" for k in data.keys())
            params = list(data.values()) + [now, str(id)]
            q = [(f"UPDATE preferences SET {set_clause}, updated_at = %s WHERE user_id = %s;", tuple(params))]
        else:
            pref_id = str(uuid4())
            cols = ", ".join(data.keys())
            placeholders = ", ".join(["%s"] * len(data))
            q = [(
                f"INSERT INTO preferences (id, user_id, {cols}, created_at, updated_at) VALUES (%s, %s, {placeholders}, %s, %s);",
                (pref_id, str(id), *data.values(), now, now)
            )]
        execute_query(q)
        result = execute_query([("SELECT * FROM preferences WHERE user_id = %s;", (str(id),))], only_one=True)
        result["preferred_neighborhoods"] = json.loads(result.get("preferred_neighborhoods") or "[]")
        return PreferencesRead(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/users/{id}/preferences")
def delete_preferences(id: UUID):
    try:
        queries = [("DELETE FROM preferences WHERE user_id = %s;", (str(id),))]
        execute_query(queries)
        return {"status": "deleted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# -----------------------------------------------------------------------------
# Health Check
# -----------------------------------------------------------------------------
def make_health(echo: Optional[str], path_echo: Optional[str] = None) -> Health:
    return Health(
        status=200,
        status_message="OK",
        timestamp=datetime.utcnow().isoformat() + "Z",
        ip_address=socket.gethostbyname(socket.gethostname()),
        echo=echo,
        path_echo=path_echo,
    )


@app.get("/health", response_model=Health)
def get_health_no_path(echo: str | None = Query(None)):
    return make_health(echo=echo)


@app.get("/health/{path_echo}", response_model=Health)
def get_health_with_path(path_echo: str, echo: str | None = Query(None)):
    return make_health(echo=echo, path_echo=path_echo)


# -----------------------------------------------------------------------------
# Root
# -----------------------------------------------------------------------------
@app.get("/")
def root():
    return {"message": "Welcome to the User Management API. See /docs for OpenAPI UI."}

# Ensure Pydantic models resolve any forward refs at import time
preferences.PreferencesRead.model_rebuild()
preferences.PreferencesCreate.model_rebuild()
preferences.PreferencesUpdate.model_rebuild()
user.UserRead.model_rebuild()
user.UserCreate.model_rebuild()
user.UserUpdate.model_rebuild()
session.SessionRead.model_rebuild()
health.Health.model_rebuild()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=port)
