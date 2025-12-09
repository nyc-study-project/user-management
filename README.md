Notes for sprint 3 deployment: Database schema has changed (see schema section) + a redirect uri to callback endpoint must be added in gcp (local example available in gcp). Additionally, the get_connection of this code should be replaced with what is currently being used in the VM. This version of get_connection works locally, but it was changed for production last sprint to use a direct connection to our databse instead of variables.

# User Management
This microservice manages users, authentication sessions, and user study-spot preferences for the NYC Study Projects system.
It provides registration & login, CRUD operations for user profiles, a preferences system backed by MySQL, and secure session management.

All Sprint 1+2 endpoints are now fully implemented and backed by a MySQL database.

## Features Implemented

### Authentication & Sessions

- Login/register system using Google
- Session table stored in MySQL
- Expiring sessions (expires_at)
- /auth/me endpoint reads the session token

### User Management
- read, update, delete users
- Pagination + filters on GET /users
  - Supports skip, limit, occupation, and location
- Optimistic concurrency with ETag
  - GET /users/{id} returns ETag header
  - PUT /users/{id} requires If-Match header
  - Prevents overwriting changes made by another client

### User Preferences
- One-to-one preferences table
- JSON fields supported: refreshments_preferred, environment
- Full CRUD implemented
- Auto-conversion between Python lists and MySQL JSON strings

## Project Structure
- **user.py** — UserRead, UserUpdate
- **preferences.py** — PreferencesCreate, PreferencesRead, PreferencesUpdate
- **session.py** — SessionCreate, SessionRead, LoginRequest
- **health.py** — Health endpoint output model

### Core file
- **main.py** — FastAPI app, DB connections, endpoints

## Database Schema

### Users Table
changes made for sprint 3: dropped password, added google id and email, and dropped username to replace with display name

```
CREATE TABLE IF NOT EXISTS users (
    id CHAR(36) PRIMARY KEY,
    display_name varchar(255) DEFAULT NULL,
    age INT DEFAULT NULL,
    occupation VARCHAR(100) DEFAULT NULL,
    location VARCHAR(100) DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    google_id  varchar(255) UNIQUE,
    email varchar(255) UNIQUE
);
```

### Preferences Table

```
CREATE TABLE IF NOT EXISTS preferences (
    user_id CHAR(36) PRIMARY KEY,                         
    wifi_required BOOLEAN DEFAULT NULL,
    outlets_required BOOLEAN DEFAULT NULL,
    seating_preference VARCHAR(10) DEFAULT NULL,    
    refreshments_preferred JSON DEFAULT NULL,        
    environment JSON DEFAULT NULL,                   
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

### Sessions Table

```
CREATE TABLE IF NOT EXISTS sessions (
    session_id CHAR(36) PRIMARY KEY,                 
    user_id CHAR(36) NOT NULL,                      
    expires_at DATETIME NOT NULL,                    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

## Current API endpoints

**Users**

- GET /users/{id} → Retrieve a user profile, Adds ETag header for concurrency support
- PUT /users/{id} → Applies partial updates, requires matching If-Match header, returns 412 Precondition Failed on mismatch
- DELETE /users/{id} → Deletes user and cascades delete into preferences and sessions
- GET /users → List all users, Pagination: skip, limit, Filters: occupation, location

**Preferences**

- GET /users/{id}/preferences → Get preferences for a user
- PUT /users/{id}/preferences → Update preferences
- DELETE /users/{id}/preferences → Delete/reset preferences
  
- Supports JSON conversion for list-type fields.

**Authentication and Sessions**

- GET /auth/login/google → Login with Google account, redirect to /auth/callback/google
- GET /auth/callback/google → Adds user to User table and creates session in Sessions table
- POST /auth/logout → Deletes session instance, requires header Authorization: Bearer <session_id>
- GET /auth/me → Returns the currently authenticated user, requires header Authorization: Bearer <session_id>

<img width="1421" height="798" alt="Screenshot 2025-10-03 at 3 29 30 PM" src="https://github.com/user-attachments/assets/9a702f91-7fdf-45e6-bf5b-e7fbcad797d1" />
