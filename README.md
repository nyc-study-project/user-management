# User Management
This microservice is responsible for managing users, their preferences, and authentication sessions for the NYC Study Projects system. 
It provides APIs for registration, login/logout, managing user profiles, and customizing study spot preferences.

As of Sprint 1, it currently has 3 models and their respective endpoints, all of which are returning **Not Implemented** for the time being.

## Current Models

**user.py** - Represents a user account and profile information
- Stores login credentials (username + password hash, never the raw password)
- Contains profile details such as age, occupation, and location
- Includes metadata like created_at and updated_at timestamps
- Acts as the primary resource — other models (preferences, sessions) reference a user by their user_id
  
**preferences.py** - Represents a user’s study/work spot preferences
- Each user has one preference instance (1-to-1 relationship)
- Defines what a user cares about in a study/work environment, (like Wi-Fi, noise level)
- Provides flexibility with an other_preferences field for custom notes or less common requirements (but we can change this later if needed)
- Fields will likley change in the future since they need to line up with the Spot Management amenity model 

**session.py** - Represents an active login session for a user
- Created automatically after a successful login
- Stores a session token (temporary credential that proves the user is logged in) in database
- Includes an expires_at timestamp so sessions automatically expire
- Tied to a specific user_id, so multiple sessions (e.g., different devices) can exist for the same user
- The idea was that a database table will hold all active session IDs and delete them upon logout or becoming expired. We can change this session method later if needed.

## Current API endpoints

**Users**

- GET /users/{id} → Retrieve a user profile
- PUT /users/{id} → Update user profile
- DELETE /users/{id} → Delete a user and associated preferences/sessions
- GET /users → List all users (should be admin only)

**Preferences**

- GET /users/{id}/preferences → Get preferences for a user
- PUT /users/{id}/preferences → Update preferences
- DELETE /users/{id}/preferences → Delete/reset preferences

**Authentication and Sessions**

- POST /auth/register → Create a new user account (password will be stored hashed)
- POST /auth/login → Login with username & password (creates session)
- POST /auth/logout → Logout (invalidates session)
- GET /auth/me → Get the current authenticated user
