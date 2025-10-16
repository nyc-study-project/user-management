import requests
from pprint import pprint

BASE = "http://localhost:8000"


def print_header(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def safe_json(r):
    try:
        return r.json()
    except Exception:
        return {"non_json_response": r.text or "<empty>"}


def run_tests():
    print_header("1. Health Check")
    res = requests.get(f"{BASE}/health")
    pprint(safe_json(res))

    print_header("2. Register User")
    payload = {
        "username": "alice123",
        "password": "TestPass123!",
        "age": 21,
        "occupation": "student",
        "location": "Brooklyn"
    }
    res = requests.post(f"{BASE}/auth/register", json=payload)
    user = safe_json(res)
    pprint(user)
    user_id = user.get("id")

    print_header("3. Login User")
    login_data = {"username": "alice123", "password": "TestPass123!"}
    res = requests.post(f"{BASE}/auth/login", json=login_data)
    session = safe_json(res)
    pprint(session)
    token = session.get("session_token")

    print_header("4. Get Current User (/auth/me)")
    headers = {"Authorization": f"Bearer {token}"}
    res = requests.get(f"{BASE}/auth/me", headers=headers)
    pprint(safe_json(res))

    print_header("5. Update User Profile")
    update = {
        "age": 22,
        "occupation": "professional",
        "location": "Manhattan"
    }
    res = requests.put(f"{BASE}/users/{user_id}", json=update)
    pprint(safe_json(res))

    print_header("6. Set Preferences")
    prefs = {
        "preferred_neighborhoods": ["Manhattan", "Brooklyn"],
        "quiet_only": True,
        "wifi_required": True,
        "outlets_required": True,
        "seating_preference": "tables"
    }
    res = requests.put(f"{BASE}/users/{user_id}/preferences", json=prefs)
    pprint(safe_json(res))

    print_header("7. Get Preferences")
    res = requests.get(f"{BASE}/users/{user_id}/preferences")
    pprint(safe_json(res))

    print_header("8. Logout User")
    res = requests.post(f"{BASE}/auth/logout", json={"session_token": token})
    pprint(safe_json(res))

    print_header("9. Delete User")
    res = requests.delete(f"{BASE}/users/{user_id}")
    print("Status:", res.status_code)

    print_header("10. Verify Deletion")
    res = requests.get(f"{BASE}/users/{user_id}")
    print("Expected 404 ->", res.status_code)


if __name__ == "__main__":
    run_tests()
