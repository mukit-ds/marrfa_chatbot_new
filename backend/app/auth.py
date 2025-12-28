# backend/app/auth.py
import hashlib
from datetime import datetime
from typing import Dict, Any
from fastapi import HTTPException


def hash_password(password: str):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


# app/auth.py
import os
import time
from datetime import datetime

# Optional in-memory fallback (per-process) for local dev
_FALLBACK_USAGE = {}  # session_id -> {"count": int, "reset_at": float}

DAILY_LIMIT = int(os.getenv("DAILY_FREE_LIMIT", "25"))  # change as you like
RESET_SECONDS = 24 * 60 * 60

def check_and_update_limit(session_id: str, usage_col) -> bool:
    """
    Returns True if user/session is allowed to chat, else False.
    If MongoDB fails, falls back to in-memory counter (or allow-all if you prefer).
    """
    now = time.time()

    # If user disabled rate-limit in local dev
    if os.getenv("DISABLE_RATE_LIMIT", "0") == "1":
        return True

    try:
        user = usage_col.find_one({"session_id": session_id})

        # first time user
        if not user:
            usage_col.insert_one({
                "session_id": session_id,
                "count": 1,
                "reset_at": datetime.utcnow(),
            })
            return True

        # simple daily-like limit (you may already have your own logic)
        count = int(user.get("count", 0))
        if count >= DAILY_LIMIT:
            return False

        usage_col.update_one(
            {"session_id": session_id},
            {"$set": {"count": count + 1}}
        )
        return True

    except Exception as e:
        # ---- Mongo down / TLS issue / network issue ----
        # Fallback logic (in-memory)
        rec = _FALLBACK_USAGE.get(session_id)
        if not rec or rec["reset_at"] < now:
            _FALLBACK_USAGE[session_id] = {"count": 1, "reset_at": now + RESET_SECONDS}
            return True

        if rec["count"] >= DAILY_LIMIT:
            return False

        rec["count"] += 1
        return True


def handle_signup(username: str, email: str, phone: str, password: str, users_col) -> Dict[str, Any]:
    """Handle user signup."""
    if users_col.find_one({"$or": [{"username": username}, {"email": email}]}):
        raise HTTPException(status_code=400, detail="User already exists")
    users_col.insert_one({
        "username": username, "email": email, "phone": phone,
        "password": hash_password(password), "created_at": datetime.now()
    })
    return {"message": "Success"}


def handle_login(identifier: str, password: str, users_col) -> Dict[str, Any]:
    """Handle user login."""
    hashed = hash_password(password)
    user = users_col.find_one({"$or": [{"username": identifier}, {"email": identifier}], "password": hashed})
    if user:
        return {"success": True, "user": {"username": user["username"], "email": user["email"]}}
    raise HTTPException(status_code=401, detail="Invalid credentials")