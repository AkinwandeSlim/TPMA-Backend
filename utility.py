from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import bcrypt
import json
from math import ceil
import traceback
from typing import Dict, List, Union, Optional, Tuple
from flask import send_file
from datetime import datetime, timedelta, timezone
import csv
import io
import uuid
from zoneinfo import ZoneInfo
import re
import logging
from mockup import save_users, load_users, generate_unique_id
from functools import wraps

import uuid
from datetime import datetime, time, timezone
import logging
import os
import bleach
from bleach import clean  # For sanitizing HTML
from pydantic import BaseModel, ValidationError
from threading import Lock  # Added import

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import html2text
import requests
import os
from dotenv import load_dotenv


from flask import send_file

load_dotenv()



app = Flask(__name__)
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:3000", "http://localhost:5173"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Authorization", "Content-Type"],
        "supports_credentials": True
    }
})


SECRET_KEY = "TPMA2025"
USERS_FILE = "users.json"
ITEMS_PER_PAGE = 10


# Initialize threading lock
lock = Lock()  # Define global lock

# Set up logging
logging.basicConfig(level=logging.DEBUG)  # Changed to DEBUG for more granularity
logger = logging.getLogger(__name__)



# Initialize html2text
h = html2text.HTML2Text()
h.ignore_links = True
h.ignore_images = True





# Load users
users = load_users()



def verify_token(token: str) -> Optional[dict]:
    logger.debug(f"Attempting to verify token: {token[:10]}... (length: {len(token)})")
    if not token:
        logger.warning("Empty token received")
        return None
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        logger.debug(f"Token decoded: {decoded}")
        return decoded
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected token error: {str(e)}")
        return None

def require_2auth(allowed_roles=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            logger.debug(f"Authenticating request: headers={request.headers}")
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
            logger.debug(f"Token received: {token[:10]}... (length: {len(token)})")
            try:
                decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                logger.debug(f"Token decoded: {decoded}")
                if allowed_roles and decoded.get("role") not in allowed_roles:
                    logger.error(f"Unauthorized: role {decoded.get('role')} not in {allowed_roles}")
                    return jsonify({"error": "Unauthorized: Insufficient role"}), 403
                return f(decoded, *args, **kwargs)
            except jwt.InvalidTokenError as e:
                logger.error(f"Invalid token: {str(e)}")
                return jsonify({"error": "Invalid or expired token"}), 401
            except Exception as e:
                logger.error(f"Unexpected auth error: {str(e)}\n{traceback.format_exc()}")
                return jsonify({"error": "Authentication error", "details": str(e)}), 500
        return decorated_function
    return decorator

def parse_time(time_str: str) -> str:
    if not time_str or not isinstance(time_str, str):
        logger.debug(f"Invalid time input: {time_str}")
        return ""
    try:
        # Handle HH:MM format
        if len(time_str.split(":")) == 2:
            datetime.strptime(time_str, "%H:%M")
            return f"{time_str}:00"
        # Handle HH:MM:SS format
        elif len(time_str.split(":")) == 3:
            datetime.strptime(time_str, "%H:%M:%S")
            return time_str
        # Handle ISO format (e.g., 2025-04-21T09:00:00Z)
        elif "T" in time_str:
            parsed = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
            return parsed.strftime("%H:%M:%S")
        else:
            raise ValueError("Invalid time format")
    except ValueError as e:
        logger.warning(f"Time parsing error: {str(e)} for input: {time_str}")
        raise ValueError("Time must be in HH:MM, HH:MM:SS, or ISO format")

def require_auth(allowed_roles: Optional[Union[str, list]] = None) -> Tuple[Optional[dict], Optional[dict]]:
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    logger.debug(f"Full token received: {token}")
    decoded = verify_token(token)
    if not decoded:
        return None, {"error": "Invalid or expired token", "status": 401}
    if allowed_roles:
        roles = [allowed_roles] if isinstance(allowed_roles, str) else allowed_roles
        if decoded.get("role") not in roles:
            return None, {"error": "Unauthorized: Insufficient role", "status": 403}
    return decoded, None





def require_3auth(allowed_roles: Optional[Union[str, List[str]]] = None) -> Tuple[Optional[Dict], Optional[Dict]]:
    """
    Authenticate a request by verifying the JWT token and checking role permissions.
    
    Args:
        allowed_roles: A single role (str), list of roles (List[str]), or None (no role restriction).
    
    Returns:
        Tuple containing:
        - Decoded token (dict) or None if authentication fails.
        - Error response (dict) or None if authentication succeeds.
    """
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    logger.debug(f"Full token received: {token[:10]}... (truncated)")

    decoded = verify_token(token)
    if not decoded:
        logger.warning("Authentication failed: Invalid or expired token")
        return None, {"error": "Invalid or expired token", "status": 401}

    if allowed_roles is not None:
        # Convert single string to list, or use list directly
        roles = [allowed_roles] if isinstance(allowed_roles, str) else allowed_roles
        logger.debug(f"Checking roles: allowed={roles}, user_role={decoded.get('role')}")

        # Validate that roles is a list of strings
        if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
            logger.error(f"Invalid allowed_roles format: {allowed_roles}")
            return None, {"error": "Internal server error: Invalid role configuration", "status": 500}

        # Check if user's role is in allowed roles
        user_role = decoded.get("role")
        if user_role not in roles:
            logger.warning(f"Unauthorized: User role {user_role} not in allowed roles {roles}")
            return None, {"error": "Unauthorized: Insufficient role", "status": 403}

    logger.debug("Authentication successful")
    return decoded, None
def get_trainee_assignment(trainee_id: str) -> Optional[dict]:
    assignment = next((a for a in users.get("tp_assignments", []) if a["traineeId"] == trainee_id), None)
    if not assignment:
        return None
    
    # Look up the school name
    schools = users.get("schools", [])
    school = next((s for s in schools if s["id"] == assignment["schoolId"]), None)
    school_name = school["name"] if school else "Unknown School"
    
    # Look up the supervisor name
    supervisor_id = assignment.get("supervisorId")
    supervisor_name = "Not Assigned"
    if supervisor_id:
        supervisors = users.get("supervisor", [])
        supervisor = next((s for s in supervisors if s["id"] == supervisor_id), None)
        if supervisor:
            supervisor_name = f"{supervisor['name']} {supervisor['surname']}"
           
    
    
    return {
        "supervisorId": assignment["supervisorId"],
        "supervisorName":  f"{supervisor['name']} {supervisor['surname']}" if supervisor else "Unknown",
        "supervisorStaffId": supervisor["staffId"] if supervisor else "Unknown",
        "schoolName": school["name"] if school else "Unknown",
        "placeOfTP": school["name"] if school else "Unknown",
        "traineeId": assignment["traineeId"],
        "schoolId": assignment["schoolId"], 
        "startDate": assignment.get("startDate", assignment.get("start_date", "")),
        "endDate": assignment.get("endDate", assignment.get("end_date", "")),
    }
    

def is_valid_date(date_str):
    """Validate YYYY-MM-DD format."""
    if not date_str:
        return True  # Allow empty dates
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
        return True
    except ValueError:
        return False
    
def get_user_id(identifier, users_data):
    for role in ['admin', 'supervisor', 'teacherTrainee']:
        user = next((u for u in users_data.get(role, []) if u.get('regNo', u.get('staffId', u.get('username', ''))) == identifier), None)
        if user:
            return user['id']
    return None



# Authentication decorator
def _require_auth(allowed_roles: Optional[list] = None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                auth_header = request.headers.get("Authorization")
                if not auth_header or not auth_header.startswith("Bearer "):
                    logger.error("Missing or invalid Authorization header")
                    return {"error": "Missing or invalid Authorization header", "status": 401}, 401
                token = auth_header.split("Bearer ")[1]
                decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                if allowed_roles and decoded["role"] not in allowed_roles:
                    logger.error(f"Unauthorized role: {decoded['role']}")
                    return {"error": f"Unauthorized: Role {decoded['role']} not allowed", "status": 403}, 403
                return f(decoded=decoded, *args, **kwargs)
            except jwt.InvalidTokenError as e:
                logger.error(f"Token error: {str(e)}")
                return {"error": "Invalid or expired token", "status": 401}, 401
            except Exception as e:
                logger.error(f"Auth error: {str(e)}", exc_info=True)
                return {"error": f"Authentication error: {str(e)}", "status": 500}, 500
        return decorated_function
    return decorator

def parse_time(time_str: str) -> Optional[str]:
    """Parse time string to HH:MM:SS format."""
    try:
        # Try HH:MM format first
        dt = datetime.strptime(time_str, "%H:%M")
        return dt.strftime("%H:%M:00")
    except ValueError:
        try:
            # Try HH:MM:SS format
            dt = datetime.strptime(time_str, "%H:%M:%S")
            return dt.strftime("%H:%M:00")
        except ValueError:
            try:
                # Try ISO format
                dt = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
                return dt.strftime("%H:%M:00")
            except ValueError:
                return None

def sanitize_html(text: str) -> str:
    """Sanitize HTML content to prevent XSS."""
    allowed_tags = ["p", "br", "strong", "em", "ul", "li", "ol"]
    return bleach.clean(text, tags=allowed_tags, strip=True)
     
def decode_jwt(token: str) -> dict:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if "identifier" not in payload or "role" not in payload:
            raise jwt.InvalidTokenError("Missing required claims in token")
        return payload
    except jwt.ExpiredSignatureError:
        logger.error("JWT token has expired")
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid JWT token: {str(e)}")
        raise ValueError("Invalid token")
    except Exception as e:
        logger.error(f"Error decoding JWT token: {str(e)}")
        raise ValueError(f"Token decoding error: {str(e)}")

