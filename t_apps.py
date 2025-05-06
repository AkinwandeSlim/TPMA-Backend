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
from dateutil.parser import parse
import csv
import io
import uuid
from zoneinfo import ZoneInfo
import re
import logging
from mockup import save_users, load_users, generate_unique_id
from utility import *
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

# # Set up allowed websites from an environment variable
# ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")


# Configure CORS
ALLOWED_ORIGINS = [
    "http://localhost:3000",  # Local development
    "https://tpma-frontend.vercel.app"  # Production frontend
]




app = Flask(__name__)
CORS(app, resources={
    r"/api/*": {
        "origins": ALLOWED_ORIGINS,
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




# Assume users is loaded via load_users() at app startup
users = load_users()





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



# Error Handlers
@app.errorhandler(404)
def handle_not_found(e):
    response = jsonify({"error": "Not Found", "message": str(e)})
    response.headers.add("Access-Control-Allow-Origin", "http://localhost:3000")
    response.headers.add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
    response.headers.add("Access-Control-Allow-Headers", "Authorization, Content-Type")
    return response, 404

@app.errorhandler(Exception)
def handle_exception(e: Exception) -> Tuple[dict, int]:
    logger.error(f"Unhandled exception: {str(e)}\n{traceback.format_exc()}")
    response = jsonify({"error": "Internal Server Error", "message": str(e)})
    response.status_code = 500
    response.headers.add("Access-Control-Allow-Origin", "http://localhost:3000")
    response.headers.add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
    response.headers.add("Access-Control-Allow-Headers", "Authorization, Content-Type")
    return response, 500

@app.route('/api/<path:path>', methods=['OPTIONS'])
def options_handler(path):
    logger.debug(f"Handling OPTIONS request for /api/{path}, headers: {request.headers}")
    response = jsonify({"message": "CORS preflight"})
    response.headers.add("Access-Control-Allow-Origin", "http://localhost:3000")
    response.headers.add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
    response.headers.add("Access-Control-Allow-Headers", "Authorization, Content-Type")
    response.headers.add("Access-Control-Allow-Credentials", "true")
    logger.debug(f"OPTIONS response headers: {response.headers}")
    return response, 200


@app.route('/api/notifications', methods=['GET', 'POST', 'OPTIONS'])
def manage_notifications():
    if request.method == 'OPTIONS':
        return jsonify({"status": "ok"}), 200
    
    decoded, error = require_auth()
    if error:
        logger.debug(f"Auth failed: {error['error']}")
        return jsonify({"error": error["error"]}), error["status"]
    
    users_data = load_users()
    # Map decoded["identifier"] to user id
    user = None
    for role in ['admin', 'supervisor', 'teacherTrainee']:
        user = next((u for u in users_data.get(role, []) if u.get('regNo', u.get('staffId', u.get('username', ''))) == decoded['identifier']), None)
        if user:
            break
    if not user:
        logger.error(f"User not found for identifier: {decoded['identifier']}")
        return jsonify({"error": "User not found"}), 404
    user_id = user['id']
    
    notifications = users_data.get('notifications', [])

    if request.method == 'GET':
        try:
            notification_type = request.args.get('type', '').upper()
            priority = request.args.get('priority', '').upper()
            read_status = request.args.get('read_status', '').lower()
            search = request.args.get('search', '').lower()
            page = int(request.args.get('page', 1))
            per_page = ITEMS_PER_PAGE
            
            logger.info(f"GET /api/notifications: user_id={user_id}, notifications_count={len(notifications)}")
            user_notifications = [
                n for n in notifications
                if n['user_id'] == user_id or n['initiator_id'] == user_id
            ]
            
            enriched_notifications = []
            events = {str(e['id']): e for e in users_data.get('events', [])}
            for n in user_notifications:
                n_copy = n.copy()
                if not n_copy.get('created_at'):
                    logger.warning(f"Missing created_at for notification {n_copy.get('id')}")
                    n_copy['created_at'] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
                else:
                    try:
                        timestamp = n_copy['created_at']
                        if timestamp.endswith('+00:00Z'):
                            timestamp = timestamp[:-1]
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        n_copy['created_at'] = dt.replace(microsecond=0).isoformat().replace('+00:00', 'Z')
                    except ValueError:
                        logger.warning(f"Invalid created_at for notification {n_copy.get('id')}: {n_copy['created_at']}")
                        n_copy['created_at'] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
                if n_copy.get('event_id') and n_copy['event_id'] in events:
                    n_copy['event_startTime'] = events[n_copy['event_id']]['startTime']
                enriched_notifications.append(n_copy)
            
            if notification_type in ['EVALUATION', 'ASSIGNMENT', 'EVENT', 'GENERAL', 'LESSON_PLAN']:
                enriched_notifications = [n for n in enriched_notifications if n['type'] == notification_type]
            if priority in ['LOW', 'MEDIUM', 'HIGH']:
                enriched_notifications = [n for n in enriched_notifications if n['priority'] == priority]
            if read_status in ['true', 'false']:
                enriched_notifications = [n for n in enriched_notifications if n['read_status'] == (read_status == 'true')]
            if search:
                enriched_notifications = [n for n in enriched_notifications if search in n['message'].lower()]
            
            enriched_notifications.sort(key=lambda x: x.get('created_at', ''), reverse=True)
            total = len(enriched_notifications)
            total_pages = max(1, (total + per_page - 1) // per_page)
            start = (page - 1) * per_page
            end = start + per_page
            paginated_notifications = enriched_notifications[start:end]
            
            logger.info(f"Fetched {len(paginated_notifications)} notifications for user {user_id}")
            return jsonify({
                'notifications': paginated_notifications,
                'totalCount': total,
                'totalPages': total_pages,
                'currentPage': page
            }), 200
        except Exception as e:
            logger.error(f"Error fetching notifications: {str(e)}")
            return jsonify({"error": "Failed to fetch notifications", "details": str(e)}), 500
    
    if request.method == 'POST':
        try:
            if decoded['role'] not in ['admin', 'supervisor', 'teacherTrainee']:
                logger.debug(f"Unauthorized role {decoded['role']} attempted to create notification")
                return jsonify({"error": "Unauthorized: Only admins, supervisors, or teacher trainees can create notifications"}), 403
            
            data = request.get_json() or {}
            required_fields = ['user_id', 'message', 'type', 'priority']
            if not all(field in data for field in required_fields):
                return jsonify({"error": "Missing required fields: user_id, message, type, priority"}), 400
            
            if data['type'] not in ['EVALUATION', 'ASSIGNMENT', 'EVENT', 'GENERAL', 'LESSON_PLAN']:
                return jsonify({"error": "Invalid type: must be EVALUATION, ASSIGNMENT, EVENT, GENERAL, or LESSON_PLAN"}), 400
            if data['priority'] not in ['LOW', 'MEDIUM', 'HIGH']:
                return jsonify({"error": "Invalid priority: must be LOW, MEDIUM, or HIGH"}), 400
            
            target_user = None
            for role in ['admin', 'supervisor', 'teacherTrainee']:
                target_user = next((u for u in users_data.get(role, []) if u['id'] == data['user_id']), None)
                if target_user:
                    break
            if not target_user:
                return jsonify({"error": "Target user not found"}), 404
            
            new_notification = {
                'id': f"notif-{len(notifications) + 1}",
                'user_id': data['user_id'],
                'initiator_id': user_id,
                'event_id': data.get('event_id', None),
                'type': data['type'],
                'priority': data['priority'],
                'message': data['message'],
                'created_at': datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                'read_status': False
            }
            
            notifications.append(new_notification)
            users_data['notifications'] = notifications
            save_users(users_data)
            
            logger.info(f"Created notification {new_notification['id']} for user {data['user_id']} by {user_id}")
            return jsonify({"message": "Notification created", "notification": new_notification}), 201
        except Exception as e:
            logger.error(f"Error creating notification: {str(e)}")
            return jsonify({"error": "Failed to create notification", "details": str(e)}), 500

@app.route("/api/notifications/unread-count", methods=["GET"])
def get_unread_notifications_count():
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"message": "Missing or invalid Authorization header"}), 401
        
        token = auth_header.split("Bearer ")[1]
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        
        users_data = load_users()
        user = None
        for role in ['admin', 'supervisor', 'teacherTrainee']:
            user = next((u for u in users_data.get(role, []) if u.get('regNo', u.get('staffId', u.get('username', ''))) == decoded['identifier']), None)
            if user:
                break
        if not user:
            return jsonify({"error": "User not found"}), 404
        user_id = user['id']
        
        notifications = users_data.get("notifications", [])
        unread_count = sum(
            1 for n in notifications
            if n["user_id"] == user_id and not n.get("read_status", True)
        )
        
        logger.info(f"Fetched unread count {unread_count} for user {user_id}")
        return jsonify({"unread_count": unread_count}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401
    except Exception as e:
        logger.error(f"Error fetching unread count: {str(e)}")
        return jsonify({"message": f"Error: {str(e)}"}), 500




@app.route('/api/notifications/<notification_id>', methods=['PUT', 'DELETE'])
def update_delete_notification(notification_id):
    decoded, error_response = require_auth()
    if error_response:
        logger.debug(f"Auth failed: {error_response.get('error')}")
        return jsonify({"error": error_response["error"]}), error_response["status"]
    
    users_data = load_users()
    user_id = get_user_id(decoded['identifier'], users_data)
    if not user_id:
        logger.error(f"User not found for identifier: {decoded['identifier']}")
        return jsonify({"error": "User not found"}), 404
    
    notifications = users_data.get('notifications', [])
    
    if request.method == 'PUT':
        try:
            data = request.get_json()
            if 'read_status' not in data:
                return jsonify({"error": "Missing read_status in request body"}), 400
            
            logger.debug(f"Attempting to update notification {notification_id} by user {user_id}")
            for n in notifications:
                if n['id'] == notification_id:
                    if not (decoded['role'] == 'admin' or n['user_id'] == user_id):
                        logger.warning(f"Unauthorized: {user_id} cannot update {notification_id} (user_id: {n['user_id']})")
                        return jsonify({"error": "Unauthorized: Only recipient or admin can update read status"}), 403
                    n['read_status'] = data['read_status']
                    # Normalize created_at
                    if n.get('created_at'):
                        try:
                            timestamp = n['created_at']
                            if timestamp.endswith('+00:00Z'):
                                timestamp = timestamp[:-1]
                            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                            n['created_at'] = dt.replace(microsecond=0).isoformat().replace('+00:00', 'Z')
                        except ValueError:
                            logger.warning(f"Invalid created_at for notification {n['id']}: {n['created_at']}")
                            n['created_at'] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
                    with lock:
                        users_data['notifications'] = notifications
                        save_users(users_data)
                    unread_count = len([
                        n for n in notifications
                        if (n['user_id'] == user_id or n['initiator_id'] == user_id) and n['read_status'] is False
                    ])
                    logger.info(f"Updated notification {notification_id} read_status to {data['read_status']} by {user_id}, unread count: {unread_count}")
                    return jsonify({"notification": n, "unread_count": unread_count}), 200
            logger.warning(f"Notification {notification_id} not found for {user_id}")
            return jsonify({"error": "Notification not found"}), 404
        except Exception as e:
            logger.error(f"Error updating notification {notification_id}: {str(e)}")
            return jsonify({"error": "Failed to update notification", "details": str(e)}), 500 
    
    elif request.method == 'DELETE':
        try:
            if decoded['role'] != 'admin':
                logger.warning(f"Unauthorized: {user_id} (role: {decoded['role']}) cannot delete notifications")
                return jsonify({"error": "Unauthorized: Only admins can delete notifications"}), 403
            initial_count = len(notifications)
            notifications = [n for n in notifications if n['id'] != notification_id]
            if len(notifications) == initial_count:
                logger.warning(f"Notification {notification_id} not found for deletion by {user_id}")
                return jsonify({"error": "Notification not found"}), 404
            with lock:
                users_data['notifications'] = notifications
                save_users(users_data)
            unread_count = len([
                n for n in notifications
                if (n['user_id'] == user_id or n['initiator_id'] == user_id) and n['read_status'] is False
            ])
            logger.info(f"Deleted notification {notification_id} by {user_id}, unread count: {unread_count}")
            return jsonify({"message": "Notification deleted", "unread_count": unread_count}), 200
        except Exception as e:
            logger.error(f"Error deleting notification {notification_id}: {str(e)}")
            return jsonify({"error": "Failed to delete notification", "details": str(e)}), 500





@app.route('/api/evaluations', methods=['POST'])
def submit_evaluation():
    decoded, error_response = require_auth()
    if error_response:
        return error_response
    
    users_data =users
    user_id = decoded['identifier']
    notifications = users_data.get('notifications', [])
    
    try:
        data = request.get_json() or {}
        required_fields = ['trainee_id', 'school', 'eval_id', 'startTime', 'endTime']
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields: trainee_id, school, eval_id, startTime, endTime"}), 400
        
        admin_notification = {
            'id': f"notif-{len(notifications) + 1}",
            'user_id': 'admin',
            'initiator_id': user_id,
            'event_id': data['eval_id'],
            'type': 'EVALUATION',
            'priority': 'MEDIUM',
            'message': f"Trainee {data['trainee_id']} submitted evaluation for School {data['school']}.",
            'created_at': datetime.now(timezone.utc).isoformat() + "Z",
            'read_status': False
        }
        notifications.append(admin_notification)
        
        users_data['notifications'] = notifications
        users_data['events'] = users_data.get('events', []) + [{
            'id': data['eval_id'],
            'type': 'EVALUATION',
            'school': data['school'],
            'startTime': data['startTime'],
            'endTime': data['endTime']
        }]
        save_data(users_data)
        
        logger.info(f"Evaluation submitted by {user_id}, notification created: {admin_notification['id']}")
        return jsonify({"message": "Evaluation submitted", "notification": admin_notification}), 201
    except Exception as e:
        logger.error(f"Error submitting evaluation: {str(e)}")
        return jsonify({"error": "Failed to submit evaluation", "details": str(e)}), 500


#Admin Routes
@app.route("/api/admins/<id>", methods=["GET"])
@_require_auth(["admin"])
def get_admin(decoded,id):
    users = load_users()
    admin = next((u for u in users if u["id"] == id and u["role"] == "admin"), None)
    if not admin:
        return jsonify({"error": "Admin not found"}), 404
    return jsonify({"admin": admin})

@app.route("/api/admins/<id>", methods=["PUT"])
@_require_auth(["admin"])
def update_admin(decoded,id):
    users = load_users()
    data = request.get_json()
    user_index = next((i for i, u in enumerate(users) if u["id"] == id and u["role"] == "admin"), None)
    if user_index is None:
        return jsonify({"error": "Admin not found"}), 404
    users[user_index].update(data)
    save_users(users)
    return jsonify({"admin": users[user_index]})



@app.route("/api/admin/reports", methods=["GET"])
def get_reports():
    decoded, error_response = require_auth("admin")
    if error_response:
        return error_response

    # Aggregate attendance data
    trainees = users.get("teacherTrainee", [])
    attendance_summary = {
        "present": 0,
        "absent": 0,
        "late": 0,
        "by_week": {}
    }

    for trainee in trainees:
        attendance_records = trainee.get("attendance", [])
        for record in attendance_records:
            date = datetime.strptime(record["date"], "%Y-%m-%d")
            week_number = (date.day - 1) // 7 + 1
            week_key = f"Week {week_number}"

            if week_key not in attendance_summary["by_week"]:
                attendance_summary["by_week"][week_key] = {"present": 0, "absent": 0, "late": 0}

            status = record["status"]
            attendance_summary[status] += 1
            attendance_summary["by_week"][week_key][status] += 1

    report = {
        "total_admins": len(users["admin"]),
        "total_trainees": len(users["teacherTrainee"]),
        "total_supervisors": len(users["supervisor"]),
        "attendance_summary": attendance_summary
    }
    return jsonify(report)


@app.route("/api/admin/trainee-gender", methods=["GET"])
def get_trainee_gender():
    decoded, error_response = require_auth("admin")
    if error_response:
        return error_response
    
    trainees = users["teacherTrainee"]
    return jsonify({
        "male": len([t for t in trainees if t["sex"] == "MALE"]),
        "female": len([t for t in trainees if t["sex"] == "FEMALE"])
    })


@app.route("/api/admin/reports/preview", methods=["GET"])
def get_report_preview():
    decoded, error_response = require_auth("admin")
    if error_response:
        return error_response
    
    reg_no = request.args.get("regNo")
    start_date = request.args.get("startDate")
    end_date = request.args.get("endDate")
    tp_location = request.args.get("tpLocation")
    
    filtered_data = report_data
    if reg_no:
        filtered_data = [r for r in filtered_data if r["regNo"] == reg_no]
    if start_date and end_date:
        filtered_data = [r for r in filtered_data if start_date <= r["date"] <= end_date]
    if tp_location:
        filtered_data = [r for r in filtered_data if r["tpLocation"] == tp_location]
    
    return jsonify(filtered_data)

@app.route("/api/events", methods=["GET"])
def get_events():
    decoded, error_response = require_auth(allowed_roles=["admin", "supervisor"])
    if error_response:
        return error_response

    date_param = request.args.get("date")
    print(f"Raw date_param: '{date_param}' (type: {type(date_param)})")
    if not date_param:
        print("No date parameter provided")
        return jsonify({"error": "Date parameter is required"}), 400

    try:
        date_param = date_param.strip()
        print(f"Stripped date_param: '{date_param}'")
        # Strict YYYY-MM-DD parsing
        if not (len(date_param) == 10 and date_param[4] == '-' and date_param[7] == '-'):
            raise ValueError("Invalid format")
        input_date = datetime.strptime(date_param, "%Y-%m-%d")
        input_date = input_date.replace(tzinfo=ZoneInfo("UTC"))
        print(f"Parsed date: {input_date}")
    except ValueError as e:
        print(f"Date parsing failed: {str(e)}")
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400

    events = users.get("events", [])
    matching_events = [
        {
            "id": event["id"],
            "title": event["title"],
            "description": event["description"],
            "startTime": event["startTime"],
            "endTime": event["endTime"]
        }
        for event in events
        if datetime.fromisoformat(event["startTime"].replace("Z", "")).date() == input_date.date()
    ]

    print(f"Returning {len(matching_events)} events")
    return jsonify(matching_events), 200

@app.route("/api/events", methods=["POST"])
def create_event():
    decoded, error_response = require_auth(allowed_roles=["admin"])
    if error_response:
        return error_response

    data = request.get_json()
    required_fields = ["title", "description", "startTime", "endTime"]
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    try:
        start_time = datetime.fromisoformat(data["startTime"].replace("Z", "")).replace(tzinfo=ZoneInfo("UTC"))
        end_time = datetime.fromisoformat(data["endTime"].replace("Z", "")).replace(tzinfo=ZoneInfo("UTC"))
        if end_time <= start_time:
            return jsonify({"error": "endTime must be after startTime"}), 400
    except ValueError:
        return jsonify({"error": "Invalid startTime or endTime format. Use YYYY-MM-DDTHH:MM:SS.sssZ"}), 400

    events = users.get("events", [])
    new_event = {
        "id": len(events) + 1,
        "title": data["title"],
        "description": data["description"],
        "startTime": data["startTime"],
        "endTime": data["endTime"]
    }
    events.append(new_event)
    users["events"] = events
    save_users()
    return jsonify({"message": "Event created successfully", "event": new_event}), 201



# Admin/Supervisors
@app.route("/api/supervisors/<supervisor_id>/mark-attendance", methods=["POST"])
def mark_attendance(supervisor_id):
    decoded, error_response = require_auth("supervisor")
    if error_response:
        return error_response

    data = request.get_json() or {}
    trainee_id = data.get("traineeId")
    date = data.get("date")  # Format: "YYYY-MM-DD"
    status = data.get("status")  # "present", "absent", or "late"

    if not all([trainee_id, date, status]) or status not in ["present", "absent", "late"]:
        return jsonify({"error": "Missing or invalid fields"}), 400

    # Verify the trainee belongs to this supervisor
    trainees = users.get("teacherTrainee", [])
    trainee = next((t for t in trainees if t["id"] == trainee_id and t["supervisorId"] == supervisor_id), None)
    if not trainee:
        return jsonify({"error": "Trainee not found or not assigned to this supervisor"}), 404

    # Add or update attendance record
    if "attendance" not in trainee:
        trainee["attendance"] = []
    
    # Check if attendance for this date already exists
    existing_record = next((record for record in trainee["attendance"] if record["date"] == date), None)
    if existing_record:
        existing_record["status"] = status
    else:
        trainee["attendance"].append({"date": date, "status": status})

    # Save updated users data
    save_users(users)
    return jsonify({"message": "Attendance marked successfully"}), 200



@app.route("/api/announcements", methods=["GET", "OPTIONS"])
def get_announcements():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    decoded, error_response = require_auth()
    if error_response:
        logger.debug(f"Auth failed for announcements: {error_response.get_json()['error']}")
        return error_response
    
    try:
        # Use mockup.py's announcements or users.json
        announcements = users.get("announcements", []) or [
            {
                "title": f"Announcement {i}",
                "description": f"Teaching practice update {i}",
                "date": (datetime.now(timezone.utc) - timedelta(days=10 - i)).isoformat() + "Z"
            } for i in range(1, 4)
        ]
        
        # Apply limit if provided
        limit = request.args.get("limit", type=int, default=3)
        announcements = sorted(
            announcements,
            key=lambda x: x.get("date", ""),
            reverse=True
        )[:limit]
        
        logger.debug(f"Returning {len(announcements)} announcements")
        return jsonify({"announcements": announcements}), 200
    except Exception as e:
        logger.error(f"Error in GET /api/announcements: {str(e)}")
        return jsonify({"error": "Failed to fetch announcements", "details": str(e)}), 500



@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    user_type, identifier, password = data.get("userType"), data.get("identifier"), data.get("password")
    print(user_type, identifier, password)
    if not all([user_type, identifier, password]):
        logger.warning("Login failed: Missing required fields")
        return jsonify({"error": "Missing required fields"}), 400
    
    user_list = users.get(user_type, [])
    user = next((u for u in user_list if u.get("username", u.get("staffId", u.get("regNo"))) == identifier), None)
    
    if not user or not bcrypt.checkpw(password.encode(), user["password"]):
        logger.warning(f"Login failed for {identifier}: Invalid credentials")
        return jsonify({"error": "Invalid credentials"}), 401
    
    token = jwt.encode({
        "identifier": identifier,
        "role": user["role"],
        "exp": datetime.now(timezone.utc) + timedelta(days=30)
    }, SECRET_KEY, algorithm="HS256")
    
    logger.info(f"Login successful for {identifier}, role: {user['role']}")
    return jsonify({"token": token, "role": user["role"]}), 200



@app.route("/api/admin/trainees", methods=["GET", "OPTIONS"])
def get_trainees():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    decoded, error_response = require_auth(["admin"])
    if error_response:
        return error_response
    
    try:
        page = int(request.args.get("page", 1))
        search = request.args.get("search", "").lower()
        sex_filter = request.args.get("sex", "").upper()  # Get sex filter from query params
        per_page = ITEMS_PER_PAGE  # 10 items per page
        # supervisor_id = request.args.get("supervisorId", "")  # Get supervisorId from query params
        # Get all trainees
        trainees = users.get("teacherTrainee", [])
  
  


        
        # Apply search filter across multiple fields
        if search:
            trainees = [
                t for t in trainees
                if any(
                    search in str(t.get(field, "")).lower()
                    for field in ["regNo", "email", "name", "surname", "phone", "address"]
                )
            ]
        
        # Apply sex filter if provided
        if sex_filter in ["MALE", "FEMALE"]:
            trainees = [t for t in trainees if t.get("sex") == sex_filter]
        
        # Sort by createdAt in descending order (newest first)
        trainees.sort(key=lambda x: x.get("createdAt", ""), reverse=True)
        
        # Calculate pagination
        total = len(trainees)
        total_pages = (total + per_page - 1) // per_page
        start = (page - 1) * per_page
        end = start + per_page
        paginated_trainees = trainees[start:end]
        
        # Sanitize the trainees data by removing the password field
        sanitized_trainees = [
            {k: v for k, v in trainee.items() if k != "password"}
            for trainee in paginated_trainees
        ]
        
        return jsonify({
            "trainees": sanitized_trainees,
            "totalCount": total,  # Changed from "total" to "totalCount"
            "totalPages": total_pages,
            "currentPage": page
        }), 200
    
    except Exception as e:
        print(f"Error in get_trainees: {str(e)}")
        return jsonify({"error": "Failed to fetch trainees", "details": str(e)}), 500




@app.route("/api/admin/trainees_id", methods=["GET", "OPTIONS"])
def get_trainees_id():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    decoded, error_response = require_auth(["admin"])
    if error_response:
        return error_response
    
    try:
        page = int(request.args.get("page", 1))
        search = request.args.get("search", "").lower()
        sex_filter = request.args.get("sex", "").upper()
        supervisor_staffid = request.args.get("supervisorId", "")  # Expect staffid
        per_page = ITEMS_PER_PAGE
        
        # Get all trainees
        trainees = users.get("teacherTrainee", [])
        
        # Apply supervisorId filter using tp_assignments
        if supervisor_staffid:
            supervisors = users.get("supervisor", [])
            supervisor = next((s for s in supervisors if s.get("staffid") == supervisor_staffid), None)
            if not supervisor:
                return jsonify({"error": f"Supervisor with staffid {supervisor_staffid} not found"}), 404
            supervisor_user_id = supervisor["id"]
            assignments = users.get("tp_assignments", [])
            trainee_ids = [a["traineeId"] for a in assignments if a.get("supervisorId") == supervisor_user_id]
            trainees = [t for t in trainees if t["id"] in trainee_ids]
        
        # Apply search filter
        if search:
            trainees = [
                t for t in trainees
                if any(
                    search in str(t.get(field, "")).lower()
                    for field in ["regNo", "email", "name", "surname", "phone", "address"]
                )
            ]
        
        # Apply sex filter
        if sex_filter in ["MALE", "FEMALE"]:
            trainees = [t for t in trainees if t.get("sex") == sex_filter]
        
        # Sort by createdAt
        trainees.sort(key=lambda x: x.get("createdAt", ""), reverse=True)
        
        # Enrich trainees with assignment data
        sanitized_trainees = []
        for trainee in trainees:
            assignment = get_trainee_assignment(trainee["id"])
            sanitized_trainee = {
                **{k: v for k, v in trainee.items() if k != "password"},
                "supervisorId": assignment["supervisorStaffId"] if assignment else "",  # staffid
                "supervisorName": assignment["supervisorName"] if assignment else "Not Assigned",
                "placeOfTP": assignment["placeOfTP"] if assignment else "Not Assigned"
            }
            sanitized_trainees.append(sanitized_trainee)
        
        # Pagination
        total = len(sanitized_trainees)
        total_pages = ceil(total / per_page)
        start = (page - 1) * per_page
        end = start + per_page
        paginated_trainees = sanitized_trainees[start:end]
        
        return jsonify({
            "trainees": paginated_trainees,
            "totalCount": total,
            "totalPages": total_pages,
            "currentPage": page
        }), 200
    
    except Exception as e:
        print(f"Error in get_trainees: {str(e)}")
        return jsonify({"error": "Failed to fetch trainees", "details": str(e)}), 500




@app.route("/api/admin/trainees", methods=["POST", "OPTIONS"])
def create_trainee():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    decoded, error_response = require_auth("admin")
    if error_response:
        return error_response
    
    data = request.get_json() or {}
    required_fields = ["regNo", "email", "password", "name", "surname", "address", "bloodType", "sex", "birthday",  "progress"]
    if not all(f in data for f in required_fields):
        return jsonify({"error": "Missing required fields"}), 400
    
    trainees = users.get("teacherTrainee", [])
    if any(t["regNo"] == data["regNo"] or t["email"] == data["email"] for t in trainees):
        return jsonify({"error": "Registration number or email already exists"}), 400
    
    new_id = str(max([int(t["id"]) for t in trainees if t["id"].isdigit()], default=100) + 1)
    new_trainee = {
        "id": new_id,
        "regNo": data["regNo"],
        "email": data["email"],
        "password": bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt()).decode(),
        "role": "teacherTrainee",
        "name": data["name"],
        "surname": data["surname"],
        "phone": data.get("phone", ""),
        "address": data["address"],
        "bloodType": data["bloodType"],
        "sex": data["sex"],
        "birthday": data["birthday"],
        "progress": data.get("progress",""),
        "img": data.get("img", ""),
        "createdAt": datetime.utcnow().isoformat() + "Z"  # Add createdAt timestamp
    }
    
    trainees.append(new_trainee)
    users["teacherTrainee"] = trainees
    save_users(users)
    sanitized_trainee = {k: v for k, v in new_trainee.items() if k != "password"}
    return jsonify({"message": "Trainee created", "trainee": sanitized_trainee}), 201

@app.route("/api/admin/trainees/<id>", methods=["PUT", "DELETE", "OPTIONS"])
def manage_trainee(id):
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    decoded, error_response = require_auth("admin")
    if error_response:
        return error_response
    
    trainees = users.get("teacherTrainee", [])
    trainee = next((t for t in trainees if t["id"] == id), None)
    if not trainee:
        return jsonify({"error": "Trainee not found"}), 404
    
    if request.method == "PUT":
        data = request.get_json() or {}
        print(f"Updating trainee ID {id} with data: {data}")
        updated_trainee = {**trainee, **data, "id": id}
        if "password" in data and data["password"]:
            updated_trainee["password"] = bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt()).decode('utf-8')
        
        trainees = [updated_trainee if t["id"] == id else t for t in trainees]
        users["teacherTrainee"] = trainees
        print(f"Updated trainee: {updated_trainee}")
        try:
            save_users(users)
            print("Successfully saved to users.json")
        except Exception as e:
            print(f"Error saving to users.json: {str(e)}")
            return jsonify({"error": "Failed to save updated trainee"}), 500
        return jsonify({"message": "Trainee updated"}), 200
    
    if request.method == "DELETE":
        users["teacherTrainee"] = [t for t in trainees if t["id"] != id]
        try:
            save_users(users)
            print(f"Successfully deleted trainee ID {id} and saved to users.json")
        except Exception as e:
            print(f"Error saving to users.json: {str(e)}")
            return jsonify({"error": "Failed to delete trainee"}), 500
        return jsonify({"message": "Trainee deleted"}), 200




@app.route('/api/tp-assignments/<trainee_id>', methods=['GET', 'OPTIONS'])
@_require_auth(['admin', 'teacherTrainee'])
def get_tp_assignment(decoded, trainee_id):
    if request.method == 'OPTIONS':
        response = jsonify({"status": "ok"})
        return response, 200

    try:
        users_data = load_users()
        # Validate trainee exists
        trainee = next((t for t in users_data.get('teacherTrainee', []) if t['id'] == trainee_id), None)
        if not trainee:
            logger.error(f"Trainee not found: {trainee_id}")
            return jsonify({"error": "Trainee not found"}), 404

        # Access control: Trainees can only view their own assignment
        if decoded['role'] == 'teacherTrainee' and decoded['identifier'] != trainee['regNo']:
            logger.warning(f"Unauthorized: {decoded['identifier']} cannot access TP assignment for {trainee_id}")
            return jsonify({"error": "Unauthorized: You can only view your own TP assignment"}), 403

        # Fetch assignment using existing function
        assignment = get_trainee_assignment(trainee_id)
        if not assignment:
            logger.info(f"No TP assignment found for trainee {trainee_id}")
            response = jsonify({
                'assignment': {
                    'supervisorId': '',
                    'supervisorName': 'Not Assigned',
                    'supervisorStaffId': '',
                    'schoolId': '',
                    'schoolName': 'Not Assigned',
                    'placeOfTP': 'Not Assigned',
                    'traineeId': trainee_id,
                    'startDate': '',
                    'endDate': '',
                    'status': 'Not Assigned'
                }
            })
            
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response, 200

        # Determine status
        status = 'Assigned'
        try:
            current_date = datetime.now(timezone.utc).date()
            start_date = None
            end_date = None
            if assignment['startDate']:
                start_date = datetime.strptime(assignment['startDate'], '%Y-%m-%d').date()
            if assignment['endDate']:
                end_date = datetime.strptime(assignment['endDate'], '%Y-%m-%d').date()
            
            if not assignment['supervisorId'] or not assignment['schoolId']:
                status = 'Not Assigned'
            elif start_date and end_date:
                if current_date < start_date:
                    status = 'Pending'
                elif current_date > end_date:
                    status = 'Completed'
        except ValueError as e:
            logger.warning(f"Invalid date format for trainee {trainee_id}: {str(e)}")
            status = 'Not Assigned'

        response_assignment = {
            'supervisorId': assignment['supervisorId'],
            'supervisorName': assignment['supervisorName'],
            'supervisorStaffId': assignment['supervisorStaffId'],
            'schoolId': assignment['schoolId'],
            'schoolName': assignment['schoolName'],
            'placeOfTP': assignment['placeOfTP'],
            'traineeId': assignment['traineeId'],
            'startDate': assignment['startDate'],
            'endDate': assignment['endDate'],
            'status': status
        }

        logger.info(f"Fetched TP assignment for trainee {trainee_id}")
        response = jsonify({'assignment': response_assignment})
        
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 200

    except Exception as e:
        logger.error(f"Error fetching TP assignment for trainee {trainee_id}: {str(e)}")
        response = jsonify({"error": "Failed to fetch TP assignment", "details": str(e)})
        
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 500







@app.route("/api/places-of-tp", methods=["GET"])
def get_places_of_tp():
    decoded, error_response = require_admin_auth()
    if error_response:
        return error_response

    schools = users.get("schools", [])
    places = [school["name"] for school in schools if school["name"]]
    return jsonify({"placesOfTP": places}), 200

@app.route('/api/admin/check-tp-period', methods=['GET'])
def check_tp_period():
    decoded, error = require_auth(["admin"])
    if error:
        return error
    data = load_users()
    today = datetime.utcnow().date().isoformat()
    pending_evaluations = [
        a for a in data.get('tp_assignments', [])
        if a['end_date'] <= today and
        not any(e['tp_assignment_id'] == a['id'] for e in data.get('student_evaluations', []))
    ]
    notifications = data.setdefault('notifications', [])
    for a in pending_evaluations:
        trainee = next((t for t in data.get('teacherTrainee', []) if t['id'] == a['traineeId']), {})
        trainee_name = f"{trainee.get('name', '')} {trainee.get('surname', '')}".strip()
        notifications.append({
            "id": f"notif-{uuid.uuid4()}",
            "user_id": decoded['id'],
            "message": f"The TP period for {trainee_name} has ended. Please submit their final evaluation.",
            "created_at": datetime.utcnow().isoformat() + "Z",
            "type": "EVALUATION",
            "priority": "HIGH",
            "read_status": False
        })
    save_users(data)
    logger.info(f"Checked TP periods: {len(pending_evaluations)} pending evaluations")
    return jsonify({"pending_evaluations": len(pending_evaluations)})

@app.route("/api/admin/tp_assignments", methods=["GET"])
def tp_assignments():
    decoded, error_response = require_auth(["admin"])
    if error_response:
        return error_response
    data = users
    page = int(request.args.get("page", 1))
    search = request.args.get("search", "")
    assignments = data.get("tp_assignments", [])
    supervisors = {s["id"]: s for s in data.get("supervisor", [])}
    trainees = {t["id"]: t for t in data.get("teacherTrainee", [])}
    schools = {s["id"]: s for s in data.get("schools", [])}

    enriched_assignments = []
    for a in assignments:
        assignment = a.copy()
        if "start_date" in assignment:
            assignment["startDate"] = assignment.pop("start_date")
        if "end_date" in assignment:
            assignment["endDate"] = assignment.pop("end_date")
        for date_key in ["startDate", "endDate"]:
            date_val = assignment.get(date_key)
            if date_val and not is_valid_date(date_val):
                logger.warning(f"Invalid {date_key} in assignment {a.get('id')}: {date_val}")
                assignment[date_key] = ""
        supervisor = supervisors.get(a.get("supervisorId"))
        if supervisor:
            assignment["supervisor"] = {
                "id": supervisor["id"],
                "staffId": supervisor.get("staffId", supervisor["id"]),
                "name": supervisor.get("name", ""),
                "surname": supervisor.get("surname", "")
            }
        trainee = trainees.get(a.get("traineeId"))
        if trainee:
            assignment["trainee"] = {
                "id": trainee["id"],
                "regNo": trainee.get("regNo", trainee["id"]),
                "name": trainee.get("name", ""),
                "surname": trainee.get("surname", "")
            }
        school = schools.get(a.get("schoolId"))
        if school:
            assignment["school"] = {
                "id": school["id"],
                "name": school.get("name", "")
            }
        enriched_assignments.append(assignment)

    if search:
        enriched_assignments = [
            a for a in enriched_assignments
            if (a.get("trainee") and search.lower() in f"{a['trainee']['name']} {a['trainee']['surname']}".lower()) or
               (a.get("supervisor") and search.lower() in f"{a['supervisor']['name']} {a['supervisor']['surname']}".lower()) or
               search.lower() in a["traineeId"].lower() or
               search.lower() in a["supervisorId"].lower()
        ]

    total_count = len(enriched_assignments)
    per_page = ITEMS_PER_PAGE
    start = (page - 1) * per_page
    end = start + per_page
    paginated = enriched_assignments[start:end]
    logger.info(f"Fetched {len(paginated)} TP assignments for page {page}")
    return jsonify({
        "assignments": paginated,
        "totalCount": total_count,
        "totalPages": (total_count + per_page - 1) // per_page
    }), 200

@app.route("/api/admin/tp_assignments", methods=["POST"])
def create_tp_assignment():
    decoded, error_response = require_auth("admin")
    if error_response:
        return error_response
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    required_fields = ["traineeId", "supervisorId", "schoolId", "startDate", "endDate"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    start_date = data.get("startDate", "")
    end_date = data.get("endDate", "")
    if start_date and not is_valid_date(start_date):
        return jsonify({"error": "Invalid startDate format, use YYYY-MM-DD"}), 400
    if end_date and not is_valid_date(end_date):
        return jsonify({"error": "Invalid endDate format, use YYYY-MM-DD"}), 400


    users_data = users

    new_assignment = {
        "id": generate_unique_id(),
        "traineeId": data.get("traineeId"),
        "supervisorId": data.get("supervisorId"),
        "schoolId": data.get("schoolId"),
        "startDate": start_date,
        "endDate": end_date
    }
    
    # Fetch school name for notifications
    school_name = ""
    for school in users_data.get("schools", []):
        if school["id"] == data["schoolId"]:
            school_name = school["name"]
            break
    
    # Fetch trainee and supervisor names
    trainee_name = data.get("traineeId")  # Fallback to ID
    supervisor_name = data.get("supervisorId")  # Fallback to ID
    for trainee in users_data.get("teacherTrainee", []):
        if trainee["id"] == data["traineeId"]:
            trainee_name = f"{trainee.get('name', '')} {trainee.get('surname', '')}".strip()
            break
    for supervisor in users_data.get("supervisor", []):
        if supervisor["id"] == data["supervisorId"]:
            supervisor_name = f"{supervisor.get('name', '')} {supervisor.get('surname', '')}".strip()
            break
    
    # Create notifications
    notifications = users_data.setdefault("notifications", [])
    now = datetime.utcnow().isoformat() + "Z"
    trainee_notification = {
        "id": f"notif-{uuid.uuid4()}",
        "user_id": data["traineeId"],
        "initiator_id": decoded["identifier"],
        "type": "ASSIGNMENT",
        "priority": "MEDIUM",
        "message": f"You have been assigned to {school_name} with supervisor {supervisor_name}.",
        "created_at": now,
        "read_status": False
    }
    supervisor_notification = {
        "id": f"notif-{uuid.uuid4()}",
        "user_id": data["supervisorId"],
        "initiator_id": decoded["identifier"],
        "type": "ASSIGNMENT",
        "priority": "MEDIUM",
        "message": f"You have been assigned to supervise {trainee_name} at {school_name}.",
        "created_at": now,
        "read_status": False
    }
    notifications.extend([trainee_notification, supervisor_notification])
    
    # Save assignment and notifications
    users_data["tp_assignments"].append(new_assignment)
    users_data["notifications"] = notifications
    save_users(users_data)
    
    logger.info(f"Created TP assignment {new_assignment['id']} by {decoded['identifier']}")
    logger.info(f"Sent notifications to {data['traineeId']} and {data['supervisorId']}")
    return jsonify({
        "message": "Assignment created",
        "assignment": new_assignment,
        "notifications": [trainee_notification, supervisor_notification]
    }), 201


@app.route('/api/admin/tp_assignments/<tp_assignment_id>', methods=['PUT', 'OPTIONS'])
def update_tp_assignment(tp_assignment_id):
    if request.method == 'OPTIONS':
        response = jsonify({"status": "ok"})
        return response, 200

    decoded, error_response = require_auth("admin")
    if error_response:
        response = jsonify(error_response[0]), error_response[1]

    try:
        data = request.get_json() or {}
        required_fields = ['traineeId', 'schoolId', 'supervisorId']
        if not all(field in data for field in required_fields):
            logger.error(f"Missing required fields: {', '.join(f for f in required_fields if f not in data)}")
            response = jsonify({"error": f"Missing required fields: {', '.join(f for f in required_fields if f not in data)}"})
            return response, 400

        users_data = load_users()

        # Validate assignment
        assignment = next((a for a in users_data.get('tp_assignments', []) if a['id'] == tp_assignment_id), None)
        if not assignment:
            logger.error(f"TP assignment not found: {tp_assignment_id}")
            response = jsonify({"error": "TP assignment not found"})
            
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response, 404

        # Verify traineeId matches assignment
        if data['traineeId'] != assignment['traineeId']:
            logger.error(f"Trainee ID mismatch: {data['traineeId']} does not match assignment {tp_assignment_id}")
            response = jsonify({"error": "Trainee ID does not match existing assignment"})
            
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response, 400

        # Validate trainee, school, and supervisor
        trainee = next((t for t in users_data.get('teacherTrainee', []) if t['id'] == data['traineeId']), None)
        if not trainee:
            logger.error(f"Trainee not found: {data['traineeId']}")
            response = jsonify({"error": "Trainee not found"})
            
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response, 404

        school = next((s for s in users_data.get('schools', []) if s['id'] == data['schoolId']), None)
        if not school:
            logger.error(f"School not found: {data['schoolId']}")
            response = jsonify({"error": "School not found"})
            
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response, 404

        supervisor = next((s for s in users_data.get('supervisor', []) if s['id'] == data['supervisorId']), None)
        if not supervisor:
            logger.error(f"Supervisor not found: {data['supervisorId']}")
            response = jsonify({"error": "Supervisor not found"})
            
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response, 404

        # Validate dates if provided
        start_date = data.get('startDate', assignment.get('start_date', ''))
        end_date = data.get('endDate', assignment.get('end_date', ''))
        if start_date and not is_valid_date(start_date):
            logger.error(f"Invalid start_date: {start_date}")
            response = jsonify({"error": "Invalid startDate format, use YYYY-MM-DD"})
            
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response, 400
        if end_date and not is_valid_date(end_date):
            logger.error(f"Invalid end_date: {end_date}")
            response = jsonify({"error": "Invalid endDate format, use YYYY-MM-DD"})
            
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response, 400

        # Update assignment
        with lock:
            updated_assignment = {
                'id': tp_assignment_id,
                'traineeId': assignment['traineeId'],
                'schoolId': data['schoolId'],
                'supervisorId': data['supervisorId'],
                'start_date': start_date,
                'end_date': end_date,
                'createdAt': assignment.get('createdAt', datetime.now(timezone.utc).isoformat() + 'Z'),
                'updatedAt': datetime.now(timezone.utc).isoformat() + 'Z'
            }

            # Replace old assignment
            users_data['tp_assignments'] = [
                updated_assignment if a['id'] == tp_assignment_id else a
                for a in users_data.get('tp_assignments', [])
            ]

            # Fetch names for notifications
            trainee_name = f"{trainee.get('name', '')} {trainee.get('surname', '')}".strip()
            supervisor_name = f"{supervisor.get('name', '')} {supervisor.get('surname', '')}".strip()
            school_name = school.get('name', '')

            # Create notifications
            notifications = users_data.setdefault('notifications', [])
            now = datetime.now(timezone.utc).isoformat() + 'Z'
            trainee_notification = {
                'id': f'notif-{uuid.uuid4()}',
                'user_id': data['traineeId'],
                'initiator_id': decoded['identifier'],
                'type': 'ASSIGNMENT',
                'priority': 'HIGH',
                'message': f'Your TP assignment has been updated: School: {school_name}, Supervisor: {supervisor_name}, Start Date: {start_date or "N/A"}, End Date: {end_date or "N/A"}.',
                'created_at': now,
                'read_status': False
            }
            supervisor_notification = {
                'id': f'notif-{uuid.uuid4()}',
                'user_id': data['supervisorId'],
                'initiator_id': decoded['identifier'],
                'type': 'ASSIGNMENT',
                'priority': 'MEDIUM',
                'message': f'Your supervision assignment for {trainee_name} at {school_name} has been updated: Start Date: {start_date or "N/A"}, End Date: {end_date or "N/A"}.',
                'created_at': now,
                'read_status': False
            }
            notifications.extend([trainee_notification, supervisor_notification])
            users_data['notifications'] = notifications

            # Save changes
            save_users(users_data)

        logger.info(f"Updated TP assignment {tp_assignment_id} for trainee {data['traineeId']}")
        response = jsonify({
            'message': 'TP assignment updated successfully',
            'assignment': {
                'id': updated_assignment['id'],
                'traineeId': updated_assignment['traineeId'],
                'schoolId': updated_assignment['schoolId'],
                'supervisorId': updated_assignment['supervisorId'],
                'startDate': updated_assignment['start_date'],
                'endDate': updated_assignment['end_date'],
                'placeOfTP': school_name,
                'createdAt': updated_assignment['createdAt'],
                'updatedAt': updated_assignment['updatedAt']
            },
            'notifications': [trainee_notification, supervisor_notification]
        })
        return response, 200

    except Exception as e:
        logger.error(f"Error updating TP assignment {tp_assignment_id}: {str(e)}")
        response = jsonify({"error": "Failed to update TP assignment", "details": str(e)})
        
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 500














@app.route("/api/admin/tp_assignments/<id>", methods=["DELETE", "OPTIONS"])
def delete_tp_assignment(id):
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    decoded, error_response = require_auth("admin")
    if error_response:
        return error_response
    
    try:
        assignments = users.get("tp_assignments", [])
        assignment = next((a for a in assignments if a["id"] == id), None)
        if not assignment:
            return jsonify({"error": "Assignment not found"}), 404
        
        users["tp_assignments"] = [a for a in assignments if a["id"] != id]
        save_users(users)
        return jsonify({"message": "TP Assignment deleted"}), 200
    except Exception as e:
        logger.error(f"Error in delete_tp_assignment: {str(e)}")
        return jsonify({"error": "Failed to delete assignment", "details": str(e)}), 500















@app.route("/api/admin/supervisors", methods=["GET", "OPTIONS"])
def get_supervisors():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    decoded, error_response = require_auth("admin")
    if error_response:
        return error_response
    
    try:
        page = int(request.args.get("page", 1))
        search = request.args.get("search", "").lower()
        sex_filter = request.args.get("sex", "").upper()  # Get sex filter from query params
        per_page = ITEMS_PER_PAGE  # 10 items per page
        
        # Get all supervisors
        supervisors = users.get("supervisor", [])
        
        # Apply search filter across multiple fields
        if search:
            supervisors = [
                s for s in supervisors
                if any(
                    search in str(s.get(field, "")).lower()
                    for field in ["staffId", "email", "name", "surname", "phone", "address"]
                )
            ]
        
        # Apply sex filter if provided
        if sex_filter in ["MALE", "FEMALE"]:
            supervisors = [s for s in supervisors if s.get("sex") == sex_filter]
        
        # Sort by createdAt in descending order (newest first)
        supervisors.sort(key=lambda x: x.get("createdAt", ""), reverse=True)
        
        # Calculate pagination
        total = len(supervisors)
        total_pages = (total + per_page - 1) // per_page
        start = (page - 1) * per_page
        end = start + per_page
        paginated_supervisors = supervisors[start:end]
        
        # Sanitize the supervisors data by removing the password field
        sanitized_supervisors = [
            {k: v for k, v in supervisor.items() if k != "password"}
            for supervisor in paginated_supervisors
        ]
        
        return jsonify({
            "supervisors": sanitized_supervisors,
            "totalCount": total,  # Changed from "total" to "totalCount"
            "totalPages": total_pages,
            "currentPage": page
        }), 200
    
    except Exception as e:
        print(f"Error in get_supervisors: {str(e)}")
        return jsonify({"error": "Failed to fetch supervisors", "details": str(e)}), 500


@app.route("/api/supervisors/<supervisor_id>", methods=["GET"])
def get_supervisor(supervisor_id):
    decoded, error_response = require_auth()
    if error_response:
        return error_response
    
    supervisor = next((s for s in users.get("supervisor", []) if s["id"] == supervisor_id), None)
    if not supervisor:
        return jsonify({"error": "Supervisor not found"}), 404
    
    # Sanitize supervisor data to exclude password
    sanitized_supervisor = {k: v for k, v in supervisor.items() if k != "password"}
    return jsonify(sanitized_supervisor)


@app.route("/api/supervisors/<supervisor_id>/trainees-average-progress", methods=["GET", "OPTIONS"])
def get_trainees_average_progress(supervisor_id):
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    decoded, error_response = require_auth()
    if error_response:
        logger.debug(f"Auth failed for supervisor ID {supervisor_id}: {error_response.get_json()['error']}")
        return error_response
    
    # Validate supervisor exists
    supervisor = next((s for s in users.get("supervisor", []) if s["id"] == supervisor_id), None)
    if not supervisor:
        logger.debug(f"Supervisor ID {supervisor_id} not found")
        return jsonify({"error": "Supervisor not found"}), 404
    
    # Access control: Admins or the supervisor themselves
    if decoded["role"] not in ["admin", "supervisor"]:
        logger.debug(f"Unauthorized role {decoded['role']} for supervisor ID {supervisor_id}")
        return jsonify({"error": "Unauthorized"}), 403
    if decoded["role"] == "supervisor" and decoded["identifier"] != supervisor["staffId"]:
        logger.debug(f"Supervisor {decoded['identifier']} attempted to access supervisor ID {supervisor_id}")
        return jsonify({"error": "Unauthorized: You can only view your own trainees"}), 403
    
    try:
        # Find trainees assigned to this supervisor via tp_assignments
        assignments = users.get("tp_assignments", [])
        trainee_ids = [a["traineeId"] for a in assignments if a["supervisorId"] == supervisor_id]
        
        if not trainee_ids:
            logger.debug(f"No trainees assigned to supervisor ID {supervisor_id}")
            return jsonify({"averageProgress": 0}), 200
        
        trainees = users.get("teacherTrainee", [])
        assigned_trainees = [
            t for t in trainees
            if t["id"] in trainee_ids
        ]
        
        if not assigned_trainees:
            logger.debug(f"No matching trainees found for supervisor ID {supervisor_id}")
            return jsonify({"averageProgress": 0}), 200
        
        # Calculate average progress
        total_progress = sum(float(t.get("progress", 0)) for t in assigned_trainees)
        average = total_progress / len(assigned_trainees)
        
        logger.debug(f"Average progress for supervisor ID {supervisor_id}: {average:.1f}")
        return jsonify({"averageProgress": round(average, 1)}), 200
    except Exception as e:
        logger.error(f"Error in GET /api/supervisors/{supervisor_id}/trainees-average-progress: {str(e)}")
        return jsonify({"error": "Failed to calculate average progress", "details": str(e)}), 500



@app.route("/api/admin/supervisors/<id>", methods=["PUT", "DELETE", "OPTIONS"])
def manage_supervisor(id):
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    decoded, error_response = require_auth("admin")
    if error_response:
        return error_response
    
    supervisors = users.get("supervisor", [])
    supervisor = next((s for s in supervisors if s["id"] == id), None)
    if not supervisor:
        return jsonify({"error": "Supervisor not found"}), 404
    
    try:
        if request.method == "PUT":
            data = request.get_json() or {}
            print(f"Updating supervisor ID {id} with data: {data}")
            
            # Check for duplicate staffId or email (excluding the current supervisor)
            if "staffId" in data and data["staffId"] != supervisor["staffId"]:
                if any(s["staffId"] == data["staffId"] and s["id"] != id for s in supervisors):
                    return jsonify({"error": "Staff ID already exists"}), 400
            
            if "email" in data and data["email"] != supervisor["email"]:
                if any(s["email"] == data["email"] and s["id"] != id for s in supervisors):
                    return jsonify({"error": "Email already exists"}), 400
            
            # Validate sex if provided
            if "sex" in data and data["sex"] not in ["MALE", "FEMALE"]:
                return jsonify({"error": "Sex must be either 'MALE' or 'FEMALE'"}), 400
            
            # Validate birthday if provided
            if "birthday" in data:
                try:
                    datetime.strptime(data["birthday"], "%Y-%m-%d")
                except ValueError:
                    return jsonify({"error": "Birthday must be in YYYY-MM-DD format"}), 400
            
            # Explicitly update fields
            supervisor["staffId"] = data.get("staffId", supervisor["staffId"])
            supervisor["email"] = data.get("email", supervisor["email"])
            if "password" in data and data["password"]:
                if not isinstance(data["password"], str) or not data["password"]:
                    return jsonify({"error": "Password must be a non-empty string"}), 400
                supervisor["password"] = bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt()).decode("utf-8")
            supervisor["name"] = data.get("name", supervisor["name"])
            supervisor["surname"] = data.get("surname", supervisor["surname"])
            supervisor["phone"] = data.get("phone", supervisor["phone"])
            supervisor["address"] = data.get("address", supervisor["address"])
            supervisor["bloodType"] = data.get("bloodType", supervisor["bloodType"])
            supervisor["sex"] = data.get("sex", supervisor["sex"])
            supervisor["birthday"] = data.get("birthday", supervisor["birthday"])
            supervisor["placeOfSupervision"] = data.get("placeOfSupervision", supervisor["placeOfSupervision"])
            # supervisor["img"] = data.get("img", supervisor["img"])
            supervisor["img"] = data.get("img", supervisor.get("img", ""))
            
            users["supervisor"] = supervisors
            save_users(users)
            return jsonify({"message": "Supervisor updated"}), 200
        
        if request.method == "DELETE":
            users["supervisor"] = [s for s in supervisors if s["id"] != id]
            save_users(users)
            return jsonify({"message": "Supervisor deleted"}), 200
    
    except Exception as e:
        print(f"Error in manage_supervisor: {str(e)}")
        return jsonify({"error": "Failed to process request", "details": str(e)}), 500


# Supervisor Routes
@app.route("/api/admin/supervisors", methods=["POST", "OPTIONS"])
def create_supervisor():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    decoded, error_response = require_auth("admin")
    if error_response:
        return error_response
    
    data = request.get_json() or {}
    required_fields = ["staffId", "email", "password", "name", "surname", "address", "bloodType", "sex", "birthday", "placeOfSupervision"]
    if not all(f in data for f in required_fields):
        return jsonify({"error": "Missing required fields"}), 400
    
    supervisors = users.get("supervisor", [])
    if any(s["staffId"] == data["staffId"] or s["email"] == data["email"] for s in supervisors):
        return jsonify({"error": "Staff ID or email already exists"}), 400
    
    new_id = str(max([int(s["id"]) for s in supervisors if s["id"].isdigit()], default=0) + 1)
    new_supervisor = {
        "id": new_id,
        "staffId": data["staffId"],
        "email": data["email"],
        "password": bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt()),
        "role": "supervisor",
        "name": data["name"],
        "surname": data["surname"],
        "phone": data.get("phone", ""),
        "address": data["address"],
        "bloodType": data["bloodType"],
        "sex": data["sex"],
        "birthday": data["birthday"],
        "placeOfSupervision": data["placeOfSupervision"],
        "img": data.get("img", "")
    }
    
    supervisors.append(new_supervisor)
    users["supervisor"] = supervisors
    save_users(users)
    sanitized_supervisor = {k: v for k, v in new_supervisor.items() if k != "password"}
    return jsonify({"message": "Supervisor created", "supervisor": sanitized_supervisor}), 201


@app.route("/api/lessons/supervisor/<supervisor_id>", methods=["GET"])
def get_supervisor_lessons(supervisor_id):
    decoded, error_response = require_auth("admin")
    if error_response:
        return error_response
    
    # Mock lessons (replace with actual data)
    lessons = [
        {"id": 1, "supervisorId": supervisor_id, "className": "Class 5A", "subject": "Math", "startTime": "2025-04-07T09:00:00Z", "endTime": "2025-04-07T10:00:00Z"}, ]
    return jsonify({"lessons": lessons}), 200


@app.route("/api/lessons/trainee/<trainee_id>", methods=["GET"])
def get_trainee_lessons(trainee_id):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return jsonify({"error": "Invalid or expired token"}), 401

    trainee = None
    for t in users.get("teacherTrainee", []):
        if t["id"] == trainee_id:
            trainee = t
            break

    if not trainee:
        return jsonify({"error": "Trainee not found"}), 404

    if decoded["role"] == "teacherTrainee" and decoded["identifier"] != trainee["regNo"]:
        return jsonify({"error": "Unauthorized: You can only view your own lessons"}), 403

    assignment = None
    for a in users.get("tp_assignments", []):
        if a["traineeId"] == trainee_id:
            assignment = a
            break

    if not assignment or not assignment["supervisorId"]:
        return jsonify({"lessons": [], "total": 0, "page": 1, "limit": 10}), 200

    if decoded["role"] == "supervisor" and decoded["identifier"] != assignment["supervisorId"]:
        return jsonify({"error": "Unauthorized: You can only view lessons of your assigned trainees"}), 403

    lessons = users.get("lessons", [])
    trainee_lessons = [lesson for lesson in lessons if lesson.get("supervisorId") == assignment["supervisorId"]]

    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 10))
    start = (page - 1) * limit
    end = start + limit

    return jsonify({
        "lessons": trainee_lessons[start:end],
        "total": len(trainee_lessons),
        "page": page,
        "limit": limit
    }), 200






@app.route("/api/trainees/me/lesson-plans", methods=["GET", "OPTIONS"])
def get_current_trainee_lesson_plans():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    # Authenticate the user
    decoded, error_response = require_auth()
    if error_response:
        logger.debug(f"Auth failed for current trainee: {error_response.get_json()['error']}")
        return error_response

    # Ensure the user is a teacherTrainee
    if decoded["role"] != "teacherTrainee":
        logger.debug(f"Unauthorized role {decoded['role']} for accessing trainee lesson plans")
        return jsonify({"error": "Unauthorized: Trainee role required"}), 403

    # Find the trainee by their identifier (regNo)
    trainee = next((t for t in users.get("teacherTrainee", []) if t["regNo"] == decoded["identifier"]), None)
    if not trainee:
        logger.debug(f"Trainee with identifier {decoded['identifier']} not found")
        return jsonify({"error": "Trainee not found"}), 404

    try:
        # Get lesson plans for this trainee
        lesson_plans = users.get("lesson_plans", [])
        trainee_lesson_plans = [
            lp for lp in lesson_plans
            if isinstance(lp, dict) and lp.get("traineeId") == trainee["id"]
        ]

        logger.debug(f"Returning {len(trainee_lesson_plans)} lesson plans for trainee {decoded['identifier']}")
        return jsonify({"data": trainee_lesson_plans}), 200
    except Exception as e:
        logger.error(f"Error in GET /api/trainees/me/lesson-plans: {str(e)}")
        return jsonify({"error": "Failed to fetch lesson plans", "details": str(e)}), 500





@app.route("/api/supervisors/<supervisor_id>/evaluations", methods=["GET", "POST"])
def handle_supervisor_evaluations(supervisor_id):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return jsonify({"error": "Invalid or expired token"}), 401

    supervisor = None
    for s in users.get("supervisor", []):
        if s["id"] == supervisor_id:
            supervisor = s
            break

    if not supervisor:
        return jsonify({"error": "Supervisor not found"}), 404

    if decoded["role"] == "supervisor" and decoded["identifier"] != supervisor["staffId"]:
        return jsonify({"error": "Unauthorized: You can only access your own evaluations"}), 403

    evaluations = users.get("evaluations", [])

    if request.method == "GET":
        supervisor_evaluations = [e for e in evaluations if e.get("supervisorId") == supervisor_id]
        if request.args.get("recent") == "true":
            one_month_ago = datetime.utcnow() - timedelta(days=30)
            supervisor_evaluations = [
                e for e in supervisor_evaluations
                if datetime.fromisoformat(e["submittedAt"].replace("Z", "")) >= one_month_ago
            ]
        return jsonify({"evaluations": supervisor_evaluations}), 200

    if request.method == "POST":
        if decoded["role"] != "supervisor":
            return jsonify({"error": "Unauthorized: Only supervisors can submit evaluations"}), 403

        data = request.get_json()
        trainee_id = data.get("traineeId")
        form_data = data.get("formData")

        if not trainee_id or not form_data:
            return jsonify({"error": "traineeId and formData are required"}), 400

        trainee = None
        for t in users.get("teacherTrainee", []):
            if t["id"] == trainee_id:
                trainee = t
                break

        if not trainee:
            return jsonify({"error": "Trainee not found"}), 404

        assignment = None
        for a in users.get("tp_assignments", []):
            if a["traineeId"] == trainee_id:
                assignment = a
                break

        if not assignment or assignment["supervisorId"] != supervisor_id:
            return jsonify({"error": "Unauthorized: Trainee not assigned to this supervisor"}), 403

        evaluation = {
            "id": str(len(evaluations) + 1),
            "supervisorId": supervisor_id,
            "traineeId": trainee_id,
            "traineeName": f"{trainee['name']} {trainee['surname']}",
            "submittedAt": datetime.utcnow().isoformat() + "Z",
            "formData": form_data
        }

        evaluations.append(evaluation)
        users["evaluations"] = evaluations
        save_users()
        return jsonify({"message": "Evaluation submitted successfully", "evaluation": evaluation}), 201

@app.route("/api/admin/schools", methods=["GET"])
def get_schools():
    try:
        decoded, error_response = require_auth()
        if error_response:
            return error_response
        
        if decoded["role"] != "admin":
            return jsonify({"error": "Unauthorized: Only admins can view schools"}), 403
        
        schools = users.get("schools", [])
        
        # Get query parameters
        page = int(request.args.get("page", 1))
        per_page = 10
        search_query = request.args.get("search", "").strip().lower()
        type_filter = request.args.get("type", "").strip().upper()
        
        # Filter schools
        filtered_schools = schools
        if search_query:
            # For larger datasets, consider indexing 'name' and 'email' fields in a proper database
            filtered_schools = [
                s for s in filtered_schools
                if search_query in s["name"].lower() or search_query in s["email"].lower()
            ]
        if type_filter in ["PRIMARY", "SECONDARY", "TERTIARY"]:
            filtered_schools = [s for s in filtered_schools if s["type"] == type_filter]
        
        # Paginate with validation
        total = len(filtered_schools)
        total_pages = (total + per_page - 1) // per_page
        page = max(1, min(page, total_pages or 1))  # Clamp page within valid range
        start = (page - 1) * per_page
        end = start + per_page
        paginated_schools = filtered_schools[start:end]
        
        return jsonify({
            "schools": paginated_schools,
            "totalCount": total,
            "totalPages": total_pages,
            "currentPage": page
        }), 200
    
    except Exception as e:
        logger.error(f"Error fetching schools: {str(e)}")
        return jsonify({"error": "Failed to fetch schools"}), 500

# Create a new school
@app.route("/api/admin/schools", methods=["POST"])
def create_school():
    decoded, error_response = require_auth()
    if error_response:
        return error_response
    
    if decoded["role"] != "admin":
        return jsonify({"error": "Unauthorized: Only admins can create schools"}), 403
    
    data = request.get_json()
    required_fields = ["name", "address", "email", "phone", "type", "principal"]
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields: " + ", ".join(required_fields)}), 400
    
    # Validate type
    if data["type"] not in ["PRIMARY", "SECONDARY", "TERTIARY"]:
        return jsonify({"error": "Invalid school type: must be PRIMARY, SECONDARY, or TERTIARY"}), 400
    
    schools = users.get("schools", [])
    
    # Check for duplicate email
    if any(s["email"] == data["email"] for s in schools):
        return jsonify({"error": "School with this email already exists"}), 400
    
    new_school = {
        "id": generate_unique_id(),
        "name": data["name"],
        "address": data["address"],
        "email": data["email"],
        "phone": data["phone"],
        "type": data["type"],
        "principal": data["principal"],
        "logo": data.get("logo", ""),
        "createdAt": datetime.now().isoformat() + "Z"
    }
    
    schools.append(new_school)
    users["schools"] = schools
    save_users(users)
    
    return jsonify({"message": "School created successfully", "school": new_school}), 201

# Update a school
@app.route("/api/admin/schools/<school_id>", methods=["PUT"])
def update_school(school_id):
    decoded, error_response = require_auth()
    if error_response:
        return error_response
    
    if decoded["role"] != "admin":
        return jsonify({"error": "Unauthorized: Only admins can update schools"}), 403
    
    data = request.get_json()
    schools = users.get("schools", [])
    school = next((s for s in schools if s["id"] == school_id), None)
    
    if not school:
        return jsonify({"error": "School not found"}), 404
    
    # Update fields
    school["name"] = data.get("name", school["name"])
    school["address"] = data.get("address", school["address"])
    school["email"] = data.get("email", school["email"])
    school["phone"] = data.get("phone", school["phone"])
    school["type"] = data.get("type", school["type"])
    school["principal"] = data.get("principal", school["principal"])
    school["logo"] = data.get("logo", school["logo"])
    
    # Validate type
    if school["type"] not in ["PRIMARY", "SECONDARY", "TERTIARY"]:
        return jsonify({"error": "Invalid school type: must be PRIMARY, SECONDARY, or TERTIARY"}), 400
    
    # Check for duplicate email (excluding the current school)
    if any(s["email"] == school["email"] and s["id"] != school_id for s in schools):
        return jsonify({"error": "School with this email already exists"}), 400
    
    users["schools"] = schools
    save_users(users)
    
    return jsonify({"message": "School updated successfully", "school": school}), 200

# Delete a school
@app.route("/api/admin/schools/<school_id>", methods=["DELETE"])
def delete_school(school_id):
    decoded, error_response = require_auth()
    if error_response:
        return error_response
    
    if decoded["role"] != "admin":
        return jsonify({"error": "Unauthorized: Only admins can delete schools"}), 403
    
    schools = users.get("schools", [])
    school = next((s for s in schools if s["id"] == school_id), None)
    
    if not school:
        return jsonify({"error": "School not found"}), 404
    
    # Check if the school is assigned to any TP assignments
    tp_assignments = users.get("tp_assignments", [])
    if any(a["schoolId"] == school_id for a in tp_assignments):
        return jsonify({"error": "Cannot delete school: It is assigned to one or more TP assignments"}), 400
    
    schools.remove(school)
    users["schools"] = schools
    save_users(users)
    
    return jsonify({"message": "School deleted successfully"}), 200





@app.route("/api/trainees/bulk", methods=["POST", "OPTIONS"])
def bulk_create_trainees():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    # Authentication check
    decoded, error_response = require_auth()
    if error_response:
        return error_response
    
    # Only admins can bulk create trainees
    if decoded["role"] != "admin":
        return jsonify({"error": "Unauthorized: Only admins can bulk create trainees"}), 403
    
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files["file"]
    
    # Validate file extension
    if not file.filename.endswith(".csv"):
        return jsonify({"error": "File must be a CSV"}), 400
    
    # Read the CSV file
    stream = io.StringIO(file.stream.read().decode("UTF-8"))
    csv_reader = csv.DictReader(stream)
    
    # Validate required fields in CSV
    required_fields = ["regNo", "name", "surname", "email", "password", "phone", "address", "bloodType", "sex", "birthday"]
    if not all(field in csv_reader.fieldnames for field in required_fields):
        return jsonify({"error": "CSV missing required fields: " + ", ".join(required_fields)}), 400
    
    trainees = users.get("teacherTrainee", [])
    created_trainees = []
    errors = []
    
    for row in csv_reader:
        # Validate sex field
        if row["sex"] not in ["MALE", "FEMALE"]:
            errors.append(f"Invalid sex value for regNo {row['regNo']}: must be 'MALE' or 'FEMALE'")
            continue
        
        # Check for duplicates based on regNo or email
        if any(t["regNo"] == row["regNo"] for t in trainees):
            errors.append(f"Trainee with regNo {row['regNo']} already exists")
            continue
        if any(t["email"] == row["email"] for t in trainees):
            errors.append(f"Trainee with email {row['email']} already exists")
            continue
        
        # Hash password with bcrypt
        try:
            hashed_password = bcrypt.hashpw(row["password"].encode(), bcrypt.gensalt())
        except Exception as e:
            errors.append(f"Error hashing password for regNo {row['regNo']}: {str(e)}")
            continue
        
        # Create new trainee object
        new_trainee = {
            "id": generate_unique_id(),
            "regNo": row["regNo"],
            "password": hashed_password.decode("utf-8"),  # Store the hashed password
            "email": row["email"],
            "role": "teacherTrainee",
            "name": row["name"],
            "surname": row["surname"],
            "phone": row["phone"],
            "address": row["address"],
            "bloodType": row["bloodType"],
            "sex": row["sex"],
            "birthday": row["birthday"],
            "progress": 0,  # Default progress
            "img": row.get("img", ""),  # Default image
            "createdAt": datetime.now().isoformat() + "Z"
        }
        
        trainees.append(new_trainee)
        created_trainees.append(new_trainee)
    
    if errors:
        return jsonify({"message": "Some trainees were not created", "errors": errors, "created": created_trainees}), 207
    
    # Update the users list and save
    users["teacherTrainee"] = trainees
    save_users(users)
    
    return jsonify({"message": "Trainees created successfully", "created": created_trainees}), 201









@app.route("/api/supervisors/bulk", methods=["POST", "OPTIONS"])
def bulk_create_supervisors():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    # Authentication check
    decoded, error_response = require_auth()
    if error_response:
        return error_response
    
    # Only admins can bulk create supervisors
    if decoded["role"] != "admin":
        return jsonify({"error": "Unauthorized: Only admins can bulk create supervisors"}), 403
    
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files["file"]
    
    # Validate file extension
    if not file.filename.endswith(".csv"):
        return jsonify({"error": "File must be a CSV"}), 400
    
    # Read the CSV file
    stream = io.StringIO(file.stream.read().decode("UTF-8"))
    csv_reader = csv.DictReader(stream)
    
    # Validate required fields in CSV
    required_fields = ["staffId", "name", "surname", "email", "password", "phone", "address", "bloodType", "sex", "birthday"]
    if not all(field in csv_reader.fieldnames for field in required_fields):
        return jsonify({"error": "CSV missing required fields: " + ", ".join(required_fields)}), 400
    
    supervisors = users.get("supervisor", [])
    created_supervisors = []
    errors = []
    
    for row in csv_reader:
        # Validate sex field
        if row["sex"] not in ["MALE", "FEMALE"]:
            errors.append(f"Invalid sex value for staffId {row['staffId']}: must be 'MALE' or 'FEMALE'")
            continue
        
        # Check for duplicates based on staffId or email
        if any(s["staffId"] == row["staffId"] for s in supervisors):
            errors.append(f"Supervisor with staffId {row['staffId']} already exists")
            continue
        if any(s["email"] == row["email"] for s in supervisors):
            errors.append(f"Supervisor with email {row['email']} already exists")
            continue
        
        # Hash password with bcrypt
        try:
            hashed_password = bcrypt.hashpw(row["password"].encode(), bcrypt.gensalt())
        except Exception as e:
            errors.append(f"Error hashing password for staffId {row['staffId']}: {str(e)}")
            continue
        
        # Create new supervisor object
        new_supervisor = {
            "id": generate_unique_id(),
            "staffId": row["staffId"],
            "password": hashed_password.decode("utf-8"),  # Store the hashed password
            "email": row["email"],
            "role": "supervisor",
            "name": row["name"],
            "surname": row["surname"],
            "phone": row["phone"],
            "address": row["address"],
            "bloodType": row["bloodType"],
            "sex": row["sex"],
            "birthday": row["birthday"],
            "img": row.get("img", ""),  # Default image
            "createdAt": datetime.now().isoformat() + "Z"
        }
        
        supervisors.append(new_supervisor)
        created_supervisors.append(new_supervisor)
    
    if errors:
        return jsonify({"message": "Some supervisors were not created", "errors": errors, "created": created_supervisors}), 207
    
    # Update the users list and save
    users["supervisor"] = supervisors
    save_users(users)
    
    return jsonify({"message": "Supervisors created successfully", "created": created_supervisors}), 201






@app.route("/api/trainees/<id>/supervisor", methods=["GET", "OPTIONS"])
def get_trainee_supervisor(id):
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    decoded, error_response = require_auth()
    if error_response:
        return error_response
    
    trainees = users.get("teacherTrainee", [])
    trainee = next((t for t in trainees if t["id"] == id), None)
    if not trainee:
        return jsonify({"error": "Trainee not found"}), 404
    
    # Access control
    if decoded["role"] not in ["admin", "teacherTrainee", "supervisor"]:
        return jsonify({"error": "Unauthorized"}), 403
    if decoded["role"] == "teacherTrainee" and decoded["identifier"] != trainee["regNo"]:
        return jsonify({"error": "Unauthorized: You can only view your own supervisor"}), 403
    
    # Get the TP assignment
    assignment = get_trainee_assignment(id)
    if not assignment:
        return jsonify({"supervisor": None, "assignment": None}), 200
    
    # Additional access control for supervisors
    if decoded["role"] == "supervisor" and assignment["supervisorId"] != decoded["identifier"]:
        return jsonify({"error": "Unauthorized: You can only view your own trainees"}), 403
    
    # Look up the supervisor
    supervisors = users.get("supervisor", [])
    supervisor = next((s for s in supervisors if s["id"] == assignment["supervisorId"]), None)
    
    # Prepare response
    response = {
        "supervisor": None,
        "assignment": {
            "traineeId":assignment["traineeId"],
            "supervisorId": assignment["supervisorId"],
            "supervisorName": assignment["supervisorName"],
            "placeOfTP": assignment["placeOfTP"],
            "schoolId": assignment["schoolId"],
            "startDate": assignment["startDate"],
            "endDate": assignment["endDate"]
        }
    }
    
    if supervisor:
        sanitized_supervisor = {k: v for k, v in supervisor.items() if k != "password"}
        response["supervisor"] = sanitized_supervisor
    
    return jsonify(response), 200





@app.route("/api/trainees/<trainee_id>/feedback-history", methods=["GET"])
def get_trainee_feedback_history(trainee_id):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return jsonify({"error": "Invalid or expired token"}), 401

    trainee = None
    for t in users.get("teacherTrainee", []):
        if t["id"] == trainee_id:
            trainee = t
            break

    if not trainee:
        return jsonify({"error": "Trainee not found"}), 404

    if decoded["role"] == "teacherTrainee" and decoded["identifier"] != trainee["regNo"]:
        return jsonify({"error": "Unauthorized: You can only view your own feedback"}), 403

    if decoded["role"] == "supervisor":
        assignment = None
        for a in users.get("tp_assignments", []):
            if a["traineeId"] == trainee_id:
                assignment = a
                break
        if not assignment or assignment["supervisorId"] != decoded["identifier"]:
            return jsonify({"error": "Unauthorized: You can only view feedback for your assigned trainees"}), 403

    feedback_list = users.get("feedback", [])
    trainee_feedback = [f for f in feedback_list if f["traineeId"] == trainee_id]
    return jsonify({"feedback": trainee_feedback}), 200

@app.route("/api/supervisors/<supervisor_id>/trainees-count", methods=["GET"])
def get_supervised_trainees_count(supervisor_id):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return jsonify({"error": "Invalid or expired token"}), 401

    supervisor = None
    for s in users.get("supervisor", []):
        if s["id"] == supervisor_id:
            supervisor = s
            break

    if not supervisor:
        return jsonify({"error": "Supervisor not found"}), 404

    if decoded["role"] == "supervisor" and decoded["identifier"] != supervisor["staffId"]:
        return jsonify({"error": "Unauthorized: You can only view your own trainees count"}), 403

    count = 0
    for a in users.get("tp_assignments", []):
        if a["supervisorId"] == supervisor_id:
            count += 1

    return jsonify({"count": count}), 200








@app.route("/api/verify", methods=["GET", "OPTIONS"])
def verify():
    if request.method == "OPTIONS":
        return "", 200
    
    decoded, error_response = require_auth()
    if error_response:
        return error_response
    return jsonify({"role": decoded["role"], "identifier": decoded["identifier"]})





# New Endpoints
@app.route('/api/admin/student-evaluations', methods=['POST'])
def submit_student_evaluation():
    decoded, error = require_auth(["admin"])
    if error:
        return error
    data = load_users()
    payload = request.get_json()
    tp_assignment_id = payload.get('tp_assignment_id')
    score = payload.get('score')
    comments = payload.get('comments')

    # Validate
    if not all([tp_assignment_id, score is not None, comments]):
        logger.error("Missing required fields in student evaluation")
        return jsonify({"error": "Missing required fields"}), 400
    if not isinstance(score, int) or score < 0 or score > 100:
        logger.error(f"Invalid score: {score}")
        return jsonify({"error": "Score must be an integer between 0 and 100"}), 400
    assignment = next((a for a in data.get('tp_assignments', []) if a['id'] == tp_assignment_id), None)
    if not assignment:
        logger.error(f"Invalid TP assignment ID: {tp_assignment_id}")
        return jsonify({"error": "Invalid TP assignment ID"}), 404
    if any(e['tp_assignment_id'] == tp_assignment_id for e in data.get('student_evaluations', [])):
        logger.error(f"Evaluation already exists for TP assignment: {tp_assignment_id}")
        return jsonify({"error": "Evaluation already submitted for this TP assignment"}), 409

    # Save Evaluation
    evaluation = {
        "id": f"seval{len(data.get('student_evaluations', [])) + 1}",
        "tp_assignment_id": tp_assignment_id,
        "score": score,
        "comments": comments,
        "submitted_at": datetime.utcnow().isoformat() + "Z"
    }
    data.setdefault('student_evaluations', []).append(evaluation)

    # Notify Trainee
    trainee = next((t for t in data.get('teacherTrainee', []) if t['id'] == assignment['traineeId']), {})
    trainee_name = f"{trainee.get('name', '')} {trainee.get('surname', '')}".strip()
    submitted_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    notifications = data.setdefault('notifications', [])
    notifications.append({
        "id": f"notif{len(notifications) + 1}",
        "user_id": assignment['traineeId'],
        "message": f"Admin has submitted your final TP evaluation: {score}/100 – {submitted_at}",
        "created_at": submitted_at
    })

    save_data(data)
    logger.info(f"Student evaluation submitted for TP assignment {tp_assignment_id}")
    return jsonify({"message": "Student evaluation submitted successfully"})



@app.route('/api/admin/supervisor-evaluations', methods=['POST'])
def submit_supervisor_evaluation():
    decoded, error = require_auth(["admin"])
    if error:
        return error
    data = load_users()
    payload = request.get_json()
    supervisor_id = payload.get('supervisor_id')
    rating = payload.get('rating')
    comments = payload.get('comments')

    # Validate
    if not all([supervisor_id, rating is not None, comments]):
        logger.error("Missing required fields in supervisor evaluation")
        return jsonify({"error": "Missing required fields"}), 400
    if not isinstance(rating, int) or rating < 0 or rating > 10:
        logger.error(f"Invalid rating: {rating}")
        return jsonify({"error": "Rating must be an integer between 0 and 10"}), 400
    supervisor = next((s for s in data.get('supervisors', []) if s['id'] == supervisor_id), None)
    if not supervisor:
        logger.error(f"Invalid supervisor ID: {supervisor_id}")
        return jsonify({"error": "Invalid supervisor ID"}), 404
    if any(e['supervisor_id'] == supervisor_id for e in data.get('supervisor_evaluations', [])):
        logger.error(f"Evaluation already exists for supervisor: {supervisor_id}")
        return jsonify({"error": "Evaluation already submitted for this supervisor"}), 409

    # Save Evaluation
    evaluation = {
        "id": f"speval{len(data.get('supervisor_evaluations', [])) + 1}",
        "supervisor_id": supervisor_id,
        "rating": rating,
        "comments": comments,
        "submitted_at": datetime.utcnow().isoformat() + "Z"
    }
    data.setdefault('supervisor_evaluations', []).append(evaluation)

    # Notify Supervisor
    supervisor_name = f"{supervisor.get('name', '')} {supervisor.get('surname', '')}".strip()
    submitted_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    data.setdefault('notifications', []).append({
        "id": f"notif{len(data.get('notifications', [])) + 1}",
        "user_id": supervisor_id,
        "message": f"Admin has submitted your performance evaluation: {rating}/10 – {submitted_at}",
        "created_at": submitted_at
    })

    save_data(data)
    logger.info(f"Supervisor evaluation submitted for {supervisor_id}")
    return jsonify({"message": "Supervisor evaluation submitted successfully"})


























@app.route("/api/admin/student_evaluations", methods=["GET"])
def student_evaluations():
    decoded, error_response = require_auth(["admin","supervisor"])
    if error_response:
        return error_response
    data = users
    page = int(request.args.get("page", 1))
    search = request.args.get("search", "").lower()
    evaluations = data.get("student_evaluations", [])
    trainees = {t["id"]: t for t in data.get("teacherTrainee", [])}
    supervisors = {s["id"]: s for s in data.get("supervisor", [])}

    enriched_evaluations = []
    for e in evaluations:
        evaluation = e.copy()
        # Validate and normalize
        if not is_valid_date(evaluation.get("submittedAt")):
            logger.warning(f"Invalid submittedAt in evaluation {e['id']}: {evaluation['submittedAt']}")
            evaluation["submittedAt"] = ""
        # Enrich with trainee details
        trainee = trainees.get(e.get("traineeId"))
        if trainee:
            evaluation["trainee"] = {
                "id": trainee["id"],
                "name": trainee.get("name", ""),
                "surname": trainee.get("surname", "")
            }
        # Enrich with supervisor details
        supervisor = supervisors.get(e.get("supervisorId"))
        if supervisor:
            evaluation["supervisor"] = {
                "id": supervisor["id"],
                "name": supervisor.get("name", ""),
                "surname": supervisor.get("surname", "")
            }
        enriched_evaluations.append(evaluation)

    # Apply search filter
    if search:
        enriched_evaluations = [
            e for e in enriched_evaluations
            if (e.get("trainee") and search in f"{e['trainee']['name']} {e['trainee']['surname']}".lower()) or
               (e.get("supervisor") and search in f"{e['supervisor']['name']} {e['supervisor']['surname']}".lower())
        ]

    # Paginate
    total_count = len(enriched_evaluations)
    per_page = ITEMS_PER_PAGE
    start = (page - 1) * per_page
    end = start + per_page
    paginated = enriched_evaluations[start:end]
    logger.info(f"Fetched {len(paginated)} student evaluations for page {page}")

    return jsonify({
        "evaluations": paginated,
        "totalCount": total_count,
        "totalPages": (total_count + per_page - 1) // per_page
    }), 200




@app.route("/api/admin/student_evaluations", methods=["POST"])
def create_student_evaluation():
    decoded, error_response = require_auth("admin")
    if error_response:
        return error_response
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    required_fields = ["tpAssignmentId", "traineeId", "supervisorId", "score"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing {field}"}), 400

    # Validate inputs
    users_data = users
    trainees = {t["id"] for t in users_data.get("teacherTrainee", [])}
    supervisors = {s["id"] for s in users_data.get("supervisor", [])}
    tp_assignments = {a["id"] for a in users_data.get("tp_assignments", [])}

    if data["traineeId"] not in trainees:
        return jsonify({"error": "Invalid traineeId"}), 400
    if data["supervisorId"] not in supervisors:
        return jsonify({"error": "Invalid supervisorId"}), 400
    if data["tpAssignmentId"] not in tp_assignments:
        return jsonify({"error": "Invalid tpAssignmentId"}), 400
    if not isinstance(data["score"], int) or data["score"] < 0 or data["score"] > 100:
        return jsonify({"error": "Score must be an integer between 0 and 100"}), 400
    if data.get("submittedAt") and not is_valid_date(data["submittedAt"]):
        return jsonify({"error": "Invalid submittedAt format, use YYYY-MM-DD"}), 400

    new_evaluation = {
        "id": generate_unique_id(),
        "tpAssignmentId": data["tpAssignmentId"],
        "traineeId": data["traineeId"],
        "supervisorId": data["supervisorId"],
        "score": data["score"],
        "comments": data.get("comments", ""),
        "submittedAt": data.get("submittedAt", "")
    }

    users_data["student_evaluations"].append(new_evaluation)
    save_users(users_data)
    logger.info(f"Created student evaluation {new_evaluation['id']}")
    return jsonify({"message": "Evaluation created", "id": new_evaluation["id"]}), 201

@app.route("/api/admin/student_evaluations/<id>", methods=["PUT"])
def update_student_evaluation(id):
    decoded, error_response = require_auth("admin")
    if error_response:
        return error_response
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    users_data = users
    evaluations = users_data.get("student_evaluations", [])
    evaluation = next((e for e in evaluations if e["id"] == id), None)
    if not evaluation:
        return jsonify({"error": "Evaluation not found"}), 404

    # Validate updates
    if "traineeId" in data and data["traineeId"] not in {t["id"] for t in users_data.get("teacherTrainee", [])}:
        return jsonify({"error": "Invalid traineeId"}), 400
    if "supervisorId" in data and data["supervisorId"] not in {s["id"] for s in users_data.get("supervisor", [])}:
        return jsonify({"error": "Invalid supervisorId"}), 400
    if "tpAssignmentId" in data and data["tpAssignmentId"] not in {a["id"] for a in users_data.get("tp_assignments", [])}:
        return jsonify({"error": "Invalid tpAssignmentId"}), 400
    if "score" in data and (not isinstance(data["score"], int) or data["score"] < 0 or data["score"] > 100):
        return jsonify({"error": "Score must be an integer between 0 and 100"}), 400
    if data.get("submittedAt") and not is_valid_date(data["submittedAt"]):
        return jsonify({"error": "Invalid submittedAt format, use YYYY-MM-DD"}), 400

    # Update fields
    evaluation.update({
        "tpAssignmentId": data.get("tpAssignmentId", evaluation["tpAssignmentId"]),
        "traineeId": data.get("traineeId", evaluation["traineeId"]),
        "supervisorId": data.get("supervisorId", evaluation["supervisorId"]),
        "score": data.get("score", evaluation["score"]),
        "comments": data.get("comments", evaluation["comments"]),
        "submittedAt": data.get("submittedAt", evaluation["submittedAt"])
    })

    save_users(users_data)
    logger.info(f"Updated student evaluation {id}")
    return jsonify({"message": "Evaluation updated"}), 200

@app.route("/api/admin/student_evaluations/<id>", methods=["DELETE"])
def delete_student_evaluation(id):
    decoded, error_response = require_auth("admin")
    if error_response:
        return error_response
    users_data = users
    evaluations = users_data.get("student_evaluations", [])
    evaluation = next((e for e in evaluations if e["id"] == id), None)
    if not evaluation:
        return jsonify({"error": "Evaluation not found"}), 404

    users_data["student_evaluations"] = [e for e in evaluations if e["id"] != id]
    save_users(users_data)
    logger.info(f"Deleted student evaluation {id}")
    return jsonify({"message": "Evaluation deleted"}), 200






@app.route("/api/supervisor/student_evaluations", methods=["GET"])
def supervisor_student_evaluations():
    decoded, error_response = require_auth("supervisor")
    if error_response:
        return error_response
    supervisor_id = decoded.get("id")  # Assume token includes supervisor ID
    data = users
    page = int(request.args.get("page", 1))
    search = request.args.get("search", "").lower()
    evaluations = [e for e in data.get("student_evaluations", []) if e["supervisorId"] == supervisor_id]
    trainees = {t["id"]: t for t in data.get("teacherTrainee", [])}

    enriched_evaluations = []
    for e in evaluations:
        evaluation = e.copy()
        if not is_valid_date(evaluation.get("submittedAt")):
            logger.warning(f"Invalid submittedAt in evaluation {e['id']}: {evaluation['submittedAt']}")
            evaluation["submittedAt"] = ""
        trainee = trainees.get(e.get("traineeId"))
        if trainee:
            evaluation["trainee"] = {
                "id": trainee["id"],
                "name": trainee.get("name", ""),
                "surname": trainee.get("surname", "")
            }
        enriched_evaluations.append(evaluation)

    if search:
        enriched_evaluations = [
            e for e in enriched_evaluations
            if e.get("trainee") and search in f"{e['trainee']['name']} {e['trainee']['surname']}".lower()
        ]

    total_count = len(enriched_evaluations)
    per_page = ITEMS_PER_PAGE
    start = (page - 1) * per_page
    end = start + per_page
    paginated = enriched_evaluations[start:end]
    logger.info(f"Supervisor {supervisor_id} fetched {len(paginated)} student evaluations for page {page}")

    return jsonify({
        "evaluations": paginated,
        "totalCount": total_count,
        "totalPages": (total_count + per_page - 1) // per_page
    }), 200

@app.route("/api/supervisor/student_evaluations", methods=["POST"])
def create_supervisor_student_evaluation():
    decoded, error_response = require_auth("supervisor")
    if error_response:
        return error_response
    supervisor_id = decoded.get("id")
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    required_fields = ["tpAssignmentId", "traineeId", "score"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing {field}"}), 400

    users_data = users
    trainees = {t["id"] for t in users_data.get("teacherTrainee", [])}
    tp_assignments = [a for a in users_data.get("tp_assignments", []) if a["supervisorId"] == supervisor_id]

    if data["traineeId"] not in trainees:
        return jsonify({"error": "Invalid traineeId"}), 400
    if data["tpAssignmentId"] not in {a["id"] for a in tp_assignments}:
        return jsonify({"error": "Invalid tpAssignmentId or not assigned to you"}), 400
    if not any(a["traineeId"] == data["traineeId"] and a["id"] == data["tpAssignmentId"] for a in tp_assignments):
        return jsonify({"error": "Trainee not assigned to this TP assignment"}), 400
    if not isinstance(data["score"], int) or data["score"] < 0 or data["score"] > 100:
        return jsonify({"error": "Score must be an integer between 0 and 100"}), 400
    if data.get("submittedAt") and not is_valid_date(data["submittedAt"]):
        return jsonify({"error": "Invalid submittedAt format, use YYYY-MM-DD"}), 400

    new_evaluation = {
        "id": generate_unique_id(),
        "tpAssignmentId": data["tpAssignmentId"],
        "traineeId": data["traineeId"],
        "supervisorId": supervisor_id,
        "score": data["score"],
        "comments": data.get("comments", ""),
        "submittedAt": data.get("submittedAt", datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    }

    users_data["student_evaluations"].append(new_evaluation)
    save_users(users_data)
    logger.info(f"Supervisor {supervisor_id} created student evaluation {new_evaluation['id']}")
    return jsonify({"message": "Evaluation created", "id": new_evaluation['id']}), 201

@app.route("/api/supervisor/student_evaluations/<id>", methods=["PUT"])
def update_supervisor_student_evaluation(id):
    decoded, error_response = require_auth("supervisor")
    if error_response:
        return error_response
    supervisor_id = decoded.get("id")
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    users_data = users
    evaluations = users_data.get("student_evaluations", [])
    evaluation = next((e for e in evaluations if e["id"] == id and e["supervisorId"] == supervisor_id), None)
    if not evaluation:
        return jsonify({"error": "Evaluation not found or not yours"}), 404

    trainees = {t["id"] for t in users_data.get("teacherTrainee", [])}
    tp_assignments = {a["id"] for a in users_data.get("tp_assignments", []) if a["supervisorId"] == supervisor_id}

    if "traineeId" in data and data["traineeId"] not in trainees:
        return jsonify({"error": "Invalid traineeId"}), 400
    if "tpAssignmentId" in data and data["tpAssignmentId"] not in tp_assignments:
        return jsonify({"error": "Invalid tpAssignmentId or not assigned to you"}), 400
    if "traineeId" in data and "tpAssignmentId" in data:
        if not any(a["traineeId"] == data["traineeId"] and a["id"] == data["tpAssignmentId"] 
                   for a in users_data.get("tp_assignments", []) if a["supervisorId"] == supervisor_id):
            return jsonify({"error": "Trainee not assigned to this TP assignment"}), 400
    if "score" in data and (not isinstance(data["score"], int) or data["score"] < 0 or data["score"] > 100):
        return jsonify({"error": "Score must be an integer between 0 and 100"}), 400
    if data.get("submittedAt") and not is_valid_date(data["submittedAt"]):
        return jsonify({"error": "Invalid submittedAt format, use YYYY-MM-DD"}), 400

    evaluation.update({
        "tpAssignmentId": data.get("tpAssignmentId", evaluation["tpAssignmentId"]),
        "traineeId": data.get("traineeId", evaluation["traineeId"]),
        "score": data.get("score", evaluation["score"]),
        "comments": data.get("comments", evaluation["comments"]),
        "submittedAt": data.get("submittedAt", evaluation["submittedAt"])
    })

    save_users(users_data)
    logger.info(f"Supervisor {supervisor_id} updated student evaluation {id}")
    return jsonify({"message": "Evaluation updated"}), 200

@app.route("/api/supervisor/student_evaluations/<id>", methods=["DELETE"])
def delete_supervisor_student_evaluation(id):
    decoded, error_response = require_auth("supervisor")
    if error_response:
        return error_response
    supervisor_id = decoded.get("id")
    users_data = users
    evaluations = users_data.get("student_evaluations", [])
    evaluation = next((e for e in evaluations if e["id"] == id and e["supervisorId"] == supervisor_id), None)
    if not evaluation:
        return jsonify({"error": "Evaluation not found or not yours"}), 404

    users_data["student_evaluations"] = [e for e in evaluations if e["id"] != id]
    save_users(users_data)
    logger.info(f"Supervisor {supervisor_id} deleted student evaluation {id}")
    return jsonify({"message": "Evaluation deleted"}), 200







@app.route("/api/admin/supervisor_evaluations", methods=["GET"])
def supervisor_evaluations():
    decoded, error_response = require_auth("admin")
    if error_response:
        return error_response
    data = users
    page = int(request.args.get("page", 1))
    search = request.args.get("search", "").lower()
    evaluations = data.get("supervisor_evaluations", [])
    supervisors = {s["id"]: s for s in data.get("supervisor", [])}

    enriched_evaluations = []
    for e in evaluations:
        evaluation = e.copy()
        if not is_valid_date(evaluation.get("timestamp")):
            logger.warning(f"Invalid timestamp in supervisor evaluation {e['id']}: {evaluation['timestamp']}")
            evaluation["timestamp"] = ""
        supervisor = supervisors.get(e.get("supervisorId"))
        if supervisor:
            evaluation["supervisor"] = {
                "id": supervisor["id"],
                "name": supervisor.get("name", ""),
                "surname": supervisor.get("surname", "")
            }
        enriched_evaluations.append(evaluation)

    if search:
        enriched_evaluations = [
            e for e in enriched_evaluations
            if e.get("supervisor") and search in f"{e['supervisor']['name']} {e['supervisor']['surname']}".lower()
        ]

    total_count = len(enriched_evaluations)
    per_page = ITEMS_PER_PAGE
    start = (page - 1) * per_page
    end = start + per_page
    paginated = enriched_evaluations[start:end]
    logger.info(f"Fetched {len(paginated)} supervisor evaluations for page {page}")

    return jsonify({
        "evaluations": paginated,
        "totalCount": total_count,
        "totalPages": (total_count + per_page - 1) // per_page
    }), 200

@app.route("/api/admin/supervisor_evaluations", methods=["POST"])
def create_supervisor_evaluation():
    decoded, error_response = require_auth("admin")
    if error_response:
        return error_response
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    required_fields = ["supervisorId", "rating"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing {field}"}), 400

    users_data = users
    supervisors = {s["id"] for s in users_data.get("supervisor", [])}

    if data["supervisorId"] not in supervisors:
        return jsonify({"error": "Invalid supervisorId"}), 400
    if not isinstance(data["rating"], int) or data["rating"] < 0 or data["rating"] > 10:
        return jsonify({"error": "Rating must be an integer between 0 and 10"}), 400
    if data.get("timestamp") and not is_valid_date(data["timestamp"]):
        return jsonify({"error": "Invalid timestamp format, use YYYY-MM-DD"}), 400

    new_evaluation = {
        "id": generate_unique_id(),
        "supervisorId": data["supervisorId"],
        "rating": data["rating"],
        "comments": data.get("comments", ""),
        "timestamp": data.get("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    }

    users_data["supervisor_evaluations"].append(new_evaluation)
    save_users(users_data)
    logger.info(f"Created supervisor evaluation {new_evaluation['id']}")
    return jsonify({"message": "Evaluation created", "id": new_evaluation['id']}), 201

@app.route("/api/admin/supervisor_evaluations/<id>", methods=["PUT"])
def update_supervisor_evaluation(id):
    decoded, error_response = require_auth("admin")
    if error_response:
        return error_response
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    users_data = users
    evaluations = users_data.get("supervisor_evaluations", [])
    evaluation = next((e for e in evaluations if e["id"] == id), None)
    if not evaluation:
        return jsonify({"error": "Evaluation not found"}), 404

    supervisors = {s["id"] for s in users_data.get("supervisor", [])}

    if "supervisorId" in data and data["supervisorId"] not in supervisors:
        return jsonify({"error": "Invalid supervisorId"}), 400
    if "rating" in data and (not isinstance(data["rating"], int) or data["rating"] < 0 or data["rating"] > 10):
        return jsonify({"error": "Rating must be an integer between 0 and 10"}), 400
    if data.get("timestamp") and not is_valid_date(data["timestamp"]):
        return jsonify({"error": "Invalid timestamp format, use YYYY-MM-DD"}), 400

    evaluation.update({
        "supervisorId": data.get("supervisorId", evaluation["supervisorId"]),
        "rating": data.get("rating", evaluation["rating"]),
        "comments": data.get("comments", evaluation["comments"]),
        "timestamp": data.get("timestamp", evaluation["timestamp"])
    })

    save_users(users_data)
    logger.info(f"Updated supervisor evaluation {id}")
    return jsonify({"message": "Evaluation updated"}), 200

@app.route("/api/admin/supervisor_evaluations/<id>", methods=["DELETE"])
def delete_supervisor_evaluation(id):
    decoded, error_response = require_auth("admin")
    if error_response:
        return error_response
    users_data = users
    evaluations = users_data.get("supervisor_evaluations", [])
    evaluation = next((e for e in evaluations if e["id"] == id), None)
    if not evaluation:
        return jsonify({"error": "Evaluation not found"}), 404

    users_data["supervisor_evaluations"] = [e for e in evaluations if e["id"] != id]
    save_users(users_data)
    logger.info(f"Deleted supervisor evaluation {id}")
    return jsonify({"message": "Evaluation deleted"}), 200








# app.py (partial, append to existing)
@app.route("/api/admin/assignments-by-school", methods=["GET"])
def assignments_by_school():
    decoded, error_response = require_auth("admin")
    if error_response:
        return error_response
    
    users_data = users
    assignments = users_data.get("tp_assignments", [])
    schools = {s["id"]: s["name"] for s in users_data.get("schools", [])}
    
    # Count assignments per school
    school_counts = {}
    for a in assignments:
        school_id = a.get("schoolId")
        if school_id in schools:
            school_name = schools[school_id]
            school_counts[school_name] = school_counts.get(school_name, 0) + 1
    
    # Format for chart
    result = [
        {"schoolName": name, "count": count}
        for name, count in school_counts.items()
    ]
    result.sort(key=lambda x: x["schoolName"])  # Consistent order
    
    logger.info(f"Fetched assignments by school: {len(result)} schools")
    return jsonify({"data": result}), 200













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













# Pydantic model for lesson plan validation
class LessonPlan(BaseModel):
    id: str
    traineeId: str
    supervisorId: str
    schoolId: str
    title: str
    subject: str
    date: str  # YYYY-MM-DD
    startTime: Optional[str] = None  # HH:MM:SS
    endTime: Optional[str] = None  # HH:MM:SS
    objectives: str
    activities: str
    resources: str
    createdAt: str  # ISO format
    status: str  # PENDING, APPROVED, REJECTED
    aiGenerated: bool = False
    traineeName: str
    supervisorName: str
    schoolName: str
    pdfUrl: Optional[str] = None

    class Config:
        extra = "allow"  # Allow extra fields





@app.route("/api/trainees/me", methods=["GET", "OPTIONS"])
# @_require_auth(["teacherTrainee"])
def get_trainee_profile():
    if request.method == "OPTIONS":
        logger.debug(f"Handling OPTIONS for /api/trainees/me, headers: {request.headers}")
        response = jsonify({"status": "ok"})
        return response, 200
    
    decoded, error_response = require_auth("teacherTrainee")
    if error_response:
        return jsonify(error_response), error_response["status"]
    
    try:
        # Load fresh users data
        users_data = load_users()
        if not users_data:
            logger.error("Failed to load users data")
            return jsonify({"error": "Internal server error: Users data unavailable"}), 500

        # Validate teacherTrainee list
        teacher_trainees = users_data.get("teacherTrainee", [])
        if not teacher_trainees:
            logger.error("No teacher trainees found in users data")
            return jsonify({"error": "Internal server error: No trainees available"}), 500

        # Optimize trainee lookup
        trainee_index = {t["regNo"]: t for t in teacher_trainees}
        trainee = trainee_index.get(decoded["identifier"])
        if not trainee:
            logger.warning(f"Trainee not found for identifier: {decoded['identifier']}")
            return jsonify({"error": "Trainee not found"}), 404
        
        logger.debug(f"Found trainee: {trainee['id']} for identifier: {decoded['identifier']}")

        # Enrich trainee data
        t_copy = trainee.copy()
        
        # Get TP assignment details with enhanced status logic
        assignment = get_trainee_assignment(t_copy["id"])
        if assignment:
            status = "Assigned"
            try:
                current_date = datetime.now(timezone.utc).date()
                start_date = None
                end_date = None
                if assignment["startDate"]:
                    try:
                        start_date = datetime.strptime(assignment["startDate"], "%Y-%m-%d").date()
                    except ValueError:
                        logger.warning(f"Invalid startDate format for trainee {trainee['id']}: {assignment['startDate']}")
                if assignment["endDate"]:
                    try:
                        end_date = datetime.strptime(assignment["endDate"], "%Y-%m-%d").date()
                    except ValueError:
                        logger.warning(f"Invalid endDate format for trainee {trainee['id']}: {assignment['endDate']}")
                
                if not assignment["supervisorId"] or assignment["supervisorName"] == "Not Assigned" or not assignment["placeOfTP"]:
                    status = "Not Assigned"
                elif start_date and end_date:
                    if current_date < start_date:
                        status = "Pending"
                    elif current_date > end_date:
                        status = "Completed"
            except Exception as e:
                logger.error(f"Error processing TP assignment dates for trainee {trainee['id']}: {str(e)}")
                status = "Not Assigned"
            
            t_copy["tpAssignment"] = {
                "supervisorName": assignment["supervisorName"],
                "placeOfTP": assignment["placeOfTP"],
                "startDate": assignment["startDate"],
                "endDate": assignment["endDate"],
                "status": status
            }
        else:
            t_copy["tpAssignment"] = {
                "supervisorName": "Not Assigned",
                "placeOfTP": "Not Assigned",
                "startDate": "",
                "endDate": "",
                "status": "Not Assigned"
            }
        logger.debug(f"TP assignment for trainee {trainee['id']}: {t_copy['tpAssignment']}")

        # Get lesson plans with relaxed validation
        lesson_plans = [
            lp for lp in users_data.get("lesson_plans", [])
            if lp.get("traineeId") == t_copy["id"]
        ]
        t_copy["lessonPlans"] = [
            {
                "id": lp.get("id", ""),
                "title": lp.get("title", "Untitled"),
                "subject": lp.get("subject", ""),
                "date": lp.get("date", ""),
                "startTime": lp.get("startTime", ""),
                "endTime": lp.get("endTime", ""),
                "status": lp.get("status", "PENDING"),
                "createdAt": lp.get("createdAt", ""),
                "objectives": lp.get("objectives", ""),
                "activities": lp.get("activities", ""),
                "resources": lp.get("resources", ""),
                "aiGenerated": lp.get("aiGenerated", False),
                "traineeName": lp.get("traineeName", ""),
                "supervisorName": lp.get("supervisorName", ""),
                "schoolName": lp.get("schoolName", ""),
                "pdfUrl": lp.get("pdfUrl", "")
            }
            for lp in lesson_plans
        ]
        logger.debug(f"Found {len(lesson_plans)} lesson plans for trainee {trainee['id']}")

        # Ensure all required fields with defaults
        safe_trainee = {
            "id": t_copy.get("id", ""),
            "regNo": t_copy.get("regNo", ""),
            "name": t_copy.get("name", ""),
            "surname": t_copy.get("surname", ""),
            "sex": t_copy.get("sex", ""),
            "birthday": t_copy.get("birthday", ""),
            "progress": str(t_copy.get("progress", "0")),  # Ensure string for frontend
            "email": t_copy.get("email", ""),
            "phone": t_copy.get("phone", ""),
            "address": t_copy.get("address", ""),
            "bloodType": t_copy.get("bloodType", ""),
            "birthday": t_copy.get("birthday", ""),
            "progress": t_copy.get("progress", ""),
            "img": t_copy.get("img", ""),
            "createdAt": t_copy.get("createdAt", ""),
            "tpAssignment": t_copy["tpAssignment"],
            "lessonPlans": t_copy["lessonPlans"]
        }
        
        logger.info(f"Fetched profile for trainee {decoded['identifier']}")
        response = jsonify(safe_trainee)
        return response, 200
    
    except Exception as e:
        logger.error(f"Error fetching trainee profile: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to fetch trainee profile", "details": str(e)}), 500


def normalize_time(time_str):
    """Normalize time to HH:mm:ss or return None if invalid."""
    if not time_str:
        return None
    try:
        if "T" in time_str:
            dt = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
            return dt.strftime("%H:%M:%S")
        parts = time_str.split(":")
        if len(parts) == 2:
            return f"{parts[0]}:{parts[1]}:00"
        if len(parts) == 3:
            return f"{parts[0]}:{parts[1]}:{parts[2]}"
        return None
    except (ValueError, TypeError):
        return None

def normalize_datetime(dt_str):
    """Normalize datetime to ISO format (e.g., 2025-04-23T00:26:06Z)."""
    if not dt_str:
        return datetime.now(timezone.utc).isoformat() + "Z"
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        return dt.isoformat() + "Z"
    except (ValueError, TypeError):
        return datetime.now(timezone.utc).isoformat() + "Z"









@app.route("/api/lesson-plans", methods=["POST"])
@_require_auth(["teacherTrainee"])
def create_lesson_plan(decoded):
    try:
        users_data = load_users()
        trainee = next((t for t in users_data.get("teacherTrainee", []) if t["regNo"] == decoded["identifier"]), None)
        if not trainee:
            logger.error(f"Trainee not found for regNo: {decoded['identifier']}")
            return jsonify({"error": "Trainee not found"}), 404

        # Check for existing pending lesson plans
        lesson_plans = users_data.get("lesson_plans", [])
        pending_plans = [lp for lp in lesson_plans if lp["traineeId"] == trainee["id"] and lp["status"] == "PENDING"]
        if pending_plans:
            logger.warning(f"Trainee {trainee['id']} already has a pending lesson plan: {pending_plans[0]['id']}")
            return jsonify({"error": "You already have a pending lesson plan. Please submit or delete it first."}), 400

        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body must be JSON"}), 400

        required_fields = ["title", "subject", "date", "objectives", "activities", "resources"]
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields: " + ", ".join(f for f in required_fields if f not in data)}), 400

        try:
            lesson_date = datetime.strptime(data["date"], "%Y-%m-%d")
        except ValueError:
            return jsonify({"error": "Invalid date format, expected YYYY-MM-DD"}), 400

        # Normalize times, make optional
        start_time = normalize_time(data.get("startTime")) if data.get("startTime") else None
        end_time = normalize_time(data.get("endTime")) if data.get("endTime") else None
        if start_time and end_time:
            start_parts = start_time.split(":")
            end_parts = end_time.split(":")
            start_dt = lesson_date.replace(hour=int(start_parts[0]), minute=int(start_parts[1]), second=0)
            end_dt = lesson_date.replace(hour=int(end_parts[0]), minute=int(end_parts[1]), second=0)
            if end_dt <= start_dt:
                return jsonify({"error": "End time must be after start time"}), 400

        assignment = get_trainee_assignment(trainee["id"])
        if not assignment:
            return jsonify({"error": "No TP assignment found for this trainee"}), 400

        sanitized_data = {
            "title": sanitize_html(data["title"]),
            "subject": sanitize_html(data["subject"]),
            "objectives": sanitize_html(data["objectives"]),
            "class": sanitize_html(data["class"]),
            "activities": sanitize_html(data["activities"]),
            "resources": sanitize_html(data["resources"])
        }

        new_lesson_plan = {
            "id": "lp" + str(uuid.uuid4()),
            "traineeId": str(trainee["id"]),
            "supervisorId": str(assignment["supervisorId"]),
            "schoolId": str(assignment["schoolId"]),
            "title": sanitized_data["title"],
            "subject": sanitized_data["subject"],
            "class": sanitized_data["class"],
            "date": data["date"],
            "startTime": start_time,
            "endTime": end_time,
            "objectives": sanitized_data["objectives"],
            "activities": sanitized_data["activities"],
            "resources": sanitized_data["resources"],
            "createdAt": datetime.now(timezone.utc).isoformat() + "Z",
            "status": "PENDING",
            "aiGenerated": bool(data.get("aiGenerated", False)),
            "traineeName": f"{trainee.get('name', '')} {trainee.get('surname', '')}".strip(),
            "supervisorName": assignment["supervisorName"],
            "schoolName": assignment["schoolName"],
            "pdfUrl": data.get('pdfUrl')
        }

        with lock:
            users_data["lesson_plans"] = lesson_plans + [new_lesson_plan]
            notifications = users_data.get("notifications", [])
            notification = {
                "id": f"notif-{uuid.uuid4()}",
                "user_id": assignment["supervisorId"],
                "initiator_id": trainee["id"],
                "type": "LESSON_PLAN",
                "priority": "MEDIUM",
                "message": f"New lesson plan submitted by {new_lesson_plan['traineeName']} for {new_lesson_plan['subject']} at {new_lesson_plan['schoolName']}.",
                "created_at": datetime.now(timezone.utc).isoformat() + "Z",
                "read_status": False
            }
            notifications.append(notification)
            users_data["notifications"] = notifications
            save_users(users_data)

        logger.info(f"Lesson plan created: {new_lesson_plan['id']} by trainee {trainee['id']}")
        response = jsonify({"message": "Lesson plan created", "lessonPlan": new_lesson_plan})
        response.headers["Access-Control-Allow-Origin"] = "http://localhost:3000"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response, 201
    except Exception as e:
        logger.error(f"Error creating lesson plan: {str(e)}", exc_info=True)
        return jsonify({"error": f"Error: {str(e)}"}), 500










# @app.route("/api/lesson-plans", methods=["POST"])
# @_require_auth(["teacherTrainee"])
# def create_lesson_plan(decoded):
    try:
        users_data = load_users()
        trainee = next((t for t in users_data.get("teacherTrainee", []) if t["regNo"] == decoded["identifier"]), None)
        if not trainee:
            logger.error(f"Trainee not found for identifier: {decoded['identifier']}")
            return jsonify({"error": "Trainee not found"}), 404

        # Check for existing pending lesson plans
        lesson_plans = users_data.get("lesson_plans", [])
        pending_plans = [lp for lp in lesson_plans if lp["traineeId"] == trainee["id"] and lp["status"] == "PENDING"]
        if pending_plans:
            logger.warning(f"Trainee {trainee['id']} already has a pending lesson plan: {pending_plans[0]['id']}")
            return jsonify({"error": "You already have a pending lesson plan. Please submit or delete it first."}), 400

        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body must be JSON"}), 400

        required_fields = ["title", "subject", "date", "objectives", "activities", "resources"]
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields: " + ", ".join(f for f in required_fields if f not in data)}), 400

        try:
            lesson_date = datetime.strptime(data["date"], "%Y-%m-%d")
        except ValueError:
            return jsonify({"error": "Invalid date format, expected YYYY-MM-DD"}), 400

        # Normalize times, make optional
        start_time = normalize_time(data.get("startTime")) if data.get("startTime") else None
        end_time = normalize_time(data.get("endTime")) if data.get("endTime") else None
        if start_time and end_time:
            start_parts = start_time.split(":")
            end_parts = end_time.split(":")
            start_dt = lesson_date.replace(hour=int(start_parts[0]), minute=int(start_parts[1]), second=0)
            end_dt = lesson_date.replace(hour=int(end_parts[0]), minute=int(end_parts[1]), second=0)
            if end_dt <= start_dt:
                return jsonify({"error": "End time must be after start time"}), 400

        # assignment = next((a for a in users_data.get("tp_assignments", []) if a["traineeId"] == trainee["id"]), None)
 
        assignment=get_trainee_assignment(trainee["id"])
 
        if not assignment:
            return jsonify({"error": "No TP assignment found for this trainee"}), 400

        sanitized_data = {
            "title": sanitize_html(data["title"]),
            "subject": sanitize_html(data["subject"]),
            "objectives": sanitize_html(data["objectives"]),
            "class":sanitize_html(data["class"]),
            "activities": sanitize_html(data["activities"]),
            "resources": sanitize_html(data["resources"])
        }

        new_lesson_plan = {
            "id": "lp"+ str(uuid.uuid4()),
            "traineeId": str(trainee["id"]),
            "supervisorId": str(assignment["supervisorId"]),
            "schoolId": str(assignment["schoolId"]),
            "title": sanitized_data["title"],
            "subject": sanitized_data["subject"],
            "class": sanitized_data["class"],
            "date": data["date"],
            "startTime": start_time,
            "endTime": end_time,
            "objectives": sanitized_data["objectives"],
            "activities": sanitized_data["activities"],
            "resources": sanitized_data["resources"],
            "createdAt": datetime.now(timezone.utc).isoformat() + "Z",
            "status": "PENDING",
            "aiGenerated": bool(data.get("aiGenerated", False)),
            "traineeName": f"{trainee.get('name', '')} {trainee.get('surname', '')}".strip(),
            "supervisorName": next((f"{s.get('name', '')} {s.get('surname', '')}".strip() for s in users_data.get("supervisor", []) if s["id"] == assignment["supervisorId"]), "Unknown"),
            "schoolName": next((s["name"] for s in users_data.get("schools", []) if s["id"] == assignment["schoolId"]), "Unknown"),
            "pdfUrl": data.get('pdfUrl')  # Store pdfUrl if provided
        }

        with lock:
            users_data["lesson_plans"] = lesson_plans + [new_lesson_plan]
            notifications = users_data.get("notifications", [])
            notification = {
                "id": f"notif-{uuid.uuid4()}",
                "user_id": assignment["supervisorId"],
                "initiator_id": trainee["regNo"],
                "type": "LESSON_PLAN",
                "priority": "MEDIUM",
                "message": f"New lesson plan submitted by {new_lesson_plan['traineeName']} for {new_lesson_plan['subject']} at {new_lesson_plan['schoolName']}.",
                "created_at": datetime.now(timezone.utc).isoformat() + "Z",
                "read_status": False
            }
            notifications.append(notification)
            users_data["notifications"] = notifications
            save_users(users_data)

        logger.info(f"Lesson plan created: {new_lesson_plan['id']} by trainee {trainee['regNo']}")
        response = jsonify({"message": "Lesson plan created", "lessonPlan": new_lesson_plan})
        response.headers["Access-Control-Allow-Origin"] = "http://localhost:3000"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response, 201
    except Exception as e:
        logger.error(f"Error creating lesson plan: {str(e)}", exc_info=True)
        return jsonify({"error": f"Error: {str(e)}"}), 500

@app.route("/api/lesson-plans/<id>", methods=["PUT"])
@_require_auth(["teacherTrainee"])
def update_lesson_plan(decoded, id: str):
    try:
        users_data = load_users()
        trainee = next((t for t in users_data.get("teacherTrainee", []) if t["regNo"] == decoded["identifier"]), None)
        if not trainee:
            logger.error(f"Trainee not found for identifier: {decoded['identifier']}")
            return jsonify({"error": "Trainee not found"}), 404

        lesson_plans = users_data.get("lesson_plans", [])
        lesson_plan = next((lp for lp in lesson_plans if lp["id"] == id and lp["traineeId"] == trainee["id"]), None)
        if not lesson_plan:
            logger.warning(f"Lesson plan {id} not found or not owned by trainee {trainee['id']}")
            return jsonify({"error": "Lesson plan not found or you lack permission"}), 404

        if lesson_plan["status"] not in ["PENDING", "REJECTED"]:
            logger.warning(f"Cannot update lesson plan {id}: status is {lesson_plan['status']}")
            return jsonify({"error": "Only pending or rejected lesson plans can be updated"}), 400

        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body must be JSON"}), 400

        required_fields = ["title", "subject", "date", "objectives", "activities", "resources"]
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields: " + ", ".join(f for f in required_fields if f not in data)}), 400

        try:
            lesson_date = datetime.strptime(data["date"], "%Y-%m-%d")
        except ValueError:
            return jsonify({"error": "Invalid date format, expected YYYY-MM-DD"}), 400

        start_time = normalize_time(data.get("startTime")) if data.get("startTime") else None
        end_time = normalize_time(data.get("endTime")) if data.get("endTime") else None
        if start_time and end_time:
            start_parts = start_time.split(":")
            end_parts = end_time.split(":")
            start_dt = lesson_date.replace(hour=int(start_parts[0]), minute=int(start_parts[1]), second=0)
            end_dt = lesson_date.replace(hour=int(end_parts[0]), minute=int(end_parts[1]), second=0)
            if end_dt <= start_dt:
                return jsonify({"error": "End time must be after start time"}), 400

        sanitized_data = {
            "title": sanitize_html(data["title"]),
            "subject": sanitize_html(data["subject"]),
            "objectives": sanitize_html(data["objectives"]),
            "class": sanitize_html(data["class"]),
            "activities": sanitize_html(data["activities"]),
            "resources": sanitize_html(data["resources"])
        }

        lesson_plan.update({
            "title": sanitized_data["title"],
            "subject": sanitized_data["subject"],
            "class": sanitized_data["class"],
            "date": data["date"],
            "startTime": start_time,
            "endTime": end_time,
            "objectives": sanitized_data["objectives"],
            "activities": sanitized_data["activities"],
            "resources": sanitized_data["resources"],
            "status": "PENDING",
            "aiGenerated": bool(data.get("aiGenerated", lesson_plan["aiGenerated"])),
            "pdfUrl": data.get('pdfUrl')
        })

        with lock:
            users_data["lesson_plans"] = [lp if lp["id"] != id else lesson_plan for lp in lesson_plans]
            notifications = users_data.get("notifications", [])
            notification = {
                "id": f"notif-{uuid.uuid4()}",
                "user_id": lesson_plan["supervisorId"],
                "initiator_id": trainee["id"],
                "type": "LESSON_PLAN_UPDATE",
                "priority": "MEDIUM",
                "message": f"Lesson plan updated by {lesson_plan['traineeName']} for {lesson_plan['subject']} at {lesson_plan['schoolName']}.",
                "created_at": datetime.now(timezone.utc).isoformat() + "Z",
                "read_status": False
            }
                  
            
            notifications.append(notification)
            users_data["notifications"] = notifications
            save_users(users_data)

        logger.info(f"Lesson plan updated: {id} by trainee {trainee['regNo']}")
        response = jsonify({"message": "Lesson plan updated", "lessonPlan": lesson_plan})
        response.headers["Access-Control-Allow-Origin"] = "http://localhost:3000"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response, 200
    except Exception as e:
        logger.error(f"Error updating lesson plan: {str(e)}", exc_info=True)
        return jsonify({"error": f"Error: {str(e)}"}), 500



@app.route("/api/lesson-plans/<id>", methods=["DELETE"])
@_require_auth(["teacherTrainee"])
def delete_lesson_plan(decoded, id: str):
    try:
        users_data = load_users()
        trainee = next((t for t in users_data.get("teacherTrainee", []) if t["regNo"] == decoded["identifier"]), None)
        if not trainee:
            logger.error(f"Trainee not found for identifier: {decoded['identifier']}")
            return jsonify({"error": "Trainee not found"}), 404

        lesson_plans = users_data.get("lesson_plans", [])
        lesson_plan = next((lp for lp in lesson_plans if lp["id"] == id and lp["traineeId"] == trainee["id"]), None)
        if not lesson_plan:
            logger.warning(f"Lesson plan {id} not found or not owned by trainee {trainee['id']}")
            return jsonify({"error": "Lesson plan not found or you lack permission"}), 404

        if lesson_plan["status"] not in ["PENDING", "REJECTED"]:
            logger.warning(f"Cannot delete lesson plan {id}: status is {lesson_plan['status']}")
            return jsonify({"error": "Only pending or rejected lesson plans can be deleted"}), 400

        with lock:
            users_data["lesson_plans"] = [lp for lp in lesson_plans if lp["id"] != id]
            notifications = users_data.get("notifications", [])
            notification = {
                "id": f"notif-{uuid.uuid4()}",
                "user_id": lesson_plan["supervisorId"],
                "initiator_id": trainee["regNo"],
                "type": "LESSON_PLAN_DELETE",
                "priority": "LOW",
                "message": f"Lesson plan deleted by {lesson_plan['traineeName']} for {lesson_plan['subject']} at {lesson_plan['schoolName']}.",
                "created_at": datetime.now(timezone.utc).isoformat() + "Z",
                "read_status": False
            }
            notifications.append(notification)
            users_data["notifications"] = notifications
            save_users(users_data)

        logger.info(f"Lesson plan deleted: {id} by trainee {trainee['regNo']}")
        response = jsonify({"message": "Lesson plan deleted"})
        response.headers["Access-Control-Allow-Origin"] = "http://localhost:3000"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response, 200
    except Exception as e:
        logger.error(f"Error deleting lesson plan: {str(e)}", exc_info=True)
        return jsonify({"error": f"Error: {str(e)}"}), 500






@app.route("/api/lesson-plans", methods=["GET"])
@_require_auth(["teacherTrainee", "supervisor", "admin"])
def get_lesson_plans(decoded):
    try:
        users_data = load_users()
        lesson_plans = users_data.get("lesson_plans", [])
        page = request.args.get("page", 1)
        limit = request.args.get("limit", 10)
        trainee_id = request.args.get("traineeId")
        supervisor_id = request.args.get("supervisorId")  # New parameter
        search = request.args.get("search", "").lower()
        subject = request.args.get("subject", "")
        status = request.args.get("status", "").upper()

        try:
            page = int(page)
            limit = int(limit)
            if page < 1 or limit < 1:
                raise ValueError
        except ValueError:
            logger.error(f"Invalid page ({page}) or limit ({limit})")
            return jsonify({"error": "Page and limit must be positive integers"}), 400

        valid_statuses = ["PENDING", "SUBMITTED", "APPROVED", "REJECTED"]
        status_list = status.split(",") if status else []
        if status_list and any(s not in valid_statuses for s in status_list):
            logger.error(f"Invalid status: {status}")
            return jsonify({"error": "Invalid status. Must be PENDING, SUBMITTED, APPROVED, or REJECTED"}), 400

        trainee_id_for_filter = None
        supervisor_id_for_filter = supervisor_id or (decoded["identifier"] if decoded["role"] == "supervisor" else None)
        if decoded["role"] == "teacherTrainee":
            trainee = next((t for t in users_data.get("teacherTrainee", []) if t["regNo"] == decoded["identifier"]), None)
            if not trainee:
                logger.error(f"Trainee not found for regNo: {decoded['identifier']}")
                return jsonify({"error": "Trainee not found"}), 404
            trainee_id_for_filter = str(trainee["id"])
        elif decoded["role"] in ["admin", "supervisor"] and trainee_id:
            trainee = next((t for t in users_data.get("teacherTrainee", []) if str(t["id"]) == trainee_id), None)
            if not trainee:
                logger.error(f"Invalid traineeId: {trainee_id}")
                return jsonify({"error": "Trainee not found for provided traineeId"}), 404
            trainee_id_for_filter = str(trainee_id)

        # Access control for supervisorId
        if supervisor_id and decoded["role"] == "supervisor" and supervisor_id != decoded["identifier"]:
            logger.warning(f"Unauthorized: Supervisor {decoded['identifier']} tried to access supervisorId {supervisor_id}")
            return jsonify({"error": "Unauthorized: You can only access your own lesson plans"}), 403

        logger.info(f"Fetching lesson plans for user: {decoded['identifier']}, role: {decoded['role']}, "
                    f"traineeId: {trainee_id or 'none'}, supervisorId: {supervisor_id or 'none'}, "
                    f"search: {search or 'none'}, subject: {subject or 'none'}, status: {status or 'none'}")

        filtered_plans = []
        for lp in lesson_plans:
            normalized_plan = {
                "id": str(lp.get("id", "")) or None,
                "traineeId": str(lp.get("traineeId", "")) or None,
                "supervisorId": str(lp.get("supervisorId", "")) or None,
                "schoolId": str(lp.get("schoolId", "")) or None,
                "title": str(lp.get("title", "")) or None,
                "subject": str(lp.get("subject", "")) or None,
                "class": str(lp.get("class", "")) or None,
                "date": str(lp.get("date", "")) or None,
                "startTime": normalize_time(lp.get("startTime")),
                "endTime": normalize_time(lp.get("endTime")),
                "objectives": str(lp.get("objectives", "")) or None,
                "activities": str(lp.get("activities", "")) or None,
                "resources": str(lp.get("resources", "")) or None,
                "createdAt": normalize_datetime(lp.get("createdAt")),
                "status": str(lp.get("status", "PENDING")).upper(),
                "aiGenerated": bool(lp.get("aiGenerated", False)),
                "traineeName": str(lp.get("traineeName", "")) or None,
                "supervisorName": str(lp.get("supervisorName", "")) or None,
                "schoolName": str(lp.get("schoolName", "")) or None,
                "pdfUrl": str(lp.get("pdfUrl", "")) if lp.get("pdfUrl") else None,
            }

            if decoded["role"] == "teacherTrainee":
                if normalized_plan["traineeId"] == trainee_id_for_filter:
                    filtered_plans.append(normalized_plan)
            elif decoded["role"] == "supervisor":
                if normalized_plan["supervisorId"] == supervisor_id_for_filter:
                    if not trainee_id_for_filter or normalized_plan["traineeId"] == trainee_id_for_filter:
                        filtered_plans.append(normalized_plan)
            elif decoded["role"] == "admin":
                if not supervisor_id_for_filter or normalized_plan["supervisorId"] == supervisor_id_for_filter:
                    if not trainee_id_for_filter or normalized_plan["traineeId"] == trainee_id_for_filter:
                        filtered_plans.append(normalized_plan)

        if search:
            filtered_plans = [
                lp for lp in filtered_plans
                if lp.get("title") and search in lp.get("title", "").lower() or 
                   lp.get("subject") and search in lp.get("subject", "").lower()
            ]
        if subject:
            filtered_plans = [lp for lp in filtered_plans if lp.get("subject") == subject]
        if status_list:
            filtered_plans = [lp for lp in filtered_plans if lp.get("status") in status_list]

        total = len(filtered_plans)
        total_pages = max(1, (total + limit - 1) // limit)
        start = (page - 1) * limit
        end = start + limit
        paginated_plans = filtered_plans[start:end]

        logger.info(f"Returning {len(paginated_plans)} lesson plans, total: {total}, pages: {total_pages}")

        response = jsonify({
            "lessonPlans": paginated_plans,
            "totalCount": total,
            "totalPages": total_pages
        })
        response.headers["Access-Control-Allow-Origin"] = "http://localhost:3000"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response, 200
    except Exception as e:
        logger.error(f"Error fetching lesson plans: {str(e)}", exc_info=True)
        return jsonify({"error": f"Error: {str(e)}"}), 500


@app.route("/api/trainees/<trainee_id>/lesson-plans", methods=["GET", "OPTIONS"])
@_require_auth(["teacherTrainee"])
def get_trainee_lesson_plans(decoded,trainee_id):
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    # # Authenticate the user
    # decoded, error_response = require_auth()
    # if error_response:
    #     logger.debug(f"Auth failed for trainee ID {trainee_id}: {error_response.get_json()['error']}")
    #     return error_response

    # Validate trainee exists
    trainee = next((t for t in users.get("teacherTrainee", []) if t["id"] == trainee_id), None)
    if not trainee:
        logger.debug(f"Trainee ID {trainee_id} not found")
        return jsonify({"error": "Trainee not found"}), 404

    # Access control: Admins, supervisors, or the trainee themselves
    if decoded["role"] not in ["admin", "supervisor", "teacherTrainee"]:
        logger.debug(f"Unauthorized role {decoded['role']} for trainee ID {trainee_id}")
        return jsonify({"error": "Unauthorized"}), 403
    if decoded["role"] == "teacherTrainee" and decoded["identifier"] != trainee["regNo"]:
        logger.debug(f"Trainee {decoded['identifier']} attempted to access trainee ID {trainee_id}")
        return jsonify({"error": "Unauthorized: You can only view your own lesson plans"}), 403

    # If the user is a supervisor, ensure they are assigned to this trainee
    if decoded["role"] == "supervisor":
        assignment = next((a for a in users.get("tp_assignments", []) if a["traineeId"] == trainee_id), None)
        if not assignment or assignment["supervisorId"] != decoded["identifier"]:
            logger.debug(f"Supervisor {decoded['identifier']} not assigned to trainee ID {trainee_id}")
            return jsonify({"error": "Unauthorized: You can only view lesson plans of your assigned trainees"}), 403

    try:
        # Get lesson plans for this trainee
        lesson_plans = users.get("lesson_plans", [])
        trainee_lesson_plans = [
            lp for lp in lesson_plans
            if isinstance(lp, dict) and lp.get("traineeId") == trainee_id
        ]

        logger.debug(f"Returning {len(trainee_lesson_plans)} lesson plans for trainee ID {trainee_id}")
        return jsonify({"data": trainee_lesson_plans}), 200
    except Exception as e:
        logger.error(f"Error in GET /api/trainees/{trainee_id}/lesson-plans: {str(e)}")
        return jsonify({"error": "Failed to fetch lesson plans", "details": str(e)}), 500



@app.route("/api/trainees/<id>", methods=["GET",])
# @_require_auth(["teacherTrainee","admin"])
def get_trainee_profiles(id):
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    
    decoded, error_response = require_auth(["teacherTrainee","admin"])
    if error_response:
        return jsonify(error_response), error_response["status"]
    
    try:
        
        users_data = load_users()
        if not users_data:
            logger.error("Failed to load users data")
            response = jsonify({"error": "Internal server error: Users data unavailable"})
            response.headers["Access-Control-Allow-Origin"] = "http://localhost:3000"
            response.headers["Access-Control-Allow-Credentials"] = "true"
            return response, 500

        teacher_trainees = users_data.get("teacherTrainee", [])
        if not teacher_trainees:
            logger.error("No teacher trainees found in users data")
            response = jsonify({"error": "Internal server error: No trainees available"})
            response.headers["Access-Control-Allow-Origin"] = "http://localhost:3000"
            response.headers["Access-Control-Allow-Credentials"] = "true"
            return response, 500

        trainee = next((t for t in teacher_trainees if t["id"] == id or t["regNo"] == id), None)
        if not trainee:
            logger.warning(f"Trainee not found for id/regNo: {id}")
            response = jsonify({"error": f"Trainee not found: {id}"})
            response.headers["Access-Control-Allow-Origin"] = "http://localhost:3000"
            response.headers["Access-Control-Allow-Credentials"] = "true"
            return response, 404

        if decoded["role"] == "teacherTrainee" and trainee["regNo"] != decoded["identifier"]:
            logger.warning(f"Unauthorized access attempt: {decoded['identifier']} tried to access trainee {id}")
            response = jsonify({"error": "Unauthorized: You can only access your own profile"})
            response.headers["Access-Control-Allow-Origin"] = "http://localhost:3000"
            response.headers["Access-Control-Allow-Credentials"] = "true"
            return response, 403
        
        logger.debug(f"Found trainee: {trainee['id']} for id/regNo: {id}")     

        # Enrich trainee data
        t_copy = trainee.copy()
        
        # Get TP assignment details with enhanced status logic
        assignment = get_trainee_assignment(t_copy["id"])
        print(assignment)
        if assignment:
            status = "Assigned"
            try:
                current_date = datetime.now(timezone.utc).date()
                start_date = None
                end_date = None
                if assignment["startDate"]:
                    try:
                        start_date = datetime.strptime(assignment["startDate"], "%Y-%m-%d").date()
                    except ValueError:
                        logger.warning(f"Invalid startDate format for trainee {trainee['id']}: {assignment['startDate']}")
                if assignment["endDate"]:
                    try:
                        end_date = datetime.strptime(assignment["endDate"], "%Y-%m-%d").date()
                    except ValueError:
                        logger.warning(f"Invalid endDate format for trainee {trainee['id']}: {assignment['endDate']}")
                
                if not assignment["supervisorId"] or assignment["supervisorName"] == "Not Assigned" or not assignment["placeOfTP"]:
                    status = "Not Assigned"
                elif start_date and end_date:
                    if current_date < start_date:
                        status = "Pending"
                    elif current_date > end_date:
                        status = "Completed"
            except Exception as e:
                logger.error(f"Error processing TP assignment dates for trainee {trainee['id']}: {str(e)}")
                status = "Not Assigned"
            
            t_copy["tpAssignment"] = {
                "supervisorName": assignment["supervisorName"],
                "placeOfTP": assignment["placeOfTP"],
                "startDate": assignment["startDate"],
                "endDate": assignment["endDate"],
                "status": status
            }
        else:
            t_copy["tpAssignment"] = {
                "supervisorName": "Not Assigned",
                "placeOfTP": "Not Assigned",
                "startDate": "",
                "endDate": "",
                "status": "Not Assigned"
            }
        logger.debug(f"TP assignment for trainee {trainee['id']}: {t_copy['tpAssignment']}")

        # Get lesson plans with relaxed validation
        lesson_plans = [
            lp for lp in users_data.get("lesson_plans", [])
            if lp.get("traineeId") == t_copy["id"]
        ]
        t_copy["lessonPlans"] = [
            {
                "id": lp.get("id", ""),
                "title": lp.get("title", "Untitled"),
                "subject": lp.get("subject", ""),
                "date": lp.get("date", ""),
                "startTime": lp.get("startTime", ""),
                "endTime": lp.get("endTime", ""),
                "status": lp.get("status", "PENDING"),
                "createdAt": lp.get("createdAt", ""),
                "objectives": lp.get("objectives", ""),
                "activities": lp.get("activities", ""),
                "resources": lp.get("resources", ""),
                "aiGenerated": lp.get("aiGenerated", False),
                "traineeName": lp.get("traineeName", ""),
                "supervisorName": lp.get("supervisorName", ""),
                "schoolName": lp.get("schoolName", ""),
                "pdfUrl": lp.get("pdfUrl", "")
            }
            for lp in lesson_plans
        ]
        logger.debug(f"Found {len(lesson_plans)} lesson plans for trainee {trainee['id']}")
   
   
        # Ensure all required fields with defaults
        safe_trainee = {
            "id": t_copy.get("id", ""),
            "regNo": t_copy.get("regNo", ""),
            "name": t_copy.get("name", ""),
            "surname": t_copy.get("surname", ""),
            "email": t_copy.get("email", ""),
            "bloodType":t_copy.get("bloodType", ""),
            "sex": t_copy.get("sex", ""),
            "phone": t_copy.get("phone", ""),
            "birthday": t_copy.get("birthday", ""),
            "progress": str(t_copy.get("progress", "0")),  # Ensure string for frontend
            "img": t_copy.get("img", ""),
            "createdAt": t_copy.get("createdAt", ""),
            "tpAssignment": t_copy["tpAssignment"],
            "lessonPlans": t_copy["lessonPlans"]
        }
        
        logger.info(f"Fetched profile for trainee {decoded['identifier']}")
        response = jsonify(safe_trainee)
        response.headers["Access-Control-Allow-Origin"] = "http://localhost:3000"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response, 200
    
    except Exception as e:
        logger.error(f"Error fetching trainee profile: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to fetch trainee profile", "details": str(e)}), 500


@app.route("/api/supervisors/<supervisor_id>/lesson-plans", methods=["GET", "OPTIONS"])
def get_supervisor_lesson_plans(supervisor_id):
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    decoded, error_response = require_auth()
    if error_response:
        logger.debug(f"Auth failed for supervisor ID {supervisor_id}: {error_response.get_json()['error']}")
        return error_response
    
    # Validate supervisor exists
    supervisor = next((s for s in users.get("supervisor", []) if s["id"] == supervisor_id), None)
    if not supervisor:
        logger.debug(f"Supervisor ID {supervisor_id} not found")
        return jsonify({"error": "Supervisor not found"}), 404
    
    # Access control: Admins or the supervisor themselves
    if decoded["role"] not in ["admin", "supervisor"]:
        logger.debug(f"Unauthorized role {decoded['role']} for supervisor ID {supervisor_id}")
        return jsonify({"error": "Unauthorized"}), 403
    if decoded["role"] == "supervisor" and decoded["identifier"] != supervisor["staffId"]:
        logger.debug(f"Supervisor {decoded['identifier']} attempted to access supervisor ID {supervisor_id}")
        return jsonify({"error": "Unauthorized: You can only view your own lesson plans"}), 403
    
    try:
        # Get lesson plans for this supervisor
        lesson_plans = users.get("lesson_plans", [])
        supervisor_lesson_plans = [
            lp for lp in lesson_plans
            if isinstance(lp, dict) and lp.get("supervisorId") == supervisor_id
        ]
        
        # Filter by status if provided
        status = request.args.get("status")
        if status:
            supervisor_lesson_plans = [
                lp for lp in supervisor_lesson_plans
                if lp.get("status") == status.upper()
            ]
        
        logger.debug(f"Returning {len(supervisor_lesson_plans)} lesson plans for supervisor ID {supervisor_id}")
        return jsonify({"lessonPlans": supervisor_lesson_plans}), 200
    except Exception as e:
        logger.error(f"Error in GET /api/supervisors/{supervisor_id}/lesson-plans: {str(e)}")
        return jsonify({"error": "Failed to fetch lesson plans", "details": str(e)}), 500



# @a






@app.route("/api/getsupervisors/<id>", methods=["GET", "OPTIONS"])
def get_supervisor_profile(id):
    if request.method == "OPTIONS":
        logger.debug(f"Handling OPTIONS for /api/getsupervisors/{id}, headers: {request.headers}")
        response = jsonify({"status": "ok"})
        return response, 200
    
    decoded, error_response = require_auth(["supervisor", "admin"])
    if error_response:
        return jsonify(error_response), error_response["status"]
    
    try:
        users_data = load_users()
        supervisor_id = get_user_id(id, users_data)
        # Validate supervisor exists
        supervisor = next((s for s in users_data.get("supervisor", []) if s["id"] == supervisor_id), None)
        if not supervisor:
            logger.warning(f"Supervisor not found for id/staffId: {id}")
            return jsonify({"error": f"Supervisor not found: {id}"}), 404
        
        # Access control
        if decoded["role"] == "supervisor" and decoded["identifier"] != supervisor["staffId"]:
            logger.warning(f"Unauthorized access attempt: {decoded['identifier']} tried to access supervisor {id}")
            return jsonify({"error": "Unauthorized: You can only access your own profile"}), 403
        
        # Enrich supervisor data
        s_copy = supervisor.copy()
        
        # Get assigned trainees
        assignments = users_data.get("tp_assignments", [])
        trainee_ids = [a["traineeId"] for a in assignments if a["supervisorId"] == supervisor["id"]]
        trainees = [
            {
                "id": t["id"],
                "name": t["name"],
                "surname": t["surname"],
                "regNo": t["regNo"],
                "email": t["email"],
                "phone": t.get("phone", ""),
                "address": t["address"],
                "bloodType": t["bloodType"],
                "sex": t["sex"],
                "birthday": t["birthday"],
                "progress": t.get("progress",""),
                "img": t.get("img", ""),
            }
            for t in users_data.get("teacherTrainee", [])
            if t["id"] in trainee_ids
        ]
        s_copy["assignedTrainees"] = trainees
        
        # Get lesson plans, sorted by createdAt descending
        lesson_plans = sorted(
            [
                lp for lp in users_data.get("lesson_plans", [])
                if lp.get("supervisorId") == supervisor["id"]
            ],
            key=lambda lp: lp.get("createdAt", datetime.now().isoformat()),
            reverse=True
        )
        s_copy["lessonPlans"] = [
            {
                "id": lp.get("id", ""),
                "traineeId": lp.get("traineeId", ""),
                "supervisorId": lp.get("supervisorId", ""),
                "title": lp.get("title", "Untitled"),
                "subject": lp.get("subject", "Unknown"),
                "class": lp.get("class", "Unknown"),
                "date": lp.get("date", datetime.now().strftime("%Y-%m-%d")),
                "startTime": normalize_time(lp.get("startTime", None)),
                "endTime": normalize_time(lp.get("endTime", None)),
                "objectives": lp.get("objectives", ""),
                "activities": lp.get("activities", ""),
                "resources": lp.get("resources", ""),
                "createdAt": normalize_datetime(lp.get("createdAt", datetime.now().isoformat())),
                "status": lp.get("status", "PENDING"),
                "aiGenerated": lp.get("aiGenerated", False),
                "traineeName": next(
                    (t["name"] + " " + t["surname"] for t in users_data.get("teacherTrainee", []) if t["id"] == lp.get("traineeId")),
                    lp.get("traineeId", "Unknown Trainee")
                ),
                "supervisorName": f"{supervisor['name']} {supervisor['surname']}",
                "schoolName": next(
                    (s["name"] for s in users_data.get("schools", []) if s["id"] == lp.get("schoolId")),
                    "Not Assigned"
                ),
                "pdfUrl": lp.get("pdfUrl", None)
            }
            for lp in lesson_plans
        ]
        
        # Validate lesson plan data
        valid_trainees = {t["id"] for t in users_data.get("teacherTrainee", [])}
        valid_schools = {s["id"] for s in users_data.get("schools", [])}
        for lp in s_copy["lessonPlans"]:
            if lp["traineeId"] not in valid_trainees:
                logger.warning(f"Lesson plan {lp['id']} has invalid traineeId: {lp['traineeId']}")
            if lp.get("schoolId") and lp["schoolId"] not in valid_schools:
                logger.warning(f"Lesson plan {lp['id']} has invalid schoolId: {lp['schoolId']}")
            
            # Log missing fields
            missing_fields = []
            required_fields = ["supervisorName", "schoolName", "class", "traineeName", "objectives", "activities", "resources"]
            for field in required_fields:
                if not lp.get(field) or lp.get(field) in ["Unknown", "Unknown Trainee", "Not Assigned"]:
                    missing_fields.append(field)
            if missing_fields:
                logger.warning(f"Lesson plan ID {lp['id']} missing fields: {missing_fields}, LessonPlan: {lp}")
        
        # Get observation schedules and backfill missing fields
        schedules = [
            s for s in users_data.get("supervisor_schedule", [])
            if s["supervisorId"] == supervisor["id"]
        ]
        updated_schedules = False
        for s in schedules:
            # Backfill lessonPlanTitle
            if not s.get("lessonPlanTitle"):
                s["lessonPlanTitle"] = next(
                    (lp["title"] for lp in lesson_plans if lp["id"] == s.get("lesson_plan_id")),
                    "Unknown Lesson Plan"
                )
                updated_schedules = True
                logger.info(f"Backfilled lessonPlanTitle for schedule {s['id']}: {s['lessonPlanTitle']}")
            
            # Backfill traineeName
            if not s.get("traineeName"):
                s["traineeName"] = next(
                    (t["name"] + " " + t["surname"] for t in users_data.get("teacherTrainee", []) if t["id"] == s.get("traineeId")),
                    "Unknown Trainee"
                )
                updated_schedules = True
                logger.info(f"Backfilled traineeName for schedule {s['id']}: {s['traineeName']}")
        
        # Save updated schedules to users.json
        if updated_schedules:
            try:
                with lock:
                    users_data["supervisor_schedule"] = [
                        s if s["supervisorId"] != supervisor["id"] else next(
                            (us for us in schedules if us["id"] == s["id"]), s
                        ) for s in users_data.get("supervisor_schedule", [])
                    ]
                    save_users(users_data)
                    logger.info(f"Saved updated schedules for supervisor {supervisor_id}")
            except Exception as e:
                logger.error(f"Failed to save updated schedules: {str(e)}")
        
        s_copy["schedules"] = [
            {
                "id": s.get("id", ""),
                "lesson_plan_id": s.get("lesson_plan_id", ""),
                "traineeId": s.get("traineeId", ""),
                "date": s.get("date", ""),
                "start_time": normalize_time(s.get("start_time", "")),
                "end_time": normalize_time(s.get("end_time", "")),
                "status": s.get("status", "SCHEDULED"),
                "created_at": normalize_datetime(s.get("created_at", "")),
                "lessonPlanTitle": s.get("lessonPlanTitle", "Unknown Lesson Plan"),
                "traineeName": s.get("traineeName", "Unknown Trainee")
            }
            for s in schedules
        ]
        
        # Ensure all required fields with defaults
        safe_supervisor = {
            "id": s_copy.get("id", ""),
            "staffId": s_copy.get("staffId", ""),
            "name": s_copy.get("name", ""),
            "surname": s_copy.get("surname", ""),
            "email": s_copy.get("email", ""),
            "phone": s_copy.get("phone", ""),       
            "address": s_copy.get("address", ""),
            "bloodType": s_copy.get("bloodType", ""),
            "birthday": s_copy.get("birthday",""),
            "placeOfSupervision": s_copy.get("placeOfSupervision",""),
            "img": s_copy.get("img",""),
            "createdAt": normalize_datetime(s_copy.get("createdAt", "")),
            "assignedTrainees": s_copy["assignedTrainees"],
            "lessonPlans": s_copy["lessonPlans"],
            "schedules": s_copy["schedules"]
    


        }
        
        logger.info(f"Fetched profile for supervisor {decoded['identifier']}")
        response = jsonify(safe_supervisor)
        response.headers["Access-Control-Allow-Origin"] = "http://localhost:3000"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response, 200
    
    except Exception as e:
        logger.error(f"Error fetching supervisor profile: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to fetch supervisor profile", "details": str(e)}), 500


@app.route("/api/supervisors/<supervisor_id>/lesson-plans/<lesson_plan_id>/review", methods=["PUT", "OPTIONS"])
def review_lesson_plan(supervisor_id, lesson_plan_id):
    if request.method == "OPTIONS":
        logger.debug("Handling OPTIONS for /api/supervisors/<supervisor_id>/lesson-plans/<lesson_plan_id>/review")
        response = jsonify({"status": "ok"})
        return response, 200

    logger.info(f"Received review request for supervisor {supervisor_id}, lesson plan {lesson_plan_id}")
    # Authentication
    decoded, error_response = require_auth(["supervisor"])
    if error_response:
        logger.warning(f"Authentication failed: {error_response}")
        return jsonify(error_response), error_response["status"]

    # Resolve supervisor ID
    users_data =load_users()
    supervisor_id = get_user_id(decoded["identifier"], users_data)
    logger.debug(f"Resolved supervisor_id: {supervisor_id}")
    # Validate supervisor
    supervisor = next((s for s in users_data.get("supervisor", []) if s["id"] == supervisor_id), None)
    if not supervisor:
        logger.error(f"Supervisor not found: {supervisor_id}")
        return jsonify({"error": "Supervisor not found"}), 404

    if decoded["identifier"] != supervisor["staffId"]:
        logger.error(f"Unauthorized: Token identifier {decoded['identifier']} does not match supervisor staffId {supervisor['staffId']}")
        return jsonify({"error": "Unauthorized: You can only review lesson plans assigned to you"}), 403

    # Validate lesson plan
    lesson_plans = users_data.get("lesson_plans", [])
    lesson_plan = next((lp for lp in lesson_plans if lp["id"] == lesson_plan_id and lp["supervisorId"] == supervisor_id), None)
    if not lesson_plan:
        logger.error(f"Lesson plan not found or not assigned: {lesson_plan_id} for supervisor {supervisor_id}")
        return jsonify({"error": "Lesson plan not found or not assigned to you"}), 404

    # Validate request data
    data = request.get_json() or {}
    logger.debug(f"Request data: {data}")
    required_fields = ["status", "comments"]
    if not all(field in data for field in required_fields):
        logger.error(f"Missing required fields: {required_fields}")
        return jsonify({"error": "Missing required fields: status, comments"}), 400
    if data["status"] not in ["APPROVED", "REJECTED"]:
        logger.error(f"Invalid status: {data['status']}")
        return jsonify({"error": "Status must be APPROVED or REJECTED"}), 400
    score = data.get("score")
    if score is not None:
        try:
            score = int(score)
            if not 0 <= score <= 10:
                logger.error(f"Invalid score: {score}")
                return jsonify({"error": "Score must be between 0 and 10"}), 400
        except (ValueError, TypeError):
            logger.error(f"Invalid score type: {score}")
            return jsonify({"error": "Score must be an integer"}), 400

    try:
        with lock:
            # Update lesson plan
            lesson_plan["status"] = data["status"]
            lesson_plan["updatedAt"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            lesson_plan["reviewComments"] = data["comments"]
            lesson_plan["reviewScore"] = score

            # Add feedback to observation_feedback
            feedback_id = f"ofb{len(users_data.get('observation_feedback', [])) + 1}"
            feedback = {
                "id": feedback_id,
                "lesson_plan_id": lesson_plan_id,
                "traineeId": lesson_plan["traineeId"],
                "supervisorId": supervisor_id,
                "score": score,
                "comments": data["comments"],
                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%d")
            }
            users_data.setdefault("observation_feedback", []).append(feedback)

            # Create observation schedule if approved
            schedule = None
            if data["status"] == "APPROVED":
                if not lesson_plan.get("date") or not lesson_plan.get("startTime") or not lesson_plan.get("endTime"):
                    logger.warning(f"Cannot schedule observation for {lesson_plan_id}: missing date or time")
                    return jsonify({"error": "Lesson plan missing date or time information"}), 400

                try:
                    # Validate date and times
                    observation_date = parse(lesson_plan["date"]).strftime("%Y-%m-%d")
                    start_time = lesson_plan["startTime"]
                    end_time = lesson_plan["endTime"]
                    start_parts = start_time.split(":")
                    end_parts = end_time.split(":")
                    if len(start_parts) < 2 or len(end_parts) < 2:
                        raise ValueError("Invalid time format")
                    start_hour, start_min = map(int, start_parts[:2])
                    end_hour, end_min = map(int, end_parts[:2])
                    if end_hour < start_hour or (end_hour == start_hour and end_min <= start_min):
                        raise ValueError("End time must be after start time")

                    # Create schedule
                    schedule_id = f"sch{generate_unique_id()}"
                    schedule = {
                        "id": schedule_id,
                        "supervisorId": supervisor_id,
                        "traineeId": lesson_plan["traineeId"],
                        "lesson_plan_id": lesson_plan_id,
                        "date": observation_date,
                        "start_time": start_time,
                        "end_time": end_time,
                        "status": "SCHEDULED",
                        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                        "lessonPlanTitle": lesson_plan["title"],
                        "traineeName": lesson_plan["traineeName"]
                    }
                    users_data.setdefault("supervisor_schedule", []).append(schedule)
                    logger.info(f"Observation schedule created: {schedule_id} for lesson plan {lesson_plan_id}")
                except ValueError as e:
                    logger.error(f"Invalid date/time for scheduling: {str(e)}")
                    return jsonify({"error": f"Invalid date or time: {str(e)}"}), 400

            # Notify trainee
            notifications = users_data.get("notifications", [])
            notification = {
                "id": f"notif-{generate_unique_id()}",
                "user_id": lesson_plan["traineeId"],
                "initiator_id": supervisor["staffId"],
                "event_id": lesson_plan_id,
                "type": "LESSON_PLAN",
                "priority": "HIGH",
                "message": f"Your lesson plan '{lesson_plan['title']}' has been {data['status'].lower()} by {lesson_plan['supervisorName']}. Comments: {data['comments']}",
                "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "read_status": False
            }
            notifications.append(notification)
            users_data["notifications"] = notifications

            # Save changes
            users_data["lesson_plans"] = [lp if lp["id"] != lesson_plan_id else lesson_plan for lp in lesson_plans]
            save_users(users_data)

        logger.info(f"Lesson plan {lesson_plan_id} reviewed by supervisor {supervisor_id} with status {data['status']}")
        return jsonify({
            "message": "Lesson plan reviewed successfully",
            "lessonPlan": lesson_plan,
            "feedback": feedback,
            "schedule": schedule
        }), 200
    except Exception as e:
        logger.error(f"Error reviewing lesson plan {lesson_plan_id}: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to review lesson plan", "details": str(e)}), 500






# Supervisor Schedule Observation Endpoint
@app.route("/api/supervisors/<supervisor_id>/schedule-observation", methods=["POST"])
def schedule_observation(supervisor_id):
    decoded, error_response = require_auth("supervisor")
    if error_response:
        return jsonify(error_response), error_response["status"]
    
    # Validate supervisor
    users_data =load_users()
    supervisor = next((s for s in users_data.get("supervisor", []) if s["id"] == supervisor_id), None)
    if not supervisor:
        return jsonify({"error": "Supervisor not found"}), 404
    if decoded["identifier"] != supervisor["staffId"]:
        return jsonify({"error": "Unauthorized: You can only schedule observations for yourself"}), 403
    
    # Validate request data
    data = request.get_json() or {}
    required_fields = ["lesson_plan_id", "trainee_id", "date", "start_time", "end_time"]
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields: lesson_plan_id, trainee_id, date, start_time, end_time"}), 400
    
    # Validate lesson plan
    lesson_plan = next((lp for lp in users_data.get("lesson_plans", []) if lp["id"] == data["lesson_plan_id"] and lp["supervisorId"] == supervisor_id), None)
    if not lesson_plan:
        return jsonify({"error": "Lesson plan not found or not assigned to you"}), 404
    if lesson_plan["status"] != "APPROVED":
        return jsonify({"error": "Only approved lesson plans can be scheduled for observation"}), 400
    
    # Validate trainee
    trainee = next((t for t in users_data.get("teacherTrainee", []) if t["id"] == data["trainee_id"]), None)
    if not trainee:
        return jsonify({"error": "Trainee not found"}), 404
    
    # Validate dates and times
    try:
        observation_date = datetime.strptime(data["date"], "%Y-%m-%d")
        start_time = normalize_time(data["start_time"])
        end_time = normalize_time(data["end_time"])
        if not start_time or not end_time:
            return jsonify({"error": "Invalid time format. Use HH:MM or HH:MM:SS"}), 400
        start_dt = observation_date.replace(
            hour=int(start_time.split(":")[0]),
            minute=int(start_time.split(":")[1]),
            second=0
        )
        end_dt = observation_date.replace(
            hour=int(end_time.split(":")[0]),
            minute=int(end_time.split(":")[1]),
            second=0
        )
        if end_dt <= start_dt:
            return jsonify({"error": "End time must be after start time"}), 400
    except ValueError:
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400
    
    try:
        with lock:
            # Create schedule
            schedule_id = f"sch{len(users_data.get('supervisor_schedule', [])) + 1}"
            schedule = {
                "id": schedule_id,
                "supervisorId": supervisor_id,
                "traineeId": data["trainee_id"],
                "lesson_plan_id": data["lesson_plan_id"],
                "date": data["date"],
                "start_time": start_time,
                "end_time": end_time,
                "status": "SCHEDULED",
                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%d")
            }
            users_data.setdefault("supervisor_schedule", []).append(schedule)
            
            # Notify trainee
            notifications = users_data.get("notifications", [])
            notification = {
                "id": f"notif-{generate_unique_id()}",
                "user_id": data["trainee_id"],
                "initiator_id": supervisor["staffId"],
                "event_id": schedule_id,
                "type": "SCHEDULE",
                "priority": "MEDIUM",
                "message": f"Observation scheduled for lesson plan '{lesson_plan['title']}' on {data['date']} from {start_time} to {end_time}.",
                "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "read_status": False
            }
            notifications.append(notification)
            users_data["notifications"] = notifications
            
            # Save changes
            save_users(users_data)
        
        logger.info(f"Observation scheduled for lesson plan {data['lesson_plan_id']} by supervisor {supervisor_id}")
        return jsonify({
            "message": "Observation scheduled successfully",
            "schedule": schedule
        }), 201
    except Exception as e:
        logger.error(f"Error scheduling observation: {str(e)}")
        return jsonify({"error": "Failed to schedule observation", "details": str(e)}), 500


@app.route("/api/supervisors/<supervisor_id>/observations/<observation_id>/feedback", methods=["POST"])
def submit_observation_feedback(supervisor_id, observation_id):
    decoded, error_response = require_auth("supervisor")
    if error_response:
        return jsonify(error_response), error_response["status"]
    
    # Load user data
    users_data = load_users()
    
    # Log debugging information
    logger.info(f"Decoded identifier: {decoded['identifier']}")
    logger.info(f"Supervisor data: {users_data.get('supervisor', [])}")
    
    # Validate supervisor
    internal_supervisor_id = get_user_id(decoded['identifier'], users_data)
    supervisor = next((s for s in users_data.get("supervisor", []) if s["staffId"] == decoded["identifier"]), None)
    logger.info(f"Found supervisor: {supervisor}")
    if not supervisor:
        return jsonify({"error": "Supervisor not found"}), 404
    if decoded["identifier"] != supervisor["staffId"]:
        return jsonify({"error": "Unauthorized: You can only submit feedback for your observations"}), 403
    
    # Validate observation
    logger.info(f"Supervisor schedule: {users_data.get('supervisor_schedule', [])}")
    observation = next((o for o in users_data.get("supervisor_schedule", []) if o["id"] == observation_id and o["supervisorId"] == supervisor["id"]), None)
    logger.info(f"Found observation: {observation}")
    if not observation:
        return jsonify({"error": "Observation not found or not assigned to you"}), 404
    if observation["status"] != "COMPLETED":
        return jsonify({"error": "Feedback can only be submitted for completed observations"}), 400
    
    # Validate request data
    data = request.get_json() or {}
    required_fields = ["score", "comments"]
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields: score, comments"}), 400
    try:
        score = int(data["score"])
        if not 0 <= score <= 10:
            return jsonify({"error": "Score must be between 0 and 10"}), 400
    except (ValueError, TypeError):
        return jsonify({"error": "Score must be an integer"}), 400
    
    try:
        with lock:
            # Add to observation_feedback
            feedback_id = f"ofb{len(users_data.get('observation_feedback', [])) + 1}"
            feedback = {
                "id": feedback_id,
                "lesson_plan_id": observation["lesson_plan_id"],
                "traineeId": observation["traineeId"],
                "supervisorId": supervisor["id"],
                "score": score,
                "comments": data["comments"],
                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%d")
            }
            users_data.setdefault("observation_feedback", []).append(feedback)
            
            # Notify trainee
            notifications = users_data.get("notifications", [])
            lesson_plan = next((lp for lp in users_data.get("lesson_plans", []) if lp["id"] == observation["lesson_plan_id"]), None)
            lesson_title = lesson_plan["title"] if lesson_plan else "Lesson"
            notification = {
                "id": f"notif-{generate_unique_id()}",
                "user_id": observation["traineeId"],
                "initiator_id": supervisor["id"],
                "event_id": observation_id,
                "type": "OBSERVATION_FEEDBACK",
                "priority": "HIGH",
                "message": f"Feedback submitted for observation of '{lesson_title}': Score {score}/10. Comments: {data['comments']}",
                "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "read_status": False
            }
            notifications.append(notification)
            users_data["notifications"] = notifications
            
            # Save changes
            save_users(users_data)
        
        logger.info(f"Feedback submitted for observation {observation_id} by supervisor {supervisor['staffId']}")
        return jsonify({
            "message": "Feedback submitted successfully",
            "feedback": feedback
        }), 200
    except Exception as e:
        logger.error(f"Error submitting observation feedback: {str(e)}")
        return jsonify({"error": "Failed to submit feedback", "details": str(e)}), 500



# Supervisor Get Assigned Trainees Endpoint
@app.route("/api/supervisors/<supervisor_id>/trainees", methods=["GET", "OPTIONS"])
def get_supervisor_trainees(supervisor_id):
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    decoded, error_response = require_auth("supervisor")
    if error_response:
        return jsonify(error_response), error_response["status"]
    
    # Validate supervisor
    supervisor = next((s for s in users.get("supervisor", []) if s["staffId"] == supervisor_id), None)
    if not supervisor:
        return jsonify({"error": "Supervisor not found"}), 404
    if decoded["identifier"] != supervisor["staffId"]:
        return jsonify({"error": "Unauthorized: You can only view your own trainees"}), 403
    
    try:
        # Get assigned trainees
        assignments = users.get("tp_assignments", [])
        trainee_ids = [a["traineeId"] for a in assignments if a["supervisorId"] == supervisor_id]
        trainees = [
            {k: v for k, v in t.items() if k != "password"}
            for t in users.get("teacherTrainee", [])
            if t["id"] in trainee_ids
        ]
        
        # Enrich trainee data with lesson plan and observation counts
        for trainee in trainees:
            lesson_plans = [lp for lp in users.get("lesson_plans", []) if lp["traineeId"] == trainee["id"]]
            observations = [o for o in users.get("observations", []) if o["traineeId"] == trainee["id"]]
            trainee["lessonPlanCount"] = len(lesson_plans)
            trainee["observationCount"] = len(observations)
            trainee["averageScore"] = sum(o.get("score", 0) for o in observations) / len(observations) if observations else 0
        
        # Pagination
        page = int(request.args.get("page", 1))
        per_page = ITEMS_PER_PAGE
        total = len(trainees)
        total_pages = max(1, (total + per_page - 1) // per_page)
        start = (page - 1) * per_page
        end = start + per_page
        paginated_trainees = trainees[start:end]
        
        logger.info(f"Fetched {len(paginated_trainees)} trainees for supervisor {supervisor_id}")
        return jsonify({
            "trainees": paginated_trainees,
            "totalCount": total,
            "totalPages": total_pages,
            "currentPage": page
        }), 200
    except Exception as e:
        logger.error(f"Error fetching trainees for supervisor {supervisor_id}: {str(e)}")
        return jsonify({"error": "Failed to fetch trainees", "details": str(e)}), 500

# # Supervisor Get Observation Schedules Endpoint
# @app.route("/api/supervisors/<supervisor_id>/schedules", methods=["GET", "OPTIONS"])
# def get_supervisor_schedules(supervisor_id):
#     if request.method == "OPTIONS":
#         return jsonify({"status": "ok"}), 200
    
#     decoded, error_response = require_auth(["supervisor"])
#     if error_response:
#         return jsonify(error_response), error_response["status"]
    
#     # Validate supervisor
#     supervisor = next((s for s in users.get("supervisor", []) if s["staffId"] == supervisor_id), None)
#     if not supervisor:
#         return jsonify({"error": "Supervisor not found"}), 404
#     if decoded["identifier"] != supervisor["staffId"]:
#         return jsonify({"error": "Unauthorized: You can only view your own schedules"}), 403
    
#     try:
#         # Get schedules
#         schedules = [
#             s for s in users.get("supervisor_schedule", [])
#             if s["supervisorId"] == supervisor_id
#         ]
        
#         # Enrich schedules with lesson plan and trainee details
#         lesson_plans = {lp["id"]: lp for lp in users.get("lesson_plans", [])}
#         trainees = {t["id"]: t for t in users.get("teacherTrainee", [])}
#         enriched_schedules = []
#         for schedule in schedules:
#             s_copy = schedule.copy()
#             lesson_plan = lesson_plans.get(schedule["lesson_plan_id"])
#             trainee = trainees.get(schedule["traineeId"])
#             s_copy["lessonPlanTitle"] = lesson_plan["title"] if lesson_plan else "Unknown"
#             s_copy["traineeName"] = f"{trainee['name']} {trainee['surname']}" if trainee else "Unknown"
#             enriched_schedules.append(s_copy)
        
#         # Filter by status if provided
#         status = request.args.get("status")
#         if status:
#             enriched_schedules = [s for s in enriched_schedules if s["status"] == status.upper()]
        
#         # Pagination
#         page = int(request.args.get("page", 1))
#         per_page = ITEMS_PER_PAGE
#         total = len(enriched_schedules)
#         total_pages = max(1, (total + per_page - 1) // per_page)
#         start = (page - 1) * per_page
#         end = start + per_page
#         paginated_schedules = enriched_schedules[start:end]
        
#         logger.info(f"Fetched {len(paginated_schedules)} schedules for supervisor {supervisor_id}")
#         return jsonify({
#             "schedules": paginated_schedules,
#             "totalCount": total,
#             "totalPages": total_pages,
#             "currentPage": page
#         }), 200
#     except Exception as e:
#         logger.error(f"Error fetching schedules for supervisor {supervisor_id}: {str(e)}")
#         return jsonify({"error": "Failed to fetch schedules", "details": str(e)}), 500





@app.route("/api/supervisors/<supervisor_id>/schedules", methods=["GET", "OPTIONS"])
def get_supervisor_schedules(supervisor_id):
    if request.method == "OPTIONS":
        logger.debug("Handling OPTIONS for /api/supervisors/<supervisor_id>/schedules")
        response = jsonify({"status": "ok"})
        return response, 200

    decoded, error_response = require_auth(["supervisor"])
    if error_response:
        logger.warning(f"Authentication failed: {error_response}")
        return jsonify(error_response), error_response["status"]

    supervisor_id = get_user_id(decoded["identifier"], users)
    logger.debug(f"Resolved supervisor_id: {supervisor_id}")
    supervisor = next((s for s in users.get("supervisor", []) if s["id"] == supervisor_id), None)
    if not supervisor:
        logger.error(f"Supervisor not found: {supervisor_id}")
        return jsonify({"error": "Supervisor not found"}), 404

    if decoded["identifier"] != supervisor["staffId"]:
        logger.error(f"Unauthorized: Token identifier {decoded['identifier']} does not match supervisor staffId {supervisor['staffId']}")
        return jsonify({"error": "Unauthorized: You can only view your schedules"}), 403

    try:
        page = int(request.args.get("page", 1))
        limit = int(request.args.get("limit", 10))
        start = (page - 1) * limit
        end = start + limit

        schedules = sorted(
            [s for s in users.get("supervisor_schedule", []) if s["supervisorId"] == supervisor_id],
            key=lambda s: s.get("created_at", datetime.now(timezone.utc).strftime("%Y-%m-%d")),
            reverse=True
        )
        total_count = len(schedules)
        total_pages = max(1, (total_count + limit - 1) // limit)
        paginated_schedules = schedules[start:end]

        response_data = {
            "schedules": [
                {
                    "id": s["id"],
                    "supervisorId": s["supervisorId"],
                    "traineeId": s["traineeId"],
                    "lesson_plan_id": s["lesson_plan_id"],
                    "date": s["date"],
                    "start_time": s["start_time"],
                    "end_time": s["end_time"],
                    "status": s["status"],
                    "created_at": s["created_at"],
                    "lessonPlanTitle": s["lessonPlanTitle"],
                    "traineeName": s["traineeName"],
                }
                for s in paginated_schedules
            ],
            "totalCount": total_count,
            "totalPages": total_pages,
            "currentPage": page,
        }

        logger.info(f"Fetched schedules for supervisor {supervisor_id}: {total_count} schedules")
        response = jsonify(response_data)
        response.headers["Access-Control-Allow-Origin"] = "http://localhost:3000"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response, 200

    except Exception as e:
        logger.error(f"Error fetching schedules: {str(e)}", exc_info=True)
        return jsonify({"error": f"Error: {str(e)}"}), 500
















@app.route("/api/supervisors/<supervisor_id>/observation-feedback", methods=["GET"])
def get_observation_feedback(supervisor_id):
    decoded, error_response = require_auth("supervisor")
    if error_response:
        return jsonify(error_response), error_response["status"]
    
    # Validate supervisor
    supervisor = next((s for s in users.get("supervisor", []) if s["staffId"] == supervisor_id), None)
    if not supervisor:
        return jsonify({"error": "Supervisor not found"}), 404
    if decoded["identifier"] != supervisor["staffId"]:
        return jsonify({"error": "Unauthorized: You can only view your own feedback"}), 403
    
    try:
        # Get feedback for supervisor's lesson plans
        feedback_list = [
            fb for fb in users.get("observation_feedback", [])
            if fb["supervisorId"] == supervisor_id
        ]
        
        # Pagination
        page = int(request.args.get("page", 1))
        per_page = ITEMS_PER_PAGE
        total = len(feedback_list)
        total_pages = max(1, (total + per_page - 1) // per_page)
        start = (page - 1) * per_page
        end = start + per_page
        paginated_feedback = feedback_list[start:end]
        
        logger.info(f"Fetched {len(paginated_feedback)} feedback items for supervisor {supervisor_id}")
        return jsonify({
            "feedback": paginated_feedback,
            "totalCount": total,
            "totalPages": total_pages,
            "currentPage": page
        }), 200
    except Exception as e:
        logger.error(f"Error fetching feedback for supervisor {supervisor_id}: {str(e)}")
        return jsonify({"error": "Failed to fetch feedback", "details": str(e)}), 500














@app.route("/api/feedback", methods=["GET", "OPTIONS"])
def get_feedback():
    # Handle CORS preflight request
    if request.method == "OPTIONS":
        response = jsonify({"status": "ok"})
        return response, 200

    # Authenticate user
    decoded, error_response = require_auth(["supervisor", "teacherTrainee"])
    if error_response:
        logger.warning(f"Authentication failed: {error_response.get_json()['error']}")
        return error_response

    # Get query parameters
    user_id = request.args.get("userId")
    role = request.args.get("role", "")  # Preserve camelCase
    page = int(request.args.get("page", 1))
    search = request.args.get("search", "").lower()
    lesson_plan_id = request.args.get("lessonPlanId")

    # Validate inputs
    valid_roles = ["supervisor", "teacherTrainee"]
    if not user_id:
        logger.error("Invalid request: userId is missing")
        return jsonify({"error": "Missing user ID"}), 400
    if not role or role not in valid_roles:
        logger.error(f"Invalid request: role={role}, expected one of {valid_roles}")
        return jsonify({"error": f"Invalid role: {role}. Expected one of {valid_roles}"}), 400

    # Resolve internal user ID
    internal_user_id = get_user_id(user_id, users)
    if not internal_user_id:
        logger.error(f"User not found for identifier: {user_id} ({role})")
        return jsonify({"error": "User not found"}), 404

    # Verify token matches user
    if decoded["identifier"] != user_id:
        logger.warning(f"Unauthorized: Token identifier {decoded['identifier']} does not match {user_id}")
        return jsonify({"error": "Unauthorized: You can only view your own feedback"}), 403

    try:
        # Get feedback
        feedback_list = users.get("observation_feedback", [])
        filtered_feedback = []

        for feedback in feedback_list:
            # Filter by role
            if role == "supervisor" and feedback["supervisorId"] != internal_user_id:
                continue
            if role == "teacherTrainee" and feedback["traineeId"] != internal_user_id:
                continue
            # Filter by lesson plan ID if provided
            if lesson_plan_id and feedback.get("lesson_plan_id") != lesson_plan_id:
                continue

            # Enrich feedback
            enriched = feedback.copy()
            lesson_plan = next(
                (lp for lp in users.get("lesson_plans", []) if lp["id"] == feedback.get("lesson_plan_id")),
                None
            )
            trainee = next(
                (t for t in users.get("teacherTrainee", []) if t["id"] == feedback["traineeId"]),
                None
            )
            supervisor = next(
                (s for s in users.get("supervisor", []) if s["id"] == feedback["supervisorId"]),
                None
            )
            enriched["lessonPlanTitle"] = lesson_plan["title"] if lesson_plan else "N/A"
            enriched["traineeName"] = f"{trainee['name']} {trainee['surname']}" if trainee else "N/A"
            enriched["supervisorName"] = f"{supervisor['name']} {supervisor['surname']}" if supervisor else "N/A"

            # Search filter
            if search:
                search_fields = [
                    enriched["lessonPlanTitle"].lower(),
                    enriched["traineeName"].lower(),
                    enriched["supervisorName"].lower(),
                    feedback["comments"].lower(),
                ]
                if not any(search in field for field in search_fields):
                    continue

            filtered_feedback.append(enriched)

        # Pagination
        total = len(filtered_feedback)
        total_pages = max(1, (total + ITEMS_PER_PAGE - 1) // ITEMS_PER_PAGE)
        start = (page - 1) * ITEMS_PER_PAGE
        end = start + ITEMS_PER_PAGE
        paginated_feedback = filtered_feedback[start:end]

        logger.info(f"Fetched {len(paginated_feedback)} feedback items for {role} {user_id}")
        return jsonify({
            "feedback": paginated_feedback,
            "totalCount": total,
            "totalPages": total_pages,
            "currentPage": page
        }), 200
    except Exception as e:
        logger.error(f"Error fetching feedback for {role} {user_id}: {str(e)}")
        return jsonify({"error": "Failed to fetch feedback", "details": str(e)}), 500












# Existing endpoints (only including the new endpoint for brevity)
@app.route("/api/supervisors/<supervisor_id>/observations/<observation_id>/status", methods=["PUT", "OPTIONS"])
def update_observation_status(supervisor_id, observation_id):
    if request.method == "OPTIONS":
        logger.debug(f"Handling OPTIONS for /api/supervisors/{supervisor_id}/observations/{observation_id}/status")
        response = jsonify({"status": "ok"})
        return response, 200

    logger.info(f"Received status update request for supervisor {supervisor_id}, observation {observation_id}")
    
    # Authentication
    decoded, error_response = require_auth(["supervisor"])
    if error_response:
        logger.warning(f"Authentication failed: {error_response}")
        return jsonify(error_response), error_response["status"]

    # Resolve supervisor ID
    users_data = load_users()
    resolved_supervisor_id = get_user_id(decoded["identifier"], users_data)
    logger.debug(f"Resolved supervisor_id: {resolved_supervisor_id}")

    # Validate supervisor
    supervisor = next((s for s in users_data.get("supervisor", []) if s["id"] == resolved_supervisor_id), None)
    if not supervisor:
        logger.error(f"Supervisor not found: {resolved_supervisor_id}")
        return jsonify({"error": "Supervisor not found"}), 404

    if decoded["identifier"] != supervisor["staffId"]:
        logger.error(f"Unauthorized: Token identifier {decoded['identifier']} does not match supervisor staffId {supervisor['staffId']}")
        return jsonify({"error": "Unauthorized: You can only update your own observations"}), 403

    # Validate observation
    schedule = next(
        (s for s in users_data.get("supervisor_schedule", []) if s["id"] == observation_id and s["supervisorId"] == resolved_supervisor_id),
        None
    )
    if not schedule:
        logger.error(f"Observation not found or not assigned: {observation_id} for supervisor {resolved_supervisor_id}")
        return jsonify({"error": "Observation not found or not assigned to you"}), 404

    # Validate request data
    data = request.get_json() or {}
    logger.debug(f"Request data: {data}")
    required_fields = ["status"]
    if not all(field in data for field in required_fields):
        logger.error(f"Missing required fields: {required_fields}")
        return jsonify({"error": "Missing required field: status"}), 400

    if data["status"] not in ["ONGOING", "COMPLETED"]:
        logger.error(f"Invalid status: {data['status']}")
        return jsonify({"error": "Status must be ONGOING or COMPLETED"}), 400

    # Validate status transition
    current_status = schedule["status"]
    if current_status == "COMPLETED":
        logger.error(f"Cannot update status: Observation {observation_id} is already COMPLETED")
        return jsonify({"error": "Observation is already completed"}), 400
    if data["status"] == "ONGOING" and current_status != "SCHEDULED":
        logger.error(f"Invalid transition: Cannot change status from {current_status} to ONGOING")
        return jsonify({"error": "Observation must be SCHEDULED to mark as ONGOING"}), 400
    if data["status"] == "COMPLETED" and current_status != "ONGOING":
        logger.error(f"Invalid transition: Cannot change status from {current_status} to COMPLETED")
        return jsonify({"error": "Observation must be ONGOING to mark as COMPLETED"}), 400

    try:
        with lock:
            # Update schedule
            schedule["status"] = data["status"]
            schedule["updated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

            # Notify trainee
            lesson_plan = next(
                (lp for lp in users_data.get("lesson_plans", []) if lp["id"] == schedule["lesson_plan_id"]),
                None
            )
            lesson_plan_title = lesson_plan["title"] if lesson_plan else "Unknown Lesson Plan"
            notifications = users_data.get("notifications", [])
            notification = {
                "id": f"notif-{generate_unique_id()}",
                "user_id": schedule["traineeId"],
                "initiator_id": supervisor["staffId"],
                "event_id": observation_id,
                "type": "OBSERVATION_STATUS",
                "priority": "MEDIUM",
                "message": f"Observation for '{lesson_plan_title}' has been marked as {data['status'].lower()}.",
                "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "read_status": False,
            }
            notifications.append(notification)
            users_data["notifications"] = notifications

            # Save changes
            users_data["supervisor_schedule"] = [
                s if s["id"] != observation_id else schedule for s in users_data.get("supervisor_schedule", [])
            ]
            save_users(users_data)

        # Prepare response
        response_schedule = {
            "id": schedule["id"],
            "supervisorId": schedule["supervisorId"],
            "traineeId": schedule["traineeId"],
            "lesson_plan_id": schedule["lesson_plan_id"],
            "date": schedule["date"],
            "start_time": normalize_time(schedule["start_time"]),
            "end_time": normalize_time(schedule["end_time"]),
            "status": schedule["status"],
            "created_at": normalize_datetime(schedule["created_at"]),
            "lessonPlanTitle": schedule.get("lessonPlanTitle", lesson_plan_title),
            "traineeName": schedule.get("traineeName", "Unknown Trainee"),
        }

        logger.info(f"Observation {observation_id} status updated to {data['status']} by supervisor {resolved_supervisor_id}")
        response = jsonify({
            "message": "Observation status updated successfully",
            "schedule": response_schedule,
        })
        response.headers["Access-Control-Allow-Origin"] = "http://localhost:3000"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response, 200

    except Exception as e:
        logger.error(f"Error updating observation status {observation_id}: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to update observation status", "details": str(e)}), 500


















def normalize_time(time_str):
    return time_str if time_str else None

def normalize_datetime(dt_str):
    return dt_str if dt_str else datetime.now().isoformat()








DIFY_API_KEY = os.getenv("DIFY_API_KEY")
DIFY_API_URL = "https://api.dify.ai/v1/chat-messages"

@app.route("/api/ai-lesson-plan", methods=["POST"])
def generate_ai_lesson_plan():
    try:
        data = request.get_json()
        query = data.get("query")
        user_id = data.get("user_id", "abc-123")
        conversation_id = data.get("conversation_id", "")
        if not query:
            return jsonify({"error": "Query is required"}), 400
        headers = {
            "Authorization": f"Bearer {DIFY_API_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "inputs": {},
            "query": query,
            "inputs": {},  # Add custom variables if needed (from Dify Prompt Arrangement)
            "response_mode": "blocking",
            "user": user_id,
            "conversation_id": conversation_id
        }
        response = requests.post(DIFY_API_URL, json=payload, headers=headers)
        response.raise_for_status()
        return jsonify(response.json())
    except requests.RequestException as e:
        return jsonify({"error": f"API request failed: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500



# PDF generation
def save_pdf(data, lesson_plan_id):
    output_dir = "static/pdfs"
    os.makedirs(output_dir, exist_ok=True)
    pdf_path = os.path.join(output_dir, f"{lesson_plan_id}.pdf")

    try:
        # Create PDF with ReportLab
        doc = SimpleDocTemplate(pdf_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Add title
        title = h.handle(data.get('title', 'Lesson Plan')).strip()
        story.append(Paragraph(title, styles['Title']))
        story.append(Spacer(1, 12))

        # Add metadata
        metadata = [
            f"Subject: {data.get('subject', 'N/A')}",
            f"Class: {data.get('class', 'N/A')}",
            f"Date: {data.get('date', 'N/A')}",
            f"Time: {data.get('startTime', 'N/A')} - {data.get('endTime', 'N/A')}",
            f"School: {data.get('schoolName', 'N/A')}",
            f"Trainee: {data.get('traineeName', 'N/A')}",
            f"Supervisor: {data.get('supervisorName', 'N/A')}"
        ]
        for line in metadata:
            story.append(Paragraph(line, styles['Normal']))
            story.append(Spacer(1, 6))

        # Add sections
        sections = [
            ('Objectives', data.get('objectives', '')),
            ('Activities', data.get('activities', '')),
            ('Resources', data.get('resources', ''))
        ]
        for title, content in sections:
            story.append(Paragraph(title, styles['Heading2']))
            plain_text = h.handle(content).strip()
            story.append(Paragraph(plain_text, styles['Normal']))
            story.append(Spacer(1, 12))

        # Build PDF
        doc.build(story)
        return f"/{pdf_path}"
    except Exception as e:
        raise Exception(f"PDF generation failed: {str(e)}")

@app.route('/api/lesson-plans/generate-pdf', methods=['POST'])
@_require_auth(["teacherTrainee"])
def generate_pdf(decoded):
    try:
        users_data = load_users()
        trainee = next((t for t in users_data.get("teacherTrainee", []) if t["regNo"] == decoded["identifier"]), None)
        if not trainee:
            logger.error(f"Trainee not found for identifier: {decoded['identifier']}")
            return jsonify({"error": "Trainee not found"}), 404

        data = request.get_json()
        lesson_plan_id = data.get('lesson_plan_id')
        if not lesson_plan_id or not data:
            logger.error("Missing lesson_plan_id or content")
            return jsonify({"error": "Lesson plan ID and content are required"}), 400

        lesson_plans = users_data.get("lesson_plans", [])
        lesson_plan = next((lp for lp in lesson_plans if lp["id"] == lesson_plan_id and lp["traineeId"] == trainee["id"]), None)
        if not lesson_plan:
            logger.warning(f"Lesson plan {lesson_plan_id} not found or not owned by trainee {trainee['id']}")
            return jsonify({"error": "Lesson plan not found or you lack permission"}), 404

        # Validate required fields
        required_fields = ["title", "subject", "class", "date", "objectives", "activities", "resources"]
        if not all(field in data for field in required_fields):
            logger.error(f"Missing required fields: {', '.join(f for f in required_fields if f not in data)}")
            return jsonify({"error": f"Missing required fields: {', '.join(f for f in required_fields if f not in data)}"}), 400

        # Sanitize and normalize input
        sanitized_data = {
            "title": sanitize_html(data["title"]),
            "subject": sanitize_html(data["subject"]),
            "class": sanitize_html(data["class"]),
            "date": data["date"],
            "startTime": normalize_time(data.get("startTime")),
            "endTime": normalize_time(data.get("endTime")),
            "objectives": sanitize_html(data["objectives"]),
            "activities": sanitize_html(data["activities"]),
            "resources": sanitize_html(data["resources"]),
            "schoolName": lesson_plan.get("schoolName", "N/A"),
            "traineeName": lesson_plan.get("traineeName", "N/A"),
            "supervisorName": lesson_plan.get("supervisorName", "N/A")
        }

        # Generate PDF
        pdf_url = save_pdf(sanitized_data, lesson_plan_id)

        # Update lesson plan with pdfUrl
        with lock:
            lesson_plan["pdfUrl"] = pdf_url
            users_data["lesson_plans"] = [lp if lp["id"] != lesson_plan_id else lesson_plan for lp in lesson_plans]
            save_users(users_data)

        logger.info(f"PDF generated for lesson plan {lesson_plan_id} by trainee {trainee['regNo']}")
        response = jsonify({"pdfUrl": pdf_url})
        response.headers["Access-Control-Allow-Origin"] = "http://localhost:3000"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response, 200
    except Exception as e:
        logger.error(f"Error generating PDF: {str(e)}", exc_info=True)
        return jsonify({"error": f"Failed to generate PDF: {str(e)}"}), 500



@app.route("/api/supervisor/trainees", methods=["GET", "OPTIONS"])
def get_super_trainees():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    
    decoded, error_response = require_auth("supervisor")
   
    if error_response:
        return error_response
    
    try:
        page = int(request.args.get("page", 1))
        search = request.args.get("search", "").lower()
        sex_filter = request.args.get("sex", "").upper()
        per_page = ITEMS_PER_PAGE
        
        # Get supervisor's user ID
        supervisor_user_id = decoded["identifier"]
        supervisor = next((s for s in users.get("supervisor", []) if s["staffId"] == supervisor_user_id), None)
        # Get trainees assigned to this supervisor
        assignments = users.get("tp_assignments", [])
        trainees = users.get("teacherTrainee", [])
        
        trainee_ids = [a["traineeId"] for a in assignments if a.get("supervisorId") == supervisor["id"]]
        trainees = [t for t in trainees if t["id"] in trainee_ids]
        
              
        # Apply search filter
        if search:
            trainees = [
                t for t in trainees
                if any(
                    search in str(t.get(field, "")).lower()
                    for field in ["regNo", "email", "name", "surname", "phone", "address"]
                )
            ]
        
        # Apply sex filter
        if sex_filter in ["MALE", "FEMALE"]:
            trainees = [t for t in trainees if t.get("sex") == sex_filter]
        
        # Sort by createdAt
        trainees.sort(key=lambda x: x.get("createdAt", ""), reverse=True)
        
        # Enrich trainees with assignment data
        sanitized_trainees = []
        for trainee in trainees:
            assignment = get_trainee_assignment(trainee["id"])
            sanitized_trainee = {
                **{k: v for k, v in trainee.items() if k != "password"},
                "supervisorId": assignment["supervisorStaffId"] if assignment else "",  # staffid
                "supervisorName": assignment["supervisorName"] if assignment else "Not Assigned",
                "placeOfTP": assignment["placeOfTP"] if assignment else "Not Assigned"
            }
            sanitized_trainees.append(sanitized_trainee)
        
        # Pagination
        total = len(sanitized_trainees)
        total_pages = ceil(total / per_page)
        start = (page - 1) * per_page
        end = start + per_page
        paginated_trainees = sanitized_trainees[start:end]
        # print(f"paginated_trainees: {sanitized_trainees}")
        return jsonify({
            "trainees": paginated_trainees,
            "totalCount": total,
            "totalPages": total_pages,
            "currentPage": page
        }), 200
    
    except Exception as e:
        print(f"Error in get_supervisor_trainees: {str(e)}")
        return jsonify({"error": "Failed to fetch trainees", "details": str(e)}), 500






if __name__ == "__main__":
    app.run(port=5000, debug=True)


