import json
from typing import Dict, List
from datetime import datetime, timedelta, timezone
import csv
import io
import uuid
import logging
from zoneinfo import ZoneInfo
import bcrypt
from dateutil.relativedelta import relativedelta
import os
from tempfile import NamedTemporaryFile
from shutil import move





# Constants
SECRET_KEY = "TPMA2025"
ITEMS_PER_PAGE = 10

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set USERS_FILE to users.json in the current script's directory
USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")



# Initial Mock Data
users: Dict[str, List[dict]] = {
    "admin": [
        {
            "id": "1",
            "username": "admin1",
            "password": bcrypt.hashpw("Secure$Admin2025!".encode(), bcrypt.gensalt()).decode("utf-8"),
            "email": "admin1@example.com",
            "role": "admin",
            "createdAt": (datetime.now(timezone.utc) - timedelta(days=100)).strftime("%Y-%m-%d")
        },
        {
            "id": "2",
            "username": "admin2",
            "password": bcrypt.hashpw("Admin#Secure2025!".encode(), bcrypt.gensalt()).decode("utf-8"),
            "email": "admin2@example.com",
            "role": "admin",
            "createdAt": (datetime.now(timezone.utc) - timedelta(days=99)).strftime("%Y-%m-%d")
        },
    ],
    "supervisor": [
        {
            "id": str(i),
            "staffId": f"STAFF{i:03d}",
            "password": bcrypt.hashpw(f"Super{i}$ecure2025!".encode(), bcrypt.gensalt()).decode("utf-8"),
            "email": f"supervisor{i}@example.com",
            "role": "supervisor",
            "name": f"Supervisor{i}",
            "surname": f"Last{i}",
            "phone": f"123-456-000{i}",
            "address": f"Address {i}",
            "bloodType": "A+" if i % 2 == 0 else "B+",
            "sex": "MALE" if i % 2 == 0 else "FEMALE",
            "birthday": "1985-01-01",
            "placeOfSupervision": f"School {chr(65 + ((i-1) % 8))}",
            "img": "",
            "createdAt": (datetime.now(timezone.utc) - timedelta(days=(10 - i))).strftime("%Y-%m-%d")
        } for i in range(1, 11)
    ],
    "teacherTrainee": [
        {
            "id": str(100 + i),
            "regNo": f"SLU/EDU/{i:03d}",
            "password": bcrypt.hashpw(f"Train{i}#ecure2025!".encode(), bcrypt.gensalt()).decode("utf-8"),
            "email": f"trainee{i}@example.com",
            "role": "teacherTrainee",
            "name": f"Trainee{i}",
            "surname": f"Student{i}",
            "phone": f"123-456-01{i:02d}",
            "address": f"Trainee Address {i}",
            "bloodType": "A+" if i % 2 == 0 else "B+",
            "sex": "MALE" if i % 2 == 0 else "FEMALE",
            "birthday": "1995-05-15",
            "progress": 80 + (i % 20),
            "img": "",
            "createdAt": (datetime.now(timezone.utc) - timedelta(days=(40 - i))).strftime("%Y-%m-%d")
        } for i in range(1, 41)
    ],
    "schools": [
        {
            "id": f"school{i}",
            "name": f"School {chr(65 + (i-1))}",
            "address": f"{123 * i} School St",
            "email": f"school{chr(97 + (i-1))}@example.com",
            "phone": f"123-456-789{i}",
            "type": ["PRIMARY", "SECONDARY", "TERTIARY"][(i-1) % 3],
            "principal": f"Principal {chr(65 + (i-1))}",
            "logo": "",
            "createdAt": (datetime.now(timezone.utc) - timedelta(days=200 - i)).strftime("%Y-%m-%d")
        } for i in range(1, 9)
    ],
    "tp_assignments": [
        {
            "id": f"tp{i}",
            "traineeId": str(100 + i),
            "supervisorId": str((i % 10) + 1),
            "schoolId": f"school{(i % 8) + 1}",
            "startDate": "" if i % 5 == 0 else (datetime.now(ZoneInfo("UTC")) - timedelta(days=30)).strftime("%Y-%m-%d"),
            "endDate": "" if i % 5 == 0 else (datetime.now(ZoneInfo("UTC")) + timedelta(days=30)).strftime("%Y-%m-%d")
        } for i in range(1, 41)
    ],
    "evaluations": [
        {
            "id": f"eval-{i}",
            "supervisorId": str(((i-1) % 10) + 1),
            "traineeId": str(100 + i),
            "traineeName": f"Trainee{i} Student{i}",
            "submittedAt": (datetime.now(timezone.utc) - timedelta(days=(30 - (i % 30)))).strftime("%Y-%m-%d"),
            "formData": {
                "lessonPlanning": {"score": 8 + (i % 2), "comments": "Good planning"},
                "teachingDelivery": {"score": 7 + (i % 3), "comments": "Clear delivery"},
                "classroomManagement": {"score": 8 + (i % 2), "comments": "Effective control"},
                "assessmentFeedback": {"score": 8, "comments": "Timely feedback"},
                "professionalism": {"score": 9, "comments": "Professional conduct"},
                "overallScore": 8 + (i % 2)
            }
        } for i in range(1, 41)
    ],
    "observations": [
        {
            "id": f"obs{i}",
            "traineeId": str(100 + i),
            "supervisorId": str(((i-1) % 10) + 1),
            "score": 7 + (i % 3),
            "comments": f"Observation {i}: Good performance",
            "status": "completed",
            "scheduled_at": (datetime.now(timezone.utc) - timedelta(days=40 - i)).strftime("%Y-%m-%d"),
            "completed_at": (datetime.now(timezone.utc) - timedelta(days=40 - i, hours=-1)).strftime("%Y-%m-%d")
        } for i in range(1, 41)
    ],
    "supervisor_schedule": [
        {
            "id": f"sch{i}",
            "supervisorId": str(((i-1) % 10) + 1),
            "traineeId": str(100 + i),
            "lesson_plan_id": f"lp{(i % 3) + 1}",
            "date": (datetime.now(timezone.utc) + timedelta(days=i)).strftime("%Y-%m-%d"),
            "start_time": "09:00:00" if i % 2 == 0 else "10:00:00",
            "end_time": "10:00:00" if i % 2 == 0 else "11:00:00",
            "status": "SCHEDULED",
            "created_at": (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%d")
        } for i in range(1, 10)
    ],
    "observation_feedback": [
        {
            "id": f"ofb{i}",
            "lesson_plan_id": f"lp{(i % 3) + 1}",
            "traineeId": str(100 + i),
            "supervisorId": str(((i-1) % 10) + 1),
            "score": 7 + (i % 3),
            "comments": f"Feedback for lesson plan lp{(i % 3) + 1}: Good engagement",
            "created_at": (datetime.now(timezone.utc) - timedelta(days=10 - i)).strftime("%Y-%m-%d")
        } for i in range(1, 10)
    ],
    "notifications": [
        {
            "id": f"notif-{i}",
            "user_id": (
                str(100 + (i % 2) + 1) if i > 6 else
                str((i % 6) + 2)
            ),
            "initiator_id": (
                "1" if i % 3 == 0 else
                str(100 + (i % 2) + 1)
            ),
            "event_id": (
                str((i % 6) + 1) if i % 4 in [2, 3] else
                f"lp{(i % 3) + 1}" if i % 4 == 0 else
                None
            ),
            "type": (
                "EVALUATION" if i % 4 == 0 else
                "ASSIGNMENT" if i % 4 == 1 else
                "EVENT" if i % 4 == 2 else
                "LESSON_PLAN"
            ),
            "priority": (
                "HIGH" if i % 3 == 0 else
                "MEDIUM" if i % 3 == 1 else
                "LOW"
            ),
            "message": (
                f"Your TP evaluation for School {chr(65 + ((i-1) % 8))} is due on 2025-04-20." if i % 4 == 0 else
                f"You are assigned to Supervisor Supervisor{((i-1) % 2) + 1} Last{((i-1) % 2) + 1} at School {chr(65 + ((i-1) % 8))}." if i % 4 == 1 else
                f"Join TP Review Meeting on 2025-04-{15 + (i % 5)} at School {chr(65 + ((i-1) % 8))}." if i % 4 == 2 else
                f"New lesson plan submitted by Trainee{(i % 2) + 1} Student{(i % 2) + 1} for {'Math' if i % 3 == 0 else 'Science' if i % 3 == 1 else 'English'} at School {chr(65 + ((i-1) % 8))}."
            ),
            "created_at": (datetime(2025, 4, 22, tzinfo=timezone.utc) + timedelta(days=i-1)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "read_status": False if i in [5, 7, 9] else True
        } for i in range(1, 10)
    ] + [
        {
            "id": f"notif-sch{i}",
            "user_id": str(((i-1) % 10) + 1),  # Supervisor IDs
            "initiator_id": str(100 + i),  # Trainee IDs
            "event_id": f"lp{(i % 3) + 1}",
            "type": "LESSON_PLAN",
            "priority": "MEDIUM",
            "message": f"Observation scheduled for lesson plan '{'Math Lesson' if i % 3 == 0 else 'Science Lesson' if i % 3 == 1 else 'English Lesson'}' by Trainee{i} Student{i} on {(datetime(2025, 4, 27, tzinfo=timezone.utc) + timedelta(days=i)).strftime('%Y-%m-%d')} at School {chr(65 + ((i-1) % 8))}.",
            "created_at": (datetime(2025, 4, 22, tzinfo=timezone.utc)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "read_status": False
        } for i in range(1, 10)],
    "feedback": [
        {
            "id": f"fb{i}",
            "traineeId": str(100 + i),
            "supervisorId": str(((i-1) % 10) + 1),
            "category": ["Lesson Plan", "Classroom Management", "Delivery"][(i-1) % 3],
            "feedback": f"Feedback {i}: Improve engagement",
            "timestamp": (datetime.now(timezone.utc) - timedelta(days=20 - i)).strftime("%Y-%m-%d")
        } for i in range(1, 41)
    ],
    "lessons": [
        {
            "id": str(i),
            "supervisorId": str(((i-1) % 10) + 1),
            "className": f"Class {(i % 5) + 1}A",
            "subject": ["Physics", "Math", "Chemistry", "Biology"][(i-1) % 4],
            "startTime": (datetime.now(timezone.utc) - timedelta(days=10 - (i % 10), hours=(i % 5))).strftime("%Y-%m-%d"),
            "endTime": (datetime.now(timezone.utc) - timedelta(days=10 - (i % 10), hours=(i % 5) - 1)).strftime("%Y-%m-%d")
        } for i in range(1, 51)
    ],
    "lesson_plans": [
        {
            "id": "lp1",
            "traineeId": "101",
            "supervisorId": "1",
            "schoolId": "school1",
            "title": "Introduction to Algebra",
            "subject": "Math",
            "class": "Jss 2",
            "date": "2025-04-07",
            "startTime": "09:00:00",
            "endTime": "10:00:00",
            "objectives": "Understand basic algebraic expressions",
            "activities": "Solve simple equations",
            "resources": "Textbook, whiteboard",
            "createdAt": "2025-04-02T10:00:00Z",
            "status": "PENDING",
            "aiGenerated": False,
            "traineeName": "Trainee1 Student1",
            "supervisorName": "Supervisor1 Last1",
            "schoolName": "School A",
            "pdfUrl": None
        },
        {
            "id": "lp2",
            "traineeId": "102",
            "supervisorId": "2",
            "schoolId": "school1",
            "title": "Grammar Basics",
            "subject": "English",
            "class": "Jss 2",
            "date": "2025-04-08",
            "startTime": "10:00:00",
            "endTime": "11:00:00",
            "objectives": "Learn sentence structure",
            "activities": "Write sentences",
            "resources": "Grammar book",
            "createdAt": "2025-04-03T11:00:00Z",
            "status": "PENDING",
            "aiGenerated": False,
            "traineeName": "Trainee1 Student1",
            "supervisorName": "Supervisor1 Last1",
            "schoolName": "School A",
            "pdfUrl": None
        },
        {
            "id": "lp3",
            "traineeId": "102",
            "supervisorId": "2",
            "schoolId": "school2",
            "title": "Photosynthesis Overview",
            "subject": "Science",
            "class": "SSS 3",
            "date": "2025-04-09",
            "startTime": "11:00:00",
            "endTime": "12:00:00",
            "objectives": "Understand the process of photosynthesis",
            "activities": "Diagram labeling",
            "resources": "Science textbook, projector",
            "createdAt": "2025-04-04T09:00:00Z",
            "status": "REJECTED",
            "aiGenerated": False,
            "traineeName": "Trainee2 Student2",
            "supervisorName": "Supervisor2 Last2",
            "schoolName": "School B",
            "pdfUrl": None
        },
                {
            "id": "lp4",
            "traineeId": "103",
            "supervisorId": "2",
            "schoolId": "school2",
            "title": "Advertisement Overview",
            "subject": "Bussines Studies",
            "class": "JSS 3",
            "date": "2025-04-09",
            "startTime": "11:00:00",
            "endTime": "12:00:00",
            "objectives": "Understand the process of Advertisement",
            "activities": "Diagram labeling",
            "resources": "Business textbook, projector",
            "createdAt": "2025-04-04T09:00:00Z",
            "status": "REJECTED",
            "aiGenerated": False,
            "traineeName": "Trainee3 Student3",
            "supervisorName": "Supervisor2 Last2",
            "schoolName": "School c",
            "pdfUrl": None
        }
    ],
    "evaluationForms": [
        {
            "id": str(i),
            "title": f"Evaluation Form {i}"
        } for i in range(7, 10)
    ],
    "announcements": [
        {
            "title": f"Announcement {i}",
            "description": f"Teaching practice update {i}",
            "date": (datetime.now(timezone.utc) - timedelta(days=10 - i)).strftime("%Y-%m-%d")
        } for i in range(1, 4)
    ],
    "events": [
        {
            "id": i,
            "title": f"Event {i}",
            "description": f"Description for event {i}",
            "startTime": (datetime(2025, 4, 13, tzinfo=timezone.utc) + timedelta(days=i-1)).strftime("%Y-%m-%d"),
            "endTime": (datetime(2025, 4, 13, tzinfo=timezone.utc) + timedelta(days=i-1, hours=2)).strftime("%Y-%m-%d")
        } for i in range(1, 7)
    ],
    "student_evaluations": [
        {
            "id": f"eval-{i}",
            "tpAssignmentId": f"tp{i}",
            "traineeId": str(100 + i),
            "supervisorId": str(((i-1) % 10) + 1),
            "score": 80 + (i % 11),
            "comments": f"Trainee {i} showed {'strong' if i % 2 == 0 else 'good'} performance but needs to improve {'lesson pacing' if i % 2 == 0 else 'student engagement'}.",
            "submittedAt": (datetime(2025, 6, 16, tzinfo=timezone.utc) + timedelta(days=i-3)).strftime("%Y-%m-%d")
        } for i in range(1, 41)
    ],
    "supervisor_evaluations": [
        {
            "id": f"sup-eval-{i}",
            "supervisorId": str(i),
            "rating": 8 + (i % 2),
            "comments": f"Supervisor {i} provides constructive feedback",
            "timestamp": (datetime.now(timezone.utc) - timedelta(days=10 - i)).strftime("%Y-%m-%d")
        } for i in range(1, 11)
    ],
}

# Additional Data Structures (unchanged)
evaluation_submissions = [
    {"week": f"Week {i}", "submitted": 30 + (i % 10), "pending": 10 - (i % 5)} for i in range(1, 5)
]

assignments: Dict[str, List[str]] = {
    f"STAFF{i:03d}": [f"SLU/EDU/{j:03d}" for j in range(i, i + 4)] for i in range(1, 11)
}

announcements = [
    {
        "title": f"Announcement {i}",
        "description": f"Teaching practice update {i}",
        "date": (datetime.now(timezone.utc) - timedelta(days=10 - i)).strftime("%Y-%m-%d")
    } for i in range(1, 4)
]

report_data = [
    {
        "regNo": f"SLU/EDU/{i:03d}",
        "date": (datetime.now(timezone.utc) - timedelta(days=10 - i)).date().isoformat(),
        "tpLocation": f"School {chr(65 + ((i-1) % 8))}",
        "submitted": i % 2 == 1
    } for i in range(1, 6)
]



# Helper Functions
def users_to_json(users_data: Dict[str, List[dict]]) -> dict:
    """Convert users data to JSON-serializable format."""
    serialized = {}
    for key, value in users_data.items():
        if isinstance(value, list):
            serialized[key] = [
                {k: v.decode("utf-8") if isinstance(v, bytes) else v for k, v in item.items()}
                for item in value
            ]
        else:
            serialized[key] = value
    return serialized

def json_to_users(json_data: dict) -> Dict[str, List[dict]]:
    """Convert JSON data back to users format with bytes passwords."""
    deserialized = {}
    for key, value in json_data.items():
        if isinstance(value, list):
            deserialized[key] = [
                {k: v.encode("utf-8") if k == "password" and isinstance(v, str) else v for k, v in item.items()}
                for item in value
            ]
        else:
            deserialized[key] = value
    return deserialized

def save_users(users_data: Dict[str, List[dict]]) -> None:
    """Save users data to users.json in the current directory, creating the file if it doesn't exist."""
    try:
        with open(USERS_FILE, "w") as f:
            json.dump(users_to_json(users_data), f, indent=4)
        logger.debug(f"Successfully saved users to {USERS_FILE}")
    except Exception as e:
        logger.error(f"Error saving {USERS_FILE}: {str(e)}")
        raise

# def load_users() -> Dict[str, List[dict]]:
#     required_keys = [
#         "admin", "supervisor", "teacherTrainee", "schools", "tp_assignments",
#         "evaluations", "observations", "supervisor_evaluations", "notifications",
#         "feedback", "lessons", "lesson_plans", "evaluationForms", "events",
#         "student_evaluations", "supervisor_evaluations"
#     ]
#     try:
#         with open(USERS_FILE, "r") as f:
#             content = f.read().strip()
#             if not content:
#                 logger.warning(f"{USERS_FILE} is empty. Initializing with mock data.")
#                 save_users(users)
#                 return users
#             users_data = json_to_users(json.loads(content))
            
#             # Ensure all required collections exist
#             for key in required_keys:
#                 if key not in users_data:
#                     logger.warning(f"Missing {key} in {USERS_FILE}. Initializing as empty list.")
#                     users_data[key] = []
            
#             # Add createdAt if missing for roles
#             for role in ["admin", "supervisor", "teacherTrainee", "schools"]:
#                 for item in users_data.get(role, []):
#                     if "createdAt" not in item:
#                         item["createdAt"] = (datetime.now(timezone.utc) - timedelta(days=100)).strftime("%Y-%m-%d")
            
#             # Validate notifications
#             for n in users_data.get("notifications", []):
#                 if not n.get("created_at"):
#                     logger.warning(f"Missing created_at for notification {n.get('id')}")
#                     n["created_at"] = datetime.now(timezone.utc).isoformat() + "Z"
#                 try:
#                     timestamp = n["created_at"]
#                     if timestamp.endswith("+00:00Z"):
#                         timestamp = timestamp[:-1]
#                     if timestamp.endswith("Z") and not timestamp.endswith("+00:00Z"):
#                         timestamp = timestamp[:-1] + "+00:00"
#                     datetime.fromisoformat(timestamp)
#                 except ValueError:
#                     logger.warning(f"Invalid created_at for notification {n.get('id')}: {n['created_at']}")
#                     n["created_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            
#             # Validate tp_assignments
#             trainees = {t["id"] for t in users_data.get("teacherTrainee", [])}
#             supervisors = {s["id"] for s in users_data.get("supervisor", [])}
#             schools = {s["id"] for s in users_data.get("schools", [])}
#             tp_assignments = {a["id"] for a in users_data.get("tp_assignments", [])}
            
#             for a in users_data.get("tp_assignments", []):
#                 if a["traineeId"] not in trainees:
#                     logger.warning(f"Invalid tp_assignment: traineeId {a['traineeId']} not found")
#                 if a.get("supervisorId") and a["supervisorId"] not in supervisors:
#                     logger.warning(f"Invalid tp_assignment: supervisorId {a['supervisorId']} not found")
#                 if a.get("schoolId") and a["schoolId"] not in schools:
#                     logger.warning(f"Invalid tp_assignment: schoolId {a['schoolId']} not found")
#                 for date_key in ["startDate", "endDate"]:
#                     date_val = a.get(date_key)
#                     if date_val and isinstance(date_val, str):
#                         try:
#                             parsed = datetime.strptime(date_val, "%Y-%m-%d")
#                             a[date_key] = parsed.strftime("%Y-%m-%d")
#                         except ValueError:
#                             logger.warning(f"Invalid {date_key} in tp_assignment {a['id']}: {date_val}")
#                             a[date_key] = ""
            
#             # Validate and clean student_evaluations
#             valid_evaluations = []
#             for e in users_data.get("student_evaluations", []):
#                 if e.get("traineeId") not in trainees:
#                     logger.warning(f"Removing invalid student_evaluation: traineeId {e['traineeId']} not found")
#                     continue
#                 if e.get("supervisorId") not in supervisors:
#                     logger.warning(f"Removing invalid student_evaluation: supervisorId {e['supervisorId']} not found")
#                     continue
#                 if e.get("tpAssignmentId") not in tp_assignments:
#                     logger.warning(f"Removing invalid student_evaluation: tpAssignmentId {e['tpAssignmentId']} not found")
#                     continue
#                 if e.get("submittedAt"):
#                     try:
#                         parsed = datetime.strptime(e["submittedAt"], "%Y-%m-%d")
#                         e["submittedAt"] = parsed.strftime("%Y-%m-%d")
#                     except ValueError:
#                         logger.warning(f"Invalid submittedAt in student_evaluation {e['id']}: {e['submittedAt']}")
#                         e["submittedAt"] = ""
#                 valid_evaluations.append(e)
            
#             users_data["student_evaluations"] = valid_evaluations
#             if len(valid_evaluations) < len(users_data.get("student_evaluations", [])):
#                 logger.info(f"Cleaned {len(users_data.get('student_evaluations', [])) - len(valid_evaluations)} invalid student_evaluations")
            
#             logger.debug(f"Successfully loaded users from {USERS_FILE}")
#             return users_data
#     except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
#         logger.error(f"Error loading {USERS_FILE}: {str(e)}. Initializing with mock data.")
#         save_users(users)
#         return users

def load_users() -> Dict[str, List[dict]]:
    required_keys = [
        "admin", "supervisor", "teacherTrainee", "schools", "tp_assignments",
        "evaluations", "observations", "supervisor_schedule", "observation_feedback",
        "notifications", "feedback", "lessons", "lesson_plans", "evaluationForms",
        "events", "student_evaluations", "supervisor_evaluations"
    ]
    try:
        with open(USERS_FILE, "r") as f:
            content = f.read().strip()
            if not content:
                logger.warning(f"{USERS_FILE} is empty. Initializing with mock data.")
                save_users(users)
                return users
            users_data = json_to_users(json.loads(content))
            
            # Ensure all required collections exist
            for key in required_keys:
                if key not in users_data:
                    logger.warning(f"Missing {key} in {USERS_FILE}. Initializing as empty list.")
                    users_data[key] = []
            
            # Add createdAt if missing for roles
            for role in ["admin", "supervisor", "teacherTrainee", "schools"]:
                for item in users_data.get(role, []):
                    if "createdAt" not in item:
                        item["createdAt"] = (datetime.now(timezone.utc) - timedelta(days=100)).strftime("%Y-%m-%d")
            
            # Validate notifications
            for n in users_data.get("notifications", []):
                if not n.get("created_at"):
                    logger.warning(f"Missing created_at for notification {n.get('id')}")
                    n["created_at"] = datetime.now(timezone.utc).isoformat() + "Z"
                try:
                    timestamp = n["created_at"]
                    if timestamp.endswith("+00:00Z"):
                        timestamp = timestamp[:-1]
                    if timestamp.endswith("Z") and not timestamp.endswith("+00:00Z"):
                        timestamp = timestamp[:-1] + "+00:00"
                    datetime.fromisoformat(timestamp)
                except ValueError:
                    logger.warning(f"Invalid created_at for notification {n.get('id')}: {n['created_at']}")
                    n["created_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            
            # Validate tp_assignments
            trainees = {t["id"] for t in users_data.get("teacherTrainee", [])}
            supervisors = {s["id"] for s in users_data.get("supervisor", [])}
            schools = {s["id"] for s in users_data.get("schools", [])}
            tp_assignments = {a["id"] for a in users_data.get("tp_assignments", [])}
            
            for a in users_data.get("tp_assignments", []):
                if a["traineeId"] not in trainees:
                    logger.warning(f"Invalid tp_assignment: traineeId {a['traineeId']} not found")
                if a.get("supervisorId") and a["supervisorId"] not in supervisors:
                    logger.warning(f"Invalid tp_assignment: supervisorId {a['supervisorId']} not found")
                if a.get("schoolId") and a["schoolId"] not in schools:
                    logger.warning(f"Invalid tp_assignment: schoolId {a['schoolId']} not found")
                for date_key in ["startDate", "endDate"]:
                    date_val = a.get(date_key)
                    if date_val and isinstance(date_val, str):
                        try:
                            parsed = datetime.strptime(date_val, "%Y-%m-%d")
                            a[date_key] = parsed.strftime("%Y-%m-%d")
                        except ValueError:
                            logger.warning(f"Invalid {date_key} in tp_assignment {a['id']}: {date_val}")
                            a[date_key] = ""
            
            # Validate supervisor_schedule
            lesson_plans = {lp["id"] for lp in users_data.get("lesson_plans", [])}
            for s in users_data.get("supervisor_schedule", []):
                if s.get("lesson_plan_id") not in lesson_plans:
                    logger.warning(f"Invalid supervisor_schedule: lesson_plan_id {s['lesson_plan_id']} not found")
                if s.get("traineeId") not in trainees:
                    logger.warning(f"Invalid supervisor_schedule: traineeId {s['traineeId']} not found")
                if s.get("supervisorId") not in supervisors:
                    logger.warning(f"Invalid supervisor_schedule: supervisorId {s['supervisorId']} not found")
                for date_key in ["date", "created_at"]:
                    date_val = s.get(date_key)
                    if date_val:
                        try:
                            parsed = datetime.strptime(date_val, "%Y-%m-%d")
                            s[date_key] = parsed.strftime("%Y-%m-%d")
                        except ValueError:
                            logger.warning(f"Invalid {date_key} in supervisor_schedule {s['id']}: {date_val}")
                            s[date_key] = ""
            
            # Validate observation_feedback
            for f in users_data.get("observation_feedback", []):
                if f.get("lesson_plan_id") not in lesson_plans:
                    logger.warning(f"Invalid observation_feedback: lesson_plan_id {f['lesson_plan_id']} not found")
                if f.get("traineeId") not in trainees:
                    logger.warning(f"Invalid observation_feedback: traineeId {f['traineeId']} not found")
                if f.get("supervisorId") not in supervisors:
                    logger.warning(f"Invalid observation_feedback: supervisorId {f['supervisorId']} not found")
                if f.get("created_at"):
                    try:
                        parsed = datetime.strptime(f["created_at"], "%Y-%m-%d")
                        f["created_at"] = parsed.strftime("%Y-%m-%d")
                    except ValueError:
                        logger.warning(f"Invalid created_at in observation_feedback {f['id']}: {f['created_at']}")
                        f["created_at"] = ""
            
            # Validate and clean student_evaluations
            valid_evaluations = []
            for e in users_data.get("student_evaluations", []):
                if e.get("traineeId") not in trainees:
                    logger.warning(f"Removing invalid student_evaluation: traineeId {e['traineeId']} not found")
                    continue
                if e.get("supervisorId") not in supervisors:
                    logger.warning(f"Removing invalid student_evaluation: supervisorId {e['supervisorId']} not found")
                    continue
                if e.get("tpAssignmentId") not in tp_assignments:
                    logger.warning(f"Removing invalid student_evaluation: tpAssignmentId {e['tpAssignmentId']} not found")
                    continue
                if e.get("submittedAt"):
                    try:
                        parsed = datetime.strptime(e["submittedAt"], "%Y-%m-%d")
                        e["submittedAt"] = parsed.strftime("%Y-%m-%d")
                    except ValueError:
                        logger.warning(f"Invalid submittedAt in student_evaluation {e['id']}: {e['submittedAt']}")
                        e["submittedAt"] = ""
                valid_evaluations.append(e)
            
            users_data["student_evaluations"] = valid_evaluations
            if len(valid_evaluations) < len(users_data.get("student_evaluations", [])):
                logger.info(f"Cleaned {len(users_data.get('student_evaluations', [])) - len(valid_evaluations)} invalid student_evaluations")
            
            logger.debug(f"Successfully loaded users from {USERS_FILE}")
            return users_data
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
        logger.error(f"Error loading {USERS_FILE}: {str(e)}. Initializing with mock data.")
        save_users(users)
        return users




def generate_unique_id() -> str:
    """Generate a unique UUID."""
    return str(uuid.uuid4())






















# # Initial Mock Data
# users: Dict[str, List[dict]] = {
#     "admin": [
#         {
#             "id": "1",
#             "username": "admin1",
#             "password": bcrypt.hashpw("Secure$Admin2025!".encode(), bcrypt.gensalt()).decode("utf-8"),
#             "email": "admin1@example.com",
#             "role": "admin",
#             "createdAt": (datetime.now(timezone.utc) - timedelta(days=100)).strftime("%Y-%m-%d")
#         },
#         {
#             "id": "2",
#             "username": "admin2",
#             "password": bcrypt.hashpw("Admin#Secure2025!".encode(), bcrypt.gensalt()).decode("utf-8"),
#             "email": "admin2@example.com",
#             "role": "admin",
#             "createdAt": (datetime.now(timezone.utc) - timedelta(days=99)).strftime("%Y-%m-%d")
#         },
#     ],
#     "supervisor": [
#         {
#             "id": str(i),
#             "staffId": f"STAFF{i:03d}",
#             "password": bcrypt.hashpw(f"Super{i}$ecure2025!".encode(), bcrypt.gensalt()).decode("utf-8"),
#             "email": f"supervisor{i}@example.com",
#             "role": "supervisor",
#             "name": f"Supervisor{i}",
#             "surname": f"Last{i}",
#             "phone": f"123-456-000{i}",
#             "address": f"Address {i}",
#             "bloodType": "A+" if i % 2 == 0 else "B+",
#             "sex": "MALE" if i % 2 == 0 else "FEMALE",
#             "birthday": "1985-01-01",
#             "placeOfSupervision": f"School {chr(65 + ((i-1) % 8))}",
#             "img": "",
#             "createdAt": (datetime.now(timezone.utc) - timedelta(days=(10 - i))).strftime("%Y-%m-%d")
#         } for i in range(1, 11)
#     ],
#     "teacherTrainee": [
#         {
#             "id": str(100 + i),
#             "regNo": f"SLU/EDU/{i:03d}",
#             "password": bcrypt.hashpw(f"Train{i}#ecure2025!".encode(), bcrypt.gensalt()).decode("utf-8"),
#             "email": f"trainee{i}@example.com",
#             "role": "teacherTrainee",
#             "name": f"Trainee{i}",
#             "surname": f"Student{i}",
#             "phone": f"123-456-01{i:02d}",
#             "address": f"Trainee Address {i}",
#             "bloodType": "A+" if i % 2 == 0 else "B+",
#             "sex": "MALE" if i % 2 == 0 else "FEMALE",
#             "birthday": "1995-05-15",
#             "progress": 80 + (i % 20),
#             "img": "",
#             "createdAt": (datetime.now(timezone.utc) - timedelta(days=(40 - i))).strftime("%Y-%m-%d")
#         } for i in range(1, 41)
#     ],
#     "schools": [
#         {
#             "id": f"school{i}",
#             "name": f"School {chr(65 + (i-1))}",
#             "address": f"{123 * i} School St",
#             "email": f"school{chr(97 + (i-1))}@example.com",
#             "phone": f"123-456-789{i}",
#             "type": ["PRIMARY", "SECONDARY", "TERTIARY"][(i-1) % 3],
#             "principal": f"Principal {chr(65 + (i-1))}",
#             "logo": "",
#             "createdAt": (datetime.now(timezone.utc) - timedelta(days=200 - i)).strftime("%Y-%m-%d")
#         } for i in range(1, 9)
#     ],
#     "tp_assignments": [
#         {
#             "id": f"tp{i}",
#             "traineeId": str(100 + i),
#             "supervisorId": str((i % 10) + 1),
#             "schoolId": f"school{(i % 8) + 1}",
#             "startDate": "" if i % 5 == 0 else (datetime.now(ZoneInfo("UTC")) - timedelta(days=30)).strftime("%Y-%m-%d"),
#             "endDate": "" if i % 5 == 0 else (datetime.now(ZoneInfo("UTC")) + timedelta(days=30)).strftime("%Y-%m-%d")
#         } for i in range(1, 41)
#     ],
#     "evaluations": [
#         {
#             "id": f"eval-{i}",
#             "supervisorId": str(((i-1) % 10) + 1),
#             "traineeId": str(100 + i),
#             "traineeName": f"Trainee{i} Student{i}",
#             "submittedAt": (datetime.now(timezone.utc) - timedelta(days=(30 - (i % 30)))).strftime("%Y-%m-%d"),
#             "formData": {
#                 "lessonPlanning": {"score": 8 + (i % 2), "comments": "Good planning"},
#                 "teachingDelivery": {"score": 7 + (i % 3), "comments": "Clear delivery"},
#                 "classroomManagement": {"score": 8 + (i % 2), "comments": "Effective control"},
#                 "assessmentFeedback": {"score": 8, "comments": "Timely feedback"},
#                 "professionalism": {"score": 9, "comments": "Professional conduct"},
#                 "overallScore": 8 + (i % 2)
#             }
#         } for i in range(1, 41)
#     ],
#     "observations": [
#         {
#             "id": f"obs{i}",
#             "traineeId": str(100 + i),
#             "supervisorId": str(((i-1) % 10) + 1),
#             "score": 7 + (i % 3),
#             "comments": f"Observation {i}: Good performance",
#             "status": "completed",
#             "scheduled_at": (datetime.now(timezone.utc) - timedelta(days=40 - i)).strftime("%Y-%m-%d"),
#             "completed_at": (datetime.now(timezone.utc) - timedelta(days=40 - i, hours=-1)).strftime("%Y-%m-%d")
#         } for i in range(1, 41)
#     ],
#     "supervisor_evaluations": [
#         {
#             "id": f"sup-eval-{i}",
#             "supervisorId": str(i),
#             "rating": 8 + (i % 2),
#             "comments": f"Supervisor {i} provides constructive feedback",
#             "timestamp": (datetime.now(timezone.utc) - timedelta(days=10 - i)).strftime("%Y-%m-%d")
#         } for i in range(1, 11)
#     ],
#     "notifications": [
#         {
#             "id": f"notif-{i}",
#             "user_id": (
#                 f"SLU/EDU/{(i % 2) + 1:03d}" if i > 6 else
#                 f"STAFF{(i % 6) + 2:03d}"
#             ),
#             "initiator_id": (
#                 "admin1" if i % 3 == 0 else
#                 f"SLU/EDU/{(i % 2) + 1:03d}"
#             ),
#             "event_id": str((i % 6) + 1),
#             "type": (
#                 "EVALUATION" if i % 4 == 0 else
#                 "ASSIGNMENT" if i % 4 == 1 else
#                 "EVENT" if i % 4 == 2 else
#                 "LESSON_PLAN"
#             ),
#             "priority": (
#                 "HIGH" if i % 3 == 0 else
#                 "MEDIUM" if i % 3 == 1 else
#                 "LOW"
#             ),
#             "message": (
#                 f"Your TP evaluation for School {chr(65 + ((i-1) % 8))} is due on 2025-04-20." if i % 3 == 0 else
#                 f"You are assigned to Supervisor STAFF{((i-1) % 2) + 1} at School {chr(65 + ((i-1) % 8))}." if i % 3 == 1 else
#                 f"Join TP Review Meeting on 2025-04-{15 + (i % 5)} at School {chr(65 + ((i-1) % 8))}."
#             ),
#             "created_at": (datetime.now(timezone.utc) - relativedelta(days=5 - (i % 5))).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
#             "read_status": False if i in [5, 7, 9] else True
#         } for i in range(1, 10)
#     ],
#     "feedback": [
#         {
#             "id": f"fb{i}",
#             "traineeId": str(100 + i),
#             "supervisorId": str(((i-1) % 10) + 1),
#             "category": ["Lesson Plan", "Classroom Management", "Delivery"][(i-1) % 3],
#             "feedback": f"Feedback {i}: Improve engagement",
#             "timestamp": (datetime.now(timezone.utc) - timedelta(days=20 - i)).strftime("%Y-%m-%d")
#         } for i in range(1, 41)
#     ],
#     "lessons": [
#         {
#             "id": str(i),
#             "supervisorId": str(((i-1) % 10) + 1),
#             "className": f"Class {(i % 5) + 1}A",
#             "subject": ["Physics", "Math", "Chemistry", "Biology"][(i-1) % 4],
#             "startTime": (datetime.now(timezone.utc) - timedelta(days=10 - (i % 10), hours=(i % 5))).strftime("%Y-%m-%d"),
#             "endTime": (datetime.now(timezone.utc) - timedelta(days=10 - (i % 10), hours=(i % 5) - 1)).strftime("%Y-%m-%d")
#         } for i in range(1, 51)
#     ],
# "lesson_plans": [
#     {
#         "id": "lp1",
#         "traineeId": "101",
#         "supervisorId": "1",
#         "schoolId": "school1",
#         "title": "Introduction to Algebra",
#         "subject": "Math",
#         "class":"Jss 2",
#         "date": "2025-04-07",
#         "startTime": "09:00:00",
#         "endTime": "10:00:00",
#         "objectives": "Understand basic algebraic expressions",
#         "activities": "Solve simple equations",
#         "resources": "Textbook, whiteboard",
#         "createdAt": "2025-04-02T10:00:00Z",
#         "status": "PENDING",
#         "aiGenerated": False,
#         "traineeName": "Trainee1 Student1",
#         "supervisorName": "Supervisor1 Last1",
#         "schoolName": "School A",
#         "pdfUrl": None
#     },
#     {
#         "id": "lp2",
#         "traineeId": "101",
#         "supervisorId": "1",
#         "schoolId": "school1",
#         "title": "Grammar Basics",
#         "subject": "English",
#         "class":"Jss 2",
#         "date": "2025-04-08",
#         "startTime": "10:00:00",
#         "endTime": "11:00:00",
#         "objectives": "Learn sentence structure",
#         "activities": "Write sentences",
#         "resources": "Grammar book",
#         "createdAt": "2025-04-03T11:00:00Z",
#         "status": "APPROVED",
#         "aiGenerated": False,
#         "traineeName": "Trainee1 Student1",
#         "supervisorName": "Supervisor1 Last1",
#         "schoolName": "School A",
#         "pdfUrl": None
#     },
#     {
#         "id": "lp3",
#         "traineeId": "102",
#         "supervisorId": "2",
#         "schoolId": "school2",
#         "title": "Photosynthesis Overview",
#         "subject": "Science",
#         "class":"SSS 3",
#         "date": "2025-04-09",
#         "startTime": "11:00:00",
#         "endTime": "12:00:00",
#         "objectives": "Understand the process of photosynthesis",
#         "activities": "Diagram labeling",
#         "resources": "Science textbook, projector",
#         "createdAt": "2025-04-04T09:00:00Z",
#         "status": "REJECTED",
#         "aiGenerated": False,
#         "traineeName": "Trainee2 Student2",
#         "supervisorName": "Supervisor2 Last2",
#         "schoolName": "School B",
#         "pdfUrl": None
#     }
# ],
#     "evaluationForms": [
#         {
#             "id": str(i),
#             "title": f"Evaluation Form {i}"
#         } for i in range(7, 10)
#     ],
#     "announcements": [
#         {
#             "title": f"Announcement {i}",
#             "description": f"Teaching practice update {i}",
#             "date": (datetime.now(timezone.utc) - timedelta(days=10 - i)).strftime("%Y-%m-%d")
#         } for i in range(1, 4)
#     ],
#     "events": [
#         {
#             "id": i,
#             "title": f"Event {i}",
#             "description": f"Description for event {i}",
#             "startTime": (datetime(2025, 4, 13, tzinfo=timezone.utc) + timedelta(days=i-1)).strftime("%Y-%m-%d"),
#             "endTime": (datetime(2025, 4, 13, tzinfo=timezone.utc) + timedelta(days=i-1, hours=2)).strftime("%Y-%m-%d")
#         } for i in range(1, 7)
#     ],
#     "student_evaluations": [
#         {
#             "id": "eval-1",
#             "tpAssignmentId": "tp1",
#             "traineeId": "101",
#             "supervisorId": "2",
#             "score": 85,
#             "comments": "Jude demonstrated strong classroom management but needs to improve lesson pacing.",
#             "submittedAt": "2025-06-16"
#         },
#         {
#             "id": "eval-2",
#             "tpAssignmentId": "tp2",
#             "traineeId": "102",
#             "supervisorId": "2",
#             "score": 78,
#             "comments": "Amaka showed good effort but needs to work on time management and student engagement.",
#             "submittedAt": "2025-06-16"
#         }
#     ] + [
#         {
#             "id": f"eval-{i}",
#             "tpAssignmentId": f"tp{i}",
#             "traineeId": str(100 + i),
#             "supervisorId": str(((i-1) % 10) + 1),
#             "score": 80 + (i % 11),
#             "comments": f"Trainee {i} showed {'strong' if i % 2 == 0 else 'good'} performance but needs to improve {'lesson pacing' if i % 2 == 0 else 'student engagement'}.",
#             "submittedAt": (datetime(2025, 6, 16, tzinfo=timezone.utc) + timedelta(days=i-3)).strftime("%Y-%m-%d")
#         } for i in range(3, 41)  # Changed to 41 to ensure tp8 is covered
#     ],
#     "supervisor_evaluations": [
#         {
#             "id": f"sup-eval-{i}",
#             "supervisorId": str(i),
#             "rating": 8 + (i % 2),
#             "comments": f"Supervisor {i} provides constructive feedback",
#             "timestamp": (datetime.now(timezone.utc) - timedelta(days=10 - i)).strftime("%Y-%m-%d")
#         } for i in range(1, 11)
#     ],
# }

# # Additional Data Structures (unchanged)
# evaluation_submissions = [
#     {"week": f"Week {i}", "submitted": 30 + (i % 10), "pending": 10 - (i % 5)} for i in range(1, 5)
# ]

# assignments: Dict[str, List[str]] = {
#     f"STAFF{i:03d}": [f"SLU/EDU/{j:03d}" for j in range(i, i + 4)] for i in range(1, 11)
# }

# announcements = [
#     {
#         "title": f"Announcement {i}",
#         "description": f"Teaching practice update {i}",
#         "date": (datetime.now(timezone.utc) - timedelta(days=10 - i)).strftime("%Y-%m-%d")
#     } for i in range(1, 4)
# ]

# report_data = [
#     {
#         "regNo": f"SLU/EDU/{i:03d}",
#         "date": (datetime.now(timezone.utc) - timedelta(days=10 - i)).date().isoformat(),
#         "tpLocation": f"School {chr(65 + ((i-1) % 8))}",
#         "submitted": i % 2 == 1
#     } for i in range(1, 6)
# ]











































# import json
# from typing import Dict, List
# from datetime import datetime, timedelta, timezone
# import csv
# import io
# import uuid
# import logging
# from zoneinfo import ZoneInfo
# import bcrypt
# from dateutil.relativedelta import relativedelta
# import os
# from tempfile import NamedTemporaryFile
# from shutil import move

# # Constants
# SECRET_KEY = "TPMA2025"
# ITEMS_PER_PAGE = 10

# # Set up logging
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)

# # Set USERS_FILE to users.json in the current script's directory
# USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")

# # Initial Mock Data
# users: Dict[str, List[dict]] = {
#     "admin": [
#         {
#             "id": "1",
#             "username": "admin1",
#             "password": bcrypt.hashpw("Secure$Admin2025!".encode(), bcrypt.gensalt()).decode("utf-8"),
#             "email": "admin1@example.com",
#             "role": "admin",
#             "createdAt": (datetime.now(timezone.utc) - timedelta(days=100)).strftime("%Y-%m-%d")
#         },
#         {
#             "id": "2",
#             "username": "admin2",
#             "password": bcrypt.hashpw("Admin#Secure2025!".encode(), bcrypt.gensalt()).decode("utf-8"),
#             "email": "admin2@example.com",
#             "role": "admin",
#             "createdAt": (datetime.now(timezone.utc) - timedelta(days=99)).strftime("%Y-%m-%d")
#         },
#     ],
#     "supervisor": [
#         {
#             "id": str(i),
#             "staffId": f"STAFF{i:03d}",
#             "password": bcrypt.hashpw(f"Super{i}$ecure2025!".encode(), bcrypt.gensalt()).decode("utf-8"),
#             "email": f"supervisor{i}@example.com",
#             "role": "supervisor",
#             "name": f"Supervisor{i}",
#             "surname": f"Last{i}",
#             "phone": f"123-456-000{i}",
#             "address": f"Address {i}",
#             "bloodType": "A+" if i % 2 == 0 else "B+",
#             "sex": "MALE" if i % 2 == 0 else "FEMALE",
#             "birthday": "1985-01-01",
#             "placeOfSupervision": f"School {chr(65 + ((i-1) % 8))}",
#             "img": "",
#             "createdAt": (datetime.now(timezone.utc) - timedelta(days=(10 - i))).strftime("%Y-%m-%d")
#         } for i in range(1, 11)
#     ],
#     "teacherTrainee": [
#         {
#             "id": str(100 + i),
#             "regNo": f"SLU/EDU/{i:03d}",
#             "password": bcrypt.hashpw(f"Train{i}#ecure2025!".encode(), bcrypt.gensalt()).decode("utf-8"),
#             "email": f"trainee{i}@example.com",
#             "role": "teacherTrainee",
#             "name": f"Trainee{i}",
#             "surname": f"Student{i}",
#             "phone": f"123-456-01{i:02d}",
#             "address": f"Trainee Address {i}",
#             "bloodType": "A+" if i % 2 == 0 else "B+",
#             "sex": "MALE" if i % 2 == 0 else "FEMALE",
#             "birthday": "1995-05-15",
#             "progress": 80 + (i % 20),
#             "img": "",
#             "createdAt": (datetime.now(timezone.utc) - timedelta(days=(40 - i))).strftime("%Y-%m-%d")
#         } for i in range(1, 41)
#     ],
#     "schools": [
#         {
#             "id": f"school{i}",
#             "name": f"School {chr(65 + (i-1))}",
#             "address": f"{123 * i} School St",
#             "email": f"school{chr(97 + (i-1))}@example.com",
#             "phone": f"123-456-789{i}",
#             "type": ["PRIMARY", "SECONDARY", "TERTIARY"][(i-1) % 3],
#             "principal": f"Principal {chr(65 + (i-1))}",
#             "logo": "",
#             "createdAt": (datetime.now(timezone.utc) - timedelta(days=200 - i)).strftime("%Y-%m-%d")
#         } for i in range(1, 9)
#     ],
#     "tp_assignments": [
#         {
#             "id": f"tp{i}",
#             "traineeId": str(100 + i),
#             "supervisorId": str((i % 10) + 1),
#             "schoolId": f"school{(i % 8) + 1}",
#             "startDate": "" if i % 5 == 0 else (datetime.now(ZoneInfo("UTC")) - timedelta(days=30)).strftime("%Y-%m-%d"),
#             "endDate": "" if i % 5 == 0 else (datetime.now(ZoneInfo("UTC")) + timedelta(days=30)).strftime("%Y-%m-%d")
#         } for i in range(1, 41)
#     ],
#     "evaluations": [
#         {
#             "id": f"eval-{i}",
#             "supervisorId": str(((i-1) % 10) + 1),
#             "traineeId": str(100 + i),
#             "traineeName": f"Trainee{i} Student{i}",
#             "submittedAt": (datetime.now(timezone.utc) - timedelta(days=(30 - (i % 30)))).strftime("%Y-%m-%d"),
#             "formData": {
#                 "lessonPlanning": {"score": 8 + (i % 2), "comments": "Good planning"},
#                 "teachingDelivery": {"score": 7 + (i % 3), "comments": "Clear delivery"},
#                 "classroomManagement": {"score": 8 + (i % 2), "comments": "Effective control"},
#                 "assessmentFeedback": {"score": 8, "comments": "Timely feedback"},
#                 "professionalism": {"score": 9, "comments": "Professional conduct"},
#                 "overallScore": 8 + (i % 2)
#             }
#         } for i in range(1, 41)
#     ],
#     "observations": [
#         {
#             "id": f"obs{i}",
#             "traineeId": str(100 + i),
#             "supervisorId": str(((i-1) % 10) + 1),
#             "score": 7 + (i % 3),
#             "comments": f"Observation {i}: Good performance",
#             "status": "completed",
#             "scheduled_at": (datetime.now(timezone.utc) - timedelta(days=40 - i)).strftime("%Y-%m-%d"),
#             "completed_at": (datetime.now(timezone.utc) - timedelta(days=40 - i, hours=-1)).strftime("%Y-%m-%d")
#         } for i in range(1, 41)
#     ],
#     "supervisor_schedule": [
#         {
#             "id": f"sch{i}",
#             "supervisorId": str(((i-1) % 10) + 1),
#             "traineeId": str(100 + i),
#             "lesson_plan_id": f"lp{(i % 3) + 1}",
#             "date": (datetime.now(timezone.utc) + timedelta(days=i)).strftime("%Y-%m-%d"),
#             "start_time": "09:00:00" if i % 2 == 0 else "10:00:00",
#             "end_time": "10:00:00" if i % 2 == 0 else "11:00:00",
#             "status": "SCHEDULED",
#             "created_at": (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%d")
#         } for i in range(1, 10)
#     ],
#     "observation_feedback": [
#         {
#             "id": f"ofb{i}",
#             "lesson_plan_id": f"lp{(i % 3) + 1}",
#             "traineeId": str(100 + i),
#             "supervisorId": str(((i-1) % 10) + 1),
#             "score": 7 + (i % 3),
#             "comments": f"Feedback for lesson plan lp{(i % 3) + 1}: Good engagement",
#             "created_at": (datetime.now(timezone.utc) - timedelta(days=10 - i)).strftime("%Y-%m-%d")
#         } for i in range(1, 10)
#     ],
#     "notifications": [
#         {
#             "id": f"notif-{i}",
#             "user_id": (
#                 f"SLU/EDU/{(i % 2) + 1:03d}" if i > 6 else
#                 f"STAFF{(i % 6) + 2:03d}"
#             ),
#             "initiator_id": (
#                 "admin1" if i % 3 == 0 else
#                 f"SLU/EDU/{(i % 2) + 1:03d}"
#             ),
#             "event_id": str((i % 6) + 1),
#             "type": (
#                 "EVALUATION" if i % 4 == 0 else
#                 "ASSIGNMENT" if i % 4 == 1 else
#                 "EVENT" if i % 4 == 2 else
#                 "LESSON_PLAN"
#             ),
#             "priority": (
#                 "HIGH" if i % 3 == 0 else
#                 "MEDIUM" if i % 3 == 1 else
#                 "LOW"
#             ),
#             "message": (
#                 f"Your TP evaluation for School {chr(65 + ((i-1) % 8))} is due on 2025-04-20." if i % 3 == 0 else
#                 f"You are assigned to Supervisor STAFF{((i-1) % 2) + 1} at School {chr(65 + ((i-1) % 8))}." if i % 3 == 1 else
#                 f"Join TP Review Meeting on 2025-04-{15 + (i % 5)} at School {chr(65 + ((i-1) % 8))}."
#             ),
#             "created_at": (datetime.now(timezone.utc) - relativedelta(days=5 - (i % 5))).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
#             "read_status": False if i in [5, 7, 9] else True
#         } for i in range(1, 10)
#     ] + [
#         {
#             "id": f"notif-sch{i}",
#             "user_id": str(100 + i),
#             "initiator_id": str(((i-1) % 10) + 1),
#             "event_id": f"sch{i}",
#             "type": "SCHEDULE",
#             "priority": "MEDIUM",
#             "message": f"Observation scheduled for lesson plan lp{(i % 3) + 1} on {(datetime.now(timezone.utc) + timedelta(days=i)).strftime('%Y-%m-%d')}.",
#             "created_at": (datetime.now(timezone.utc) - timedelta(days=5)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
#             "read_status": False
#         } for i in range(1, 10)
#     ],
#     "feedback": [
#         {
#             "id": f"fb{i}",
#             "traineeId": str(100 + i),
#             "supervisorId": str(((i-1) % 10) + 1),
#             "category": ["Lesson Plan", "Classroom Management", "Delivery"][(i-1) % 3],
#             "feedback": f"Feedback {i}: Improve engagement",
#             "timestamp": (datetime.now(timezone.utc) - timedelta(days=20 - i)).strftime("%Y-%m-%d")
#         } for i in range(1, 41)
#     ],
#     "lessons": [
#         {
#             "id": str(i),
#             "supervisorId": str(((i-1) % 10) + 1),
#             "className": f"Class {(i % 5) + 1}A",
#             "subject": ["Physics", "Math", "Chemistry", "Biology"][(i-1) % 4],
#             "startTime": (datetime.now(timezone.utc) - timedelta(days=10 - (i % 10), hours=(i % 5))).strftime("%Y-%m-%d"),
#             "endTime": (datetime.now(timezone.utc) - timedelta(days=10 - (i % 10), hours=(i % 5) - 1)).strftime("%Y-%m-%d")
#         } for i in range(1, 51)
#     ],
#     "lesson_plans": [
#         {
#             "id": "lp1",
#             "traineeId": "101",
#             "supervisorId": "1",
#             "schoolId": "school1",
#             "title": "Introduction to Algebra",
#             "subject": "Math",
#             "class": "Jss 2",
#             "date": "2025-04-07",
#             "startTime": "09:00:00",
#             "endTime": "10:00:00",
#             "objectives": "Understand basic algebraic expressions",
#             "activities": "Solve simple equations",
#             "resources": "Textbook, whiteboard",
#             "createdAt": "2025-04-02T10:00:00Z",
#             "status": "PENDING",
#             "aiGenerated": False,
#             "traineeName": "Trainee1 Student1",
#             "supervisorName": "Supervisor1 Last1",
#             "schoolName": "School A",
#             "pdfUrl": None
#         },
#         {
#             "id": "lp2",
#             "traineeId": "101",
#             "supervisorId": "1",
#             "schoolId": "school1",
#             "title": "Grammar Basics",
#             "subject": "English",
#             "class": "Jss 2",
#             "date": "2025-04-08",
#             "startTime": "10:00:00",
#             "endTime": "11:00:00",
#             "objectives": "Learn sentence structure",
#             "activities": "Write sentences",
#             "resources": "Grammar book",
#             "createdAt": "2025-04-03T11:00:00Z",
#             "status": "PENDING",
#             "aiGenerated": False,
#             "traineeName": "Trainee1 Student1",
#             "supervisorName": "Supervisor1 Last1",
#             "schoolName": "School A",
#             "pdfUrl": None
#         },
#         {
#             "id": "lp3",
#             "traineeId": "102",
#             "supervisorId": "2",
#             "schoolId": "school2",
#             "title": "Photosynthesis Overview",
#             "subject": "Science",
#             "class": "SSS 3",
#             "date": "2025-04-09",
#             "startTime": "11:00:00",
#             "endTime": "12:00:00",
#             "objectives": "Understand the process of photosynthesis",
#             "activities": "Diagram labeling",
#             "resources": "Science textbook, projector",
#             "createdAt": "2025-04-04T09:00:00Z",
#             "status": "REJECTED",
#             "aiGenerated": False,
#             "traineeName": "Trainee2 Student2",
#             "supervisorName": "Supervisor2 Last2",
#             "schoolName": "School B",
#             "pdfUrl": None
#         }
#     ],
#     "evaluationForms": [
#         {
#             "id": str(i),
#             "title": f"Evaluation Form {i}"
#         } for i in range(7, 10)
#     ],
#     "announcements": [
#         {
#             "title": f"Announcement {i}",
#             "description": f"Teaching practice update {i}",
#             "date": (datetime.now(timezone.utc) - timedelta(days=10 - i)).strftime("%Y-%m-%d")
#         } for i in range(1, 4)
#     ],
#     "events": [
#         {
#             "id": i,
#             "title": f"Event {i}",
#             "description": f"Description for event {i}",
#             "startTime": (datetime(2025, 4, 13, tzinfo=timezone.utc) + timedelta(days=i-1)).strftime("%Y-%m-%d"),
#             "endTime": (datetime(2025, 4, 13, tzinfo=timezone.utc) + timedelta(days=i-1, hours=2)).strftime("%Y-%m-%d")
#         } for i in range(1, 7)
#     ],
#     "student_evaluations": [
#         {
#             "id": f"eval-{i}",
#             "tpAssignmentId": f"tp{i}",
#             "traineeId": str(100 + i),
#             "supervisorId": str(((i-1) % 10) + 1),
#             "score": 80 + (i % 11),
#             "comments": f"Trainee {i} showed {'strong' if i % 2 == 0 else 'good'} performance but needs to improve {'lesson pacing' if i % 2 == 0 else 'student engagement'}.",
#             "submittedAt": (datetime(2025, 6, 16, tzinfo=timezone.utc) + timedelta(days=i-3)).strftime("%Y-%m-%d")
#         } for i in range(1, 41)
#     ],
#     "supervisor_evaluations": [
#         {
#             "id": f"sup-eval-{i}",
#             "supervisorId": str(i),
#             "rating": 8 + (i % 2),
#             "comments": f"Supervisor {i} provides constructive feedback",
#             "timestamp": (datetime.now(timezone.utc) - timedelta(days=10 - i)).strftime("%Y-%m-%d")
#         } for i in range(1, 11)
#     ],
# }

# # Additional Data Structures (unchanged)
# evaluation_submissions = [
#     {"week": f"Week {i}", "submitted": 30 + (i % 10), "pending": 10 - (i % 5)} for i in range(1, 5)
# ]

# assignments: Dict[str, List[str]] = {
#     f"STAFF{i:03d}": [f"SLU/EDU/{j:03d}" for j in range(i, i + 4)] for i in range(1, 11)
# }

# announcements = [
#     {
#         "title": f"Announcement {i}",
#         "description": f"Teaching practice update {i}",
#         "date": (datetime.now(timezone.utc) - timedelta(days=10 - i)).strftime("%Y-%m-%d")
#     } for i in range(1, 4)
# ]

# report_data = [
#     {
#         "regNo": f"SLU/EDU/{i:03d}",
#         "date": (datetime.now(timezone.utc) - timedelta(days=10 - i)).date().isoformat(),
#         "tpLocation": f"School {chr(65 + ((i-1) % 8))}",
#         "submitted": i % 2 == 1
#     } for i in range(1, 6)
# ]

# # Helper Functions
# def users_to_json(users_data: Dict[str, List[dict]]) -> dict:
#     """Convert users data to JSON-serializable format."""
#     serialized = {}
#     for key, value in users_data.items():
#         if isinstance(value, list):
#             serialized[key] = [
#                 {k: v.decode("utf-8") if isinstance(v, bytes) else v for k, v in item.items()}
#                 for item in value
#             ]
#         else:
#             serialized[key] = value
#     return serialized

# def json_to_users(json_data: dict) -> Dict[str, List[dict]]:
#     """Convert JSON data back to users format with bytes passwords."""
#     deserialized = {}
#     for key, value in json_data.items():
#         if isinstance(value, list):
#             deserialized[key] = [
#                 {k: v.encode("utf-8") if k == "password" and isinstance(v, str) else v for k, v in item.items()}
#                 for item in value
#             ]
#         else:
#             deserialized[key] = value
#     return deserialized

# def save_users(users_data: Dict[str, List[dict]]) -> None:
#     """Save users data to users.json in the current directory, creating the file if it doesn't exist."""
#     try:
#         with open(USERS_FILE, "w") as f:
#             json.dump(users_to_json(users_data), f, indent=4)
#         logger.debug(f"Successfully saved users to {USERS_FILE}")
#     except Exception as e:
#         logger.error(f"Error saving {USERS_FILE}: {str(e)}")
#         raise

# def load_users() -> Dict[str, List[dict]]:
#     required_keys = [
#         "admin", "supervisor", "teacherTrainee", "schools", "tp_assignments",
#         "evaluations", "observations", "supervisor_schedule", "observation_feedback",
#         "notifications", "feedback", "lessons", "lesson_plans", "evaluationForms",
#         "events", "student_evaluations", "supervisor_evaluations"
#     ]
#     try:
#         with open(USERS_FILE, "r") as f:
#             content = f.read().strip()
#             if not content:
#                 logger.warning(f"{USERS_FILE} is empty. Initializing with mock data.")
#                 save_users(users)
#                 return users
#             users_data = json_to_users(json.loads(content))
            
#             # Ensure all required collections exist
#             for key in required_keys:
#                 if key not in users_data:
#                     logger.warning(f"Missing {key} in {USERS_FILE}. Initializing as empty list.")
#                     users_data[key] = []
            
#             # Add createdAt if missing for roles
#             for role in ["admin", "supervisor", "teacherTrainee", "schools"]:
#                 for item in users_data.get(role, []):
#                     if "createdAt" not in item:
#                         item["createdAt"] = (datetime.now(timezone.utc) - timedelta(days=100)).strftime("%Y-%m-%d")
            
#             # Validate notifications
#             for n in users_data.get("notifications", []):
#                 if not n.get("created_at"):
#                     logger.warning(f"Missing created_at for notification {n.get('id')}")
#                     n["created_at"] = datetime.now(timezone.utc).isoformat() + "Z"
#                 try:
#                     timestamp = n["created_at"]
#                     if timestamp.endswith("+00:00Z"):
#                         timestamp = timestamp[:-1]
#                     if timestamp.endswith("Z") and not timestamp.endswith("+00:00Z"):
#                         timestamp = timestamp[:-1] + "+00:00"
#                     datetime.fromisoformat(timestamp)
#                 except ValueError:
#                     logger.warning(f"Invalid created_at for notification {n.get('id')}: {n['created_at']}")
#                     n["created_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            
#             # Validate tp_assignments
#             trainees = {t["id"] for t in users_data.get("teacherTrainee", [])}
#             supervisors = {s["id"] for s in users_data.get("supervisor", [])}
#             schools = {s["id"] for s in users_data.get("schools", [])}
#             tp_assignments = {a["id"] for a in users_data.get("tp_assignments", [])}
            
#             for a in users_data.get("tp_assignments", []):
#                 if a["traineeId"] not in trainees:
#                     logger.warning(f"Invalid tp_assignment: traineeId {a['traineeId']} not found")
#                 if a.get("supervisorId") and a["supervisorId"] not in supervisors:
#                     logger.warning(f"Invalid tp_assignment: supervisorId {a['supervisorId']} not found")
#                 if a.get("schoolId") and a["schoolId"] not in schools:
#                     logger.warning(f"Invalid tp_assignment: schoolId {a['schoolId']} not found")
#                 for date_key in ["startDate", "endDate"]:
#                     date_val = a.get(date_key)
#                     if date_val and isinstance(date_val, str):
#                         try:
#                             parsed = datetime.strptime(date_val, "%Y-%m-%d")
#                             a[date_key] = parsed.strftime("%Y-%m-%d")
#                         except ValueError:
#                             logger.warning(f"Invalid {date_key} in tp_assignment {a['id']}: {date_val}")
#                             a[date_key] = ""
            
#             # Validate supervisor_schedule
#             lesson_plans = {lp["id"] for lp in users_data.get("lesson_plans", [])}
#             for s in users_data.get("supervisor_schedule", []):
#                 if s.get("lesson_plan_id") not in lesson_plans:
#                     logger.warning(f"Invalid supervisor_schedule: lesson_plan_id {s['lesson_plan_id']} not found")
#                 if s.get("traineeId") not in trainees:
#                     logger.warning(f"Invalid supervisor_schedule: traineeId {s['traineeId']} not found")
#                 if s.get("supervisorId") not in supervisors:
#                     logger.warning(f"Invalid supervisor_schedule: supervisorId {s['supervisorId']} not found")
#                 for date_key in ["date", "created_at"]:
#                     date_val = s.get(date_key)
#                     if date_val:
#                         try:
#                             parsed = datetime.strptime(date_val, "%Y-%m-%d")
#                             s[date_key] = parsed.strftime("%Y-%m-%d")
#                         except ValueError:
#                             logger.warning(f"Invalid {date_key} in supervisor_schedule {s['id']}: {date_val}")
#                             s[date_key] = ""
            
#             # Validate observation_feedback
#             for f in users_data.get("observation_feedback", []):
#                 if f.get("lesson_plan_id") not in lesson_plans:
#                     logger.warning(f"Invalid observation_feedback: lesson_plan_id {f['lesson_plan_id']} not found")
#                 if f.get("traineeId") not in trainees:
#                     logger.warning(f"Invalid observation_feedback: traineeId {f['traineeId']} not found")
#                 if f.get("supervisorId") not in supervisors:
#                     logger.warning(f"Invalid observation_feedback: supervisorId {f['supervisorId']} not found")
#                 if f.get("created_at"):
#                     try:
#                         parsed = datetime.strptime(f["created_at"], "%Y-%m-%d")
#                         f["created_at"] = parsed.strftime("%Y-%m-%d")
#                     except ValueError:
#                         logger.warning(f"Invalid created_at in observation_feedback {f['id']}: {f['created_at']}")
#                         f["created_at"] = ""
            
#             # Validate and clean student_evaluations
#             valid_evaluations = []
#             for e in users_data.get("student_evaluations", []):
#                 if e.get("traineeId") not in trainees:
#                     logger.warning(f"Removing invalid student_evaluation: traineeId {e['traineeId']} not found")
#                     continue
#                 if e.get("supervisorId") not in supervisors:
#                     logger.warning(f"Removing invalid student_evaluation: supervisorId {e['supervisorId']} not found")
#                     continue
#                 if e.get("tpAssignmentId") not in tp_assignments:
#                     logger.warning(f"Removing invalid student_evaluation: tpAssignmentId {e['tpAssignmentId']} not found")
#                     continue
#                 if e.get("submittedAt"):
#                     try:
#                         parsed = datetime.strptime(e["submittedAt"], "%Y-%m-%d")
#                         e["submittedAt"] = parsed.strftime("%Y-%m-%d")
#                     except ValueError:
#                         logger.warning(f"Invalid submittedAt in student_evaluation {e['id']}: {e['submittedAt']}")
#                         e["submittedAt"] = ""
#                 valid_evaluations.append(e)
            
#             users_data["student_evaluations"] = valid_evaluations
#             if len(valid_evaluations) < len(users_data.get("student_evaluations", [])):
#                 logger.info(f"Cleaned {len(users_data.get('student_evaluations', [])) - len(valid_evaluations)} invalid student_evaluations")
            
#             logger.debug(f"Successfully loaded users from {USERS_FILE}")
#             return users_data
#     except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
#         logger.error(f"Error loading {USERS_FILE}: {str(e)}. Initializing with mock data.")
#         save_users(users)
#         return users

# def generate_unique_id() -> str:
    """Generate a unique UUID."""
    return str(uuid.uuid4())