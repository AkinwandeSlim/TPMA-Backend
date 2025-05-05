import requests
import json
import logging
from typing import Dict, Any

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_URL = "http://localhost:5000/api"



SUPERVISOR_USERTYPE = "supervisor"
SUPERVISOR_STAFF_ID = "STAFF002"
SUPERVISOR_PASSWORD = "Super2$ecure2025!"



SUPERVISOR_ID = "sup1"  # Replace with a valid supervisor ID from users.json
LESSON_PLAN_ID = "1"  # Replace with a valid lesson plan ID assigned to the supervisor
TRAINEE_ID = "101"  # Replace with a valid trainee ID assigned to the supervisor
OBSERVATION_ID = "obs1"  # Replace with a valid observation ID (may need to create one)



def authenticate() -> Dict[str, Any]:
    """Authenticate as a supervisor and return the JWT token."""
    url = f"{BASE_URL}/login"
    payload = {
        "userType": "supervisor",
        "identifier": "STAFF002",
        "password":"Super2$ecure2025!"
    }
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        data = response.json()
        token = data.get("token")
        if not token:
            raise ValueError("No token received")
        logger.info("Authentication successful")
        return {"Authorization": f"Bearer {token}"}
    except requests.RequestException as e:
        logger.error(f"Authentication failed: {str(e)}")
        return {}

def test_review_lesson_plan(headers: Dict[str, Any]):
    """Test reviewing a lesson plan."""
    url = f"{BASE_URL}/supervisors/{SUPERVISOR_ID}/lesson-plans/{LESSON_PLAN_ID}/review"
    payload = {
        "status": "APPROVED",
        "comments": "Well-structured plan, good objectives."
    }
    try:
        response = requests.put(url, json=payload, headers=headers)
        response.raise_for_status()
        logger.info(f"Review Lesson Plan: {response.json()}")
    except requests.RequestException as e:
        logger.error(f"Review Lesson Plan failed: {str(e)} - {response.text}")

def test_schedule_observation(headers: Dict[str, Any]):
    """Test scheduling an observation."""
    url = f"{BASE_URL}/supervisors/{SUPERVISOR_ID}/schedule-observation"
    payload = {
        "lesson_plan_id": LESSON_PLAN_ID,
        "trainee_id": TRAINEE_ID,
        "date": "2025-05-01",
        "start_time": "09:00",
        "end_time": "10:00"
    }
    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        logger.info(f"Schedule Observation: {response.json()}")
    except requests.RequestException as e:
        logger.error(f"Schedule Observation failed: {str(e)} - {response.text}")

def test_submit_observation_feedback(headers: Dict[str, Any]):
    """Test submitting observation feedback."""
    url = f"{BASE_URL}/supervisors/{SUPERVISOR_ID}/observations/{OBSERVATION_ID}/feedback"
    payload = {
        "score": 8,
        "comments": "Good delivery, but pacing could be improved."
    }
    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        logger.info(f"Submit Observation Feedback: {response.json()}")
    except requests.RequestException as e:
        logger.error(f"Submit Observation Feedback failed: {str(e)} - {response.text}")

def test_get_trainees(headers: Dict[str, Any]):
    """Test fetching assigned trainees."""
    url = f"{BASE_URL}/supervisors/{SUPERVISOR_ID}/trainees?page=1"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        logger.info(f"Get Trainees: {response.json()}")
    except requests.RequestException as e:
        logger.error(f"Get Trainees failed: {str(e)} - {response.text}")

def test_get_schedules(headers: Dict[str, Any]):
    """Test fetching observation schedules."""
    url = f"{BASE_URL}/supervisors/{SUPERVISOR_ID}/schedules?page=1"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        logger.info(f"Get Schedules: {response.json()}")
    except requests.RequestException as e:
        logger.error(f"Get Schedules failed: {str(e)} - {response.text}")

def main():
    """Run all tests."""
    headers = authenticate()
    if not headers:
        logger.error("Aborting tests due to authentication failure")
        return
    
    logger.info("Starting endpoint tests...")
    test_review_lesson_plan(headers)
    # test_schedule_observation(headers)
    # test_submit_observation_feedback(headers)
    # test_get_trainees(headers)
    # test_get_schedules(headers)
    logger.info("All tests completed.")

if __name__ == "__main__":
    main()