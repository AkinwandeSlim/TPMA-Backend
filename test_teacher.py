import requests
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_URL = "http://localhost:5000/api"
HEADERS = {"Content-Type": "application/json"}

# Trainee credentials from mockdata.py
TRAINEE_CREDENTIALS = {
    "userType": "teacherTrainee",
    "identifier": "SLU/EDU/001",  # Trainee with id=101
    "password": "Train1#ecure2025!"
}

def login():
    """Login as a teacherTrainee and return the token."""
    url = f"{BASE_URL}/login"
    response = requests.post(url, headers=HEADERS, data=json.dumps(TRAINEE_CREDENTIALS))
    if response.status_code == 200:
        data = response.json()
        logger.info("Login successful for teacherTrainee")
        return data["token"]
    else:
        logger.error(f"Login failed: {response.status_code} - {response.text}")
        raise Exception("Login failed")

def test_verify(token):
    """Test the /api/verify endpoint."""
    url = f"{BASE_URL}/verify"
    headers = HEADERS.copy()
    headers["Authorization"] = f"Bearer {token}"
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        assert data["role"] == "teacherTrainee"
        assert data["identifier"] == TRAINEE_CREDENTIALS["identifier"]
        logger.info("Verify endpoint test passed")
    else:
        logger.error(f"Verify endpoint failed: {response.status_code} - {response.text}")
        raise AssertionError("Verify endpoint failed")

def test_get_supervisor(token):
    """Test the /api/trainees/<id>/supervisor endpoint."""
    trainee_id = "101"  # Matches SLU/EDU/001
    url = f"{BASE_URL}/trainees/{trainee_id}/supervisor"
    headers = HEADERS.copy()
    headers["Authorization"] = f"Bearer {token}"
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        print(f"API RESPONSE: {data} ")
        # Validate assignment details from mockdata
        assert data["assignment"]["traineeId"] == trainee_id
        assert data["assignment"]["supervisorId"] == "2"  # From tp_assignments: tp1
        assert data["assignment"]["schoolId"] == "school2"
        assert "supervisor" in data
        assert data["supervisor"]["id"] == "2"
        logger.info("Get supervisor endpoint test passed")
    else:
        logger.error(f"Get supervisor failed: {response.status_code} - {response.text}")
        raise AssertionError("Get supervisor endpoint failed")

def test_feedback_history(token):
    """Test the /api/trainees/<trainee_id>/feedback-history endpoint."""
    trainee_id = "101"
    url = f"{BASE_URL}/trainees/{trainee_id}/feedback-history"
    headers = HEADERS.copy()
    headers["Authorization"] = f"Bearer {token}"
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        feedback = data["feedback"]
        # Validate feedback from mockdata
        assert len(feedback) > 0
        assert feedback[0]["traineeId"] == trainee_id
        assert feedback[0]["supervisorId"] == "2"  # From feedback: fb1
        logger.info("Feedback history endpoint test passed")
    else:
        logger.error(f"Feedback history failed: {response.status_code} - {response.text}")
        raise AssertionError("Feedback history endpoint failed")

def test_notifications(token):
    """Test the /api/notifications endpoint for a trainee."""
    url = f"{BASE_URL}/notifications"
    headers = HEADERS.copy()
    headers["Authorization"] = f"Bearer {token}"
    response = requests.get(url, headers=headers)
    # print()
    if response.status_code == 200:
        data = response.json()
        notifications = data["notifications"]
      
      
        # Validate notifications for user_id=1 (or initiator_id)
        assert len(notifications) > 0
        assert any(n["user_id"] == "1" or n["initiator_id"] == "1" for n in notifications)
        logger.info("Notifications endpoint test passed")
    else:
        logger.error(f"Notifications failed: {response.status_code} - {response.text}")
        raise AssertionError("Notifications endpoint failed")

def test_unauthorized_access(token):
    """Test unauthorized access to another trainee's data."""
    other_trainee_id = "102"  # Different trainee
    url = f"{BASE_URL}/trainees/{other_trainee_id}/feedback-history"
    headers = HEADERS.copy()
    headers["Authorization"] = f"Bearer {token}"
    response = requests.get(url, headers=headers)
    
    if response.status_code == 403:
        logger.info("Unauthorized access test passed")
    else:
        logger.error(f"Unauthorized access test failed: {response.status_code} - {response.text}")
        raise AssertionError("Unauthorized access test failed")

def run_tests():
    """Run all tests."""
    try:
        # Step 1: Login
        token = login()
        
        # Step 2: Test endpoints
        test_verify(token)
        test_get_supervisor(token)
        # test_feedback_history(token)
        # test_notifications(token)
        test_unauthorized_access(token)
        
        logger.info("All tests passed successfully!")
    except Exception as e:
        logger.error(f"Test failed: {str(e)}")
        raise

if __name__ == "__main__":
    run_tests()