"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.hash import sha256_crypt
import json
from typing import Optional
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import os
from pathlib import Path

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

# Auth config
SECRET_KEY = "supersecretkey123"  # 生产环境请更换
ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# Load teacher users
with open(os.path.join(current_dir, "config", "users.json")) as f:
    users_data = json.load(f)
TEACHERS = {u["username"]: u for u in users_data["teachers"]}

def authenticate_user(username: str, password: str) -> Optional[dict]:
    user = TEACHERS.get(username)
    if not user:
        return None
    # 密码为 sha256 哈希
    if user["password"] != sha256_crypt.hash(password) and user["password"] != password:
        return None
    return user

def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None or username not in TEACHERS:
            raise credentials_exception
        return TEACHERS[username]
    except JWTError:
        raise credentials_exception


# 登录接口
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token({"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities



# 只有教师可注册/注销
@app.post("/activities/{activity_name}/signup")
def signup_for_activity(activity_name: str, email: str, user: dict = Depends(get_current_user)):
    """Sign up a student for an activity (admin only)"""
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")
    activity = activities[activity_name]
    if email in activity["participants"]:
        raise HTTPException(status_code=400, detail="Student is already signed up")
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}



@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(activity_name: str, email: str, user: dict = Depends(get_current_user)):
    """Unregister a student from an activity (admin only)"""
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")
    activity = activities[activity_name]
    if email not in activity["participants"]:
        raise HTTPException(status_code=400, detail="Student is not signed up for this activity")
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
