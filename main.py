from fastapi import FastAPI, Form, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import json, os

app = FastAPI(title="FM Radio Login API", description="Login system with IP ban-evasion prevention")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_FILE = "users.json"
BAN_IP_FILE = "banned_ips.json"


# ---------- HELPERS ----------
def load_json(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        try:
            return json.load(f)
        except:
            return {}

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def get_ip(request: Request):
    return request.client.host


# ---------- HOME ----------
@app.get("/")
def home():
    return {"message": "FM Radio Login API running!"}


# ---------- SIGNUP ----------
@app.post("/signup")
def signup(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = get_ip(request)
    users = load_json(DB_FILE)
    banned_ips = load_json(BAN_IP_FILE)

    # BLOCK signup from banned IP
    if ip in banned_ips:
        raise HTTPException(403, detail="Signup blocked — your IP is banned.")

    if username in users:
        raise HTTPException(400, detail="Username already exists")

    # Create account + store IP
    users[username] = {
        "password": password,
        "banned": False,
        "ip": ip
    }

    save_json(DB_FILE, users)
    return {"message": f"Account created for {username}"}


# ---------- LOGIN ----------
@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = get_ip(request)
    users = load_json(DB_FILE)
    banned_ips = load_json(BAN_IP_FILE)

    # IF IP IS BANNED → BLOCK LOGIN
    if ip in banned_ips:
        raise HTTPException(403, detail="Access denied — your IP is banned.")

    if username not in users:
        raise HTTPException(404, detail="User not found")

    user = users[username]

    # Incorrect password
    if user["password"] != password:
        raise HTTPException(401, detail="Incorrect password")

    # User account banned
    if user.get("banned", False):
        return {"message": "User is banned", "user": username, "banned": True}

    return {"message": f"Welcome back, {username}!", "user": username, "banned": False}


# ---------- ADMIN BAN ----------
@app.post("/ban")
def ban_user(username: str = Form(...)):
    users = load_json(DB_FILE)
    banned_ips = load_json(BAN_IP_FILE)

    if username not in users:
        raise HTTPException(404, detail="User not found")

    ip = users[username].get("ip")

    # Ban account
    users[username]["banned"] = True

    # Ban IP
    if ip:
        banned_ips[ip] = True

    save_json(DB_FILE, users)
    save_json(BAN_IP_FILE, banned_ips)

    return {"message": f"{username} and IP {ip} have been banned."}


# ---------- ADMIN UNBAN ----------
@app.post("/unban")
def unban_user(username: str = Form(...)):
    users = load_json(DB_FILE)
    banned_ips = load_json(BAN_IP_FILE)

    if username not in users:
        raise HTTPException(404, detail="User not found")

    ip = users[username].get("ip")

    # Unban account
    users[username]["banned"] = False

    # Remove IP ban
    if ip in banned_ips:
        del banned_ips[ip]

    save_json(DB_FILE, users)
    save_json(BAN_IP_FILE, banned_ips)

    return {"message": f"{username} and IP {ip} have been unbanned."}
