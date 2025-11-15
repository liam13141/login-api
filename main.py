from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
import json, os, hashlib, random

app = FastAPI(title="FM Radio Login API", description="Smart Login API + Admin Panel")

# ====== CORS ======
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ====== User Storage ======
DB_FILE = "users.json"

def load_users():
    if not os.path.exists(DB_FILE): 
        return {}
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}

def save_users(data):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def hash_pw(pw: str):
    return hashlib.sha256(pw.encode()).hexdigest()

# ====== Error Codes ======
ERRORS = {
    1: "API may be down or you are offline.",
    2: "It seems like you are using a VPN — please turn it off to login.",
    3: "Suspicious login attempt detected.",
    4: "Account is banned or temporarily locked.",
    5: "Invalid username or password.",
    6: "Username already exists.",
    7: "Too many login attempts — slow down!",
    8: "Server could not verify your IP address.",
    9: "Unexpected internal error. Please try again later.",
    10: "Connection timeout. Please refresh the page."
}

# ====== VPN / Network Simulation ======
def simulate_network_check(ip: str):
    if not ip or ip == "127.0.0.1":
        raise HTTPException(status_code=503, detail={"code": 1, "message": ERRORS[1]})

    if any(bad in ip for bad in ["10.", "172.", "192.168."]):
        raise HTTPException(status_code=400, detail={"code": 2, "message": ERRORS[2]})

    if random.random() < 0.02:
        raise HTTPException(status_code=500, detail={"code": 9, "message": ERRORS[9]})


# ============================================================
#                     MAIN ROUTES
# ============================================================

@app.get("/")
def home():
    return {"message": "FM Radio Login API online!"}


# SIGNUP
@app.post("/signup")
def signup(username: str = Form(...), password: str = Form(...)):
    users = load_users()
    if username in users:
        raise HTTPException(status_code=400, detail={"code": 6, "message": ERRORS[6]})

    users[username] = {"password": hash_pw(password), "banned": False}
    save_users(users)
    return {"success": True, "message": f"Account created for {username}"}


# LOGIN
@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    client_ip = request.client.host
    simulate_network_check(client_ip)

    users = load_users()

    if username not in users:
        raise HTTPException(status_code=401, detail={"code": 5, "message": ERRORS[5]})

    if users[username].get("banned"):
        raise HTTPException(status_code=403, detail={"code": 4, "message": ERRORS[4]})

    if users[username]["password"] != hash_pw(password):
        raise HTTPException(status_code=401, detail={"code": 5, "message": ERRORS[5]})

    # Random suspicious attempt detection
    if random.randint(1, 20) == 10:
        raise HTTPException(status_code=403, detail={"code": 3, "message": ERRORS[3]})

    return {"success": True, "user": username, "message": f"Welcome back, {username}!"}


# DELETE ACCOUNT (no password required)
@app.post("/delete")
def delete(username: str = Form(...)):
    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail={"code": 5, "message": "Account not found"})
    del users[username]
    save_users(users)
    return {"success": True, "message": f"Account '{username}' deleted successfully."}


# BAN
@app.post("/ban")
def ban(username: str = Form(...)):
    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail={"code": 5, "message": "User not found"})
    users[username]["banned"] = True
    save_users(users)
    return {"success": True, "message": f"User {username} has been banned."}


# UNBAN
@app.post("/unban")
def unban(username: str = Form(...)):
    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail={"code": 5, "message": "User not found"})
    users[username]["banned"] = False
    save_users(users)
    return {"success": True, "message": f"User {username} has been unbanned."}



# ============================================================
#                     ADMIN PANEL (HTML)
# ============================================================

@app.get("/admin", response_class=HTMLResponse)
def admin_panel():
    users = load_users()

    html = """
    <html>
    <head>
        <title>FM Radio Admin Panel</title>
        <style>
            body { font-family: Arial; background: #0d1117; color: #f1f5f9; text-align: center; padding: 20px; }
            table { width: 80%; margin: auto; border-collapse: collapse; }
            th, td { padding: 12px; border-bottom: 1px solid #333; }
            .btn { padding: 8px 14px; border-radius:6px; cursor:pointer; border:none; }
            .ban { background:#d9534f; color:white; }
            .unban { background:#5cb85c; color:white; }
            .delete { background:#ff4444; color:white; }
        </style>
    </head>
    <body>
        <h1>FM Radio Admin Panel</h1>
        <table>
            <tr><th>User</th><th>Status</th><th>Actions</th></tr>
    """

    for user, info in users.items():
        banned = info.get("banned", False)
        status = "🚫 Banned" if banned else "✔ Active"
        html += f"""
        <tr>
            <td>{user}</td>
            <td>{status}</td>
            <td>
                <button class="btn {'unban' if banned else 'ban'}" onclick="action('{user}', '{'unban' if banned else 'ban'}')">
                    {'Unban' if banned else 'Ban'}
                </button>
                <button class="btn delete" onclick="action('{user}', 'delete')">Delete</button>
            </td>
        </tr>
        """

    html += """
        </table>

        <script>
        function action(user, type) {
            let url = '/' + type;
            let body = new URLSearchParams({ username: user });

            fetch(url, { method: 'POST', body })
            .then(r => r.json())
            .then(d => { alert(d.message); location.reload(); })
        }
        </script>

    </body>
    </html>
    """

    return html


# ============================================================
#                  CUSTOM ERROR HANDLER
# ============================================================

@app.exception_handler(HTTPException)
def errors(req: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": exc.detail,
            "source": "FM Login API"
        }
    )
