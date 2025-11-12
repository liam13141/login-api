from fastapi import FastAPI, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import json, os

app = FastAPI(title="FM Radio Login API", description="Login system with auto-login, ban system, and delete account")

# Allow local HTML/JS access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_FILE = "users.json"

def load_users():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def save_users(users):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)

class BanModel(BaseModel):
    username: str

@app.get("/")
def home():
    return {"message": "✅ FM Radio Login API is running!"}

@app.post("/signup")
def signup(username: str = Form(...), password: str = Form(...)):
    users = load_users()
    if username in users:
        raise HTTPException(status_code=400, detail="Username already exists")
    users[username] = {"password": password, "banned": False}
    save_users(users)
    return {"message": f"Account created for {username}"}

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    if users[username]["password"] != password:
        raise HTTPException(status_code=401, detail="Incorrect password")
    if users[username].get("banned", False):
        return {"message": "User is banned", "user": username, "banned": True}
    return {"message": f"Welcome back, {username}!", "user": username, "banned": False}

@app.post("/ban")
def ban_user(data: BanModel):
    users = load_users()
    if data.username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    users[data.username]["banned"] = True
    save_users(users)
    return {"message": f"{data.username} has been banned."}

@app.post("/unban")
def unban_user(data: BanModel):
    users = load_users()
    if data.username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    users[data.username]["banned"] = False
    save_users(users)
    return {"message": f"{data.username} has been unbanned."}

@app.post("/logout")
def logout():
    return {"message": "Logged out successfully"}

# 🗑️ NEW: Delete Account
@app.post("/delete")
def delete_account(username: str = Form(...), password: str = Form(...)):
    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    if users[username]["password"] != password:
        raise HTTPException(status_code=401, detail="Incorrect password")
    
    del users[username]
    save_users(users)
    return {"message": f"Account '{username}' deleted successfully."}

# --------------------------
# Developer Panel (HTML)
# --------------------------
@app.get("/dev", response_class=HTMLResponse)
def dev_panel():
    users = load_users()
    html = """
    <html>
    <head>
        <title>FM Radio Developer Panel</title>
        <style>
            body { font-family: Poppins, sans-serif; background: #0f172a; color: #f1f5f9; text-align: center; }
            h1 { color: #38bdf8; }
            table { margin: 20px auto; border-collapse: collapse; width: 80%; }
            th, td { padding: 12px 20px; border-bottom: 1px solid #334155; }
            button { padding: 8px 16px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; }
            .ban { background: #ef4444; color: white; }
            .unban { background: #22c55e; color: white; }
            .delete { background: #f87171; color: white; }
            .status { font-weight: 500; }
            #logoutBtn { margin-top: 20px; background: #6366f1; color: white; padding: 10px 20px; border-radius: 8px; }
        </style>
    </head>
    <body>
        <h1>🛠️ FM Radio Developer Panel</h1>
        <table>
            <tr><th>Username</th><th>Status</th><th>Actions</th></tr>
    """
    for username, info in users.items():
        banned = info.get("banned", False)
        status = "🚫 Banned" if banned else "✅ Active"
        button_label = "Unban" if banned else "Ban"
        button_class = "unban" if banned else "ban"
        html += f"""
            <tr id='row-{username}'>
                <td>{username}</td>
                <td class='status'>{status}</td>
                <td>
                    <button class='{button_class}' onclick="toggleBan('{username}', {str(banned).lower()})">{button_label}</button>
                    <button class='delete' onclick="deleteAccount('{username}')">🗑️ Delete</button>
                </td>
            </tr>
        """
    html += """
        </table>
        <button id="logoutBtn" onclick="logout()">🚪 Log Out</button>

        <script>
        // Toggle Ban/Unban
        async function toggleBan(username, isBanned) {
            const endpoint = isBanned ? '/unban' : '/ban';
            const body = JSON.stringify({ username });
            const headers = { 'Content-Type': 'application/json' };
            const res = await fetch(endpoint, { method: 'POST', headers, body });
            const data = await res.json();
            alert(data.message);
            location.reload();
        }

        // 🗑️ Delete Account
        async function deleteAccount(username) {
            if (!confirm(`Are you sure you want to permanently delete '${username}'?`)) return;
            const password = prompt("Enter the password for this account to confirm:");
            if (!password) return alert("Deletion cancelled.");
            const form = new FormData();
            form.append("username", username);
            form.append("password", password);
            const res = await fetch("/delete", { method: "POST", body: form });
            const data = await res.json();
            alert(data.message);
            location.reload();
        }

        // Logout
        async function logout() {
            localStorage.removeItem('fmradio_user');
            localStorage.removeItem('fmradio_pass');
            const res = await fetch('/logout', { method: 'POST' });
            const data = await res.json();
            alert(data.message);
            location.reload();
        }
        </script>
    </body>
    </html>
    """
    return html
