from pydantic import BaseModel
import json, os

app = FastAPI(title="FM Radio Login API", description="Login system with auto-login, ban system, and delete account")
app = FastAPI(title="FM Radio Login API", description="Login system with auto-login, ban system, and instant delete account")

# Allow local HTML/JS access
app.add_middleware(
@@ -79,15 +79,13 @@ def unban_user(data: BanModel):
def logout():
    return {"message": "Logged out successfully"}

# 🗑️ NEW: Delete Account
# 🗑️ Instant Delete Account (no password required)
@app.post("/delete")
def delete_account(username: str = Form(...), password: str = Form(...)):
def delete_account(username: str = Form(...)):
    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    if users[username]["password"] != password:
        raise HTTPException(status_code=401, detail="Incorrect password")
    

    del users[username]
    save_users(users)
    return {"message": f"Account '{username}' deleted successfully."}
@@ -151,14 +149,11 @@ def dev_panel():
            location.reload();
        }

        // 🗑️ Delete Account
        // 🗑️ Instant Delete Account
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
