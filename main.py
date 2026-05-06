import os
import subprocess
import shutil
import uuid
import time
from datetime import datetime, timedelta
from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Response, Depends, Form
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from typing import Optional
import random

import sqlite3
from contextlib import contextmanager

app = FastAPI(title="PDF OCR ji deela")

# --- Database Setup ---
DB_FILE = "database.db"

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        # Tabel User
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL
            )
        """)
        # Tabel Blacklist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_blacklist (
                ip TEXT PRIMARY KEY,
                failed_count INTEGER DEFAULT 0,
                block_until DATETIME
            )
        """)
        # Tabel History
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ocr_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                original_filename TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Insert default user if not exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", ("kpukonut",))
        if cursor.fetchone()[0] == 0:
            cursor.execute("DELETE FROM users WHERE username = ?", ("admin",)) # Hapus admin lama
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                           ("kpukonut", "123abcMetnahBRO!"))
        conn.commit()

init_db()

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_FILE)
    try:
        yield conn
    finally:
        conn.close()

# --- Security Configuration ---
SESSION_COOKIE_NAME = "pdf_ocr_session"
FAILED_ATTEMPT_LIMIT = 5
CAPTCHA_THRESHOLD = 2
BLOCK_DURATION = timedelta(days=1)

# Sessions still in memory for speed (optional to move to DB)
sessions = {}  # session_id: {username: str, expiry: datetime}
captchas = {}  # ip: answer

# Directory for temporary files
TEMP_DIR = "temp_processing"
os.makedirs(TEMP_DIR, exist_ok=True)

def get_client_ip(request: Request):
    return request.client.host

def is_ip_blocked(ip: str):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT failed_count, block_until FROM ip_blacklist WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        if row:
            failed_count, block_until_str = row
            if block_until_str:
                block_until = datetime.fromisoformat(block_until_str)
                if block_until > datetime.now():
                    return True, block_until
                elif failed_count >= FAILED_ATTEMPT_LIMIT:
                    # Block expired, reset in DB
                    cursor.execute("DELETE FROM ip_blacklist WHERE ip = ?", (ip,))
                    conn.commit()
    return False, None

async def get_current_user(request: Request):
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id or session_id not in sessions:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    if sessions[session_id]['expiry'] < datetime.now():
        del sessions[session_id]
        raise HTTPException(status_code=401, detail="Session expired")
    
    return session_id

@app.get("/", response_class=HTMLResponse)
async def read_index():
    with open("index.html", "r") as f:
        return f.read()

@app.get("/api/captcha")
async def generate_captcha(request: Request):
    ip = get_client_ip(request)
    num1 = random.randint(1, 10)
    num2 = random.randint(1, 10)
    captchas[ip] = num1 + num2
    return {"question": f"Berapa {num1} + {num2}?"}

@app.get("/api/login-status")
async def login_status(request: Request):
    ip = get_client_ip(request)
    count = 0
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT failed_count FROM ip_blacklist WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        if row:
            count = row[0]
            
    return {
        "captcha_required": count >= CAPTCHA_THRESHOLD,
        "failed_count": count
    }

@app.post("/api/login")
async def login(
    request: Request,
    response: Response,
    username: str = Form("admin"),
    password: str = Form(...),
    captcha_answer: Optional[int] = Form(None)
):
    ip = get_client_ip(request)
    
    # Check if blocked
    blocked, block_until = is_ip_blocked(ip)
    if blocked:
        time_left = block_until - datetime.now()
        hours = int(time_left.total_seconds() // 3600)
        minutes = int((time_left.total_seconds() % 3600) // 60)
        raise HTTPException(status_code=403, detail=f"IP Terblokir. Sisa waktu: {hours} jam {minutes} menit.")

    # Get current failed count
    current_fails = 0
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT failed_count FROM ip_blacklist WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        if row: current_fails = row[0]

    # Check Captcha
    if current_fails >= CAPTCHA_THRESHOLD:
        if ip not in captchas or captcha_answer is None or captcha_answer != captchas[ip]:
            raise HTTPException(status_code=400, detail="Jawaban Captcha salah atau belum diisi.")

    # Check Credentials
    authenticated = False
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row and row[0] == password:
            authenticated = True

    if authenticated:
        # Success - Reset failed attempts
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM ip_blacklist WHERE ip = ?", (ip,))
            conn.commit()
        
        session_id = str(uuid.uuid4())
        sessions[session_id] = {
            "username": username,
            "expiry": datetime.now() + timedelta(hours=12)
        }
        
        response.set_cookie(key=SESSION_COOKIE_NAME, value=session_id, httponly=True, max_age=3600 * 12)
        return {"status": "success"}
    else:
        # Fail - Update DB
        new_count = current_fails + 1
        block_until = None
        if new_count >= FAILED_ATTEMPT_LIMIT:
            block_until = (datetime.now() + BLOCK_DURATION).isoformat()
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ip_blacklist (ip, failed_count, block_until) 
                VALUES (?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET 
                    failed_count = excluded.failed_count,
                    block_until = excluded.block_until
            """, (ip, new_count, block_until))
            conn.commit()
        
        if new_count >= FAILED_ATTEMPT_LIMIT:
            raise HTTPException(status_code=403, detail="Terlalu banyak percobaan. IP Anda diblokir selama 24 jam.")
        
        raise HTTPException(status_code=401, detail=f"Password salah. Sisa percobaan: {FAILED_ATTEMPT_LIMIT - new_count}")

@app.post("/api/logout")
async def logout(response: Response, session_id: str = Depends(get_current_user)):
    if session_id in sessions:
        del sessions[session_id]
    response.delete_cookie(SESSION_COOKIE_NAME)
    return {"status": "success"}

@app.post("/api/change-password")
async def change_password(
    current_password: str = Form(...),
    new_password: str = Form(...),
    session_id: str = Depends(get_current_user)
):
    username = sessions[session_id]['username']
    
    with get_db() as conn:
        cursor = conn.cursor()
        # Verify current password
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        
        if not row or row[0] != current_password:
            raise HTTPException(status_code=400, detail="Password lama salah.")
        
        # Update to new password
        cursor.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, username))
        conn.commit()
        
    return {"status": "success", "message": "Password berhasil diubah."}

@app.get("/api/history")
async def get_history(
    q: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    page: int = 1,
    session_id: str = Depends(get_current_user)
):
    username = sessions[session_id]['username']
    limit = 10
    offset = (page - 1) * limit
    
    base_query = "FROM ocr_history WHERE username = ?"
    params = [username]
    
    if q:
        base_query += " AND original_filename LIKE ?"
        params.append(f"%{q}%")
    if start:
        base_query += " AND DATE(timestamp) >= ?"
        params.append(start)
    if end:
        base_query += " AND DATE(timestamp) <= ?"
        params.append(end)
        
    # Count total items for pagination
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT COUNT(*) {base_query}", params)
        total_items = cursor.fetchone()[0]
        
        # Get paginated data
        query = f"SELECT original_filename, timestamp {base_query} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        cursor.execute(query, params + [limit, offset])
        rows = cursor.fetchall()
        
    history = []
    for row in rows:
        history.append({
            "filename": row[0],
            "timestamp": row[1]
        })
        
    total_pages = (total_items + limit - 1) // limit
    
    return {
        "items": history,
        "total_pages": total_pages,
        "current_page": page,
        "total_items": total_items
    }

@app.get("/api/check-auth")
async def check_auth(request: Request):
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id and session_id in sessions and sessions[session_id]['expiry'] > datetime.now():
        return {"authenticated": True}
    return {"authenticated": False}

@app.post("/process")
async def process_pdf(file: UploadFile = File(...), session_id: str = Depends(get_current_user)):
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are allowed")

    job_id = str(uuid.uuid4())
    input_path = os.path.join(TEMP_DIR, f"{job_id}_input.pdf")
    output_path = os.path.join(TEMP_DIR, f"{job_id}_output.pdf")

    try:
        # Save uploaded file
        with open(input_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Run ocrmypdf
        # --skip-text: Skip OCR on pages that already contain text
        # --optimize 1: Optimize for size
        process = subprocess.run(
            ["ocrmypdf", "--force-ocr", input_path, output_path],
            capture_output=True,
            text=True
        )

        if process.returncode != 0:
            print(f"OCR Error: {process.stderr}")
            raise HTTPException(status_code=500, detail=f"OCR processing failed: {process.stderr}")

        if not os.path.exists(output_path):
            raise HTTPException(status_code=500, detail="Output file not generated")

        # Record in history
        username = sessions[session_id]['username']
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ocr_history (username, original_filename) 
                VALUES (?, ?)
            """, (username, file.filename))
            conn.commit()

        base_name = os.path.splitext(file.filename)[0]
        return FileResponse(
            output_path, 
            filename=f"{base_name}_ocr.pdf",
            media_type="application/pdf"
        )

    except Exception as e:
        print(f"Internal Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    
    # Note: Cleanup should ideally be handled after the response is sent.
    # In a real app, you'd use a background task or a periodic cleanup script.
    # For simplicity, we'll leave it to a cleanup cron/task.

@app.on_event("shutdown")
def cleanup_temp():
    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
