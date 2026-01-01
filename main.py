from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
import requests, json, re, sqlite3
import bcrypt
from datetime import datetime, timedelta
import jwt

# ---------------------------
# CONFIG 
# ---------------------------
API_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "meta-llama/llama-4-maverick"
API_KEY = "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"  
JWT_SECRET = "n3f8K#4pQ!vZ2xR9tL1m"         
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60

HEADERS = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
MAX_TOKENS = 300

SYSTEM_PROMPT = """
You are a professional quiz master AI.
Rules:
- Respond ONLY in valid JSON
- Never repeat a question
- Match difficulty strictly
"""

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

app = FastAPI(title="TriviAI Backend")

# CORS Configuration for React Native
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development - restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------
# DATABASE INIT
# ---------------------------
DB_FILE = "trivia.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Check if table exists
    c.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='users'")
    if c.fetchone()[0] == 0:
        c.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            xp INTEGER DEFAULT 0
        )
        """)
    else:
        # Simple migration for dev: check if email column exists, if not add it
        # This prevents needing to delete the DB manually
        try:
            c.execute("SELECT email FROM users LIMIT 1")
        except sqlite3.OperationalError:
            c.execute("ALTER TABLE users ADD COLUMN email TEXT UNIQUE DEFAULT ''")
    
    conn.commit()
    conn.close()

init_db()

# ---------------------------
# SCHEMAS
# ---------------------------
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class QuizGenerateRequest(BaseModel):
    topic: str
    quiz_type: str           # MCQ | True/False | Programming | Riddle
    difficulty: str          # Easy | Medium | Hard | Very Hard
    asked_questions: List[str] = []

class QuizSubmitRequest(BaseModel):
    user_answer: str
    correct_answer: str

class QuizSubmitResponse(BaseModel):
    correct: bool
    xp_earned: int
    level: int

# ---------------------------
# UTILS
# ---------------------------
def get_password_hash(password: str) -> str:
    """Hash password using bcrypt. Passwords are automatically truncated to 72 bytes by bcrypt."""
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against bcrypt hash."""
    password_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=JWT_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, username, xp, email FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    
    if row is None:
        raise HTTPException(status_code=401, detail="User not found")
    
    return {"id": row[0], "username": row[1], "xp": row[2], "email": row[3]}

def call_llm(prompt: str) -> dict:
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": MAX_TOKENS
    }
    r = requests.post(API_URL, headers=HEADERS, json=payload, timeout=30)
    r.raise_for_status()
    content = r.json()["choices"][0]["message"]["content"]
    return extract_json(content)

def extract_json(text: str) -> dict:
    match = re.search(r"\{(?:.|\n)*\}", text)
    if not match:
        raise ValueError("Invalid JSON from AI")
    return json.loads(match.group())

def calculate_level(xp: int) -> int:
    return min(xp // 100, 10)

# ---------------------------
# AUTH ENDPOINTS
# ---------------------------
@app.post("/auth/signup", response_model=Token)
def signup(user: UserCreate):
    # Basic email validation
    if not re.match(r"[^@]+@[^@]+\.[^@]+", user.email):
        raise HTTPException(status_code=400, detail="Invalid email address")

    hashed_password = get_password_hash(user.password)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (user.username, user.email, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError as e:
        conn.close()
        # Check which constraint failed
        if "username" in str(e):
            raise HTTPException(status_code=400, detail="Username already exists")
        elif "email" in str(e):
            raise HTTPException(status_code=400, detail="Email already exists")
        else:
             raise HTTPException(status_code=400, detail="User already exists")
        
    conn.close()
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT username, password FROM users WHERE username=?", (form_data.username,))
    row = c.fetchone()
    conn.close()
    if row is None or not verify_password(form_data.password, row[1]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token({"sub": row[0]})
    return {"access_token": token, "token_type": "bearer"}

# ---------------------------
# USER ENDPOINTS
# ---------------------------
@app.get("/user/profile")
def get_user_profile(user=Depends(get_current_user)):
    level = calculate_level(user["xp"])
    return {
        "username": user["username"],
        "email": user["email"] if "email" in user.keys() else "", # Handle legacy users or if column missing in dict (though row factory handled elsewhere?) Wait, user is a dict from get_current_user
        "xp": user["xp"],
        "level": level
    }

@app.get("/user/leaderboard")
def get_leaderboard():
    """Get top 100 users ranked by XP"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        SELECT username, xp 
        FROM users 
        ORDER BY xp DESC 
        LIMIT 100
    """)
    rows = c.fetchall()
    conn.close()
    
    leaderboard = []
    for idx, row in enumerate(rows, start=1):
        username, xp = row
        level = calculate_level(xp)
        leaderboard.append({
            "rank": idx,
            "username": username,
            "xp": xp,
            "level": level
        })
    
    return {"leaderboard": leaderboard}

# ---------------------------
# QUIZ ENDPOINTS
# ---------------------------
@app.post("/quiz/generate")
def generate_quiz(req: QuizGenerateRequest, user=Depends(get_current_user)):
    if req.quiz_type == "Programming":
        prompt = f"""
Generate exactly one short programming quiz question.
Return JSON only.
Keys: question, type, answer
Programming Language: {req.topic}
Difficulty: {req.difficulty}
Do not repeat: {req.asked_questions}
"""
    elif req.quiz_type == "Riddle":
        prompt = f"""
Generate exactly one fun riddle.
Return JSON only.
Keys: question, type, answer
Difficulty: {req.difficulty}
Do not repeat: {req.asked_questions}
"""
    else:
        prompt = f"""
Generate exactly one quiz question.
Return JSON only.
Keys: question, options, answer, type
Topic: {req.topic}
Difficulty: {req.difficulty}
Type: {req.quiz_type}
Do not repeat: {req.asked_questions}
"""

    try:
        return call_llm(prompt)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/quiz/submit", response_model=QuizSubmitResponse)
def submit_answer(req: QuizSubmitRequest, user=Depends(get_current_user)):
    correct = req.user_answer.strip().lower() == req.correct_answer.strip().lower()
    xp_earned = 10 if correct else 0

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    new_xp = user["xp"] + xp_earned
    c.execute("UPDATE users SET xp=? WHERE id=?", (new_xp, user["id"]))
    conn.commit()
    conn.close()

    level = calculate_level(new_xp)
    return {"correct": correct, "xp_earned": xp_earned, "level": level}
