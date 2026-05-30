from fastapi import FastAPI, HTTPException, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from auth import hash_password, verify_password, create_access_token, get_current_user
from models import User
from database import get_db, engine
from models import Base
from datetime import datetime
from mongo import login_signals
from anomaly import analyze_login

Base.metadata.create_all(bind=engine)

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Server is running"}

@app.get("/health")
async def health_check():
    return {"status": "running"}

class LoginRequest(BaseModel):
    email: str
    password: str

class RegisterRequest(BaseModel):
    email: str
    password: str

@app.post("/auth/register")
async def register(request:RegisterRequest, db: Session = Depends(get_db)):
    hashed = hash_password(request.password)
    user = User(email=request.email, password_hash = hashed)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "User registered successfully", "email":user.email,}

@app.post("/auth/login")
async def login (req : Request , request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=401, detail = "Invalid Credentials")
    if not verify_password(request.password, user.password_hash):
        raise HTTPException(status_code =401, detail = "Invalid Credentials")
    token = create_access_token({"sub": user.email})
    signal = {
        "email":user.email,
        "timestamp":datetime.utcnow(),
        "ip_address":req.client.host,
        "user_agent": req.headers.get("user-agent")
    }
    login_signals.insert_one(signal)
    return{"access_token": token, "token_type":"bearer"}

@app.get("/protected")
async def protected_route (current_user = Depends(get_current_user)):
    return{"email":current_user}

@app.get("/auth/analyze/{email}")
def analyze_user(email:str, current_user:str = Depends(get_current_user)):
    result = analyze_login(email)
    return result
    
