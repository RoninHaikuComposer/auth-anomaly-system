from fastapi import FastAPI, HTTPException, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from auth import hash_password, verify_password, create_access_token, get_current_user, SECRET_KEY, ALGORITHM
from models import User
from database import get_db, engine
from models import Base
from datetime import datetime
from mongo import login_signals
from anomaly import analyze_login
from risk import risk_analysis
from session_manager import start_session, log_request, end_session
from jose import JWTError, jwt
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from lockout import check_lockout , update_lockout
import os



Base.metadata.create_all(bind=engine)

app = FastAPI()
@app.middleware("http")
async def session_middleware(request, call_next):
    auth_header = request.headers.get("authorization")
    if auth_header is None:
        return await call_next(request)
    token = auth_header.split(" ")[1]
    try:
        user_data = get_current_user(token)
        session_id = user_data["session_id"]
        log_request(session_id, request.url.path)
        return await call_next(request)

    except  HTTPException:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms = [ALGORITHM], options = {"verify_exp":False})
            session_id = payload.get("session_id")
            end_session(session_id)
        except:
            pass
        return JSONResponse(status_code = 401, content = {"detail":"Invalid/Expired Token"})
        




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
    
    try:
       db.add(user)
       db.commit()
       db.refresh(user)
       return {"message": "User registered successfully", "email":user.email}
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code = 409, detail = "Email already exists")
    
@app.post("/auth/login")
async def login (req : Request , request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=401, detail = "Invalid Credentials")
    if check_lockout(user) == True:
        raise HTTPException(status_code = 403, detail = "Too many attempts")
    if not verify_password(request.password, user.password_hash):
        raise HTTPException(status_code =401, detail = "Invalid Credentials")
    session_id = start_session(user.email)
    token = create_access_token({"sub": user.email, "session_id":session_id})
    signal = {
        "email":user.email,
        "timestamp":datetime.utcnow(),
        "ip_address":req.client.host,
        "user_agent": req.headers.get("user-agent")
        
    }
    login_signals.insert_one(signal)
    result = analyze_login(request.email)
    if result["verdict"] == "insufficient_data":
        return result
    risk_level, action = risk_analysis(result["score"])
    if action == "block":
        update_lockout(user, db)
        raise HTTPException(status_code = 403, detail = "forbidden")
    
    return{"access_token": token, "token_type":"bearer"}




@app.get("/protected")
async def protected_route (current_user = Depends(get_current_user)):
    return{"email":current_user}

@app.get("/auth/analyze/{email}")
def analyze_user(email:str, current_user:dict = Depends(get_current_user)):
    result = analyze_login(email)
    risk_level, action = risk_analysis(result["score"])
    return { "verdict" : result["verdict"], "score": result["score"], "risk_level" : risk_level, "action":action}
    
