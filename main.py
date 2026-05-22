from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from auth import hash_password, verify_password
from models import User
from database import get_db, engine
from models import Base

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
    return {"message": "User registered successfully", "email":user.email}

@app.post("/auth/login")
async def login (request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail = "User not found")
    if not verify_password(request.password, user.password_hash):
        raise HTTPException(status_code =401, detail = "Incorrect Password")
    return{"message":"Login Successful","email":"user.email"}
    
