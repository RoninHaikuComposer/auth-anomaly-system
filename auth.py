from jose import JWTError, jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer

SECRET_KEY = "your-secret-key-keep-it-safe"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl = "/auth/login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated = "auto")

def hash_password(password: str)-> str:
    return  pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str)->bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token (data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes = ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp":expire})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm = ALGORITHM)
    return token

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms = [ALGORITHM])
        email : str = payload.get("sub")
        session_id : str = payload.get("session_id")
        if email is None:
            raise HTTPException(status_code= 401, detail = "Invalid Token")
        return {"email":email, "session_id": session_id}
    except JWTError:
        raise HTTPException(status_code = 401, detail = "Invalid Token")

