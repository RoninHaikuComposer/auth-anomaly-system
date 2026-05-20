from fastapi import FastAPI
app = FastAPI()

@app.get("/")
async def root():
    return {"message":"Server is running"}

@app.get("/health")
async def health_check():
    return{"status":"running"}


from pydantic import BaseModel

class LoginRequest (BaseModel):
    email : str
    password : str

@app.post("/auth/login")
async def login(request: LoginRequest):
    return {
        "Message":"Login Recieved",
        "email": request.email
    }

    