from fastapi import FastAPI
app = FastAPI()

@app.get("/")
async def root():
    return {"message":"Server is running"}

@app.get("/health")
async def health_check():
    return{"status":"running"}