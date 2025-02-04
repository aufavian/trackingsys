from fastapi import FastAPI, Depends, HTTPException
from pymongo import MongoClient
from pydantic import BaseModel
import bcrypt
import jwt
import os
from dotenv import load_dotenv

load_dotenv()
app = FastAPI()

MONGO_URI = os.getenv("MONGO_URI")
JWT_SECRET = os.getenv("JWT_SECRET")

client = MongoClient(MONGO_URI)
db = client.mis_db
users = db.users

class User(BaseModel):
    name: str
    email: str
    password: str

@app.post("/register")
async def register(user: User):
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
    users.insert_one({"name": user.name, "email": user.email, "password": hashed_password})
    return {"message": "User registered"}

@app.post("/login")
async def login(user: User):
    user_db = users.find_one({"email": user.email})
    if not user_db or not bcrypt.checkpw(user.password.encode('utf-8'), user_db["password"]):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    token = jwt.encode({"email": user.email}, JWT_SECRET, algorithm="HS256")
    return {"token": token}
