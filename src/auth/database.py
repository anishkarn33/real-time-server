from fastapi import FastAPI, HTTPException
from pymongo import MongoClient
from passlib.context import CryptContext
from datetime import datetime
from pydantic import BaseModel

app = FastAPI()

# MongoDB connection details
MONGO_HOST = "localhost"
MONGO_PORT = 27017
MONGO_DB = "authentication_db"
MONGO_COLLECTION = "users"

# Connect to MongoDB
client = MongoClient(MONGO_HOST, MONGO_PORT)
db = client[MONGO_DB]
users_collection = db[MONGO_COLLECTION]

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# User model
class User(BaseModel):
    username: str
    email: str
    password: str

# Function to hash password
def get_password_hash(password):
    return pwd_context.hash(password)

# Function to verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# User registration endpoint
@app.post("/register")
async def register_user(user: User):
    # Check if username or email already exists
    existing_user = users_collection.find_one({"$or": [{"username": user.username}, {"email": user.email}]})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already exists")

    # Hash password
    hashed_password = get_password_hash(user.password)

    # Create new user document
    new_user = {
        "username": user.username,
        "email": user.email,
        "password": hashed_password,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    result = users_collection.insert_one(new_user)
    return {"message": "User registered successfully"}

# User login endpoint
@app.post("/login")
async def login_user(username: str, password: str):
    # Find user by username
    user = users_collection.find_one({"username": username})
    if not user or not verify_password(password, user["password"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    # Log user in 
    return {"message": "User logged in successfully"}

# User logout endpoint
@app.post("/logout")
async def logout_user():
    # Log user out 
    return {"message": "User logged out successfully"}


@app.get("/")
async def read_root():
    return {"message": "Hello, World!"}