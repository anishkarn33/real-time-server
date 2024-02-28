from fastapi import APIRouter, HTTPException, WebSocket
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
from typing import Optional
from src.auth.models import User, UserInDB



router = APIRouter()

# Secret key for signing JWT tokens
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Function to verify hashed password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Function to hash password
def get_password_hash(password):
    return pwd_context.hash(password)

# Function to create JWT token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Function to decode JWT token
def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return User(username=username)
    except JWTError:
        return None

# Function to authenticate user
def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

# Function to get user from fake DB
def get_user(fake_db, username: str):
    if username in fake_db:
        user_dict = fake_db[username]
        return UserInDB(**user_dict)


@router.post("/token")
async def login_for_access_token(user: User):
    if not authenticate_user(user.username, user.password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


# WebSocket endpoint with authentication
@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    # Receive authentication message
    auth_message = await websocket.receive_text()
    username, password = auth_message.split(":")
    
    # Authenticate user
    if not authenticate_user(username, password):
        await websocket.close()
        return

    # Authentication successful, continue WebSocket communication
    while True:
        try:
            data = await websocket.receive_text()   
            # Handle WebSocket data here
        except Exception as e:
            # Handle any errors during WebSocket communication
            print(f"WebSocket error: {e}")
            break