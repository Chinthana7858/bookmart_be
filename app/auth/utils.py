from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from app.models.user import User
from app.db import get_db
from sqlalchemy.orm import Session
import os

SECRET_KEY = "cea0a0f2df29e617f113ac7d24a0670405cce2be738524b60e0c37b6a0769ca82673545667e5aaed24b699ca3724ee68b9243e0ec472e9e87d62cdbd288948881901b0c07dddcf27db64332c38e4fedc2296e5f9508a2e2858c005cd58e18a3cdd1ba74a27a6e59769a159c0f4ee94dd29843667428a99fb81c9a384ad25655fb47ba1362552cd957fbd44ee818ee8a29840baa637f96cc6e2dd3ce79f2eacc35fa7f8840517b72fe25e55381fb66ad93464c7031021728c2ffbee98959f0f4b7b0a12d338ee5b4e630a5dc0d3b972012c3ce1008f119bae9803f3617fb31d88bcd0b0b1dab3286ec0496457aa255c3bfab6fc834fdc5cb5bc96cc9ffbdfde29"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 600

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get("jwt")
    if not token:
        raise HTTPException(status_code=401, detail="Token missing")
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def require_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

def require_user(current_user: User = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return current_user
