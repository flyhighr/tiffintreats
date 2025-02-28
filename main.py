from fastapi import FastAPI, HTTPException, Depends, Security, BackgroundTasks, Query
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any, Union
from datetime import datetime, timedelta
from pymongo import MongoClient, ASCENDING
from pymongo.server_api import ServerApi
import os
from dotenv import load_dotenv
import uvicorn
import pytz
from enum import Enum
from bson import ObjectId
import asyncio
import httpx
import json
import secrets
import hashlib

# Load environment variables
load_dotenv()

# Initialize FastAPI
app = FastAPI(title="TiffinTreats API")

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*", "X-API-Key"],
)

# MongoDB Connection
MONGODB_URL = os.getenv("MONGODB_URL")
client = MongoClient(MONGODB_URL, server_api=ServerApi('1'))
db = client.tiffintreats

# Constants
ADMIN_ID = os.getenv("ADMIN_ID", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "admin_api_key_secret")
IST = pytz.timezone('Asia/Kolkata')

# Security
api_key_header = APIKeyHeader(name="X-API-Key")

# Enums
class TiffinTime(str, Enum):
    MORNING = "morning"
    EVENING = "evening"
    
class TiffinStatus(str, Enum):
    SCHEDULED = "scheduled"
    PREPARING = "preparing"
    PREPARED = "prepared"
    OUT_FOR_DELIVERY = "out_for_delivery"
    DELIVERED = "delivered"
    CANCELLED = "cancelled"

class RequestStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    ARCHIVED = "archived"

class PollVoteOption(BaseModel):
    option: str
    user_id: str

# Base Models
class UserBase(BaseModel):
    user_id: str
    name: str
    email: EmailStr
    address: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(IST))
    
    class Config:
        from_attributes = True

class TiffinBase(BaseModel):
    date: str
    time: TiffinTime
    description: Optional[str] = None
    price: float
    cancellation_time: str
    delivery_time: Optional[str] = None
    status: TiffinStatus = TiffinStatus.SCHEDULED

class TiffinCreate(TiffinBase):
    assigned_users: List[str]

class Tiffin(TiffinBase):
    id: str = Field(alias="_id")
    created_at: datetime = Field(default_factory=lambda: datetime.now(IST))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(IST))

    class Config:
        from_attributes = True

class TiffinUpdate(BaseModel):
    description: Optional[str] = None
    price: Optional[float] = None
    cancellation_time: Optional[str] = None
    delivery_time: Optional[str] = None
    status: Optional[TiffinStatus] = None
    menu_items: Optional[List[str]] = None
    assigned_users: Optional[List[str]] = None

class Notice(BaseModel):
    title: str
    content: str
    priority: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(IST))
    expires_at: Optional[datetime] = None

class PollOption(BaseModel):
    option: str
    votes: int = 0

class Poll(BaseModel):
    question: str
    options: List[PollOption]
    start_date: datetime
    end_date: datetime
    active: bool = True

class TiffinRequest(BaseModel):
    user_id: str
    description: str
    preferred_date: str
    preferred_time: TiffinTime
    special_instructions: Optional[str] = None
    status: RequestStatus = RequestStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(IST))

class TiffinRequestApproval(BaseModel):
    date: str
    time: TiffinTime
    price: float
    delivery_time: Optional[str] = None 
    cancellation_time: str
    menu_items: Optional[List[str]] = None

class Invoice(BaseModel):
    user_id: str
    start_date: str
    end_date: str
    tiffins: List[str]
    total_amount: float
    paid: bool = False
    generated_at: datetime = Field(default_factory=lambda: datetime.now(IST))

class Notification(BaseModel):
    user_id: str
    title: str
    message: str
    type: str  # "info", "warning", "error", "success"
    read: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(IST))

class UserStats(BaseModel):
    total_tiffins: int
    cancelled_tiffins: int
    total_spent: float
    active_since: datetime
    last_login: Optional[datetime] = None
    current_month_tiffins: int
    favorite_time: Optional[str] = None

# Helper Functions for MongoDB ObjectId handling
class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(type="string")

# Authentication Functions
async def verify_admin(api_key: str = Depends(api_key_header)):
    if api_key != ADMIN_API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid admin API key"
        )
    return True

async def verify_user(api_key: str = Depends(api_key_header)):
    # Check if it's admin first
    if api_key == ADMIN_API_KEY:
        return ADMIN_ID
        
    user = db.users.find_one({"api_key": api_key})
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )
    
    # Check if user is active
    if not user.get("active", True):
        raise HTTPException(
            status_code=403,
            detail="User account is inactive"
        )
        
    return user["user_id"]

async def verify_api_key(api_key: str = Depends(api_key_header)):
    """Verify API key for both admin and regular users"""
    # Check if it's the admin API key
    if api_key == ADMIN_API_KEY:
        return {"user_id": ADMIN_ID, "is_admin": True}
    
    # Otherwise check regular users
    user = db.users.find_one({"api_key": api_key})
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )
        
    # Check if user is active
    if not user.get("active", True):
        raise HTTPException(
            status_code=403,
            detail="User account is inactive"
        )
        
    return {"user_id": user["user_id"], "is_admin": False}

# Utility Functions
def generate_api_key() -> str:
    return secrets.token_hex(24)

def hash_password(password: str) -> str:
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def is_valid_object_id(id_str: str) -> bool:
    """Check if string is a valid MongoDB ObjectId"""
    try:
        ObjectId(id_str)
        return True
    except Exception:
        return False

def parse_time(time_str: str) -> datetime:
    try:
        return datetime.strptime(time_str, "%H:%M").replace(tzinfo=IST)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid time format. Use HH:MM"
        )

async def is_cancellation_allowed(tiffin: dict) -> bool:
    try:
        current_time = datetime.now(IST)
        tiffin_date = datetime.strptime(tiffin["date"], "%Y-%m-%d").date()
        cancellation_time = datetime.strptime(tiffin["cancellation_time"], "%H:%M").time()
        
        # If tiffin date is in the past, no cancellation allowed
        today = datetime.now(IST).date()
        if tiffin_date < today:
            return False
            
        # If tiffin date is in the future, allow cancellation
        if tiffin_date > today:
            return True
        
        # For today's tiffins, check cancellation time
        cancellation_datetime = IST.localize(datetime.combine(tiffin_date, cancellation_time))
        
        return current_time < cancellation_datetime
    except Exception:
        # If any error occurs, default to not allowing cancellation
        return False

def serialize_doc(doc):
    """Convert MongoDB document to JSON-serializable format"""
    if doc is None:
        return None
        
    if isinstance(doc, dict):
        for k, v in doc.items():
            if isinstance(v, ObjectId):
                doc[k] = str(v)
            elif isinstance(v, datetime):
                doc[k] = v.isoformat()
            elif isinstance(v, dict):
                doc[k] = serialize_doc(v)
            elif isinstance(v, list):
                doc[k] = [serialize_doc(item) for item in v]
    return doc

# Health Check
@app.get("/health")
async def health_check():
    try:
        client.admin.command('ping')
        return {
            "status": "healthy",
            "timestamp": datetime.now(IST)
        }
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=str(e)
        )

# Keep Alive Function
APP_URL = os.getenv("APP_URL", "https://tiffintreats-20mb.onrender.com")
PING_INTERVAL = 14 * 60  # 14 minutes

async def keep_alive():
    async with httpx.AsyncClient() as client:
        while True:
            try:
                response = await client.get(f"{APP_URL}/health")
                print(f"Keep-alive ping sent. Status: {response.status_code}")
            except Exception as e:
                print(f"Keep-alive ping failed: {e}")
            await asyncio.sleep(PING_INTERVAL)

# Root
@app.get("/")
async def root():
    return {
        "message": "Welcome to TiffinTreats API",
        "docs": "/docs"
    }

# Authentication Endpoints
@app.get("/auth/login")
@app.post("/auth/login")
async def login(user_id: str, password: str):
    # Check for admin login
    if user_id == ADMIN_ID and password == ADMIN_PASSWORD:
        return {
            "status": "success",
            "api_key": ADMIN_API_KEY,
            "role": "admin"
        }
    
    # Regular user login
    user = db.users.find_one({"user_id": user_id})
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )
        
    # For existing users who don't have hashed passwords yet
    stored_password = user.get("password", "")
    if len(stored_password) == 64:  # Already hashed
        if stored_password != hash_password(password):
            raise HTTPException(
                status_code=401,
                detail="Invalid credentials"
            )
    else:  # Plain text password from old system
        if stored_password != password:
            raise HTTPException(
                status_code=401,
                detail="Invalid credentials"
            )
        # Update to hashed password
        db.users.update_one(
            {"user_id": user_id},
            {"$set": {"password": hash_password(password)}}
        )
    
    # Check if user is active
    if not user.get("active", True):
        raise HTTPException(
            status_code=403,
            detail="Your account is inactive. Please contact an administrator."
        )
    
    # Generate new API key on each login for security
    new_api_key = generate_api_key()
    db.users.update_one(
        {"user_id": user_id},
        {"$set": {"api_key": new_api_key, "last_login": datetime.now(IST)}}
    )
    
    return {
        "status": "success",
        "api_key": new_api_key,
        "role": "user"
    }

# User Management Endpoints
@app.post("/admin/users")
async def create_user(user: UserCreate, _: bool = Depends(verify_admin)):
    # Check if user already exists
    if db.users.find_one({"user_id": user.user_id}):
        raise HTTPException(
            status_code=400,
            detail="User ID already exists"
        )
    
    if db.users.find_one({"email": user.email}):
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )
    
    # Create user document
    user_dict = user.dict()
    hashed_password = hash_password(user.password)
    user_dict.update({
        "password": hashed_password,
        "api_key": generate_api_key(),
        "created_at": datetime.now(IST),
        "active": True,
        "last_login": None
    })
    
    try:
        db.users.insert_one(user_dict)
        return {"status": "success", "user_id": user.user_id}
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create user: {str(e)}"
        )

@app.get("/admin/users")
async def get_all_users(_: bool = Depends(verify_admin)):
    try:
        users = list(db.users.find({}, {"password": 0, "api_key": 0}))
        for user in users:
            user["_id"] = str(user["_id"])
        return users
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch users: {str(e)}"
        )

@app.get("/admin/users/{user_id}")
async def get_user(user_id: str, _: bool = Depends(verify_admin)):
    user = db.users.find_one({"user_id": user_id}, {"password": 0, "api_key": 0})
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )
    user["_id"] = str(user["_id"])
    return user

@app.put("/admin/users/{user_id}")
async def update_user(
    user_id: str,
    updates: Dict,
    _: bool = Depends(verify_admin)
):
    # Don't allow updating admin user through this endpoint
    if user_id == ADMIN_ID:
        raise HTTPException(
            status_code=400,
            detail="Admin user cannot be updated through this endpoint"
        )
    
    allowed_updates = {"name", "email", "address", "active"}
    update_data = {k: v for k, v in updates.items() if k in allowed_updates}
    
    if not update_data:
        raise HTTPException(
            status_code=400,
            detail="No valid updates provided"
        )
    
    # Check email uniqueness if email is being updated
    if "email" in update_data:
        existing_user = db.users.find_one({
            "email": update_data["email"],
            "user_id": {"$ne": user_id}
        })
        if existing_user:
            raise HTTPException(
                status_code=400,
                detail="Email already registered"
            )
    
    result = db.users.update_one(
        {"user_id": user_id},
        {"$set": update_data}
    )
    
    if result.matched_count == 0:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )
    
    return {"status": "success"}

@app.put("/admin/users/{user_id}/reset-password")
async def reset_user_password(
    user_id: str,
    new_password: str,
    _: bool = Depends(verify_admin)
):
    """Reset a user's password (admin only)"""
    if user_id == ADMIN_ID:
        raise HTTPException(
            status_code=400,
            detail="Admin password cannot be reset through this endpoint"
        )
    
    user = db.users.find_one({"user_id": user_id})
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )
    
    hashed_password = hash_password(new_password)
    db.users.update_one(
        {"user_id": user_id},
        {"$set": {"password": hashed_password}}
    )
    
    return {"status": "success", "message": "Password reset successfully"}

@app.delete("/admin/users/{user_id}")
async def delete_user(user_id: str, _: bool = Depends(verify_admin)):
    # Don't allow deleting admin
    if user_id == ADMIN_ID:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete admin user"
        )
    
    result = db.users.delete_one({"user_id": user_id})
    if result.deleted_count == 0:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )
    
    # Clean up user's data
    db.tiffins.update_many(
        {"assigned_users": user_id},
        {"$pull": {"assigned_users": user_id}}
    )
    
    # Clean up user's votes, notifications, etc.
    db.poll_votes.delete_many({"user_id": user_id})
    db.notifications.delete_many({"user_id": user_id})
    db.tiffin_requests.delete_many({"user_id": user_id})
    
    return {"status": "success"}

# User Profile Endpoints
@app.get("/user/profile")
async def get_user_profile(user_id: str = Depends(verify_user)):
    # If admin is checking profile, return admin info
    if user_id == ADMIN_ID:
        return {
            "user_id": ADMIN_ID,
            "name": "Administrator",
            "email": "admin@tiffintreats.com",
            "address": "Admin Office",
            "active": True,
            "created_at": datetime.now(IST).isoformat()
        }
    
    user = db.users.find_one(
        {"user_id": user_id},
        {"password": 0, "api_key": 0}
    )
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )
    user["_id"] = str(user["_id"])
    return user

@app.put("/user/profile")
async def update_user_profile(
    updates: Dict,
    user_id: str = Depends(verify_user)
):
    # Admin can't update profile through this endpoint
    if user_id == ADMIN_ID:
        raise HTTPException(
            status_code=400,
            detail="Admin profile cannot be updated through this endpoint"
        )
    
    allowed_updates = {"name", "email", "address"}
    update_data = {k: v for k, v in updates.items() if k in allowed_updates}
    
    if not update_data:
        raise HTTPException(
            status_code=400,
            detail="No valid updates provided"
        )
    
    # Check email uniqueness if email is being updated
    if "email" in update_data:
        existing_user = db.users.find_one({
            "email": update_data["email"],
            "user_id": {"$ne": user_id}
        })
        if existing_user:
            raise HTTPException(
                status_code=400,
                detail="Email already registered"
            )
    
    result = db.users.update_one(
        {"user_id": user_id},
        {"$set": update_data}
    )
    
    if result.matched_count == 0:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )
    
    return {"status": "success"}

@app.put("/user/password")
async def change_password(
    old_password: str,
    new_password: str,
    user_id: str = Depends(verify_user)
):
    # Admin can't change password through this endpoint
    if user_id == ADMIN_ID:
        raise HTTPException(
            status_code=400,
            detail="Admin password cannot be changed through this endpoint"
        )
    
    user = db.users.find_one({"user_id": user_id})
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )
    
    # Check if old password matches
    stored_password = user.get("password", "")
    if len(stored_password) == 64:  # Already hashed
        if stored_password != hash_password(old_password):
            raise HTTPException(
                status_code=401,
                detail="Current password is incorrect"
            )
    else:  # Plain text password from old system
        if stored_password != old_password:
            raise HTTPException(
                status_code=401,
                detail="Current password is incorrect"
            )
    
    # Update to new hashed password
    hashed_new_password = hash_password(new_password)
    db.users.update_one(
        {"user_id": user_id},
        {"$set": {"password": hashed_new_password}}
    )
    
    return {"status": "success"}

# Tiffin Management Endpoints
@app.post("/admin/tiffins")
async def create_tiffin(tiffin: TiffinCreate, _: bool = Depends(verify_admin)):
    try:
        # Validate assigned users exist
        for user_id in tiffin.assigned_users:
            if not db.users.find_one({"user_id": user_id, "active": True}):
                raise HTTPException(
                    status_code=400,
                    detail=f"User {user_id} not found or inactive"
                )
        
        # Validate time formats
        try:
            datetime.strptime(tiffin.cancellation_time, "%H:%M")
            datetime.strptime(tiffin.date, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid date or time format. Use YYYY-MM-DD for date and HH:MM for times"
            )
        
        # Create tiffin document
        tiffin_dict = tiffin.dict()
        tiffin_dict.update({
            "created_at": datetime.now(IST),
            "updated_at": datetime.now(IST)
        })
        
        result = db.tiffins.insert_one(tiffin_dict)
        
        # Create notifications for assigned users
        for user_id in tiffin.assigned_users:
            notification = {
                "user_id": user_id,
                "title": "New Tiffin Scheduled",
                "message": f"A new tiffin has been scheduled for {tiffin.date} ({tiffin.time}).",
                "type": "info",
                "read": False,
                "created_at": datetime.now(IST)
            }
            db.notifications.insert_one(notification)
        
        return {
            "status": "success",
            "tiffin_id": str(result.inserted_id)
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create tiffin: {str(e)}"
        )
@app.post("/admin/batch-tiffins")
async def create_batch_tiffins(
    base_tiffin: TiffinBase,
    user_groups: List[List[str]],
    _: bool = Depends(verify_admin)
):
    try:
        # Validate time formats in base_tiffin
        try:
            datetime.strptime(base_tiffin.cancellation_time, "%H:%M")
            # Only validate delivery_time if it's provided
            if base_tiffin.delivery_time:
                datetime.strptime(base_tiffin.delivery_time, "%H:%M")
            datetime.strptime(base_tiffin.date, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid date or time format. Use YYYY-MM-DD for date and HH:MM for times"
            )
        
        for user_group in user_groups:
            # Skip empty groups
            if not user_group:
                continue
                
            # Validate all users in group
            for user_id in user_group:
                if not db.users.find_one({"user_id": user_id, "active": True}):
                    raise HTTPException(
                        status_code=400,
                        detail=f"User {user_id} not found or inactive"
                    )
            
            # Create tiffin for this group
            tiffin_dict = base_tiffin.dict()
            tiffin_dict.update({
                "assigned_users": user_group,
                "created_at": datetime.now(IST),
                "updated_at": datetime.now(IST)
            })
            
            result = db.tiffins.insert_one(tiffin_dict)
            tiffin_id = str(result.inserted_id)
            
            # Create notifications for assigned users
            for user_id in user_group:
                notification = {
                    "user_id": user_id,
                    "title": "New Tiffin Scheduled",
                    "message": f"A new tiffin has been scheduled for {base_tiffin.date} ({base_tiffin.time}).",
                    "type": "info",
                    "read": False,
                    "created_at": datetime.now(IST)
                }
                db.notifications.insert_one(notification)
        
        return {
            "status": "success",
            "message": f"Created tiffins for {len(user_groups)} user groups"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create batch tiffins: {str(e)}"
        )

@app.get("/admin/tiffins")
async def get_all_tiffins(
    date: Optional[str] = None,
    status: Optional[TiffinStatus] = None,
    time: Optional[TiffinTime] = None,
    user_id: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    _: bool = Depends(verify_admin)
):
    try:
        query = {}
        
        if date:
            # Validate date format
            try:
                datetime.strptime(date, "%Y-%m-%d")
                query["date"] = date
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid date format. Use YYYY-MM-DD"
                )
        
        if status:
            query["status"] = status
            
        if time:
            query["time"] = time
            
        if user_id:
            query["assigned_users"] = user_id
        
        # Get total count for pagination
        total_count = db.tiffins.count_documents(query)
        
        # Get tiffins with pagination
        tiffins = list(db.tiffins.find(query).sort("date", -1).skip(skip).limit(limit))
        
        # Serialize tiffins
        for tiffin in tiffins:
            tiffin["_id"] = str(tiffin["_id"])
            
        return {
            "total": total_count,
            "skip": skip,
            "limit": limit,
            "data": tiffins
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch tiffins: {str(e)}"
        )

@app.get("/admin/tiffins/{tiffin_id}")
async def get_tiffin_by_id(
    tiffin_id: str,
    _: bool = Depends(verify_admin)
):
    try:
        if not is_valid_object_id(tiffin_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid tiffin ID format"
            )
            
        tiffin = db.tiffins.find_one({"_id": ObjectId(tiffin_id)})
        
        if not tiffin:
            raise HTTPException(
                status_code=404,
                detail="Tiffin not found"
            )
        
        # Get user details for assigned users
        user_details = []
        for user_id in tiffin["assigned_users"]:
            user = db.users.find_one({"user_id": user_id}, {"password": 0, "api_key": 0})
            if user:
                user["_id"] = str(user["_id"])
                user_details.append(user)
        
        tiffin["_id"] = str(tiffin["_id"])
        tiffin["user_details"] = user_details
        
        return tiffin
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch tiffin: {str(e)}"
        )

@app.put("/admin/tiffins/{tiffin_id}")
async def update_tiffin(
    tiffin_id: str,
    updates: TiffinUpdate,
    _: bool = Depends(verify_admin)
):
    try:
        if not is_valid_object_id(tiffin_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid tiffin ID format"
            )
        
        # Get the current tiffin to check for changes
        current_tiffin = db.tiffins.find_one({"_id": ObjectId(tiffin_id)})
        if not current_tiffin:
            raise HTTPException(
                status_code=404,
                detail="Tiffin not found"
            )
        
        # Prepare update data
        update_data = {}
        for field, value in updates.dict(exclude_unset=True).items():
            if value is not None:  # Only include non-None values
                update_data[field] = value
        
        if not update_data:
            raise HTTPException(
                status_code=400,
                detail="No valid updates provided"
            )
        
        # Validate time formats if provided
        if "cancellation_time" in update_data:
            try:
                datetime.strptime(update_data["cancellation_time"], "%H:%M")
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid cancellation_time format. Use HH:MM"
                )
                
        if "delivery_time" in update_data:
            try:
                datetime.strptime(update_data["delivery_time"], "%H:%M")
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid delivery_time format. Use HH:MM"
                )
        
        # Check if assigned users exist if provided
        if "assigned_users" in update_data:
            new_users = set(update_data["assigned_users"]) - set(current_tiffin["assigned_users"])
            for user_id in new_users:
                if not db.users.find_one({"user_id": user_id, "active": True}):
                    raise HTTPException(
                        status_code=400,
                        detail=f"User {user_id} not found or inactive"
                    )
        
        # Add updated_at timestamp
        update_data["updated_at"] = datetime.now(IST)
        
        result = db.tiffins.update_one(
            {"_id": ObjectId(tiffin_id)},
            {"$set": update_data}
        )
        
        # If status changed, notify affected users
        if "status" in update_data and update_data["status"] != current_tiffin["status"]:
            status_display = {
                "scheduled": "Scheduled",
                "preparing": "Being Prepared",
                "prepared": "Prepared",
                "out_for_delivery": "Out for Delivery",
                "delivered": "Delivered",
                "cancelled": "Cancelled"
            }
            
            status_message = f"Your tiffin for {current_tiffin['date']} ({current_tiffin['time']}) is now {status_display.get(update_data['status'], update_data['status'])}."
            
            for user_id in current_tiffin["assigned_users"]:
                notification = {
                    "user_id": user_id,
                    "title": "Tiffin Status Updated",
                    "message": status_message,
                    "type": "info",
                    "read": False,
                    "created_at": datetime.now(IST)
                }
                db.notifications.insert_one(notification)
        
        # If new users added, notify them
        if "assigned_users" in update_data:
            new_users = set(update_data["assigned_users"]) - set(current_tiffin["assigned_users"])
            for user_id in new_users:
                notification = {
                    "user_id": user_id,
                    "title": "New Tiffin Assigned",
                    "message": f"A tiffin has been assigned to you for {current_tiffin['date']} ({current_tiffin['time']}).",
                    "type": "info",
                    "read": False,
                    "created_at": datetime.now(IST)
                }
                db.notifications.insert_one(notification)
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update tiffin: {str(e)}"
        )

@app.put("/admin/tiffins/{tiffin_id}/status")
async def update_tiffin_status(
    tiffin_id: str,
    status: TiffinStatus,
    _: bool = Depends(verify_admin)
):
    try:
        if not is_valid_object_id(tiffin_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid tiffin ID format"
            )
        
        # Get current tiffin to check if status is changing
        current_tiffin = db.tiffins.find_one({"_id": ObjectId(tiffin_id)})
        if not current_tiffin:
            raise HTTPException(
                status_code=404,
                detail="Tiffin not found"
            )
            
        # Update status
        result = db.tiffins.update_one(
            {"_id": ObjectId(tiffin_id)},
            {
                "$set": {
                    "status": status,
                    "updated_at": datetime.now(IST)
                }
            }
        )
        
        # If status changed, notify assigned users
        if status != current_tiffin["status"]:
            status_display = {
                "scheduled": "Scheduled",
                "preparing": "Being Prepared",
                "prepared": "Prepared",
                "out_for_delivery": "Out for Delivery",
                "delivered": "Delivered",
                "cancelled": "Cancelled"
            }
            
            status_message = f"Your tiffin for {current_tiffin['date']} ({current_tiffin['time']}) is now {status_display.get(status, status)}."
            
            for user_id in current_tiffin["assigned_users"]:
                notification = {
                    "user_id": user_id,
                    "title": "Tiffin Status Updated",
                    "message": status_message,
                    "type": "info",
                    "read": False,
                    "created_at": datetime.now(IST)
                }
                db.notifications.insert_one(notification)
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update tiffin status: {str(e)}"
        )

@app.put("/admin/tiffins/{tiffin_id}/assign")
async def assign_users_to_tiffin(
    tiffin_id: str,
    user_ids: List[str],
    _: bool = Depends(verify_admin)
):
    try:
        if not is_valid_object_id(tiffin_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid tiffin ID format"
            )
            
        # Get current tiffin
        tiffin = db.tiffins.find_one({"_id": ObjectId(tiffin_id)})
        if not tiffin:
            raise HTTPException(
                status_code=404,
                detail="Tiffin not found"
            )
            
        # Validate users exist
        for user_id in user_ids:
            if not db.users.find_one({"user_id": user_id, "active": True}):
                raise HTTPException(
                    status_code=400,
                    detail=f"User {user_id} not found or inactive"
                )
                
        # Find new users (not already assigned)
        current_users = set(tiffin["assigned_users"])
        new_users = [uid for uid in user_ids if uid not in current_users]
                
        # Update tiffin with new users
        result = db.tiffins.update_one(
            {"_id": ObjectId(tiffin_id)},
            {
                "$addToSet": {"assigned_users": {"$each": user_ids}},
                "$set": {"updated_at": datetime.now(IST)}
            }
        )
        
        # Notify new users
        for user_id in new_users:
            notification = {
                "user_id": user_id,
                "title": "New Tiffin Assigned",
                "message": f"A tiffin has been assigned to you for {tiffin['date']} ({tiffin['time']}).",
                "type": "info",
                "read": False,
                "created_at": datetime.now(IST)
            }
            db.notifications.insert_one(notification)
        
        return {
            "status": "success",
            "assigned_users": list(set(tiffin["assigned_users"]).union(set(user_ids)))
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to assign users to tiffin: {str(e)}"
        )

@app.put("/admin/tiffins/{tiffin_id}/unassign")
async def unassign_users_from_tiffin(
    tiffin_id: str,
    user_ids: List[str],
    _: bool = Depends(verify_admin)
):
    try:
        if not is_valid_object_id(tiffin_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid tiffin ID format"
            )
            
        # Get current tiffin
        tiffin = db.tiffins.find_one({"_id": ObjectId(tiffin_id)})
        if not tiffin:
            raise HTTPException(
                status_code=404,
                detail="Tiffin not found"
            )
                
        # Update tiffin by removing users
        result = db.tiffins.update_one(
            {"_id": ObjectId(tiffin_id)},
            {
                "$pullAll": {"assigned_users": user_ids},
                "$set": {"updated_at": datetime.now(IST)}
            }
        )
        
        # If no users left, mark as cancelled
        updated_tiffin = db.tiffins.find_one({"_id": ObjectId(tiffin_id)})
        if not updated_tiffin["assigned_users"]:
            db.tiffins.update_one(
                {"_id": ObjectId(tiffin_id)},
                {"$set": {"status": TiffinStatus.CANCELLED}}
            )
            
        # Notify unassigned users
        for user_id in user_ids:
            notification = {
                "user_id": user_id,
                "title": "Tiffin Unassigned",
                "message": f"You have been unassigned from the tiffin scheduled for {tiffin['date']} ({tiffin['time']}).",
                "type": "info",
                "read": False,
                "created_at": datetime.now(IST)
            }
            db.notifications.insert_one(notification)
        
        return {
            "status": "success",
            "remaining_users": list(set(tiffin["assigned_users"]) - set(user_ids))
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to unassign users from tiffin: {str(e)}"
        )

@app.delete("/admin/tiffins/{tiffin_id}")
async def delete_tiffin(tiffin_id: str, _: bool = Depends(verify_admin)):
    try:
        if not is_valid_object_id(tiffin_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid tiffin ID format"
            )
            
        # Get tiffin first to notify users
        tiffin = db.tiffins.find_one({"_id": ObjectId(tiffin_id)})
        if not tiffin:
            raise HTTPException(
                status_code=404,
                detail="Tiffin not found"
            )
            
        # Delete the tiffin
        result = db.tiffins.delete_one({"_id": ObjectId(tiffin_id)})
        
        # Notify affected users
        for user_id in tiffin["assigned_users"]:
            notification = {
                "user_id": user_id,
                "title": "Tiffin Cancelled",
                "message": f"The tiffin scheduled for {tiffin['date']} ({tiffin['time']}) has been cancelled.",
                "type": "warning",
                "read": False,
                "created_at": datetime.now(IST)
            }
            db.notifications.insert_one(notification)
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete tiffin: {str(e)}"
        )

@app.get("/user/tiffins")
async def get_user_tiffins(
    user_id: str = Depends(verify_user),
    date: Optional[str] = None,
    time: Optional[TiffinTime] = None,
    status: Optional[TiffinStatus] = None,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0)
):
    try:
        query = {"assigned_users": user_id}
        
        if date:
            # Validate date format
            try:
                datetime.strptime(date, "%Y-%m-%d")
                query["date"] = date
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid date format. Use YYYY-MM-DD"
                )
                
        if time:
            query["time"] = time
            
        if status:
            query["status"] = status
        
        # Get total count for pagination
        total_count = db.tiffins.count_documents(query)
        
        # Get tiffins with pagination
        tiffins = list(db.tiffins.find(query).sort("date", -1).skip(skip).limit(limit))
        
        # Serialize tiffins and remove description for regular users
        for tiffin in tiffins:
            tiffin["_id"] = str(tiffin["_id"])
            if user_id != ADMIN_ID:  # Only hide for non-admin users
                if "description" in tiffin:
                    tiffin.pop("description", None)
                if "delivery_time" in tiffin:
                    tiffin.pop("delivery_time", None)
            
        return {
            "total": total_count,
            "skip": skip,
            "limit": limit,
            "data": tiffins
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch user tiffins: {str(e)}"
        )
        
@app.get("/user/tiffins/{tiffin_id}")
async def get_user_tiffin_by_id(
    tiffin_id: str,
    user_id: str = Depends(verify_user)
):
    try:
        if not is_valid_object_id(tiffin_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid tiffin ID format"
            )
            
        # For regular users, only show tiffins assigned to them
        # For admin, show any tiffin
        query = {"_id": ObjectId(tiffin_id)}
        if user_id != ADMIN_ID:
            query["assigned_users"] = user_id
            
        tiffin = db.tiffins.find_one(query)
        
        if not tiffin:
            raise HTTPException(
                status_code=404,
                detail="Tiffin not found"
            )
            
        tiffin["_id"] = str(tiffin["_id"])
        
        return tiffin
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch tiffin: {str(e)}"
        )
        
@app.get("/user/tiffins/{tiffin_id}/cancellations")
async def get_tiffin_cancellations(
    tiffin_id: str,
    user_id: str = Depends(verify_user)
):
    try:
        if not is_valid_object_id(tiffin_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid tiffin ID format"
            )
            
        # Get the tiffin
        tiffin = db.tiffins.find_one({"_id": ObjectId(tiffin_id)})
        if not tiffin:
            raise HTTPException(
                status_code=404,
                detail="Tiffin not found"
            )
            
        # Check if user is authorized (admin or assigned to this tiffin)
        if user_id != ADMIN_ID and user_id not in tiffin.get("assigned_users", []):
            raise HTTPException(
                status_code=403,
                detail="Not authorized to view this tiffin"
            )
            
        # Get cancellation events from tiffin history
        cancellations = []
        
        # If tiffin has a cancellations field, return it
        if "cancellations" in tiffin:
            for cancellation in tiffin["cancellations"]:
                # Get user details
                cancelled_user = db.users.find_one(
                    {"user_id": cancellation["user_id"]},
                    {"name": 1, "email": 1}
                )
                
                cancellation_info = {
                    "user_id": cancellation["user_id"],
                    "name": cancelled_user.get("name", "Unknown User") if cancelled_user else "Unknown User",
                    "email": cancelled_user.get("email", "No email") if cancelled_user else "No email",
                    "cancelled_at": cancellation["cancelled_at"]
                }
                cancellations.append(cancellation_info)
                
        return {
            "tiffin_id": str(tiffin["_id"]),
            "cancellations": cancellations
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get cancellations: {str(e)}"
        )

@app.get("/user/tiffins/today")
async def get_user_today_tiffins(user_id: str = Depends(verify_user)):
    try:
        today = datetime.now(IST).strftime("%Y-%m-%d")
        query = {
            "assigned_users": user_id,
            "date": today
        }
        
        tiffins = list(db.tiffins.find(query).sort("time", 1))
        
        # Properly serialize the tiffins
        serialized_tiffins = []
        for tiffin in tiffins:
            serialized_tiffin = serialize_doc(tiffin)  # Using the serialize_doc function
            serialized_tiffins.append(serialized_tiffin)
            
        return serialized_tiffins
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch today's tiffins: {str(e)}"
        )

@app.get("/user/tiffins/upcoming")
async def get_user_upcoming_tiffins(
    user_id: str = Depends(verify_user),
    days: int = Query(7, ge=1, le=30)
):
    try:
        today = datetime.now(IST).strftime("%Y-%m-%d")
        end_date = (datetime.now(IST) + timedelta(days=days)).strftime("%Y-%m-%d")
        
        query = {
            "assigned_users": user_id,
            "date": {"$gte": today, "$lte": end_date},
            "status": {"$ne": TiffinStatus.CANCELLED}
        }
        
        tiffins = list(db.tiffins.find(query).sort("date", 1).sort("time", 1))
        
        # Properly serialize the tiffins
        serialized_tiffins = []
        for tiffin in tiffins:
            serialized_tiffin = serialize_doc(tiffin)  # Using the serialize_doc function
            serialized_tiffins.append(serialized_tiffin)
            
        return serialized_tiffins
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch upcoming tiffins: {str(e)}"
        )
        
@app.post("/user/cancel-tiffin")
async def cancel_tiffin(
    tiffin_id: str,
    user_id: str = Depends(verify_user)
):
    try:
        if not is_valid_object_id(tiffin_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid tiffin ID format"
            )
            
        tiffin = db.tiffins.find_one({"_id": ObjectId(tiffin_id)})
        if not tiffin:
            raise HTTPException(
                status_code=404,
                detail="Tiffin not found"
            )
        
        # Admin can cancel any tiffin
        if user_id != ADMIN_ID and user_id not in tiffin["assigned_users"]:
            raise HTTPException(
                status_code=403,
                detail="Not authorized to cancel this tiffin"
            )
        
        # Only check cancellation time for regular users, not admin
        if user_id != ADMIN_ID and not await is_cancellation_allowed(tiffin):
            raise HTTPException(
                status_code=400,
                detail="Cancellation time has passed"
            )
        
        # Record cancellation event
        cancellation_record = {
            "user_id": user_id,
            "cancelled_at": datetime.now(IST)
        }
        
        # For admin, just change status
        if user_id == ADMIN_ID:
            result = db.tiffins.update_one(
                {"_id": ObjectId(tiffin_id)},
                {
                    "$set": {
                        "status": TiffinStatus.CANCELLED,
                        "updated_at": datetime.now(IST)
                    },
                    "$push": {
                        "cancellations": cancellation_record
                    }
                }
            )
            
            # Notify all assigned users
            for assigned_user in tiffin["assigned_users"]:
                notification = {
                    "user_id": assigned_user,
                    "title": "Tiffin Cancelled",
                    "message": f"The tiffin scheduled for {tiffin['date']} ({tiffin['time']}) has been cancelled by admin.",
                    "type": "warning",
                    "read": False,
                    "created_at": datetime.now(IST)
                }
                db.notifications.insert_one(notification)
        else:
            # For regular user, remove them from assigned_users
            result = db.tiffins.update_one(
                {"_id": ObjectId(tiffin_id)},
                {
                    "$pull": {"assigned_users": user_id},
                    "$set": {"updated_at": datetime.now(IST)},
                    "$push": {
                        "cancellations": cancellation_record
                    }
                }
            )
            
            # Notify user of cancellation
            notification = {
                "user_id": user_id,
                "title": "Tiffin Cancelled",
                "message": f"You have successfully cancelled your tiffin for {tiffin['date']} ({tiffin['time']}).",
                "type": "info",
                "read": False,
                "created_at": datetime.now(IST)
            }
            db.notifications.insert_one(notification)
            
            # If no users left, mark as cancelled
            updated_tiffin = db.tiffins.find_one({"_id": ObjectId(tiffin_id)})
            if not updated_tiffin["assigned_users"]:
                db.tiffins.update_one(
                    {"_id": ObjectId(tiffin_id)},
                    {"$set": {"status": TiffinStatus.CANCELLED}}
                )
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to cancel tiffin: {str(e)}"
        )

@app.get("/user/history")
async def get_user_history(
    user_id: str = Depends(verify_user),
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0)
):
    try:
        query = {"assigned_users": user_id}
        
        # Add date filters if provided
        if start_date or end_date:
            query["date"] = {}
            
            if start_date:
                try:
                    datetime.strptime(start_date, "%Y-%m-%d")
                    query["date"]["$gte"] = start_date
                except ValueError:
                    raise HTTPException(
                        status_code=400,
                        detail="Invalid start_date format. Use YYYY-MM-DD"
                    )
                
            if end_date:
                try:
                    datetime.strptime(end_date, "%Y-%m-%d")
                    query["date"]["$lte"] = end_date
                except ValueError:
                    raise HTTPException(
                        status_code=400,
                        detail="Invalid end_date format. Use YYYY-MM-DD"
                    )
        else:
            # Default to past tiffins if no date range specified
            today = datetime.now(IST).strftime("%Y-%m-%d")
            query["date"] = {"$lt": today}
        
        # Get total count for pagination
        total_count = db.tiffins.count_documents(query)
        
        # Get history with pagination
        history = list(db.tiffins.find(query).sort("date", -1).skip(skip).limit(limit))
        
        # Serialize history items
        for item in history:
            item["_id"] = str(item["_id"])
            
        return {
            "total": total_count,
            "skip": skip,
            "limit": limit,
            "data": history
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch history: {str(e)}"
        )

@app.post("/user/request-tiffin")
async def request_special_tiffin(
    request_data: dict,  # Change this to accept a plain dictionary instead of TiffinRequest
    user_id: str = Depends(verify_user)
):
    try:
        # Create a TiffinRequest object with the authenticated user's ID
        request = TiffinRequest(
            user_id=user_id,
            description=request_data.get("description", ""),
            preferred_date=request_data.get("preferred_date", ""),
            preferred_time=request_data.get("preferred_time", ""),
            special_instructions=request_data.get("special_instructions", None)
        )
        
        # Validate date format
        try:
            datetime.strptime(request.preferred_date, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid preferred_date format. Use YYYY-MM-DD"
            )
        
        request_dict = request.dict()
        request_dict.update({
            "status": "pending",
            "created_at": datetime.now(IST)
        })
        
        result = db.tiffin_requests.insert_one(request_dict)
        
        # Create notification for admin
        admin_notification = {
            "user_id": ADMIN_ID,
            "title": "New Special Tiffin Request",
            "message": f"User {request.user_id} has requested a special tiffin for {request.preferred_date}.",
            "type": "info",
            "read": False,
            "created_at": datetime.now(IST)
        }
        db.notifications.insert_one(admin_notification)
        
        return {
            "status": "success",
            "request_id": str(result.inserted_id)
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create tiffin request: {str(e)}"
        )

@app.get("/admin/tiffin-requests")
async def get_tiffin_requests(
    status: Optional[RequestStatus] = None,
    user_id: Optional[str] = None,
    _: bool = Depends(verify_admin)
):
    try:
        query = {}
        
        if status:
            query["status"] = status
            
        if user_id:
            query["user_id"] = user_id
        
        requests = list(db.tiffin_requests.find(query).sort("created_at", -1))
        
        # Serialize requests
        for request in requests:
            request["_id"] = str(request["_id"])
            
        return requests
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch tiffin requests: {str(e)}"
        )

@app.get("/admin/tiffin-requests/{request_id}")
async def get_tiffin_request(
    request_id: str,
    _: bool = Depends(verify_admin)
):
    try:
        if not is_valid_object_id(request_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid request ID format"
            )
            
        request = db.tiffin_requests.find_one({"_id": ObjectId(request_id)})
        
        if not request:
            raise HTTPException(
                status_code=404,
                detail="Tiffin request not found"
            )
        
        # Get user details
        user = db.users.find_one({"user_id": request["user_id"]}, {"password": 0, "api_key": 0})
        if user:
            user["_id"] = str(user["_id"])
            request["user_details"] = user
        
        request["_id"] = str(request["_id"])
        
        return request
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch tiffin request: {str(e)}"
        )

@app.post("/admin/tiffin-requests/{request_id}/approve")
async def approve_tiffin_request(
    request_id: str,
    approval: TiffinRequestApproval,
    _: bool = Depends(verify_admin)
):
    try:
        if not is_valid_object_id(request_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid request ID format"
            )
            
        # Get the request
        request = db.tiffin_requests.find_one({"_id": ObjectId(request_id)})
        if not request:
            raise HTTPException(
                status_code=404,
                detail="Tiffin request not found"
            )
            
        # Check if request is already processed
        if request["status"] != RequestStatus.PENDING:
            raise HTTPException(
                status_code=400,
                detail=f"Request is already {request['status']}"
            )
            
        # Validate date and time formats
        try:
            datetime.strptime(approval.date, "%Y-%m-%d")
            datetime.strptime(approval.cancellation_time, "%H:%M")
            # Only validate delivery_time if it's provided
            if approval.delivery_time:
                datetime.strptime(approval.delivery_time, "%H:%M")
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid date or time format. Use YYYY-MM-DD for date and HH:MM for times"
            )
            
        # Create a new tiffin based on the request
        tiffin = {
            "date": approval.date,
            "time": approval.time,
            "description": request["description"],
            "price": approval.price,
            "cancellation_time": approval.cancellation_time,
            # Set a default delivery time if not provided
            "delivery_time": approval.delivery_time or "12:00",
            "status": TiffinStatus.SCHEDULED,
            "menu_items": approval.menu_items or ["Special Tiffin"],
            "assigned_users": [request["user_id"]],
            "created_at": datetime.now(IST),
            "updated_at": datetime.now(IST),
            "special_request": True,
            "request_id": str(request["_id"])
        }
        
        result = db.tiffins.insert_one(tiffin)
        
        # Update request status
        db.tiffin_requests.update_one(
            {"_id": ObjectId(request_id)},
            {
                "$set": {
                    "status": RequestStatus.APPROVED,
                    "approved_at": datetime.now(IST),
                    "tiffin_id": str(result.inserted_id)
                }
            }
        )
        
        # Notify the user
        notification = {
            "user_id": request["user_id"],
            "title": "Special Tiffin Request Approved",
            "message": f"Your special tiffin request for {approval.date} ({approval.time}) has been approved.",
            "type": "success",
            "read": False,
            "created_at": datetime.now(IST)
        }
        db.notifications.insert_one(notification)
        
        return {
            "status": "success",
            "tiffin_id": str(result.inserted_id)
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to approve tiffin request: {str(e)}"
        )
        
@app.post("/admin/tiffin-requests/{request_id}/reject")
async def reject_tiffin_request(
    request_id: str,
    reason: Optional[str] = None,
    _: bool = Depends(verify_admin)
):
    try:
        if not is_valid_object_id(request_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid request ID format"
            )
            
        # Get the request
        request = db.tiffin_requests.find_one({"_id": ObjectId(request_id)})
        if not request:
            raise HTTPException(
                status_code=404,
                detail="Tiffin request not found"
            )
            
        # Check if request is already processed
        if request["status"] != RequestStatus.PENDING:
            raise HTTPException(
                status_code=400,
                detail=f"Request is already {request['status']}"
            )
            
        # Update request status
        db.tiffin_requests.update_one(
            {"_id": ObjectId(request_id)},
            {
                "$set": {
                    "status": RequestStatus.REJECTED,
                    "rejected_at": datetime.now(IST),
                    "rejection_reason": reason
                }
            }
        )
        
        # Notify the user
        message = f"Your special tiffin request for {request['preferred_date']} ({request['preferred_time']}) has been rejected."
        if reason:
            message += f" Reason: {reason}"
            
        notification = {
            "user_id": request["user_id"],
            "title": "Special Tiffin Request Rejected",
            "message": message,
            "type": "warning",
            "read": False,
            "created_at": datetime.now(IST)
        }
        db.notifications.insert_one(notification)
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to reject tiffin request: {str(e)}"
        )

# Notice Management Endpoints
@app.post("/admin/notices")
async def create_notice(notice: Notice, _: bool = Depends(verify_admin)):
    try:
        notice_dict = notice.dict()
        result = db.notices.insert_one(notice_dict)
        
        # Create notifications for all active users
        users = list(db.users.find({"active": True}, {"user_id": 1}))
        
        priority_text = "Normal"
        if notice.priority == 1:
            priority_text = "Important"
        elif notice.priority == 2:
            priority_text = "Urgent"
            
        for user in users:
            notification = {
                "user_id": user["user_id"],
                "title": f"New {priority_text} Notice",
                "message": notice.title,
                "type": "info" if notice.priority == 0 else "warning" if notice.priority == 1 else "error",
                "read": False,
                "created_at": datetime.now(IST),
                "notice_id": str(result.inserted_id)
            }
            db.notifications.insert_one(notification)
        
        return {
            "status": "success",
            "notice_id": str(result.inserted_id)
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create notice: {str(e)}"
        )

@app.get("/admin/notices")
async def get_all_notices(_: bool = Depends(verify_admin)):
    try:
        notices = list(db.notices.find().sort("created_at", -1))
        for notice in notices:
            notice["_id"] = str(notice["_id"])
        return notices
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch notices: {str(e)}"
        )

@app.get("/user/notices")
async def get_user_notices(user_id: str = Depends(verify_user)):
    try:
        current_time = datetime.now(IST)
        query = {
            "$or": [
                {"expires_at": None},
                {"expires_at": {"$gt": current_time}}
            ]
        }
        
        notices = list(db.notices.find(query).sort("priority", -1).sort("created_at", -1))
        for notice in notices:
            notice["_id"] = str(notice["_id"])
        return notices
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch notices: {str(e)}"
        )

@app.get("/admin/notices/{notice_id}")
async def get_notice_by_id(
    notice_id: str,
    _: bool = Depends(verify_admin)
):
    try:
        if not is_valid_object_id(notice_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid notice ID format"
            )
            
        notice = db.notices.find_one({"_id": ObjectId(notice_id)})
        
        if not notice:
            raise HTTPException(
                status_code=404,
                detail="Notice not found"
            )
        
        notice["_id"] = str(notice["_id"])
        return notice
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch notice: {str(e)}"
        )
           
@app.put("/admin/notices/{notice_id}")
async def update_notice(
    notice_id: str,
    updates: Dict,
    _: bool = Depends(verify_admin)
):
    try:
        if not is_valid_object_id(notice_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid notice ID format"
            )
            
        allowed_updates = {"title", "content", "priority", "expires_at"}
        update_data = {k: v for k, v in updates.items() if k in allowed_updates}
        
        if not update_data:
            raise HTTPException(
                status_code=400,
                detail="No valid updates provided"
            )
        
        result = db.notices.update_one(
            {"_id": ObjectId(notice_id)},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=404,
                detail="Notice not found"
            )
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update notice: {str(e)}"
        )

@app.delete("/admin/notices/{notice_id}")
async def delete_notice(notice_id: str, _: bool = Depends(verify_admin)):
    try:
        if not is_valid_object_id(notice_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid notice ID format"
            )
            
        result = db.notices.delete_one({"_id": ObjectId(notice_id)})
        if result.deleted_count == 0:
            raise HTTPException(
                status_code=404,
                detail="Notice not found"
            )
            
        # Delete related notifications
        db.notifications.delete_many({"notice_id": notice_id})
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete notice: {str(e)}"
        )

# Poll Management Endpoints
@app.post("/admin/polls")
async def create_poll(poll: Poll, _: bool = Depends(verify_admin)):
    try:
        poll_dict = poll.dict()
        result = db.polls.insert_one(poll_dict)
        
        # Create notifications for all active users
        users = list(db.users.find({"active": True}, {"user_id": 1}))
        
        for user in users:
            notification = {
                "user_id": user["user_id"],
                "title": "New Poll Available",
                "message": f"A new poll is available: {poll.question}",
                "type": "info",
                "read": False,
                "created_at": datetime.now(IST),
                "poll_id": str(result.inserted_id)
            }
            db.notifications.insert_one(notification)
        
        return {
            "status": "success",
            "poll_id": str(result.inserted_id)
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create poll: {str(e)}"
        )

@app.get("/admin/polls")
async def get_all_polls(_: bool = Depends(verify_admin)):
    try:
        polls = list(db.polls.find().sort("end_date", -1))
        for poll in polls:
            poll["_id"] = str(poll["_id"])
        return polls
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch polls: {str(e)}"
        )
        
@app.get("/admin/polls/{poll_id}/votes")
async def get_poll_votes(
    poll_id: str,
    _: bool = Depends(verify_admin)
):
    try:
        if not is_valid_object_id(poll_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid poll ID format"
            )
        
        # Get the poll to verify it exists
        poll = db.polls.find_one({"_id": ObjectId(poll_id)})
        if not poll:
            raise HTTPException(
                status_code=404,
                detail="Poll not found"
            )
        
        # Get all votes for this poll
        votes = list(db.poll_votes.find({"poll_id": ObjectId(poll_id)}))
        
        # Get user details for each vote
        detailed_votes = []
        for vote in votes:
            user = db.users.find_one({"user_id": vote["user_id"]}, {"name": 1, "user_id": 1})
            detailed_vote = {
                "user_id": vote["user_id"],
                "user_name": user["name"] if user else "Unknown User",
                "option_index": vote["option_index"],
                "voted_at": vote["voted_at"]
            }
            detailed_votes.append(detailed_vote)
        
        return {
            "poll_id": poll_id,
            "votes": detailed_votes
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch poll votes: {str(e)}"
        )
        
@app.get("/user/polls")
async def get_active_polls(user_id: str = Depends(verify_user)):
    try:
        current_time = datetime.now(IST)
        query = {
            "active": True,
            "start_date": {"$lte": current_time},
            "end_date": {"$gt": current_time}
        }
        
        polls = list(db.polls.find(query))
        
        # For each poll, check if user has already voted
        for poll in polls:
            poll["_id"] = str(poll["_id"])
            
            # Check if user has already voted
            vote = db.poll_votes.find_one({
                "poll_id": ObjectId(poll["_id"]),
                "user_id": user_id
            })
            
            poll["has_voted"] = vote is not None
            if vote:
                poll["user_vote"] = vote["option_index"]
            
            # For non-admin users, don't show vote counts
            if user_id != ADMIN_ID:
                for option in poll["options"]:
                    option["votes"] = 0
        
        return polls
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch polls: {str(e)}"
        )
        
@app.get("/user/polls/{poll_id}")
async def get_poll_by_id(
    poll_id: str,
    user_id: str = Depends(verify_user)
):
    try:
        if not is_valid_object_id(poll_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid poll ID format"
            )
            
        poll = db.polls.find_one({"_id": ObjectId(poll_id)})
        
        if not poll:
            raise HTTPException(
                status_code=404,
                detail="Poll not found"
            )
        
        poll["_id"] = str(poll["_id"])
        
        # Check if user has already voted
        vote = db.poll_votes.find_one({
            "poll_id": ObjectId(poll_id),
            "user_id": user_id
        })
        
        poll["has_voted"] = vote is not None
        if vote:
            poll["user_vote"] = vote["option_index"]
        
        return poll
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch poll: {str(e)}"
        )

@app.post("/user/polls/{poll_id}/vote")
async def vote_poll(
    poll_id: str,
    option_index: int,
    user_id: str = Depends(verify_user)
):
    try:
        if not is_valid_object_id(poll_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid poll ID format"
            )
            
        # Check if poll exists and is active
        current_time = datetime.now(IST)
        poll = db.polls.find_one({
            "_id": ObjectId(poll_id),
            "active": True,
            "start_date": {"$lte": current_time},
            "end_date": {"$gt": current_time}
        })
        
        if not poll:
            raise HTTPException(
                status_code=404,
                detail="Poll not found or inactive"
            )
        
        # Check if user already voted (skip for admin)
        if user_id != ADMIN_ID:
            existing_vote = db.poll_votes.find_one({
                "poll_id": ObjectId(poll_id),
                "user_id": user_id
            })
            
            if existing_vote:
                raise HTTPException(
                    status_code=400,
                    detail="You have already voted in this poll"
                )
        
        # Validate option index
        if option_index < 0 or option_index >= len(poll["options"]):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid option index. Must be between 0 and {len(poll['options']) - 1}"
            )
        
        # Record vote (skip for admin to avoid skewing results)
        if user_id != ADMIN_ID:
            db.poll_votes.insert_one({
                "poll_id": ObjectId(poll_id),
                "user_id": user_id,
                "option_index": option_index,
                "voted_at": datetime.now(IST)
            })
            
            # Update poll results
            db.polls.update_one(
                {"_id": ObjectId(poll_id)},
                {"$inc": {f"options.{option_index}.votes": 1}}
            )
        
        return {
            "status": "success", 
            "message": "Your vote has been recorded"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to record vote: {str(e)}"
        )
        
@app.put("/admin/polls/{poll_id}")
async def update_poll(
    poll_id: str,
    updates: Dict,
    _: bool = Depends(verify_admin)
):
    try:
        if not is_valid_object_id(poll_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid poll ID format"
            )
            
        allowed_updates = {"question", "options", "start_date", "end_date", "active"}
        update_data = {k: v for k, v in updates.items() if k in allowed_updates}
        
        if not update_data:
            raise HTTPException(
                status_code=400,
                detail="No valid updates provided"
            )
        
        # Don't allow changing options if votes already exist
        if "options" in update_data:
            vote_count = db.poll_votes.count_documents({"poll_id": ObjectId(poll_id)})
            if vote_count > 0:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot modify poll options after voting has started"
                )
        
        result = db.polls.update_one(
            {"_id": ObjectId(poll_id)},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=404,
                detail="Poll not found"
            )
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update poll: {str(e)}"
        )

@app.delete("/admin/polls/{poll_id}")
async def delete_poll(poll_id: str, _: bool = Depends(verify_admin)):
    try:
        if not is_valid_object_id(poll_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid poll ID format"
            )
            
        # Delete poll
        result = db.polls.delete_one({"_id": ObjectId(poll_id)})
        if result.deleted_count == 0:
            raise HTTPException(
                status_code=404,
                detail="Poll not found"
            )
            
        # Delete all votes for this poll
        db.poll_votes.delete_many({"poll_id": ObjectId(poll_id)})
        
        # Delete related notifications
        db.notifications.delete_many({"poll_id": poll_id})
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete poll: {str(e)}"
        )

# Invoice Management Endpoints
@app.post("/admin/generate-invoices")
async def generate_invoices(
    start_date: str,
    end_date: str,
    _: bool = Depends(verify_admin)
):
    try:
        # Validate date formats
        try:
            datetime.strptime(start_date, "%Y-%m-%d")
            datetime.strptime(end_date, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid date format. Use YYYY-MM-DD"
            )
            
        users = list(db.users.find({"active": True}))
        generated_invoices = []
        
        for user in users:
            # Get user's tiffins for the period
            tiffins = list(db.tiffins.find({
                "assigned_users": user["user_id"],
                "date": {"$gte": start_date, "$lte": end_date},
                "status": {"$ne": TiffinStatus.CANCELLED}
            }))
            
            if tiffins:
                # Check if an invoice already exists for this period and user
                existing_invoice = db.invoices.find_one({
                    "user_id": user["user_id"],
                    "start_date": start_date,
                    "end_date": end_date
                })
                
                if existing_invoice:
                    # Update existing invoice
                    db.invoices.update_one(
                        {"_id": existing_invoice["_id"]},
                        {
                            "$set": {
                                "tiffins": [str(t["_id"]) for t in tiffins],
                                "total_amount": sum(t["price"] for t in tiffins),
                                "updated_at": datetime.now(IST)
                            }
                        }
                    )
                    generated_invoices.append(str(existing_invoice["_id"]))
                else:
                    # Create new invoice
                    invoice = Invoice(
                        user_id=user["user_id"],
                        start_date=start_date,
                        end_date=end_date,
                        tiffins=[str(t["_id"]) for t in tiffins],
                        total_amount=sum(t["price"] for t in tiffins)
                    )
                    
                    result = db.invoices.insert_one(invoice.dict())
                    generated_invoices.append(str(result.inserted_id))
                    
                    # Create notification for user
                    notification = {
                        "user_id": user["user_id"],
                        "title": "New Invoice Generated",
                        "message": f"A new invoice has been generated for the period {start_date} to {end_date}.",
                        "type": "info",
                        "read": False,
                        "created_at": datetime.now(IST),
                        "invoice_id": str(result.inserted_id)
                    }
                    db.notifications.insert_one(notification)
        
        return {
            "status": "success",
            "generated_invoices": len(generated_invoices)
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate invoices: {str(e)}"
        )

@app.get("/admin/invoices")
async def get_all_invoices(
    user_id: Optional[str] = None,
    paid: Optional[bool] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    _: bool = Depends(verify_admin)
):
    try:
        query = {}
        
        if user_id:
            query["user_id"] = user_id
            
        if paid is not None:
            query["paid"] = paid
            
        if start_date:
            try:
                datetime.strptime(start_date, "%Y-%m-%d")
                query["start_date"] = {"$gte": start_date}
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid start_date format. Use YYYY-MM-DD"
                )
                
        if end_date:
            try:
                datetime.strptime(end_date, "%Y-%m-%d")
                query["end_date"] = {"$lte": end_date}
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid end_date format. Use YYYY-MM-DD"
                )
        
        invoices = list(db.invoices.find(query).sort("generated_at", -1))
        
        # Add user details to each invoice
        for invoice in invoices:
            invoice["_id"] = str(invoice["_id"])
            
            user = db.users.find_one({"user_id": invoice["user_id"]}, {"password": 0, "api_key": 0})
            if user:
                user["_id"] = str(user["_id"])
                invoice["user_details"] = user
        
        return invoices
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch invoices: {str(e)}"
        )

@app.get("/admin/invoices/{invoice_id}")
async def get_invoice_by_id(
    invoice_id: str,
    _: bool = Depends(verify_admin)
):
    try:
        if not is_valid_object_id(invoice_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid invoice ID format"
            )
            
        invoice = db.invoices.find_one({"_id": ObjectId(invoice_id)})
        
        if not invoice:
            raise HTTPException(
                status_code=404,
                detail="Invoice not found"
            )
            
        invoice["_id"] = str(invoice["_id"])
        
        # Get user details
        user = db.users.find_one({"user_id": invoice["user_id"]}, {"password": 0, "api_key": 0})
        if user:
            user["_id"] = str(user["_id"])
            invoice["user_details"] = user
            
        # Get tiffin details
        tiffin_details = []
        for tiffin_id in invoice["tiffins"]:
            if is_valid_object_id(tiffin_id):
                tiffin = db.tiffins.find_one({"_id": ObjectId(tiffin_id)})
                if tiffin:
                    tiffin["_id"] = str(tiffin["_id"])
                    tiffin_details.append(tiffin)
        
        invoice["tiffin_details"] = tiffin_details
        
        return invoice
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch invoice: {str(e)}"
        )

@app.get("/user/invoices")
async def get_user_invoices(
    user_id: str = Depends(verify_user),
    paid: Optional[bool] = None
):
    try:
        query = {}
        
        # Admin can see all invoices
        if user_id != ADMIN_ID:
            query["user_id"] = user_id
            
        if paid is not None:
            query["paid"] = paid
        
        invoices = list(db.invoices.find(query).sort("generated_at", -1))
        
        for invoice in invoices:
            invoice["_id"] = str(invoice["_id"])
            
            # Get tiffin count and details
            tiffin_ids = [ObjectId(t_id) for t_id in invoice["tiffins"] if is_valid_object_id(t_id)]
            invoice["tiffin_count"] = len(tiffin_ids)
            
        return invoices
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch invoices: {str(e)}"
        )

@app.get("/user/invoices/{invoice_id}")
async def get_user_invoice_by_id(
    invoice_id: str,
    user_id: str = Depends(verify_user)
):
    try:
        if not is_valid_object_id(invoice_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid invoice ID format"
            )
            
        # Construct query based on user role
        query = {"_id": ObjectId(invoice_id)}
        if user_id != ADMIN_ID:
            query["user_id"] = user_id
            
        invoice = db.invoices.find_one(query)
        
        if not invoice:
            raise HTTPException(
                status_code=404,
                detail="Invoice not found"
            )
            
        invoice["_id"] = str(invoice["_id"])
        
        # Get tiffin details
        tiffin_details = []
        for tiffin_id in invoice["tiffins"]:
            if is_valid_object_id(tiffin_id):
                tiffin = db.tiffins.find_one({"_id": ObjectId(tiffin_id)})
                if tiffin:
                    tiffin["_id"] = str(tiffin["_id"])
                    tiffin_details.append(tiffin)
        
        invoice["tiffin_details"] = tiffin_details
        
        return invoice
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch invoice: {str(e)}"
        )

@app.put("/admin/invoices/{invoice_id}/mark-paid")
async def mark_invoice_paid(
    invoice_id: str,
    _: bool = Depends(verify_admin)
):
    try:
        if not is_valid_object_id(invoice_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid invoice ID format"
            )
            
        # Get invoice first to check if it's already paid
        invoice = db.invoices.find_one({"_id": ObjectId(invoice_id)})
        if not invoice:
            raise HTTPException(
                status_code=404,
                detail="Invoice not found"
            )
            
        if invoice.get("paid", False):
            return {"status": "success", "message": "Invoice was already marked as paid"}
            
        result = db.invoices.update_one(
            {"_id": ObjectId(invoice_id)},
            {"$set": {"paid": True, "paid_at": datetime.now(IST)}}
        )
        
        # Notify user
        notification = {
            "user_id": invoice["user_id"],
            "title": "Invoice Payment Received",
            "message": f"Your payment for invoice #{invoice_id[:8]} has been received.",
            "type": "success",
            "read": False,
            "created_at": datetime.now(IST),
            "invoice_id": invoice_id
        }
        db.notifications.insert_one(notification)
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to mark invoice as paid: {str(e)}"
        )

@app.delete("/admin/invoices/{invoice_id}")
async def delete_invoice(
    invoice_id: str,
    _: bool = Depends(verify_admin)
):
    try:
        if not is_valid_object_id(invoice_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid invoice ID format"
            )
            
        result = db.invoices.delete_one({"_id": ObjectId(invoice_id)})
        
        if result.deleted_count == 0:
            raise HTTPException(
                status_code=404,
                detail="Invoice not found"
            )
            
        # Delete related notifications
        db.notifications.delete_many({"invoice_id": invoice_id})
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete invoice: {str(e)}"
        )

# Notification Endpoints
@app.get("/user/notifications")
async def get_user_notifications(
    user_id: str = Depends(verify_user),
    read: Optional[bool] = None,
    limit: int = Query(50, ge=1, le=100)
):
    try:
        query = {"user_id": user_id}
        
        if read is not None:
            query["read"] = read
            
        notifications = list(db.notifications.find(query).sort("created_at", -1).limit(limit))
        
        for notification in notifications:
            notification["_id"] = str(notification["_id"])
            
        # Get unread count
        unread_count = db.notifications.count_documents({"user_id": user_id, "read": False})
            
        return {
            "notifications": notifications,
            "unread_count": unread_count
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch notifications: {str(e)}"
        )

@app.post("/user/notifications/mark-read")
async def mark_notifications_read(
    notification_ids: List[str],
    user_id: str = Depends(verify_user)
):
    try:
        # Convert string IDs to ObjectIds
        object_ids = []
        for nid in notification_ids:
            if is_valid_object_id(nid):
                object_ids.append(ObjectId(nid))
        
        if not object_ids:
            return {"status": "success", "marked_count": 0}
            
        # Only mark notifications that belong to the user
        result = db.notifications.update_many(
            {
                "_id": {"$in": object_ids},
                "user_id": user_id
            },
            {"$set": {"read": True}}
        )
        
        return {
            "status": "success",
            "marked_count": result.modified_count
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to mark notifications as read: {str(e)}"
        )

@app.post("/user/notifications/mark-all-read")
async def mark_all_notifications_read(user_id: str = Depends(verify_user)):
    try:
        result = db.notifications.update_many(
            {"user_id": user_id, "read": False},
            {"$set": {"read": True}}
        )
        
        return {
            "status": "success",
            "marked_count": result.modified_count
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to mark all notifications as read: {str(e)}"
        )

@app.delete("/user/notifications/{notification_id}")
async def delete_notification(
    notification_id: str,
    user_id: str = Depends(verify_user)
):
    try:
        if not is_valid_object_id(notification_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid notification ID format"
            )
            
        # Only delete notification if it belongs to the user
        result = db.notifications.delete_one({
            "_id": ObjectId(notification_id),
            "user_id": user_id
        })
        
        if result.deleted_count == 0:
            raise HTTPException(
                status_code=404,
                detail="Notification not found or not authorized to delete"
            )
            
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete notification: {str(e)}"
        )

# Dashboard Statistics
@app.get("/admin/dashboard")
async def get_dashboard_stats(_: bool = Depends(verify_admin)):
    try:
        today = datetime.now(IST).strftime("%Y-%m-%d")
        current_month_start = datetime.now(IST).replace(day=1).strftime("%Y-%m-%d")
        
        # Calculate various stats
        total_users = db.users.count_documents({"active": True})
        
        active_tiffins = db.tiffins.count_documents({
            "date": today,
            "status": {"$nin": [TiffinStatus.DELIVERED, TiffinStatus.CANCELLED]}
        })
        
        today_deliveries = db.tiffins.count_documents({
            "date": today,
            "status": TiffinStatus.DELIVERED
        })
        
        # Calculate monthly revenue
        monthly_tiffins = list(db.tiffins.find({
            "date": {"$gte": current_month_start, "$lte": today},
            "status": {"$ne": TiffinStatus.CANCELLED}
        }))
        
        monthly_revenue = sum(t.get("price", 0) for t in monthly_tiffins)
        
        # Get pending requests count
        pending_requests = db.tiffin_requests.count_documents({"status": RequestStatus.PENDING})
        
        # Get unpaid invoices count
        unpaid_invoices = db.invoices.count_documents({"paid": False})
        
        # Get user growth (new users in the last 30 days)
        thirty_days_ago = (datetime.now(IST) - timedelta(days=30)).isoformat()
        new_users = db.users.count_documents({
            "created_at": {"$gte": thirty_days_ago}
        })
        
        stats = {
            "total_users": total_users,
            "active_tiffins": active_tiffins,
            "today_deliveries": today_deliveries,
            "monthly_revenue": monthly_revenue,
            "pending_requests": pending_requests,
            "unpaid_invoices": unpaid_invoices,
            "new_users_30d": new_users,
            "timestamp": datetime.now(IST).isoformat()
        }
        return stats
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch dashboard stats: {str(e)}"
        )

@app.get("/admin/user/{user_id}/stats")
async def get_user_stats(user_id: str, _: bool = Depends(verify_admin)):
    try:
        user = db.users.find_one({"user_id": user_id})
        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )
        
        # Get all tiffins for this user
        tiffins = list(db.tiffins.find({"assigned_users": user_id}))
        
        # Calculate current month tiffins
        current_month_start = datetime.now(IST).replace(day=1).strftime("%Y-%m-%d")
        current_month_tiffins = [t for t in tiffins if t["date"] >= current_month_start]
        
        # Calculate favorite time slot
        time_counts = {}
        for tiffin in tiffins:
            if tiffin["status"] != TiffinStatus.CANCELLED:
                time = tiffin["time"]
                time_counts[time] = time_counts.get(time, 0) + 1
        
        favorite_time = None
        max_count = 0
        for time, count in time_counts.items():
            if count > max_count:
                max_count = count
                favorite_time = time
        
        stats = UserStats(
            total_tiffins=len([t for t in tiffins if t["status"] != TiffinStatus.CANCELLED]),
            cancelled_tiffins=len([t for t in tiffins if t["status"] == TiffinStatus.CANCELLED]),
            total_spent=sum(t.get("price", 0) for t in tiffins if t["status"] != TiffinStatus.CANCELLED),
            active_since=user["created_at"],
            last_login=user.get("last_login"),
            current_month_tiffins=len([t for t in current_month_tiffins if t["status"] != TiffinStatus.CANCELLED]),
            favorite_time=favorite_time
        )
        
        return stats.dict()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch user stats: {str(e)}"
        )

@app.get("/user/dashboard/stats")
async def get_user_dashboard_stats(user_id: str = Depends(verify_user)):
    try:
        # Get today's date
        today = datetime.now(IST).strftime("%Y-%m-%d")
        current_month_start = datetime.now(IST).replace(day=1).strftime("%Y-%m-%d")
        
        # Get today's tiffins
        today_tiffins = list(db.tiffins.find({
            "assigned_users": user_id,
            "date": today
        }).sort("time", 1))
        
        # Get next delivery time
        next_delivery = None
        current_hour = datetime.now(IST).hour
        
        for tiffin in today_tiffins:
            if tiffin["status"] != TiffinStatus.CANCELLED:
                delivery_hour = int(tiffin["delivery_time"].split(":")[0])
                if delivery_hour > current_hour:
                    next_delivery = tiffin["delivery_time"]
                    break
        
        # If no upcoming delivery today, find the next day's first delivery
        if not next_delivery and today_tiffins:
            next_day_tiffin = db.tiffins.find_one({
                "assigned_users": user_id,
                "date": {"$gt": today},
                "status": {"$ne": TiffinStatus.CANCELLED}
            }, sort=[("date", 1), ("delivery_time", 1)])
            
            if next_day_tiffin:
                next_delivery = f"{next_day_tiffin['date']} {next_day_tiffin['delivery_time']}"
        
        # Get current month tiffins
        current_month_tiffins = list(db.tiffins.find({
            "assigned_users": user_id,
            "date": {"$gte": current_month_start, "$lte": today}
        }))
        
        # Get pending invoices
        pending_invoices = db.invoices.count_documents({
            "user_id": user_id,
            "paid": False
        })
        
        # Get upcoming tiffins (next 7 days)
        week_end = (datetime.now(IST) + timedelta(days=7)).strftime("%Y-%m-%d")
        upcoming_tiffins = db.tiffins.count_documents({
            "assigned_users": user_id,
            "date": {"$gt": today, "$lte": week_end},
            "status": {"$ne": TiffinStatus.CANCELLED}
        })
        
        # Get unread notifications
        unread_notifications = db.notifications.count_documents({
            "user_id": user_id,
            "read": False
        })
        
        stats = {
            "today_tiffins": len(today_tiffins),
            "next_delivery": next_delivery,
            "month_tiffins": len([t for t in current_month_tiffins if t["status"] != TiffinStatus.CANCELLED]),
            "month_spent": sum(t.get("price", 0) for t in current_month_tiffins if t["status"] != TiffinStatus.CANCELLED),
            "pending_invoices": pending_invoices,
            "upcoming_tiffins": upcoming_tiffins,
            "unread_notifications": unread_notifications
        }
        
        return stats
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch dashboard stats: {str(e)}"
        )

# System Management
@app.get("/admin/system-health")
async def check_system_health(_: bool = Depends(verify_admin)):
    """Check system health and database status"""
    try:
        db_status = client.admin.command('ping')
        current_time = datetime.now(IST)
        
        # Get collection counts
        users_count = db.users.count_documents({})
        tiffins_count = db.tiffins.count_documents({})
        notices_count = db.notices.count_documents({})
        polls_count = db.polls.count_documents({})
        invoices_count = db.invoices.count_documents({})
        notifications_count = db.notifications.count_documents({})
        
        # Get database size info
        db_stats = client.tiffintreats.command("dbStats")
        
        stats = {
            "database_status": "healthy" if db_status else "unhealthy",
            "server_time": current_time.isoformat(),
            "timezone": str(IST),
            "collection_stats": {
                "users": users_count,
                "tiffins": tiffins_count,
                "notices": notices_count,
                "polls": polls_count,
                "invoices": invoices_count,
                "notifications": notifications_count
            },
            "database_size_mb": round(db_stats["dataSize"] / (1024 * 1024), 2),
            "storage_size_mb": round(db_stats["storageSize"] / (1024 * 1024), 2)
        }
        return stats
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"System health check failed: {str(e)}"
        )

@app.post("/admin/cleanup-data")
async def cleanup_old_data(
    days: int = Query(30, ge=7, le=365),
    _: bool = Depends(verify_admin)
):
    """Manually trigger cleanup of old data"""
    try:
        cutoff_date = (datetime.now(IST) - timedelta(days=days))
        
        # Clean up expired notices
        notices_result = db.notices.delete_many({
            "expires_at": {"$lt": cutoff_date}
        })
        
        # Deactivate old polls
        polls_result = db.polls.update_many(
            {
                "end_date": {"$lt": cutoff_date},
                "active": True
            },
            {"$set": {"active": False}}
        )
        
        # Archive old tiffin requests
        requests_result = db.tiffin_requests.update_many(
            {
                "created_at": {"$lt": cutoff_date},
                "status": RequestStatus.PENDING
            },
            {"$set": {"status": RequestStatus.ARCHIVED}}
        )
        
        # Clean up old read notifications
        notifications_result = db.notifications.delete_many({
            "created_at": {"$lt": cutoff_date},
            "read": True
        })
        
        return {
            "status": "success",
            "cleaned_up": {
                "expired_notices": notices_result.deleted_count,
                "deactivated_polls": polls_result.modified_count,
                "archived_requests": requests_result.modified_count,
                "deleted_notifications": notifications_result.deleted_count
            }
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Cleanup failed: {str(e)}"
        )

@app.get("/admin/export-data")
async def export_data(_: bool = Depends(verify_admin)):
    """Export all relevant data for backup"""
    try:
        export_data = {
            "users": list(db.users.find({}, {"password": 0, "api_key": 0})),
            "tiffins": list(db.tiffins.find()),
            "notices": list(db.notices.find()),
            "polls": list(db.polls.find()),
            "invoices": list(db.invoices.find()),
            "tiffin_requests": list(db.tiffin_requests.find()),
            "export_time": datetime.now(IST).isoformat()
        }
        
        # Convert ObjectIds to strings
        for collection in export_data.values():
            if isinstance(collection, list):
                for doc in collection:
                    if isinstance(doc, dict):
                        doc = serialize_doc(doc)
        
        return export_data
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to export data: {str(e)}"
        )

# Cleanup Functions
async def cleanup_old_data_task():
    """Cleanup old notices, polls, and other data periodically"""
    try:
        thirty_days_ago = datetime.now(IST) - timedelta(days=30)
        
        # Clean up expired notices
        db.notices.delete_many({
            "expires_at": {"$lt": thirty_days_ago}
        })
        
        # Deactivate old polls
        db.polls.update_many(
            {
                "end_date": {"$lt": thirty_days_ago},
                "active": True
            },
            {"$set": {"active": False}}
        )
        
        # Archive old tiffin requests
        db.tiffin_requests.update_many(
            {
                "created_at": {"$lt": thirty_days_ago},
                "status": "pending"
            },
            {"$set": {"status": "archived"}}
        )
        
        # Clean up old read notifications
        db.notifications.delete_many({
            "created_at": {"$lt": thirty_days_ago},
            "read": True
        })
        
        print("Cleanup completed successfully")
    except Exception as e:
        print(f"Cleanup error: {str(e)}")

# Database Indexes
def setup_indexes():
    """Setup necessary database indexes"""
    try:
        # User indexes
        db.users.create_index([("user_id", ASCENDING)], unique=True)
        db.users.create_index([("email", ASCENDING)], unique=True)
        db.users.create_index([("api_key", ASCENDING)], sparse=True)
        db.users.create_index([("active", ASCENDING)])
        
        # Tiffin indexes
        db.tiffins.create_index([("date", ASCENDING)])
        db.tiffins.create_index([("assigned_users", ASCENDING)])
        db.tiffins.create_index([("status", ASCENDING)])
        db.tiffins.create_index([("date", ASCENDING), ("status", ASCENDING)])
        db.tiffins.create_index([("date", ASCENDING), ("assigned_users", ASCENDING)])
        
        # Poll votes index
        db.poll_votes.create_index(
            [("poll_id", ASCENDING), ("user_id", ASCENDING)],
            unique=True
        )
        
        # Notice index
        db.notices.create_index([("expires_at", ASCENDING)])
        db.notices.create_index([("priority", ASCENDING)])
        
        # Invoice index
        db.invoices.create_index([("user_id", ASCENDING)])
        db.invoices.create_index([("paid", ASCENDING)])
        db.invoices.create_index([("start_date", ASCENDING), ("end_date", ASCENDING)])
        
        # Notification index
        db.notifications.create_index([("user_id", ASCENDING)])
        db.notifications.create_index([("user_id", ASCENDING), ("read", ASCENDING)])
        db.notifications.create_index([("created_at", ASCENDING)])
        
        # Tiffin request index
        db.tiffin_requests.create_index([("user_id", ASCENDING)])
        db.tiffin_requests.create_index([("status", ASCENDING)])
        db.tiffin_requests.create_index([("created_at", ASCENDING)])
        
        print("Database indexes setup completed")
    except Exception as e:
        print(f"Error setting up indexes: {str(e)}")

# Startup Event
@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    try:
        # Setup database indexes
        setup_indexes()
        
        # Start background tasks
        asyncio.create_task(cleanup_old_data_task())
        
        # Start keep-alive task
        asyncio.create_task(keep_alive())
        
        print("Application startup completed successfully")
    except Exception as e:
        print(f"Startup error: {str(e)}")

# Shutdown Event
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on application shutdown"""
    try:
        # Close MongoDB connection
        client.close()
        print("Application shutdown completed successfully")
    except Exception as e:
        print(f"Shutdown error: {str(e)}")

# Main entry point
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
