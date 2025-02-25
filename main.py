from fastapi import FastAPI, HTTPException, Depends, Security, BackgroundTasks
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict
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
ADMIN_ID = os.getenv("ADMIN_ID")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")
IST = pytz.timezone('Asia/Kolkata')

# Security
api_key_header = APIKeyHeader(name="X-API-Key")

# Enums
class TiffinTime(str, Enum):
    MORNING = "morning"
    AFTERNOON = "afternoon"
    EVENING = "evening"

class TiffinStatus(str, Enum):
    SCHEDULED = "scheduled"
    PREPARING = "preparing"
    PREPARED = "prepared"
    OUT_FOR_DELIVERY = "out_for_delivery"
    DELIVERED = "delivered"
    CANCELLED = "cancelled"

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
    description: str
    price: float
    cancellation_time: str
    delivery_time: str
    status: TiffinStatus = TiffinStatus.SCHEDULED
    menu_items: List[str]

class TiffinCreate(TiffinBase):
    assigned_users: List[str]

class Tiffin(TiffinBase):
    id: str = Field(alias="_id")
    created_at: datetime = Field(default_factory=lambda: datetime.now(IST))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(IST))

    class Config:
        from_attributes = True

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

class Invoice(BaseModel):
    user_id: str
    start_date: str
    end_date: str
    tiffins: List[str]
    total_amount: float
    paid: bool = False
    generated_at: datetime = Field(default_factory=lambda: datetime.now(IST))

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
    return {"user_id": user["user_id"], "is_admin": False}

# Utility Functions
def generate_api_key() -> str:
    return os.urandom(24).hex()

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
        
        # Combine date and cancellation time
        cancellation_datetime = IST.localize(datetime.combine(tiffin_date, cancellation_time))
        
        return current_time < cancellation_datetime
    except Exception:
        # If any error occurs, default to not allowing cancellation
        return False

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
    if not user or user.get("password") != password:  # Simple password check
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
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
    user_dict.update({
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
    if not user or user["password"] != old_password:
        raise HTTPException(
            status_code=401,
            detail="Invalid current password"
        )
    
    db.users.update_one(
        {"user_id": user_id},
        {"$set": {"password": new_password}}
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
            datetime.strptime(tiffin.delivery_time, "%H:%M")
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
    date: str,
    time: TiffinTime,
    base_tiffin: TiffinCreate,
    user_groups: List[List[str]],
    _: bool = Depends(verify_admin)
):
    created_tiffins = []
    
    # Validate date format
    try:
        datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid date format. Use YYYY-MM-DD"
        )
    
    # Validate time formats in base_tiffin
    try:
        datetime.strptime(base_tiffin.cancellation_time, "%H:%M")
        datetime.strptime(base_tiffin.delivery_time, "%H:%M")
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid time format. Use HH:MM for cancellation_time and delivery_time"
        )
    
    try:
        for user_group in user_groups:
            # Validate all users in group
            for user_id in user_group:
                if not db.users.find_one({"user_id": user_id, "active": True}):
                    raise HTTPException(
                        status_code=400,
                        detail=f"User {user_id} not found or inactive"
                    )
            
            tiffin = base_tiffin.copy()
            tiffin.assigned_users = user_group
            tiffin.date = date
            tiffin.time = time
            
            tiffin_dict = tiffin.dict()
            tiffin_dict.update({
                "created_at": datetime.now(IST),
                "updated_at": datetime.now(IST)
            })
            
            result = db.tiffins.insert_one(tiffin_dict)
            created_tiffins.append(str(result.inserted_id))
        
        return {
            "status": "success",
            "created_tiffins": created_tiffins
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
        
        tiffins = list(db.tiffins.find(query).sort("date", -1))
        for tiffin in tiffins:
            tiffin["_id"] = str(tiffin["_id"])
        return tiffins
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch tiffins: {str(e)}"
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
            
        result = db.tiffins.update_one(
            {"_id": ObjectId(tiffin_id)},
            {
                "$set": {
                    "status": status,
                    "updated_at": datetime.now(IST)
                }
            }
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=404,
                detail="Tiffin not found"
            )
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update tiffin status: {str(e)}"
        )

@app.delete("/admin/tiffins/{tiffin_id}")
async def delete_tiffin(tiffin_id: str, _: bool = Depends(verify_admin)):
    try:
        if not is_valid_object_id(tiffin_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid tiffin ID format"
            )
            
        result = db.tiffins.delete_one({"_id": ObjectId(tiffin_id)})
        
        if result.deleted_count == 0:
            raise HTTPException(
                status_code=404,
                detail="Tiffin not found"
            )
        
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
    date: Optional[str] = None
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
        
        tiffins = list(db.tiffins.find(query).sort("date", -1))
        for tiffin in tiffins:
            tiffin["_id"] = str(tiffin["_id"])
        return tiffins
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch user tiffins: {str(e)}"
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
        
        # For admin, just change status
        if user_id == ADMIN_ID:
            result = db.tiffins.update_one(
                {"_id": ObjectId(tiffin_id)},
                {
                    "$set": {
                        "status": TiffinStatus.CANCELLED,
                        "updated_at": datetime.now(IST)
                    }
                }
            )
        else:
            # For regular user, remove them from assigned_users
            result = db.tiffins.update_one(
                {"_id": ObjectId(tiffin_id)},
                {
                    "$pull": {"assigned_users": user_id},
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
    end_date: Optional[str] = None
):
    try:
        query = {"assigned_users": user_id}
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
        
        history = list(db.tiffins.find(query).sort("date", -1))
        for item in history:
            item["_id"] = str(item["_id"])
        return history
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch history: {str(e)}"
        )

@app.post("/user/request-tiffin")
async def request_special_tiffin(
    request: TiffinRequest,
    user_id: str = Depends(verify_user)
):
    try:
        # If admin is making request, use the provided user_id
        # Otherwise, override with authenticated user's ID
        if user_id != ADMIN_ID:
            request.user_id = user_id
        
        # Validate user exists
        target_user = db.users.find_one({"user_id": request.user_id})
        if not target_user:
            raise HTTPException(
                status_code=404,
                detail="User not found"
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
    status: Optional[str] = None,
    _: bool = Depends(verify_admin)
):
    try:
        query = {}
        if status:
            query["status"] = status
        
        requests = list(db.tiffin_requests.find(query).sort("created_at", -1))
        for request in requests:
            request["_id"] = str(request["_id"])
        return requests
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch tiffin requests: {str(e)}"
        )

# Notice Management Endpoints
@app.post("/admin/notices")
async def create_notice(notice: Notice, _: bool = Depends(verify_admin)):
    try:
        notice_dict = notice.dict()
        result = db.notices.insert_one(notice_dict)
        return {
            "status": "success",
            "notice_id": str(result.inserted_id)
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create notice: {str(e)}"
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
        return {
            "status": "success",
            "poll_id": str(result.inserted_id)
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create poll: {str(e)}"
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
        for poll in polls:
            poll["_id"] = str(poll["_id"])
        return polls
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch polls: {str(e)}"
        )

@app.post("/user/vote-poll/{poll_id}")
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
        poll = db.polls.find_one({
            "_id": ObjectId(poll_id),
            "active": True,
            "start_date": {"$lte": datetime.now(IST)},
            "end_date": {"$gt": datetime.now(IST)}
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
                    detail="Already voted in this poll"
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
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to record vote: {str(e)}"
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
                invoice = Invoice(
                    user_id=user["user_id"],
                    start_date=start_date,
                    end_date=end_date,
                    tiffins=[str(t["_id"]) for t in tiffins],
                    total_amount=sum(t["price"] for t in tiffins)
                )
                
                result = db.invoices.insert_one(invoice.dict())
                generated_invoices.append(str(result.inserted_id))
        
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

@app.get("/user/invoices")
async def get_user_invoices(user_id: str = Depends(verify_user)):
    try:
        # Admin can see all invoices
        if user_id == ADMIN_ID:
            invoices = list(db.invoices.find().sort("generated_at", -1))
        else:
            invoices = list(db.invoices.find({"user_id": user_id}).sort("generated_at", -1))
            
        for invoice in invoices:
            invoice["_id"] = str(invoice["_id"])
        return invoices
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch invoices: {str(e)}"
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
            
        result = db.invoices.update_one(
            {"_id": ObjectId(invoice_id)},
            {"$set": {"paid": True}}
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=404,
                detail="Invoice not found"
            )
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update invoice: {str(e)}"
        )

# Dashboard Statistics
@app.get("/admin/dashboard")
async def get_dashboard_stats(_: bool = Depends(verify_admin)):
    try:
        today = datetime.now(IST).strftime("%Y-%m-%d")
        
        stats = {
            "total_users": db.users.count_documents({"active": True}),
            "active_tiffins": db.tiffins.count_documents({
                "date": today,
                "status": {"$nin": [TiffinStatus.DELIVERED, TiffinStatus.CANCELLED]}
            }),
            "today_deliveries": db.tiffins.count_documents({
                "date": today,
                "status": TiffinStatus.DELIVERED
            }),
            "monthly_revenue": await calculate_monthly_revenue()
        }
        return stats
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch dashboard stats: {str(e)}"
        )

async def calculate_monthly_revenue():
    try:
        start_date = datetime.now(IST).replace(day=1).strftime("%Y-%m-%d")
        end_date = datetime.now(IST).strftime("%Y-%m-%d")
        
        tiffins = list(db.tiffins.find({
            "date": {"$gte": start_date, "$lte": end_date},
            "status": {"$ne": TiffinStatus.CANCELLED}
        }))
        
        return sum(t["price"] for t in tiffins)
    except Exception:
        return 0

# Additional Utility Endpoints
@app.get("/admin/user/{user_id}/stats")
async def get_user_stats(user_id: str, _: bool = Depends(verify_admin)):
    try:
        user = db.users.find_one({"user_id": user_id})
        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )
        
        tiffins = list(db.tiffins.find({"assigned_users": user_id}))
        
        stats = {
            "total_tiffins": len(tiffins),
            "cancelled_tiffins": sum(1 for t in tiffins if t["status"] == TiffinStatus.CANCELLED),
            "total_spent": sum(t["price"] for t in tiffins if t["status"] != TiffinStatus.CANCELLED),
            "active_since": user["created_at"],
            "last_login": user.get("last_login"),
            "current_month_tiffins": sum(1 for t in tiffins if 
                t["date"][:7] == datetime.now(IST).strftime("%Y-%m")
            )
        }
        return stats
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch user stats: {str(e)}"
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
            "invoices": list(db.invoices.find())
        }
        
        # Convert ObjectIds to strings
        for collection in export_data.values():
            for doc in collection:
                doc["_id"] = str(doc["_id"])
                # Convert datetime objects to ISO format strings
                for key, value in doc.items():
                    if isinstance(value, datetime):
                        doc[key] = value.isoformat()
        
        return export_data
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to export data: {str(e)}"
        )

@app.get("/admin/system-health")
async def check_system_health(_: bool = Depends(verify_admin)):
    """Check system health and database status"""
    try:
        db_status = client.admin.command('ping')
        current_time = datetime.now(IST)
        
        stats = {
            "database_status": "healthy" if db_status else "unhealthy",
            "total_users": db.users.count_documents({}),
            "total_tiffins": db.tiffins.count_documents({}),
            "active_polls": db.polls.count_documents({"active": True}),
            "server_time": current_time,
            "timezone": str(IST)
        }
        return stats
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"System health check failed: {str(e)}"
        )

# Cleanup Functions
async def cleanup_old_data():
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
        
        # Tiffin indexes
        db.tiffins.create_index([("date", ASCENDING)])
        db.tiffins.create_index([("assigned_users", ASCENDING)])
        db.tiffins.create_index([("status", ASCENDING)])
        
        # Poll votes index
        db.poll_votes.create_index(
            [("poll_id", ASCENDING), ("user_id", ASCENDING)],
            unique=True
        )
        
        # Notice index
        db.notices.create_index([("expires_at", ASCENDING)])
        
        # Invoice index
        db.invoices.create_index([("user_id", ASCENDING)])
        
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
        background_tasks = BackgroundTasks()
        background_tasks.add_task(cleanup_old_data)
        
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
