rom fastapi import FastAPI, HTTPException, Depends, Security, BackgroundTasks
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
from passlib.context import CryptContext
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
    allow_headers=["*"],
)

# Database Configuration
MONGODB_URL = os.getenv("MONGODB_URL")
client = MongoClient(MONGODB_URL, server_api=ServerApi('1'))
db = client.tiffintreats

# Security Configuration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
api_key_header = APIKeyHeader(name="X-API-Key")

# Admin Configuration
ADMIN_IDS = os.getenv("ADMIN_IDS", "").split(",")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")

# Timezone Configuration
IST = pytz.timezone('Asia/Kolkata')

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

# Models
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
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

async def verify_admin(api_key: str = Depends(api_key_header)):
    if api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return True

async def verify_user(api_key: str = Depends(api_key_header)):
    user = db.users.find_one({"api_key": api_key})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return user["user_id"]

# Utility Functions
def parse_time(time_str: str) -> datetime:
    return datetime.strptime(time_str, "%H:%M").replace(tzinfo=IST)

async def is_cancellation_allowed(tiffin: dict) -> bool:
    current_time = datetime.now(IST)
    cancellation_time = parse_time(tiffin["cancellation_time"])
    return current_time < cancellation_time

async def calculate_monthly_revenue():
    start_date = datetime.now(IST).replace(day=1).strftime("%Y-%m-%d")
    end_date = datetime.now(IST).strftime("%Y-%m-%d")
    
    tiffins = list(db.tiffins.find({
        "date": {"$gte": start_date, "$lte": end_date},
        "status": {"$ne": TiffinStatus.CANCELLED}
    }))
    
    return sum(t["price"] for t in tiffins)

# Health Check Endpoint
@app.get("/health")
async def health_check():
    try:
        client.admin.command('ping')
        return {"status": "healthy", "timestamp": datetime.now(IST)}
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))
        

APP_URL = os.getenv("APP_URL", "https://tiffintreats-20mb.onrender.com")
PING_INTERVAL = 14 * 60 
async def keep_alive():
    async with httpx.AsyncClient() as client:
        while True:
            try:
                response = await client.get(f"{APP_URL}/health")
                print(f"Keep-alive ping sent. Status: {response.status_code}")
            except Exception as e:
                print(f"Keep-alive ping failed: {e}")
            await asyncio.sleep(PING_INTERVAL)
# Root Endpoint
@app.get("/")
async def root():
    return {"message": "Welcome to TiffinTreats API", "docs": "/docs"}

# User Endpoints
@app.post("/auth/login")
async def login(user_id: str, password: str):
    user = db.users.find_one({"user_id": user_id})
    if not user or not verify_password(password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return {
        "status": "success",
        "api_key": user["api_key"],
        "role": "admin" if user_id in ADMIN_IDS else "user"
    }

@app.get("/user/tiffins", response_model=List[Tiffin])
async def get_user_tiffins(
    user_id: str = Depends(verify_user),
    date: Optional[str] = None
):
    query = {"assigned_users": user_id}
    if date:
        query["date"] = date
    
    tiffins = list(db.tiffins.find(query))
    for tiffin in tiffins:
        tiffin["_id"] = str(tiffin["_id"])
    return tiffins

@app.post("/user/cancel-tiffin")
async def cancel_tiffin(
    tiffin_id: str,
    user_id: str = Depends(verify_user)
):
    tiffin = db.tiffins.find_one({"_id": ObjectId(tiffin_id)})
    if not tiffin:
        raise HTTPException(status_code=404, detail="Tiffin not found")
    
    if user_id not in tiffin["assigned_users"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    if not await is_cancellation_allowed(tiffin):
        raise HTTPException(status_code=400, detail="Cancellation time has passed")
    
    db.tiffins.update_one(
        {"_id": ObjectId(tiffin_id)},
        {
            "$set": {"status": TiffinStatus.CANCELLED},
            "$pull": {"assigned_users": user_id}
        }
    )
    
    return {"status": "success"}

@app.get("/user/history")
async def get_user_history(
    user_id: str = Depends(verify_user),
    start_date: Optional[str] = None,
    end_date: Optional[str] = None
):
    query = {"assigned_users": user_id}
    if start_date:
        query["date"] = {"$gte": start_date}
    if end_date:
        query["date"] = {"$lte": end_date}
    
    history = list(db.tiffins.find(query).sort("date", -1))
    for item in history:
        item["_id"] = str(item["_id"])
    return history

@app.get("/user/invoices")
async def get_user_invoices(user_id: str = Depends(verify_user)):
    invoices = list(db.invoices.find({"user_id": user_id}))
    for invoice in invoices:
        invoice["_id"] = str(invoice["_id"])
    return invoices

@app.post("/user/request-tiffin")
async def request_special_tiffin(
    request: TiffinRequest,
    user_id: str = Depends(verify_user)
):
    request_dict = request.dict()
    request_dict["status"] = "pending"
    request_dict["created_at"] = datetime.now(IST)
    result = db.tiffin_requests.insert_one(request_dict)
    return {"status": "success", "request_id": str(result.inserted_id)}

@app.put("/user/profile")
async def update_user_profile(
    updates: Dict,
    user_id: str = Depends(verify_user)
):
    allowed_updates = ["name", "address", "email"]
    update_data = {k: v for k, v in updates.items() if k in allowed_updates}
    
    if not update_data:
        raise HTTPException(status_code=400, detail="No valid updates provided")
    
    db.users.update_one(
        {"user_id": user_id},
        {"$set": update_data}
    )
    return {"status": "success"}

@app.post("/user/vote-poll/{poll_id}")
async def vote_poll(
    poll_id: str,
    option_index: int,
    user_id: str = Depends(verify_user)
):
    existing_vote = db.poll_votes.find_one({
        "poll_id": ObjectId(poll_id),
        "user_id": user_id
    })
    
    if existing_vote:
        raise HTTPException(status_code=400, detail="Already voted")
    
    db.poll_votes.insert_one({
        "poll_id": ObjectId(poll_id),
        "user_id": user_id,
        "option_index": option_index,
        "voted_at": datetime.now(IST)
    })
    
    db.polls.update_one(
        {"_id": ObjectId(poll_id)},
        {"$inc": {f"options.{option_index}.votes": 1}}
    )
    
    return {"status": "success"}

# Admin Endpoints
@app.post("/admin/users", dependencies=[Depends(verify_admin)])
async def create_user(user: UserCreate):
    existing_user = db.users.find_one({"user_id": user.user_id})
    if existing_user:
        raise HTTPException(status_code=400, detail="User ID already exists")
    
    user_dict = user.dict()
    user_dict["password"] = get_password_hash(user_dict["password"])
    user_dict["api_key"] = os.urandom(24).hex()
    
    db.users.insert_one(user_dict)
    return {"status": "success", "user_id": user.user_id}

@app.post("/admin/tiffins", dependencies=[Depends(verify_admin)])
async def create_tiffin(tiffin: TiffinCreate):
    tiffin_dict = tiffin.dict()
    tiffin_dict["created_at"] = datetime.now(IST)
    result = db.tiffins.insert_one(tiffin_dict)
    return {"status": "success", "tiffin_id": str(result.inserted_id)}

@app.put("/admin/tiffins/{tiffin_id}/status", dependencies=[Depends(verify_admin)])
async def update_tiffin_status(tiffin_id: str, status: TiffinStatus):
    result = db.tiffins.update_one(
        {"_id": ObjectId(tiffin_id)},
        {
            "$set": {
                "status": status,
                "updated_at": datetime.now(IST)
            }
        }
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Tiffin not found")
    return {"status": "success"}

@app.get("/admin/dashboard", dependencies=[Depends(verify_admin)])
async def get_dashboard_stats():
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

@app.get("/admin/user/{user_id}/stats", dependencies=[Depends(verify_admin)])
async def get_user_stats(user_id: str):
    user = db.users.find_one({"user_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    tiffins = list(db.tiffins.find({"assigned_users": user_id}))
    
    stats = {
        "total_tiffins": len(tiffins),
        "cancelled_tiffins": sum(1 for t in tiffins if t["status"] == TiffinStatus.CANCELLED),
        "total_spent": sum(t["price"] for t in tiffins if t["status"] != TiffinStatus.CANCELLED),
        "active_since": user["created_at"]
    }
    return stats

@app.post("/admin/generate-invoices", dependencies=[Depends(verify_admin)])
async def generate_invoices(start_date: str, end_date: str):
    users = list(db.users.find({"active": True}))
    generated_invoices = []
    
    for user in users:
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
    
    return {"status": "success", "generated_invoices": len(generated_invoices)}

@app.post("/admin/batch-tiffins", dependencies=[Depends(verify_admin)])
async def create_batch_tiffins(
    date: str,
    time: TiffinTime,
    base_tiffin: TiffinCreate,
    user_groups: List[List[str]]
):
    created_tiffins = []
    
    for user_group in user_groups:
        tiffin = base_tiffin.copy()
        tiffin.assigned_users = user_group
        tiffin.date = date
        tiffin.time = time
        
        tiffin_dict = tiffin.dict()
        tiffin_dict["created_at"] = datetime.now(IST)
        result = db.tiffins.insert_one(tiffin_dict)
        created_tiffins.append(str(result.inserted_id))
    
    return {"status": "success", "created_tiffins": created_tiffins}

@app.delete("/admin/tiffins/{tiffin_id}", dependencies=[Depends(verify_admin)])
async def delete_tiffin(tiffin_id: str):
    result = db.tiffins.delete_one({"_id": ObjectId(tiffin_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Tiffin not found")
    return {"status": "success"}

@app.post("/admin/notices", dependencies=[Depends(verify_admin)])
async def create_notice(notice: Notice):
    result = db.notices.insert_one(notice.dict())
    return {"status": "success", "notice_id": str(result.inserted_id)}

@app.post("/admin/polls", dependencies=[Depends(verify_admin)])
async def create_poll(poll: Poll):
    result = db.polls.insert_one(poll.dict())
    return {"status": "success", "poll_id": str(result.inserted_id)}

# Add the new endpoints to the existing code

# Fetch Notices for Users
@app.get("/user/notices")
async def get_user_notices(user_id: str = Depends(verify_user)):
    notices = list(db.notices.find().sort("created_at", -1))
    for notice in notices:
        notice["_id"] = str(notice["_id"])
    return notices

# Manage Addresses for Admins
@app.put("/admin/users/{user_id}/address", dependencies=[Depends(verify_admin)])
async def update_user_address(user_id: str, address: str):
    result = db.users.update_one(
        {"user_id": user_id},
        {"$set": {"address": address}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "success"}

# View All Histories for Admins
@app.get("/admin/histories", dependencies=[Depends(verify_admin)])
async def get_all_histories():
    histories = list(db.tiffins.find().sort("date", -1))
    for history in histories:
        history["_id"] = str(history["_id"])
    return histories

# Background Tasks
async def cleanup_old_data():
    thirty_days_ago = datetime.now(IST) - timedelta(days=30)
    db.notices.delete_many({"expires_at": {"$lt": thirty_days_ago}})
    db.polls.update_many(
        {"end_date": {"$lt": thirty_days_ago}},
        {"$set": {"active": False}}
    )

# Startup Event
@app.on_event("startup")
async def startup_event():
    # Create indexes
    db.users.create_index([("user_id", ASCENDING)], unique=True)
    db.users.create_index([("email", ASCENDING)], unique=True)
    db.users.create_index([("api_key", ASCENDING)], unique=True)
    db.tiffins.create_index([("date", ASCENDING), ("time", ASCENDING)])
    db.poll_votes.create_index(
        [("poll_id", ASCENDING), ("user_id", ASCENDING)],
        unique=True
    )
    
    # Schedule background tasks
    background_tasks = BackgroundTasks()
    background_tasks.add_task(cleanup_old_data)
    
    # Start the keep-alive task
    asyncio.create_task(keep_alive())
    
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
