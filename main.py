from fastapi import FastAPI, HTTPException, Depends, Security, BackgroundTasks
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from datetime import datetime, time, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
import os
from dotenv import load_dotenv
import uvicorn
import pytz
from enum import Enum

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
client = AsyncIOMotorClient(MONGODB_URL)
db = client.tiffintreats

# Admin Configuration
ADMIN_IDS = os.getenv("ADMIN_IDS").split(",")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

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
    address: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(IST))
    
    class Config:
        orm_mode = True

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

# Utility Functions
def parse_time(time_str: str) -> datetime:
    return datetime.strptime(time_str, "%H:%M").replace(tzinfo=IST)

async def is_cancellation_allowed(tiffin: dict) -> bool:
    current_time = datetime.now(IST)
    cancellation_time = parse_time(tiffin["cancellation_time"])
    return current_time < cancellation_time

# Authentication Middleware
async def verify_admin(
    user_id: str = Depends(APIKeyHeader(name="user-id")),
    password: str = Depends(APIKeyHeader(name="password"))
):
    if user_id not in ADMIN_IDS or password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user_id

async def verify_user(
    user_id: str = Depends(APIKeyHeader(name="user-id")),
    password: str = Depends(APIKeyHeader(name="password"))
):
    user = await db.users.find_one({"user_id": user_id})
    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user_id

# Health Check Endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now(IST)}

# User Endpoints
@app.post("/auth/login")
async def login(user_id: str, password: str):
    if user_id in ADMIN_IDS and password == ADMIN_PASSWORD:
        return {"status": "success", "role": "admin"}
    
    user = await db.users.find_one({"user_id": user_id})
    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return {"status": "success", "role": "user"}

@app.get("/user/tiffins", response_model=List[Tiffin])
async def get_user_tiffins(
    user_id: str = Depends(verify_user),
    date: Optional[str] = None
):
    query = {"assigned_users": user_id}
    if date:
        query["date"] = date
    
    tiffins = await db.tiffins.find(query).to_list(None)
    return tiffins

@app.post("/user/cancel-tiffin")
async def cancel_tiffin(
    tiffin_id: str,
    user_id: str = Depends(verify_user)
):
    tiffin = await db.tiffins.find_one({"_id": ObjectId(tiffin_id)})
    if not tiffin:
        raise HTTPException(status_code=404, detail="Tiffin not found")
    
    if user_id not in tiffin["assigned_users"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    if not await is_cancellation_allowed(tiffin):
        raise HTTPException(status_code=400, detail="Cancellation time has passed")
    
    await db.tiffins.update_one(
        {"_id": ObjectId(tiffin_id)},
        {
            "$set": {"status": TiffinStatus.CANCELLED},
            "$pull": {"assigned_users": user_id}
        }
    )
    
    return {"status": "success"}

# Admin Endpoints
@app.post("/admin/users", dependencies=[Depends(verify_admin)])
async def create_user(user: UserCreate):
    existing_user = await db.users.find_one({"user_id": user.user_id})
    if existing_user:
        raise HTTPException(status_code=400, detail="User ID already exists")
    
    user_dict = user.dict()
    await db.users.insert_one(user_dict)
    return {"status": "success", "user_id": user.user_id}

@app.post("/admin/tiffins", dependencies=[Depends(verify_admin)])
async def create_tiffin(tiffin: TiffinCreate):
    tiffin_dict = tiffin.dict()
    tiffin_dict["created_at"] = datetime.now(IST)
    result = await db.tiffins.insert_one(tiffin_dict)
    return {"status": "success", "tiffin_id": str(result.inserted_id)}

@app.put("/admin/tiffins/{tiffin_id}/status", dependencies=[Depends(verify_admin)])
async def update_tiffin_status(tiffin_id: str, status: TiffinStatus):
    result = await db.tiffins.update_one(
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

@app.post("/admin/notices", dependencies=[Depends(verify_admin)])
async def create_notice(notice: Notice):
    result = await db.notices.insert_one(notice.dict())
    return {"status": "success", "notice_id": str(result.inserted_id)}

@app.post("/admin/polls", dependencies=[Depends(verify_admin)])
async def create_poll(poll: Poll):
    result = await db.polls.insert_one(poll.dict())
    return {"status": "success", "poll_id": str(result.inserted_id)}

# Additional Models
class TiffinHistory(BaseModel):
    user_id: str
    tiffin_id: str
    original_status: TiffinStatus
    new_status: TiffinStatus
    changed_at: datetime = Field(default_factory=lambda: datetime.now(IST))

class UserStats(BaseModel):
    total_tiffins: int
    cancelled_tiffins: int
    total_spent: float
    active_since: datetime

class DashboardStats(BaseModel):
    total_users: int
    active_tiffins: int
    today_deliveries: int
    monthly_revenue: float

# User Endpoints (continued)

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
    
    history = await db.tiffins.find(query).sort("date", -1).to_list(None)
    return history

@app.get("/user/invoices")
async def get_user_invoices(user_id: str = Depends(verify_user)):
    invoices = await db.invoices.find({"user_id": user_id}).to_list(None)
    return invoices

@app.post("/user/request-tiffin")
async def request_special_tiffin(
    request: TiffinRequest,
    user_id: str = Depends(verify_user)
):
    request_dict = request.dict()
    request_dict["status"] = "pending"
    request_dict["created_at"] = datetime.now(IST)
    result = await db.tiffin_requests.insert_one(request_dict)
    return {"status": "success", "request_id": str(result.inserted_id)}

@app.put("/user/profile")
async def update_user_profile(
    updates: Dict,
    user_id: str = Depends(verify_user)
):
    allowed_updates = ["name", "address"]
    update_data = {k: v for k, v in updates.items() if k in allowed_updates}
    
    if not update_data:
        raise HTTPException(status_code=400, detail="No valid updates provided")
    
    result = await db.users.update_one(
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
    # Check if user already voted
    existing_vote = await db.poll_votes.find_one({
        "poll_id": ObjectId(poll_id),
        "user_id": user_id
    })
    
    if existing_vote:
        raise HTTPException(status_code=400, detail="Already voted")
    
    # Record vote
    await db.poll_votes.insert_one({
        "poll_id": ObjectId(poll_id),
        "user_id": user_id,
        "option_index": option_index,
        "voted_at": datetime.now(IST)
    })
    
    # Update poll option count
    await db.polls.update_one(
        {"_id": ObjectId(poll_id)},
        {"$inc": {f"options.{option_index}.votes": 1}}
    )
    
    return {"status": "success"}

# Admin Endpoints (continued)

@app.get("/admin/dashboard", dependencies=[Depends(verify_admin)])
async def get_dashboard_stats():
    today = datetime.now(IST).strftime("%Y-%m-%d")
    
    stats = DashboardStats(
        total_users=await db.users.count_documents({"active": True}),
        active_tiffins=await db.tiffins.count_documents({
            "date": today,
            "status": {"$nin": [TiffinStatus.DELIVERED, TiffinStatus.CANCELLED]}
        }),
        today_deliveries=await db.tiffins.count_documents({
            "date": today,
            "status": TiffinStatus.DELIVERED
        }),
        monthly_revenue=await calculate_monthly_revenue()
    )
    return stats

@app.get("/admin/user/{user_id}/stats", dependencies=[Depends(verify_admin)])
async def get_user_stats(user_id: str):
    user = await db.users.find_one({"user_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    tiffins = await db.tiffins.find({"assigned_users": user_id}).to_list(None)
    
    stats = UserStats(
        total_tiffins=len(tiffins),
        cancelled_tiffins=sum(1 for t in tiffins if t["status"] == TiffinStatus.CANCELLED),
        total_spent=sum(t["price"] for t in tiffins if t["status"] != TiffinStatus.CANCELLED),
        active_since=user["created_at"]
    )
    return stats

@app.post("/admin/generate-invoices", dependencies=[Depends(verify_admin)])
async def generate_invoices(start_date: str, end_date: str):
    users = await db.users.find({"active": True}).to_list(None)
    generated_invoices = []
    
    for user in users:
        tiffins = await db.tiffins.find({
            "assigned_users": user["user_id"],
            "date": {"$gte": start_date, "$lte": end_date},
            "status": {"$ne": TiffinStatus.CANCELLED}
        }).to_list(None)
        
        if tiffins:
            invoice = Invoice(
                user_id=user["user_id"],
                start_date=start_date,
                end_date=end_date,
                tiffins=[str(t["_id"]) for t in tiffins],
                total_amount=sum(t["price"] for t in tiffins)
            )
            result = await db.invoices.insert_one(invoice.dict())
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
        
        result = await db.tiffins.insert_one(tiffin.dict())
        created_tiffins.append(str(result.inserted_id))
    
    return {"status": "success", "created_tiffins": created_tiffins}

@app.delete("/admin/tiffins/{tiffin_id}", dependencies=[Depends(verify_admin)])
async def delete_tiffin(tiffin_id: str):
    result = await db.tiffins.delete_one({"_id": ObjectId(tiffin_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Tiffin not found")
    return {"status": "success"}

# Utility Functions
async def calculate_monthly_revenue():
    start_date = datetime.now(IST).replace(day=1).strftime("%Y-%m-%d")
    end_date = datetime.now(IST).strftime("%Y-%m-%d")
    
    tiffins = await db.tiffins.find({
        "date": {"$gte": start_date, "$lte": end_date},
        "status": {"$ne": TiffinStatus.CANCELLED}
    }).to_list(None)
    
    return sum(t["price"] for t in tiffins)

# Background Tasks
async def cleanup_old_data():
    thirty_days_ago = datetime.now(IST) - timedelta(days=30)
    await db.notices.delete_many({"expires_at": {"$lt": thirty_days_ago}})
    await db.polls.update_many(
        {"end_date": {"$lt": thirty_days_ago}},
        {"$set": {"active": False}}
    )

# Startup Event
@app.on_event("startup")
async def startup_event():
    # Create indexes
    await db.users.create_index("user_id", unique=True)
    await db.tiffins.create_index([("date", 1), ("time", 1)])
    await db.poll_votes.create_index([("poll_id", 1), ("user_id", 1)], unique=True)

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        workers=4
    )
