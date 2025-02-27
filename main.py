from fastapi import FastAPI, HTTPException, Depends, Security, BackgroundTasks, Query, Request
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr, validator
from typing import List, Optional, Dict, Any, Union
from datetime import datetime, timedelta
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.server_api import ServerApi
from bson import ObjectId
import os
from dotenv import load_dotenv
import uvicorn
import pytz
from enum import Enum
import asyncio
import httpx
import json
import secrets
import hashlib
import logging
import time
import re
import boto3
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.requests import Request as StarletteRequest
from starlette.status import HTTP_429_TOO_MANY_REQUESTS
import socket
import uuid
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("api.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("tiffintreats-api")

# Load environment variables
load_dotenv()

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Initialize FastAPI
app = FastAPI(title="TiffinTreats API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security constants
API_KEY_EXPIRY_DAYS = int(os.getenv("API_KEY_EXPIRY_DAYS", "30"))
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
LOGIN_LOCKOUT_MINUTES = int(os.getenv("LOGIN_LOCKOUT_MINUTES", "30"))
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "").encode()
if not ENCRYPTION_KEY:
    # Generate a key if not provided
    salt = b"tiffintreats_salt"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    ENCRYPTION_KEY = base64.urlsafe_b64encode(kdf.derive("default_key".encode()))
    logger.warning("Using default encryption key. Set ENCRYPTION_KEY in environment for better security.")

# Initialize encryption
cipher_suite = Fernet(ENCRYPTION_KEY)

# CORS Configuration with stricter settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        os.getenv("FRONTEND_URL", "http://localhost:3000"),
        os.getenv("ADMIN_FRONTEND_URL", "http://localhost:5000")
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*", "X-API-Key"],
    max_age=86400,  # 1 day in seconds
)

# MongoDB Connection
MONGODB_URL = os.getenv("MONGODB_URL")
client = MongoClient(MONGODB_URL, server_api=ServerApi('1'))
db = client.tiffintreats

# AWS S3 for backups
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY", "")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_KEY", "")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
AWS_BUCKET = os.getenv("AWS_BUCKET", "tiffintreats-backups")

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
    AFTERNOON = "afternoon"
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

# Base Models with Enhanced Validation
class UserBase(BaseModel):
    user_id: str
    name: str
    email: EmailStr
    address: str
    
    @validator('user_id')
    def validate_user_id(cls, v):
        if not re.match(r'^[a-zA-Z0-9_]{3,30}$', v):
            raise ValueError('user_id must be 3-30 characters and contain only letters, numbers, and underscores')
        return v
    
    @validator('name')
    def validate_name(cls, v):
        if not re.match(r'^[a-zA-Z0-9\s]{2,100}$', v):
            raise ValueError('Name must be 2-100 characters')
        return v
    
    @validator('address')
    def validate_address(cls, v):
        if len(v) < 5 or len(v) > 200:
            raise ValueError('Address must be 5-200 characters')
        return v

class UserCreate(UserBase):
    password: str
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'[0-9]', v):
            raise ValueError('Password must contain at least one number')
        return v

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
    
    @validator('date')
    def validate_date(cls, v):
        try:
            datetime.strptime(v, "%Y-%m-%d")
        except ValueError:
            raise ValueError('Date must be in YYYY-MM-DD format')
        return v
    
    @validator('price')
    def validate_price(cls, v):
        if v < 0:
            raise ValueError('Price cannot be negative')
        return round(v, 2)  # Round to 2 decimal places
    
    @validator('cancellation_time', 'delivery_time')
    def validate_time_format(cls, v):
        try:
            datetime.strptime(v, "%H:%M")
        except ValueError:
            raise ValueError('Time must be in HH:MM format')
        return v

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
    
    @validator('price')
    def validate_price(cls, v):
        if v is not None and v < 0:
            raise ValueError('Price cannot be negative')
        return round(v, 2) if v is not None else None
    
    @validator('cancellation_time', 'delivery_time')
    def validate_time_format(cls, v):
        if v is not None:
            try:
                datetime.strptime(v, "%H:%M")
            except ValueError:
                raise ValueError('Time must be in HH:MM format')
        return v

class Notice(BaseModel):
    title: str
    content: str
    priority: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(IST))
    expires_at: Optional[datetime] = None
    
    @validator('title')
    def validate_title(cls, v):
        if len(v) < 3 or len(v) > 100:
            raise ValueError('Title must be 3-100 characters')
        return v
    
    @validator('priority')
    def validate_priority(cls, v):
        if v not in [0, 1, 2]:
            raise ValueError('Priority must be 0, 1, or 2')
        return v

class PollOption(BaseModel):
    option: str
    votes: int = 0
    
    @validator('option')
    def validate_option(cls, v):
        if len(v) < 1 or len(v) > 100:
            raise ValueError('Option must be 1-100 characters')
        return v
    
    @validator('votes')
    def validate_votes(cls, v):
        if v < 0:
            raise ValueError('Votes cannot be negative')
        return v

class Poll(BaseModel):
    question: str
    options: List[PollOption]
    start_date: datetime
    end_date: datetime
    active: bool = True
    
    @validator('question')
    def validate_question(cls, v):
        if len(v) < 5 or len(v) > 200:
            raise ValueError('Question must be 5-200 characters')
        return v
    
    @validator('options')
    def validate_options(cls, v):
        if len(v) < 2:
            raise ValueError('Poll must have at least 2 options')
        return v
    
    @validator('end_date')
    def validate_end_date(cls, v, values):
        if 'start_date' in values and v <= values['start_date']:
            raise ValueError('End date must be after start date')
        return v

class TiffinRequest(BaseModel):
    user_id: str
    description: str
    preferred_date: str
    preferred_time: TiffinTime
    special_instructions: Optional[str] = None
    status: RequestStatus = RequestStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(IST))
    
    @validator('preferred_date')
    def validate_date(cls, v):
        try:
            datetime.strptime(v, "%Y-%m-%d")
        except ValueError:
            raise ValueError('Date must be in YYYY-MM-DD format')
        return v
    
    @validator('description')
    def validate_description(cls, v):
        if len(v) < 5 or len(v) > 500:
            raise ValueError('Description must be 5-500 characters')
        return v

class TiffinRequestApproval(BaseModel):
    date: str
    time: TiffinTime
    price: float
    delivery_time: str
    cancellation_time: str
    menu_items: Optional[List[str]] = None
    
    @validator('date')
    def validate_date(cls, v):
        try:
            datetime.strptime(v, "%Y-%m-%d")
        except ValueError:
            raise ValueError('Date must be in YYYY-MM-DD format')
        return v
    
    @validator('price')
    def validate_price(cls, v):
        if v < 0:
            raise ValueError('Price cannot be negative')
        return round(v, 2)
    
    @validator('cancellation_time', 'delivery_time')
    def validate_time_format(cls, v):
        try:
            datetime.strptime(v, "%H:%M")
        except ValueError:
            raise ValueError('Time must be in HH:MM format')
        return v

class Invoice(BaseModel):
    user_id: str
    start_date: str
    end_date: str
    tiffins: List[str]
    total_amount: float
    paid: bool = False
    generated_at: datetime = Field(default_factory=lambda: datetime.now(IST))
    
    @validator('start_date', 'end_date')
    def validate_date(cls, v):
        try:
            datetime.strptime(v, "%Y-%m-%d")
        except ValueError:
            raise ValueError('Date must be in YYYY-MM-DD format')
        return v
    
    @validator('total_amount')
    def validate_total_amount(cls, v):
        if v < 0:
            raise ValueError('Total amount cannot be negative')
        return round(v, 2)
    
    @validator('end_date')
    def validate_end_date(cls, v, values):
        if 'start_date' in values and v < values['start_date']:
            raise ValueError('End date must be after or equal to start date')
        return v

class Notification(BaseModel):
    user_id: str
    title: str
    message: str
    type: str  # "info", "warning", "error", "success"
    read: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(IST))
    
    @validator('type')
    def validate_type(cls, v):
        if v not in ["info", "warning", "error", "success"]:
            raise ValueError('Type must be one of: info, warning, error, success')
        return v

class UserStats(BaseModel):
    total_tiffins: int
    cancelled_tiffins: int
    total_spent: float
    active_since: datetime
    last_login: Optional[datetime] = None
    current_month_tiffins: int
    favorite_time: Optional[str] = None

class LoginAttempt(BaseModel):
    user_id: str
    attempts: int = 1
    last_attempt: datetime = Field(default_factory=lambda: datetime.now(IST))
    locked_until: Optional[datetime] = None

class AuditLog(BaseModel):
    user_id: str
    action: str
    resource: str
    resource_id: Optional[str] = None
    details: Optional[Dict] = None
    ip_address: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(IST))

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
async def verify_admin(api_key: str = Depends(api_key_header), request: Request = None):
    if api_key != ADMIN_API_KEY:
        # Log failed admin access attempt
        client_ip = request.client.host if request else "unknown"
        log_security_event("admin_access_failed", None, f"Invalid admin API key from IP: {client_ip}")
        raise HTTPException(
            status_code=401,
            detail="Invalid admin API key"
        )
    return True

async def verify_user(api_key: str = Depends(api_key_header), request: Request = None):
    # Check if it's admin first
    if api_key == ADMIN_API_KEY:
        return ADMIN_ID
        
    user = db.users.find_one({"api_key": api_key})
    if not user:
        # Log failed user access attempt
        client_ip = request.client.host if request else "unknown"
        log_security_event("user_access_failed", None, f"Invalid API key from IP: {client_ip}")
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )
    
    # Check if API key is expired
    if user.get("api_key_expiry"):
        expiry = user["api_key_expiry"]
        if isinstance(expiry, str):
            expiry = datetime.fromisoformat(expiry)
        if datetime.now(IST) > expiry:
            log_security_event("expired_api_key", user["user_id"], "User attempted to use expired API key")
            raise HTTPException(
                status_code=401,
                detail="API key has expired. Please log in again."
            )
    
    # Check if user is active
    if not user.get("active", True):
        log_security_event("inactive_user_access", user["user_id"], "Inactive user attempted to access API")
        raise HTTPException(
            status_code=403,
            detail="User account is inactive"
        )
        
    return user["user_id"]

async def verify_api_key(api_key: str = Depends(api_key_header), request: Request = None):
    """Verify API key for both admin and regular users"""
    # Check if it's the admin API key
    if api_key == ADMIN_API_KEY:
        return {"user_id": ADMIN_ID, "is_admin": True}
    
    # Otherwise check regular users
    user = db.users.find_one({"api_key": api_key})
    if not user:
        # Log failed access attempt
        client_ip = request.client.host if request else "unknown"
        log_security_event("api_access_failed", None, f"Invalid API key from IP: {client_ip}")
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )
    
    # Check if API key is expired
    if user.get("api_key_expiry"):
        expiry = user["api_key_expiry"]
        if isinstance(expiry, str):
            expiry = datetime.fromisoformat(expiry)
        if datetime.now(IST) > expiry:
            log_security_event("expired_api_key", user["user_id"], "User attempted to use expired API key")
            raise HTTPException(
                status_code=401,
                detail="API key has expired. Please log in again."
            )
        
    # Check if user is active
    if not user.get("active", True):
        log_security_event("inactive_user_access", user["user_id"], "Inactive user attempted to access API")
        raise HTTPException(
            status_code=403,
            detail="User account is inactive"
        )
        
    return {"user_id": user["user_id"], "is_admin": False}

# Rate limiting middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    
    # Apply different rate limits based on endpoint and client
    client_ip = request.client.host
    path = request.url.path
    
    # Implement tiered rate limiting
    if path.startswith("/admin"):
        # Admin endpoints get higher limit
        if await is_rate_limited(client_ip, "admin", 300, 60):  # 300 requests per minute
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please try again later."}
            )
    elif path.startswith("/auth"):
        # Auth endpoints get strict limit to prevent brute force
        if await is_rate_limited(client_ip, "auth", 10, 60):  # 10 requests per minute
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many authentication attempts. Please try again later."}
            )
    else:
        # Regular endpoints
        if await is_rate_limited(client_ip, "general", 120, 60):  # 120 requests per minute
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please try again later."}
            )
    
    response = await call_next(request)
    
    # Add processing time header
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    
    # Add security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    return response

# Utility Functions
async def is_rate_limited(client_ip: str, endpoint_type: str, max_requests: int, window_seconds: int) -> bool:
    """Check if the client IP is rate limited for the given endpoint type"""
    current_time = time.time()
    key = f"rate_limit:{client_ip}:{endpoint_type}"
    
    # Use MongoDB for rate limiting storage
    result = db.rate_limits.find_one({"key": key})
    
    if not result:
        # First request, create new record
        db.rate_limits.insert_one({
            "key": key,
            "requests": 1,
            "window_start": current_time,
            "updated_at": datetime.now(IST)
        })
        return False
    
    # Check if window has expired
    if current_time - result["window_start"] > window_seconds:
        # Reset window
        db.rate_limits.update_one(
            {"key": key},
            {
                "$set": {
                    "requests": 1,
                    "window_start": current_time,
                    "updated_at": datetime.now(IST)
                }
            }
        )
        return False
    
    # Increment request count
    requests = result["requests"] + 1
    db.rate_limits.update_one(
        {"key": key},
        {
            "$set": {
                "requests": requests,
                "updated_at": datetime.now(IST)
            }
        }
    )
    
    # Check if limit exceeded
    if requests > max_requests:
        # Log rate limit exceeded
        logger.warning(f"Rate limit exceeded: {client_ip} for {endpoint_type}")
        return True
    
    return False

def generate_api_key() -> str:
    """Generate a secure API key"""
    return secrets.token_hex(32)  # Increased from 24 to 32 bytes for more security

def hash_password(password: str) -> str:
    """Hash password using SHA-256 with salt"""
    salt = secrets.token_hex(8)
    hashed = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}:{hashed}"

def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verify a password against the stored hash"""
    if ":" not in stored_password:
        # Handle old password format (no salt)
        return stored_password == hashlib.sha256(provided_password.encode()).hexdigest()
    
    # Handle new salted format
    salt, hashed = stored_password.split(":", 1)
    return hashed == hashlib.sha256((provided_password + salt).encode()).hexdigest()

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

def encrypt_sensitive_data(data: str) -> str:
    """Encrypt sensitive data"""
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_sensitive_data(encrypted_data: str) -> str:
    """Decrypt sensitive data"""
    try:
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except Exception:
        logger.error("Failed to decrypt data")
        return None

def log_security_event(action: str, user_id: Optional[str], details: str, ip_address: Optional[str] = None):
    """Log security-related events to the database"""
    try:
        db.security_logs.insert_one({
            "action": action,
            "user_id": user_id,
            "details": details,
            "ip_address": ip_address,
            "timestamp": datetime.now(IST)
        })
    except Exception as e:
        logger.error(f"Failed to log security event: {e}")

def log_audit(user_id: str, action: str, resource: str, resource_id: Optional[str] = None, 
              details: Optional[Dict] = None, ip_address: Optional[str] = None):
    """Log audit information for important actions"""
    try:
        db.audit_logs.insert_one({
            "user_id": user_id,
            "action": action,
            "resource": resource,
            "resource_id": resource_id,
            "details": details,
            "ip_address": ip_address,
            "timestamp": datetime.now(IST)
        })
    except Exception as e:
        logger.error(f"Failed to create audit log: {e}")

async def create_database_backup():
    """Create a backup of the entire database"""
    try:
        logger.info("Starting database backup")
        timestamp = datetime.now(IST).strftime("%Y%m%d_%H%M%S")
        backup_filename = f"backup_{timestamp}.json"
        
        # Export collections
        backup_data = {}
        for collection_name in ["users", "tiffins", "notices", "polls", "poll_votes", 
                               "invoices", "notifications", "tiffin_requests", "audit_logs"]:
            collection = db[collection_name]
            backup_data[collection_name] = list(collection.find())
        
        # Sanitize data (remove passwords, convert ObjectIds to strings)
        if "users" in backup_data:
            for user in backup_data["users"]:
                if "password" in user:
                    user["password"] = "REDACTED"
                if "api_key" in user:
                    user["api_key"] = "REDACTED"
        
        # Serialize all data
        for collection_name, documents in backup_data.items():
            backup_data[collection_name] = [serialize_doc(doc) for doc in documents]
        
        # Add metadata
        backup_data["_metadata"] = {
            "timestamp": datetime.now(IST).isoformat(),
            "version": "1.0",
            "hostname": socket.gethostname()
        }
        
        # Save to local file first
        local_path = f"backups/{backup_filename}"
        os.makedirs("backups", exist_ok=True)
        
        with open(local_path, "w") as f:
            json.dump(backup_data, f)
        
        logger.info(f"Local backup created at {local_path}")
        
        # Upload to S3 if configured
        if AWS_ACCESS_KEY and AWS_SECRET_KEY:
            s3_client = boto3.client(
                's3',
                aws_access_key_id=AWS_ACCESS_KEY,
                aws_secret_access_key=AWS_SECRET_KEY,
                region_name=AWS_REGION
            )
            
            s3_client.upload_file(
                local_path,
                AWS_BUCKET,
                backup_filename
            )
            
            logger.info(f"Backup uploaded to S3: {AWS_BUCKET}/{backup_filename}")
        
        return {"status": "success", "filename": backup_filename}
    except Exception as e:
        logger.error(f"Backup failed: {str(e)}")
        return {"status": "failed", "error": str(e)}

async def periodic_backup_task():
    """Run backups periodically"""
    while True:
        try:
            await create_database_backup()
            # Wait for 24 hours before next backup
            await asyncio.sleep(24 * 60 * 60)
        except Exception as e:
            logger.error(f"Error in periodic backup: {e}")
            # Wait for 1 hour before retrying on error
            await asyncio.sleep(60 * 60)

async def update_price_history(tiffin_id: str, old_price: float, new_price: float, user_id: str):
    """Track price changes for audit purposes"""
    try:
        db.price_history.insert_one({
            "tiffin_id": tiffin_id,
            "old_price": old_price,
            "new_price": new_price,
            "changed_by": user_id,
            "changed_at": datetime.now(IST),
            "percent_change": round(((new_price - old_price) / old_price) * 100, 2) if old_price > 0 else 0
        })
        
        # Log significant price changes (more than 20%)
        if old_price > 0 and abs((new_price - old_price) / old_price) > 0.2:
            logger.warning(f"Significant price change detected: Tiffin {tiffin_id} price changed from {old_price} to {new_price} by {user_id}")
            
    except Exception as e:
        logger.error(f"Failed to update price history: {e}")

# Health Check
@app.get("/health")
async def health_check():
    try:
        client.admin.command('ping')
        return {
            "status": "healthy",
            "timestamp": datetime.now(IST),
            "server": socket.gethostname()
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
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
                logger.info(f"Keep-alive ping sent. Status: {response.status_code}")
            except Exception as e:
                logger.error(f"Keep-alive ping failed: {e}")
            await asyncio.sleep(PING_INTERVAL)

# Root
@app.get("/")
@limiter.limit("60/minute")
async def root(request: Request):
    return {
        "message": "Welcome to TiffinTreats API",
        "docs": "/docs",
        "version": "2.0",
        "timestamp": datetime.now(IST).isoformat()
    }

# Authentication Endpoints
@app.get("/auth/login")
@app.post("/auth/login")
@limiter.limit("10/minute")
async def login(request: Request, user_id: str, password: str):
    client_ip = request.client.host
    
    # Check for login attempts to prevent brute force
    login_attempt = db.login_attempts.find_one({"user_id": user_id})
    current_time = datetime.now(IST)
    
    if login_attempt:
        # Check if account is locked
        if login_attempt.get("locked_until") and login_attempt["locked_until"] > current_time:
            lock_minutes = round((login_attempt["locked_until"] - current_time).total_seconds() / 60)
            log_security_event("login_blocked", user_id, f"Attempted login to locked account from IP: {client_ip}")
            raise HTTPException(
                status_code=429,
                detail=f"Account is temporarily locked. Try again in {lock_minutes} minutes."
            )
        
        # Reset attempts if lockout period has passed
        if login_attempt.get("locked_until") and login_attempt["locked_until"] <= current_time:
            db.login_attempts.update_one(
                {"user_id": user_id},
                {"$set": {"attempts": 0, "locked_until": None}}
            )
    
    # Check for admin login
    if user_id == ADMIN_ID and password == ADMIN_PASSWORD:
        # Reset any previous failed attempts
        if login_attempt:
            db.login_attempts.update_one(
                {"user_id": user_id},
                {"$set": {"attempts": 0, "locked_until": None, "last_attempt": current_time}}
            )
        
        log_audit(ADMIN_ID, "login", "admin", None, None, client_ip)
        
        return {
            "status": "success",
            "api_key": ADMIN_API_KEY,
            "role": "admin"
        }
    
    # Regular user login
    user = db.users.find_one({"user_id": user_id})
    if not user:
        # Increment failed attempts even for non-existent users to prevent user enumeration
        update_login_attempts(user_id, success=False)
        log_security_event("login_failed", user_id, f"Login attempt with invalid user_id from IP: {client_ip}")
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )
    
    # Verify password
    stored_password = user.get("password", "")
    password_correct = False
    
    if ":" in stored_password:  # New salted hash format
        password_correct = verify_password(stored_password, password)
    elif len(stored_password) == 64:  # Old SHA-256 format
        password_correct = stored_password == hashlib.sha256(password.encode()).hexdigest()
    else:  # Plain text password from old system
        password_correct = stored_password == password
    
    if not password_correct:
        update_login_attempts(user_id, success=False)
        log_security_event("login_failed", user_id, f"Failed login attempt from IP: {client_ip}")
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )
    
    # Upgrade to salted hash if using old format
    if ":" not in stored_password:
        new_hashed_password = hash_password(password)
        db.users.update_one(
            {"user_id": user_id},
            {"$set": {"password": new_hashed_password}}
        )
    
    # Check if user is active
    if not user.get("active", True):
        log_security_event("inactive_user_login", user_id, f"Inactive user attempted to login from IP: {client_ip}")
        raise HTTPException(
            status_code=403,
            detail="Your account is inactive. Please contact an administrator."
        )
    
    # Reset failed login attempts
    update_login_attempts(user_id, success=True)
    
    # Generate new API key on each login for security
    new_api_key = generate_api_key()
    
    # Set API key expiry
    api_key_expiry = datetime.now(IST) + timedelta(days=API_KEY_EXPIRY_DAYS)
    
    db.users.update_one(
        {"user_id": user_id},
        {
            "$set": {
                "api_key": new_api_key,
                "api_key_expiry": api_key_expiry,
                "last_login": datetime.now(IST),
                "last_login_ip": client_ip
            }
        }
    )
    
    log_audit(user_id, "login", "user", None, None, client_ip)
    
    return {
        "status": "success",
        "api_key": new_api_key,
        "role": "user",
        "expires_at": api_key_expiry.isoformat()
    }

def update_login_attempts(user_id: str, success: bool):
    """Update login attempts for a user"""
    current_time = datetime.now(IST)
    
    if success:
        # Reset attempts on successful login
        db.login_attempts.update_one(
            {"user_id": user_id},
            {"$set": {"attempts": 0, "locked_until": None, "last_attempt": current_time}},
            upsert=True
        )
        return
    
    # Handle failed login
    login_attempt = db.login_attempts.find_one({"user_id": user_id})
    
    if not login_attempt:
        # First failed attempt
        db.login_attempts.insert_one({
            "user_id": user_id,
            "attempts": 1,
            "last_attempt": current_time,
            "locked_until": None
        })
        return
    
    # Increment attempts
    attempts = login_attempt.get("attempts", 0) + 1
    update_data = {
        "attempts": attempts,
        "last_attempt": current_time
    }
    
    # Lock account if too many attempts
    if attempts >= MAX_LOGIN_ATTEMPTS:
        locked_until = current_time + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
        update_data["locked_until"] = locked_until
        logger.warning(f"Account {user_id} locked until {locked_until} due to too many failed login attempts")
    
    db.login_attempts.update_one(
        {"user_id": user_id},
        {"$set": update_data}
    )

# User Management Endpoints
@app.post("/admin/users")
@limiter.limit("30/minute")
async def create_user(request: Request, user: UserCreate, auth: bool = Depends(verify_admin)):
    try:
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
            "api_key_expiry": (datetime.now(IST) + timedelta(days=API_KEY_EXPIRY_DAYS)),
            "created_at": datetime.now(IST),
            "active": True,
            "last_login": None,
            "created_by": ADMIN_ID,
            "created_from_ip": request.client.host
        })
        
        # Remove plaintext password
        user_dict.pop("password", None)
        user_dict["password"] = hashed_password
        
        try:
            db.users.insert_one(user_dict)
            log_audit(ADMIN_ID, "create", "user", user.user_id, 
                     {"email": user.email, "name": user.name}, request.client.host)
            return {"status": "success", "user_id": user.user_id}
        except Exception as e:
            logger.error(f"Failed to create user: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to create user: Database error"
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error creating user: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred"
        )

@app.get("/admin/users")
@limiter.limit("60/minute")
async def get_all_users(
    request: Request,
    active: Optional[bool] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    auth: bool = Depends(verify_admin)
):
    try:
        query = {}
        
        if active is not None:
            query["active"] = active
            
        if search:
            # Search in multiple fields
            query["$or"] = [
                {"user_id": {"$regex": search, "$options": "i"}},
                {"name": {"$regex": search, "$options": "i"}},
                {"email": {"$regex": search, "$options": "i"}}
            ]
        
        # Get total count for pagination
        total_count = db.users.count_documents(query)
        
        # Get users with pagination
        users = list(db.users.find(
            query, 
            {"password": 0, "api_key": 0}
        ).sort("created_at", -1).skip(skip).limit(limit))
        
        # Serialize users
        for user in users:
            user["_id"] = str(user["_id"])
            
        log_audit(ADMIN_ID, "list", "users", None, 
                 {"count": len(users), "filter": query}, request.client.host)
                 
        return {
            "total": total_count,
            "skip": skip,
            "limit": limit,
            "data": users
        }
    except Exception as e:
        logger.error(f"Failed to fetch users: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to fetch users"
        )

@app.get("/admin/users/{user_id}")
@limiter.limit("60/minute")
async def get_user(user_id: str, request: Request, auth: bool = Depends(verify_admin)):
    try:
        user = db.users.find_one({"user_id": user_id}, {"password": 0, "api_key": 0})
        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )
        user["_id"] = str(user["_id"])
        
        # Get user stats
        tiffins = list(db.tiffins.find({"assigned_users": user_id}))
        
        current_month_start = datetime.now(IST).replace(day=1).strftime("%Y-%m-%d")
        current_month_tiffins = [t for t in tiffins if t["date"] >= current_month_start]
        
        user["stats"] = {
            "total_tiffins": len([t for t in tiffins if t["status"] != TiffinStatus.CANCELLED]),
            "cancelled_tiffins": len([t for t in tiffins if t["status"] == TiffinStatus.CANCELLED]),
            "total_spent": sum(t.get("price", 0) for t in tiffins if t["status"] != TiffinStatus.CANCELLED),
            "current_month_tiffins": len([t for t in current_month_tiffins if t["status"] != TiffinStatus.CANCELLED]),
        }
        
        log_audit(ADMIN_ID, "view", "user", user_id, None, request.client.host)
        return user
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to fetch user"
        )

@app.put("/admin/users/{user_id}")
@limiter.limit("30/minute")
async def update_user(
    user_id: str,
    updates: Dict,
    request: Request,
    auth: bool = Depends(verify_admin)
):
    try:
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
            # Validate email format
            if not re.match(r"[^@]+@[^@]+\.[^@]+", update_data["email"]):
                raise HTTPException(
                    status_code=400,
                    detail="Invalid email format"
                )
                
            existing_user = db.users.find_one({
                "email": update_data["email"],
                "user_id": {"$ne": user_id}
            })
            if existing_user:
                raise HTTPException(
                    status_code=400,
                    detail="Email already registered"
                )
        
        # Add update metadata
        update_data["updated_at"] = datetime.now(IST)
        update_data["updated_by"] = ADMIN_ID
        
        # Get original user data for audit log
        original_user = db.users.find_one({"user_id": user_id}, {"password": 0, "api_key": 0})
        if not original_user:
            raise HTTPException(
                status_code=404,
                detail="User not found"
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
        
        # Log the update with changes for audit
        changes = {k: {"old": original_user.get(k), "new": v} for k, v in update_data.items() 
                  if k != "updated_at" and k != "updated_by"}
        
        log_audit(ADMIN_ID, "update", "user", user_id, 
                 {"changes": changes}, request.client.host)
        
        # If user was deactivated, invalidate their API key
        if "active" in update_data and update_data["active"] is False:
            db.users.update_one(
                {"user_id": user_id},
                {"$unset": {"api_key": ""}}
            )
            logger.info(f"User {user_id} deactivated and API key invalidated by admin")
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to update user"
        )

@app.put("/admin/users/{user_id}/reset-password")
@limiter.limit("20/minute")
async def reset_user_password(
    user_id: str,
    new_password: str,
    request: Request,
    auth: bool = Depends(verify_admin)
):
    """Reset a user's password (admin only)"""
    try:
        if user_id == ADMIN_ID:
            raise HTTPException(
                status_code=400,
                detail="Admin password cannot be reset through this endpoint"
            )
        
        # Validate password strength
        if len(new_password) < 8:
            raise HTTPException(
                status_code=400,
                detail="Password must be at least 8 characters long"
            )
            
        if not re.search(r'[A-Z]', new_password) or not re.search(r'[a-z]', new_password) or not re.search(r'[0-9]', new_password):
            raise HTTPException(
                status_code=400,
                detail="Password must contain uppercase, lowercase, and numbers"
            )
        
        user = db.users.find_one({"user_id": user_id})
        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )
        
        hashed_password = hash_password(new_password)
        
        # Reset password and invalidate API key for security
        db.users.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "password": hashed_password,
                    "password_reset_at": datetime.now(IST),
                    "password_reset_by": ADMIN_ID
                },
                "$unset": {"api_key": ""}  # Force re-login
            }
        )
        
        log_audit(ADMIN_ID, "reset_password", "user", user_id, 
                 {"forced_logout": True}, request.client.host)
        
        # Clear any login attempts
        db.login_attempts.delete_one({"user_id": user_id})
        
        return {"status": "success", "message": "Password reset successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resetting password for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to reset password"
        )

@app.delete("/admin/users/{user_id}")
@limiter.limit("10/minute")
async def delete_user(user_id: str, request: Request, auth: bool = Depends(verify_admin)):
    try:
        # Don't allow deleting admin
        if user_id == ADMIN_ID:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete admin user"
            )
        
        # Get user data for audit log before deletion
        user = db.users.find_one({"user_id": user_id})
        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found"
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
        
        log_audit(ADMIN_ID, "delete", "user", user_id, 
                 {"email": user.get("email"), "name": user.get("name")}, 
                 request.client.host)
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to delete user"
        )

# User Profile Endpoints
@app.get("/user/profile")
@limiter.limit("60/minute")
async def get_user_profile(request: Request, user_id: str = Depends(verify_user)):
    try:
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
        
        # Add API key expiry info if available
        if "api_key_expiry" in user:
            expiry = user["api_key_expiry"]
            if isinstance(expiry, datetime):
                user["api_key_expires_in_days"] = (expiry - datetime.now(IST)).days
        
        return user
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching profile for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to fetch user profile"
        )

@app.put("/user/profile")
@limiter.limit("30/minute")
async def update_user_profile(
    updates: Dict,
    request: Request,
    user_id: str = Depends(verify_user)
):
    try:
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
        
        # Validate fields
        if "name" in update_data and (len(update_data["name"]) < 2 or len(update_data["name"]) > 100):
            raise HTTPException(
                status_code=400,
                detail="Name must be 2-100 characters"
            )
            
        if "address" in update_data and (len(update_data["address"]) < 5 or len(update_data["address"]) > 200):
            raise HTTPException(
                status_code=400,
                detail="Address must be 5-200 characters"
            )
        
        # Check email uniqueness if email is being updated
        if "email" in update_data:
            # Validate email format
            if not re.match(r"[^@]+@[^@]+\.[^@]+", update_data["email"]):
                raise HTTPException(
                    status_code=400,
                    detail="Invalid email format"
                )
                
            existing_user = db.users.find_one({
                "email": update_data["email"],
                "user_id": {"$ne": user_id}
            })
            if existing_user:
                raise HTTPException(
                    status_code=400,
                    detail="Email already registered"
                )
        
        # Add update metadata
        update_data["updated_at"] = datetime.now(IST)
        update_data["updated_by"] = user_id
        
        # Get original data for audit
        original_user = db.users.find_one({"user_id": user_id}, {"password": 0, "api_key": 0})
        
        result = db.users.update_one(
            {"user_id": user_id},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )
        
        # Log changes for audit
        changes = {k: {"old": original_user.get(k), "new": v} for k, v in update_data.items() 
                  if k != "updated_at" and k != "updated_by"}
                  
        log_audit(user_id, "update", "profile", user_id, 
                 {"changes": changes}, request.client.host)
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating profile for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to update user profile"
        )

@app.put("/user/password")
@limiter.limit("10/minute")
async def change_password(
    old_password: str,
    new_password: str,
    request: Request,
    user_id: str = Depends(verify_user)
):
    try:
        # Admin can't change password through this endpoint
        if user_id == ADMIN_ID:
            raise HTTPException(
                status_code=400,
                detail="Admin password cannot be changed through this endpoint"
            )
        
        # Validate new password strength
        if len(new_password) < 8:
            raise HTTPException(
                status_code=400,
                detail="New password must be at least 8 characters long"
            )
            
        if not re.search(r'[A-Z]', new_password) or not re.search(r'[a-z]', new_password) or not re.search(r'[0-9]', new_password):
            raise HTTPException(
                status_code=400,
                detail="New password must contain uppercase, lowercase, and numbers"
            )
        
        user = db.users.find_one({"user_id": user_id})
        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )
        
        # Check if old password matches
        stored_password = user.get("password", "")
        password_correct = False
        
        if ":" in stored_password:  # New salted hash format
            password_correct = verify_password(stored_password, old_password)
        elif len(stored_password) == 64:  # Old SHA-256 format
            password_correct = stored_password == hashlib.sha256(old_password.encode()).hexdigest()
        else:  # Plain text password from old system
            password_correct = stored_password == old_password
            
        if not password_correct:
            # Log failed password change attempt
            log_security_event("password_change_failed", user_id, 
                              f"Failed password change attempt from IP: {request.client.host}")
            
            raise HTTPException(
                status_code=401,
                detail="Current password is incorrect"
            )
        
        # Update to new hashed password
        hashed_new_password = hash_password(new_password)
        
        # Invalidate existing API key to force re-login with new password
        new_api_key = generate_api_key()
        api_key_expiry = datetime.now(IST) + timedelta(days=API_KEY_EXPIRY_DAYS)
        
        db.users.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "password": hashed_new_password,
                    "api_key": new_api_key,
                    "api_key_expiry": api_key_expiry,
                    "password_changed_at": datetime.now(IST)
                }
            }
        )
        
        log_audit(user_id, "change_password", "user", user_id, None, request.client.host)
        
        return {
            "status": "success",
            "api_key": new_api_key,
            "expires_at": api_key_expiry.isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error changing password for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to change password"
        )

# Tiffin Management Endpoints
@app.post("/admin/tiffins")
@limiter.limit("60/minute")
async def create_tiffin(tiffin: TiffinCreate, request: Request, auth: bool = Depends(verify_admin)):
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
        
        # Additional validation
        if tiffin.price < 0:
            raise HTTPException(
                status_code=400,
                detail="Price cannot be negative"
            )
            
        if not tiffin.menu_items:
            raise HTTPException(
                status_code=400,
                detail="Menu items cannot be empty"
            )
        
        # Create tiffin document
        tiffin_dict = tiffin.dict()
        tiffin_dict.update({
            "created_at": datetime.now(IST),
            "updated_at": datetime.now(IST),
            "created_by": ADMIN_ID
        })
        
        result = db.tiffins.insert_one(tiffin_dict)
        tiffin_id = str(result.inserted_id)
        
        # Log the creation
        log_audit(ADMIN_ID, "create", "tiffin", tiffin_id, 
                 {"date": tiffin.date, "price": tiffin.price, "users": tiffin.assigned_users}, 
                 request.client.host)
        
        # Create notifications for assigned users
        for user_id in tiffin.assigned_users:
            notification = {
                "user_id": user_id,
                "title": "New Tiffin Scheduled",
                "message": f"A new tiffin has been scheduled for {tiffin.date} ({tiffin.time}).",
                "type": "info",
                "read": False,
                "created_at": datetime.now(IST),
                "tiffin_id": tiffin_id
            }
            db.notifications.insert_one(notification)
        
        return {
            "status": "success",
            "tiffin_id": tiffin_id
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create tiffin: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create tiffin: An unexpected error occurred"
        )

@app.post("/admin/batch-tiffins")
@limiter.limit("30/minute")
async def create_batch_tiffins(
    base_tiffin: TiffinBase,
    user_groups: List[List[str]],
    request: Request,
    auth: bool = Depends(verify_admin)
):
    try:
        # Validate time formats in base_tiffin
        try:
            datetime.strptime(base_tiffin.cancellation_time, "%H:%M")
            datetime.strptime(base_tiffin.delivery_time, "%H:%M")
            datetime.strptime(base_tiffin.date, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid date or time format. Use YYYY-MM-DD for date and HH:MM for times"
            )
        
        # Additional validation
        if base_tiffin.price < 0:
            raise HTTPException(
                status_code=400,
                detail="Price cannot be negative"
            )
            
        if not base_tiffin.menu_items:
            raise HTTPException(
                status_code=400,
                detail="Menu items cannot be empty"
            )
        
        created_tiffins = []
        
        for user_group in user_groups:
            # Skip empty groups
            if not user_group:
                continue
                
            # Validate all users in group
            invalid_users = []
            for user_id in user_group:
                if not db.users.find_one({"user_id": user_id, "active": True}):
                    invalid_users.append(user_id)
            
            if invalid_users:
                raise HTTPException(
                    status_code=400,
                    detail=f"Users not found or inactive: {', '.join(invalid_users)}"
                )
            
            # Create tiffin for this group
            tiffin_dict = base_tiffin.dict()
            tiffin_dict.update({
                "assigned_users": user_group,
                "created_at": datetime.now(IST),
                "updated_at": datetime.now(IST),
                "created_by": ADMIN_ID
            })
            
            result = db.tiffins.insert_one(tiffin_dict)
            tiffin_id = str(result.inserted_id)
            created_tiffins.append(tiffin_id)
            
            # Create notifications for assigned users
            for user_id in user_group:
                notification = {
                    "user_id": user_id,
                    "title": "New Tiffin Scheduled",
                    "message": f"A new tiffin has been scheduled for {base_tiffin.date} ({base_tiffin.time}).",
                    "type": "info",
                    "read": False,
                    "created_at": datetime.now(IST),
                    "tiffin_id": tiffin_id
                }
                db.notifications.insert_one(notification)
        
        log_audit(ADMIN_ID, "batch_create", "tiffins", None, 
                 {"date": base_tiffin.date, "price": base_tiffin.price, 
                  "count": len(created_tiffins), "tiffin_ids": created_tiffins}, 
                 request.client.host)
        
        return {
            "status": "success",
            "message": f"Created tiffins for {len(user_groups)} user groups",
            "tiffin_ids": created_tiffins
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create batch tiffins: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create batch tiffins: An unexpected error occurred"
        )

@app.get("/admin/tiffins")
@limiter.limit("120/minute")
async def get_all_tiffins(
    request: Request,
    date: Optional[str] = None,
    status: Optional[TiffinStatus] = None,
    time: Optional[TiffinTime] = None,
    user_id: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    auth: bool = Depends(verify_admin)
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
        logger.error(f"Failed to fetch tiffins: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch tiffins: An unexpected error occurred"
        )

@app.get("/admin/tiffins/{tiffin_id}")
@limiter.limit("120/minute")
async def get_tiffin_by_id(
    tiffin_id: str,
    request: Request,
    auth: bool = Depends(verify_admin)
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
        logger.error(f"Failed to fetch tiffin {tiffin_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch tiffin: An unexpected error occurred"
        )

@app.put("/admin/tiffins/{tiffin_id}")
@limiter.limit("60/minute")
async def update_tiffin(
    tiffin_id: str,
    updates: TiffinUpdate,
    request: Request,
    auth: bool = Depends(verify_admin)
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
        
        # Check if price is being updated
        if "price" in update_data:
            if update_data["price"] < 0:
                raise HTTPException(
                    status_code=400,
                    detail="Price cannot be negative"
                )
            
            # Track price change
            old_price = current_tiffin.get("price", 0)
            new_price = update_data["price"]
            
            # Log significant price changes (>10% change)
            if old_price > 0 and abs((new_price - old_price) / old_price) > 0.1:
                await update_price_history(tiffin_id, old_price, new_price, ADMIN_ID)
                log_audit(ADMIN_ID, "price_change", "tiffin", tiffin_id, 
                         {"old_price": old_price, "new_price": new_price, 
                          "percent_change": round(((new_price - old_price) / old_price) * 100, 2)}, 
                         request.client.host)
        
        # Check if assigned users exist if provided
        if "assigned_users" in update_data:
            new_users = set(update_data["assigned_users"]) - set(current_tiffin["assigned_users"])
            for user_id in new_users:
                if not db.users.find_one({"user_id": user_id, "active": True}):
                    raise HTTPException(
                        status_code=400,
                        detail=f"User {user_id} not found or inactive"
                    )
        
        # Add update metadata
        update_data["updated_at"] = datetime.now(IST)
        update_data["updated_by"] = ADMIN_ID
        
        # Prepare audit log data
        changes = {}
        for field, value in update_data.items():
            if field not in ["updated_at", "updated_by"] and value != current_tiffin.get(field):
                changes[field] = {
                    "old": current_tiffin.get(field),
                    "new": value
                }
        
        result = db.tiffins.update_one(
            {"_id": ObjectId(tiffin_id)},
            {"$set": update_data}
        )
        
        # Log the update
        if changes:
            log_audit(ADMIN_ID, "update", "tiffin", tiffin_id, {"changes": changes}, request.client.host)
        
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
                    "created_at": datetime.now(IST),
                    "tiffin_id": tiffin_id
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
                    "created_at": datetime.now(IST),
                    "tiffin_id": tiffin_id
                }
                db.notifications.insert_one(notification)
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update tiffin {tiffin_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update tiffin: An unexpected error occurred"
        )

@app.put("/admin/tiffins/{tiffin_id}/status")
@limiter.limit("120/minute")
async def update_tiffin_status(
    tiffin_id: str,
    status: TiffinStatus,
    request: Request,
    auth: bool = Depends(verify_admin)
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
        
        # Check if status is actually changing
        if status == current_tiffin["status"]:
            return {"status": "success", "message": "Tiffin already has this status"}
            
        # Update status
        result = db.tiffins.update_one(
            {"_id": ObjectId(tiffin_id)},
            {
                "$set": {
                    "status": status,
                    "updated_at": datetime.now(IST),
                    "updated_by": ADMIN_ID,
                    f"status_{status}_at": datetime.now(IST)  # Track when each status was set
                }
            }
        )
        
        # Log the status change
        log_audit(ADMIN_ID, "status_change", "tiffin", tiffin_id, 
                 {"old_status": current_tiffin["status"], "new_status": status}, 
                 request.client.host)
        
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
                    "created_at": datetime.now(IST),
                    "tiffin_id": tiffin_id
                }
                db.notifications.insert_one(notification)
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update tiffin status for {tiffin_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update tiffin status: An unexpected error occurred"
        )

@app.put("/admin/tiffins/{tiffin_id}/assign")
@limiter.limit("60/minute")
async def assign_users_to_tiffin(
    tiffin_id: str,
    user_ids: List[str],
    request: Request,
    auth: bool = Depends(verify_admin)
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
        invalid_users = []
        for user_id in user_ids:
            if not db.users.find_one({"user_id": user_id, "active": True}):
                invalid_users.append(user_id)
                
        if invalid_users:
            raise HTTPException(
                status_code=400,
                detail=f"Users not found or inactive: {', '.join(invalid_users)}"
            )
                
        # Find new users (not already assigned)
        current_users = set(tiffin["assigned_users"])
        new_users = [uid for uid in user_ids if uid not in current_users]
                
        # Update tiffin with new users
        result = db.tiffins.update_one(
            {"_id": ObjectId(tiffin_id)},
            {
                "$addToSet": {"assigned_users": {"$each": user_ids}},
                "$set": {
                    "updated_at": datetime.now(IST),
                    "updated_by": ADMIN_ID
                }
            }
        )
        
        # Log the assignment
        log_audit(ADMIN_ID, "assign_users", "tiffin", tiffin_id, 
                 {"users_added": new_users}, request.client.host)
        
        # Notify new users
        for user_id in new_users:
            notification = {
                "user_id": user_id,
                "title": "New Tiffin Assigned",
                "message": f"A tiffin has been assigned to you for {tiffin['date']} ({tiffin['time']}).",
                "type": "info",
                "read": False,
                "created_at": datetime.now(IST),
                "tiffin_id": tiffin_id
            }
            db.notifications.insert_one(notification)
        
        return {
            "status": "success",
            "assigned_users": list(set(tiffin["assigned_users"]).union(set(user_ids)))
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to assign users to tiffin {tiffin_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to assign users to tiffin: An unexpected error occurred"
        )

@app.put("/admin/tiffins/{tiffin_id}/unassign")
@limiter.limit("60/minute")
async def unassign_users_from_tiffin(
    tiffin_id: str,
    user_ids: List[str],
    request: Request,
    auth: bool = Depends(verify_admin)
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
                "$set": {
                    "updated_at": datetime.now(IST),
                    "updated_by": ADMIN_ID
                }
            }
        )
        
        # Log the unassignment
        log_audit(ADMIN_ID, "unassign_users", "tiffin", tiffin_id, 
                 {"users_removed": user_ids}, request.client.host)
        
        # If no users left, mark as cancelled
        updated_tiffin = db.tiffins.find_one({"_id": ObjectId(tiffin_id)})
        if not updated_tiffin["assigned_users"]:
            db.tiffins.update_one(
                {"_id": ObjectId(tiffin_id)},
                {
                    "$set": {
                        "status": TiffinStatus.CANCELLED,
                        "cancellation_reason": "All users unassigned"
                    }
                }
            )
            
        # Notify unassigned users
        for user_id in user_ids:
            notification = {
                "user_id": user_id,
                "title": "Tiffin Unassigned",
                "message": f"You have been unassigned from the tiffin scheduled for {tiffin['date']} ({tiffin['time']}).",
                "type": "info",
                "read": False,
                "created_at": datetime.now(IST),
                "tiffin_id": tiffin_id
            }
            db.notifications.insert_one(notification)
        
        return {
            "status": "success",
            "remaining_users": list(set(tiffin["assigned_users"]) - set(user_ids))
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to unassign users from tiffin {tiffin_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to unassign users from tiffin: An unexpected error occurred"
        )

@app.delete("/admin/tiffins/{tiffin_id}")
@limiter.limit("30/minute")
async def delete_tiffin(tiffin_id: str, request: Request, auth: bool = Depends(verify_admin)):
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
        
        # Backup tiffin data before deletion
        backup_tiffin = {**tiffin}
        backup_tiffin["_id"] = str(backup_tiffin["_id"])
        backup_tiffin["deleted_at"] = datetime.now(IST).isoformat()
        backup_tiffin["deleted_by"] = ADMIN_ID
        
        # Store in deleted_tiffins collection for audit
        db.deleted_tiffins.insert_one(backup_tiffin)
            
        # Delete the tiffin
        result = db.tiffins.delete_one({"_id": ObjectId(tiffin_id)})
        
        # Log deletion
        log_audit(ADMIN_ID, "delete", "tiffin", tiffin_id, 
                 {"date": tiffin.get("date"), "price": tiffin.get("price"), 
                  "users_affected": tiffin.get("assigned_users", [])}, 
                 request.client.host)
        
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
        logger.error(f"Failed to delete tiffin {tiffin_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete tiffin: An unexpected error occurred"
        )

@app.get("/user/tiffins")
@limiter.limit("120/minute")
async def get_user_tiffins(
    request: Request,
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
        logger.error(f"Failed to fetch user tiffins for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch user tiffins: An unexpected error occurred"
        )

@app.get("/user/tiffins/{tiffin_id}")
@limiter.limit("120/minute")
async def get_user_tiffin_by_id(
    tiffin_id: str,
    request: Request,
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
        logger.error(f"Failed to fetch tiffin {tiffin_id} for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch tiffin: An unexpected error occurred"
        )
        
@app.get("/user/tiffins/today")
@limiter.limit("120/minute")
async def get_user_today_tiffins(request: Request, user_id: str = Depends(verify_user)):
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
        logger.error(f"Failed to fetch today's tiffins for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch today's tiffins: An unexpected error occurred"
        )

@app.get("/user/tiffins/upcoming")
@limiter.limit("120/minute")
async def get_user_upcoming_tiffins(
    request: Request,
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
        logger.error(f"Failed to fetch upcoming tiffins for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch upcoming tiffins: An unexpected error occurred"
        )
        
@app.post("/user/cancel-tiffin")
@limiter.limit("30/minute")
async def cancel_tiffin(
    tiffin_id: str,
    request: Request,
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
            log_security_event("unauthorized_cancellation", user_id, 
                              f"User attempted to cancel tiffin they're not assigned to: {tiffin_id}")
            raise HTTPException(
                status_code=403,
                detail="Not authorized to cancel this tiffin"
            )
        
        # Only check cancellation time for regular users, not admin
        if user_id != ADMIN_ID and not await is_cancellation_allowed(tiffin):
            log_security_event("late_cancellation", user_id, 
                              f"User attempted to cancel tiffin after cancellation time: {tiffin_id}")
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
                        "updated_at": datetime.now(IST),
                        "updated_by": ADMIN_ID,
                        "cancellation_reason": "Cancelled by admin",
                        "cancelled_at": datetime.now(IST)
                    }
                }
            )
            
            # Log admin cancellation
            log_audit(ADMIN_ID, "cancel", "tiffin", tiffin_id, 
                     {"date": tiffin.get("date"), "affected_users": tiffin.get("assigned_users", [])}, 
                     request.client.host)
            
            # Notify all assigned users
            for assigned_user in tiffin["assigned_users"]:
                notification = {
                    "user_id": assigned_user,
                    "title": "Tiffin Cancelled",
                    "message": f"The tiffin scheduled for {tiffin['date']} ({tiffin['time']}) has been cancelled by admin.",
                    "type": "warning",
                    "read": False,
                    "created_at": datetime.now(IST),
                    "tiffin_id": tiffin_id
                }
                db.notifications.insert_one(notification)
        else:
            # For regular user, remove them from assigned_users
            result = db.tiffins.update_one(
                {"_id": ObjectId(tiffin_id)},
                {
                    "$pull": {"assigned_users": user_id},
                    "$set": {
                        "updated_at": datetime.now(IST),
                        "updated_by": user_id
                    },
                    "$push": {
                        "cancellations": {
                            "user_id": user_id,
                            "cancelled_at": datetime.now(IST)
                        }
                    }
                }
            )
            
            # Log user cancellation
            log_audit(user_id, "cancel", "tiffin", tiffin_id, 
                     {"date": tiffin.get("date")}, request.client.host)
            
            # Notify user of cancellation
            notification = {
                "user_id": user_id,
                "title": "Tiffin Cancelled",
                "message": f"You have successfully cancelled your tiffin for {tiffin['date']} ({tiffin['time']}).",
                "type": "info",
                "read": False,
                "created_at": datetime.now(IST),
                "tiffin_id": tiffin_id
            }
            db.notifications.insert_one(notification)
            
            # If no users left, mark as cancelled
            updated_tiffin = db.tiffins.find_one({"_id": ObjectId(tiffin_id)})
            if not updated_tiffin["assigned_users"]:
                db.tiffins.update_one(
                    {"_id": ObjectId(tiffin_id)},
                    {
                        "$set": {
                            "status": TiffinStatus.CANCELLED,
                            "cancellation_reason": "All users cancelled",
                            "cancelled_at": datetime.now(IST)
                        }
                    }
                )
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cancel tiffin {tiffin_id} for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to cancel tiffin: An unexpected error occurred"
        )

@app.get("/user/history")
@limiter.limit("60/minute")
async def get_user_history(
    request: Request,
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
        logger.error(f"Failed to fetch history for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch history: An unexpected error occurred"
        )

@app.post("/user/request-tiffin")
@limiter.limit("20/minute")
async def request_special_tiffin(
    request_data: dict,
    request: Request,
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
            
            # Don't allow requests for past dates
            today = datetime.now(IST).strftime("%Y-%m-%d")
            if request.preferred_date < today:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot request tiffin for a past date"
                )
                
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid preferred_date format. Use YYYY-MM-DD"
            )
        
        # Validate description
        if len(request.description.strip()) < 5:
            raise HTTPException(
                status_code=400,
                detail="Description must be at least 5 characters"
            )
        
        request_dict = request.dict()
        request_dict.update({
            "status": "pending",
            "created_at": datetime.now(IST),
            "client_ip": request.client.host if request else None
        })
        
        result = db.tiffin_requests.insert_one(request_dict)
        request_id = str(result.inserted_id)
        
        # Log the request
        log_audit(user_id, "create", "tiffin_request", request_id, 
                 {"date": request.preferred_date, "time": request.preferred_time}, 
                 request.client.host if request else None)
        
        # Create notification for admin
        admin_notification = {
            "user_id": ADMIN_ID,
            "title": "New Special Tiffin Request",
            "message": f"User {request.user_id} has requested a special tiffin for {request.preferred_date}.",
            "type": "info",
            "read": False,
            "created_at": datetime.now(IST),
            "request_id": request_id
        }
        db.notifications.insert_one(admin_notification)
        
        return {
            "status": "success",
            "request_id": request_id
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create tiffin request for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create tiffin request: An unexpected error occurred"
        )

@app.get("/admin/tiffin-requests")
@limiter.limit("60/minute")
async def get_tiffin_requests(
    request: Request,
    status: Optional[RequestStatus] = None,
    user_id: Optional[str] = None,
    auth: bool = Depends(verify_admin)
):
    try:
        query = {}
        
        if status:
            query["status"] = status
            
        if user_id:
            query["user_id"] = user_id
        
        requests = list(db.tiffin_requests.find(query).sort("created_at", -1))
        
        # Add user details to each request
        for req in requests:
            req["_id"] = str(req["_id"])
            user = db.users.find_one({"user_id": req["user_id"]}, {"password": 0, "api_key": 0})
            if user:
                user["_id"] = str(user["_id"])
                req["user_details"] = user
            
        return requests
    except Exception as e:
        logger.error(f"Failed to fetch tiffin requests: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch tiffin requests: An unexpected error occurred"
        )

@app.get("/admin/tiffin-requests/{request_id}")
@limiter.limit("60/minute")
async def get_tiffin_request(
    request_id: str,
    request: Request,
    auth: bool = Depends(verify_admin)
):
    try:
        if not is_valid_object_id(request_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid request ID format"
            )
            
        tiffin_request = db.tiffin_requests.find_one({"_id": ObjectId(request_id)})
        
        if not tiffin_request:
            raise HTTPException(
                status_code=404,
                detail="Tiffin request not found"
            )
        
        # Get user details
        user = db.users.find_one({"user_id": tiffin_request["user_id"]}, {"password": 0, "api_key": 0})
        if user:
            user["_id"] = str(user["_id"])
            tiffin_request["user_details"] = user
        
        tiffin_request["_id"] = str(tiffin_request["_id"])
        
        return tiffin_request
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch tiffin request {request_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch tiffin request: An unexpected error occurred"
        )

@app.post("/admin/tiffin-requests/{request_id}/approve")
@limiter.limit("30/minute")
async def approve_tiffin_request(
    request_id: str,
    approval: TiffinRequestApproval,
    request: Request,
    auth: bool = Depends(verify_admin)
):
    try:
        if not is_valid_object_id(request_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid request ID format"
            )
            
        # Get the request
        tiffin_request = db.tiffin_requests.find_one({"_id": ObjectId(request_id)})
        if not tiffin_request:
            raise HTTPException(
                status_code=404,
                detail="Tiffin request not found"
            )
            
        # Check if request is already processed
        if tiffin_request["status"] != RequestStatus.PENDING:
            raise HTTPException(
                status_code=400,
                detail=f"Request is already {tiffin_request['status']}"
            )
            
        # Validate date and time formats
        try:
            datetime.strptime(approval.date, "%Y-%m-%d")
            datetime.strptime(approval.cancellation_time, "%H:%M")
            datetime.strptime(approval.delivery_time, "%H:%M")
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid date or time format. Use YYYY-MM-DD for date and HH:MM for times"
            )
            
        # Additional validation
        if approval.price < 0:
            raise HTTPException(
                status_code=400,
                detail="Price cannot be negative"
            )
            
        # Create a new tiffin based on the request
        tiffin = {
            "date": approval.date,
            "time": approval.time,
            "description": tiffin_request["description"],
            "price": approval.price,
            "cancellation_time": approval.cancellation_time,
            "delivery_time": approval.delivery_time,
            "status": TiffinStatus.SCHEDULED,
            "menu_items": approval.menu_items or ["Special Tiffin"],
            "assigned_users": [tiffin_request["user_id"]],
            "created_at": datetime.now(IST),
            "updated_at": datetime.now(IST),
            "special_request": True,
            "request_id": str(tiffin_request["_id"]),
            "created_by": ADMIN_ID,
            "special_instructions": tiffin_request.get("special_instructions")
        }
        
        result = db.tiffins.insert_one(tiffin)
        tiffin_id = str(result.inserted_id)
        
        # Log the approval
        log_audit(ADMIN_ID, "approve", "tiffin_request", request_id, 
                 {"tiffin_id": tiffin_id, "price": approval.price}, 
                 request.client.host)
        
        # Update request status
        db.tiffin_requests.update_one(
            {"_id": ObjectId(request_id)},
            {
                "$set": {
                    "status": RequestStatus.APPROVED,
                    "approved_at": datetime.now(IST),
                    "approved_by": ADMIN_ID,
                    "tiffin_id": tiffin_id
                }
            }
        )
        
        # Notify the user
        notification = {
            "user_id": tiffin_request["user_id"],
            "title": "Special Tiffin Request Approved",
            "message": f"Your special tiffin request for {approval.date} ({approval.time}) has been approved.",
            "type": "success",
            "read": False,
            "created_at": datetime.now(IST),
            "tiffin_id": tiffin_id,
            "request_id": request_id
        }
        db.notifications.insert_one(notification)
        
        return {
            "status": "success",
            "tiffin_id": tiffin_id
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to approve tiffin request {request_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to approve tiffin request: An unexpected error occurred"
        )

@app.post("/admin/tiffin-requests/{request_id}/reject")
@limiter.limit("30/minute")
async def reject_tiffin_request(
    request_id: str,
    reason: Optional[str] = None,
    request: Request = None,
    auth: bool = Depends(verify_admin)
):
    try:
        if not is_valid_object_id(request_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid request ID format"
            )
            
        # Get the request
        tiffin_request = db.tiffin_requests.find_one({"_id": ObjectId(request_id)})
        if not tiffin_request:
            raise HTTPException(
                status_code=404,
                detail="Tiffin request not found"
            )
            
        # Check if request is already processed
        if tiffin_request["status"] != RequestStatus.PENDING:
            raise HTTPException(
                status_code=400,
                detail=f"Request is already {tiffin_request['status']}"
            )
            
        # Update request status
        db.tiffin_requests.update_one(
            {"_id": ObjectId(request_id)},
            {
                "$set": {
                    "status": RequestStatus.REJECTED,
                    "rejected_at": datetime.now(IST),
                    "rejected_by": ADMIN_ID,
                    "rejection_reason": reason
                }
            }
        )
        
        # Log the rejection
        log_audit(ADMIN_ID, "reject", "tiffin_request", request_id, 
                 {"reason": reason}, 
                 request.client.host if request else None)
        
        # Notify the user
        message = f"Your special tiffin request for {tiffin_request['preferred_date']} ({tiffin_request['preferred_time']}) has been rejected."
        if reason:
            message += f" Reason: {reason}"
            
        notification = {
            "user_id": tiffin_request["user_id"],
            "title": "Special Tiffin Request Rejected",
            "message": message,
            "type": "warning",
            "read": False,
            "created_at": datetime.now(IST),
            "request_id": request_id
        }
        db.notifications.insert_one(notification)
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to reject tiffin request {request_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to reject tiffin request: An unexpected error occurred"
        )

# Notice Management Endpoints
@app.post("/admin/notices")
@limiter.limit("30/minute")
async def create_notice(notice: Notice, request: Request, auth: bool = Depends(verify_admin)):
    try:
        # Additional validation
        if len(notice.title.strip()) < 3:
            raise HTTPException(
                status_code=400,
                detail="Notice title must be at least 3 characters"
            )
            
        if len(notice.content.strip()) < 5:
            raise HTTPException(
                status_code=400,
                detail="Notice content must be at least 5 characters"
            )
            
        if notice.priority not in [0, 1, 2]:
            raise HTTPException(
                status_code=400,
                detail="Priority must be 0 (Normal), 1 (Important), or 2 (Urgent)"
            )
        
        notice_dict = notice.dict()
        notice_dict["created_by"] = ADMIN_ID
        
        result = db.notices.insert_one(notice_dict)
        notice_id = str(result.inserted_id)
        
        # Log the notice creation
        log_audit(ADMIN_ID, "create", "notice", notice_id, 
                 {"title": notice.title, "priority": notice.priority}, 
                 request.client.host)
        
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
                "notice_id": notice_id
            }
            db.notifications.insert_one(notification)
        
        return {
            "status": "success",
            "notice_id": notice_id
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create notice: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create notice: An unexpected error occurred"
        )

@app.get("/admin/notices")
@limiter.limit("60/minute")
async def get_all_notices(request: Request, auth: bool = Depends(verify_admin)):
    try:
        notices = list(db.notices.find().sort("created_at", -1))
        for notice in notices:
            notice["_id"] = str(notice["_id"])
        return notices
    except Exception as e:
        logger.error(f"Failed to fetch notices: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch notices: An unexpected error occurred"
        )

@app.get("/user/notices")
@limiter.limit("60/minute")
async def get_user_notices(request: Request, user_id: str = Depends(verify_user)):
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
        logger.error(f"Failed to fetch notices for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch notices: An unexpected error occurred"
        )

@app.get("/admin/notices/{notice_id}")
@limiter.limit("60/minute")
async def get_notice_by_id(
    notice_id: str,
    request: Request,
    auth: bool = Depends(verify_admin)
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
        logger.error(f"Failed to fetch notice {notice_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch notice: An unexpected error occurred"
        )
           
@app.put("/admin/notices/{notice_id}")
@limiter.limit("30/minute")
async def update_notice(
    notice_id: str,
    updates: Dict,
    request: Request,
    auth: bool = Depends(verify_admin)
):
    try:
        if not is_valid_object_id(notice_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid notice ID format"
            )
            
        # Get current notice for audit
        current_notice = db.notices.find_one({"_id": ObjectId(notice_id)})
        if not current_notice:
            raise HTTPException(
                status_code=404,
                detail="Notice not found"
            )
            
        allowed_updates = {"title", "content", "priority", "expires_at"}
        update_data = {k: v for k, v in updates.items() if k in allowed_updates}
        
        if not update_data:
            raise HTTPException(
                status_code=400,
                detail="No valid updates provided"
            )
        
        # Additional validation
        if "title" in update_data and len(update_data["title"].strip()) < 3:
            raise HTTPException(
                status_code=400,
                detail="Notice title must be at least 3 characters"
            )
            
        if "content" in update_data and len(update_data["content"].strip()) < 5:
            raise HTTPException(
                status_code=400,
                detail="Notice content must be at least 5 characters"
            )
            
        if "priority" in update_data and update_data["priority"] not in [0, 1, 2]:
            raise HTTPException(
                status_code=400,
                detail="Priority must be 0 (Normal), 1 (Important), or 2 (Urgent)"
            )
        
        # Add update metadata
        update_data["updated_at"] = datetime.now(IST)
        update_data["updated_by"] = ADMIN_ID
        
        # Prepare audit log data
        changes = {}
        for field, value in update_data.items():
            if field not in ["updated_at", "updated_by"] and value != current_notice.get(field):
                changes[field] = {
                    "old": current_notice.get(field),
                    "new": value
                }
        
        result = db.notices.update_one(
            {"_id": ObjectId(notice_id)},
            {"$set": update_data}
        )
        
        # Log the update
        if changes:
            log_audit(ADMIN_ID, "update", "notice", notice_id, 
                     {"changes": changes}, request.client.host)
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update notice {notice_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update notice: An unexpected error occurred"
        )

@app.delete("/admin/notices/{notice_id}")
@limiter.limit("20/minute")
async def delete_notice(notice_id: str, request: Request, auth: bool = Depends(verify_admin)):
    try:
        if not is_valid_object_id(notice_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid notice ID format"
            )
        
        # Get notice before deletion for audit
        notice = db.notices.find_one({"_id": ObjectId(notice_id)})
        if not notice:
            raise HTTPException(
                status_code=404,
                detail="Notice not found"
            )
            
        # Backup notice data
        backup_notice = {**notice}
        backup_notice["_id"] = str(backup_notice["_id"])
        backup_notice["deleted_at"] = datetime.now(IST).isoformat()
        backup_notice["deleted_by"] = ADMIN_ID
        
        # Store in deleted_notices collection for audit
        db.deleted_notices.insert_one(backup_notice)
            
        result = db.notices.delete_one({"_id": ObjectId(notice_id)})
        if result.deleted_count == 0:
            raise HTTPException(
                status_code=404,
                detail="Notice not found"
            )
            
        # Log the deletion
        log_audit(ADMIN_ID, "delete", "notice", notice_id, 
                 {"title": notice.get("title"), "priority": notice.get("priority")}, 
                 request.client.host)
            
        # Delete related notifications
        db.notifications.delete_many({"notice_id": notice_id})
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete notice {notice_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete notice: An unexpected error occurred"
        )

# Poll Management Endpoints
@app.post("/admin/polls")
@limiter.limit("30/minute")
async def create_poll(poll: Poll, request: Request, auth: bool = Depends(verify_admin)):
    try:
        # Additional validation
        if len(poll.question.strip()) < 5:
            raise HTTPException(
                status_code=400,
                detail="Poll question must be at least 5 characters"
            )
            
        if len(poll.options) < 2:
            raise HTTPException(
                status_code=400,
                detail="Poll must have at least 2 options"
            )
            
        for option in poll.options:
            if len(option.option.strip()) < 1:
                raise HTTPException(
                    status_code=400,
                    detail="Poll options cannot be empty"
                )
        
        if poll.end_date <= poll.start_date:
            raise HTTPException(
                status_code=400,
                detail="End date must be after start date"
            )
        
        poll_dict = poll.dict()
        poll_dict["created_by"] = ADMIN_ID
        poll_dict["created_at"] = datetime.now(IST)
        
        result = db.polls.insert_one(poll_dict)
        poll_id = str(result.inserted_id)
        
        # Log the poll creation
        log_audit(ADMIN_ID, "create", "poll", poll_id, 
                 {"question": poll.question, "options_count": len(poll.options)}, 
                 request.client.host)
        
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
                "poll_id": poll_id
            }
            db.notifications.insert_one(notification)
        
        return {
            "status": "success",
            "poll_id": poll_id
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create poll: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create poll: An unexpected error occurred"
        )

@app.get("/admin/polls")
@limiter.limit("60/minute")
async def get_all_polls(request: Request, auth: bool = Depends(verify_admin)):
    try:
        polls = list(db.polls.find().sort("end_date", -1))
        for poll in polls:
            poll["_id"] = str(poll["_id"])
            
            # Add vote counts
            poll["total_votes"] = sum(option.get("votes", 0) for option in poll["options"])
            
        return polls
    except Exception as e:
        logger.error(f"Failed to fetch polls: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch polls: An unexpected error occurred"
        )

@app.get("/user/polls")
@limiter.limit("60/minute")
async def get_active_polls(request: Request, user_id: str = Depends(verify_user)):
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
                
            # Add total votes
            poll["total_votes"] = sum(option.get("votes", 0) for option in poll["options"])
        
        return polls
    except Exception as e:
        logger.error(f"Failed to fetch polls for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch polls: An unexpected error occurred"
        )

@app.get("/user/polls/{poll_id}")
@limiter.limit("60/minute")
async def get_poll_by_id(
    poll_id: str,
    request: Request,
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
            
        # Add total votes
        poll["total_votes"] = sum(option.get("votes", 0) for option in poll["options"])
        
        return poll
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch poll {poll_id} for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch poll: An unexpected error occurred"
        )

@app.post("/user/polls/{poll_id}/vote")
@limiter.limit("30/minute")
async def vote_poll(
    poll_id: str,
    option_index: int,
    request: Request,
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
            # Record vote with IP for security
            db.poll_votes.insert_one({
                "poll_id": ObjectId(poll_id),
                "user_id": user_id,
                "option_index": option_index,
                "voted_at": datetime.now(IST),
                "ip_address": request.client.host if request else None
            })
            
            # Update poll results atomically
            db.polls.update_one(
                {"_id": ObjectId(poll_id)},
                {"$inc": {f"options.{option_index}.votes": 1}}
            )
            
            # Log the vote
            log_audit(user_id, "vote", "poll", poll_id, 
                     {"option_index": option_index}, request.client.host)
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to record vote for poll {poll_id} by user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to record vote: An unexpected error occurred"
        )
@app.put("/admin/polls/{poll_id}")
@limiter.limit("30/minute")
async def update_poll(
    poll_id: str,
    updates: Dict,
    request: Request,
    auth: bool = Depends(verify_admin)
):
    try:
        if not is_valid_object_id(poll_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid poll ID format"
            )
            
        # Get current poll for audit
        current_poll = db.polls.find_one({"_id": ObjectId(poll_id)})
        if not current_poll:
            raise HTTPException(
                status_code=404,
                detail="Poll not found"
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
                
            # Validate options
            if len(update_data["options"]) < 2:
                raise HTTPException(
                    status_code=400,
                    detail="Poll must have at least 2 options"
                )
                
            for option in update_data["options"]:
                if len(option["option"].strip()) < 1:
                    raise HTTPException(
                        status_code=400,
                        detail="Poll options cannot be empty"
                    )
        
        # Validate dates if provided
        if "start_date" in update_data and "end_date" in update_data:
            if update_data["end_date"] <= update_data["start_date"]:
                raise HTTPException(
                    status_code=400,
                    detail="End date must be after start date"
                )
        elif "start_date" in update_data and update_data["start_date"] >= current_poll["end_date"]:
            raise HTTPException(
                status_code=400,
                detail="Start date must be before end date"
            )
        elif "end_date" in update_data and update_data["end_date"] <= current_poll["start_date"]:
            raise HTTPException(
                status_code=400,
                detail="End date must be after start date"
            )
        
        # Add update metadata
        update_data["updated_at"] = datetime.now(IST)
        update_data["updated_by"] = ADMIN_ID
        
        # Prepare audit log data
        changes = {}
        for field, value in update_data.items():
            if field not in ["updated_at", "updated_by"] and value != current_poll.get(field):
                if field == "options":
                    changes[field] = {
                        "old_count": len(current_poll.get("options", [])),
                        "new_count": len(value)
                    }
                else:
                    changes[field] = {
                        "old": current_poll.get(field),
                        "new": value
                    }
        
        result = db.polls.update_one(
            {"_id": ObjectId(poll_id)},
            {"$set": update_data}
        )
        
        # Log the update
        if changes:
            log_audit(ADMIN_ID, "update", "poll", poll_id, 
                     {"changes": changes}, request.client.host)
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update poll {poll_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update poll: An unexpected error occurred"
        )

@app.delete("/admin/polls/{poll_id}")
@limiter.limit("20/minute")
async def delete_poll(poll_id: str, request: Request, auth: bool = Depends(verify_admin)):
    try:
        if not is_valid_object_id(poll_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid poll ID format"
            )
            
        # Get poll before deletion for audit
        poll = db.polls.find_one({"_id": ObjectId(poll_id)})
        if not poll:
            raise HTTPException(
                status_code=404,
                detail="Poll not found"
            )
            
        # Backup poll data
        backup_poll = {**poll}
        backup_poll["_id"] = str(backup_poll["_id"])
        backup_poll["deleted_at"] = datetime.now(IST).isoformat()
        backup_poll["deleted_by"] = ADMIN_ID
        
        # Store in deleted_polls collection for audit
        db.deleted_polls.insert_one(backup_poll)
            
        # Delete poll
        result = db.polls.delete_one({"_id": ObjectId(poll_id)})
        if result.deleted_count == 0:
            raise HTTPException(
                status_code=404,
                detail="Poll not found"
            )
            
        # Log the deletion
        log_audit(ADMIN_ID, "delete", "poll", poll_id, 
                 {"question": poll.get("question"), "votes": sum(o.get("votes", 0) for o in poll.get("options", []))}, 
                 request.client.host)
            
        # Delete all votes for this poll
        db.poll_votes.delete_many({"poll_id": ObjectId(poll_id)})
        
        # Delete related notifications
        db.notifications.delete_many({"poll_id": poll_id})
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete poll {poll_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete poll: An unexpected error occurred"
        )

# Invoice Management Endpoints
@app.post("/admin/generate-invoices")
@limiter.limit("10/minute")
async def generate_invoices(
    start_date: str,
    end_date: str,
    request: Request,
    auth: bool = Depends(verify_admin)
):
    try:
        # Validate date formats
        try:
            datetime.strptime(start_date, "%Y-%m-%d")
            datetime.strptime(end_date, "%Y-%m-%d")
            
            if end_date < start_date:
                raise HTTPException(
                    status_code=400,
                    detail="End date must be after or equal to start date"
                )
                
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid date format. Use YYYY-MM-DD"
            )
            
        users = list(db.users.find({"active": True}))
        generated_invoices = []
        skipped_users = []
        
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
                    total_amount = sum(t.get("price", 0) for t in tiffins)
                    db.invoices.update_one(
                        {"_id": existing_invoice["_id"]},
                        {
                            "$set": {
                                "tiffins": [str(t["_id"]) for t in tiffins],
                                "total_amount": total_amount,
                                "updated_at": datetime.now(IST),
                                "updated_by": ADMIN_ID
                            }
                        }
                    )
                    
                    # Log the update
                    log_audit(ADMIN_ID, "update", "invoice", str(existing_invoice["_id"]), 
                             {"user_id": user["user_id"], "total_amount": total_amount, 
                              "tiffin_count": len(tiffins)}, 
                             request.client.host)
                    
                    generated_invoices.append({
                        "user_id": user["user_id"],
                        "invoice_id": str(existing_invoice["_id"]),
                        "status": "updated",
                        "total_amount": total_amount,
                        "tiffin_count": len(tiffins)
                    })
                else:
                    # Create new invoice
                    total_amount = sum(t.get("price", 0) for t in tiffins)
                    invoice = {
                        "user_id": user["user_id"],
                        "start_date": start_date,
                        "end_date": end_date,
                        "tiffins": [str(t["_id"]) for t in tiffins],
                        "total_amount": total_amount,
                        "paid": False,
                        "generated_at": datetime.now(IST),
                        "generated_by": ADMIN_ID
                    }
                    
                    result = db.invoices.insert_one(invoice)
                    invoice_id = str(result.inserted_id)
                    
                    # Log the creation
                    log_audit(ADMIN_ID, "create", "invoice", invoice_id, 
                             {"user_id": user["user_id"], "total_amount": total_amount, 
                              "tiffin_count": len(tiffins)}, 
                             request.client.host)
                    
                    # Create notification for user
                    notification = {
                        "user_id": user["user_id"],
                        "title": "New Invoice Generated",
                        "message": f"A new invoice has been generated for the period {start_date} to {end_date}.",
                        "type": "info",
                        "read": False,
                        "created_at": datetime.now(IST),
                        "invoice_id": invoice_id
                    }
                    db.notifications.insert_one(notification)
                    
                    generated_invoices.append({
                        "user_id": user["user_id"],
                        "invoice_id": invoice_id,
                        "status": "created",
                        "total_amount": total_amount,
                        "tiffin_count": len(tiffins)
                    })
            else:
                skipped_users.append(user["user_id"])
        
        return {
            "status": "success",
            "generated_invoices": len(generated_invoices),
            "invoice_details": generated_invoices,
            "skipped_users": skipped_users
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate invoices: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate invoices: An unexpected error occurred"
        )

@app.get("/admin/invoices")
@limiter.limit("60/minute")
async def get_all_invoices(
    request: Request,
    user_id: Optional[str] = None,
    paid: Optional[bool] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    auth: bool = Depends(verify_admin)
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
                
            # Calculate tiffin count
            invoice["tiffin_count"] = len(invoice.get("tiffins", []))
        
        return invoices
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch invoices: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch invoices: An unexpected error occurred"
        )

@app.get("/admin/invoices/{invoice_id}")
@limiter.limit("60/minute")
async def get_invoice_by_id(
    invoice_id: str,
    request: Request,
    auth: bool = Depends(verify_admin)
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
        logger.error(f"Failed to fetch invoice {invoice_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch invoice: An unexpected error occurred"
        )

@app.get("/user/invoices")
@limiter.limit("60/minute")
async def get_user_invoices(
    request: Request,
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
            
            # Add payment status details
            if invoice.get("paid"):
                invoice["payment_status"] = "Paid"
                if invoice.get("paid_at"):
                    invoice["payment_date"] = invoice["paid_at"].isoformat() if isinstance(invoice["paid_at"], datetime) else invoice["paid_at"]
            else:
                invoice["payment_status"] = "Unpaid"
            
        return invoices
    except Exception as e:
        logger.error(f"Failed to fetch invoices for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch invoices: An unexpected error occurred"
        )

@app.get("/user/invoices/{invoice_id}")
@limiter.limit("60/minute")
async def get_user_invoice_by_id(
    invoice_id: str,
    request: Request,
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
        
        # Add payment status details
        if invoice.get("paid"):
            invoice["payment_status"] = "Paid"
            if invoice.get("paid_at"):
                invoice["payment_date"] = invoice["paid_at"].isoformat() if isinstance(invoice["paid_at"], datetime) else invoice["paid_at"]
        else:
            invoice["payment_status"] = "Unpaid"
        
        return invoice
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch invoice {invoice_id} for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch invoice: An unexpected error occurred"
        )

@app.put("/admin/invoices/{invoice_id}/mark-paid")
@limiter.limit("30/minute")
async def mark_invoice_paid(
    invoice_id: str,
    request: Request,
    auth: bool = Depends(verify_admin)
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
            {
                "$set": {
                    "paid": True, 
                    "paid_at": datetime.now(IST),
                    "marked_paid_by": ADMIN_ID
                }
            }
        )
        
        # Log the payment
        log_audit(ADMIN_ID, "mark_paid", "invoice", invoice_id, 
                 {"user_id": invoice["user_id"], "amount": invoice["total_amount"]}, 
                 request.client.host)
        
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
        logger.error(f"Failed to mark invoice {invoice_id} as paid: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to mark invoice as paid: An unexpected error occurred"
        )

@app.delete("/admin/invoices/{invoice_id}")
@limiter.limit("20/minute")
async def delete_invoice(
    invoice_id: str,
    request: Request,
    auth: bool = Depends(verify_admin)
):
    try:
        if not is_valid_object_id(invoice_id):
            raise HTTPException(
                status_code=400,
                detail="Invalid invoice ID format"
            )
            
        # Get invoice before deletion for audit
        invoice = db.invoices.find_one({"_id": ObjectId(invoice_id)})
        if not invoice:
            raise HTTPException(
                status_code=404,
                detail="Invoice not found"
            )
            
        # Backup invoice data
        backup_invoice = {**invoice}
        backup_invoice["_id"] = str(backup_invoice["_id"])
        backup_invoice["deleted_at"] = datetime.now(IST).isoformat()
        backup_invoice["deleted_by"] = ADMIN_ID
        
        # Store in deleted_invoices collection for audit
        db.deleted_invoices.insert_one(backup_invoice)
            
        result = db.invoices.delete_one({"_id": ObjectId(invoice_id)})
        
        if result.deleted_count == 0:
            raise HTTPException(
                status_code=404,
                detail="Invoice not found"
            )
            
        # Log the deletion
        log_audit(ADMIN_ID, "delete", "invoice", invoice_id, 
                 {"user_id": invoice["user_id"], "amount": invoice["total_amount"]}, 
                 request.client.host)
            
        # Delete related notifications
        db.notifications.delete_many({"invoice_id": invoice_id})
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete invoice {invoice_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete invoice: An unexpected error occurred"
        )

# Notification Endpoints
@app.get("/user/notifications")
@limiter.limit("120/minute")
async def get_user_notifications(
    request: Request,
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
        logger.error(f"Failed to fetch notifications for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch notifications: An unexpected error occurred"
        )

@app.post("/user/notifications/mark-read")
@limiter.limit("60/minute")
async def mark_notifications_read(
    notification_ids: List[str],
    request: Request,
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
            {"$set": {"read": True, "read_at": datetime.now(IST)}}
        )
        
        return {
            "status": "success",
            "marked_count": result.modified_count
        }
    except Exception as e:
        logger.error(f"Failed to mark notifications as read for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to mark notifications as read: An unexpected error occurred"
        )

@app.post("/user/notifications/mark-all-read")
@limiter.limit("20/minute")
async def mark_all_notifications_read(request: Request, user_id: str = Depends(verify_user)):
    try:
        result = db.notifications.update_many(
            {"user_id": user_id, "read": False},
            {"$set": {"read": True, "read_at": datetime.now(IST)}}
        )
        
        return {
            "status": "success",
            "marked_count": result.modified_count
        }
    except Exception as e:
        logger.error(f"Failed to mark all notifications as read for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to mark all notifications as read: An unexpected error occurred"
        )

@app.delete("/user/notifications/{notification_id}")
@limiter.limit("30/minute")
async def delete_notification(
    notification_id: str,
    request: Request,
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
        logger.error(f"Failed to delete notification {notification_id} for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete notification: An unexpected error occurred"
        )

# Dashboard Statistics
@app.get("/admin/dashboard")
@limiter.limit("60/minute")
async def get_dashboard_stats(request: Request, auth: bool = Depends(verify_admin)):
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
        
        # Get system status
        system_status = {
            "db_connection": "healthy",
            "backup_status": "ok" if os.path.exists("backups") and len(os.listdir("backups")) > 0 else "no recent backups",
            "server_time": datetime.now(IST).isoformat(),
            "server_uptime": "unknown"  # This would need OS-specific code to determine
        }
        
        stats = {
            "total_users": total_users,
            "active_tiffins": active_tiffins,
            "today_deliveries": today_deliveries,
            "monthly_revenue": monthly_revenue,
            "pending_requests": pending_requests,
            "unpaid_invoices": unpaid_invoices,
            "new_users_30d": new_users,
            "system_status": system_status,
            "timestamp": datetime.now(IST).isoformat()
        }
        return stats
    except Exception as e:
        logger.error(f"Failed to fetch dashboard stats: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch dashboard stats: An unexpected error occurred"
        )

@app.get("/admin/user/{user_id}/stats")
@limiter.limit("60/minute")
async def get_user_stats(user_id: str, request: Request, auth: bool = Depends(verify_admin)):
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
        
        # Calculate payment stats
        invoices = list(db.invoices.find({"user_id": user_id}))
        total_invoices = len(invoices)
        paid_invoices = len([i for i in invoices if i.get("paid", False)])
        total_invoiced = sum(i.get("total_amount", 0) for i in invoices)
        total_paid = sum(i.get("total_amount", 0) for i in invoices if i.get("paid", False))
        
        # Get cancellation rate
        if len(tiffins) > 0:
            cancellation_rate = len([t for t in tiffins if t["status"] == TiffinStatus.CANCELLED]) / len(tiffins) * 100
        else:
            cancellation_rate = 0
            
        # Get login history
        login_history = list(db.audit_logs.find(
            {"user_id": user_id, "action": "login"},
            {"timestamp": 1, "ip_address": 1}
        ).sort("timestamp", -1).limit(5))
        
        for entry in login_history:
            entry["_id"] = str(entry["_id"])
        
        stats = {
            "total_tiffins": len([t for t in tiffins if t["status"] != TiffinStatus.CANCELLED]),
            "cancelled_tiffins": len([t for t in tiffins if t["status"] == TiffinStatus.CANCELLED]),
            "total_spent": sum(t.get("price", 0) for t in tiffins if t["status"] != TiffinStatus.CANCELLED),
            "active_since": user["created_at"].isoformat() if isinstance(user["created_at"], datetime) else user["created_at"],
            "last_login": user.get("last_login").isoformat() if user.get("last_login") and isinstance(user.get("last_login"), datetime) else user.get("last_login"),
            "current_month_tiffins": len([t for t in current_month_tiffins if t["status"] != TiffinStatus.CANCELLED]),
            "favorite_time": favorite_time,
            "payment_stats": {
                "total_invoices": total_invoices,
                "paid_invoices": paid_invoices,
                "payment_rate": (paid_invoices / total_invoices * 100) if total_invoices > 0 else 0,
                "total_invoiced": total_invoiced,
                "total_paid": total_paid,
                "outstanding_balance": total_invoiced - total_paid
            },
            "cancellation_rate": cancellation_rate,
            "login_history": login_history
        }
        
        return stats
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch user stats for {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch user stats: An unexpected error occurred"
        )

@app.get("/user/dashboard/stats")
@limiter.limit("60/minute")
async def get_user_dashboard_stats(request: Request, user_id: str = Depends(verify_user)):
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
        
        # Get active polls
        current_time = datetime.now(IST)
        active_polls = db.polls.count_documents({
            "active": True,
            "start_date": {"$lte": current_time},
            "end_date": {"$gt": current_time}
        })
        
        # Calculate user's payment status
        invoices = list(db.invoices.find({"user_id": user_id}))
        total_invoiced = sum(i.get("total_amount", 0) for i in invoices)
        total_paid = sum(i.get("total_amount", 0) for i in invoices if i.get("paid", False))
        outstanding_balance = total_invoiced - total_paid
        
        stats = {
            "today_tiffins": len(today_tiffins),
            "next_delivery": next_delivery,
            "month_tiffins": len([t for t in current_month_tiffins if t["status"] != TiffinStatus.CANCELLED]),
            "month_spent": sum(t.get("price", 0) for t in current_month_tiffins if t["status"] != TiffinStatus.CANCELLED),
            "pending_invoices": pending_invoices,
            "upcoming_tiffins": upcoming_tiffins,
            "unread_notifications": unread_notifications,
            "active_polls": active_polls,
            "payment_status": {
                "total_invoiced": total_invoiced,
                "total_paid": total_paid,
                "outstanding_balance": outstanding_balance
            }
        }
        
        return stats
    except Exception as e:
        logger.error(f"Failed to fetch dashboard stats for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch dashboard stats: An unexpected error occurred"
        )

# System Management
@app.get("/admin/system-health")
@limiter.limit("30/minute")
async def check_system_health(request: Request, auth: bool = Depends(verify_admin)):
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
        
        # Check backup status
        backup_dir = "backups"
        latest_backup = None
        if os.path.exists(backup_dir) and os.listdir(backup_dir):
            backup_files = sorted(os.listdir(backup_dir), reverse=True)
            if backup_files:
                latest_backup = backup_files[0]
                latest_backup_time = os.path.getmtime(os.path.join(backup_dir, latest_backup))
                latest_backup_age = (time.time() - latest_backup_time) / 3600  # hours
        
        # Check rate limiter status
        rate_limit_count = db.rate_limits.count_documents({})
        
        # Check security logs
        security_alerts = db.security_logs.count_documents({
            "timestamp": {"$gte": (datetime.now(IST) - timedelta(days=1)).isoformat()}
        })
        
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
                "notifications": notifications_count,
                "rate_limits": rate_limit_count,
                "security_logs": security_alerts
            },
            "database_size_mb": round(db_stats["dataSize"] / (1024 * 1024), 2),
            "storage_size_mb": round(db_stats["storageSize"] / (1024 * 1024), 2),
            "backup_status": {
                "latest_backup": latest_backup,
                "backup_age_hours": round(latest_backup_age, 2) if latest_backup else None,
                "status": "OK" if latest_backup and latest_backup_age < 24 else "Warning: No recent backups" 
            },
            "hostname": socket.gethostname(),
            "ip_address": socket.gethostbyname(socket.gethostname())
        }
        
        # Log the system health check
        log_audit(ADMIN_ID, "check", "system_health", None, None, request.client.host)
        
        return stats
    except Exception as e:
        logger.error(f"System health check failed: {str(e)}")
        raise HTTPException(
            status_code=503,
            detail=f"System health check failed: {str(e)}"
        )

@app.post("/admin/cleanup-data")
@limiter.limit("5/hour")
async def cleanup_old_data(
    days: int = Query(30, ge=7, le=365),
    request: Request = None,
    auth: bool = Depends(verify_admin)
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
        
        # Clean up old rate limit records
        rate_limits_result = db.rate_limits.delete_many({
            "updated_at": {"$lt": cutoff_date}
        })
        
        # Archive old security logs to backup
        security_logs = list(db.security_logs.find({
            "timestamp": {"$lt": cutoff_date}
        }))
        
        if security_logs:
            # Backup security logs before deletion
            for log in security_logs:
                log["_id"] = str(log["_id"])
            
            # Save to archive
            archive_filename = f"security_logs_archive_{datetime.now(IST).strftime('%Y%m%d')}.json"
            os.makedirs("backups/security_logs", exist_ok=True)
            
            with open(f"backups/security_logs/{archive_filename}", "w") as f:
                json.dump(security_logs, f)
                
            # Delete archived logs
            security_logs_result = db.security_logs.delete_many({
                "timestamp": {"$lt": cutoff_date}
            })
        else:
            security_logs_result = {"deleted_count": 0}
        
        # Log the cleanup
        log_audit(ADMIN_ID, "cleanup", "system", None, 
                 {"days": days, "cutoff_date": cutoff_date.isoformat()}, 
                 request.client.host if request else None)
        
        return {
            "status": "success",
            "cleaned_up": {
                "expired_notices": notices_result.deleted_count,
                "deactivated_polls": polls_result.modified_count,
                "archived_requests": requests_result.modified_count,
                "deleted_notifications": notifications_result.deleted_count,
                "deleted_rate_limits": rate_limits_result.deleted_count if hasattr(rate_limits_result, "deleted_count") else 0,
                "archived_security_logs": security_logs_result["deleted_count"] if isinstance(security_logs_result, dict) else security_logs_result.deleted_count
            }
        }
    except Exception as e:
        logger.error(f"Cleanup failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Cleanup failed: An unexpected error occurred"
        )

@app.post("/admin/backup")
@limiter.limit("12/day")
async def trigger_backup(request: Request, auth: bool = Depends(verify_admin)):
    """Manually trigger a database backup"""
    try:
        backup_result = await create_database_backup()
        
        # Log the backup
        log_audit(ADMIN_ID, "backup", "database", None, 
                 {"result": backup_result}, request.client.host)
        
        return backup_result
    except Exception as e:
        logger.error(f"Manual backup failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Backup failed: An unexpected error occurred"
        )

@app.get("/admin/backups")
@limiter.limit("60/minute")
async def list_backups(request: Request, auth: bool = Depends(verify_admin)):
    """List all available backups"""
    try:
        backup_dir = "backups"
        backups = []
        
        if os.path.exists(backup_dir):
            for filename in os.listdir(backup_dir):
                if filename.endswith(".json") and filename.startswith("backup_"):
                    file_path = os.path.join(backup_dir, filename)
                    
                    # Get file stats
                    stats = os.stat(file_path)
                    created_time = datetime.fromtimestamp(stats.st_ctime, IST)
                    size_mb = stats.st_size / (1024 * 1024)
                    
                    backups.append({
                        "filename": filename,
                        "created_at": created_time.isoformat(),
                        "size_mb": round(size_mb, 2)
                    })
        
        # Sort backups by creation time (newest first)
        backups.sort(key=lambda x: x["created_at"], reverse=True)
        
        # Check S3 backups if configured
        s3_backups = []
        if AWS_ACCESS_KEY and AWS_SECRET_KEY:
            try:
                s3_client = boto3.client(
                    's3',
                    aws_access_key_id=AWS_ACCESS_KEY,
                    aws_secret_access_key=AWS_SECRET_KEY,
                    region_name=AWS_REGION
                )
                
                response = s3_client.list_objects_v2(Bucket=AWS_BUCKET, Prefix="backup_")
                
                if "Contents" in response:
                    for obj in response["Contents"]:
                        s3_backups.append({
                            "filename": obj["Key"],
                            "created_at": obj["LastModified"].isoformat(),
                            "size_mb": round(obj["Size"] / (1024 * 1024), 2),
                            "location": "s3"
                        })
                        
                # Sort S3 backups by creation time (newest first)
                s3_backups.sort(key=lambda x: x["created_at"], reverse=True)
            except Exception as e:
                logger.error(f"Failed to list S3 backups: {str(e)}")
                s3_backups = [{"error": "Failed to list S3 backups", "details": str(e)}]
        
        return {
            "local_backups": backups,
            "s3_backups": s3_backups,
            "backup_status": "OK" if backups or s3_backups else "No backups found"
        }
    except Exception as e:
        logger.error(f"Failed to list backups: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to list backups: An unexpected error occurred"
        )

@app.get("/admin/export-data")
@limiter.limit("10/day")
async def export_data(request: Request, auth: bool = Depends(verify_admin)):
    """Export all relevant data for backup"""
    try:
        # Generate a unique export ID
        export_id = f"export_{datetime.now(IST).strftime('%Y%m%d_%H%M%S')}"
        
        # Create collections to export
        collections_to_export = [
            "users", "tiffins", "notices", "polls", "invoices", 
            "tiffin_requests", "audit_logs"
        ]
        
        export_data = {
            "metadata": {
                "export_id": export_id,
                "exported_at": datetime.now(IST).isoformat(),
                "exported_by": ADMIN_ID,
                "hostname": socket.gethostname()
            }
        }
        
        # Export each collection with sensitive data redacted
        for collection_name in collections_to_export:
            collection = db[collection_name]
            docs = list(collection.find())
            
            # Redact sensitive information
            if collection_name == "users":
                for doc in docs:
                    if "password" in doc:
                        doc["password"] = "REDACTED"
                    if "api_key" in doc:
                        doc["api_key"] = "REDACTED"
            
            # Serialize ObjectIds and dates
            for doc in docs:
                doc = serialize_doc(doc)
                
            export_data[collection_name] = docs
        
        # Log the export
        log_audit(ADMIN_ID, "export", "database", None, 
                 {"export_id": export_id}, request.client.host)
        
        # Save export to file
        export_path = f"backups/{export_id}.json"
        os.makedirs("backups", exist_ok=True)
        
        with open(export_path, "w") as f:
            json.dump(export_data, f)
        
        # Return the export data
        return {
            "status": "success",
            "export_id": export_id,
            "exported_at": export_data["metadata"]["exported_at"],
            "collections": collections_to_export,
            "record_counts": {collection: len(export_data[collection]) for collection in collections_to_export},
            "file_path": export_path
        }
    except Exception as e:
        logger.error(f"Failed to export data: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to export data: An unexpected error occurred"
        )

@app.get("/admin/security-logs")
@limiter.limit("60/minute")
async def get_security_logs(
    request: Request,
    days: int = Query(7, ge=1, le=30),
    action: Optional[str] = None,
    user_id: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    auth: bool = Depends(verify_admin)
):
    """Get security logs for monitoring"""
    try:
        query = {}
        
        # Filter by time range
        cutoff_date = (datetime.now(IST) - timedelta(days=days))
        query["timestamp"] = {"$gte": cutoff_date}
        
        # Filter by action if provided
        if action:
            query["action"] = action
            
        # Filter by user if provided
        if user_id:
            query["user_id"] = user_id
            
        # Get total count for pagination
        total_count = db.security_logs.count_documents(query)
        
        # Get logs with pagination
        logs = list(db.security_logs.find(query).sort("timestamp", -1).skip(skip).limit(limit))
        
        # Serialize logs
        for log in logs:
            log["_id"] = str(log["_id"])
            
        return {
            "total": total_count,
            "skip": skip,
            "limit": limit,
            "data": logs
        }
    except Exception as e:
        logger.error(f"Failed to fetch security logs: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch security logs: An unexpected error occurred"
        )

@app.get("/admin/audit-logs")
@limiter.limit("60/minute")
async def get_audit_logs(
    request: Request,
    days: int = Query(7, ge=1, le=30),
    action: Optional[str] = None,
    user_id: Optional[str] = None,
    resource: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    auth: bool = Depends(verify_admin)
):
    """Get audit logs for monitoring"""
    try:
        query = {}
        
        # Filter by time range
        cutoff_date = (datetime.now(IST) - timedelta(days=days))
        query["timestamp"] = {"$gte": cutoff_date}
        
        # Apply other filters if provided
        if action:
            query["action"] = action
            
        if user_id:
            query["user_id"] = user_id
            
        if resource:
            query["resource"] = resource
            
        # Get total count for pagination
        total_count = db.audit_logs.count_documents(query)
        
        # Get logs with pagination
        logs = list(db.audit_logs.find(query).sort("timestamp", -1).skip(skip).limit(limit))
        
        # Serialize logs
        for log in logs:
            log["_id"] = str(log["_id"])
            
        return {
            "total": total_count,
            "skip": skip,
            "limit": limit,
            "data": logs
        }
    except Exception as e:
        logger.error(f"Failed to fetch audit logs: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch audit logs: An unexpected error occurred"
        )

@app.get("/admin/price-history")
@limiter.limit("60/minute")
async def get_price_history(
    request: Request,
    tiffin_id: Optional[str] = None,
    days: int = Query(30, ge=1, le=365),
    limit: int = Query(100, ge=1, le=500),
    auth: bool = Depends(verify_admin)
):
    """Get price change history for monitoring"""
    try:
        query = {}
        
        # Filter by tiffin if provided
        if tiffin_id:
            if not is_valid_object_id(tiffin_id):
                raise HTTPException(
                    status_code=400,
                    detail="Invalid tiffin ID format"
                )
            query["tiffin_id"] = tiffin_id
            
        # Filter by time range
        cutoff_date = (datetime.now(IST) - timedelta(days=days))
        query["changed_at"] = {"$gte": cutoff_date}
        
        # Get price history with pagination
        history = list(db.price_history.find(query).sort("changed_at", -1).limit(limit))
        
        # Serialize history items
        for item in history:
            item["_id"] = str(item["_id"])
            
            # Add tiffin details if available
            if "tiffin_id" in item and is_valid_object_id(item["tiffin_id"]):
                tiffin = db.tiffins.find_one({"_id": ObjectId(item["tiffin_id"])})
                if tiffin:
                    item["tiffin_details"] = {
                        "date": tiffin.get("date"),
                        "time": tiffin.get("time"),
                        "status": tiffin.get("status")
                    }
        
        return history
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch price history: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch price history: An unexpected error occurred"
        )

# Cleanup Functions
async def cleanup_old_data_task():
    """Cleanup old notices, polls, and other data periodically"""
    try:
        while True:
            logger.info("Starting scheduled data cleanup task")
            
            try:
                thirty_days_ago = datetime.now(IST) - timedelta(days=30)
                
                # Clean up expired notices
                notices_result = db.notices.delete_many({
                    "expires_at": {"$lt": thirty_days_ago}
                })
                if notices_result.deleted_count > 0:
                    logger.info(f"Cleaned up {notices_result.deleted_count} expired notices")
                
                # Deactivate old polls
                polls_result = db.polls.update_many(
                    {
                        "end_date": {"$lt": thirty_days_ago},
                        "active": True
                    },
                    {"$set": {"active": False}}
                )
                if polls_result.modified_count > 0:
                    logger.info(f"Deactivated {polls_result.modified_count} old polls")
                
                # Archive old tiffin requests
                requests_result = db.tiffin_requests.update_many(
                    {
                        "created_at": {"$lt": thirty_days_ago},
                        "status": "pending"
                    },
                    {"$set": {"status": "archived"}}
                )
                if requests_result.modified_count > 0:
                    logger.info(f"Archived {requests_result.modified_count} old tiffin requests")
                
                # Clean up old read notifications
                notifications_result = db.notifications.delete_many({
                    "created_at": {"$lt": thirty_days_ago},
                    "read": True
                })
                if notifications_result.deleted_count > 0:
                    logger.info(f"Cleaned up {notifications_result.deleted_count} old read notifications")
                
                # Clean up old rate limits
                rate_limits_result = db.rate_limits.delete_many({
                    "updated_at": {"$lt": thirty_days_ago}
                })
                if hasattr(rate_limits_result, "deleted_count") and rate_limits_result.deleted_count > 0:
                    logger.info(f"Cleaned up {rate_limits_result.deleted_count} old rate limit records")
                
                # Archive old security logs (older than 90 days)
                ninety_days_ago = datetime.now(IST) - timedelta(days=90)
                security_logs = list(db.security_logs.find({
                    "timestamp": {"$lt": ninety_days_ago}
                }))
                
                if security_logs:
                    # Serialize logs
                    for log in security_logs:
                        log["_id"] = str(log["_id"])
                    
                    # Save to archive
                    archive_filename = f"security_logs_archive_{datetime.now(IST).strftime('%Y%m%d')}.json"
                    os.makedirs("backups/security_logs", exist_ok=True)
                    
                    with open(f"backups/security_logs/{archive_filename}", "w") as f:
                        json.dump(security_logs, f)
                    
                    # Delete archived logs
                    security_logs_result = db.security_logs.delete_many({
                        "timestamp": {"$lt": ninety_days_ago}
                    })
                    if security_logs_result.deleted_count > 0:
                        logger.info(f"Archived and cleaned up {security_logs_result.deleted_count} old security logs")
                
                logger.info("Scheduled cleanup completed successfully")
            except Exception as e:
                logger.error(f"Error during scheduled cleanup: {str(e)}")
            
            # Run cleanup every day
            await asyncio.sleep(24 * 60 * 60)
    except asyncio.CancelledError:
        logger.info("Cleanup task cancelled")
    except Exception as e:
        logger.error(f"Cleanup task error: {str(e)}")

# Database Indexes
def setup_indexes():
    """Setup necessary database indexes"""
    try:
        # User indexes
        db.users.create_index([("user_id", ASCENDING)], unique=True)
        db.users.create_index([("email", ASCENDING)], unique=True)
        db.users.create_index([("api_key", ASCENDING)], sparse=True)
        db.users.create_index([("active", ASCENDING)])
        db.users.create_index([("api_key_expiry", ASCENDING)], sparse=True)
        db.users.create_index([("last_login", ASCENDING)], sparse=True)
        
        # Tiffin indexes
        db.tiffins.create_index([("date", ASCENDING)])
        db.tiffins.create_index([("assigned_users", ASCENDING)])
        db.tiffins.create_index([("status", ASCENDING)])
        db.tiffins.create_index([("date", ASCENDING), ("status", ASCENDING)])
        db.tiffins.create_index([("date", ASCENDING), ("assigned_users", ASCENDING)])
        db.tiffins.create_index([("date", ASCENDING), ("time", ASCENDING)])
        
        # Poll votes index
        db.poll_votes.create_index(
            [("poll_id", ASCENDING), ("user_id", ASCENDING)],
            unique=True
        )
        db.poll_votes.create_index([("voted_at", ASCENDING)])
        
        # Notice index
        db.notices.create_index([("expires_at", ASCENDING)])
        db.notices.create_index([("priority", ASCENDING)])
        db.notices.create_index([("created_at", ASCENDING)])
        
        # Invoice index
        db.invoices.create_index([("user_id", ASCENDING)])
        db.invoices.create_index([("paid", ASCENDING)])
        db.invoices.create_index([("start_date", ASCENDING), ("end_date", ASCENDING)])
        db.invoices.create_index([("generated_at", ASCENDING)])
        
        # Notification index
        db.notifications.create_index([("user_id", ASCENDING)])
        db.notifications.create_index([("user_id", ASCENDING), ("read", ASCENDING)])
        db.notifications.create_index([("created_at", ASCENDING)])
        db.notifications.create_index([("tiffin_id", ASCENDING)], sparse=True)
        db.notifications.create_index([("notice_id", ASCENDING)], sparse=True)
        
        # Tiffin request index
        db.tiffin_requests.create_index([("user_id", ASCENDING)])
        db.tiffin_requests.create_index([("status", ASCENDING)])
        db.tiffin_requests.create_index([("created_at", ASCENDING)])
        
        # Security logs index
        db.security_logs.create_index([("timestamp", ASCENDING)])
        db.security_logs.create_index([("user_id", ASCENDING)], sparse=True)
        db.security_logs.create_index([("action", ASCENDING)])
        db.security_logs.create_index([("ip_address", ASCENDING)], sparse=True)
        
        # Audit logs index
        db.audit_logs.create_index([("timestamp", ASCENDING)])
        db.audit_logs.create_index([("user_id", ASCENDING)])
        db.audit_logs.create_index([("action", ASCENDING)])
        db.audit_logs.create_index([("resource", ASCENDING)])
        
        # Rate limits index
        db.rate_limits.create_index([("key", ASCENDING)], unique=True)
        db.rate_limits.create_index([("window_start", ASCENDING)])
        db.rate_limits.create_index([("updated_at", ASCENDING)])
        
        # Login attempts index
        db.login_attempts.create_index([("user_id", ASCENDING)], unique=True)
        db.login_attempts.create_index([("locked_until", ASCENDING)], sparse=True)
        
        # Price history index
        db.price_history.create_index([("tiffin_id", ASCENDING)])
        db.price_history.create_index([("changed_at", ASCENDING)])
        db.price_history.create_index([("changed_by", ASCENDING)])
        
        logger.info("Database indexes setup completed")
    except Exception as e:
        logger.error(f"Error setting up indexes: {str(e)}")

# Startup Event
@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    try:
        # Setup database indexes
        setup_indexes()
        
        # Start background tasks
        asyncio.create_task(cleanup_old_data_task())
        asyncio.create_task(periodic_backup_task())
        
        # Start keep-alive task
        asyncio.create_task(keep_alive())
        
        # Log startup
        logger.info("Application startup completed successfully")
        
        # Create initial admin notification about secure startup
        try:
            db.notifications.insert_one({
                "user_id": ADMIN_ID,
                "title": "System Started",
                "message": f"TiffinTreats API started securely on {socket.gethostname()} at {datetime.now(IST).isoformat()}",
                "type": "info",
                "read": False,
                "created_at": datetime.now(IST)
            })
        except Exception as e:
            logger.error(f"Failed to create startup notification: {str(e)}")
        
    except Exception as e:
        logger.error(f"Startup error: {str(e)}")

# Shutdown Event
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on application shutdown"""
    try:
        # Create a final backup before shutdown
        try:
            await create_database_backup()
        except Exception as e:
            logger.error(f"Final backup error during shutdown: {str(e)}")
        
        # Close MongoDB connection
        client.close()
        logger.info("Application shutdown completed successfully")
    except Exception as e:
        logger.error(f"Shutdown error: {str(e)}")

# Main entry point
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
