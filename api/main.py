#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nexus-Scanner REST API
Profesyonel siber güvenlik aracı - FastAPI REST API

Bu modül Nexus-Scanner için RESTful API endpoints sağlar.
"""

import os
import sys
import uvicorn
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from contextlib import asynccontextmanager

# FastAPI imports
from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, validator
import jwt
from passlib.context import CryptContext

# Proje modüllerini import et
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from database import DatabaseManager, get_database_manager
    from database.models import User, Target, Scan, Finding, Report
    from reports import ReportManager, create_report_manager
    from core.scanner import NexusScanner
except ImportError as e:
    print(f"⚠️ Modül import hatası: {e}")
    print("Lütfen PYTHONPATH'i kontrol edin veya modülleri yükleyin.")

# Güvenlik
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT ayarları
SECRET_KEY = os.getenv("NEXUS_SECRET_KEY", "nexus-scanner-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Pydantic modelleri
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., pattern=r'^[\w\.-]+@[\w\.-]+\.\w+$')
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = Field(None, max_length=100)
    role: str = Field(default="user")

class UserLogin(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int

class AuthResponse(BaseModel):
    user: dict
    token: str
    refreshToken: str
    expiresIn: int
    tokenType: str

class TargetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    url: str = Field(..., pattern=r'^https?://.+')
    description: Optional[str] = Field(None, max_length=500)
    target_type: str = Field(default="web")
    
    @validator('url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v

class ScanCreate(BaseModel):
    target_id: int
    scan_type: str = Field(..., pattern=r'^(web|network|full)$')
    scan_config: Optional[Dict[str, Any]] = Field(default_factory=dict)
    scheduled_at: Optional[datetime] = None
    
class ScanUpdate(BaseModel):
    status: Optional[str] = None
    progress: Optional[int] = Field(None, ge=0, le=100)
    
class ReportGenerate(BaseModel):
    scan_id: int
    format_type: str = Field(..., pattern=r'^(html|pdf|json)$')
    include_raw_data: bool = Field(default=False)

# Lifespan event handler
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("🚀 Nexus-Scanner API başlatılıyor...")
    
    # Database bağlantısını test et
    try:
        db_manager = get_database_manager()
        if db_manager.test_connection():
            print("✅ Database bağlantısı başarılı")
        else:
            print("❌ Database bağlantısı başarısız")
    except Exception as e:
        print(f"⚠️ Database bağlantı hatası: {e}")
    
    yield
    
    # Shutdown
    print("🛑 Nexus-Scanner API kapatılıyor...")

# FastAPI uygulaması
app = FastAPI(
    title="Nexus-Scanner API",
    description="Profesyonel siber güvenlik aracı REST API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# API Router oluştur
from fastapi import APIRouter
api_router = APIRouter(tags=["API"])

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Production'da specific origins kullan
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Trusted host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"]  # Production'da specific hosts kullan
)

# Static files
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Utility functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """JWT access token oluşturur"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Şifre doğrulama"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Şifre hash'leme"""
    return pwd_context.hash(password)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Mevcut kullanıcıyı JWT token'dan alır"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    
    # Database'den kullanıcıyı al
    db_manager = get_database_manager()
    with db_manager.get_session() as session:
        user = session.query(User).filter(User.username == username).first()
        if user is None:
            raise credentials_exception
    
    return user

# API Endpoints

@app.get("/", tags=["Root"])
async def root():
    """API ana endpoint"""
    return {
        "message": "Nexus-Scanner API v1.0.0",
        "description": "Profesyonel siber güvenlik aracı REST API",
        "docs": "/docs",
        "redoc": "/redoc",
        "status": "active",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health", tags=["Health"])
async def health_check():
    """Sistem sağlık kontrolü"""
    try:
        # Database bağlantısını test et
        db_manager = get_database_manager()
        db_status = "healthy" if db_manager.test_connection() else "unhealthy"
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0.0",
            "database": db_status,
            "uptime": "running"
        }
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
        )

# Settings endpoints
@api_router.get("/settings", tags=["Settings"])
async def get_settings():
    """Kullanıcı ayarlarını getir"""
    return {
        "data": {
            "settings": {
                "theme": "light",
                "language": "en",
                "notifications": True,
                "auto_scan": False,
                "scan_frequency": "daily",
                "email_reports": True
            }
        }
    }

@api_router.post("/settings", tags=["Settings"])
async def create_settings(settings_data: dict):
    """Kullanıcı ayarları oluştur"""
    # Burada normalde database'e kaydedilir
    return {
        "message": "Settings created successfully",
        "data": {
            "settings": settings_data
        }
    }

@api_router.put("/settings", tags=["Settings"])
async def update_settings(settings_data: dict):
    """Kullanıcı ayarlarını güncelle"""
    # Burada normalde database'e kaydedilir
    return {
        "message": "Settings updated successfully",
        "data": {
            "settings": settings_data
        }
    }

@api_router.get("/settings/schema", tags=["Settings"])
async def get_settings_schema():
    """Ayarlar şemasını getir"""
    return {
        "data": {
            "theme": {"type": "string", "enum": ["light", "dark", "system"]},
            "language": {"type": "string", "enum": ["en", "tr"]},
            "notifications": {"type": "boolean"},
            "auto_scan": {"type": "boolean"},
            "scan_frequency": {"type": "string", "enum": ["daily", "weekly", "monthly"]},
            "email_reports": {"type": "boolean"}
        }
    }

# Authentication endpoints
@api_router.post("/auth/register", tags=["Authentication"])
async def register_user(user_data: UserCreate):
    """Yeni kullanıcı kaydı"""
    db_manager = get_database_manager()
    
    with db_manager.get_session() as session:
        # Kullanıcı zaten var mı kontrol et
        existing_user = session.query(User).filter(
            (User.username == user_data.username) | (User.email == user_data.email)
        ).first()
        
        if existing_user:
            raise HTTPException(
                status_code=400,
                detail="Username or email already registered"
            )
        
        # Yeni kullanıcı oluştur
        hashed_password = get_password_hash(user_data.password)
        new_user = User(
            username=user_data.username,
            email=user_data.email,
            password_hash=hashed_password,
            full_name=user_data.full_name,
            role=user_data.role,
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        session.add(new_user)
        session.commit()
        
        # Access token oluştur
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": new_user.username, "user_id": new_user.id},
            expires_delta=access_token_expires
        )
        
        # Refresh token oluştur (7 gün geçerli)
        refresh_token_expires = timedelta(days=7)
        refresh_token = create_access_token(
            data={"sub": new_user.username, "user_id": new_user.id},
            expires_delta=refresh_token_expires
        )
        
        # User bilgilerini hazırla
        user_response = {
            "id": new_user.id,
            "email": new_user.email,
            "username": new_user.username,
            "firstName": new_user.full_name.split()[0] if new_user.full_name else new_user.username,
            "lastName": " ".join(new_user.full_name.split()[1:]) if new_user.full_name and len(new_user.full_name.split()) > 1 else "",
            "role": new_user.role,
            "isActive": new_user.is_active,
            "isVerified": True,
            "lastLogin": None,
            "createdAt": new_user.created_at.isoformat() if new_user.created_at else None,
            "updatedAt": new_user.updated_at.isoformat() if new_user.updated_at else None
        }
        
        auth_response = {
            "user": user_response,
            "token": access_token,
            "refreshToken": refresh_token,
            "expiresIn": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "tokenType": "bearer"
        }
        
        return {
            "data": auth_response,
            "message": "Registration successful",
            "success": True
        }

@api_router.post("/auth/login", tags=["Authentication"])
async def login_user(user_credentials: UserLogin):
    """Kullanıcı girişi"""
    db_manager = get_database_manager()
    
    with db_manager.get_session() as session:
        user = session.query(User).filter(
            User.email == user_credentials.email
        ).first()
        
        if not user or not verify_password(user_credentials.password, user.password_hash):
            raise HTTPException(
                status_code=401,
                detail="Incorrect username or password"
            )
        
        if not user.is_active:
            raise HTTPException(
                status_code=401,
                detail="User account is disabled"
            )
        
        # Access token oluştur
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username, "user_id": user.id},
            expires_delta=access_token_expires
        )
        
        # Refresh token oluştur (7 gün geçerli)
        refresh_token_expires = timedelta(days=7)
        refresh_token = create_access_token(
            data={"sub": user.username, "user_id": user.id},
            expires_delta=refresh_token_expires
        )
        
        # Son giriş zamanını güncelle
        user.last_login_at = datetime.utcnow()
        session.commit()
        
        # User bilgilerini hazırla
        user_data = {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "firstName": user.full_name.split()[0] if user.full_name else user.username,
            "lastName": " ".join(user.full_name.split()[1:]) if user.full_name and len(user.full_name.split()) > 1 else "",
            "role": user.role,
            "isActive": user.is_active,
            "isVerified": True,
            "lastLogin": user.last_login_at.isoformat() if user.last_login_at else None,
            "createdAt": user.created_at.isoformat() if user.created_at else None,
            "updatedAt": user.updated_at.isoformat() if user.updated_at else None
        }
        
        auth_response = {
            "user": user_data,
            "token": access_token,
            "refreshToken": access_token,  # Şimdilik aynı token
            "expiresIn": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "tokenType": "bearer"
        }
        
        return {
            "data": auth_response,
            "message": "Login successful",
            "success": True
        }

@api_router.post("/auth/logout", tags=["Authentication"])
async def logout_user(current_user: User = Depends(get_current_user)):
    """Kullanıcı çıkışı"""
    # Token blacklist işlemi burada yapılabilir
    # Şimdilik basit bir response dönüyoruz
    return {
        "message": "Successfully logged out"
    }

@api_router.post("/auth/refresh", tags=["Authentication"])
async def refresh_token(refresh_data: dict):
    """Token yenileme"""
    refresh_token = refresh_data.get("refreshToken")
    
    if not refresh_token:
        raise HTTPException(
            status_code=400,
            detail="Refresh token is required"
        )
    
    try:
        # JWT token'ı decode et ve doğrula
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("user_id")
        
        if username is None or user_id is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid refresh token"
            )
        
        # Kullanıcıyı veritabanından getir
        db_manager = get_database_manager()
        with db_manager.get_session() as session:
            user = session.query(User).filter(User.id == user_id).first()
            
            if not user or not user.is_active:
                raise HTTPException(
                    status_code=401,
                    detail="User not found or inactive"
                )
            
            # Yeni access token oluştur
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            new_access_token = create_access_token(
                data={"sub": user.username, "user_id": user.id},
                expires_delta=access_token_expires
            )
            
            # Yeni refresh token oluştur
            new_refresh_token = create_access_token(
                data={"sub": user.username, "user_id": user.id},
                expires_delta=timedelta(days=7)  # Refresh token 7 gün geçerli
            )
            
            return {
                "token": new_access_token,
                "refreshToken": new_refresh_token,
                "expiresIn": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                "tokenType": "bearer"
            }
            
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Refresh token has expired"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token"
        )

@api_router.get("/auth/me", tags=["Authentication"])
async def get_current_user_info():
    """Mevcut kullanıcı bilgileri"""
    # Demo kullanıcı bilgileri döndür
    user_data = {
        "id": 1,
        "username": "demo",
        "email": "demo@nexus-scanner.com",
        "firstName": "Demo",
        "lastName": "User",
        "role": "user",
        "isActive": True,
        "isVerified": True,
        "lastLogin": "2024-01-01T00:00:00",
        "createdAt": "2024-01-01T00:00:00",
        "updatedAt": "2024-01-01T00:00:00"
    }
    
    return {
        "data": {
            "user": user_data
        },
        "message": "User info retrieved successfully",
        "success": True
    }

# Target endpoints
@api_router.get("/targets", tags=["Targets"])
async def list_targets(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    current_user: User = Depends(get_current_user)
):
    """Hedefleri listele"""
    db_manager = get_database_manager()
    
    with db_manager.get_session() as session:
        targets = session.query(Target).filter(
            Target.created_by == current_user.id
        ).offset(skip).limit(limit).all()
        
        return {
            "targets": [
                {
                    "id": target.id,
                    "name": target.name,
                    "url": target.url,
                    "description": target.description,
                    "target_type": target.target_type,
                    "created_at": target.created_at.isoformat() if target.created_at else None,
                    "last_scan_at": target.last_scan_at.isoformat() if target.last_scan_at else None
                }
                for target in targets
            ],
            "total": len(targets),
            "skip": skip,
            "limit": limit
        }

@api_router.post("/targets", tags=["Targets"])
async def create_target(
    target_data: TargetCreate,
    current_user: User = Depends(get_current_user)
):
    """Yeni hedef oluştur"""
    db_manager = get_database_manager()
    
    with db_manager.get_session() as session:
        # Aynı URL zaten var mı kontrol et
        existing_target = session.query(Target).filter(
            Target.url == target_data.url,
            Target.created_by == current_user.id
        ).first()
        
        if existing_target:
            raise HTTPException(
                status_code=400,
                detail="Target with this URL already exists"
            )
        
        new_target = Target(
            name=target_data.name,
            url=target_data.url,
            description=target_data.description,
            target_type=target_data.target_type,
            created_by=current_user.id,
            created_at=datetime.utcnow()
        )
        
        session.add(new_target)
        session.commit()
        
        return {
            "message": "Target created successfully",
            "target_id": new_target.id,
            "name": new_target.name,
            "url": new_target.url
        }

@api_router.get("/targets/{target_id}", tags=["Targets"])
async def get_target(
    target_id: int,
    current_user: User = Depends(get_current_user)
):
    """Hedef detayları"""
    db_manager = get_database_manager()
    
    with db_manager.get_session() as session:
        target = session.query(Target).filter(
            Target.id == target_id,
            Target.created_by == current_user.id
        ).first()
        
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        
        # Son taramaları al
        recent_scans = session.query(Scan).filter(
            Scan.target_id == target_id
        ).order_by(Scan.created_at.desc()).limit(5).all()
        
        return {
            "id": target.id,
            "name": target.name,
            "url": target.url,
            "description": target.description,
            "target_type": target.target_type,
            "created_at": target.created_at.isoformat() if target.created_at else None,
            "last_scan_at": target.last_scan_at.isoformat() if target.last_scan_at else None,
            "recent_scans": [
                {
                    "id": scan.id,
                    "scan_type": scan.scan_type,
                    "status": scan.status,
                    "created_at": scan.created_at.isoformat() if scan.created_at else None,
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None
                }
                for scan in recent_scans
            ]
        }

# Scan endpoints
@api_router.get("/scans", tags=["Scans"])
async def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000)
):
    """Taramaları listele"""
    db_manager = get_database_manager()
    
    with db_manager.get_session() as session:
        scans = session.query(Scan).offset(skip).limit(limit).all()
        
        return {
            "data": [
                {
                    "id": scan.id,
                    "target_id": scan.target_id,
                    "scan_type": scan.scan_type,
                    "status": scan.status,
                    "started_at": scan.started_at.isoformat() if scan.started_at else None,
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    "duration_seconds": scan.duration_seconds,
                    "total_findings": scan.total_findings,
                    "created_at": scan.created_at.isoformat() if scan.created_at else None
                }
                for scan in scans
            ],
            "total": session.query(Scan).count(),
            "skip": skip,
            "limit": limit
        }

@api_router.post("/scans", tags=["Scans"])
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
):
    """Yeni tarama başlat"""
    db_manager = get_database_manager()
    
    with db_manager.get_session() as session:
        # Hedefin var olduğunu ve kullanıcıya ait olduğunu kontrol et
        target = session.query(Target).filter(
            Target.id == scan_data.target_id,
            Target.created_by == current_user.id
        ).first()
        
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        
        # Yeni tarama oluştur
        new_scan = Scan(
            target_id=scan_data.target_id,
            scan_type=scan_data.scan_type,
            status="pending",
            scan_config=scan_data.scan_config,
            created_by=current_user.id,
            created_at=datetime.utcnow(),
            scheduled_at=scan_data.scheduled_at
        )
        
        session.add(new_scan)
        session.commit()
        
        # Arka planda taramayı başlat
        if not scan_data.scheduled_at or scan_data.scheduled_at <= datetime.utcnow():
            background_tasks.add_task(run_scan_background, new_scan.id)
        
        return {
            "message": "Scan created successfully",
            "scan_id": new_scan.id,
            "status": new_scan.status,
            "target_name": target.name
        }

async def run_scan_background(scan_id: int):
    """Arka planda tarama çalıştır"""
    try:
        db_manager = get_database_manager()
        
        with db_manager.get_session() as session:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return
            
            target = session.query(Target).filter(Target.id == scan.target_id).first()
            if not target:
                return
            
            # Tarama durumunu güncelle
            scan.status = "running"
            scan.started_at = datetime.utcnow()
            session.commit()
            
            # Scanner'ı başlat
            scanner = NexusScanner()
            
            # Tarama tipine göre uygun modülleri çalıştır
            scan_config = scan.scan_config or {}
            
            if scan.scan_type == "web":
                results = await scanner.scan_web_target(
                    target.url,
                    config=scan_config
                )
            elif scan.scan_type == "network":
                results = await scanner.scan_network_target(
                    target.url,
                    config=scan_config
                )
            else:  # full
                results = await scanner.scan_full_target(
                    target.url,
                    config=scan_config
                )
            
            # Sonuçları kaydet
            scan.status = "completed"
            scan.completed_at = datetime.utcnow()
            scan.results = results
            
            # Bulguları kaydet
            if results and "findings" in results:
                for finding_data in results["findings"]:
                    finding = Finding(
                        scan_id=scan.id,
                        title=finding_data.get("title", "Unknown"),
                        description=finding_data.get("description", ""),
                        risk_level=finding_data.get("risk_level", "info"),
                        vulnerability_type=finding_data.get("vulnerability_type", "Unknown"),
                        affected_url=finding_data.get("affected_url", ""),
                        payload=finding_data.get("payload", ""),
                        evidence=finding_data.get("evidence", ""),
                        recommendation=finding_data.get("recommendation", ""),
                        confidence=finding_data.get("confidence", "medium"),
                        severity_score=finding_data.get("severity_score", 0.0),
                        created_at=datetime.utcnow()
                    )
                    session.add(finding)
            
            # Hedefin son tarama zamanını güncelle
            target.last_scan_at = datetime.utcnow()
            
            session.commit()
            
    except Exception as e:
        # Hata durumunda tarama durumunu güncelle
        with db_manager.get_session() as session:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = "failed"
                scan.error_message = str(e)
                scan.completed_at = datetime.utcnow()
                session.commit()

@api_router.get("/scans", tags=["Scans"])
async def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    status: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user)
):
    """Taramaları listele"""
    db_manager = get_database_manager()
    
    with db_manager.get_session() as session:
        query = session.query(Scan).filter(Scan.created_by == current_user.id)
        
        if status:
            query = query.filter(Scan.status == status)
        
        scans = query.order_by(Scan.created_at.desc()).offset(skip).limit(limit).all()
        
        return {
            "scans": [
                {
                    "id": scan.id,
                    "target_id": scan.target_id,
                    "scan_type": scan.scan_type,
                    "status": scan.status,
                    "progress": scan.progress,
                    "created_at": scan.created_at.isoformat() if scan.created_at else None,
                    "started_at": scan.started_at.isoformat() if scan.started_at else None,
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    "error_message": scan.error_message
                }
                for scan in scans
            ],
            "total": len(scans),
            "skip": skip,
            "limit": limit
        }

@api_router.get("/scans/{scan_id}", tags=["Scans"])
async def get_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user)
):
    """Tarama detayları"""
    db_manager = get_database_manager()
    
    with db_manager.get_session() as session:
        scan = session.query(Scan).filter(
            Scan.id == scan_id,
            Scan.created_by == current_user.id
        ).first()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Bulguları al
        findings = session.query(Finding).filter(
            Finding.scan_id == scan_id
        ).all()
        
        # Hedef bilgisini al
        target = session.query(Target).filter(Target.id == scan.target_id).first()
        
        return {
            "id": scan.id,
            "target": {
                "id": target.id if target else None,
                "name": target.name if target else None,
                "url": target.url if target else None
            },
            "scan_type": scan.scan_type,
            "status": scan.status,
            "progress": scan.progress,
            "scan_config": scan.scan_config,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "error_message": scan.error_message,
            "findings": [
                {
                    "id": finding.id,
                    "title": finding.title,
                    "description": finding.description,
                    "risk_level": finding.risk_level,
                    "vulnerability_type": finding.vulnerability_type,
                    "affected_url": finding.affected_url,
                    "confidence": finding.confidence,
                    "severity_score": finding.severity_score,
                    "created_at": finding.created_at.isoformat() if finding.created_at else None
                }
                for finding in findings
            ],
            "findings_summary": {
                "total": len(findings),
                "critical": len([f for f in findings if f.risk_level == "critical"]),
                "high": len([f for f in findings if f.risk_level == "high"]),
                "medium": len([f for f in findings if f.risk_level == "medium"]),
                "low": len([f for f in findings if f.risk_level == "low"]),
                "info": len([f for f in findings if f.risk_level == "info"])
            }
        }

# Report endpoints
@api_router.post("/reports/generate", tags=["Reports"])
async def generate_report(
    report_data: ReportGenerate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
):
    """Rapor oluştur"""
    db_manager = get_database_manager()
    
    with db_manager.get_session() as session:
        # Taramanın var olduğunu ve kullanıcıya ait olduğunu kontrol et
        scan = session.query(Scan).filter(
            Scan.id == report_data.scan_id,
            Scan.created_by == current_user.id
        ).first()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        if scan.status != "completed":
            raise HTTPException(status_code=400, detail="Scan is not completed yet")
        
        # Rapor kaydı oluştur
        new_report = Report(
            scan_id=report_data.scan_id,
            format_type=report_data.format_type,
            status="generating",
            created_by=current_user.id,
            created_at=datetime.utcnow()
        )
        
        session.add(new_report)
        session.commit()
        
        # Arka planda rapor oluştur
        background_tasks.add_task(
            generate_report_background,
            new_report.id,
            report_data.include_raw_data
        )
        
        return {
            "message": "Report generation started",
            "report_id": new_report.id,
            "format_type": new_report.format_type,
            "status": new_report.status
        }

async def generate_report_background(report_id: int, include_raw_data: bool = False):
    """Arka planda rapor oluştur"""
    try:
        db_manager = get_database_manager()
        
        with db_manager.get_session() as session:
            report = session.query(Report).filter(Report.id == report_id).first()
            if not report:
                return
            
            scan = session.query(Scan).filter(Scan.id == report.scan_id).first()
            target = session.query(Target).filter(Target.id == scan.target_id).first()
            findings = session.query(Finding).filter(Finding.scan_id == scan.id).all()
            
            # Rapor verilerini hazırla
            scan_data = {
                "scan_id": scan.id,
                "target_name": target.name if target else "Unknown",
                "target_url": target.url if target else "",
                "scan_type": scan.scan_type,
                "scan_status": scan.status,
                "started_at": scan.started_at,
                "completed_at": scan.completed_at,
                "duration": (scan.completed_at - scan.started_at).total_seconds() if scan.completed_at and scan.started_at else 0,
                "findings": [
                    {
                        "title": f.title,
                        "description": f.description,
                        "risk_level": f.risk_level,
                        "vulnerability_type": f.vulnerability_type,
                        "affected_url": f.affected_url,
                        "payload": f.payload,
                        "evidence": f.evidence,
                        "recommendation": f.recommendation,
                        "confidence": f.confidence,
                        "severity_score": f.severity_score
                    }
                    for f in findings
                ],
                "scan_config": scan.scan_config or {}
            }
            
            # Rapor oluşturucu
            report_manager = create_report_manager("./reports/generated")
            
            # Dosya adı
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"nexus_report_{scan.id}_{timestamp}"
            output_path = os.path.join("./reports/generated", f"{filename}.{report.format_type}")
            
            # Raporu oluştur
            success = report_manager.generate_single_report(
                scan_data,
                report.format_type,
                output_path
            )
            
            if success:
                report.status = "completed"
                report.file_path = output_path
                report.file_size = os.path.getsize(output_path)
                report.completed_at = datetime.utcnow()
            else:
                report.status = "failed"
                report.error_message = "Report generation failed"
            
            session.commit()
            
    except Exception as e:
        # Hata durumunda rapor durumunu güncelle
        with db_manager.get_session() as session:
            report = session.query(Report).filter(Report.id == report_id).first()
            if report:
                report.status = "failed"
                report.error_message = str(e)
                session.commit()

@api_router.get("/reports", tags=["Reports"])
async def list_reports(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    current_user: User = Depends(get_current_user)
):
    """Raporları listele"""
    db_manager = get_database_manager()
    
    with db_manager.get_session() as session:
        reports = session.query(Report).filter(
            Report.created_by == current_user.id
        ).order_by(Report.created_at.desc()).offset(skip).limit(limit).all()
        
        return {
            "reports": [
                {
                    "id": report.id,
                    "scan_id": report.scan_id,
                    "format_type": report.format_type,
                    "status": report.status,
                    "file_size": report.file_size,
                    "created_at": report.created_at.isoformat() if report.created_at else None,
                    "completed_at": report.completed_at.isoformat() if report.completed_at else None,
                    "error_message": report.error_message
                }
                for report in reports
            ],
            "total": len(reports),
            "skip": skip,
            "limit": limit
        }

@api_router.get("/reports/{report_id}/download", tags=["Reports"])
async def download_report(
    report_id: int,
    current_user: User = Depends(get_current_user)
):
    """Rapor indir"""
    db_manager = get_database_manager()
    
    with db_manager.get_session() as session:
        report = session.query(Report).filter(
            Report.id == report_id,
            Report.created_by == current_user.id
        ).first()
        
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        if report.status != "completed" or not report.file_path:
            raise HTTPException(status_code=400, detail="Report is not ready for download")
        
        if not os.path.exists(report.file_path):
            raise HTTPException(status_code=404, detail="Report file not found")
        
        # MIME type belirleme
        mime_types = {
            "html": "text/html",
            "pdf": "application/pdf",
            "json": "application/json"
        }
        
        return FileResponse(
            path=report.file_path,
            media_type=mime_types.get(report.format_type, "application/octet-stream"),
            filename=os.path.basename(report.file_path)
        )

# Vulnerability endpoints
@api_router.get("/vulnerabilities", tags=["Vulnerabilities"])
async def list_vulnerabilities(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000)
):
    """Güvenlik açıklarını listele"""
    db_manager = get_database_manager()
    
    with db_manager.get_session() as session:
        findings = session.query(Finding).offset(skip).limit(limit).all()
        
        return {
            "data": [
                {
                    "id": finding.id,
                    "scan_id": finding.scan_id,
                    "vulnerability_type": finding.vulnerability_type,
                    "title": finding.title,
                    "description": finding.description,
                    "risk_level": finding.risk_level,
                    "confidence": finding.confidence,
                    "severity_score": finding.severity_score,
                    "affected_url": finding.affected_url,
                    "recommendation": finding.recommendation,
                    "is_false_positive": finding.is_false_positive,
                    "created_at": finding.created_at.isoformat() if finding.created_at else None
                }
                for finding in findings
            ],
            "total": session.query(Finding).count(),
            "skip": skip,
            "limit": limit
        }

# Statistics endpoints
@api_router.get("/stats/dashboard", tags=["Statistics"])
@api_router.get("/dashboard/stats", tags=["Statistics"])
async def get_dashboard_stats():
    """Dashboard istatistikleri"""
    db_manager = get_database_manager()
    
    with db_manager.get_session() as session:
        # Temel sayılar
        total_targets = session.query(Target).count()
        total_scans = session.query(Scan).count()
        total_findings = session.query(Finding).count()
        total_reports = session.query(Report).count()
        
        # Son 30 gündeki taramalar
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_scans = session.query(Scan).filter(
            Scan.created_at >= thirty_days_ago
        ).count()
        
        # Risk dağılımı
        risk_distribution = {}
        for risk_level in ["critical", "high", "medium", "low", "info"]:
            count = session.query(Finding).filter(
                Finding.risk_level == risk_level
            ).count()
            risk_distribution[risk_level] = count
        
        # Son taramalar
        latest_scans = session.query(Scan).order_by(Scan.created_at.desc()).limit(5).all()
        
        dashboard_data = {
            "totalTargets": total_targets,
            "activeScans": recent_scans,
            "totalVulnerabilities": total_findings,
            "criticalVulnerabilities": risk_distribution.get("critical", 0),
            "totalReports": total_reports,
            "recentScans": [
                {
                    "id": scan.id,
                    "target_id": scan.target_id,
                    "scan_type": scan.scan_type.value if hasattr(scan.scan_type, 'value') else str(scan.scan_type),
                    "status": scan.status.value if hasattr(scan.status, 'value') else str(scan.status),
                    "created_at": scan.created_at.isoformat() if scan.created_at else None
                }
                for scan in latest_scans
            ],
            "vulnerabilityTrends": [],
            "scanActivity": [],
            "topVulnerabilities": []
        }
        
        return {
             "data": dashboard_data,
             "message": "Dashboard stats retrieved successfully",
             "success": True
         }

# API Router'ı mount et
app.include_router(api_router, prefix="/api")

# Error handlers
@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={"detail": "Resource not found"}
    )

@app.exception_handler(500)
async def internal_error_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

# Development server
if __name__ == "__main__":
    print("🚀 Nexus-Scanner API Development Server")
    print("=" * 50)
    print("📍 URL: http://localhost:8000")
    print("📚 Docs: http://localhost:8000/docs")
    print("🔄 ReDoc: http://localhost:8000/redoc")
    print("=" * 50)
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="debug",
        access_log=True
    )