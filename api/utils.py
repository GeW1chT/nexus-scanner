#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nexus-Scanner API Utilities
API için yardımcı fonksiyonlar ve sınıflar

Bu modül API için genel amaçlı utility fonksiyonları sağlar:
- Validation helpers
- Response formatters
- Error handlers
- Data converters
- Security utilities
"""

import re
import hashlib
import secrets
import base64
import json
from typing import Dict, Any, List, Optional, Union, Tuple
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs
from email.utils import parseaddr

from fastapi import HTTPException, status
from pydantic import BaseModel, validator
import jwt
from passlib.context import CryptContext

# Password context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Validation patterns
PATTERNS = {
    "email": re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
    "url": re.compile(r'^https?://[^\s/$.?#].[^\s]*$'),
    "ip": re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'),
    "domain": re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'),
    "username": re.compile(r'^[a-zA-Z0-9_-]{3,50}$'),
    "password": re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$')
}

class ValidationError(Exception):
    """Validation hatası"""
    pass

class SecurityError(Exception):
    """Güvenlik hatası"""
    pass

# Validation functions
def validate_email(email: str) -> bool:
    """
    Email adresini doğrular
    
    Args:
        email (str): Email adresi
    
    Returns:
        bool: Geçerli mi?
    """
    if not email or len(email) > 254:
        return False
    
    # Regex kontrolü
    if not PATTERNS["email"].match(email):
        return False
    
    # Email parsing kontrolü
    try:
        name, addr = parseaddr(email)
        return addr == email and '@' in addr
    except Exception:
        return False

def validate_url(url: str) -> bool:
    """
    URL'yi doğrular
    
    Args:
        url (str): URL
    
    Returns:
        bool: Geçerli mi?
    """
    if not url or len(url) > 2048:
        return False
    
    try:
        parsed = urlparse(url)
        return all([
            parsed.scheme in ['http', 'https'],
            parsed.netloc,
            PATTERNS["url"].match(url)
        ])
    except Exception:
        return False

def validate_ip_address(ip: str) -> bool:
    """
    IP adresini doğrular
    
    Args:
        ip (str): IP adresi
    
    Returns:
        bool: Geçerli mi?
    """
    return bool(PATTERNS["ip"].match(ip))

def validate_domain(domain: str) -> bool:
    """
    Domain adını doğrular
    
    Args:
        domain (str): Domain adı
    
    Returns:
        bool: Geçerli mi?
    """
    if not domain or len(domain) > 253:
        return False
    
    return bool(PATTERNS["domain"].match(domain))

def validate_username(username: str) -> bool:
    """
    Kullanıcı adını doğrular
    
    Args:
        username (str): Kullanıcı adı
    
    Returns:
        bool: Geçerli mi?
    """
    return bool(PATTERNS["username"].match(username))

def validate_password_strength(password: str) -> Tuple[bool, List[str]]:
    """
    Şifre gücünü doğrular
    
    Args:
        password (str): Şifre
    
    Returns:
        Tuple[bool, List[str]]: (Geçerli mi?, Hata mesajları)
    """
    errors = []
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    
    if len(password) > 128:
        errors.append("Password must be less than 128 characters")
    
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one digit")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain at least one special character")
    
    # Yaygın şifreler kontrolü
    common_passwords = [
        "password", "123456", "123456789", "qwerty", "abc123",
        "password123", "admin", "letmein", "welcome", "monkey"
    ]
    
    if password.lower() in common_passwords:
        errors.append("Password is too common")
    
    return len(errors) == 0, errors

def validate_scan_config(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Tarama konfigürasyonunu doğrular
    
    Args:
        config (Dict[str, Any]): Tarama konfigürasyonu
    
    Returns:
        Tuple[bool, List[str]]: (Geçerli mi?, Hata mesajları)
    """
    errors = []
    
    # Timeout kontrolü
    timeout = config.get("timeout", 30)
    if not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > 300:
        errors.append("Timeout must be between 1 and 300 seconds")
    
    # Thread count kontrolü
    threads = config.get("threads", 10)
    if not isinstance(threads, int) or threads <= 0 or threads > 100:
        errors.append("Thread count must be between 1 and 100")
    
    # User agent kontrolü
    user_agent = config.get("user_agent", "")
    if user_agent and len(user_agent) > 200:
        errors.append("User agent must be less than 200 characters")
    
    # Headers kontrolü
    headers = config.get("headers", {})
    if not isinstance(headers, dict):
        errors.append("Headers must be a dictionary")
    else:
        for key, value in headers.items():
            if not isinstance(key, str) or not isinstance(value, str):
                errors.append("Header keys and values must be strings")
                break
            if len(key) > 100 or len(value) > 500:
                errors.append("Header keys/values are too long")
                break
    
    return len(errors) == 0, errors

# Security functions
def generate_secure_token(length: int = 32) -> str:
    """
    Güvenli token oluşturur
    
    Args:
        length (int): Token uzunluğu
    
    Returns:
        str: Güvenli token
    """
    return secrets.token_urlsafe(length)

def generate_api_key() -> str:
    """
    API key oluşturur
    
    Returns:
        str: API key
    """
    prefix = "nxs_"
    random_part = secrets.token_urlsafe(32)
    return f"{prefix}{random_part}"

def hash_password(password: str) -> str:
    """
    Şifreyi hash'ler
    
    Args:
        password (str): Şifre
    
    Returns:
        str: Hash'lenmiş şifre
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Şifreyi doğrular
    
    Args:
        plain_password (str): Düz şifre
        hashed_password (str): Hash'lenmiş şifre
    
    Returns:
        bool: Doğru mu?
    """
    return pwd_context.verify(plain_password, hashed_password)

def create_jwt_token(
    data: Dict[str, Any],
    secret_key: str,
    algorithm: str = "HS256",
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    JWT token oluşturur
    
    Args:
        data (Dict[str, Any]): Token verisi
        secret_key (str): Gizli anahtar
        algorithm (str): Algoritma
        expires_delta (Optional[timedelta]): Geçerlilik süresi
    
    Returns:
        str: JWT token
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=algorithm)
    
    return encoded_jwt

def verify_jwt_token(
    token: str,
    secret_key: str,
    algorithm: str = "HS256"
) -> Optional[Dict[str, Any]]:
    """
    JWT token'ı doğrular
    
    Args:
        token (str): JWT token
        secret_key (str): Gizli anahtar
        algorithm (str): Algoritma
    
    Returns:
        Optional[Dict[str, Any]]: Token verisi veya None
    """
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        return payload
    except jwt.PyJWTError:
        return None

def sanitize_input(input_str: str, max_length: int = 1000) -> str:
    """
    Kullanıcı girdisini temizler
    
    Args:
        input_str (str): Girdi
        max_length (int): Maksimum uzunluk
    
    Returns:
        str: Temizlenmiş girdi
    """
    if not isinstance(input_str, str):
        return ""
    
    # Uzunluk kontrolü
    if len(input_str) > max_length:
        input_str = input_str[:max_length]
    
    # Tehlikeli karakterleri kaldır
    dangerous_chars = ['<', '>', '"', "'", '&', '\x00', '\r', '\n']
    for char in dangerous_chars:
        input_str = input_str.replace(char, '')
    
    return input_str.strip()

def calculate_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """
    Dosya hash'ini hesaplar
    
    Args:
        file_path (str): Dosya yolu
        algorithm (str): Hash algoritması
    
    Returns:
        str: Dosya hash'i
    """
    hash_func = hashlib.new(algorithm)
    
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        raise SecurityError(f"File hash calculation failed: {e}")

# Response formatters
def format_success_response(
    data: Any = None,
    message: str = "Success",
    meta: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Başarı response'u formatlar
    
    Args:
        data (Any): Response verisi
        message (str): Başarı mesajı
        meta (Optional[Dict[str, Any]]): Meta bilgiler
    
    Returns:
        Dict[str, Any]: Formatlanmış response
    """
    response = {
        "success": True,
        "message": message,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    if data is not None:
        response["data"] = data
    
    if meta:
        response["meta"] = meta
    
    return response

def format_error_response(
    message: str = "Error occurred",
    error_code: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Hata response'u formatlar
    
    Args:
        message (str): Hata mesajı
        error_code (Optional[str]): Hata kodu
        details (Optional[Dict[str, Any]]): Hata detayları
    
    Returns:
        Dict[str, Any]: Formatlanmış response
    """
    response = {
        "success": False,
        "message": message,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    if error_code:
        response["error_code"] = error_code
    
    if details:
        response["details"] = details
    
    return response

def format_pagination_response(
    items: List[Any],
    total: int,
    page: int,
    per_page: int,
    message: str = "Success"
) -> Dict[str, Any]:
    """
    Sayfalama response'u formatlar
    
    Args:
        items (List[Any]): Öğeler
        total (int): Toplam öğe sayısı
        page (int): Mevcut sayfa
        per_page (int): Sayfa başına öğe
        message (str): Mesaj
    
    Returns:
        Dict[str, Any]: Formatlanmış response
    """
    total_pages = (total + per_page - 1) // per_page
    
    return format_success_response(
        data=items,
        message=message,
        meta={
            "pagination": {
                "total": total,
                "page": page,
                "per_page": per_page,
                "total_pages": total_pages,
                "has_next": page < total_pages,
                "has_prev": page > 1
            }
        }
    )

# Data converters
def convert_datetime_to_iso(dt: Optional[datetime]) -> Optional[str]:
    """
    Datetime'ı ISO formatına çevirir
    
    Args:
        dt (Optional[datetime]): Datetime objesi
    
    Returns:
        Optional[str]: ISO format string
    """
    return dt.isoformat() if dt else None

def convert_timedelta_to_seconds(td: Optional[timedelta]) -> Optional[float]:
    """
    Timedelta'yı saniyeye çevirir
    
    Args:
        td (Optional[timedelta]): Timedelta objesi
    
    Returns:
        Optional[float]: Saniye cinsinden süre
    """
    return td.total_seconds() if td else None

def convert_bytes_to_human_readable(bytes_size: int) -> str:
    """
    Byte'ları okunabilir formata çevirir
    
    Args:
        bytes_size (int): Byte cinsinden boyut
    
    Returns:
        str: Okunabilir format
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.1f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.1f} PB"

def parse_query_params(query_string: str) -> Dict[str, List[str]]:
    """
    Query parametrelerini parse eder
    
    Args:
        query_string (str): Query string
    
    Returns:
        Dict[str, List[str]]: Parse edilmiş parametreler
    """
    return parse_qs(query_string)

# Error handlers
def create_http_exception(
    status_code: int,
    message: str,
    error_code: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> HTTPException:
    """
    HTTP exception oluşturur
    
    Args:
        status_code (int): HTTP status kodu
        message (str): Hata mesajı
        error_code (Optional[str]): Hata kodu
        details (Optional[Dict[str, Any]]): Hata detayları
    
    Returns:
        HTTPException: HTTP exception
    """
    detail = format_error_response(message, error_code, details)
    return HTTPException(status_code=status_code, detail=detail)

def handle_validation_error(errors: List[str]) -> HTTPException:
    """
    Validation hatası işler
    
    Args:
        errors (List[str]): Hata mesajları
    
    Returns:
        HTTPException: HTTP exception
    """
    return create_http_exception(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        message="Validation failed",
        error_code="VALIDATION_ERROR",
        details={"errors": errors}
    )

def handle_authentication_error(message: str = "Authentication failed") -> HTTPException:
    """
    Authentication hatası işler
    
    Args:
        message (str): Hata mesajı
    
    Returns:
        HTTPException: HTTP exception
    """
    return create_http_exception(
        status_code=status.HTTP_401_UNAUTHORIZED,
        message=message,
        error_code="AUTHENTICATION_ERROR"
    )

def handle_authorization_error(message: str = "Access denied") -> HTTPException:
    """
    Authorization hatası işler
    
    Args:
        message (str): Hata mesajı
    
    Returns:
        HTTPException: HTTP exception
    """
    return create_http_exception(
        status_code=status.HTTP_403_FORBIDDEN,
        message=message,
        error_code="AUTHORIZATION_ERROR"
    )

def handle_not_found_error(resource: str = "Resource") -> HTTPException:
    """
    Not found hatası işler
    
    Args:
        resource (str): Kaynak adı
    
    Returns:
        HTTPException: HTTP exception
    """
    return create_http_exception(
        status_code=status.HTTP_404_NOT_FOUND,
        message=f"{resource} not found",
        error_code="NOT_FOUND_ERROR"
    )

# Utility classes
class APIResponse(BaseModel):
    """Standart API response modeli"""
    success: bool
    message: str
    timestamp: str
    data: Optional[Any] = None
    meta: Optional[Dict[str, Any]] = None

class PaginationParams(BaseModel):
    """Sayfalama parametreleri"""
    page: int = 1
    per_page: int = 20
    
    @validator('page')
    def validate_page(cls, v):
        if v < 1:
            raise ValueError('Page must be greater than 0')
        return v
    
    @validator('per_page')
    def validate_per_page(cls, v):
        if v < 1 or v > 100:
            raise ValueError('Per page must be between 1 and 100')
        return v

class SortParams(BaseModel):
    """Sıralama parametreleri"""
    sort_by: str = "created_at"
    sort_order: str = "desc"
    
    @validator('sort_order')
    def validate_sort_order(cls, v):
        if v not in ['asc', 'desc']:
            raise ValueError('Sort order must be asc or desc')
        return v

class FilterParams(BaseModel):
    """Filtreleme parametreleri"""
    search: Optional[str] = None
    status: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None

# Test fonksiyonu
if __name__ == "__main__":
    print("🧪 Nexus-Scanner API Utilities Test")
    print("=" * 40)
    
    # Validation testleri
    test_cases = [
        ("email", "test@example.com", validate_email),
        ("url", "https://example.com", validate_url),
        ("ip", "192.168.1.1", validate_ip_address),
        ("domain", "example.com", validate_domain),
        ("username", "testuser", validate_username)
    ]
    
    for test_type, test_value, test_func in test_cases:
        result = test_func(test_value)
        print(f"✅ {test_type}: {test_value} -> {result}")
    
    # Password strength testi
    password = "TestPassword123!"
    is_strong, errors = validate_password_strength(password)
    print(f"🔒 Password strength: {is_strong} (errors: {len(errors)})")
    
    # Token generation testi
    token = generate_secure_token()
    api_key = generate_api_key()
    print(f"🔑 Token: {token[:20]}...")
    print(f"🗝️ API Key: {api_key[:20]}...")
    
    # Response formatting testi
    success_resp = format_success_response({"test": "data"}, "Test successful")
    error_resp = format_error_response("Test error", "TEST_ERROR")
    print(f"✅ Success response: {success_resp['success']}")
    print(f"❌ Error response: {error_resp['success']}")
    
    print("=" * 40)