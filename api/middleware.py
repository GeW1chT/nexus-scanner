#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nexus-Scanner API Middleware
FastAPI middleware'leri ve güvenlik katmanları

Bu modül API için özel middleware'ler sağlar:
- Rate limiting
- Request logging
- Security headers
- Error handling
- Performance monitoring
"""

import time
import json
import logging
from typing import Dict, Any, Optional, Callable
from datetime import datetime, timedelta
from collections import defaultdict, deque

from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

# Logging setup
logger = logging.getLogger(__name__)

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware
    IP bazlı istek sınırlama
    """
    
    def __init__(
        self,
        app: ASGIApp,
        requests_per_minute: int = 60,
        burst_size: int = 10,
        cleanup_interval: int = 300  # 5 dakika
    ):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.burst_size = burst_size
        self.cleanup_interval = cleanup_interval
        
        # IP bazlı istek takibi
        self.request_counts: Dict[str, deque] = defaultdict(deque)
        self.last_cleanup = time.time()
    
    def _cleanup_old_requests(self):
        """Eski istekleri temizle"""
        current_time = time.time()
        
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        cutoff_time = current_time - 60  # 1 dakika öncesi
        
        for ip in list(self.request_counts.keys()):
            requests = self.request_counts[ip]
            
            # Eski istekleri kaldır
            while requests and requests[0] < cutoff_time:
                requests.popleft()
            
            # Boş deque'ları kaldır
            if not requests:
                del self.request_counts[ip]
        
        self.last_cleanup = current_time
    
    def _is_rate_limited(self, client_ip: str) -> bool:
        """Rate limit kontrolü"""
        current_time = time.time()
        requests = self.request_counts[client_ip]
        
        # Son 1 dakikadaki istekleri say
        cutoff_time = current_time - 60
        while requests and requests[0] < cutoff_time:
            requests.popleft()
        
        # Burst kontrolü (son 10 saniye)
        burst_cutoff = current_time - 10
        recent_requests = sum(1 for req_time in requests if req_time > burst_cutoff)
        
        if recent_requests >= self.burst_size:
            return True
        
        # Dakikalık limit kontrolü
        if len(requests) >= self.requests_per_minute:
            return True
        
        return False
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Client IP'sini al
        client_ip = request.client.host if request.client else "unknown"
        
        # X-Forwarded-For header'ını kontrol et
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        
        # Eski istekleri temizle
        self._cleanup_old_requests()
        
        # Rate limit kontrolü
        if self._is_rate_limited(client_ip):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after": 60
                },
                headers={"Retry-After": "60"}
            )
        
        # İsteği kaydet
        current_time = time.time()
        self.request_counts[client_ip].append(current_time)
        
        # İsteği işle
        response = await call_next(request)
        
        # Rate limit header'larını ekle
        remaining = max(0, self.requests_per_minute - len(self.request_counts[client_ip]))
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(current_time + 60))
        
        return response

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Request logging middleware
    Tüm HTTP isteklerini loglar
    """
    
    def __init__(self, app: ASGIApp, log_body: bool = False):
        super().__init__(app)
        self.log_body = log_body
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()
        
        # Request bilgileri
        client_ip = request.client.host if request.client else "unknown"
        method = request.method
        url = str(request.url)
        user_agent = request.headers.get("User-Agent", "unknown")
        
        # Request body (eğer isteniyorsa)
        body_data = None
        if self.log_body and method in ["POST", "PUT", "PATCH"]:
            try:
                body = await request.body()
                if body:
                    body_data = body.decode("utf-8")[:1000]  # İlk 1000 karakter
            except Exception:
                body_data = "<unable to read body>"
        
        # İsteği işle
        try:
            response = await call_next(request)
            process_time = time.time() - start_time
            
            # Success log
            log_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "client_ip": client_ip,
                "method": method,
                "url": url,
                "status_code": response.status_code,
                "process_time": round(process_time, 4),
                "user_agent": user_agent
            }
            
            if body_data:
                log_data["request_body"] = body_data
            
            logger.info(f"HTTP Request: {json.dumps(log_data)}")
            
            # Response header'larına timing bilgisi ekle
            response.headers["X-Process-Time"] = str(round(process_time, 4))
            
            return response
            
        except Exception as e:
            process_time = time.time() - start_time
            
            # Error log
            log_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "client_ip": client_ip,
                "method": method,
                "url": url,
                "error": str(e),
                "process_time": round(process_time, 4),
                "user_agent": user_agent
            }
            
            if body_data:
                log_data["request_body"] = body_data
            
            logger.error(f"HTTP Request Error: {json.dumps(log_data)}")
            
            # Error response
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Internal server error"},
                headers={"X-Process-Time": str(round(process_time, 4))}
            )

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Security headers middleware
    Güvenlik header'larını ekler
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        
        self.security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        # Güvenlik header'larını ekle
        for header, value in self.security_headers.items():
            response.headers[header] = value
        
        return response

class PerformanceMonitoringMiddleware(BaseHTTPMiddleware):
    """
    Performance monitoring middleware
    Performans metrikleri toplar
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.metrics = {
            "total_requests": 0,
            "total_errors": 0,
            "avg_response_time": 0.0,
            "slow_requests": 0,  # >1 saniye
            "endpoint_stats": defaultdict(lambda: {
                "count": 0,
                "total_time": 0.0,
                "errors": 0
            })
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()
        endpoint = f"{request.method} {request.url.path}"
        
        try:
            response = await call_next(request)
            process_time = time.time() - start_time
            
            # Metrikleri güncelle
            self._update_metrics(endpoint, process_time, response.status_code >= 400)
            
            return response
            
        except Exception as e:
            process_time = time.time() - start_time
            
            # Error metrikleri
            self._update_metrics(endpoint, process_time, True)
            
            raise e
    
    def _update_metrics(self, endpoint: str, process_time: float, is_error: bool):
        """Metrikleri güncelle"""
        self.metrics["total_requests"] += 1
        
        if is_error:
            self.metrics["total_errors"] += 1
        
        if process_time > 1.0:
            self.metrics["slow_requests"] += 1
        
        # Ortalama response time güncelle
        total_time = self.metrics["avg_response_time"] * (self.metrics["total_requests"] - 1)
        self.metrics["avg_response_time"] = (total_time + process_time) / self.metrics["total_requests"]
        
        # Endpoint istatistikleri
        endpoint_stats = self.metrics["endpoint_stats"][endpoint]
        endpoint_stats["count"] += 1
        endpoint_stats["total_time"] += process_time
        
        if is_error:
            endpoint_stats["errors"] += 1
    
    def get_metrics(self) -> Dict[str, Any]:
        """Mevcut metrikleri döndür"""
        metrics = dict(self.metrics)
        
        # Endpoint istatistiklerini hesapla
        for endpoint, stats in metrics["endpoint_stats"].items():
            if stats["count"] > 0:
                stats["avg_time"] = stats["total_time"] / stats["count"]
                stats["error_rate"] = stats["errors"] / stats["count"]
        
        return metrics

class APIKeyMiddleware(BaseHTTPMiddleware):
    """
    API Key middleware
    Belirli endpoint'ler için API key kontrolü
    """
    
    def __init__(self, app: ASGIApp, api_keys: Optional[Dict[str, str]] = None):
        super().__init__(app)
        self.api_keys = api_keys or {}
        
        # API key gerektiren endpoint'ler
        self.protected_paths = [
            "/api/admin",
            "/api/system"
        ]
    
    def _requires_api_key(self, path: str) -> bool:
        """Path API key gerektiriyor mu?"""
        return any(path.startswith(protected) for protected in self.protected_paths)
    
    def _validate_api_key(self, api_key: str) -> bool:
        """API key geçerli mi?"""
        return api_key in self.api_keys.values()
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path
        
        # API key kontrolü gerekli mi?
        if self._requires_api_key(path):
            api_key = request.headers.get("X-API-Key")
            
            if not api_key:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "API key required"}
                )
            
            if not self._validate_api_key(api_key):
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Invalid API key"}
                )
        
        return await call_next(request)

class CacheMiddleware(BaseHTTPMiddleware):
    """
    Simple cache middleware
    GET istekleri için basit cache
    """
    
    def __init__(self, app: ASGIApp, cache_ttl: int = 300):
        super().__init__(app)
        self.cache_ttl = cache_ttl
        self.cache: Dict[str, Dict[str, Any]] = {}
        
        # Cache'lenecek endpoint'ler
        self.cacheable_paths = [
            "/stats/dashboard",
            "/targets",
            "/scans"
        ]
    
    def _is_cacheable(self, request: Request) -> bool:
        """İstek cache'lenebilir mi?"""
        if request.method != "GET":
            return False
        
        path = request.url.path
        return any(path.startswith(cacheable) for cacheable in self.cacheable_paths)
    
    def _get_cache_key(self, request: Request) -> str:
        """Cache key oluştur"""
        return f"{request.method}:{request.url.path}:{request.url.query}"
    
    def _is_cache_valid(self, cache_entry: Dict[str, Any]) -> bool:
        """Cache geçerli mi?"""
        return time.time() - cache_entry["timestamp"] < self.cache_ttl
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not self._is_cacheable(request):
            return await call_next(request)
        
        cache_key = self._get_cache_key(request)
        
        # Cache'den kontrol et
        if cache_key in self.cache:
            cache_entry = self.cache[cache_key]
            
            if self._is_cache_valid(cache_entry):
                # Cache hit
                response_data = cache_entry["response"]
                response = JSONResponse(
                    content=response_data["content"],
                    status_code=response_data["status_code"]
                )
                response.headers["X-Cache"] = "HIT"
                return response
            else:
                # Cache expired
                del self.cache[cache_key]
        
        # Cache miss - isteği işle
        response = await call_next(request)
        
        # Başarılı response'ları cache'le
        if response.status_code == 200:
            try:
                # Response body'sini oku
                body = b""
                async for chunk in response.body_iterator:
                    body += chunk
                
                content = json.loads(body.decode())
                
                # Cache'e kaydet
                self.cache[cache_key] = {
                    "timestamp": time.time(),
                    "response": {
                        "content": content,
                        "status_code": response.status_code
                    }
                }
                
                # Yeni response oluştur
                new_response = JSONResponse(
                    content=content,
                    status_code=response.status_code
                )
                
                # Header'ları kopyala
                for key, value in response.headers.items():
                    new_response.headers[key] = value
                
                new_response.headers["X-Cache"] = "MISS"
                return new_response
                
            except Exception:
                # Cache hatası - orijinal response'u döndür
                pass
        
        response.headers["X-Cache"] = "SKIP"
        return response

# Middleware factory fonksiyonları
def create_rate_limit_middleware(requests_per_minute: int = 60, burst_size: int = 10):
    """Rate limit middleware oluştur"""
    def middleware_factory(app: ASGIApp) -> RateLimitMiddleware:
        return RateLimitMiddleware(app, requests_per_minute, burst_size)
    return middleware_factory

def create_logging_middleware(log_body: bool = False):
    """Logging middleware oluştur"""
    def middleware_factory(app: ASGIApp) -> RequestLoggingMiddleware:
        return RequestLoggingMiddleware(app, log_body)
    return middleware_factory

def create_cache_middleware(cache_ttl: int = 300):
    """Cache middleware oluştur"""
    def middleware_factory(app: ASGIApp) -> CacheMiddleware:
        return CacheMiddleware(app, cache_ttl)
    return middleware_factory

# Tüm middleware'leri uygulama fonksiyonu
def setup_middlewares(app: FastAPI, config: Optional[Dict[str, Any]] = None):
    """
    Tüm middleware'leri FastAPI uygulamasına ekler
    
    Args:
        app (FastAPI): FastAPI uygulaması
        config (Optional[Dict[str, Any]]): Middleware konfigürasyonu
    """
    config = config or {}
    
    # Performance monitoring (en içte)
    performance_middleware = PerformanceMonitoringMiddleware(app)
    app.add_middleware(PerformanceMonitoringMiddleware)
    
    # Cache middleware
    if config.get("enable_cache", True):
        cache_ttl = config.get("cache_ttl", 300)
        app.add_middleware(CacheMiddleware, cache_ttl=cache_ttl)
    
    # Security headers
    app.add_middleware(SecurityHeadersMiddleware)
    
    # API key middleware
    api_keys = config.get("api_keys")
    if api_keys:
        app.add_middleware(APIKeyMiddleware, api_keys=api_keys)
    
    # Request logging
    if config.get("enable_logging", True):
        log_body = config.get("log_request_body", False)
        app.add_middleware(RequestLoggingMiddleware, log_body=log_body)
    
    # Rate limiting (en dışta)
    if config.get("enable_rate_limit", True):
        requests_per_minute = config.get("requests_per_minute", 60)
        burst_size = config.get("burst_size", 10)
        app.add_middleware(RateLimitMiddleware, 
                          requests_per_minute=requests_per_minute,
                          burst_size=burst_size)
    
    # Performance middleware'ini app'e ekle (metrics erişimi için)
    app.state.performance_middleware = performance_middleware
    
    logger.info("✅ Tüm middleware'ler başarıyla eklendi")

# Test fonksiyonu
if __name__ == "__main__":
    print("🧪 Nexus-Scanner API Middleware Test")
    print("=" * 40)
    
    # Middleware'leri test et
    from fastapi import FastAPI
    
    app = FastAPI()
    
    # Middleware'leri ekle
    setup_middlewares(app, {
        "enable_cache": True,
        "enable_logging": True,
        "enable_rate_limit": True,
        "requests_per_minute": 100,
        "cache_ttl": 600
    })
    
    print(f"✅ {len(app.user_middleware)} middleware eklendi")
    print("=" * 40)