#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nexus-Scanner API Module
Profesyonel siber güvenlik aracı - REST API modülü

Bu modül Nexus-Scanner için FastAPI tabanlı REST API sağlar.
Kullanıcı yönetimi, hedef yönetimi, tarama işlemleri ve raporlama
funksiyonlarını web servisi olarak sunar.

Özellikler:
- JWT tabanlı authentication
- RESTful API endpoints
- Async/await desteği
- Otomatik API dokümantasyonu
- CORS ve güvenlik middleware'leri
- Background task işleme
- File upload/download
- Real-time scan monitoring

Kullanım:
    from api import create_app, get_app_config
    
    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=8000)

Endpoints:
    Authentication:
        POST /auth/register - Kullanıcı kaydı
        POST /auth/login - Kullanıcı girişi
        GET /auth/me - Kullanıcı bilgileri
    
    Targets:
        GET /targets - Hedefleri listele
        POST /targets - Yeni hedef oluştur
        GET /targets/{id} - Hedef detayları
    
    Scans:
        GET /scans - Taramaları listele
        POST /scans - Yeni tarama başlat
        GET /scans/{id} - Tarama detayları
    
    Reports:
        POST /reports/generate - Rapor oluştur
        GET /reports - Raporları listele
        GET /reports/{id}/download - Rapor indir
    
    Statistics:
        GET /stats/dashboard - Dashboard istatistikleri

Yazar: Nexus-Scanner Team
Versiyon: 1.0.0
Lisans: MIT
"""

import os
import sys
from typing import Dict, Any, Optional
from datetime import datetime

# Version bilgisi
__version__ = "1.0.0"
__author__ = "Nexus-Scanner Team"
__license__ = "MIT"
__description__ = "Nexus-Scanner REST API Module"

# API konfigürasyonu
API_CONFIG = {
    "title": "Nexus-Scanner API",
    "description": "Profesyonel siber güvenlik aracı REST API",
    "version": __version__,
    "docs_url": "/docs",
    "redoc_url": "/redoc",
    "openapi_url": "/openapi.json"
}

# Güvenlik ayarları
SECURITY_CONFIG = {
    "secret_key": os.getenv("NEXUS_SECRET_KEY", "nexus-scanner-secret-key-change-in-production"),
    "algorithm": "HS256",
    "access_token_expire_minutes": 30,
    "refresh_token_expire_days": 7
}

# CORS ayarları
CORS_CONFIG = {
    "allow_origins": ["*"],  # Production'da specific origins kullan
    "allow_credentials": True,
    "allow_methods": ["*"],
    "allow_headers": ["*"]
}

# Rate limiting ayarları
RATE_LIMIT_CONFIG = {
    "requests_per_minute": 60,
    "burst_size": 10
}

try:
    # FastAPI imports
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.middleware.trustedhost import TrustedHostMiddleware
    from fastapi.staticfiles import StaticFiles
    
    # Proje modüllerini import et
    from .main import app as main_app
    
    # API uygulaması mevcut
    API_AVAILABLE = True
    
except ImportError as e:
    print(f"⚠️ API modülü import hatası: {e}")
    print("FastAPI ve bağımlılıkları yüklü değil. 'pip install -r api/requirements.txt' çalıştırın.")
    API_AVAILABLE = False
    main_app = None

def get_api_info() -> Dict[str, Any]:
    """
    API modülü hakkında bilgi döndürür
    
    Returns:
        Dict[str, Any]: API bilgileri
    """
    return {
        "name": "Nexus-Scanner API",
        "version": __version__,
        "description": __description__,
        "author": __author__,
        "license": __license__,
        "available": API_AVAILABLE,
        "endpoints": {
            "docs": "/docs",
            "redoc": "/redoc",
            "openapi": "/openapi.json",
            "health": "/health"
        },
        "features": [
            "JWT Authentication",
            "RESTful Endpoints",
            "Async Support",
            "Auto Documentation",
            "CORS Support",
            "Background Tasks",
            "File Operations",
            "Real-time Monitoring"
        ]
    }

def get_app_config() -> Dict[str, Any]:
    """
    Uygulama konfigürasyonunu döndürür
    
    Returns:
        Dict[str, Any]: Konfigürasyon ayarları
    """
    return {
        "api": API_CONFIG,
        "security": SECURITY_CONFIG,
        "cors": CORS_CONFIG,
        "rate_limit": RATE_LIMIT_CONFIG
    }

def create_app(config: Optional[Dict[str, Any]] = None) -> Optional[FastAPI]:
    """
    FastAPI uygulaması oluşturur
    
    Args:
        config (Optional[Dict[str, Any]]): Özel konfigürasyon
    
    Returns:
        Optional[FastAPI]: FastAPI uygulaması veya None
    """
    if not API_AVAILABLE:
        print("❌ API modülü kullanılamıyor. Bağımlılıkları yükleyin.")
        return None
    
    try:
        # Konfigürasyonu birleştir
        app_config = get_app_config()
        if config:
            app_config.update(config)
        
        # FastAPI uygulaması oluştur
        app = FastAPI(
            title=app_config["api"]["title"],
            description=app_config["api"]["description"],
            version=app_config["api"]["version"],
            docs_url=app_config["api"]["docs_url"],
            redoc_url=app_config["api"]["redoc_url"],
            openapi_url=app_config["api"]["openapi_url"]
        )
        
        # CORS middleware ekle
        app.add_middleware(
            CORSMiddleware,
            **app_config["cors"]
        )
        
        # Trusted host middleware ekle
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=["*"]  # Production'da specific hosts kullan
        )
        
        # Static files
        static_dir = os.path.join(os.path.dirname(__file__), "static")
        if os.path.exists(static_dir):
            app.mount("/static", StaticFiles(directory=static_dir), name="static")
        
        return app
        
    except Exception as e:
        print(f"❌ API uygulaması oluşturulamadı: {e}")
        return None

def start_api_server(
    host: str = "0.0.0.0",
    port: int = 8000,
    reload: bool = False,
    log_level: str = "info"
) -> None:
    """
    API sunucusunu başlatır
    
    Args:
        host (str): Sunucu host adresi
        port (int): Sunucu portu
        reload (bool): Otomatik yeniden yükleme
        log_level (str): Log seviyesi
    """
    if not API_AVAILABLE:
        print("❌ API sunucusu başlatılamıyor. Bağımlılıkları yükleyin.")
        return
    
    try:
        import uvicorn
        
        print("🚀 Nexus-Scanner API Server")
        print("=" * 50)
        print(f"📍 URL: http://{host}:{port}")
        print(f"📚 Docs: http://{host}:{port}/docs")
        print(f"🔄 ReDoc: http://{host}:{port}/redoc")
        print(f"💚 Health: http://{host}:{port}/health")
        print("=" * 50)
        
        uvicorn.run(
            "api.main:app",
            host=host,
            port=port,
            reload=reload,
            log_level=log_level
        )
        
    except ImportError:
        print("❌ uvicorn yüklü değil. 'pip install uvicorn' çalıştırın.")
    except Exception as e:
        print(f"❌ API sunucusu başlatılamadı: {e}")

def test_api_connection(base_url: str = "http://localhost:8000") -> bool:
    """
    API bağlantısını test eder
    
    Args:
        base_url (str): API base URL
    
    Returns:
        bool: Bağlantı durumu
    """
    try:
        import requests
        
        response = requests.get(f"{base_url}/health", timeout=5)
        return response.status_code == 200
        
    except Exception as e:
        print(f"⚠️ API bağlantı testi başarısız: {e}")
        return False

def get_api_status() -> Dict[str, Any]:
    """
    API durumunu döndürür
    
    Returns:
        Dict[str, Any]: API durum bilgileri
    """
    status = {
        "module_available": API_AVAILABLE,
        "timestamp": datetime.utcnow().isoformat(),
        "version": __version__
    }
    
    if API_AVAILABLE:
        status["connection_test"] = test_api_connection()
        status["endpoints"] = {
            "health": "/health",
            "docs": "/docs",
            "auth": "/auth/*",
            "targets": "/targets/*",
            "scans": "/scans/*",
            "reports": "/reports/*",
            "stats": "/stats/*"
        }
    
    return status

# Convenience exports
__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "__description__",
    "API_AVAILABLE",
    "get_api_info",
    "get_app_config",
    "create_app",
    "start_api_server",
    "test_api_connection",
    "get_api_status",
    "main_app"
]

# Modül yüklendiğinde bilgi göster
if __name__ != "__main__":
    info = get_api_info()
    print(f"📡 {info['name']} v{info['version']} - {'✅ Hazır' if info['available'] else '❌ Kullanılamıyor'}")

# Test fonksiyonu
if __name__ == "__main__":
    print("🧪 Nexus-Scanner API Module Test")
    print("=" * 40)
    
    # API bilgilerini göster
    info = get_api_info()
    print(f"📡 Modül: {info['name']}")
    print(f"📦 Versiyon: {info['version']}")
    print(f"✅ Durum: {'Hazır' if info['available'] else 'Kullanılamıyor'}")
    
    if info['available']:
        print(f"🔗 Endpoints: {len(info['endpoints'])} adet")
        print(f"⚡ Özellikler: {len(info['features'])} adet")
        
        # Konfigürasyonu göster
        config = get_app_config()
        print(f"⚙️ Konfigürasyon: {len(config)} kategori")
        
        # API durumunu kontrol et
        status = get_api_status()
        print(f"📊 Durum: {status}")
    
    print("=" * 40)