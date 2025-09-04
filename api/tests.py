#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nexus-Scanner API Tests
API endpoint'leri için test suite

Bu modül FastAPI uygulaması için kapsamlı testler sağlar:
- Authentication testleri
- CRUD operation testleri
- Validation testleri
- Security testleri
- Performance testleri
"""

import os
import sys
import pytest
import asyncio
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

# Test imports
from fastapi.testclient import TestClient
from fastapi import status
import json

# Proje modüllerini import et
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from api.main import app
    from api.utils import generate_secure_token, create_jwt_token
    from database import get_database_manager
    from database.models import User, Target, Scan, Finding, Report
except ImportError as e:
    print(f"⚠️ Test modülü import hatası: {e}")
    pytest.skip("Required modules not available", allow_module_level=True)

# Test client
client = TestClient(app)

# Test configuration
TEST_CONFIG = {
    "test_user": {
        "username": "testuser",
        "email": "test@example.com",
        "password": "TestPassword123!",
        "full_name": "Test User"
    },
    "test_target": {
        "name": "Test Target",
        "url": "https://example.com",
        "description": "Test target for API testing",
        "target_type": "web"
    },
    "test_scan": {
        "scan_type": "web",
        "scan_config": {
            "timeout": 30,
            "threads": 5
        }
    }
}

class TestHelper:
    """Test yardımcı sınıfı"""
    
    def __init__(self):
        self.access_token: Optional[str] = None
        self.user_id: Optional[int] = None
        self.target_id: Optional[int] = None
        self.scan_id: Optional[int] = None
    
    def get_auth_headers(self) -> Dict[str, str]:
        """Authentication header'larını döndür"""
        if not self.access_token:
            raise ValueError("No access token available")
        return {"Authorization": f"Bearer {self.access_token}"}
    
    def register_test_user(self) -> Dict[str, Any]:
        """Test kullanıcısı kaydı"""
        response = client.post("/auth/register", json=TEST_CONFIG["test_user"])
        return response
    
    def login_test_user(self) -> Dict[str, Any]:
        """Test kullanıcısı girişi"""
        login_data = {
            "username": TEST_CONFIG["test_user"]["username"],
            "password": TEST_CONFIG["test_user"]["password"]
        }
        response = client.post("/auth/login", json=login_data)
        
        if response.status_code == 200:
            token_data = response.json()
            self.access_token = token_data["access_token"]
        
        return response
    
    def create_test_target(self) -> Dict[str, Any]:
        """Test hedefi oluştur"""
        response = client.post(
            "/targets",
            json=TEST_CONFIG["test_target"],
            headers=self.get_auth_headers()
        )
        
        if response.status_code == 200:
            target_data = response.json()
            self.target_id = target_data["target_id"]
        
        return response
    
    def create_test_scan(self) -> Dict[str, Any]:
        """Test taraması oluştur"""
        if not self.target_id:
            raise ValueError("No target ID available")
        
        scan_data = TEST_CONFIG["test_scan"].copy()
        scan_data["target_id"] = self.target_id
        
        response = client.post(
            "/scans",
            json=scan_data,
            headers=self.get_auth_headers()
        )
        
        if response.status_code == 200:
            scan_response = response.json()
            self.scan_id = scan_response["scan_id"]
        
        return response
    
    def cleanup(self):
        """Test verilerini temizle"""
        # Bu gerçek bir uygulamada database cleanup yapılır
        pass

# Test fixtures
@pytest.fixture
def test_helper():
    """Test helper fixture"""
    helper = TestHelper()
    yield helper
    helper.cleanup()

@pytest.fixture
def authenticated_helper(test_helper):
    """Authenticated test helper fixture"""
    # Kullanıcı kaydı ve girişi
    test_helper.register_test_user()
    test_helper.login_test_user()
    return test_helper

# Root endpoint testleri
class TestRootEndpoints:
    """Root endpoint testleri"""
    
    def test_root_endpoint(self):
        """Root endpoint testi"""
        response = client.get("/")
        assert response.status_code == 200
        
        data = response.json()
        assert "message" in data
        assert "Nexus-Scanner API" in data["message"]
        assert "status" in data
        assert data["status"] == "active"
    
    def test_health_endpoint(self):
        """Health endpoint testi"""
        response = client.get("/health")
        assert response.status_code == 200
        
        data = response.json()
        assert "status" in data
        assert "timestamp" in data
        assert "version" in data
        assert "database" in data

# Authentication testleri
class TestAuthentication:
    """Authentication endpoint testleri"""
    
    def test_user_registration_success(self, test_helper):
        """Başarılı kullanıcı kaydı testi"""
        response = test_helper.register_test_user()
        assert response.status_code == 200
        
        data = response.json()
        assert "message" in data
        assert "user_id" in data
        assert "username" in data
        assert data["username"] == TEST_CONFIG["test_user"]["username"]
    
    def test_user_registration_duplicate(self, test_helper):
        """Duplicate kullanıcı kaydı testi"""
        # İlk kayıt
        test_helper.register_test_user()
        
        # Duplicate kayıt
        response = test_helper.register_test_user()
        assert response.status_code == 400
        
        data = response.json()
        assert "detail" in data
    
    def test_user_registration_invalid_email(self):
        """Geçersiz email ile kayıt testi"""
        invalid_user = TEST_CONFIG["test_user"].copy()
        invalid_user["email"] = "invalid-email"
        
        response = client.post("/auth/register", json=invalid_user)
        assert response.status_code == 422
    
    def test_user_login_success(self, test_helper):
        """Başarılı kullanıcı girişi testi"""
        # Önce kayıt ol
        test_helper.register_test_user()
        
        # Giriş yap
        response = test_helper.login_test_user()
        assert response.status_code == 200
        
        data = response.json()
        assert "access_token" in data
        assert "token_type" in data
        assert "expires_in" in data
        assert data["token_type"] == "bearer"
    
    def test_user_login_invalid_credentials(self):
        """Geçersiz kimlik bilgileri ile giriş testi"""
        login_data = {
            "username": "nonexistent",
            "password": "wrongpassword"
        }
        
        response = client.post("/auth/login", json=login_data)
        assert response.status_code == 401
        
        data = response.json()
        assert "detail" in data
    
    def test_get_current_user(self, authenticated_helper):
        """Mevcut kullanıcı bilgileri testi"""
        response = client.get(
            "/auth/me",
            headers=authenticated_helper.get_auth_headers()
        )
        assert response.status_code == 200
        
        data = response.json()
        assert "id" in data
        assert "username" in data
        assert "email" in data
        assert data["username"] == TEST_CONFIG["test_user"]["username"]
    
    def test_get_current_user_unauthorized(self):
        """Yetkisiz kullanıcı bilgileri testi"""
        response = client.get("/auth/me")
        assert response.status_code == 403

# Target endpoint testleri
class TestTargets:
    """Target endpoint testleri"""
    
    def test_create_target_success(self, authenticated_helper):
        """Başarılı hedef oluşturma testi"""
        response = authenticated_helper.create_test_target()
        assert response.status_code == 200
        
        data = response.json()
        assert "message" in data
        assert "target_id" in data
        assert "name" in data
        assert "url" in data
    
    def test_create_target_invalid_url(self, authenticated_helper):
        """Geçersiz URL ile hedef oluşturma testi"""
        invalid_target = TEST_CONFIG["test_target"].copy()
        invalid_target["url"] = "invalid-url"
        
        response = client.post(
            "/targets",
            json=invalid_target,
            headers=authenticated_helper.get_auth_headers()
        )
        assert response.status_code == 422
    
    def test_create_target_unauthorized(self):
        """Yetkisiz hedef oluşturma testi"""
        response = client.post("/targets", json=TEST_CONFIG["test_target"])
        assert response.status_code == 403
    
    def test_list_targets(self, authenticated_helper):
        """Hedefleri listeleme testi"""
        # Önce bir hedef oluştur
        authenticated_helper.create_test_target()
        
        response = client.get(
            "/targets",
            headers=authenticated_helper.get_auth_headers()
        )
        assert response.status_code == 200
        
        data = response.json()
        assert "targets" in data
        assert "total" in data
        assert len(data["targets"]) > 0
    
    def test_get_target_details(self, authenticated_helper):
        """Hedef detayları testi"""
        # Önce bir hedef oluştur
        authenticated_helper.create_test_target()
        
        response = client.get(
            f"/targets/{authenticated_helper.target_id}",
            headers=authenticated_helper.get_auth_headers()
        )
        assert response.status_code == 200
        
        data = response.json()
        assert "id" in data
        assert "name" in data
        assert "url" in data
        assert "recent_scans" in data
    
    def test_get_target_not_found(self, authenticated_helper):
        """Bulunamayan hedef testi"""
        response = client.get(
            "/targets/99999",
            headers=authenticated_helper.get_auth_headers()
        )
        assert response.status_code == 404

# Scan endpoint testleri
class TestScans:
    """Scan endpoint testleri"""
    
    def test_create_scan_success(self, authenticated_helper):
        """Başarılı tarama oluşturma testi"""
        # Önce bir hedef oluştur
        authenticated_helper.create_test_target()
        
        # Tarama oluştur
        response = authenticated_helper.create_test_scan()
        assert response.status_code == 200
        
        data = response.json()
        assert "message" in data
        assert "scan_id" in data
        assert "status" in data
        assert "target_name" in data
    
    def test_create_scan_invalid_target(self, authenticated_helper):
        """Geçersiz hedef ile tarama oluşturma testi"""
        scan_data = TEST_CONFIG["test_scan"].copy()
        scan_data["target_id"] = 99999
        
        response = client.post(
            "/scans",
            json=scan_data,
            headers=authenticated_helper.get_auth_headers()
        )
        assert response.status_code == 404
    
    def test_list_scans(self, authenticated_helper):
        """Taramaları listeleme testi"""
        # Önce bir tarama oluştur
        authenticated_helper.create_test_target()
        authenticated_helper.create_test_scan()
        
        response = client.get(
            "/scans",
            headers=authenticated_helper.get_auth_headers()
        )
        assert response.status_code == 200
        
        data = response.json()
        assert "scans" in data
        assert "total" in data
        assert len(data["scans"]) > 0
    
    def test_get_scan_details(self, authenticated_helper):
        """Tarama detayları testi"""
        # Önce bir tarama oluştur
        authenticated_helper.create_test_target()
        authenticated_helper.create_test_scan()
        
        response = client.get(
            f"/scans/{authenticated_helper.scan_id}",
            headers=authenticated_helper.get_auth_headers()
        )
        assert response.status_code == 200
        
        data = response.json()
        assert "id" in data
        assert "target" in data
        assert "scan_type" in data
        assert "status" in data
        assert "findings" in data
        assert "findings_summary" in data

# Report endpoint testleri
class TestReports:
    """Report endpoint testleri"""
    
    def test_list_reports(self, authenticated_helper):
        """Raporları listeleme testi"""
        response = client.get(
            "/reports",
            headers=authenticated_helper.get_auth_headers()
        )
        assert response.status_code == 200
        
        data = response.json()
        assert "reports" in data
        assert "total" in data

# Statistics endpoint testleri
class TestStatistics:
    """Statistics endpoint testleri"""
    
    def test_dashboard_stats(self, authenticated_helper):
        """Dashboard istatistikleri testi"""
        response = client.get(
            "/stats/dashboard",
            headers=authenticated_helper.get_auth_headers()
        )
        assert response.status_code == 200
        
        data = response.json()
        assert "summary" in data
        assert "risk_distribution" in data
        assert "latest_scans" in data
        
        # Summary kontrolü
        summary = data["summary"]
        assert "total_targets" in summary
        assert "total_scans" in summary
        assert "total_findings" in summary
        assert "total_reports" in summary

# Security testleri
class TestSecurity:
    """Security testleri"""
    
    def test_sql_injection_protection(self, authenticated_helper):
        """SQL injection koruması testi"""
        malicious_input = "'; DROP TABLE users; --"
        
        # Hedef oluşturmaya SQL injection dene
        malicious_target = TEST_CONFIG["test_target"].copy()
        malicious_target["name"] = malicious_input
        
        response = client.post(
            "/targets",
            json=malicious_target,
            headers=authenticated_helper.get_auth_headers()
        )
        
        # İstek başarılı olsa bile SQL injection çalışmamalı
        # Database hala erişilebilir olmalı
        health_response = client.get("/health")
        assert health_response.status_code == 200
    
    def test_xss_protection(self, authenticated_helper):
        """XSS koruması testi"""
        xss_payload = "<script>alert('xss')</script>"
        
        malicious_target = TEST_CONFIG["test_target"].copy()
        malicious_target["description"] = xss_payload
        
        response = client.post(
            "/targets",
            json=malicious_target,
            headers=authenticated_helper.get_auth_headers()
        )
        
        # Response'da script tag'i olmamalı
        if response.status_code == 200:
            response_text = response.text
            assert "<script>" not in response_text
    
    def test_rate_limiting(self):
        """Rate limiting testi"""
        # Çok sayıda istek gönder
        responses = []
        for i in range(70):  # Rate limit 60/dakika
            response = client.get("/")
            responses.append(response.status_code)
        
        # En az bir 429 (Too Many Requests) olmalı
        assert 429 in responses
    
    def test_cors_headers(self):
        """CORS header'ları testi"""
        response = client.options("/")
        
        # CORS header'ları kontrol et
        assert "access-control-allow-origin" in response.headers
        assert "access-control-allow-methods" in response.headers
        assert "access-control-allow-headers" in response.headers

# Performance testleri
class TestPerformance:
    """Performance testleri"""
    
    def test_response_time(self):
        """Response time testi"""
        import time
        
        start_time = time.time()
        response = client.get("/")
        end_time = time.time()
        
        response_time = end_time - start_time
        
        assert response.status_code == 200
        assert response_time < 1.0  # 1 saniyeden az olmalı
    
    def test_concurrent_requests(self, authenticated_helper):
        """Eşzamanlı istek testi"""
        import threading
        import time
        
        results = []
        
        def make_request():
            response = client.get(
                "/targets",
                headers=authenticated_helper.get_auth_headers()
            )
            results.append(response.status_code)
        
        # 10 eşzamanlı istek
        threads = []
        for i in range(10):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()
        
        # Tüm thread'lerin bitmesini bekle
        for thread in threads:
            thread.join()
        
        # Tüm istekler başarılı olmalı
        assert len(results) == 10
        assert all(status == 200 for status in results)

# Integration testleri
class TestIntegration:
    """Integration testleri"""
    
    def test_full_workflow(self, test_helper):
        """Tam workflow testi"""
        # 1. Kullanıcı kaydı
        register_response = test_helper.register_test_user()
        assert register_response.status_code == 200
        
        # 2. Giriş
        login_response = test_helper.login_test_user()
        assert login_response.status_code == 200
        
        # 3. Hedef oluşturma
        target_response = test_helper.create_test_target()
        assert target_response.status_code == 200
        
        # 4. Tarama başlatma
        scan_response = test_helper.create_test_scan()
        assert scan_response.status_code == 200
        
        # 5. Tarama durumunu kontrol etme
        scan_detail_response = client.get(
            f"/scans/{test_helper.scan_id}",
            headers=test_helper.get_auth_headers()
        )
        assert scan_detail_response.status_code == 200
        
        # 6. Dashboard istatistikleri
        stats_response = client.get(
            "/stats/dashboard",
            headers=test_helper.get_auth_headers()
        )
        assert stats_response.status_code == 200

# Pytest configuration
pytest_plugins = []

def pytest_configure(config):
    """Pytest konfigürasyonu"""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m "not slow"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )

# Test runner
if __name__ == "__main__":
    print("🧪 Nexus-Scanner API Tests")
    print("=" * 40)
    
    # Pytest'i çalıştır
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--color=yes"
    ])