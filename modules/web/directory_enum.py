#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nexus-Scanner Directory Enumeration Module
Profesyonel siber güvenlik aracı - Dizin ve dosya keşfi

Bu modül web uygulamalarında gizli dizin ve dosyaları tespit eder.
"""

import requests
import threading
import time
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

@dataclass
class DirectoryResult:
    """Dizin tarama sonucu"""
    url: str
    status_code: int
    content_length: int
    content_type: str = ""
    response_time: float = 0.0
    title: str = ""
    is_directory: bool = False
    risk_level: str = "info"  # info, low, medium, high, critical

class DirectoryEnumerator:
    """Web dizin ve dosya numaralandırıcısı"""
    
    def __init__(self, timeout: int = 10, max_threads: int = 10, delay: float = 0.1):
        self.timeout = timeout
        self.max_threads = max_threads
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Nexus-Scanner/1.0 (Security Testing Tool)'
        })
        
        # Yaygın dizin ve dosya isimleri
        self.common_paths = [
            # Admin panelleri
            'admin/', 'admin.php', 'administrator/', 'admin/login.php',
            'wp-admin/', 'cpanel/', 'control/', 'manager/',
            
            # Konfigürasyon dosyaları
            'config/', 'config.php', 'configuration.php', 'settings.php',
            'config.xml', 'web.config', '.env', 'config.json',
            
            # Backup dosyaları
            'backup/', 'backups/', 'backup.zip', 'backup.tar.gz',
            'backup.sql', 'database.sql', 'dump.sql',
            
            # Log dosyaları
            'logs/', 'log/', 'access.log', 'error.log', 'debug.log',
            'application.log', 'system.log',
            
            # Geliştirme dosyaları
            'test/', 'testing/', 'dev/', 'development/', 'staging/',
            'phpinfo.php', 'info.php', 'test.php',
            
            # Veritabanı dosyaları
            'database/', 'db/', 'mysql/', 'phpmyadmin/',
            'adminer.php', 'database.sqlite',
            
            # Upload dizinleri
            'upload/', 'uploads/', 'files/', 'media/', 'images/',
            'documents/', 'attachments/',
            
            # API endpoints
            'api/', 'rest/', 'webservice/', 'services/',
            'api/v1/', 'api/v2/', 'graphql/',
            
            # Yaygın dosyalar
            'robots.txt', 'sitemap.xml', '.htaccess', '.htpasswd',
            'crossdomain.xml', 'clientaccesspolicy.xml',
            
            # CMS specific
            'wp-content/', 'wp-includes/', 'wp-config.php',
            'sites/default/', 'modules/', 'themes/',
            
            # Güvenlik dosyaları
            'security/', '.git/', '.svn/', '.hg/',
            'CHANGELOG', 'README', 'LICENSE',
            
            # Temporary dosyalar
            'tmp/', 'temp/', 'cache/', 'session/',
            
            # Yaygın dizinler
            'assets/', 'static/', 'public/', 'private/',
            'includes/', 'lib/', 'libraries/', 'vendor/',
            
            # Error pages
            '404.php', '403.php', '500.php', 'error.php'
        ]
        
        # Hassas dosya uzantıları
        self.sensitive_extensions = [
            '.bak', '.backup', '.old', '.orig', '.tmp',
            '.sql', '.db', '.sqlite', '.mdb',
            '.log', '.txt', '.xml', '.json',
            '.zip', '.tar.gz', '.rar',
            '.php~', '.php.bak', '.asp.bak'
        ]
        
        # Risk seviyesi belirleme
        self.risk_patterns = {
            'critical': [
                'config', 'database', 'backup', '.env', 'admin',
                'phpmyadmin', 'cpanel', 'manager'
            ],
            'high': [
                'log', 'debug', 'test', 'dev', 'staging',
                'phpinfo', '.git', '.svn', 'upload'
            ],
            'medium': [
                'api', 'rest', 'webservice', 'cache',
                'tmp', 'temp', 'session'
            ]
        }
    
    def scan_directory(self, base_url: str, custom_paths: List[str] = None,
                      include_extensions: bool = True) -> List[DirectoryResult]:
        """Belirtilen URL'de dizin taraması yapar"""
        
        if not base_url.endswith('/'):
            base_url += '/'
        
        print(f"🔍 Dizin taraması başlatılıyor: {base_url}")
        
        # Test edilecek path'leri hazırla
        paths_to_test = self.common_paths.copy()
        
        if custom_paths:
            paths_to_test.extend(custom_paths)
        
        # Hassas uzantılarla kombinasyonlar oluştur
        if include_extensions:
            extended_paths = []
            for path in paths_to_test[:20]:  # İlk 20 path için uzantı kombinasyonları
                if not path.endswith('/') and '.' not in path:
                    for ext in self.sensitive_extensions:
                        extended_paths.append(path + ext)
            paths_to_test.extend(extended_paths)
        
        print(f"📋 {len(paths_to_test)} path test edilecek")
        
        results = []
        
        # Multi-threaded tarama
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_path = {
                executor.submit(self._test_path, base_url, path): path 
                for path in paths_to_test
            }
            
            completed = 0
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        if result.status_code == 200:
                            print(f"  ✅ Bulundu: {path} ({result.status_code})")
                        elif result.status_code in [301, 302, 403]:
                            print(f"  ⚠️  İlginç: {path} ({result.status_code})")
                    
                    completed += 1
                    if completed % 50 == 0:
                        print(f"  📊 İlerleme: {completed}/{len(paths_to_test)}")
                        
                except Exception as e:
                    print(f"  ❌ Hata ({path}): {str(e)}")
                
                # Rate limiting
                time.sleep(self.delay)
        
        # Sonuçları risk seviyesine göre sırala
        results.sort(key=lambda x: (
            {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}[x.risk_level],
            -x.status_code
        ))
        
        return results
    
    def _test_path(self, base_url: str, path: str) -> Optional[DirectoryResult]:
        """Tek bir path'i test eder"""
        
        test_url = urljoin(base_url, path)
        
        try:
            start_time = time.time()
            response = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
            response_time = time.time() - start_time
            
            # Sadece ilginç status code'ları kaydet
            if response.status_code in [200, 301, 302, 403, 401, 500]:
                
                # Content-Type ve title bilgilerini al
                content_type = response.headers.get('content-type', '').split(';')[0]
                title = self._extract_title(response.text) if response.status_code == 200 else ""
                
                # Dizin mi dosya mı kontrol et
                is_directory = (
                    path.endswith('/') or 
                    'text/html' in content_type and 'Index of' in response.text
                )
                
                # Risk seviyesini belirle
                risk_level = self._determine_risk_level(path, response.status_code)
                
                return DirectoryResult(
                    url=test_url,
                    status_code=response.status_code,
                    content_length=len(response.content),
                    content_type=content_type,
                    response_time=response_time,
                    title=title,
                    is_directory=is_directory,
                    risk_level=risk_level
                )
            
        except requests.exceptions.RequestException:
            # Bağlantı hataları normal, sessizce geç
            pass
        
        return None
    
    def _extract_title(self, html_content: str) -> str:
        """HTML içeriğinden title'ı çıkarır"""
        try:
            import re
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
            if title_match:
                return title_match.group(1).strip()[:100]  # İlk 100 karakter
        except:
            pass
        return ""
    
    def _determine_risk_level(self, path: str, status_code: int) -> str:
        """Path ve status code'a göre risk seviyesi belirler"""
        
        path_lower = path.lower()
        
        # Status code'a göre temel risk
        if status_code == 200:
            base_risk = "medium"
        elif status_code in [403, 401]:
            base_risk = "high"  # Korumalı alan
        elif status_code in [301, 302]:
            base_risk = "low"   # Redirect
        else:
            base_risk = "info"
        
        # Path içeriğine göre risk artırımı
        for risk_level, patterns in self.risk_patterns.items():
            for pattern in patterns:
                if pattern in path_lower:
                    if risk_level == 'critical':
                        return 'critical'
                    elif risk_level == 'high' and base_risk != 'critical':
                        return 'high'
                    elif risk_level == 'medium' and base_risk in ['info', 'low']:
                        return 'medium'
        
        return base_risk
    
    def generate_report(self, results: List[DirectoryResult]) -> Dict[str, Any]:
        """Tarama sonuçlarından rapor oluşturur"""
        
        total_found = len(results)
        
        # Status code'lara göre grupla
        status_summary = {}
        risk_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        content_types = {}
        
        accessible_count = 0
        protected_count = 0
        redirect_count = 0
        
        for result in results:
            # Status code summary
            status_summary[result.status_code] = status_summary.get(result.status_code, 0) + 1
            
            # Risk summary
            risk_summary[result.risk_level] += 1
            
            # Content type summary
            if result.content_type:
                content_types[result.content_type] = content_types.get(result.content_type, 0) + 1
            
            # Access summary
            if result.status_code == 200:
                accessible_count += 1
            elif result.status_code in [401, 403]:
                protected_count += 1
            elif result.status_code in [301, 302]:
                redirect_count += 1
        
        # Kritik bulgular
        critical_findings = [
            result for result in results 
            if result.risk_level in ['critical', 'high'] and result.status_code == 200
        ]
        
        # Korumalı alanlar
        protected_areas = [
            result for result in results 
            if result.status_code in [401, 403]
        ]
        
        return {
            "scan_summary": {
                "total_found": total_found,
                "accessible_count": accessible_count,
                "protected_count": protected_count,
                "redirect_count": redirect_count
            },
            "status_summary": status_summary,
            "risk_summary": risk_summary,
            "content_types": content_types,
            "critical_findings": [
                {
                    "url": result.url,
                    "status_code": result.status_code,
                    "risk_level": result.risk_level,
                    "content_type": result.content_type,
                    "title": result.title,
                    "content_length": result.content_length
                }
                for result in critical_findings
            ],
            "protected_areas": [
                {
                    "url": result.url,
                    "status_code": result.status_code,
                    "risk_level": result.risk_level
                }
                for result in protected_areas
            ],
            "recommendations": self._get_recommendations(critical_findings, protected_areas)
        }
    
    def _get_recommendations(self, critical_findings: List[DirectoryResult], 
                           protected_areas: List[DirectoryResult]) -> List[str]:
        """Güvenlik önerileri döndürür"""
        
        recommendations = []
        
        if critical_findings:
            recommendations.extend([
                "🚨 ACIL: Kritik dosya/dizinler herkese açık!",
                "✅ Hassas dosyaları web dizininden kaldırın",
                "✅ .htaccess ile erişimi kısıtlayın",
                "✅ Backup dosyalarını güvenli konuma taşıyın"
            ])
        
        if protected_areas:
            recommendations.extend([
                "⚠️  Korumalı alanlar tespit edildi",
                "✅ Erişim kontrollerini gözden geçirin",
                "✅ Gereksiz admin panellerini kaldırın"
            ])
        
        # Genel öneriler
        recommendations.extend([
            "✅ robots.txt dosyasını kontrol edin",
            "✅ Directory listing'i devre dışı bırakın",
            "✅ Gereksiz dosyaları sunucudan kaldırın",
            "✅ Düzenli güvenlik taramaları yapın",
            "✅ Web sunucu konfigürasyonunu sıkılaştırın"
        ])
        
        return recommendations

# Test fonksiyonu
if __name__ == "__main__":
    enumerator = DirectoryEnumerator(max_threads=5, delay=0.2)
    
    # Test URL'i
    test_url = "http://testphp.vulnweb.com/"
    
    print("Nexus-Scanner Directory Enumeration Test")
    print("=" * 45)
    
    results = enumerator.scan_directory(test_url)
    report = enumerator.generate_report(results)
    
    print("\n📊 Tarama Raporu:")
    print(f"Toplam Bulgu: {report['scan_summary']['total_found']}")
    print(f"Erişilebilir: {report['scan_summary']['accessible_count']}")
    print(f"Korumalı: {report['scan_summary']['protected_count']}")
    print(f"Yönlendirme: {report['scan_summary']['redirect_count']}")
    
    if report['critical_findings']:
        print("\n🚨 Kritik Bulgular:")
        for finding in report['critical_findings'][:5]:  # İlk 5 tanesi
            print(f"  - {finding['url']} ({finding['status_code']}) - {finding['risk_level']}")
    
    if report['protected_areas']:
        print("\n🔒 Korumalı Alanlar:")
        for area in report['protected_areas'][:5]:  # İlk 5 tanesi
            print(f"  - {area['url']} ({area['status_code']})")
    
    print("\n💡 Öneriler:")
    for rec in report['recommendations'][:5]:  # İlk 5 öneri
        print(f"  {rec}")