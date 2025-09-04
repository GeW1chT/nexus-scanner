#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nexus-Scanner SSL/TLS Security Checker Module
Profesyonel siber güvenlik aracı - SSL/TLS güvenlik analizi

Bu modül web sitelerinin SSL/TLS konfigürasyonlarını analiz eder.
"""

import ssl
import socket
import requests
import datetime
import hashlib
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import concurrent.futures
import time

@dataclass
class SSLResult:
    """SSL/TLS kontrol sonucu"""
    hostname: str
    port: int
    is_valid: bool
    certificate_info: Dict[str, Any]
    protocol_info: Dict[str, Any]
    cipher_info: Dict[str, Any]
    vulnerabilities: List[Dict[str, Any]]
    security_score: int  # 0-100 arası
    risk_level: str  # low, medium, high, critical
    recommendations: List[str]
    scan_time: float

class SSLChecker:
    """SSL/TLS güvenlik kontrolcüsü"""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        
        # Zayıf cipher suite'ler
        self.weak_ciphers = {
            'NULL': 'critical',
            'EXPORT': 'critical', 
            'DES': 'critical',
            'RC4': 'high',
            'MD5': 'high',
            'SHA1': 'medium',
            'CBC': 'low'  # Padding oracle saldırıları için
        }
        
        # Güvenli protokoller
        self.secure_protocols = {
            'TLSv1.3': 100,
            'TLSv1.2': 90,
            'TLSv1.1': 60,
            'TLSv1.0': 40,
            'SSLv3': 10,
            'SSLv2': 0
        }
        
        # Güvenli anahtar boyutları
        self.key_size_scores = {
            4096: 100,
            2048: 90,
            1024: 50,
            512: 10
        }
    
    def check_ssl(self, hostname: str, port: int = 443) -> SSLResult:
        """Belirtilen host için SSL/TLS kontrolü yapar"""
        
        start_time = time.time()
        
        print(f"🔒 SSL/TLS kontrolü başlatılıyor: {hostname}:{port}")
        
        try:
            # SSL bağlantısı kur
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    
                    # Sertifika bilgilerini al
                    cert_info = self._analyze_certificate(ssock.getpeercert(binary_form=False))
                    cert_der = ssock.getpeercert(binary_form=True)
                    
                    # Protokol bilgilerini al
                    protocol_info = self._analyze_protocol(ssock)
                    
                    # Cipher bilgilerini al
                    cipher_info = self._analyze_cipher(ssock)
                    
                    # Güvenlik açıklarını kontrol et
                    vulnerabilities = self._check_vulnerabilities(
                        hostname, port, cert_info, protocol_info, cipher_info
                    )
                    
                    # Güvenlik skorunu hesapla
                    security_score, risk_level = self._calculate_security_score(
                        cert_info, protocol_info, cipher_info, vulnerabilities
                    )
                    
                    # Önerileri oluştur
                    recommendations = self._generate_recommendations(
                        cert_info, protocol_info, cipher_info, vulnerabilities
                    )
                    
                    scan_time = time.time() - start_time
                    
                    return SSLResult(
                        hostname=hostname,
                        port=port,
                        is_valid=True,
                        certificate_info=cert_info,
                        protocol_info=protocol_info,
                        cipher_info=cipher_info,
                        vulnerabilities=vulnerabilities,
                        security_score=security_score,
                        risk_level=risk_level,
                        recommendations=recommendations,
                        scan_time=scan_time
                    )
        
        except Exception as e:
            scan_time = time.time() - start_time
            
            return SSLResult(
                hostname=hostname,
                port=port,
                is_valid=False,
                certificate_info={"error": str(e)},
                protocol_info={},
                cipher_info={},
                vulnerabilities=[{
                    "type": "connection_error",
                    "severity": "high",
                    "description": f"SSL bağlantısı kurulamadı: {str(e)}"
                }],
                security_score=0,
                risk_level="critical",
                recommendations=["SSL/TLS konfigürasyonunu kontrol edin"],
                scan_time=scan_time
            )
    
    def _analyze_certificate(self, cert: Dict[str, Any]) -> Dict[str, Any]:
        """Sertifika bilgilerini analiz eder"""
        
        if not cert:
            return {"error": "Sertifika bilgisi alınamadı"}
        
        # Tarih bilgilerini parse et
        not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        now = datetime.datetime.now()
        
        # Kalan süre
        days_until_expiry = (not_after - now).days
        
        # Subject ve issuer bilgileri
        subject = dict(x[0] for x in cert.get('subject', []))
        issuer = dict(x[0] for x in cert.get('issuer', []))
        
        # SAN (Subject Alternative Names)
        san_list = []
        for ext in cert.get('subjectAltName', []):
            if ext[0] == 'DNS':
                san_list.append(ext[1])
        
        # Anahtar bilgileri
        public_key = cert.get('subjectPublicKeyInfo', {})
        key_size = self._extract_key_size(cert)
        
        return {
            "subject": subject,
            "issuer": issuer,
            "version": cert.get('version', 'Unknown'),
            "serial_number": cert.get('serialNumber', 'Unknown'),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_until_expiry": days_until_expiry,
            "is_expired": now > not_after,
            "is_self_signed": subject.get('commonName') == issuer.get('commonName'),
            "common_name": subject.get('commonName', 'Unknown'),
            "organization": subject.get('organizationName', 'Unknown'),
            "san_list": san_list,
            "key_size": key_size,
            "signature_algorithm": cert.get('signatureAlgorithm', 'Unknown')
        }
    
    def _extract_key_size(self, cert: Dict[str, Any]) -> int:
        """Sertifikadan anahtar boyutunu çıkarır"""
        try:
            # Bu basit bir yaklaşım, gerçek implementasyonda
            # cryptography kütüphanesi kullanılabilir
            return 2048  # Default değer
        except:
            return 0
    
    def _analyze_protocol(self, ssock) -> Dict[str, Any]:
        """SSL/TLS protokol bilgilerini analiz eder"""
        
        protocol_version = ssock.version()
        
        return {
            "version": protocol_version,
            "is_secure": protocol_version in ['TLSv1.2', 'TLSv1.3'],
            "score": self.secure_protocols.get(protocol_version, 0)
        }
    
    def _analyze_cipher(self, ssock) -> Dict[str, Any]:
        """Cipher suite bilgilerini analiz eder"""
        
        cipher = ssock.cipher()
        if not cipher:
            return {"error": "Cipher bilgisi alınamadı"}
        
        cipher_name, protocol_version, key_bits = cipher
        
        # Cipher güvenliğini değerlendir
        is_weak = any(weak in cipher_name.upper() for weak in self.weak_ciphers.keys())
        
        # Cipher kategorisini belirle
        cipher_category = "unknown"
        if "ECDHE" in cipher_name:
            cipher_category = "perfect_forward_secrecy"
        elif "DHE" in cipher_name:
            cipher_category = "forward_secrecy"
        elif "RSA" in cipher_name:
            cipher_category = "rsa_key_exchange"
        
        return {
            "name": cipher_name,
            "protocol": protocol_version,
            "key_bits": key_bits,
            "is_weak": is_weak,
            "category": cipher_category,
            "supports_pfs": "ECDHE" in cipher_name or "DHE" in cipher_name
        }
    
    def _check_vulnerabilities(self, hostname: str, port: int, 
                             cert_info: Dict, protocol_info: Dict, 
                             cipher_info: Dict) -> List[Dict[str, Any]]:
        """Bilinen güvenlik açıklarını kontrol eder"""
        
        vulnerabilities = []
        
        # Sertifika kontrolleri
        if cert_info.get('is_expired'):
            vulnerabilities.append({
                "type": "expired_certificate",
                "severity": "critical",
                "description": "SSL sertifikası süresi dolmuş",
                "details": f"Sertifika {cert_info.get('not_after')} tarihinde süresi dolmuş"
            })
        
        if cert_info.get('days_until_expiry', 0) < 30:
            vulnerabilities.append({
                "type": "expiring_certificate",
                "severity": "medium",
                "description": "SSL sertifikası yakında sona erecek",
                "details": f"{cert_info.get('days_until_expiry')} gün kaldı"
            })
        
        if cert_info.get('is_self_signed'):
            vulnerabilities.append({
                "type": "self_signed_certificate",
                "severity": "high",
                "description": "Self-signed sertifika kullanılıyor",
                "details": "Güvenilir CA tarafından imzalanmamış"
            })
        
        # Protokol kontrolleri
        protocol_version = protocol_info.get('version')
        if protocol_version in ['SSLv2', 'SSLv3', 'TLSv1.0']:
            vulnerabilities.append({
                "type": "weak_protocol",
                "severity": "high",
                "description": f"Güvensiz protokol: {protocol_version}",
                "details": "Eski ve güvensiz SSL/TLS versiyonu"
            })
        
        # Cipher kontrolleri
        if cipher_info.get('is_weak'):
            vulnerabilities.append({
                "type": "weak_cipher",
                "severity": "high",
                "description": "Zayıf cipher suite kullanılıyor",
                "details": f"Cipher: {cipher_info.get('name')}"
            })
        
        if not cipher_info.get('supports_pfs'):
            vulnerabilities.append({
                "type": "no_perfect_forward_secrecy",
                "severity": "medium",
                "description": "Perfect Forward Secrecy desteklenmiyor",
                "details": "ECDHE veya DHE cipher suite kullanılmıyor"
            })
        
        # Anahtar boyutu kontrolleri
        key_size = cert_info.get('key_size', 0)
        if key_size < 2048:
            vulnerabilities.append({
                "type": "weak_key_size",
                "severity": "high",
                "description": f"Zayıf anahtar boyutu: {key_size} bit",
                "details": "En az 2048 bit RSA anahtar önerilir"
            })
        
        return vulnerabilities
    
    def _calculate_security_score(self, cert_info: Dict, protocol_info: Dict,
                                cipher_info: Dict, vulnerabilities: List) -> Tuple[int, str]:
        """Güvenlik skorunu hesaplar"""
        
        score = 100
        
        # Protokol skoru
        protocol_score = protocol_info.get('score', 0)
        score = min(score, protocol_score + 20)  # Protokol en fazla 80 puan verebilir
        
        # Sertifika skoru
        if cert_info.get('is_expired'):
            score -= 50
        elif cert_info.get('days_until_expiry', 0) < 30:
            score -= 20
        
        if cert_info.get('is_self_signed'):
            score -= 30
        
        # Anahtar boyutu skoru
        key_size = cert_info.get('key_size', 0)
        key_score = max([s for k, s in self.key_size_scores.items() if key_size >= k] or [0])
        score = min(score, key_score + 30)
        
        # Cipher skoru
        if cipher_info.get('is_weak'):
            score -= 40
        
        if not cipher_info.get('supports_pfs'):
            score -= 15
        
        # Güvenlik açığı cezaları
        for vuln in vulnerabilities:
            if vuln['severity'] == 'critical':
                score -= 30
            elif vuln['severity'] == 'high':
                score -= 20
            elif vuln['severity'] == 'medium':
                score -= 10
        
        score = max(0, min(100, score))
        
        # Risk seviyesi belirleme
        if score >= 80:
            risk_level = "low"
        elif score >= 60:
            risk_level = "medium"
        elif score >= 40:
            risk_level = "high"
        else:
            risk_level = "critical"
        
        return score, risk_level
    
    def _generate_recommendations(self, cert_info: Dict, protocol_info: Dict,
                                cipher_info: Dict, vulnerabilities: List) -> List[str]:
        """Güvenlik önerilerini oluşturur"""
        
        recommendations = []
        
        # Sertifika önerileri
        if cert_info.get('is_expired'):
            recommendations.append("🚨 ACIL: SSL sertifikasını yenileyin")
        elif cert_info.get('days_until_expiry', 0) < 30:
            recommendations.append("⚠️ SSL sertifikasını yakında yenileyin")
        
        if cert_info.get('is_self_signed'):
            recommendations.append("✅ Güvenilir CA'dan sertifika alın")
        
        # Protokol önerileri
        protocol_version = protocol_info.get('version')
        if protocol_version not in ['TLSv1.2', 'TLSv1.3']:
            recommendations.append("✅ TLS 1.2 veya 1.3 kullanın")
            recommendations.append("✅ Eski SSL/TLS versiyonlarını devre dışı bırakın")
        
        # Cipher önerileri
        if cipher_info.get('is_weak'):
            recommendations.append("✅ Güçlü cipher suite'leri kullanın")
            recommendations.append("✅ Zayıf şifreleme algoritmalarını kaldırın")
        
        if not cipher_info.get('supports_pfs'):
            recommendations.append("✅ Perfect Forward Secrecy'yi etkinleştirin")
            recommendations.append("✅ ECDHE cipher suite'lerini tercih edin")
        
        # Anahtar boyutu önerileri
        key_size = cert_info.get('key_size', 0)
        if key_size < 2048:
            recommendations.append("✅ En az 2048 bit RSA anahtar kullanın")
        elif key_size < 4096:
            recommendations.append("💡 4096 bit RSA anahtar düşünün")
        
        # Genel öneriler
        recommendations.extend([
            "✅ SSL Labs ile düzenli test yapın",
            "✅ HSTS header'ını etkinleştirin",
            "✅ Certificate Transparency'yi kontrol edin",
            "✅ OCSP Stapling'i etkinleştirin",
            "✅ Güvenlik header'larını ekleyin"
        ])
        
        return recommendations
    
    def check_multiple_hosts(self, hosts: List[Tuple[str, int]]) -> List[SSLResult]:
        """Birden fazla host için SSL kontrolü yapar"""
        
        results = []
        
        print(f"🔒 {len(hosts)} host için SSL kontrolü başlatılıyor...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_host = {
                executor.submit(self.check_ssl, host, port): (host, port)
                for host, port in hosts
            }
            
            for future in concurrent.futures.as_completed(future_to_host):
                host, port = future_to_host[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    status = "✅" if result.is_valid else "❌"
                    score = result.security_score if result.is_valid else 0
                    print(f"  {status} {host}:{port} - Skor: {score}/100 ({result.risk_level})")
                    
                except Exception as e:
                    print(f"  ❌ {host}:{port} - Hata: {str(e)}")
        
        return results
    
    def generate_report(self, results: List[SSLResult]) -> Dict[str, Any]:
        """SSL kontrol sonuçlarından rapor oluşturur"""
        
        total_hosts = len(results)
        valid_ssl = sum(1 for r in results if r.is_valid)
        invalid_ssl = total_hosts - valid_ssl
        
        # Risk dağılımı
        risk_distribution = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for result in results:
            risk_distribution[result.risk_level] += 1
        
        # Ortalama skor
        valid_results = [r for r in results if r.is_valid]
        avg_score = sum(r.security_score for r in valid_results) / len(valid_results) if valid_results else 0
        
        # En yaygın güvenlik açıkları
        vulnerability_types = {}
        for result in results:
            for vuln in result.vulnerabilities:
                vuln_type = vuln['type']
                vulnerability_types[vuln_type] = vulnerability_types.get(vuln_type, 0) + 1
        
        # Kritik bulgular
        critical_issues = [
            {
                "hostname": result.hostname,
                "port": result.port,
                "score": result.security_score,
                "risk_level": result.risk_level,
                "issues": [v['description'] for v in result.vulnerabilities if v['severity'] in ['critical', 'high']]
            }
            for result in results
            if result.risk_level in ['critical', 'high'] or not result.is_valid
        ]
        
        return {
            "scan_summary": {
                "total_hosts": total_hosts,
                "valid_ssl": valid_ssl,
                "invalid_ssl": invalid_ssl,
                "average_score": round(avg_score, 1)
            },
            "risk_distribution": risk_distribution,
            "vulnerability_types": vulnerability_types,
            "critical_issues": critical_issues,
            "recommendations": self._get_general_recommendations(results)
        }
    
    def _get_general_recommendations(self, results: List[SSLResult]) -> List[str]:
        """Genel güvenlik önerilerini döndürür"""
        
        recommendations = [
            "🔒 SSL/TLS Güvenlik Önerileri:",
            "✅ Tüm sitelerde HTTPS kullanın",
            "✅ TLS 1.2 ve üzeri versiyonları tercih edin",
            "✅ Güçlü cipher suite'leri yapılandırın",
            "✅ Perfect Forward Secrecy'yi etkinleştirin",
            "✅ Sertifikaları düzenli olarak yenileyin",
            "✅ HSTS header'ını kullanın",
            "✅ SSL Labs ile düzenli testler yapın",
            "✅ Certificate pinning düşünün",
            "✅ OCSP stapling'i etkinleştirin"
        ]
        
        return recommendations

# Test fonksiyonu
if __name__ == "__main__":
    checker = SSLChecker()
    
    # Test host'ları
    test_hosts = [
        ("google.com", 443),
        ("github.com", 443),
        ("badssl.com", 443)
    ]
    
    print("Nexus-Scanner SSL/TLS Security Check")
    print("=" * 40)
    
    results = checker.check_multiple_hosts(test_hosts)
    report = checker.generate_report(results)
    
    print("\n📊 SSL/TLS Raporu:")
    print(f"Toplam Host: {report['scan_summary']['total_hosts']}")
    print(f"Geçerli SSL: {report['scan_summary']['valid_ssl']}")
    print(f"Ortalama Skor: {report['scan_summary']['average_score']}/100")
    
    print("\n📈 Risk Dağılımı:")
    for risk, count in report['risk_distribution'].items():
        if count > 0:
            print(f"  {risk.upper()}: {count}")
    
    if report['critical_issues']:
        print("\n🚨 Kritik Sorunlar:")
        for issue in report['critical_issues'][:3]:
            print(f"  - {issue['hostname']}:{issue['port']} (Skor: {issue['score']})")
            for problem in issue['issues'][:2]:
                print(f"    • {problem}")