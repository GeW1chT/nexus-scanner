#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nexus-Scanner JSON Report Generator
Profesyonel siber güvenlik aracı - JSON rapor oluşturucu

Bu modül tarama sonuçlarından yapılandırılmış JSON raporları oluşturur.
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
import uuid

@dataclass
class JSONReportData:
    """JSON rapor verilerini tutan sınıf"""
    scan_id: str
    target_name: str
    target_url: str
    scan_type: str
    scan_status: str
    started_at: str
    completed_at: str
    duration: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    findings: List[Dict[str, Any]]
    scan_config: Dict[str, Any]
    metadata: Dict[str, Any]

class JSONReportGenerator:
    """JSON rapor oluşturucu sınıfı"""
    
    def __init__(self):
        """
        JSON rapor oluşturucuyu başlatır
        """
        self.version = "1.0.0"
        self.generator_info = {
            "name": "Nexus-Scanner JSON Generator",
            "version": self.version,
            "description": "Profesyonel siber güvenlik aracı JSON rapor oluşturucu"
        }
    
    def _format_datetime(self, dt) -> str:
        """Tarih formatı (ISO 8601)"""
        if isinstance(dt, str):
            return dt
        elif isinstance(dt, datetime):
            return dt.isoformat()
        else:
            return datetime.now().isoformat()
    
    def _calculate_risk_score(self, findings: List[Dict[str, Any]]) -> float:
        """Risk skorunu hesaplar"""
        if not findings:
            return 0.0
        
        risk_weights = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 1.0
        }
        
        total_score = 0.0
        for finding in findings:
            risk_level = finding.get('risk_level', 'info').lower()
            severity_score = finding.get('severity_score', 0)
            
            # Risk seviyesi ve severity score'u birleştir
            base_score = risk_weights.get(risk_level, 1.0)
            if severity_score > 0:
                total_score += (base_score * severity_score) / 10
            else:
                total_score += base_score
        
        # 0-100 arası normalize et
        max_possible_score = len(findings) * 10.0
        normalized_score = min((total_score / max_possible_score) * 100, 100.0)
        
        return round(normalized_score, 2)
    
    def _get_risk_distribution(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Risk dağılımını hesaplar"""
        distribution = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for finding in findings:
            risk_level = finding.get('risk_level', 'info').lower()
            if risk_level in distribution:
                distribution[risk_level] += 1
        
        total = sum(distribution.values())
        
        # Yüzdelik dağılım ekle
        percentages = {}
        for risk, count in distribution.items():
            percentages[f"{risk}_percentage"] = round((count / max(total, 1)) * 100, 1)
        
        return {**distribution, **percentages, 'total': total}
    
    def _get_vulnerability_types(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Zafiyet türlerini sayar"""
        vuln_types = {}
        
        for finding in findings:
            vuln_type = finding.get('vulnerability_type', 'Unknown')
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        # En yaygın 10 zafiyet türünü döndür
        return dict(sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)[:10])
    
    def _get_affected_components(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Etkilenen bileşenleri analiz eder"""
        urls = set()
        parameters = set()
        methods = set()
        
        for finding in findings:
            if finding.get('affected_url'):
                urls.add(finding['affected_url'])
            if finding.get('affected_parameter'):
                parameters.add(finding['affected_parameter'])
            if finding.get('method'):
                methods.add(finding['method'])
        
        return {
            'unique_urls': len(urls),
            'unique_parameters': len(parameters),
            'http_methods': list(methods),
            'affected_urls': list(urls)[:20],  # İlk 20 URL
            'affected_parameters': list(parameters)[:20]  # İlk 20 parametre
        }
    
    def _generate_recommendations(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Bulgulara dayalı öneriler oluşturur"""
        recommendations = []
        
        # Risk seviyesine göre genel öneriler
        risk_counts = self._get_risk_distribution(findings)
        
        if risk_counts['critical'] > 0:
            recommendations.append({
                'priority': 'critical',
                'category': 'immediate_action',
                'title': 'Kritik Güvenlik Açıklarını Derhal Giderin',
                'description': f"{risk_counts['critical']} adet kritik güvenlik açığı tespit edildi. Bu açıklar derhal giderilmelidir.",
                'estimated_effort': 'high',
                'timeline': 'immediate'
            })
        
        if risk_counts['high'] > 0:
            recommendations.append({
                'priority': 'high',
                'category': 'security_hardening',
                'title': 'Yüksek Risk Seviyeli Açıkları Giderin',
                'description': f"{risk_counts['high']} adet yüksek risk seviyeli açık bulundu. 1-2 hafta içinde giderilmelidir.",
                'estimated_effort': 'medium',
                'timeline': '1-2 weeks'
            })
        
        # Zafiyet türüne göre özel öneriler
        vuln_types = self._get_vulnerability_types(findings)
        
        if 'SQL Injection' in vuln_types:
            recommendations.append({
                'priority': 'high',
                'category': 'code_security',
                'title': 'SQL Injection Koruması Uygulayın',
                'description': 'Parametreli sorgular kullanın ve kullanıcı girdilerini validate edin.',
                'estimated_effort': 'medium',
                'timeline': '1 week'
            })
        
        if 'Cross-Site Scripting' in vuln_types:
            recommendations.append({
                'priority': 'high',
                'category': 'web_security',
                'title': 'XSS Koruması Ekleyin',
                'description': 'Kullanıcı girdilerini encode edin ve CSP header kullanın.',
                'estimated_effort': 'medium',
                'timeline': '1 week'
            })
        
        # Genel güvenlik önerileri
        recommendations.extend([
            {
                'priority': 'medium',
                'category': 'monitoring',
                'title': 'Düzenli Güvenlik Taramaları',
                'description': 'Aylık otomatik güvenlik taramaları planlayın.',
                'estimated_effort': 'low',
                'timeline': 'ongoing'
            },
            {
                'priority': 'medium',
                'category': 'maintenance',
                'title': 'Sistem Güncellemeleri',
                'description': 'Tüm sistem bileşenlerini güncel tutun.',
                'estimated_effort': 'low',
                'timeline': 'ongoing'
            }
        ])
        
        return recommendations
    
    def _generate_executive_summary(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Yönetici özeti oluşturur"""
        findings = report_data.get('findings', [])
        risk_score = self._calculate_risk_score(findings)
        
        # Risk seviyesi belirleme
        if risk_score >= 80:
            risk_level = 'critical'
            risk_description = 'Kritik güvenlik riskleri tespit edildi'
        elif risk_score >= 60:
            risk_level = 'high'
            risk_description = 'Yüksek güvenlik riskleri mevcut'
        elif risk_score >= 40:
            risk_level = 'medium'
            risk_description = 'Orta seviye güvenlik riskleri bulundu'
        elif risk_score >= 20:
            risk_level = 'low'
            risk_description = 'Düşük seviye güvenlik riskleri tespit edildi'
        else:
            risk_level = 'minimal'
            risk_description = 'Minimal güvenlik riski'
        
        return {
            'overall_risk_score': risk_score,
            'overall_risk_level': risk_level,
            'risk_description': risk_description,
            'total_findings': len(findings),
            'scan_duration_minutes': round(report_data.get('duration', 0) / 60, 2),
            'scan_efficiency': 'high' if len(findings) > 0 else 'normal',
            'key_concerns': self._get_key_concerns(findings),
            'immediate_actions_required': self._get_immediate_actions(findings)
        }
    
    def _get_key_concerns(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Ana endişeleri listeler"""
        concerns = []
        
        critical_findings = [f for f in findings if f.get('risk_level', '').lower() == 'critical']
        high_findings = [f for f in findings if f.get('risk_level', '').lower() == 'high']
        
        if critical_findings:
            concerns.append(f"{len(critical_findings)} kritik güvenlik açığı")
        
        if high_findings:
            concerns.append(f"{len(high_findings)} yüksek risk seviyeli açık")
        
        # En yaygın zafiyet türleri
        vuln_types = self._get_vulnerability_types(findings)
        top_vulns = list(vuln_types.keys())[:3]
        
        for vuln in top_vulns:
            if vuln_types[vuln] > 1:
                concerns.append(f"Çoklu {vuln} zafiyetleri")
        
        return concerns[:5]  # En fazla 5 endişe
    
    def _get_immediate_actions(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Acil eylemler listesi"""
        actions = []
        
        critical_findings = [f for f in findings if f.get('risk_level', '').lower() == 'critical']
        
        if critical_findings:
            actions.append("Kritik güvenlik açıklarını derhal giderin")
        
        # SQL Injection kontrolü
        sql_findings = [f for f in findings if 'sql' in f.get('vulnerability_type', '').lower()]
        if sql_findings:
            actions.append("SQL Injection koruması uygulayın")
        
        # XSS kontrolü
        xss_findings = [f for f in findings if 'xss' in f.get('vulnerability_type', '').lower() or 'cross-site' in f.get('vulnerability_type', '').lower()]
        if xss_findings:
            actions.append("XSS koruması ekleyin")
        
        if not actions:
            actions.append("Düzenli güvenlik taramaları planlayın")
        
        return actions[:5]  # En fazla 5 eylem
    
    def generate_report(self, scan_data: Dict[str, Any], output_path: str, 
                      include_raw_data: bool = False, 
                      compress_output: bool = False) -> bool:
        """JSON raporu oluşturur"""
        try:
            # Çıktı dizinini oluştur
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            findings = scan_data.get('findings', [])
            
            # Ana rapor yapısı
            report = {
                'report_metadata': {
                    'report_id': str(uuid.uuid4()),
                    'generated_at': self._format_datetime(datetime.now()),
                    'generator': self.generator_info,
                    'report_version': '1.0',
                    'report_type': 'security_scan'
                },
                
                'scan_information': {
                    'scan_id': scan_data.get('scan_id', 'N/A'),
                    'target_name': scan_data.get('target_name', 'Unknown Target'),
                    'target_url': scan_data.get('target_url', ''),
                    'scan_type': scan_data.get('scan_type', 'General Scan'),
                    'scan_status': scan_data.get('scan_status', 'completed'),
                    'started_at': self._format_datetime(scan_data.get('started_at')),
                    'completed_at': self._format_datetime(scan_data.get('completed_at')),
                    'duration_seconds': scan_data.get('duration', 0),
                    'scan_config': scan_data.get('scan_config', {})
                },
                
                'executive_summary': self._generate_executive_summary(scan_data),
                
                'risk_analysis': {
                    'overall_risk_score': self._calculate_risk_score(findings),
                    'risk_distribution': self._get_risk_distribution(findings),
                    'vulnerability_types': self._get_vulnerability_types(findings),
                    'affected_components': self._get_affected_components(findings)
                },
                
                'findings': {
                    'total_count': len(findings),
                    'summary': {
                        'critical': len([f for f in findings if f.get('risk_level', '').lower() == 'critical']),
                        'high': len([f for f in findings if f.get('risk_level', '').lower() == 'high']),
                        'medium': len([f for f in findings if f.get('risk_level', '').lower() == 'medium']),
                        'low': len([f for f in findings if f.get('risk_level', '').lower() == 'low']),
                        'info': len([f for f in findings if f.get('risk_level', '').lower() == 'info'])
                    },
                    'details': findings
                },
                
                'recommendations': self._generate_recommendations(findings),
                
                'compliance': {
                    'owasp_top_10_coverage': self._check_owasp_coverage(findings),
                    'security_standards': {
                        'iso_27001': 'partial',
                        'nist_framework': 'partial',
                        'pci_dss': 'not_assessed'
                    }
                }
            }
            
            # Ham veri ekleme (opsiyonel)
            if include_raw_data:
                report['raw_scan_data'] = scan_data
            
            # JSON'u dosyaya yaz
            with open(output_path, 'w', encoding='utf-8') as f:
                if compress_output:
                    json.dump(report, f, ensure_ascii=False, separators=(',', ':'))
                else:
                    json.dump(report, f, ensure_ascii=False, indent=2)
            
            return True
            
        except Exception as e:
            print(f"❌ JSON rapor oluşturma hatası: {str(e)}")
            return False
    
    def _check_owasp_coverage(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """OWASP Top 10 kapsamını kontrol eder"""
        owasp_mapping = {
            'A01:2021 – Broken Access Control': ['access_control', 'authorization'],
            'A02:2021 – Cryptographic Failures': ['crypto', 'encryption', 'ssl', 'tls'],
            'A03:2021 – Injection': ['sql_injection', 'command_injection', 'ldap_injection'],
            'A04:2021 – Insecure Design': ['design_flaw'],
            'A05:2021 – Security Misconfiguration': ['misconfiguration', 'default_credentials'],
            'A06:2021 – Vulnerable Components': ['outdated_component', 'vulnerable_library'],
            'A07:2021 – Authentication Failures': ['weak_authentication', 'session_management'],
            'A08:2021 – Software Integrity Failures': ['integrity'],
            'A09:2021 – Logging Failures': ['logging', 'monitoring'],
            'A10:2021 – Server-Side Request Forgery': ['ssrf']
        }
        
        coverage = {}
        
        for owasp_item, keywords in owasp_mapping.items():
            found_vulns = []
            for finding in findings:
                vuln_type = finding.get('vulnerability_type', '').lower()
                title = finding.get('title', '').lower()
                
                for keyword in keywords:
                    if keyword in vuln_type or keyword in title:
                        found_vulns.append(finding.get('title', 'Unknown'))
                        break
            
            coverage[owasp_item] = {
                'covered': len(found_vulns) > 0,
                'finding_count': len(found_vulns),
                'findings': found_vulns[:3]  # İlk 3 bulgu
            }
        
        total_covered = sum(1 for item in coverage.values() if item['covered'])
        coverage_percentage = (total_covered / len(owasp_mapping)) * 100
        
        return {
            'coverage_percentage': round(coverage_percentage, 1),
            'covered_categories': total_covered,
            'total_categories': len(owasp_mapping),
            'details': coverage
        }
    
    def validate_report(self, report_path: str) -> Dict[str, Any]:
        """Rapor dosyasını doğrular"""
        try:
            with open(report_path, 'r', encoding='utf-8') as f:
                report = json.load(f)
            
            # Temel alanları kontrol et
            required_fields = [
                'report_metadata',
                'scan_information', 
                'executive_summary',
                'risk_analysis',
                'findings',
                'recommendations'
            ]
            
            missing_fields = []
            for field in required_fields:
                if field not in report:
                    missing_fields.append(field)
            
            # Dosya boyutu
            file_size = os.path.getsize(report_path)
            
            return {
                'valid': len(missing_fields) == 0,
                'missing_fields': missing_fields,
                'file_size_bytes': file_size,
                'findings_count': len(report.get('findings', {}).get('details', [])),
                'report_id': report.get('report_metadata', {}).get('report_id'),
                'generated_at': report.get('report_metadata', {}).get('generated_at')
            }
            
        except Exception as e:
            return {
                'valid': False,
                'error': str(e),
                'file_exists': os.path.exists(report_path)
            }

# Test fonksiyonu
if __name__ == "__main__":
    print("Nexus-Scanner JSON Report Generator Test")
    print("=" * 50)
    
    # Test verisi oluştur
    test_data = {
        'scan_id': 'SCAN_20240115_002',
        'target_name': 'Test Web Application',
        'target_url': 'https://testphp.vulnweb.com',
        'scan_type': 'Comprehensive Web Security Scan',
        'scan_status': 'completed',
        'started_at': datetime.now().replace(hour=14, minute=30, second=0),
        'completed_at': datetime.now(),
        'duration': 2400,  # 40 dakika
        'findings': [
            {
                'id': 'FIND_001',
                'title': 'SQL Injection in Login Form',
                'description': 'The login form is vulnerable to SQL injection attacks.',
                'risk_level': 'critical',
                'vulnerability_type': 'SQL Injection',
                'affected_url': 'https://testphp.vulnweb.com/login.php',
                'affected_parameter': 'username',
                'method': 'POST',
                'payload': "admin' OR '1'='1' --",
                'evidence': 'MySQL error message revealed in response',
                'recommendation': 'Use parameterized queries and input validation.',
                'confidence': 'high',
                'severity_score': 9.8,
                'cwe_id': 'CWE-89',
                'owasp_category': 'A03:2021 – Injection'
            },
            {
                'id': 'FIND_002',
                'title': 'Reflected XSS in Search Function',
                'description': 'User input is reflected without proper encoding.',
                'risk_level': 'high',
                'vulnerability_type': 'Cross-Site Scripting',
                'affected_url': 'https://testphp.vulnweb.com/search.php',
                'affected_parameter': 'searchFor',
                'method': 'GET',
                'payload': '<script>alert("XSS")</script>',
                'evidence': 'Script executed in browser context',
                'recommendation': 'Implement proper output encoding and CSP headers.',
                'confidence': 'high',
                'severity_score': 7.2,
                'cwe_id': 'CWE-79',
                'owasp_category': 'A03:2021 – Injection'
            },
            {
                'id': 'FIND_003',
                'title': 'Weak SSL/TLS Configuration',
                'description': 'Server supports weak cipher suites.',
                'risk_level': 'medium',
                'vulnerability_type': 'SSL/TLS Misconfiguration',
                'affected_url': 'https://testphp.vulnweb.com',
                'method': 'N/A',
                'evidence': 'TLSv1.0 and weak ciphers detected',
                'recommendation': 'Disable weak protocols and cipher suites.',
                'confidence': 'medium',
                'severity_score': 5.5,
                'cwe_id': 'CWE-326'
            }
        ],
        'scan_config': {
            'timeout': 30,
            'threads': 10,
            'user_agent': 'Nexus-Scanner/1.0',
            'follow_redirects': True,
            'max_depth': 3
        }
    }
    
    # JSON generator oluştur
    generator = JSONReportGenerator()
    
    # Test raporları oluştur
    output_dir = os.path.dirname(__file__)
    
    # Normal JSON raporu
    normal_path = os.path.join(output_dir, 'test_report.json')
    if generator.generate_report(test_data, normal_path):
        print(f"✅ Normal JSON raporu oluşturuldu: {normal_path}")
        
        # Raporu doğrula
        validation = generator.validate_report(normal_path)
        print(f"📋 Rapor doğrulama: {'✅ Geçerli' if validation['valid'] else '❌ Geçersiz'}")
        print(f"📄 Dosya boyutu: {validation.get('file_size_bytes', 0)} bytes")
        print(f"🔍 Bulgu sayısı: {validation.get('findings_count', 0)}")
    
    # Sıkıştırılmış JSON raporu
    compressed_path = os.path.join(output_dir, 'test_report_compressed.json')
    if generator.generate_report(test_data, compressed_path, compress_output=True):
        print(f"✅ Sıkıştırılmış JSON raporu oluşturuldu: {compressed_path}")
    
    # Ham veri içeren rapor
    raw_data_path = os.path.join(output_dir, 'test_report_with_raw.json')
    if generator.generate_report(test_data, raw_data_path, include_raw_data=True):
        print(f"✅ Ham veri içeren JSON raporu oluşturuldu: {raw_data_path}")
    
    print("\n📊 Test tamamlandı!")