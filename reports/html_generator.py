#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nexus-Scanner HTML Report Generator
Profesyonel siber güvenlik aracı - HTML rapor oluşturucu

Bu modül tarama sonuçlarından profesyonel HTML raporları oluşturur.
"""

import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from jinja2 import Template, Environment, FileSystemLoader
import base64
from dataclasses import dataclass

@dataclass
class ReportData:
    """Rapor verilerini tutan sınıf"""
    scan_id: str
    target_name: str
    target_url: str
    scan_type: str
    scan_status: str
    started_at: datetime
    completed_at: datetime
    duration: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    findings: List[Dict[str, Any]]
    scan_config: Dict[str, Any]
    
class HTMLReportGenerator:
    """HTML rapor oluşturucu sınıfı"""
    
    def __init__(self, template_dir: str = None):
        """
        HTML rapor oluşturucuyu başlatır
        
        Args:
            template_dir: Template dosyalarının bulunduğu dizin
        """
        if template_dir is None:
            template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        
        self.template_dir = template_dir
        os.makedirs(template_dir, exist_ok=True)
        
        # Jinja2 environment oluştur
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=True
        )
        
        # Custom filters ekle
        self.env.filters['format_datetime'] = self._format_datetime
        self.env.filters['format_duration'] = self._format_duration
        self.env.filters['risk_color'] = self._get_risk_color
        self.env.filters['risk_icon'] = self._get_risk_icon
        self.env.filters['truncate_text'] = self._truncate_text
        
        # Template'leri oluştur
        self._create_templates()
    
    def _format_datetime(self, dt: datetime) -> str:
        """Tarih formatı"""
        if isinstance(dt, str):
            try:
                dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
            except:
                return dt
        return dt.strftime('%d.%m.%Y %H:%M:%S') if dt else 'N/A'
    
    def _format_duration(self, seconds: int) -> str:
        """Süre formatı"""
        if not seconds:
            return '0 saniye'
        
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        
        if hours > 0:
            return f"{hours}s {minutes}d {secs}sn"
        elif minutes > 0:
            return f"{minutes}d {secs}sn"
        else:
            return f"{secs}sn"
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Risk seviyesi rengi"""
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745',
            'info': '#17a2b8'
        }
        return colors.get(risk_level.lower(), '#6c757d')
    
    def _get_risk_icon(self, risk_level: str) -> str:
        """Risk seviyesi ikonu"""
        icons = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢',
            'info': '🔵'
        }
        return icons.get(risk_level.lower(), '⚪')
    
    def _truncate_text(self, text: str, length: int = 100) -> str:
        """Metni kısaltır"""
        if not text or len(text) <= length:
            return text
        return text[:length] + '...'
    
    def _create_templates(self):
        """Template dosyalarını oluşturur"""
        # Ana template
        main_template = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nexus-Scanner Güvenlik Raporu - {{ report_data.target_name }}</title>
    <style>
        {{ css_content }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="report-header">
            <div class="header-content">
                <div class="logo">
                    <h1>🛡️ Nexus-Scanner</h1>
                    <p>Profesyonel Siber Güvenlik Raporu</p>
                </div>
                <div class="report-info">
                    <p><strong>Rapor Tarihi:</strong> {{ now|format_datetime }}</p>
                    <p><strong>Rapor ID:</strong> {{ report_data.scan_id }}</p>
                </div>
            </div>
        </header>

        <!-- Executive Summary -->
        <section class="executive-summary">
            <h2>📊 Yönetici Özeti</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Hedef Bilgileri</h3>
                    <p><strong>Hedef:</strong> {{ report_data.target_name }}</p>
                    <p><strong>URL:</strong> {{ report_data.target_url }}</p>
                    <p><strong>Tarama Türü:</strong> {{ report_data.scan_type }}</p>
                </div>
                <div class="summary-card">
                    <h3>Tarama Bilgileri</h3>
                    <p><strong>Başlangıç:</strong> {{ report_data.started_at|format_datetime }}</p>
                    <p><strong>Bitiş:</strong> {{ report_data.completed_at|format_datetime }}</p>
                    <p><strong>Süre:</strong> {{ report_data.duration|format_duration }}</p>
                </div>
            </div>
        </section>

        <!-- Risk Overview -->
        <section class="risk-overview">
            <h2>🎯 Risk Genel Bakış</h2>
            <div class="risk-stats">
                <div class="risk-card critical">
                    <div class="risk-number">{{ report_data.critical_findings }}</div>
                    <div class="risk-label">Kritik</div>
                </div>
                <div class="risk-card high">
                    <div class="risk-number">{{ report_data.high_findings }}</div>
                    <div class="risk-label">Yüksek</div>
                </div>
                <div class="risk-card medium">
                    <div class="risk-number">{{ report_data.medium_findings }}</div>
                    <div class="risk-label">Orta</div>
                </div>
                <div class="risk-card low">
                    <div class="risk-number">{{ report_data.low_findings }}</div>
                    <div class="risk-label">Düşük</div>
                </div>
                <div class="risk-card info">
                    <div class="risk-number">{{ report_data.info_findings }}</div>
                    <div class="risk-label">Bilgi</div>
                </div>
            </div>
            
            <div class="total-findings">
                <h3>Toplam Bulgular: {{ report_data.total_findings }}</h3>
            </div>
        </section>

        <!-- Findings Details -->
        <section class="findings-details">
            <h2>🔍 Detaylı Bulgular</h2>
            
            {% if report_data.findings %}
                {% for finding in report_data.findings %}
                <div class="finding-card {{ finding.risk_level|lower }}">
                    <div class="finding-header">
                        <span class="risk-badge {{ finding.risk_level|lower }}">
                            {{ finding.risk_level|risk_icon }} {{ finding.risk_level|upper }}
                        </span>
                        <h3>{{ finding.title }}</h3>
                    </div>
                    
                    <div class="finding-content">
                        <div class="finding-info">
                            <p><strong>Açıklama:</strong> {{ finding.description }}</p>
                            
                            {% if finding.affected_url %}
                            <p><strong>Etkilenen URL:</strong> <code>{{ finding.affected_url }}</code></p>
                            {% endif %}
                            
                            {% if finding.affected_parameter %}
                            <p><strong>Etkilenen Parametre:</strong> <code>{{ finding.affected_parameter }}</code></p>
                            {% endif %}
                            
                            {% if finding.payload %}
                            <p><strong>Payload:</strong> <code>{{ finding.payload|truncate_text(200) }}</code></p>
                            {% endif %}
                            
                            {% if finding.evidence %}
                            <div class="evidence">
                                <strong>Kanıt:</strong>
                                <pre><code>{{ finding.evidence|truncate_text(500) }}</code></pre>
                            </div>
                            {% endif %}
                            
                            {% if finding.recommendation %}
                            <div class="recommendation">
                                <strong>💡 Çözüm Önerisi:</strong>
                                <p>{{ finding.recommendation }}</p>
                            </div>
                            {% endif %}
                        </div>
                        
                        <div class="finding-meta">
                            <p><strong>Güven Seviyesi:</strong> {{ finding.confidence|title }}</p>
                            <p><strong>Severity Score:</strong> {{ "%.1f"|format(finding.severity_score) }}</p>
                            <p><strong>Zafiyet Türü:</strong> {{ finding.vulnerability_type }}</p>
                        </div>
                    </div>
                </div>
                {% endfor %}
            {% else %}
                <div class="no-findings">
                    <p>✅ Bu taramada herhangi bir güvenlik açığı tespit edilmedi.</p>
                </div>
            {% endif %}
        </section>

        <!-- Recommendations -->
        <section class="recommendations">
            <h2>💡 Genel Öneriler</h2>
            <div class="recommendation-list">
                <ul>
                    <li>Tüm kritik ve yüksek risk seviyeli güvenlik açıklarını öncelikli olarak giderin</li>
                    <li>Düzenli güvenlik taramaları yapın (en az ayda bir)</li>
                    <li>Sistem ve uygulamalarınızı güncel tutun</li>
                    <li>Güvenlik politikalarınızı gözden geçirin</li>
                    <li>Personel güvenlik eğitimlerini düzenleyin</li>
                    <li>Güvenlik izleme ve log analizi sistemleri kurun</li>
                </ul>
            </div>
        </section>

        <!-- Footer -->
        <footer class="report-footer">
            <div class="footer-content">
                <p>Bu rapor Nexus-Scanner v1.0.0 tarafından otomatik olarak oluşturulmuştur.</p>
                <p>Rapor Tarihi: {{ now|format_datetime }}</p>
                <p>© 2024 Nexus-Scanner - Profesyonel Siber Güvenlik Aracı</p>
            </div>
        </footer>
    </div>
</body>
</html>
        """
        
        # CSS stilleri
        css_content = """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f8f9fa;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        /* Header */
        .report-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo h1 {
            font-size: 2.5em;
            margin-bottom: 5px;
        }
        
        .logo p {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .report-info {
            text-align: right;
        }
        
        /* Sections */
        section {
            background: white;
            margin-bottom: 30px;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        
        /* Executive Summary */
        .summary-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        
        .summary-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }
        
        .summary-card h3 {
            color: #2c3e50;
            margin-bottom: 15px;
        }
        
        /* Risk Overview */
        .risk-stats {
            display: flex;
            justify-content: space-around;
            margin-bottom: 30px;
            flex-wrap: wrap;
            gap: 15px;
        }
        
        .risk-card {
            text-align: center;
            padding: 20px;
            border-radius: 10px;
            color: white;
            min-width: 120px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .risk-card.critical { background-color: #dc3545; }
        .risk-card.high { background-color: #fd7e14; }
        .risk-card.medium { background-color: #ffc107; color: #333; }
        .risk-card.low { background-color: #28a745; }
        .risk-card.info { background-color: #17a2b8; }
        
        .risk-number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .risk-label {
            font-size: 1.1em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .total-findings {
            text-align: center;
            padding: 20px;
            background: #e9ecef;
            border-radius: 8px;
        }
        
        /* Findings */
        .finding-card {
            border: 1px solid #dee2e6;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        
        .finding-card.critical { border-left: 5px solid #dc3545; }
        .finding-card.high { border-left: 5px solid #fd7e14; }
        .finding-card.medium { border-left: 5px solid #ffc107; }
        .finding-card.low { border-left: 5px solid #28a745; }
        .finding-card.info { border-left: 5px solid #17a2b8; }
        
        .finding-header {
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 1px solid #dee2e6;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .risk-badge {
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .risk-badge.critical { background-color: #dc3545; color: white; }
        .risk-badge.high { background-color: #fd7e14; color: white; }
        .risk-badge.medium { background-color: #ffc107; color: #333; }
        .risk-badge.low { background-color: #28a745; color: white; }
        .risk-badge.info { background-color: #17a2b8; color: white; }
        
        .finding-content {
            padding: 20px;
        }
        
        .finding-info {
            margin-bottom: 20px;
        }
        
        .finding-info p {
            margin-bottom: 10px;
        }
        
        .evidence {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
        }
        
        .evidence pre {
            background: #343a40;
            color: #f8f9fa;
            padding: 10px;
            border-radius: 3px;
            overflow-x: auto;
            font-size: 0.9em;
        }
        
        .recommendation {
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
        }
        
        .finding-meta {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            border-top: 1px solid #dee2e6;
        }
        
        code {
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        
        .no-findings {
            text-align: center;
            padding: 40px;
            background: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 8px;
            color: #155724;
        }
        
        /* Recommendations */
        .recommendation-list ul {
            list-style: none;
        }
        
        .recommendation-list li {
            padding: 10px 0;
            border-bottom: 1px solid #eee;
            position: relative;
            padding-left: 30px;
        }
        
        .recommendation-list li:before {
            content: '✓';
            position: absolute;
            left: 0;
            color: #28a745;
            font-weight: bold;
        }
        
        /* Footer */
        .report-footer {
            background: #343a40;
            color: white;
            text-align: center;
            padding: 20px;
            border-radius: 10px;
            margin-top: 30px;
        }
        
        .footer-content p {
            margin-bottom: 5px;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .header-content {
                flex-direction: column;
                text-align: center;
                gap: 20px;
            }
            
            .summary-grid {
                grid-template-columns: 1fr;
            }
            
            .risk-stats {
                flex-direction: column;
                align-items: center;
            }
            
            .finding-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
        }
        
        @page {
            margin: 1cm;
        }
        
        @media print {
            body {
                background: white;
            }
            
            .container {
                max-width: none;
                padding: 0;
            }
            
            section {
                box-shadow: none;
                border: 1px solid #ddd;
            }
        }
        """
        
        # Template dosyasını oluştur
        template_path = os.path.join(self.template_dir, 'report_template.html')
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(main_template)
        
        # CSS dosyasını oluştur
        css_path = os.path.join(self.template_dir, 'report_styles.css')
        with open(css_path, 'w', encoding='utf-8') as f:
            f.write(css_content)
    
    def generate_report(self, report_data: ReportData, output_path: str) -> bool:
        """HTML raporu oluşturur"""
        try:
            # Template'i yükle
            template = self.env.get_template('report_template.html')
            
            # CSS içeriğini oku
            css_path = os.path.join(self.template_dir, 'report_styles.css')
            with open(css_path, 'r', encoding='utf-8') as f:
                css_content = f.read()
            
            # Template'i render et
            html_content = template.render(
                report_data=report_data,
                css_content=css_content,
                now=datetime.now()
            )
            
            # Çıktı dizinini oluştur
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # HTML dosyasını kaydet
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return True
            
        except Exception as e:
            print(f"❌ HTML rapor oluşturma hatası: {str(e)}")
            return False
    
    def generate_from_scan_data(self, scan_data: Dict[str, Any], output_path: str) -> bool:
        """Tarama verisinden HTML raporu oluşturur"""
        try:
            # Scan data'yı ReportData'ya çevir
            report_data = ReportData(
                scan_id=scan_data.get('scan_id', 'N/A'),
                target_name=scan_data.get('target_name', 'Bilinmeyen Hedef'),
                target_url=scan_data.get('target_url', ''),
                scan_type=scan_data.get('scan_type', 'Genel Tarama'),
                scan_status=scan_data.get('scan_status', 'completed'),
                started_at=scan_data.get('started_at', datetime.now()),
                completed_at=scan_data.get('completed_at', datetime.now()),
                duration=scan_data.get('duration', 0),
                total_findings=scan_data.get('total_findings', 0),
                critical_findings=scan_data.get('critical_findings', 0),
                high_findings=scan_data.get('high_findings', 0),
                medium_findings=scan_data.get('medium_findings', 0),
                low_findings=scan_data.get('low_findings', 0),
                info_findings=scan_data.get('info_findings', 0),
                findings=scan_data.get('findings', []),
                scan_config=scan_data.get('scan_config', {})
            )
            
            return self.generate_report(report_data, output_path)
            
        except Exception as e:
            print(f"❌ Scan data'dan HTML rapor oluşturma hatası: {str(e)}")
            return False

# Test fonksiyonu
if __name__ == "__main__":
    print("Nexus-Scanner HTML Report Generator Test")
    print("=" * 50)
    
    # Test verisi oluştur
    test_data = {
        'scan_id': 'SCAN_20240115_001',
        'target_name': 'Test Web Sitesi',
        'target_url': 'https://testphp.vulnweb.com',
        'scan_type': 'Web Güvenlik Taraması',
        'scan_status': 'completed',
        'started_at': datetime.now().replace(hour=10, minute=0, second=0),
        'completed_at': datetime.now(),
        'duration': 1800,  # 30 dakika
        'total_findings': 5,
        'critical_findings': 1,
        'high_findings': 2,
        'medium_findings': 1,
        'low_findings': 1,
        'info_findings': 0,
        'findings': [
            {
                'title': 'SQL Injection Zafiyeti',
                'description': 'Kullanıcı girdilerinin yeterince filtrelenmemesi nedeniyle SQL injection saldırısı mümkün.',
                'risk_level': 'critical',
                'vulnerability_type': 'SQL Injection',
                'affected_url': 'https://testphp.vulnweb.com/artists.php?artist=1',
                'affected_parameter': 'artist',
                'payload': "1' OR '1'='1",
                'evidence': 'MySQL error: You have an error in your SQL syntax',
                'recommendation': 'Parametreli sorgular (prepared statements) kullanın ve kullanıcı girdilerini validate edin.',
                'confidence': 'high',
                'severity_score': 9.8
            },
            {
                'title': 'Cross-Site Scripting (XSS)',
                'description': 'Kullanıcı girdilerinin encode edilmemesi nedeniyle XSS saldırısı mümkün.',
                'risk_level': 'high',
                'vulnerability_type': 'Cross-Site Scripting',
                'affected_url': 'https://testphp.vulnweb.com/search.php',
                'affected_parameter': 'searchFor',
                'payload': '<script>alert("XSS")</script>',
                'evidence': 'Script tag reflected in response without encoding',
                'recommendation': 'Tüm kullanıcı girdilerini HTML encode edin ve CSP header kullanın.',
                'confidence': 'high',
                'severity_score': 7.5
            }
        ],
        'scan_config': {
            'timeout': 30,
            'threads': 10,
            'user_agent': 'Nexus-Scanner/1.0'
        }
    }
    
    # HTML generator oluştur
    generator = HTMLReportGenerator()
    
    # Test raporu oluştur
    output_path = os.path.join(os.path.dirname(__file__), 'test_report.html')
    
    if generator.generate_from_scan_data(test_data, output_path):
        print(f"✅ Test raporu oluşturuldu: {output_path}")
        print(f"📄 Rapor boyutu: {os.path.getsize(output_path)} bytes")
    else:
        print("❌ Test raporu oluşturulamadı")