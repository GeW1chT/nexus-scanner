#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nexus-Scanner PDF Report Generator
Profesyonel siber güvenlik aracı - PDF rapor oluşturucu

Bu modül tarama sonuçlarından profesyonel PDF raporları oluşturur.
"""

import os
import io
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image, KeepTogether
    )
    from reportlab.platypus.flowables import HRFlowable
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("⚠️ ReportLab kütüphanesi bulunamadı. PDF rapor oluşturma devre dışı.")
    print("Kurulum için: pip install reportlab")

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

class PDFReportGenerator:
    """PDF rapor oluşturucu sınıfı"""
    
    def __init__(self):
        """
        PDF rapor oluşturucuyu başlatır
        """
        if not REPORTLAB_AVAILABLE:
            raise ImportError("ReportLab kütüphanesi gerekli. 'pip install reportlab' ile kurun.")
        
        # Stil ayarları
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        
        # Renk paleti
        self.colors = {
            'primary': colors.HexColor('#2c3e50'),
            'secondary': colors.HexColor('#3498db'),
            'critical': colors.HexColor('#e74c3c'),
            'high': colors.HexColor('#f39c12'),
            'medium': colors.HexColor('#f1c40f'),
            'low': colors.HexColor('#27ae60'),
            'info': colors.HexColor('#3498db'),
            'light_gray': colors.HexColor('#ecf0f1'),
            'dark_gray': colors.HexColor('#95a5a6')
        }
    
    def _setup_custom_styles(self):
        """Özel stilleri ayarlar"""
        # Başlık stilleri
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#2c3e50'),
            alignment=TA_CENTER
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomHeading1',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.HexColor('#2c3e50'),
            borderWidth=1,
            borderColor=colors.HexColor('#3498db'),
            borderPadding=5
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=8,
            spaceBefore=15,
            textColor=colors.HexColor('#34495e')
        ))
        
        # Risk badge stilleri
        for risk in ['critical', 'high', 'medium', 'low', 'info']:
            self.styles.add(ParagraphStyle(
                name=f'Risk_{risk.title()}',
                parent=self.styles['Normal'],
                fontSize=10,
                textColor=colors.white,
                backColor=self.colors[risk],
                borderWidth=1,
                borderColor=self.colors[risk],
                borderPadding=3,
                alignment=TA_CENTER
            ))
        
        # Kod stili
        self.styles.add(ParagraphStyle(
            name='Code',
            parent=self.styles['Normal'],
            fontSize=9,
            fontName='Courier',
            backColor=colors.HexColor('#f8f9fa'),
            borderWidth=1,
            borderColor=colors.HexColor('#dee2e6'),
            borderPadding=5,
            leftIndent=10,
            rightIndent=10
        ))
        
        # Öneri stili
        self.styles.add(ParagraphStyle(
            name='Recommendation',
            parent=self.styles['Normal'],
            fontSize=10,
            backColor=colors.HexColor('#d1ecf1'),
            borderWidth=1,
            borderColor=colors.HexColor('#bee5eb'),
            borderPadding=8,
            leftIndent=10,
            rightIndent=10
        ))
    
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
    
    def _get_risk_color(self, risk_level: str):
        """Risk seviyesi rengi"""
        return self.colors.get(risk_level.lower(), self.colors['dark_gray'])
    
    def _create_header(self, report_data: ReportData) -> List:
        """Rapor başlığını oluşturur"""
        story = []
        
        # Ana başlık
        title = Paragraph(
            "🛡️ Nexus-Scanner<br/>Profesyonel Siber Güvenlik Raporu",
            self.styles['CustomTitle']
        )
        story.append(title)
        story.append(Spacer(1, 20))
        
        # Rapor bilgileri tablosu
        report_info_data = [
            ['Rapor Tarihi:', self._format_datetime(datetime.now())],
            ['Rapor ID:', report_data.scan_id],
            ['Hedef:', report_data.target_name],
            ['URL:', report_data.target_url],
            ['Tarama Türü:', report_data.scan_type]
        ]
        
        report_info_table = Table(report_info_data, colWidths=[2*inch, 4*inch])
        report_info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.colors['light_gray']),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(report_info_table)
        story.append(Spacer(1, 30))
        
        return story
    
    def _create_executive_summary(self, report_data: ReportData) -> List:
        """Yönetici özetini oluşturur"""
        story = []
        
        # Başlık
        story.append(Paragraph("📊 Yönetici Özeti", self.styles['CustomHeading1']))
        
        # Tarama bilgileri
        scan_info_data = [
            ['Başlangıç Zamanı:', self._format_datetime(report_data.started_at)],
            ['Bitiş Zamanı:', self._format_datetime(report_data.completed_at)],
            ['Tarama Süresi:', self._format_duration(report_data.duration)],
            ['Durum:', report_data.scan_status.title()]
        ]
        
        scan_info_table = Table(scan_info_data, colWidths=[2*inch, 4*inch])
        scan_info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.colors['light_gray']),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(scan_info_table)
        story.append(Spacer(1, 20))
        
        return story
    
    def _create_risk_overview(self, report_data: ReportData) -> List:
        """Risk genel bakışını oluşturur"""
        story = []
        
        # Başlık
        story.append(Paragraph("🎯 Risk Genel Bakış", self.styles['CustomHeading1']))
        
        # Risk istatistikleri tablosu
        risk_data = [
            ['Risk Seviyesi', 'Bulgu Sayısı', 'Yüzde'],
            ['Kritik', str(report_data.critical_findings), f"{(report_data.critical_findings/max(report_data.total_findings,1)*100):.1f}%"],
            ['Yüksek', str(report_data.high_findings), f"{(report_data.high_findings/max(report_data.total_findings,1)*100):.1f}%"],
            ['Orta', str(report_data.medium_findings), f"{(report_data.medium_findings/max(report_data.total_findings,1)*100):.1f}%"],
            ['Düşük', str(report_data.low_findings), f"{(report_data.low_findings/max(report_data.total_findings,1)*100):.1f}%"],
            ['Bilgi', str(report_data.info_findings), f"{(report_data.info_findings/max(report_data.total_findings,1)*100):.1f}%"]
        ]
        
        risk_table = Table(risk_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
        risk_table.setStyle(TableStyle([
            # Header
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            
            # Risk seviyeleri
            ('BACKGROUND', (0, 1), (-1, 1), self.colors['critical']),
            ('BACKGROUND', (0, 2), (-1, 2), self.colors['high']),
            ('BACKGROUND', (0, 3), (-1, 3), self.colors['medium']),
            ('BACKGROUND', (0, 4), (-1, 4), self.colors['low']),
            ('BACKGROUND', (0, 5), (-1, 5), self.colors['info']),
            
            # Genel stil
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(risk_table)
        story.append(Spacer(1, 15))
        
        # Toplam bulgular
        total_text = Paragraph(
            f"<b>Toplam Bulgular: {report_data.total_findings}</b>",
            self.styles['CustomHeading2']
        )
        story.append(total_text)
        story.append(Spacer(1, 20))
        
        return story
    
    def _create_findings_details(self, report_data: ReportData) -> List:
        """Detaylı bulguları oluşturur"""
        story = []
        
        # Başlık
        story.append(Paragraph("🔍 Detaylı Bulgular", self.styles['CustomHeading1']))
        
        if not report_data.findings:
            no_findings = Paragraph(
                "✅ Bu taramada herhangi bir güvenlik açığı tespit edilmedi.",
                self.styles['Normal']
            )
            story.append(no_findings)
            return story
        
        # Her bulgu için detay
        for i, finding in enumerate(report_data.findings, 1):
            # Bulgu başlığı
            risk_level = finding.get('risk_level', 'info').lower()
            risk_icons = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢',
                'info': '🔵'
            }
            
            finding_title = Paragraph(
                f"{risk_icons.get(risk_level, '⚪')} {i}. {finding.get('title', 'Bilinmeyen Bulgu')}",
                self.styles['CustomHeading2']
            )
            story.append(finding_title)
            
            # Risk badge
            risk_badge = Paragraph(
                f"<b>{finding.get('risk_level', 'INFO').upper()}</b>",
                self.styles[f'Risk_{risk_level.title()}']
            )
            story.append(risk_badge)
            story.append(Spacer(1, 10))
            
            # Bulgu detayları tablosu
            finding_details = []
            
            if finding.get('description'):
                finding_details.append(['Açıklama:', finding['description']])
            
            if finding.get('vulnerability_type'):
                finding_details.append(['Zafiyet Türü:', finding['vulnerability_type']])
            
            if finding.get('affected_url'):
                finding_details.append(['Etkilenen URL:', finding['affected_url']])
            
            if finding.get('affected_parameter'):
                finding_details.append(['Etkilenen Parametre:', finding['affected_parameter']])
            
            if finding.get('confidence'):
                finding_details.append(['Güven Seviyesi:', finding['confidence'].title()])
            
            if finding.get('severity_score'):
                finding_details.append(['Severity Score:', f"{finding['severity_score']:.1f}"])
            
            if finding_details:
                details_table = Table(finding_details, colWidths=[2*inch, 4*inch])
                details_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), self.colors['light_gray']),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                story.append(details_table)
                story.append(Spacer(1, 10))
            
            # Payload
            if finding.get('payload'):
                payload_title = Paragraph("<b>Payload:</b>", self.styles['Normal'])
                story.append(payload_title)
                payload_text = Paragraph(finding['payload'][:500], self.styles['Code'])
                story.append(payload_text)
                story.append(Spacer(1, 10))
            
            # Kanıt
            if finding.get('evidence'):
                evidence_title = Paragraph("<b>Kanıt:</b>", self.styles['Normal'])
                story.append(evidence_title)
                evidence_text = Paragraph(finding['evidence'][:500], self.styles['Code'])
                story.append(evidence_text)
                story.append(Spacer(1, 10))
            
            # Çözüm önerisi
            if finding.get('recommendation'):
                rec_title = Paragraph("<b>💡 Çözüm Önerisi:</b>", self.styles['Normal'])
                story.append(rec_title)
                rec_text = Paragraph(finding['recommendation'], self.styles['Recommendation'])
                story.append(rec_text)
            
            story.append(Spacer(1, 20))
            
            # Sayfa sonu (her 3 bulguda bir)
            if i % 3 == 0 and i < len(report_data.findings):
                story.append(PageBreak())
        
        return story
    
    def _create_recommendations(self) -> List:
        """Genel önerileri oluşturur"""
        story = []
        
        # Başlık
        story.append(Paragraph("💡 Genel Öneriler", self.styles['CustomHeading1']))
        
        recommendations = [
            "Tüm kritik ve yüksek risk seviyeli güvenlik açıklarını öncelikli olarak giderin",
            "Düzenli güvenlik taramaları yapın (en az ayda bir)",
            "Sistem ve uygulamalarınızı güncel tutun",
            "Güvenlik politikalarınızı gözden geçirin",
            "Personel güvenlik eğitimlerini düzenleyin",
            "Güvenlik izleme ve log analizi sistemleri kurun",
            "Penetrasyon testlerini düzenli olarak yaptırın",
            "Güvenlik açığı yönetim süreçlerini oluşturun"
        ]
        
        for rec in recommendations:
            bullet_point = Paragraph(f"• {rec}", self.styles['Normal'])
            story.append(bullet_point)
            story.append(Spacer(1, 5))
        
        story.append(Spacer(1, 20))
        
        return story
    
    def _create_footer(self) -> List:
        """Rapor alt bilgisini oluşturur"""
        story = []
        
        # Çizgi
        story.append(HRFlowable(width="100%", thickness=1, color=self.colors['dark_gray']))
        story.append(Spacer(1, 10))
        
        # Footer metni
        footer_text = Paragraph(
            "Bu rapor Nexus-Scanner v1.0.0 tarafından otomatik olarak oluşturulmuştur.<br/>"
            f"Rapor Tarihi: {self._format_datetime(datetime.now())}<br/>"
            "© 2024 Nexus-Scanner - Profesyonel Siber Güvenlik Aracı",
            self.styles['Normal']
        )
        story.append(footer_text)
        
        return story
    
    def generate_report(self, report_data: ReportData, output_path: str) -> bool:
        """PDF raporu oluşturur"""
        try:
            # Çıktı dizinini oluştur
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # PDF dokümanını oluştur
            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Rapor içeriğini oluştur
            story = []
            
            # Header
            story.extend(self._create_header(report_data))
            
            # Executive Summary
            story.extend(self._create_executive_summary(report_data))
            
            # Risk Overview
            story.extend(self._create_risk_overview(report_data))
            
            # Sayfa sonu
            story.append(PageBreak())
            
            # Findings Details
            story.extend(self._create_findings_details(report_data))
            
            # Sayfa sonu
            story.append(PageBreak())
            
            # Recommendations
            story.extend(self._create_recommendations())
            
            # Footer
            story.extend(self._create_footer())
            
            # PDF'i oluştur
            doc.build(story)
            
            return True
            
        except Exception as e:
            print(f"❌ PDF rapor oluşturma hatası: {str(e)}")
            return False
    
    def generate_from_scan_data(self, scan_data: Dict[str, Any], output_path: str) -> bool:
        """Tarama verisinden PDF raporu oluşturur"""
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
            print(f"❌ Scan data'dan PDF rapor oluşturma hatası: {str(e)}")
            return False

# Test fonksiyonu
if __name__ == "__main__":
    if not REPORTLAB_AVAILABLE:
        print("❌ ReportLab kütüphanesi gerekli. Test çalıştırılamıyor.")
        exit(1)
    
    print("Nexus-Scanner PDF Report Generator Test")
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
    
    # PDF generator oluştur
    generator = PDFReportGenerator()
    
    # Test raporu oluştur
    output_path = os.path.join(os.path.dirname(__file__), 'test_report.pdf')
    
    if generator.generate_from_scan_data(test_data, output_path):
        print(f"✅ Test raporu oluşturuldu: {output_path}")
        print(f"📄 Rapor boyutu: {os.path.getsize(output_path)} bytes")
    else:
        print("❌ Test raporu oluşturulamadı")