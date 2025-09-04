#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nexus-Scanner Reports Module
Profesyonel siber güvenlik aracı - Rapor sistemi

Bu modül tarama sonuçlarından çeşitli formatlarda raporlar oluşturur:
- HTML raporları (web görüntüleme için)
- PDF raporları (yazdırma ve paylaşım için)
- JSON raporları (API entegrasyonu için)

Özellikler:
- Çoklu rapor formatı desteği
- Risk analizi ve öncelik sıralaması
- Profesyonel görsel tasarım
- Otomatik öneri sistemi
- OWASP uyumluluk kontrolü
"""

__version__ = "1.0.0"
__author__ = "Nexus-Scanner Team"
__description__ = "Professional cybersecurity tool reporting system"

import os
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass

# Rapor oluşturucuları import et
try:
    from .html_generator import HTMLReportGenerator
    HTML_AVAILABLE = True
except ImportError as e:
    HTML_AVAILABLE = False
    print(f"⚠️ HTML rapor oluşturucu yüklenemedi: {e}")

try:
    from .pdf_generator import PDFReportGenerator
    PDF_AVAILABLE = True
except ImportError as e:
    PDF_AVAILABLE = False
    print(f"⚠️ PDF rapor oluşturucu yüklenemedi: {e}")

try:
    from .json_generator import JSONReportGenerator
    JSON_AVAILABLE = True
except ImportError as e:
    JSON_AVAILABLE = False
    print(f"⚠️ JSON rapor oluşturucu yüklenemedi: {e}")

# Logging ayarları
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ReportConfig:
    """Rapor konfigürasyon sınıfı"""
    output_directory: str = "./reports"
    include_raw_data: bool = False
    compress_json: bool = False
    auto_open_html: bool = False
    pdf_page_size: str = "A4"
    report_template: str = "default"
    custom_logo_path: Optional[str] = None
    company_name: Optional[str] = None
    report_footer: Optional[str] = None

class ReportManager:
    """Ana rapor yöneticisi sınıfı"""
    
    def __init__(self, config: Optional[ReportConfig] = None):
        """
        Rapor yöneticisini başlatır
        
        Args:
            config: Rapor konfigürasyonu
        """
        self.config = config or ReportConfig()
        
        # Rapor oluşturucuları
        self.html_generator = HTMLReportGenerator() if HTML_AVAILABLE else None
        self.pdf_generator = PDFReportGenerator() if PDF_AVAILABLE else None
        self.json_generator = JSONReportGenerator() if JSON_AVAILABLE else None
        
        # Çıktı dizinini oluştur
        os.makedirs(self.config.output_directory, exist_ok=True)
        
        logger.info(f"Rapor yöneticisi başlatıldı. Çıktı dizini: {self.config.output_directory}")
        logger.info(f"Mevcut formatlar: HTML={HTML_AVAILABLE}, PDF={PDF_AVAILABLE}, JSON={JSON_AVAILABLE}")
    
    def generate_all_reports(self, scan_data: Dict[str, Any], 
                           base_filename: Optional[str] = None) -> Dict[str, Any]:
        """
        Tüm mevcut formatlarda rapor oluşturur
        
        Args:
            scan_data: Tarama verisi
            base_filename: Temel dosya adı (opsiyonel)
            
        Returns:
            Dict: Oluşturulan raporların bilgileri
        """
        if not base_filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            scan_id = scan_data.get('scan_id', 'unknown')
            base_filename = f"nexus_scan_{scan_id}_{timestamp}"
        
        results = {
            'base_filename': base_filename,
            'generated_at': datetime.now().isoformat(),
            'reports': {},
            'errors': []
        }
        
        # HTML raporu
        if self.html_generator:
            html_path = os.path.join(self.config.output_directory, f"{base_filename}.html")
            try:
                if self.html_generator.generate_from_scan_data(scan_data, html_path):
                    results['reports']['html'] = {
                        'path': html_path,
                        'size_bytes': os.path.getsize(html_path),
                        'status': 'success'
                    }
                    logger.info(f"✅ HTML raporu oluşturuldu: {html_path}")
                else:
                    results['errors'].append('HTML raporu oluşturulamadı')
            except Exception as e:
                results['errors'].append(f'HTML rapor hatası: {str(e)}')
                logger.error(f"❌ HTML rapor hatası: {e}")
        
        # PDF raporu
        if self.pdf_generator:
            pdf_path = os.path.join(self.config.output_directory, f"{base_filename}.pdf")
            try:
                if self.pdf_generator.generate_from_scan_data(scan_data, pdf_path):
                    results['reports']['pdf'] = {
                        'path': pdf_path,
                        'size_bytes': os.path.getsize(pdf_path),
                        'status': 'success'
                    }
                    logger.info(f"✅ PDF raporu oluşturuldu: {pdf_path}")
                else:
                    results['errors'].append('PDF raporu oluşturulamadı')
            except Exception as e:
                results['errors'].append(f'PDF rapor hatası: {str(e)}')
                logger.error(f"❌ PDF rapor hatası: {e}")
        
        # JSON raporu
        if self.json_generator:
            json_path = os.path.join(self.config.output_directory, f"{base_filename}.json")
            try:
                if self.json_generator.generate_report(
                    scan_data, 
                    json_path, 
                    include_raw_data=self.config.include_raw_data,
                    compress_output=self.config.compress_json
                ):
                    results['reports']['json'] = {
                        'path': json_path,
                        'size_bytes': os.path.getsize(json_path),
                        'status': 'success'
                    }
                    logger.info(f"✅ JSON raporu oluşturuldu: {json_path}")
                else:
                    results['errors'].append('JSON raporu oluşturulamadı')
            except Exception as e:
                results['errors'].append(f'JSON rapor hatası: {str(e)}')
                logger.error(f"❌ JSON rapor hatası: {e}")
        
        # Özet bilgi
        total_reports = len(results['reports'])
        total_errors = len(results['errors'])
        
        logger.info(f"📊 Rapor oluşturma tamamlandı: {total_reports} başarılı, {total_errors} hata")
        
        return results
    
    def generate_single_report(self, scan_data: Dict[str, Any], 
                             format_type: str, 
                             output_path: str) -> bool:
        """
        Tek bir formatta rapor oluşturur
        
        Args:
            scan_data: Tarama verisi
            format_type: Rapor formatı ('html', 'pdf', 'json')
            output_path: Çıktı dosya yolu
            
        Returns:
            bool: Başarı durumu
        """
        format_type = format_type.lower()
        
        try:
            if format_type == 'html' and self.html_generator:
                return self.html_generator.generate_from_scan_data(scan_data, output_path)
            
            elif format_type == 'pdf' and self.pdf_generator:
                return self.pdf_generator.generate_from_scan_data(scan_data, output_path)
            
            elif format_type == 'json' and self.json_generator:
                return self.json_generator.generate_report(
                    scan_data, 
                    output_path,
                    include_raw_data=self.config.include_raw_data,
                    compress_output=self.config.compress_json
                )
            
            else:
                logger.error(f"❌ Desteklenmeyen format veya generator mevcut değil: {format_type}")
                return False
                
        except Exception as e:
            logger.error(f"❌ {format_type.upper()} rapor oluşturma hatası: {e}")
            return False
    
    def get_available_formats(self) -> List[str]:
        """
        Mevcut rapor formatlarını döndürür
        
        Returns:
            List[str]: Mevcut formatlar listesi
        """
        formats = []
        
        if HTML_AVAILABLE and self.html_generator:
            formats.append('html')
        
        if PDF_AVAILABLE and self.pdf_generator:
            formats.append('pdf')
        
        if JSON_AVAILABLE and self.json_generator:
            formats.append('json')
        
        return formats
    
    def validate_scan_data(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Tarama verisini doğrular
        
        Args:
            scan_data: Doğrulanacak tarama verisi
            
        Returns:
            Dict: Doğrulama sonucu
        """
        validation_result = {
            'valid': True,
            'warnings': [],
            'errors': [],
            'suggestions': []
        }
        
        # Zorunlu alanları kontrol et
        required_fields = ['scan_id', 'target_name', 'scan_type', 'findings']
        
        for field in required_fields:
            if field not in scan_data:
                validation_result['errors'].append(f"Zorunlu alan eksik: {field}")
                validation_result['valid'] = False
        
        # Bulgular kontrolü
        findings = scan_data.get('findings', [])
        if not isinstance(findings, list):
            validation_result['errors'].append("Bulgular bir liste olmalı")
            validation_result['valid'] = False
        elif len(findings) == 0:
            validation_result['warnings'].append("Hiç bulgu yok")
        
        # Tarih kontrolü
        date_fields = ['started_at', 'completed_at']
        for field in date_fields:
            if field in scan_data and scan_data[field]:
                try:
                    if isinstance(scan_data[field], str):
                        datetime.fromisoformat(scan_data[field].replace('Z', '+00:00'))
                except ValueError:
                    validation_result['warnings'].append(f"Geçersiz tarih formatı: {field}")
        
        # Öneriler
        if len(findings) > 0:
            critical_count = len([f for f in findings if f.get('risk_level', '').lower() == 'critical'])
            if critical_count > 0:
                validation_result['suggestions'].append(f"{critical_count} kritik bulgu var - öncelikli rapor oluşturun")
        
        return validation_result
    
    def get_report_statistics(self) -> Dict[str, Any]:
        """
        Rapor dizini istatistiklerini döndürür
        
        Returns:
            Dict: İstatistik bilgileri
        """
        stats = {
            'output_directory': self.config.output_directory,
            'total_files': 0,
            'file_types': {},
            'total_size_bytes': 0,
            'latest_report': None,
            'oldest_report': None
        }
        
        try:
            if not os.path.exists(self.config.output_directory):
                return stats
            
            files = []
            for filename in os.listdir(self.config.output_directory):
                filepath = os.path.join(self.config.output_directory, filename)
                if os.path.isfile(filepath):
                    file_ext = os.path.splitext(filename)[1].lower()
                    file_size = os.path.getsize(filepath)
                    file_mtime = os.path.getmtime(filepath)
                    
                    files.append({
                        'name': filename,
                        'path': filepath,
                        'extension': file_ext,
                        'size': file_size,
                        'modified': file_mtime
                    })
                    
                    # Dosya türü sayısı
                    stats['file_types'][file_ext] = stats['file_types'].get(file_ext, 0) + 1
                    
                    # Toplam boyut
                    stats['total_size_bytes'] += file_size
            
            stats['total_files'] = len(files)
            
            if files:
                # En yeni ve en eski dosya
                files_by_time = sorted(files, key=lambda x: x['modified'])
                stats['oldest_report'] = files_by_time[0]['name']
                stats['latest_report'] = files_by_time[-1]['name']
        
        except Exception as e:
            logger.error(f"❌ İstatistik toplama hatası: {e}")
        
        return stats

# Kolaylık fonksiyonları
def create_report_manager(output_dir: str = "./reports", **kwargs) -> ReportManager:
    """
    Rapor yöneticisi oluşturur
    
    Args:
        output_dir: Çıktı dizini
        **kwargs: Ek konfigürasyon parametreleri
        
    Returns:
        ReportManager: Yapılandırılmış rapor yöneticisi
    """
    config = ReportConfig(output_directory=output_dir, **kwargs)
    return ReportManager(config)

def quick_report(scan_data: Dict[str, Any], 
                output_dir: str = "./reports", 
                formats: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Hızlı rapor oluşturma fonksiyonu
    
    Args:
        scan_data: Tarama verisi
        output_dir: Çıktı dizini
        formats: İstenen formatlar (None ise tümü)
        
    Returns:
        Dict: Rapor oluşturma sonucu
    """
    manager = create_report_manager(output_dir)
    
    if formats:
        # Belirli formatlar
        results = {
            'base_filename': f"quick_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'generated_at': datetime.now().isoformat(),
            'reports': {},
            'errors': []
        }
        
        for fmt in formats:
            if fmt in manager.get_available_formats():
                filename = f"{results['base_filename']}.{fmt}"
                output_path = os.path.join(output_dir, filename)
                
                if manager.generate_single_report(scan_data, fmt, output_path):
                    results['reports'][fmt] = {
                        'path': output_path,
                        'size_bytes': os.path.getsize(output_path),
                        'status': 'success'
                    }
                else:
                    results['errors'].append(f'{fmt.upper()} raporu oluşturulamadı')
        
        return results
    else:
        # Tüm formatlar
        return manager.generate_all_reports(scan_data)

# Modül exports
__all__ = [
    'ReportManager',
    'ReportConfig', 
    'HTMLReportGenerator',
    'PDFReportGenerator',
    'JSONReportGenerator',
    'create_report_manager',
    'quick_report',
    'HTML_AVAILABLE',
    'PDF_AVAILABLE', 
    'JSON_AVAILABLE'
]

# Başlangıç mesajı
if __name__ != "__main__":
    available_formats = []
    if HTML_AVAILABLE:
        available_formats.append('HTML')
    if PDF_AVAILABLE:
        available_formats.append('PDF')
    if JSON_AVAILABLE:
        available_formats.append('JSON')
    
    logger.info(f"📊 Nexus-Scanner Reports v{__version__} yüklendi")
    logger.info(f"🎯 Mevcut formatlar: {', '.join(available_formats) if available_formats else 'Hiçbiri'}")

# Test fonksiyonu
if __name__ == "__main__":
    print("Nexus-Scanner Reports Module Test")
    print("=" * 50)
    
    # Test verisi
    test_scan_data = {
        'scan_id': 'TEST_SCAN_001',
        'target_name': 'Test Application',
        'target_url': 'https://example.com',
        'scan_type': 'Full Security Scan',
        'scan_status': 'completed',
        'started_at': datetime.now().replace(hour=10, minute=0),
        'completed_at': datetime.now(),
        'duration': 1200,
        'findings': [
            {
                'title': 'Test SQL Injection',
                'description': 'Test vulnerability for demonstration',
                'risk_level': 'high',
                'vulnerability_type': 'SQL Injection',
                'affected_url': 'https://example.com/login',
                'recommendation': 'Use parameterized queries'
            }
        ]
    }
    
    # Rapor yöneticisi oluştur
    manager = create_report_manager('./test_reports')
    
    print(f"📋 Mevcut formatlar: {manager.get_available_formats()}")
    
    # Veri doğrulama
    validation = manager.validate_scan_data(test_scan_data)
    print(f"✅ Veri doğrulama: {'Geçerli' if validation['valid'] else 'Geçersiz'}")
    
    # Hızlı rapor oluştur
    results = quick_report(test_scan_data, './test_reports')
    print(f"📊 Oluşturulan raporlar: {len(results['reports'])}")
    
    # İstatistikler
    stats = manager.get_report_statistics()
    print(f"📈 Toplam dosya: {stats['total_files']}")
    print(f"💾 Toplam boyut: {stats['total_size_bytes']} bytes")
    
    print("\n🎉 Test tamamlandı!")