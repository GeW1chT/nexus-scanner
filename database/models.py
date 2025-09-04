#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nexus-Scanner Database Models
Profesyonel siber güvenlik aracı - Veritabanı modelleri

Bu modül tüm veritabanı tablolarını ve ilişkilerini tanımlar.
"""

from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, Float, ForeignKey, JSON, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
import enum

Base = declarative_base()

# Enum tanımlamaları
class ScanType(enum.Enum):
    """Tarama türleri"""
    PORT_SCAN = "port_scan"
    WEB_SCAN = "web_scan"
    SSL_SCAN = "ssl_scan"
    VULNERABILITY_SCAN = "vulnerability_scan"
    FULL_SCAN = "full_scan"

class ScanStatus(enum.Enum):
    """Tarama durumları"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class RiskLevel(enum.Enum):
    """Risk seviyeleri"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class VulnerabilityType(enum.Enum):
    """Güvenlik açığı türleri"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    OPEN_PORT = "open_port"
    SSL_ISSUE = "ssl_issue"
    WEAK_AUTHENTICATION = "weak_authentication"
    INFORMATION_DISCLOSURE = "information_disclosure"
    CONFIGURATION_ERROR = "configuration_error"
    OTHER = "other"

# Ana modeller
class Target(Base):
    """Tarama hedefleri"""
    __tablename__ = 'targets'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, comment="Hedef adı")
    host = Column(String(255), nullable=False, comment="IP adresi veya domain")
    description = Column(Text, comment="Hedef açıklaması")
    tags = Column(JSON, comment="Etiketler (JSON array)")
    is_active = Column(Boolean, default=True, comment="Aktif durumu")
    created_at = Column(DateTime, default=func.now(), comment="Oluşturulma tarihi")
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), comment="Güncellenme tarihi")
    
    # İlişkiler
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Target(id={self.id}, name='{self.name}', host='{self.host}')>"

class Scan(Base):
    """Tarama kayıtları"""
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(Integer, ForeignKey('targets.id'), nullable=False, comment="Hedef ID")
    scan_type = Column(Enum(ScanType), nullable=False, comment="Tarama türü")
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, comment="Tarama durumu")
    
    # Tarama parametreleri
    scan_config = Column(JSON, comment="Tarama konfigürasyonu (JSON)")
    
    # Zaman bilgileri
    started_at = Column(DateTime, comment="Başlangıç zamanı")
    completed_at = Column(DateTime, comment="Bitiş zamanı")
    duration = Column(Float, comment="Süre (saniye)")
    
    # Sonuç özeti
    total_findings = Column(Integer, default=0, comment="Toplam bulgu sayısı")
    critical_findings = Column(Integer, default=0, comment="Kritik bulgu sayısı")
    high_findings = Column(Integer, default=0, comment="Yüksek risk bulgu sayısı")
    medium_findings = Column(Integer, default=0, comment="Orta risk bulgu sayısı")
    low_findings = Column(Integer, default=0, comment="Düşük risk bulgu sayısı")
    info_findings = Column(Integer, default=0, comment="Bilgi amaçlı bulgu sayısı")
    
    # Meta bilgiler
    error_message = Column(Text, comment="Hata mesajı (varsa)")
    created_at = Column(DateTime, default=func.now(), comment="Oluşturulma tarihi")
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), comment="Güncellenme tarihi")
    
    # İlişkiler
    target = relationship("Target", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Scan(id={self.id}, type='{self.scan_type.value}', status='{self.status.value}')>"

class Finding(Base):
    """Güvenlik bulgularıı"""
    __tablename__ = 'findings'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False, comment="Tarama ID")
    
    # Bulgu bilgileri
    vulnerability_type = Column(Enum(VulnerabilityType), nullable=False, comment="Güvenlik açığı türü")
    risk_level = Column(Enum(RiskLevel), nullable=False, comment="Risk seviyesi")
    title = Column(String(500), nullable=False, comment="Bulgu başlığı")
    description = Column(Text, nullable=False, comment="Detaylı açıklama")
    
    # Teknik detaylar
    affected_url = Column(String(1000), comment="Etkilenen URL")
    affected_parameter = Column(String(255), comment="Etkilenen parametre")
    payload = Column(Text, comment="Kullanılan payload")
    response = Column(Text, comment="Sunucu yanıtı")
    
    # Ağ bilgileri (port taraması için)
    port = Column(Integer, comment="Port numarası")
    protocol = Column(String(10), comment="Protokol (tcp/udp)")
    service = Column(String(100), comment="Servis adı")
    service_version = Column(String(255), comment="Servis versiyonu")
    banner = Column(Text, comment="Servis banner'ı")
    
    # SSL bilgileri
    ssl_info = Column(JSON, comment="SSL/TLS detayları (JSON)")
    
    # Çözüm önerileri
    recommendation = Column(Text, comment="Çözüm önerisi")
    references = Column(JSON, comment="Referanslar (JSON array)")
    
    # Durum bilgileri
    is_false_positive = Column(Boolean, default=False, comment="Yanlış pozitif mi?")
    is_fixed = Column(Boolean, default=False, comment="Düzeltildi mi?")
    fixed_at = Column(DateTime, comment="Düzeltilme tarihi")
    notes = Column(Text, comment="Notlar")
    
    # Meta bilgiler
    confidence = Column(Float, comment="Güven skoru (0-1)")
    severity_score = Column(Float, comment="Ciddiyet skoru (0-10)")
    created_at = Column(DateTime, default=func.now(), comment="Oluşturulma tarihi")
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), comment="Güncellenme tarihi")
    
    # İlişkiler
    scan = relationship("Scan", back_populates="findings")
    
    def __repr__(self):
        return f"<Finding(id={self.id}, type='{self.vulnerability_type.value}', risk='{self.risk_level.value}')>"

class Report(Base):
    """Rapor kayıtları"""
    __tablename__ = 'reports'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False, comment="Tarama ID")
    
    # Rapor bilgileri
    title = Column(String(500), nullable=False, comment="Rapor başlığı")
    format = Column(String(20), nullable=False, comment="Rapor formatı (html/pdf/json)")
    file_path = Column(String(1000), comment="Dosya yolu")
    file_size = Column(Integer, comment="Dosya boyutu (byte)")
    
    # Rapor içeriği
    summary = Column(Text, comment="Rapor özeti")
    content = Column(Text, comment="Rapor içeriği")
    
    # Meta bilgiler
    generated_at = Column(DateTime, default=func.now(), comment="Oluşturulma tarihi")
    expires_at = Column(DateTime, comment="Son kullanma tarihi")
    download_count = Column(Integer, default=0, comment="İndirme sayısı")
    
    # İlişkiler
    scan = relationship("Scan", back_populates="reports")
    
    def __repr__(self):
        return f"<Report(id={self.id}, format='{self.format}', scan_id={self.scan_id})>"

class ScanTemplate(Base):
    """Tarama şablonları"""
    __tablename__ = 'scan_templates'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, comment="Şablon adı")
    description = Column(Text, comment="Şablon açıklaması")
    scan_types = Column(JSON, nullable=False, comment="Tarama türleri (JSON array)")
    config = Column(JSON, nullable=False, comment="Konfigürasyon (JSON)")
    
    # Şablon ayarları
    is_default = Column(Boolean, default=False, comment="Varsayılan şablon mu?")
    is_active = Column(Boolean, default=True, comment="Aktif durumu")
    
    # Meta bilgiler
    created_at = Column(DateTime, default=func.now(), comment="Oluşturulma tarihi")
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), comment="Güncellenme tarihi")
    
    def __repr__(self):
        return f"<ScanTemplate(id={self.id}, name='{self.name}')>"

class ScanSchedule(Base):
    """Zamanlanmış taramalar"""
    __tablename__ = 'scan_schedules'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(Integer, ForeignKey('targets.id'), nullable=False, comment="Hedef ID")
    template_id = Column(Integer, ForeignKey('scan_templates.id'), comment="Şablon ID")
    
    # Zamanlama bilgileri
    name = Column(String(255), nullable=False, comment="Zamanlama adı")
    cron_expression = Column(String(100), nullable=False, comment="Cron ifadesi")
    timezone = Column(String(50), default='UTC', comment="Zaman dilimi")
    
    # Durum bilgileri
    is_active = Column(Boolean, default=True, comment="Aktif durumu")
    last_run = Column(DateTime, comment="Son çalışma zamanı")
    next_run = Column(DateTime, comment="Sonraki çalışma zamanı")
    run_count = Column(Integer, default=0, comment="Çalışma sayısı")
    
    # Bildirim ayarları
    notification_emails = Column(JSON, comment="Bildirim e-postaları (JSON array)")
    notify_on_completion = Column(Boolean, default=True, comment="Tamamlandığında bildir")
    notify_on_critical = Column(Boolean, default=True, comment="Kritik bulgularda bildir")
    
    # Meta bilgiler
    created_at = Column(DateTime, default=func.now(), comment="Oluşturulma tarihi")
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), comment="Güncellenme tarihi")
    
    # İlişkiler
    target = relationship("Target")
    template = relationship("ScanTemplate")
    
    def __repr__(self):
        return f"<ScanSchedule(id={self.id}, name='{self.name}', active={self.is_active})>"

class User(Base):
    """Kullanıcı hesapları"""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False, comment="Kullanıcı adı")
    email = Column(String(255), unique=True, nullable=False, comment="E-posta adresi")
    password_hash = Column(String(255), nullable=False, comment="Şifre hash'i")
    
    # Profil bilgileri
    full_name = Column(String(255), comment="Tam adı")
    role = Column(String(50), default='user', comment="Kullanıcı rolü")
    
    # Hesap durumu
    is_active = Column(Boolean, default=True, comment="Aktif durumu")
    is_verified = Column(Boolean, default=False, comment="Doğrulanmış mı?")
    last_login = Column(DateTime, comment="Son giriş zamanı")
    
    # API erişimi
    api_key = Column(String(255), unique=True, comment="API anahtarı")
    api_key_expires = Column(DateTime, comment="API anahtarı son kullanma")
    
    # Meta bilgiler
    created_at = Column(DateTime, default=func.now(), comment="Oluşturulma tarihi")
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), comment="Güncellenme tarihi")
    
    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"

class AuditLog(Base):
    """Sistem denetim kayıtları"""
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), comment="Kullanıcı ID")
    
    # Eylem bilgileri
    action = Column(String(100), nullable=False, comment="Gerçekleştirilen eylem")
    resource_type = Column(String(50), comment="Kaynak türü")
    resource_id = Column(Integer, comment="Kaynak ID")
    
    # Detaylar
    description = Column(Text, comment="Eylem açıklaması")
    ip_address = Column(String(45), comment="IP adresi")
    user_agent = Column(String(500), comment="User agent")
    
    # Ek veriler
    old_values = Column(JSON, comment="Eski değerler (JSON)")
    new_values = Column(JSON, comment="Yeni değerler (JSON)")
    
    # Meta bilgiler
    created_at = Column(DateTime, default=func.now(), comment="Oluşturulma tarihi")
    
    # İlişkiler
    user = relationship("User")
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, action='{self.action}', user_id={self.user_id})>"

class SystemConfig(Base):
    """Sistem konfigürasyonu"""
    __tablename__ = 'system_config'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(100), unique=True, nullable=False, comment="Konfigürasyon anahtarı")
    value = Column(Text, comment="Konfigürasyon değeri")
    data_type = Column(String(20), default='string', comment="Veri türü")
    description = Column(Text, comment="Açıklama")
    
    # Meta bilgiler
    is_encrypted = Column(Boolean, default=False, comment="Şifrelenmiş mi?")
    created_at = Column(DateTime, default=func.now(), comment="Oluşturulma tarihi")
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), comment="Güncellenme tarihi")
    
    def __repr__(self):
        return f"<SystemConfig(key='{self.key}', type='{self.data_type}')>"

# Yardımcı fonksiyonlar
def create_tables(engine):
    """Tüm tabloları oluşturur"""
    Base.metadata.create_all(engine)
    print("✅ Veritabanı tabloları oluşturuldu")

def drop_tables(engine):
    """Tüm tabloları siler"""
    Base.metadata.drop_all(engine)
    print("❌ Veritabanı tabloları silindi")

def get_table_info():
    """Tablo bilgilerini döndürür"""
    tables = []
    for table_name, table in Base.metadata.tables.items():
        column_count = len(table.columns)
        tables.append({
            'name': table_name,
            'columns': column_count,
            'comment': table.comment or 'Açıklama yok'
        })
    return tables

if __name__ == "__main__":
    # Tablo bilgilerini göster
    print("Nexus-Scanner Database Models")
    print("=" * 35)
    
    tables = get_table_info()
    for table in tables:
        print(f"📋 {table['name']}: {table['columns']} sütun")
    
    print(f"\n📊 Toplam {len(tables)} tablo tanımlandı")
    
    # Enum değerlerini göster
    print("\n🏷️ Enum Değerleri:")
    print(f"Tarama Türleri: {[t.value for t in ScanType]}")
    print(f"Risk Seviyeleri: {[r.value for r in RiskLevel]}")
    print(f"Güvenlik Açığı Türleri: {[v.value for v in VulnerabilityType]}")